//! Process anomaly detection engine.
//!
//! Analyzes process lists for:
//! - **Hidden processes**: found by psscan but not pslist (unlinked from ActiveProcessLinks)
//! - **Parent-child violations**: processes with unexpected parents
//! - **Singleton violations**: critical processes with multiple instances
//! - **LOLBin detection**: legitimate binaries being abused with suspicious arguments
//! - **lsass.exe children**: potential credential dumping indicators

use crate::plugins::cmdline::CmdlineInfo;
use crate::rules::{lolbins, parent_child};
use crate::server::types::ProcessInfo;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::debug;

/// Severity level for anomalies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// A single process anomaly finding.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Anomaly {
    pub category: String,
    pub severity: Severity,
    pub pid: u64,
    pub process_name: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_pid: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<String>,
}

/// Results of process anomaly analysis.
#[derive(Debug, Serialize, Deserialize)]
pub struct AnomalyReport {
    pub total_anomalies: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub anomalies: Vec<Anomaly>,
    /// Process tree as list of (pid, ppid, name) for visualization.
    pub process_tree: Vec<ProcessTreeNode>,
}

/// A node in the process tree.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProcessTreeNode {
    pub pid: u64,
    pub ppid: u64,
    pub name: String,
    pub children: Vec<ProcessTreeNode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anomaly_count: Option<usize>,
}

/// Run full process anomaly analysis.
///
/// # Arguments
/// * `pslist_procs` - Processes from pslist (walking ActiveProcessLinks)
/// * `psscan_procs` - Processes from psscan (physical memory scan), or None
/// * `cmdlines` - Command lines for processes, or None
pub fn analyze(
    pslist_procs: &[ProcessInfo],
    psscan_procs: Option<&[ProcessInfo]>,
    cmdlines: Option<&[CmdlineInfo]>,
) -> AnomalyReport {
    let mut anomalies = Vec::new();

    // Build lookup tables
    let _pslist_by_pid: HashMap<u64, &ProcessInfo> =
        pslist_procs.iter().map(|p| (p.pid, p)).collect();
    let name_by_pid: HashMap<u64, &str> = pslist_procs
        .iter()
        .map(|p| (p.pid, p.name.as_str()))
        .collect();
    let cmdline_by_pid: HashMap<u64, &str> = cmdlines
        .unwrap_or(&[])
        .iter()
        .map(|c| (c.pid, c.cmdline.as_str()))
        .collect();

    // 1. Hidden process detection (psscan - pslist diff)
    if let Some(scan_procs) = psscan_procs {
        detect_hidden_processes(pslist_procs, scan_procs, &mut anomalies);
    }

    // 2. Parent-child violations
    detect_parent_child_violations(pslist_procs, &name_by_pid, &mut anomalies);

    // 3. Singleton violations
    detect_singleton_violations(pslist_procs, &mut anomalies);

    // 4. LOLBin detection
    if cmdlines.is_some() {
        detect_lolbin_abuse(pslist_procs, &cmdline_by_pid, &mut anomalies);
    }

    // 5. lsass.exe children
    detect_lsass_children(pslist_procs, &name_by_pid, &mut anomalies);

    // 6. Suspicious process names (misspellings of system processes)
    detect_name_masquerading(pslist_procs, &mut anomalies);

    // Sort by severity
    anomalies.sort_by(|a, b| a.severity.cmp(&b.severity));

    // Build tree
    let tree = build_process_tree(pslist_procs, &anomalies);

    // Count severities
    let critical_count = anomalies.iter().filter(|a| a.severity == Severity::Critical).count();
    let high_count = anomalies.iter().filter(|a| a.severity == Severity::High).count();
    let medium_count = anomalies.iter().filter(|a| a.severity == Severity::Medium).count();
    let low_count = anomalies.iter().filter(|a| a.severity == Severity::Low).count();

    AnomalyReport {
        total_anomalies: anomalies.len(),
        critical_count,
        high_count,
        medium_count,
        low_count,
        anomalies,
        process_tree: tree,
    }
}

/// Detect hidden processes: in psscan but not in pslist.
fn detect_hidden_processes(
    pslist_procs: &[ProcessInfo],
    psscan_procs: &[ProcessInfo],
    anomalies: &mut Vec<Anomaly>,
) {
    let pslist_pids: std::collections::HashSet<u64> =
        pslist_procs.iter().map(|p| p.pid).collect();

    for proc in psscan_procs {
        // Skip PID 0 (Idle) — it's always excluded from pslist
        if proc.pid == 0 {
            continue;
        }

        // Skip exited processes (have exit time)
        if proc.exit_time.is_some() {
            continue;
        }

        if !pslist_pids.contains(&proc.pid) {
            debug!("Hidden process detected: {} (PID {})", proc.name, proc.pid);
            anomalies.push(Anomaly {
                category: "hidden_process".to_string(),
                severity: Severity::Critical,
                pid: proc.pid,
                process_name: proc.name.clone(),
                description: format!(
                    "Process '{}' (PID {}) found by psscan but NOT in pslist — \
                     unlinked from ActiveProcessLinks (rootkit behavior)",
                    proc.name, proc.pid
                ),
                parent_pid: Some(proc.ppid),
                parent_name: None,
                cmdline: None,
            });
        }
    }
}

/// Detect parent-child relationship violations.
///
/// Handles two common benign scenarios that would otherwise be false positives:
/// 1. **Parent exited normally**: smss.exe session workers exit after creating
///    csrss.exe/wininit.exe/winlogon.exe; userinit.exe exits after launching
///    explorer.exe. These show as parent `<unknown>` and are downgraded to info.
/// 2. **PID reuse**: After the original parent exits, Windows may reuse its PID
///    for an unrelated process. Detected when the "parent" was created after the
///    child. Also downgraded to info.
fn detect_parent_child_violations(
    procs: &[ProcessInfo],
    name_by_pid: &HashMap<u64, &str>,
    anomalies: &mut Vec<Anomaly>,
) {
    // Build create_time lookup for PID reuse detection
    let create_time_by_pid: HashMap<u64, &str> = procs
        .iter()
        .filter_map(|p| p.create_time.as_deref().map(|t| (p.pid, t)))
        .collect();

    for proc in procs {
        if proc.pid == 0 || proc.pid == 4 {
            continue;
        }

        if let Some(rule) = parent_child::find_rule(&proc.name) {
            let parent_name = name_by_pid.get(&proc.ppid).copied().unwrap_or("<unknown>");

            if rule
                .expected_parents
                .iter()
                .any(|p| p.eq_ignore_ascii_case(parent_name))
            {
                continue; // Parent matches — no violation
            }

            let parent_exists = name_by_pid.contains_key(&proc.ppid);

            // Determine if this is a known benign pattern
            let (severity, description) = if !parent_exists && rule.parent_may_exit {
                // Case 1: Parent not in pslist, but expected parent normally exits.
                // This is normal Windows behavior (e.g., smss session worker exits
                // after spawning csrss/wininit/winlogon).
                (
                    Severity::Info,
                    format!(
                        "'{}' (PID {}) parent PID {} not in process list. \
                         Expected parent [{}] normally exits after spawning — \
                         this is standard Windows behavior.",
                        proc.name,
                        proc.pid,
                        proc.ppid,
                        rule.expected_parents.join(", "),
                    ),
                )
            } else if parent_exists && rule.parent_may_exit && is_pid_reuse(proc, procs, &create_time_by_pid)
            {
                // Case 2: Parent exists but wrong name, and evidence indicates
                // PID reuse (parent created after child, parent terminated, or
                // sibling smss-child processes share the same PPID).
                (
                    Severity::Info,
                    format!(
                        "'{}' (PID {}) has parent '{}' (PID {}) — \
                         PID reuse detected (original parent [{}] exited after boot).",
                        proc.name,
                        proc.pid,
                        parent_name,
                        proc.ppid,
                        rule.expected_parents.join(", "),
                    ),
                )
            } else {
                // Genuine violation — unexpected parent
                let sev = match rule.severity {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "medium" => Severity::Medium,
                    _ => Severity::Low,
                };
                (
                    sev,
                    format!(
                        "'{}' (PID {}) has unexpected parent '{}' (PID {}). \
                         Expected: [{}]. Parent exists: {}. {}",
                        proc.name,
                        proc.pid,
                        parent_name,
                        proc.ppid,
                        rule.expected_parents.join(", "),
                        parent_exists,
                        rule.description
                    ),
                )
            };

            anomalies.push(Anomaly {
                category: "parent_child_violation".to_string(),
                severity,
                pid: proc.pid,
                process_name: proc.name.clone(),
                description,
                parent_pid: Some(proc.ppid),
                parent_name: Some(parent_name.to_string()),
                cmdline: None,
            });
        }
    }
}

/// Processes created by short-lived child smss.exe instances during boot.
const SMSS_CHILD_SPAWNS: &[&str] = &["csrss.exe", "wininit.exe", "winlogon.exe"];

/// Check if a process's parent PID was likely reused after the original parent exited.
///
/// Uses three independent signals:
///   1. **Timestamp ordering**: parent created after child (impossible for real parent).
///   2. **Terminated parent**: current PID holder has exit_time or 0 threads.
///   3. **Sibling detection**: multiple smss-child processes share the same PPID
///      (e.g. csrss.exe + wininit.exe both have PPID 484 → child smss.exe PID reuse).
fn is_pid_reuse(
    child: &ProcessInfo,
    all_procs: &[ProcessInfo],
    create_time_by_pid: &HashMap<u64, &str>,
) -> bool {
    // Signal 1: Parent created after child
    let child_time = child.create_time.as_deref().unwrap_or("");
    let parent_time = create_time_by_pid.get(&child.ppid).copied().unwrap_or("");
    if !child_time.is_empty() && !parent_time.is_empty() && parent_time > child_time {
        return true;
    }

    // Signal 2: Current PID holder is terminated
    if let Some(parent) = all_procs.iter().find(|p| p.pid == child.ppid) {
        if parent.exit_time.is_some() {
            return true;
        }
        if parent.threads == Some(0) {
            return true;
        }
    }

    // Signal 3: Sibling smss-child processes share the same PPID
    // (e.g. csrss.exe + wininit.exe both parented by same dead child smss.exe)
    if SMSS_CHILD_SPAWNS.iter().any(|s| s.eq_ignore_ascii_case(&child.name)) {
        let sibling_count = all_procs
            .iter()
            .filter(|p| {
                p.ppid == child.ppid
                    && SMSS_CHILD_SPAWNS
                        .iter()
                        .any(|s| s.eq_ignore_ascii_case(&p.name))
            })
            .count();
        if sibling_count >= 2 {
            return true;
        }
    }

    false
}

/// Detect singleton process violations (e.g., multiple lsass.exe).
fn detect_singleton_violations(procs: &[ProcessInfo], anomalies: &mut Vec<Anomaly>) {
    // Count instances of each process name
    let mut counts: HashMap<String, Vec<&ProcessInfo>> = HashMap::new();
    for proc in procs {
        // Skip exited processes
        if proc.exit_time.is_some() {
            continue;
        }
        counts
            .entry(proc.name.to_lowercase())
            .or_default()
            .push(proc);
    }

    for (_name_lower, instances) in &counts {
        if instances.len() <= 1 {
            continue;
        }

        // Check if this process should be singleton
        if let Some(rule) = parent_child::find_rule(&instances[0].name) {
            if rule.singleton {
                let severity = match rule.severity {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    _ => Severity::Medium,
                };

                for inst in instances.iter().skip(1) {
                    anomalies.push(Anomaly {
                        category: "singleton_violation".to_string(),
                        severity: severity.clone(),
                        pid: inst.pid,
                        process_name: inst.name.clone(),
                        description: format!(
                            "Multiple instances of '{}' detected ({} total). \
                             This process should be a singleton. \
                             Extra instance PID {} may be malicious.",
                            inst.name,
                            instances.len(),
                            inst.pid
                        ),
                        parent_pid: Some(inst.ppid),
                        parent_name: None,
                        cmdline: None,
                    });
                }
            }
        }
    }
}

/// Detect LOLBin abuse based on command line arguments.
fn detect_lolbin_abuse(
    procs: &[ProcessInfo],
    cmdline_by_pid: &HashMap<u64, &str>,
    anomalies: &mut Vec<Anomaly>,
) {
    for proc in procs {
        if let Some(&cmdline) = cmdline_by_pid.get(&proc.pid) {
            if cmdline.is_empty() {
                continue;
            }

            let matches = lolbins::check_suspicious_args(&proc.name, cmdline);
            if !matches.is_empty() {
                anomalies.push(Anomaly {
                    category: "lolbin_abuse".to_string(),
                    severity: Severity::High,
                    pid: proc.pid,
                    process_name: proc.name.clone(),
                    description: format!(
                        "LOLBin '{}' (PID {}) has suspicious arguments: [{}]. \
                         Cmdline: {}",
                        proc.name,
                        proc.pid,
                        matches.join(", "),
                        truncate(cmdline, 200)
                    ),
                    parent_pid: Some(proc.ppid),
                    parent_name: None,
                    cmdline: Some(cmdline.to_string()),
                });
            }
        }
    }
}

/// Detect processes that are children of lsass.exe (credential dumping indicator).
fn detect_lsass_children(
    procs: &[ProcessInfo],
    _name_by_pid: &HashMap<u64, &str>,
    anomalies: &mut Vec<Anomaly>,
) {
    // Find lsass PID(s)
    let lsass_pids: Vec<u64> = procs
        .iter()
        .filter(|p| p.name.eq_ignore_ascii_case("lsass.exe"))
        .map(|p| p.pid)
        .collect();

    for proc in procs {
        if lsass_pids.contains(&proc.ppid) {
            // Skip known legitimate lsass children
            let lower = proc.name.to_lowercase();
            if lower == "lsaiso.exe" || lower == "efssvc.exe" {
                continue;
            }

            anomalies.push(Anomaly {
                category: "lsass_child".to_string(),
                severity: Severity::Critical,
                pid: proc.pid,
                process_name: proc.name.clone(),
                description: format!(
                    "'{}' (PID {}) is a child of lsass.exe (PID {}). \
                     This is a strong indicator of credential dumping or injection.",
                    proc.name, proc.pid, proc.ppid
                ),
                parent_pid: Some(proc.ppid),
                parent_name: Some("lsass.exe".to_string()),
                cmdline: None,
            });
        }
    }
}

/// Detect process name masquerading (misspellings of system processes).
fn detect_name_masquerading(procs: &[ProcessInfo], anomalies: &mut Vec<Anomaly>) {
    // Common masquerading targets and their misspellings
    let targets = [
        ("svchost.exe", &["svch0st.exe", "scvhost.exe", "svchosl.exe", "svchosts.exe", "svchostss.exe"][..]),
        ("lsass.exe", &["lsas.exe", "lsasss.exe", "isass.exe", "lssas.exe"][..]),
        ("csrss.exe", &["csrs.exe", "csrsss.exe", "csrsc.exe"][..]),
        ("services.exe", &["service.exe", "servicess.exe"][..]),
        ("explorer.exe", &["explor.exe", "explorar.exe", "explorer.exe.exe"][..]),
    ];

    for proc in procs {
        let name_lower = proc.name.to_lowercase();
        for (_, misspellings) in &targets {
            if misspellings.iter().any(|m| m.eq_ignore_ascii_case(&name_lower)) {
                anomalies.push(Anomaly {
                    category: "name_masquerading".to_string(),
                    severity: Severity::High,
                    pid: proc.pid,
                    process_name: proc.name.clone(),
                    description: format!(
                        "Process '{}' (PID {}) appears to be masquerading as a system process \
                         (common misspelling technique used by malware)",
                        proc.name, proc.pid
                    ),
                    parent_pid: Some(proc.ppid),
                    parent_name: None,
                    cmdline: None,
                });
            }
        }
    }
}

/// Build a process tree from flat process list.
pub fn build_process_tree(
    procs: &[ProcessInfo],
    anomalies: &[Anomaly],
) -> Vec<ProcessTreeNode> {
    // Count anomalies per PID
    let mut anomaly_counts: HashMap<u64, usize> = HashMap::new();
    for a in anomalies {
        *anomaly_counts.entry(a.pid).or_default() += 1;
    }

    // Build lookup: PID → children
    let mut children_map: HashMap<u64, Vec<&ProcessInfo>> = HashMap::new();
    let pid_set: std::collections::HashSet<u64> = procs.iter().map(|p| p.pid).collect();

    for proc in procs {
        children_map.entry(proc.ppid).or_default().push(proc);
    }

    // Find root processes (PPID not in pid_set, or PID 0/4)
    let roots: Vec<&ProcessInfo> = procs
        .iter()
        .filter(|p| !pid_set.contains(&p.ppid) || p.pid == 0 || p.pid == 4)
        .collect();

    fn build_node(
        proc: &ProcessInfo,
        children_map: &HashMap<u64, Vec<&ProcessInfo>>,
        anomaly_counts: &HashMap<u64, usize>,
        depth: usize,
    ) -> ProcessTreeNode {
        let children = if depth < 20 {
            children_map
                .get(&proc.pid)
                .map(|kids| {
                    kids.iter()
                        .filter(|k| k.pid != proc.pid) // Avoid self-reference
                        .map(|k| build_node(k, children_map, anomaly_counts, depth + 1))
                        .collect()
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        let acount = anomaly_counts.get(&proc.pid).copied();

        ProcessTreeNode {
            pid: proc.pid,
            ppid: proc.ppid,
            name: proc.name.clone(),
            children,
            anomaly_count: acount,
        }
    }

    roots
        .iter()
        .map(|r| build_node(r, &children_map, &anomaly_counts, 0))
        .collect()
}

/// Truncate a string to max length with "..." suffix.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proc(pid: u64, ppid: u64, name: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid,
            name: name.to_string(),
            offset: 0,
            create_time: None,
            exit_time: None,
            threads: None,
            handles: None,
            session_id: None,
            wow64: None,
        }
    }

    #[test]
    fn test_hidden_process_detection() {
        let pslist = vec![
            make_proc(4, 0, "System"),
            make_proc(100, 4, "smss.exe"),
        ];
        let psscan = vec![
            make_proc(4, 0, "System"),
            make_proc(100, 4, "smss.exe"),
            make_proc(666, 100, "evil.exe"), // Hidden!
        ];

        let report = analyze(&pslist, Some(&psscan), None);
        let hidden: Vec<_> = report
            .anomalies
            .iter()
            .filter(|a| a.category == "hidden_process")
            .collect();

        assert_eq!(hidden.len(), 1);
        assert_eq!(hidden[0].pid, 666);
        assert_eq!(hidden[0].severity, Severity::Critical);
    }

    #[test]
    fn test_parent_child_violation() {
        let procs = vec![
            make_proc(4, 0, "System"),
            make_proc(100, 4, "smss.exe"),
            make_proc(500, 100, "csrss.exe"),     // OK — parent is smss.exe
            make_proc(600, 100, "wininit.exe"),    // OK — parent is smss.exe
            make_proc(700, 999, "lsass.exe"),      // BAD — parent should be wininit.exe
        ];

        let report = analyze(&procs, None, None);
        let violations: Vec<_> = report
            .anomalies
            .iter()
            .filter(|a| a.category == "parent_child_violation")
            .collect();

        assert!(violations.iter().any(|v| v.pid == 700));
    }

    #[test]
    fn test_singleton_violation() {
        let procs = vec![
            make_proc(4, 0, "System"),
            make_proc(600, 500, "lsass.exe"),   // First instance
            make_proc(1234, 500, "lsass.exe"),  // Second instance — BAD!
        ];

        let report = analyze(&procs, None, None);
        let violations: Vec<_> = report
            .anomalies
            .iter()
            .filter(|a| a.category == "singleton_violation")
            .collect();

        assert!(!violations.is_empty());
    }

    #[test]
    fn test_lolbin_detection() {
        let procs = vec![
            make_proc(4, 0, "System"),
            make_proc(1000, 500, "powershell.exe"),
        ];
        let cmdlines = vec![CmdlineInfo {
            pid: 1000,
            name: "powershell.exe".to_string(),
            cmdline: "powershell.exe -nop -w hidden -enc SGVsbG8=".to_string(),
            image_path: None,
        }];

        let report = analyze(&procs, None, Some(&cmdlines));
        let lolbins: Vec<_> = report
            .anomalies
            .iter()
            .filter(|a| a.category == "lolbin_abuse")
            .collect();

        assert!(!lolbins.is_empty());
        assert_eq!(lolbins[0].pid, 1000);
    }

    #[test]
    fn test_lsass_child_detection() {
        let procs = vec![
            make_proc(4, 0, "System"),
            make_proc(600, 500, "lsass.exe"),
            make_proc(999, 600, "procdump.exe"), // Child of lsass — BAD!
        ];

        let report = analyze(&procs, None, None);
        let children: Vec<_> = report
            .anomalies
            .iter()
            .filter(|a| a.category == "lsass_child")
            .collect();

        assert_eq!(children.len(), 1);
        assert_eq!(children[0].pid, 999);
    }

    #[test]
    fn test_name_masquerading() {
        let procs = vec![
            make_proc(4, 0, "System"),
            make_proc(100, 4, "svch0st.exe"), // Misspelled svchost
        ];

        let report = analyze(&procs, None, None);
        let masq: Vec<_> = report
            .anomalies
            .iter()
            .filter(|a| a.category == "name_masquerading")
            .collect();

        assert_eq!(masq.len(), 1);
        assert_eq!(masq[0].pid, 100);
    }

    #[test]
    fn test_build_process_tree() {
        let procs = vec![
            make_proc(4, 0, "System"),
            make_proc(100, 4, "smss.exe"),
            make_proc(200, 100, "csrss.exe"),
            make_proc(300, 100, "wininit.exe"),
            make_proc(400, 300, "services.exe"),
        ];

        let tree = build_process_tree(&procs, &[]);
        assert!(!tree.is_empty());

        // System should be a root
        let system = tree.iter().find(|n| n.pid == 4).unwrap();
        assert_eq!(system.children.len(), 1); // smss.exe
        assert_eq!(system.children[0].children.len(), 2); // csrss + wininit
    }

    #[test]
    fn test_clean_system_no_anomalies() {
        let procs = vec![
            make_proc(4, 0, "System"),
            make_proc(100, 4, "smss.exe"),
            make_proc(200, 100, "csrss.exe"),
            make_proc(300, 100, "wininit.exe"),
            make_proc(400, 300, "services.exe"),
            make_proc(500, 300, "lsass.exe"),
            make_proc(600, 400, "svchost.exe"),
        ];

        let report = analyze(&procs, Some(&procs), None);
        // A clean system should have no anomalies (or very few)
        assert_eq!(report.critical_count, 0);
    }

    #[test]
    fn test_parent_exited_normally_downgraded_to_info() {
        // Simulate real Windows: smss.exe session worker (PID 312) exits after
        // spawning csrss.exe and wininit.exe. Only master smss.exe (PID 100)
        // remains in pslist.
        let procs = vec![
            make_proc(4, 0, "System"),
            make_proc(100, 4, "smss.exe"),        // Master smss
            make_proc(320, 312, "csrss.exe"),      // Parent 312 (smss worker) exited
            make_proc(424, 312, "wininit.exe"),    // Parent 312 (smss worker) exited
            make_proc(368, 360, "csrss.exe"),      // Parent 360 (smss worker) exited
            make_proc(416, 360, "winlogon.exe"),   // Parent 360 (smss worker) exited
            make_proc(500, 424, "services.exe"),
            make_proc(510, 424, "lsass.exe"),
        ];

        let report = analyze(&procs, None, None);

        // csrss/wininit/winlogon with exited smss parents should be info, not critical
        let critical_violations: Vec<_> = report
            .anomalies
            .iter()
            .filter(|a| a.category == "parent_child_violation" && a.severity == Severity::Critical)
            .collect();
        assert_eq!(critical_violations.len(), 0, "Expected no critical violations, got: {:?}",
            critical_violations.iter().map(|a| format!("{} PID {}", a.process_name, a.pid)).collect::<Vec<_>>());

        let info_violations: Vec<_> = report
            .anomalies
            .iter()
            .filter(|a| a.category == "parent_child_violation" && a.severity == Severity::Info)
            .collect();
        assert_eq!(info_violations.len(), 4, "Expected 4 info violations for exited parents");
    }

    #[test]
    fn test_pid_reuse_downgraded_to_info() {
        // Win11 scenario: csrss.exe PID 496 was created by smss worker PID 484.
        // After smss worker exits, PID 484 gets reused by LogonUI.exe (created later).
        let mut csrss = make_proc(496, 484, "csrss.exe");
        csrss.create_time = Some("2024-01-01 00:00:10".to_string());
        let mut logonui = make_proc(484, 400, "LogonUI.exe");
        logonui.create_time = Some("2024-01-01 00:01:00".to_string()); // Created AFTER csrss

        let procs = vec![
            make_proc(4, 0, "System"),
            make_proc(100, 4, "smss.exe"),
            logonui,
            csrss,
        ];

        let report = analyze(&procs, None, None);

        let csrss_violations: Vec<_> = report
            .anomalies
            .iter()
            .filter(|a| a.category == "parent_child_violation" && a.pid == 496)
            .collect();
        assert_eq!(csrss_violations.len(), 1);
        assert_eq!(csrss_violations[0].severity, Severity::Info, "PID reuse should be info");
        assert!(csrss_violations[0].description.contains("PID reuse"));
    }

    #[test]
    fn test_pid_reuse_same_timestamp_sibling_detection() {
        // When child smss.exe exits and its PID is reused within the same second,
        // timestamp comparison can't detect it. Sibling detection catches it:
        // csrss.exe + wininit.exe both share the same PPID → child smss.exe PID reuse.
        let mut csrss = make_proc(500, 450, "csrss.exe");
        csrss.create_time = Some("2024-01-01T00:00:00Z".to_string());
        let mut wininit = make_proc(550, 450, "wininit.exe");
        wininit.create_time = Some("2024-01-01T00:00:00Z".to_string());
        let mut other = make_proc(450, 400, "LogonUI.exe");
        other.create_time = Some("2024-01-01T00:00:00Z".to_string()); // Same timestamp

        let procs = vec![
            make_proc(4, 0, "System"),
            make_proc(100, 4, "smss.exe"),
            csrss,
            wininit,
            other,
        ];

        let report = analyze(&procs, None, None);

        // Both csrss and wininit should be Info, not Critical
        for pid in [500, 550] {
            let violations: Vec<_> = report
                .anomalies
                .iter()
                .filter(|a| a.category == "parent_child_violation" && a.pid == pid)
                .collect();
            assert_eq!(violations.len(), 1, "Expected 1 violation for PID {pid}");
            assert_eq!(
                violations[0].severity, Severity::Info,
                "PID {pid} ({}) should be Info (sibling detection), got {:?}",
                violations[0].process_name, violations[0].severity
            );
        }
    }

    #[test]
    fn test_pid_reuse_terminated_parent_detection() {
        // When the current PID holder is terminated (has exit_time), it signals
        // PID reuse even without timestamp ordering or sibling evidence.
        let mut csrss = make_proc(500, 450, "csrss.exe");
        csrss.create_time = Some("2024-01-01T00:00:00Z".to_string());
        let mut terminated = make_proc(450, 400, "LogonUI.exe");
        terminated.create_time = Some("2024-01-01T00:00:00Z".to_string());
        terminated.exit_time = Some("2024-01-01T00:02:00Z".to_string());

        let procs = vec![
            make_proc(4, 0, "System"),
            make_proc(100, 4, "smss.exe"),
            csrss,
            terminated,
        ];

        let report = analyze(&procs, None, None);

        let violations: Vec<_> = report
            .anomalies
            .iter()
            .filter(|a| a.category == "parent_child_violation" && a.pid == 500)
            .collect();
        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0].severity, Severity::Info,
            "Terminated parent should trigger PID reuse detection"
        );
    }

    #[test]
    fn test_smss_child_of_smss_is_normal() {
        // Master smss.exe creates per-session worker smss.exe instances
        let procs = vec![
            make_proc(4, 0, "System"),
            make_proc(356, 4, "smss.exe"),       // Master
            make_proc(6920, 356, "smss.exe"),    // Session worker — normal
        ];

        let report = analyze(&procs, None, None);

        let smss_violations: Vec<_> = report
            .anomalies
            .iter()
            .filter(|a| a.category == "parent_child_violation" && a.pid == 6920)
            .collect();
        assert_eq!(smss_violations.len(), 0, "smss.exe child of smss.exe should not be a violation");
    }

    #[test]
    fn test_genuine_violation_still_flagged() {
        // lsass.exe started by cmd.exe — this is always suspicious
        let procs = vec![
            make_proc(4, 0, "System"),
            make_proc(100, 4, "smss.exe"),
            make_proc(300, 100, "wininit.exe"),
            make_proc(999, 300, "cmd.exe"),
            make_proc(700, 999, "lsass.exe"), // BAD — parent is cmd.exe, not wininit.exe
        ];

        let report = analyze(&procs, None, None);

        let violations: Vec<_> = report
            .anomalies
            .iter()
            .filter(|a| a.category == "parent_child_violation" && a.pid == 700)
            .collect();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].severity, Severity::Critical, "Real violation should stay critical");
    }

    #[test]
    fn test_explorer_with_exited_userinit_is_info() {
        // userinit.exe exits after launching explorer.exe — parent missing from pslist
        let procs = vec![
            make_proc(4, 0, "System"),
            make_proc(100, 4, "smss.exe"),
            make_proc(1064, 1050, "explorer.exe"), // Parent 1050 (userinit.exe) exited
        ];

        let report = analyze(&procs, None, None);

        let explorer_violations: Vec<_> = report
            .anomalies
            .iter()
            .filter(|a| a.category == "parent_child_violation" && a.pid == 1064)
            .collect();
        assert_eq!(explorer_violations.len(), 1);
        assert_eq!(explorer_violations[0].severity, Severity::Info);
    }
}
