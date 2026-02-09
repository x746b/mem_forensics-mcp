//! Full triage orchestrator — runs all analyzers and correlates findings.
//!
//! This is the primary automated analysis entry point. It:
//! 1. Runs all available plugins (pslist, psscan, cmdline, netscan, cmdscan)
//! 2. Runs all analyzers (process anomalies, network C2)
//! 3. Cross-correlates findings (hidden+c2=rootkit, lsass_child+creds=credential_theft, etc.)
//! 4. Extracts IOCs (suspicious PIDs, IPs, ports, credentials)
//! 5. Computes an overall risk score
//! 6. Generates recommended response actions

use crate::analyzers::{network_analyzer, process_anomalies};
use crate::memory::image::MemoryImage;
use crate::memory::virtual_memory::VirtualMemory;
use crate::plugins::{cmdline, cmdscan, malfind, netscan, pslist, psscan};
use crate::server::types::{InjectedRegion, ProcessInfo};
use isf::IsfSymbols;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tracing::info;

use super::process_anomalies::Severity;

// ── Output types ─────────────────────────────────────────────────────

/// Overall threat level for the memory image.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ThreatLevel {
    /// Active compromise detected (rootkit, C2, credential theft).
    Critical,
    /// Strong indicators of compromise (hidden processes, C2 connections).
    High,
    /// Suspicious activity detected (LOLBin abuse, anomalous processes).
    Medium,
    /// Minor anomalies found (parent-child violations, singleton issues).
    Low,
    /// No significant findings.
    Clean,
}

/// A cross-analyzer correlation finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Correlation {
    pub category: String,
    pub severity: Severity,
    pub description: String,
    pub evidence: Vec<String>,
}

/// Extracted indicator of compromise.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ioc {
    pub ioc_type: String, // "pid", "ip", "port", "credential", "process_name"
    pub value: String,
    pub context: String,
}

/// Recommended response action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub priority: Severity,
    pub action: String,
    pub reason: String,
}

/// Complete triage report.
#[derive(Debug, Serialize, Deserialize)]
pub struct TriageReport {
    /// Overall threat assessment.
    pub threat_level: ThreatLevel,
    /// Numeric risk score (0-100).
    pub risk_score: u32,
    /// Human-readable summary.
    pub summary: String,

    /// Process analysis results.
    pub process_count: usize,
    pub hidden_process_count: usize,
    pub process_anomaly_count: usize,
    pub process_anomalies: process_anomalies::AnomalyReport,

    /// Network analysis results.
    pub connection_count: usize,
    pub flagged_connection_count: usize,
    pub network_report: Option<network_analyzer::C2Report>,

    /// Command history results.
    pub suspicious_command_count: usize,

    /// Injected code detection results.
    pub injected_code_count: usize,
    pub injected_pe_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub injected_regions: Vec<InjectedRegion>,

    /// Cross-analyzer correlations.
    pub correlations: Vec<Correlation>,

    /// Extracted IOCs.
    pub iocs: Vec<Ioc>,

    /// Recommended response actions.
    pub recommended_actions: Vec<Action>,
}

// ── Triage context (internal) ────────────────────────────────────────

/// Internal context accumulated during triage.
struct TriageContext {
    pslist_procs: Vec<ProcessInfo>,
    psscan_procs: Vec<ProcessInfo>,
    #[allow(dead_code)]
    cmdlines: Vec<cmdline::CmdlineInfo>,
    netscan_result: Option<netscan::NetscanResult>,
    cmdscan_hits: usize,
    malfind_regions: Vec<InjectedRegion>,
    anomaly_report: process_anomalies::AnomalyReport,
    c2_report: Option<network_analyzer::C2Report>,
}

// ── Main entry point ─────────────────────────────────────────────────

/// Run a full triage analysis on a memory session.
///
/// This is the top-level orchestrator that runs everything and correlates
/// findings into a single report.
#[allow(dead_code)]
pub fn run(
    symbols: &IsfSymbols,
    image: &MemoryImage,
    kernel_vm: Option<&Arc<VirtualMemory>>,
    kernel_base: Option<u64>,
    scan_chunk_size: usize,
) -> TriageReport {
    run_with_head(symbols, image, kernel_vm, kernel_base, scan_chunk_size, None)
}

/// Like [`run`], but with a PsActiveProcessHead override.
pub fn run_with_head(
    symbols: &IsfSymbols,
    image: &MemoryImage,
    kernel_vm: Option<&Arc<VirtualMemory>>,
    kernel_base: Option<u64>,
    scan_chunk_size: usize,
    ps_head_override: Option<u64>,
) -> TriageReport {
    info!("full_triage: starting comprehensive analysis...");

    // ── Step 1: Run all plugins ──────────────────────────────────────

    // pslist (requires VM)
    let pslist_procs = if let Some(vm) = kernel_vm {
        pslist::run_with_head(symbols, vm.as_ref(), kernel_base, ps_head_override).unwrap_or_default()
    } else {
        Vec::new()
    };
    info!("full_triage: pslist found {} processes", pslist_procs.len());

    // psscan (physical memory)
    let psscan_procs = psscan::run(symbols, image, scan_chunk_size).unwrap_or_default();
    info!("full_triage: psscan found {} processes", psscan_procs.len());

    // cmdline (requires VM)
    let cmdlines = if let Some(vm) = kernel_vm {
        let physical = image.physical_layer();
        cmdline::run_with_head(symbols, vm.as_ref(), physical, kernel_base, None, ps_head_override).unwrap_or_default()
    } else {
        Vec::new()
    };
    info!("full_triage: extracted {} command lines", cmdlines.len());

    // netscan
    let netscan_offsets = crate::plugins::netscan::NetscanOffsets::from_isf(symbols)
        .unwrap_or_else(|| netscan::NetscanOffsets::win10_19041_x64());
    let kernel_vm_access: Option<&dyn isf::MemoryAccess> =
        kernel_vm.map(|vm| vm.as_ref() as &dyn isf::MemoryAccess);
    let netscan_result = netscan::run(symbols, image, kernel_vm_access, &netscan_offsets, scan_chunk_size).ok();
    if let Some(ref nr) = netscan_result {
        info!("full_triage: netscan found {} connections", nr.total);
    }

    // cmdscan
    let cmdscan_result = cmdscan::run(image, scan_chunk_size, 500).ok();
    let cmdscan_hits = cmdscan_result.as_ref().map(|r| r.total_hits).unwrap_or(0);
    info!("full_triage: cmdscan found {} suspicious hits", cmdscan_hits);

    // malfind (requires VM + physical layer)
    let malfind_regions = if let Some(vm) = kernel_vm {
        let physical = image.physical_layer();
        malfind::run(symbols, vm.as_ref(), physical, kernel_base, None, ps_head_override, 200)
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    info!("full_triage: malfind found {} injected regions ({} with PE headers)",
        malfind_regions.len(),
        malfind_regions.iter().filter(|r| r.has_pe_header).count());

    // ── Step 2: Run analyzers ────────────────────────────────────────

    let cmdlines_ref = if cmdlines.is_empty() {
        None
    } else {
        Some(cmdlines.as_slice())
    };

    let anomaly_report = process_anomalies::analyze(
        &pslist_procs,
        Some(&psscan_procs),
        cmdlines_ref,
    );
    info!(
        "full_triage: process analyzer found {} anomalies",
        anomaly_report.total_anomalies
    );

    let c2_report = netscan_result.as_ref().map(|nr| {
        network_analyzer::analyze(&nr.connections, cmdlines_ref)
    });
    if let Some(ref c2) = c2_report {
        info!(
            "full_triage: C2 analyzer flagged {} connections",
            c2.flagged_connections
        );
    }

    // ── Step 3: Build context and correlate ──────────────────────────

    let ctx = TriageContext {
        pslist_procs,
        psscan_procs,
        cmdlines,
        netscan_result,
        cmdscan_hits,
        malfind_regions,
        anomaly_report,
        c2_report,
    };

    let correlations = build_correlations(&ctx);
    let iocs = extract_iocs(&ctx);
    let risk_score = compute_risk_score(&ctx, &correlations);
    let threat_level = threat_level_from_score(risk_score);
    let summary = build_summary(&ctx, &correlations, &threat_level, risk_score);
    let recommended_actions = build_actions(&ctx, &correlations, &threat_level);

    info!(
        "full_triage: complete — threat_level={:?}, risk_score={}, correlations={}, iocs={}",
        threat_level,
        risk_score,
        correlations.len(),
        iocs.len()
    );

    TriageReport {
        threat_level,
        risk_score,
        summary,
        process_count: ctx.pslist_procs.len().max(ctx.psscan_procs.len()),
        hidden_process_count: ctx
            .anomaly_report
            .anomalies
            .iter()
            .filter(|a| a.category == "hidden_process")
            .count(),
        process_anomaly_count: ctx.anomaly_report.total_anomalies,
        process_anomalies: ctx.anomaly_report,
        connection_count: ctx
            .netscan_result
            .as_ref()
            .map(|r| r.total)
            .unwrap_or(0),
        flagged_connection_count: ctx
            .c2_report
            .as_ref()
            .map(|r| r.flagged_connections)
            .unwrap_or(0),
        network_report: ctx.c2_report,
        suspicious_command_count: ctx.cmdscan_hits,
        injected_code_count: ctx.malfind_regions.len(),
        injected_pe_count: ctx.malfind_regions.iter().filter(|r| r.has_pe_header).count(),
        injected_regions: ctx.malfind_regions,
        correlations,
        iocs,
        recommended_actions,
    }
}

// ── Cross-analyzer correlations ──────────────────────────────────────

fn build_correlations(ctx: &TriageContext) -> Vec<Correlation> {
    let mut correlations = Vec::new();

    let has_hidden = ctx
        .anomaly_report
        .anomalies
        .iter()
        .any(|a| a.category == "hidden_process");
    let has_c2 = ctx
        .c2_report
        .as_ref()
        .map(|r| r.critical_count + r.high_count > 0)
        .unwrap_or(false);
    let has_lsass_child = ctx
        .anomaly_report
        .anomalies
        .iter()
        .any(|a| a.category == "lsass_child");
    let has_lolbin = ctx
        .anomaly_report
        .anomalies
        .iter()
        .any(|a| a.category == "lolbin_abuse");
    let has_masquerading = ctx
        .anomaly_report
        .anomalies
        .iter()
        .any(|a| a.category == "name_masquerading");
    let has_suspicious_cmds = ctx.cmdscan_hits > 0;
    let has_injected_pe = ctx.malfind_regions.iter().any(|r| r.has_pe_header);
    let has_injected_code = !ctx.malfind_regions.is_empty();

    // Injected PE header = strong malware indicator
    if has_injected_pe {
        let pe_regions: Vec<String> = ctx
            .malfind_regions
            .iter()
            .filter(|r| r.has_pe_header)
            .map(|r| format!("{} (PID {}) at {:#x}", r.process_name, r.pid, r.vad_start))
            .collect();

        correlations.push(Correlation {
            category: "code_injection".to_string(),
            severity: Severity::Critical,
            description: "PE header (MZ) found in executable+writable private memory — \
                         strong indicator of injected code (DLL injection, process hollowing, or reflective loading)."
                .to_string(),
            evidence: pe_regions,
        });
    }

    // Injected code + C2 = active implant
    if has_injected_code && has_c2 {
        correlations.push(Correlation {
            category: "active_implant".to_string(),
            severity: Severity::Critical,
            description: "Injected code regions combined with C2 network activity — \
                         likely active malware implant (beacon, RAT, or backdoor)."
                .to_string(),
            evidence: vec![
                format!("{} injected code regions detected", ctx.malfind_regions.len()),
                "Active C2 connections flagged".to_string(),
            ],
        });
    }

    // Injected code + hidden process = advanced malware
    if has_injected_code && has_hidden {
        correlations.push(Correlation {
            category: "stealth_injection".to_string(),
            severity: Severity::Critical,
            description: "Injected code alongside hidden processes — \
                         advanced malware using both process hiding and code injection."
                .to_string(),
            evidence: vec![
                format!("{} injected code regions", ctx.malfind_regions.len()),
                "Hidden process(es) detected via psscan".to_string(),
            ],
        });
    }

    // Hidden process + C2 = rootkit behavior
    if has_hidden && has_c2 {
        let hidden_names: Vec<String> = ctx
            .anomaly_report
            .anomalies
            .iter()
            .filter(|a| a.category == "hidden_process")
            .map(|a| format!("{} (PID {})", a.process_name, a.pid))
            .collect();

        correlations.push(Correlation {
            category: "rootkit".to_string(),
            severity: Severity::Critical,
            description: "Hidden process(es) detected alongside C2 network activity — \
                         strong indicator of rootkit or advanced persistent threat."
                .to_string(),
            evidence: vec![
                format!("Hidden processes: {}", hidden_names.join(", ")),
                "Active C2 connections flagged".to_string(),
            ],
        });
    }

    // lsass child + credential extraction = active credential theft
    if has_lsass_child {
        let child_names: Vec<String> = ctx
            .anomaly_report
            .anomalies
            .iter()
            .filter(|a| a.category == "lsass_child")
            .map(|a| format!("{} (PID {})", a.process_name, a.pid))
            .collect();

        let evidence = vec![format!("LSASS children: {}", child_names.join(", "))];

        correlations.push(Correlation {
            category: "credential_theft".to_string(),
            severity: Severity::Critical,
            description: "Process spawned under lsass.exe — active credential dumping \
                         (mimikatz/procdump behavior)."
                .to_string(),
            evidence,
        });
    }

    // Hidden process + name masquerading = evasion
    if has_hidden && has_masquerading {
        correlations.push(Correlation {
            category: "evasion".to_string(),
            severity: Severity::Critical,
            description: "Hidden processes combined with name masquerading — \
                         sophisticated evasion technique."
                .to_string(),
            evidence: vec![
                "Hidden process detected via psscan".to_string(),
                "Process name masquerading detected".to_string(),
            ],
        });
    }

    // LOLBin abuse + C2 = living-off-the-land attack
    if has_lolbin && has_c2 {
        correlations.push(Correlation {
            category: "lotl_attack".to_string(),
            severity: Severity::High,
            description: "LOLBin abuse detected alongside C2 activity — \
                         living-off-the-land attack pattern."
                .to_string(),
            evidence: vec![
                "LOLBin process with suspicious arguments".to_string(),
                "C2-indicative network connections".to_string(),
            ],
        });
    }

    // LOLBin + suspicious commands = staged execution
    if has_lolbin && has_suspicious_cmds {
        correlations.push(Correlation {
            category: "staged_execution".to_string(),
            severity: Severity::High,
            description: "LOLBin abuse with suspicious command history — \
                         likely staged/scripted attack."
                .to_string(),
            evidence: vec![
                "LOLBin with suspicious arguments".to_string(),
                format!("{} suspicious command fragments in memory", ctx.cmdscan_hits),
            ],
        });
    }

    // C2 + suspicious commands = active C2 session
    if has_c2 && has_suspicious_cmds {
        correlations.push(Correlation {
            category: "active_c2_session".to_string(),
            severity: Severity::Critical,
            description: "C2 network connections with suspicious commands in memory — \
                         active command-and-control session."
                .to_string(),
            evidence: vec![
                "C2 connections detected".to_string(),
                format!("{} suspicious command fragments found", ctx.cmdscan_hits),
            ],
        });
    }

    // Sort by severity
    correlations.sort_by(|a, b| a.severity.cmp(&b.severity));
    correlations
}

// ── IOC extraction ───────────────────────────────────────────────────

fn extract_iocs(ctx: &TriageContext) -> Vec<Ioc> {
    let mut iocs = Vec::new();
    let mut seen = HashSet::new();

    // Hidden process PIDs
    for anomaly in &ctx.anomaly_report.anomalies {
        if anomaly.category == "hidden_process" {
            let key = format!("pid:{}", anomaly.pid);
            if seen.insert(key) {
                iocs.push(Ioc {
                    ioc_type: "pid".to_string(),
                    value: anomaly.pid.to_string(),
                    context: format!("Hidden process: {} (PID {})", anomaly.process_name, anomaly.pid),
                });
            }
        }
    }

    // LSASS child PIDs
    for anomaly in &ctx.anomaly_report.anomalies {
        if anomaly.category == "lsass_child" {
            let key = format!("pid:{}", anomaly.pid);
            if seen.insert(key) {
                iocs.push(Ioc {
                    ioc_type: "pid".to_string(),
                    value: anomaly.pid.to_string(),
                    context: format!("LSASS child: {} (PID {})", anomaly.process_name, anomaly.pid),
                });
            }
        }
    }

    // Masquerading process names
    for anomaly in &ctx.anomaly_report.anomalies {
        if anomaly.category == "name_masquerading" {
            let key = format!("name:{}", anomaly.process_name.to_lowercase());
            if seen.insert(key) {
                iocs.push(Ioc {
                    ioc_type: "process_name".to_string(),
                    value: anomaly.process_name.clone(),
                    context: "Process name masquerading".to_string(),
                });
            }
        }
    }

    // Injected code PIDs
    for region in &ctx.malfind_regions {
        if region.has_pe_header {
            let key = format!("injection:{}:{:#x}", region.pid, region.vad_start);
            if seen.insert(key) {
                iocs.push(Ioc {
                    ioc_type: "pid".to_string(),
                    value: region.pid.to_string(),
                    context: format!(
                        "Injected PE in {} (PID {}) at {:#x}-{:#x} ({})",
                        region.process_name, region.pid, region.vad_start, region.vad_end, region.protection
                    ),
                });
            }
        }
    }

    // C2 IPs and ports
    if let Some(ref c2) = ctx.c2_report {
        for scored in &c2.flagged {
            if scored.severity == Severity::Critical || scored.severity == Severity::High {
                let conn = &scored.connection;

                // Remote IP
                if conn.remote_addr != "*"
                    && conn.remote_addr != "0.0.0.0"
                    && conn.remote_addr != "::"
                    && !conn.remote_addr.is_empty()
                {
                    let key = format!("ip:{}", conn.remote_addr);
                    if seen.insert(key) {
                        iocs.push(Ioc {
                            ioc_type: "ip".to_string(),
                            value: conn.remote_addr.clone(),
                            context: format!(
                                "C2 connection from {} (PID {}) to {}:{}",
                                conn.process_name.as_deref().unwrap_or("?"),
                                conn.pid,
                                conn.remote_addr,
                                conn.remote_port
                            ),
                        });
                    }
                }

                // Suspicious ports
                if conn.remote_port > 0 {
                    let key = format!("port:{}", conn.remote_port);
                    if seen.insert(key) {
                        if crate::rules::suspicious_ports::find_suspicious_port(conn.remote_port)
                            .is_some()
                        {
                            iocs.push(Ioc {
                                ioc_type: "port".to_string(),
                                value: conn.remote_port.to_string(),
                                context: format!("Suspicious remote port {}", conn.remote_port),
                            });
                        }
                    }
                }

                if conn.local_port > 0 {
                    let key = format!("port:{}", conn.local_port);
                    if seen.insert(key) {
                        if crate::rules::suspicious_ports::find_suspicious_port(conn.local_port)
                            .is_some()
                        {
                            iocs.push(Ioc {
                                ioc_type: "port".to_string(),
                                value: conn.local_port.to_string(),
                                context: format!("Suspicious local port {}", conn.local_port),
                            });
                        }
                    }
                }
            }
        }
    }

    iocs
}

// ── Risk scoring ─────────────────────────────────────────────────────

fn compute_risk_score(ctx: &TriageContext, correlations: &[Correlation]) -> u32 {
    let mut score: u32 = 0;

    // Process anomalies
    score += ctx.anomaly_report.critical_count as u32 * 25;
    score += ctx.anomaly_report.high_count as u32 * 15;
    score += ctx.anomaly_report.medium_count as u32 * 8;
    score += ctx.anomaly_report.low_count as u32 * 3;

    // Network findings
    if let Some(ref c2) = ctx.c2_report {
        score += c2.critical_count as u32 * 20;
        score += c2.high_count as u32 * 12;
        score += c2.medium_count as u32 * 5;
    }

    // Command history
    if ctx.cmdscan_hits > 0 {
        score += (ctx.cmdscan_hits as u32).min(20) * 2;
    }

    // Injected code
    let pe_injections = ctx.malfind_regions.iter().filter(|r| r.has_pe_header).count() as u32;
    let rwx_regions = ctx.malfind_regions.len() as u32;
    score += pe_injections * 20;       // PE in RWX = very suspicious
    score += rwx_regions.min(10) * 2;  // RWX regions add moderate risk

    // Correlations amplify the score
    for corr in correlations {
        match corr.severity {
            Severity::Critical => score += 20,
            Severity::High => score += 10,
            Severity::Medium => score += 5,
            _ => {}
        }
    }

    score.min(100)
}

fn threat_level_from_score(score: u32) -> ThreatLevel {
    match score {
        0..=5 => ThreatLevel::Clean,
        6..=20 => ThreatLevel::Low,
        21..=45 => ThreatLevel::Medium,
        46..=70 => ThreatLevel::High,
        _ => ThreatLevel::Critical,
    }
}

// ── Summary generation ───────────────────────────────────────────────

fn build_summary(
    ctx: &TriageContext,
    correlations: &[Correlation],
    threat_level: &ThreatLevel,
    risk_score: u32,
) -> String {
    let mut parts = Vec::new();

    parts.push(format!(
        "Threat Level: {:?} (score {}/100)",
        threat_level, risk_score
    ));

    let proc_count = ctx.pslist_procs.len().max(ctx.psscan_procs.len());
    parts.push(format!("Processes: {} found", proc_count));

    if ctx.anomaly_report.total_anomalies > 0 {
        parts.push(format!(
            "Process Anomalies: {} ({} critical, {} high)",
            ctx.anomaly_report.total_anomalies,
            ctx.anomaly_report.critical_count,
            ctx.anomaly_report.high_count
        ));
    }

    if let Some(ref c2) = ctx.c2_report {
        if c2.flagged_connections > 0 {
            parts.push(format!(
                "Network: {} flagged of {} connections ({} critical)",
                c2.flagged_connections, c2.total_connections, c2.critical_count
            ));
        } else {
            parts.push(format!(
                "Network: {} connections, none flagged",
                c2.total_connections
            ));
        }
    }

    if ctx.cmdscan_hits > 0 {
        parts.push(format!(
            "Commands: {} suspicious fragments",
            ctx.cmdscan_hits
        ));
    }

    if !ctx.malfind_regions.is_empty() {
        let pe_count = ctx.malfind_regions.iter().filter(|r| r.has_pe_header).count();
        if pe_count > 0 {
            parts.push(format!(
                "Injected Code: {} regions ({} with PE headers)",
                ctx.malfind_regions.len(), pe_count
            ));
        } else {
            parts.push(format!(
                "Injected Code: {} RWX regions (no PE headers)",
                ctx.malfind_regions.len()
            ));
        }
    }

    if !correlations.is_empty() {
        let corr_names: Vec<&str> = correlations.iter().map(|c| c.category.as_str()).collect();
        parts.push(format!(
            "Correlations: {} ({})",
            correlations.len(),
            corr_names.join(", ")
        ));
    }

    parts.join(". ")
}

// ── Recommended actions ──────────────────────────────────────────────

fn build_actions(
    ctx: &TriageContext,
    correlations: &[Correlation],
    threat_level: &ThreatLevel,
) -> Vec<Action> {
    let mut actions = Vec::new();

    let has_hidden = ctx
        .anomaly_report
        .anomalies
        .iter()
        .any(|a| a.category == "hidden_process");
    let has_c2 = ctx
        .c2_report
        .as_ref()
        .map(|r| r.critical_count + r.high_count > 0)
        .unwrap_or(false);
    let has_lsass_child = ctx
        .anomaly_report
        .anomalies
        .iter()
        .any(|a| a.category == "lsass_child");
    let has_rootkit = correlations.iter().any(|c| c.category == "rootkit");
    let has_injected_pe = ctx.malfind_regions.iter().any(|r| r.has_pe_header);

    // Critical actions
    if has_rootkit {
        actions.push(Action {
            priority: Severity::Critical,
            action: "ISOLATE HOST IMMEDIATELY".to_string(),
            reason: "Rootkit behavior detected (hidden process + C2). \
                    Network isolation required to prevent lateral movement."
                .to_string(),
        });
    }

    if has_lsass_child {
        actions.push(Action {
            priority: Severity::Critical,
            action: "Reset all domain credentials".to_string(),
            reason: "Active credential dumping detected (LSASS child process). \
                    Assume all credentials on this host are compromised."
                .to_string(),
        });
    }

    if has_c2 {
        actions.push(Action {
            priority: Severity::Critical,
            action: "Block C2 IPs at firewall".to_string(),
            reason: "Active C2 connections detected. Block identified remote IPs \
                    and monitor for re-establishment attempts."
                .to_string(),
        });
    }

    if has_injected_pe {
        let affected: Vec<String> = ctx
            .malfind_regions
            .iter()
            .filter(|r| r.has_pe_header)
            .map(|r| format!("{} (PID {})", r.process_name, r.pid))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        actions.push(Action {
            priority: Severity::Critical,
            action: "Investigate injected PE modules".to_string(),
            reason: format!(
                "PE headers found in RWX private memory of: {}. \
                 Dump injected regions for malware analysis.",
                affected.join(", ")
            ),
        });
    }

    // High actions
    if has_hidden {
        actions.push(Action {
            priority: Severity::High,
            action: "Perform full disk forensic acquisition".to_string(),
            reason: "Hidden processes indicate advanced malware. \
                    Preserve disk evidence before remediation."
                .to_string(),
        });
    }

    if ctx
        .anomaly_report
        .anomalies
        .iter()
        .any(|a| a.category == "lolbin_abuse")
    {
        actions.push(Action {
            priority: Severity::High,
            action: "Review LOLBin execution and restrict via AppLocker/WDAC".to_string(),
            reason: "LOLBin abuse detected. Investigate execution chain and \
                    consider application whitelisting."
                .to_string(),
        });
    }

    // Medium actions
    if ctx.cmdscan_hits > 5 {
        actions.push(Action {
            priority: Severity::Medium,
            action: "Review suspicious command history in detail".to_string(),
            reason: format!(
                "{} suspicious command fragments found. \
                 Manual review needed to determine attacker activity.",
                ctx.cmdscan_hits
            ),
        });
    }

    // General recommendations
    if *threat_level != ThreatLevel::Clean {
        actions.push(Action {
            priority: Severity::Low,
            action: "Scan all endpoints with updated AV signatures".to_string(),
            reason: "Indicators of compromise detected. \
                    Sweep other hosts for similar artifacts."
                .to_string(),
        });
    }

    // Sort by priority
    actions.sort_by(|a, b| a.priority.cmp(&b.priority));
    actions
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::network_analyzer::{C2Report, ScoredConnection};
    use crate::plugins::netscan::NetworkConnection;

    fn make_anomaly(category: &str, severity: Severity, pid: u64, name: &str) -> process_anomalies::Anomaly {
        process_anomalies::Anomaly {
            category: category.to_string(),
            severity,
            pid,
            process_name: name.to_string(),
            description: format!("test anomaly: {}", category),
            parent_pid: None,
            parent_name: None,
            cmdline: None,
        }
    }

    fn make_anomaly_report(anomalies: Vec<process_anomalies::Anomaly>) -> process_anomalies::AnomalyReport {
        let critical_count = anomalies.iter().filter(|a| a.severity == Severity::Critical).count();
        let high_count = anomalies.iter().filter(|a| a.severity == Severity::High).count();
        let medium_count = anomalies.iter().filter(|a| a.severity == Severity::Medium).count();
        let low_count = anomalies.iter().filter(|a| a.severity == Severity::Low).count();
        process_anomalies::AnomalyReport {
            total_anomalies: anomalies.len(),
            critical_count,
            high_count,
            medium_count,
            low_count,
            anomalies,
            process_tree: Vec::new(),
        }
    }

    fn make_c2_report(critical: usize, high: usize) -> C2Report {
        let mut flagged = Vec::new();
        for _ in 0..critical {
            flagged.push(ScoredConnection {
                severity: Severity::Critical,
                indicators: vec!["test".to_string()],
                connection: NetworkConnection {
                    protocol: "TCPv4".to_string(),
                    local_addr: "0.0.0.0".to_string(),
                    local_port: 4444,
                    remote_addr: "203.0.113.1".to_string(),
                    remote_port: 4444,
                    state: Some("ESTABLISHED".to_string()),
                    pid: 666,
                    process_name: Some("evil.exe".to_string()),
                    offset: 0,
                    create_time: None,
                    address_family: None,
                },
            });
        }
        for _ in 0..high {
            flagged.push(ScoredConnection {
                severity: Severity::High,
                indicators: vec!["test".to_string()],
                connection: NetworkConnection {
                    protocol: "TCPv4".to_string(),
                    local_addr: "0.0.0.0".to_string(),
                    local_port: 1337,
                    remote_addr: "198.51.100.1".to_string(),
                    remote_port: 1337,
                    state: Some("ESTABLISHED".to_string()),
                    pid: 777,
                    process_name: Some("beacon.exe".to_string()),
                    offset: 0,
                    create_time: None,
                    address_family: None,
                },
            });
        }
        C2Report {
            total_connections: 10,
            flagged_connections: flagged.len(),
            critical_count: critical,
            high_count: high,
            medium_count: 0,
            low_count: 0,
            flagged,
        }
    }

    #[test]
    fn test_rootkit_correlation() {
        let ctx = TriageContext {
            pslist_procs: Vec::new(),
            psscan_procs: Vec::new(),
            cmdlines: Vec::new(),
            netscan_result: None,
            cmdscan_hits: 0,
            malfind_regions: Vec::new(),

            anomaly_report: make_anomaly_report(vec![
                make_anomaly("hidden_process", Severity::Critical, 666, "evil.exe"),
            ]),
            c2_report: Some(make_c2_report(1, 0)),
        };

        let correlations = build_correlations(&ctx);
        assert!(correlations.iter().any(|c| c.category == "rootkit"));
    }

    #[test]
    fn test_credential_theft_correlation() {
        let ctx = TriageContext {
            pslist_procs: Vec::new(),
            psscan_procs: Vec::new(),
            cmdlines: Vec::new(),
            netscan_result: None,
            cmdscan_hits: 0,
            malfind_regions: Vec::new(),
            anomaly_report: make_anomaly_report(vec![
                make_anomaly("lsass_child", Severity::Critical, 999, "procdump.exe"),
            ]),
            c2_report: None,
        };

        let correlations = build_correlations(&ctx);
        assert!(correlations.iter().any(|c| c.category == "credential_theft"));
    }

    #[test]
    fn test_lotl_attack_correlation() {
        let ctx = TriageContext {
            pslist_procs: Vec::new(),
            psscan_procs: Vec::new(),
            cmdlines: Vec::new(),
            netscan_result: None,
            cmdscan_hits: 0,
            malfind_regions: Vec::new(),
            anomaly_report: make_anomaly_report(vec![
                make_anomaly("lolbin_abuse", Severity::High, 1000, "powershell.exe"),
            ]),
            c2_report: Some(make_c2_report(1, 0)),
        };

        let correlations = build_correlations(&ctx);
        assert!(correlations.iter().any(|c| c.category == "lotl_attack"));
    }

    #[test]
    fn test_clean_system_no_correlations() {
        let ctx = TriageContext {
            pslist_procs: Vec::new(),
            psscan_procs: Vec::new(),
            cmdlines: Vec::new(),
            netscan_result: None,
            cmdscan_hits: 0,
            malfind_regions: Vec::new(),
            anomaly_report: make_anomaly_report(Vec::new()),
            c2_report: Some(C2Report {
                total_connections: 5,
                flagged_connections: 0,
                critical_count: 0,
                high_count: 0,
                medium_count: 0,
                low_count: 0,
                flagged: Vec::new(),
            }),
        };

        let correlations = build_correlations(&ctx);
        assert!(correlations.is_empty());
    }

    #[test]
    fn test_risk_scoring() {
        // Clean system
        let ctx_clean = TriageContext {
            pslist_procs: Vec::new(),
            psscan_procs: Vec::new(),
            cmdlines: Vec::new(),
            netscan_result: None,
            cmdscan_hits: 0,
            malfind_regions: Vec::new(),
            anomaly_report: make_anomaly_report(Vec::new()),
            c2_report: None,
        };
        assert_eq!(compute_risk_score(&ctx_clean, &[]), 0);
        assert_eq!(threat_level_from_score(0), ThreatLevel::Clean);

        // Compromised system
        let ctx_bad = TriageContext {
            pslist_procs: Vec::new(),
            psscan_procs: Vec::new(),
            cmdlines: Vec::new(),
            netscan_result: None,
            cmdscan_hits: 10,
            malfind_regions: Vec::new(),
            anomaly_report: make_anomaly_report(vec![
                make_anomaly("hidden_process", Severity::Critical, 666, "evil.exe"),
                make_anomaly("lsass_child", Severity::Critical, 999, "dump.exe"),
            ]),
            c2_report: Some(make_c2_report(2, 1)),
        };

        let corrs = build_correlations(&ctx_bad);
        let score = compute_risk_score(&ctx_bad, &corrs);
        assert!(score >= 70, "expected score >= 70, got {}", score);
        assert_eq!(threat_level_from_score(score), ThreatLevel::Critical);
    }

    #[test]
    fn test_ioc_extraction() {
        let ctx = TriageContext {
            pslist_procs: Vec::new(),
            psscan_procs: Vec::new(),
            cmdlines: Vec::new(),
            netscan_result: None,
            cmdscan_hits: 0,
            malfind_regions: Vec::new(),
            anomaly_report: make_anomaly_report(vec![
                make_anomaly("hidden_process", Severity::Critical, 666, "evil.exe"),
                make_anomaly("name_masquerading", Severity::High, 777, "svch0st.exe"),
            ]),
            c2_report: Some(make_c2_report(1, 0)),
        };

        let iocs = extract_iocs(&ctx);
        assert!(iocs.iter().any(|i| i.ioc_type == "pid" && i.value == "666"));
        assert!(iocs.iter().any(|i| i.ioc_type == "process_name" && i.value == "svch0st.exe"));
        assert!(iocs.iter().any(|i| i.ioc_type == "ip" && i.value == "203.0.113.1"));
    }

    #[test]
    fn test_recommended_actions_rootkit() {
        let ctx = TriageContext {
            pslist_procs: Vec::new(),
            psscan_procs: Vec::new(),
            cmdlines: Vec::new(),
            netscan_result: None,
            cmdscan_hits: 0,
            malfind_regions: Vec::new(),
            anomaly_report: make_anomaly_report(vec![
                make_anomaly("hidden_process", Severity::Critical, 666, "evil.exe"),
            ]),
            c2_report: Some(make_c2_report(1, 0)),
        };

        let correlations = build_correlations(&ctx);
        let actions = build_actions(&ctx, &correlations, &ThreatLevel::Critical);

        assert!(actions.iter().any(|a| a.action.contains("ISOLATE")));
        assert!(actions.iter().any(|a| a.action.contains("Block C2")));
    }

    #[test]
    fn test_summary_generation() {
        let ctx = TriageContext {
            pslist_procs: vec![ProcessInfo {
                pid: 4,
                ppid: 0,
                name: "System".to_string(),
                offset: 0,
                create_time: None,
                exit_time: None,
                threads: None,
                handles: None,
                session_id: None,
                wow64: None,
            }],
            psscan_procs: Vec::new(),
            cmdlines: Vec::new(),
            netscan_result: None,
            cmdscan_hits: 0,
            malfind_regions: Vec::new(),
            anomaly_report: make_anomaly_report(Vec::new()),
            c2_report: None,
        };

        let summary = build_summary(&ctx, &[], &ThreatLevel::Clean, 0);
        assert!(summary.contains("Clean"));
        assert!(summary.contains("Processes: 1"));
    }
}
