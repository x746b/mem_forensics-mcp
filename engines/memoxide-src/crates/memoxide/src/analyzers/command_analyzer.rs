//! Structured command-line analyzer — pattern-match PEB cmdlines against suspicious patterns.
//!
//! Layer 1 of two-layer command analysis: high-confidence findings from structured
//! process command lines (from PEB via cmdline plugin), as opposed to the raw memory
//! scan in cmdscan.rs (Layer 2).

use crate::plugins::cmdline::CmdlineInfo;
use crate::rules::command_patterns::{CommandSeverity, COMMAND_PATTERNS};
use super::process_anomalies::Severity;
use serde::{Deserialize, Serialize};

/// System processes to skip — their cmdlines inherently contain pattern-matching
/// strings but are OS processes, not attacker activity.
const SYSTEM_PROCESS_NAMES: &[&str] = &[
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "lsm.exe",
    "winlogon.exe",
];

/// A structured command finding from a process's PEB command line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandFinding {
    pub pid: u64,
    pub process_name: String,
    /// Truncated to 200 chars.
    pub command: String,
    pub severity: Severity,
    pub indicators: Vec<CommandIndicator>,
}

/// A single pattern match within a command line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandIndicator {
    pub category: String,
    pub severity: Severity,
    pub description: String,
}

fn map_severity(cs: CommandSeverity) -> Severity {
    match cs {
        CommandSeverity::Critical => Severity::Critical,
        CommandSeverity::High => Severity::High,
        CommandSeverity::Medium => Severity::Medium,
        CommandSeverity::Low => Severity::Low,
    }
}

/// Check if there is a word boundary before `pos` in `haystack`.
/// Reuses the same logic as cmdscan for short needles.
fn has_word_boundary_before(haystack: &[u8], pos: usize) -> bool {
    if pos == 0 {
        return true;
    }
    let b = haystack[pos - 1];
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0 | b'|' | b';' | b'"' | b'\'' | b'(' | b')')
}

/// Analyze structured command lines against suspicious patterns.
///
/// Returns at most 50 findings, sorted by severity (Critical first).
pub fn analyze(cmdlines: &[CmdlineInfo]) -> Vec<CommandFinding> {
    let mut findings = Vec::new();

    for info in cmdlines {
        // Skip empty/error cmdlines
        if info.cmdline.is_empty() || info.cmdline.starts_with("<error:") {
            continue;
        }

        // Skip system processes
        let name_lower = info.name.to_lowercase();
        if SYSTEM_PROCESS_NAMES.iter().any(|&s| s == name_lower) {
            continue;
        }

        let cmdline_lower = info.cmdline.to_lowercase();
        let cmdline_bytes = cmdline_lower.as_bytes();
        let mut indicators = Vec::new();

        for pat in COMMAND_PATTERNS {
            let needle = pat.needle.to_lowercase();

            // Find substring match (case-insensitive via pre-lowered strings)
            if let Some(pos) = cmdline_lower.find(&needle) {
                // For short needles, require word boundary
                if needle.len() < 6 && !has_word_boundary_before(cmdline_bytes, pos) {
                    continue;
                }

                indicators.push(CommandIndicator {
                    category: pat.category.to_string(),
                    severity: map_severity(pat.severity),
                    description: pat.description.to_string(),
                });
            }
        }

        if indicators.is_empty() {
            continue;
        }

        // Overall severity = highest across all matched indicators
        let highest = indicators
            .iter()
            .map(|i| &i.severity)
            .min() // Severity enum: Critical < High < Medium < Low (Ord)
            .cloned()
            .unwrap_or(Severity::Low);

        let command = if info.cmdline.len() > 200 {
            format!("{}...", &info.cmdline[..197])
        } else {
            info.cmdline.clone()
        };

        findings.push(CommandFinding {
            pid: info.pid,
            process_name: info.name.clone(),
            command,
            severity: highest,
            indicators,
        });
    }

    // Sort by severity (Critical first — Ord on Severity: Critical < High < ...)
    findings.sort_by(|a, b| a.severity.cmp(&b.severity));
    findings.truncate(50);
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmdline(pid: u64, name: &str, cmdline: &str) -> CmdlineInfo {
        CmdlineInfo {
            pid,
            name: name.to_string(),
            cmdline: cmdline.to_string(),
            image_path: None,
        }
    }

    #[test]
    fn test_mimikatz_detected() {
        let cmdlines = vec![make_cmdline(
            1000,
            "cmd.exe",
            "cmd.exe /c mimikatz.exe privilege::debug",
        )];
        let findings = analyze(&cmdlines);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0]
            .indicators
            .iter()
            .any(|i| i.category == "cred_dumping"));
    }

    #[test]
    fn test_system_processes_skipped() {
        let cmdlines = vec![
            make_cmdline(4, "System", ""),
            make_cmdline(500, "svchost.exe", "svchost.exe -k netsvcs"),
            make_cmdline(600, "lsass.exe", "lsass.exe"),
        ];
        let findings = analyze(&cmdlines);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_powershell_encoded() {
        let cmdlines = vec![make_cmdline(
            2000,
            "powershell.exe",
            "powershell.exe -enc SQBFAFgA",
        )];
        let findings = analyze(&cmdlines);
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .indicators
            .iter()
            .any(|i| i.category == "powershell_encoded"));
    }

    #[test]
    fn test_short_needle_word_boundary() {
        // "-enc" inside "content-encoding" should NOT match
        let cmdlines = vec![make_cmdline(
            3000,
            "app.exe",
            "app.exe --content-encoding gzip",
        )];
        let findings = analyze(&cmdlines);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_multiple_indicators_single_finding() {
        let cmdlines = vec![make_cmdline(
            4000,
            "powershell.exe",
            "powershell.exe -enc downloadstring mimikatz",
        )];
        let findings = analyze(&cmdlines);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].indicators.len() >= 3);
        assert_eq!(findings[0].severity, Severity::Critical); // mimikatz is Critical
    }

    #[test]
    fn test_empty_cmdlines() {
        let cmdlines = vec![
            make_cmdline(1, "idle.exe", ""),
            make_cmdline(2, "broken.exe", "<error: read failed>"),
        ];
        let findings = analyze(&cmdlines);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_truncation() {
        let long_cmd = format!("cmd.exe /c mimikatz {}", "A".repeat(300));
        let cmdlines = vec![make_cmdline(5000, "cmd.exe", &long_cmd)];
        let findings = analyze(&cmdlines);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].command.len() <= 200);
        assert!(findings[0].command.ends_with("..."));
    }
}
