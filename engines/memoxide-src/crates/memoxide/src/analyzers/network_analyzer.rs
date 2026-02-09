//! Network analyzer — correlate netscan output into C2-focused findings.
//!
//! Heuristics are intentionally simple and explainable:
//! - Suspicious ports (known C2/RAT/mining/backdoor defaults)
//! - LOLBin network activity (especially with suspicious arguments)
//! - System processes with unusual remote connections

use crate::analyzers::process_anomalies::Severity;
use crate::plugins::cmdline::CmdlineInfo;
use crate::plugins::netscan::NetworkConnection;
use crate::rules::{lolbins, suspicious_ports};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A scored/annotated connection with human-readable indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoredConnection {
    pub severity: Severity,
    pub indicators: Vec<String>,
    pub connection: NetworkConnection,
}

/// Output of the C2 network analyzer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Report {
    pub total_connections: usize,
    pub flagged_connections: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub flagged: Vec<ScoredConnection>,
}

pub fn analyze(connections: &[NetworkConnection], cmdlines: Option<&[CmdlineInfo]>) -> C2Report {
    let cmdline_by_pid: HashMap<u64, &str> = cmdlines
        .unwrap_or(&[])
        .iter()
        .map(|c| (c.pid, c.cmdline.as_str()))
        .collect();

    let mut flagged = Vec::new();

    for c in connections {
        let mut severity: Option<Severity> = None;
        let mut indicators = Vec::new();

        // 1) Known suspicious ports: local or remote.
        for (which, port) in [("local", c.local_port), ("remote", c.remote_port)] {
            if port == 0 {
                continue;
            }
            if let Some(sp) = suspicious_ports::find_suspicious_port(port) {
                let s = map_port_severity(sp.severity);
                severity = max_severity(severity, s);
                indicators.push(format!(
                    "suspicious_{}_port={} severity={:?} category={} ({})",
                    which, port, sp.severity, sp.category, sp.description
                ));
            }
        }

        // 2) Listener on a suspicious port.
        if c.state.as_deref() == Some("LISTENING") {
            if suspicious_ports::find_suspicious_port(c.local_port).is_some() {
                severity = max_severity(severity, Severity::High);
                indicators.push("listening_on_suspicious_port".to_string());
            }
        }

        // 3) LOLBin network activity (process name + optional cmdline indicators).
        if let Some(pname) = c.process_name.as_deref() {
            if let Some(entry) = lolbins::find_lolbin(pname) {
                // Only meaningful if there is a remote endpoint (best-effort).
                if is_remote_endpoint_present(c) {
                    severity = max_severity(severity, Severity::Medium);
                    indicators.push(format!(
                        "lolbin_network_activity name={} category={:?} ({})",
                        entry.name, entry.category, entry.description
                    ));

                    if let Some(cmd) = cmdline_by_pid.get(&c.pid).copied() {
                        let matches = lolbins::check_suspicious_args(pname, cmd);
                        if !matches.is_empty() {
                            severity = max_severity(severity, Severity::High);
                            indicators.push(format!(
                                "lolbin_suspicious_args patterns={}",
                                matches.join(",")
                            ));
                        }
                    }
                }
            }
        }

        // 4) High-value/system processes with unusual remote endpoints.
        if let Some(pname) = c.process_name.as_deref() {
            if is_high_value_process(pname) && is_remote_endpoint_present(c) {
                // If the remote looks public, raise.
                if remote_looks_public(&c.remote_addr) {
                    severity = max_severity(severity, Severity::High);
                    indicators.push(format!(
                        "high_value_process_remote_connection process={}",
                        pname
                    ));
                } else {
                    severity = max_severity(severity, Severity::Low);
                    indicators.push(format!(
                        "high_value_process_connection process={}",
                        pname
                    ));
                }
            }
        }

        if let Some(sev) = severity {
            flagged.push(ScoredConnection {
                severity: sev,
                indicators,
                connection: c.clone(),
            });
        }
    }

    // Sort most severe first.
    flagged.sort_by(|a, b| b.severity.cmp(&a.severity));

    let critical_count = flagged
        .iter()
        .filter(|x| x.severity == Severity::Critical)
        .count();
    let high_count = flagged.iter().filter(|x| x.severity == Severity::High).count();
    let medium_count = flagged
        .iter()
        .filter(|x| x.severity == Severity::Medium)
        .count();
    let low_count = flagged.iter().filter(|x| x.severity == Severity::Low).count();

    C2Report {
        total_connections: connections.len(),
        flagged_connections: flagged.len(),
        critical_count,
        high_count,
        medium_count,
        low_count,
        flagged,
    }
}

fn map_port_severity(s: suspicious_ports::PortSeverity) -> Severity {
    match s {
        suspicious_ports::PortSeverity::Critical => Severity::Critical,
        suspicious_ports::PortSeverity::High => Severity::High,
        suspicious_ports::PortSeverity::Medium => Severity::Medium,
        suspicious_ports::PortSeverity::Low => Severity::Low,
    }
}

fn max_severity(cur: Option<Severity>, next: Severity) -> Option<Severity> {
    match cur {
        None => Some(next),
        Some(c) => Some(if next > c { next } else { c }),
    }
}

fn is_remote_endpoint_present(c: &NetworkConnection) -> bool {
    if c.remote_port == 0 {
        return false;
    }
    let r = c.remote_addr.as_str();
    !(r == "*" || r == "0.0.0.0" || r == "::" || r.is_empty())
}

fn is_high_value_process(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "lsass.exe"
            | "winlogon.exe"
            | "services.exe"
            | "csrss.exe"
            | "svchost.exe"
            | "explorer.exe"
    )
}

fn remote_looks_public(remote: &str) -> bool {
    let ip = match parse_ip(remote) {
        Some(ip) => ip,
        None => return false,
    };
    match ip {
        IpAddr::V4(v4) => is_public_ipv4(v4),
        IpAddr::V6(v6) => is_public_ipv6(v6),
    }
}

fn parse_ip(s: &str) -> Option<IpAddr> {
    // Some sources include brackets or scope ids; handle the common cases.
    let trimmed = s.trim().trim_matches('[').trim_matches(']');
    let trimmed = match trimmed.split('%').next() {
        Some(v) => v,
        None => trimmed,
    };
    trimmed.parse::<IpAddr>().ok()
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_link_local() {
        return false;
    }
    // RFC1918 private ranges.
    let o = ip.octets();
    if o[0] == 10 {
        return false;
    }
    if o[0] == 172 && (16..=31).contains(&o[1]) {
        return false;
    }
    if o[0] == 192 && o[1] == 168 {
        return false;
    }
    // CGNAT 100.64.0.0/10
    if o[0] == 100 && (64..=127).contains(&o[1]) {
        return false;
    }
    true
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() {
        return false;
    }
    if ip.is_unicast_link_local() {
        return false;
    }
    // Unique local addresses fc00::/7
    let seg0 = ip.segments()[0];
    if (seg0 & 0xfe00) == 0xfc00 {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_ipv4_heuristic() {
        assert!(!is_public_ipv4("10.1.2.3".parse().unwrap()));
        assert!(!is_public_ipv4("192.168.1.1".parse().unwrap()));
        assert!(!is_public_ipv4("172.16.0.1".parse().unwrap()));
        assert!(is_public_ipv4("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_parse_ip_brackets_and_scope() {
        assert_eq!(parse_ip("[8.8.8.8]").unwrap(), "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(
            parse_ip("fe80::1%12").unwrap(),
            "fe80::1".parse::<IpAddr>().unwrap()
        );
    }
}

