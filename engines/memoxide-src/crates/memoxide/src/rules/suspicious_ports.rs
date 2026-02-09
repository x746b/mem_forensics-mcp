//! Suspicious port definitions for C2 and malware detection.
//!
//! Categorized port numbers commonly associated with C2 frameworks,
//! reverse shells, and malware families.

use serde::{Deserialize, Serialize};

/// Severity level for a suspicious port match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// A suspicious port entry.
pub struct SuspiciousPort {
    pub port: u16,
    pub severity: PortSeverity,
    pub category: &'static str,
    pub description: &'static str,
}

/// Known suspicious ports.
pub static SUSPICIOUS_PORTS: &[SuspiciousPort] = &[
    // -- Metasploit / Meterpreter defaults --
    SuspiciousPort { port: 4444, severity: PortSeverity::Critical, category: "c2", description: "Metasploit/Meterpreter default" },
    SuspiciousPort { port: 4445, severity: PortSeverity::High, category: "c2", description: "Metasploit alt listener" },
    SuspiciousPort { port: 5555, severity: PortSeverity::High, category: "c2", description: "Metasploit/reverse shell" },
    // -- Cobalt Strike --
    SuspiciousPort { port: 50050, severity: PortSeverity::Critical, category: "c2", description: "Cobalt Strike team server default" },
    // -- Empire / Covenant --
    SuspiciousPort { port: 8443, severity: PortSeverity::Medium, category: "c2", description: "Empire/Covenant C2 (alt HTTPS)" },
    // -- Reverse shells --
    SuspiciousPort { port: 1234, severity: PortSeverity::High, category: "reverse_shell", description: "Common reverse shell port" },
    SuspiciousPort { port: 1337, severity: PortSeverity::High, category: "reverse_shell", description: "Common reverse shell (leet)" },
    SuspiciousPort { port: 6666, severity: PortSeverity::High, category: "reverse_shell", description: "Common reverse shell port" },
    SuspiciousPort { port: 6667, severity: PortSeverity::Medium, category: "irc_c2", description: "IRC (often used for botnets)" },
    SuspiciousPort { port: 6668, severity: PortSeverity::Medium, category: "irc_c2", description: "IRC alt" },
    SuspiciousPort { port: 6669, severity: PortSeverity::Medium, category: "irc_c2", description: "IRC alt" },
    SuspiciousPort { port: 7777, severity: PortSeverity::High, category: "reverse_shell", description: "Common reverse shell port" },
    SuspiciousPort { port: 8888, severity: PortSeverity::Medium, category: "reverse_shell", description: "Common reverse shell port" },
    SuspiciousPort { port: 9999, severity: PortSeverity::High, category: "reverse_shell", description: "Common reverse shell port" },
    // -- RATs --
    SuspiciousPort { port: 3460, severity: PortSeverity::Critical, category: "rat", description: "Poison Ivy default" },
    SuspiciousPort { port: 5552, severity: PortSeverity::High, category: "rat", description: "njRAT variant" },
    SuspiciousPort { port: 1604, severity: PortSeverity::High, category: "rat", description: "DarkComet default" },
    SuspiciousPort { port: 10000, severity: PortSeverity::Medium, category: "rat", description: "Common RAT port" },
    SuspiciousPort { port: 10001, severity: PortSeverity::Medium, category: "rat", description: "Common RAT port" },
    // -- Mining --
    SuspiciousPort { port: 3333, severity: PortSeverity::High, category: "mining", description: "Cryptominer stratum" },
    SuspiciousPort { port: 14444, severity: PortSeverity::High, category: "mining", description: "Monero mining pool" },
    SuspiciousPort { port: 45700, severity: PortSeverity::High, category: "mining", description: "Monero mining pool" },
    // -- Sliver --
    SuspiciousPort { port: 31337, severity: PortSeverity::Critical, category: "c2", description: "Sliver C2 / elite backdoor" },
    SuspiciousPort { port: 8080, severity: PortSeverity::Low, category: "proxy", description: "HTTP proxy (also used by C2)" },
    SuspiciousPort { port: 8081, severity: PortSeverity::Low, category: "proxy", description: "HTTP alt proxy" },
    // -- Misc suspicious --
    SuspiciousPort { port: 4438, severity: PortSeverity::High, category: "c2", description: "Havoc C2 default" },
    SuspiciousPort { port: 2222, severity: PortSeverity::Medium, category: "backdoor", description: "Alt SSH / backdoor" },
    SuspiciousPort { port: 12345, severity: PortSeverity::High, category: "backdoor", description: "NetBus / common backdoor" },
    SuspiciousPort { port: 54321, severity: PortSeverity::High, category: "backdoor", description: "Common backdoor port" },
];

/// Look up a port in the suspicious ports list.
pub fn find_suspicious_port(port: u16) -> Option<&'static SuspiciousPort> {
    SUSPICIOUS_PORTS.iter().find(|sp| sp.port == port)
}

/// Check if a port is suspicious at or above a given severity.
#[allow(dead_code)]
pub fn is_suspicious(port: u16, min_severity: PortSeverity) -> bool {
    SUSPICIOUS_PORTS.iter().any(|sp| {
        sp.port == port && severity_rank(sp.severity) >= severity_rank(min_severity)
    })
}

#[allow(dead_code)]
fn severity_rank(s: PortSeverity) -> u8 {
    match s {
        PortSeverity::Low => 1,
        PortSeverity::Medium => 2,
        PortSeverity::High => 3,
        PortSeverity::Critical => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_known_port() {
        let result = find_suspicious_port(4444);
        assert!(result.is_some());
        let sp = result.unwrap();
        assert_eq!(sp.severity, PortSeverity::Critical);
        assert_eq!(sp.category, "c2");
    }

    #[test]
    fn test_unknown_port() {
        assert!(find_suspicious_port(80).is_none());
        assert!(find_suspicious_port(443).is_none());
    }

    #[test]
    fn test_is_suspicious_severity_filter() {
        assert!(is_suspicious(4444, PortSeverity::High));
        assert!(is_suspicious(4444, PortSeverity::Critical));
        assert!(!is_suspicious(8080, PortSeverity::High)); // 8080 is Low
        assert!(is_suspicious(8080, PortSeverity::Low));
    }
}
