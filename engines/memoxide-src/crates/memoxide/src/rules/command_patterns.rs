//! Suspicious command patterns for command history triage.
//!
//! This is a pragmatic first cut: literal substring patterns that work for both
//! ASCII buffers and UTF-16LE ("wide") strings.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum CommandSeverity {
    Critical,
    High,
    Medium,
    Low,
}

pub struct CommandPattern {
    pub category: &'static str,
    pub severity: CommandSeverity,
    /// Case-insensitive substring.
    pub needle: &'static str,
    pub description: &'static str,
}

pub static COMMAND_PATTERNS: &[CommandPattern] = &[
    CommandPattern {
        category: "powershell_encoded",
        severity: CommandSeverity::High,
        needle: "-enc",
        description: "PowerShell encoded command flag",
    },
    CommandPattern {
        category: "powershell_download",
        severity: CommandSeverity::High,
        needle: "downloadstring",
        description: "PowerShell downloadstring usage",
    },
    CommandPattern {
        category: "powershell_download",
        severity: CommandSeverity::High,
        needle: "invoke-webrequest",
        description: "PowerShell Invoke-WebRequest usage",
    },
    CommandPattern {
        category: "powershell_exec",
        severity: CommandSeverity::High,
        needle: "invoke-expression",
        description: "PowerShell Invoke-Expression (IEX) usage",
    },
    CommandPattern {
        category: "powershell_exec",
        severity: CommandSeverity::High,
        needle: " i e x ",
        description: "PowerShell IEX (spaced) pattern",
    },
    CommandPattern {
        category: "certutil_download",
        severity: CommandSeverity::High,
        needle: "certutil",
        description: "Certutil usage (often abused for download/decode)",
    },
    CommandPattern {
        category: "bitsadmin_download",
        severity: CommandSeverity::Medium,
        needle: "bitsadmin",
        description: "BITSAdmin usage (often abused for downloads)",
    },
    CommandPattern {
        category: "wmic_exec",
        severity: CommandSeverity::High,
        needle: "process call create",
        description: "WMIC process creation (lateral movement/exec)",
    },
    CommandPattern {
        category: "schtasks_persistence",
        severity: CommandSeverity::High,
        needle: "schtasks /create",
        description: "Scheduled task creation (persistence)",
    },
    CommandPattern {
        category: "registry_persistence",
        severity: CommandSeverity::High,
        needle: "currentversion\\run",
        description: "Registry Run key modification (persistence)",
    },
    CommandPattern {
        category: "cred_dumping",
        severity: CommandSeverity::Critical,
        needle: "mimikatz",
        description: "Mimikatz keyword",
    },
    CommandPattern {
        category: "cred_dumping",
        severity: CommandSeverity::High,
        needle: "procdump",
        description: "ProcDump usage (commonly used on LSASS)",
    },
    CommandPattern {
        category: "remote_exec",
        severity: CommandSeverity::High,
        needle: "psexec",
        description: "PsExec usage (remote execution)",
    },
    CommandPattern {
        category: "tunneling",
        severity: CommandSeverity::Medium,
        needle: "ssh -r",
        description: "SSH reverse tunneling",
    },
    CommandPattern {
        category: "payload_staging",
        severity: CommandSeverity::Medium,
        needle: "frombase64string",
        description: "Base64 decode staging",
    },
];

#[allow(dead_code)]
pub fn severity_rank(s: CommandSeverity) -> u8 {
    match s {
        CommandSeverity::Low => 1,
        CommandSeverity::Medium => 2,
        CommandSeverity::High => 3,
        CommandSeverity::Critical => 4,
    }
}

