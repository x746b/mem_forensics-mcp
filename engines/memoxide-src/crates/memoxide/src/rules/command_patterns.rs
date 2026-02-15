//! Suspicious command patterns for command history triage.
//!
//! Process-agnostic patterns: substring matches that detect suspicious activity
//! regardless of which process runs them. Process-specific LOLBin detection
//! (e.g. certutil.exe + `-urlcache`) is handled by `rules/lolbins.rs`.

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
    // ── PowerShell execution ────────────────────────────────────────
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
    // ── WMI execution ───────────────────────────────────────────────
    CommandPattern {
        category: "wmic_exec",
        severity: CommandSeverity::High,
        needle: "process call create",
        description: "WMIC process creation (lateral movement/exec)",
    },
    // ── Persistence ─────────────────────────────────────────────────
    CommandPattern {
        category: "persistence",
        severity: CommandSeverity::High,
        needle: "schtasks /create",
        description: "Scheduled task creation (persistence)",
    },
    CommandPattern {
        category: "persistence",
        severity: CommandSeverity::High,
        needle: "currentversion\\run",
        description: "Registry Run key modification (persistence)",
    },
    CommandPattern {
        category: "persistence",
        severity: CommandSeverity::High,
        needle: "sc create",
        description: "Service creation (persistence)",
    },
    CommandPattern {
        category: "persistence",
        severity: CommandSeverity::High,
        needle: "sc config",
        description: "Service reconfiguration (persistence/tampering)",
    },
    // ── Credential dumping ──────────────────────────────────────────
    CommandPattern {
        category: "cred_dumping",
        severity: CommandSeverity::Critical,
        needle: "mimikatz",
        description: "Mimikatz keyword",
    },
    CommandPattern {
        category: "cred_dumping",
        severity: CommandSeverity::Critical,
        needle: "sekurlsa",
        description: "Mimikatz sekurlsa module (credential extraction)",
    },
    CommandPattern {
        category: "cred_dumping",
        severity: CommandSeverity::Critical,
        needle: "ntdsutil",
        description: "ntdsutil usage (AD database extraction)",
    },
    CommandPattern {
        category: "cred_dumping",
        severity: CommandSeverity::High,
        needle: "procdump",
        description: "ProcDump usage (commonly used on LSASS)",
    },
    // ── Reconnaissance ──────────────────────────────────────────────
    CommandPattern {
        category: "recon",
        severity: CommandSeverity::Medium,
        needle: "whoami",
        description: "User/privilege reconnaissance",
    },
    CommandPattern {
        category: "recon",
        severity: CommandSeverity::Medium,
        needle: "net user",
        description: "User account enumeration",
    },
    CommandPattern {
        category: "recon",
        severity: CommandSeverity::Medium,
        needle: "net group",
        description: "Domain group enumeration",
    },
    CommandPattern {
        category: "recon",
        severity: CommandSeverity::Medium,
        needle: "net localgroup",
        description: "Local group enumeration",
    },
    CommandPattern {
        category: "recon",
        severity: CommandSeverity::Medium,
        needle: "nltest",
        description: "Domain trust enumeration (nltest)",
    },
    // ── Defense evasion ─────────────────────────────────────────────
    CommandPattern {
        category: "defense_evasion",
        severity: CommandSeverity::High,
        needle: "wevtutil cl",
        description: "Event log clearing (wevtutil)",
    },
    CommandPattern {
        category: "defense_evasion",
        severity: CommandSeverity::High,
        needle: "clear-eventlog",
        description: "PowerShell event log clearing",
    },
    CommandPattern {
        category: "defense_evasion",
        severity: CommandSeverity::High,
        needle: "set-mppreference",
        description: "Windows Defender configuration tampering",
    },
    // ── Lateral movement ────────────────────────────────────────────
    CommandPattern {
        category: "lateral_movement",
        severity: CommandSeverity::High,
        needle: "enter-pssession",
        description: "PowerShell remote session (lateral movement)",
    },
    CommandPattern {
        category: "lateral_movement",
        severity: CommandSeverity::High,
        needle: "invoke-command",
        description: "PowerShell remote command execution",
    },
    CommandPattern {
        category: "lateral_movement",
        severity: CommandSeverity::High,
        needle: "new-pssession",
        description: "PowerShell new remote session",
    },
    // ── Tunneling / staging ─────────────────────────────────────────
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
    // ── Privilege escalation tools ────────────────────────────────
    CommandPattern {
        category: "privesc",
        severity: CommandSeverity::Critical,
        needle: "godpotato",
        description: "GodPotato privilege escalation (SeImpersonate exploit)",
    },
    CommandPattern {
        category: "privesc",
        severity: CommandSeverity::Critical,
        needle: "sharpefspotato",
        description: "SharpEfsPotato privilege escalation",
    },
    CommandPattern {
        category: "privesc",
        severity: CommandSeverity::High,
        needle: "fullpowers",
        description: "FullPowers privilege restoration for service accounts",
    },
    CommandPattern {
        category: "privesc",
        severity: CommandSeverity::High,
        needle: "runascs",
        description: "RunasCs alternative runas implementation",
    },
    // ── Credential tools (specific) ──────────────────────────────
    CommandPattern {
        category: "cred_dumping",
        severity: CommandSeverity::Critical,
        needle: "secretsdump",
        description: "Impacket secretsdump (credential extraction)",
    },
    CommandPattern {
        category: "cred_dumping",
        severity: CommandSeverity::Critical,
        needle: "dcsync",
        description: "DCSync attack (AD replication abuse)",
    },
    CommandPattern {
        category: "cred_dumping",
        severity: CommandSeverity::High,
        needle: "ms-mcs-admpwd",
        description: "LAPS password attribute query",
    },
    // ── AD / certificate attacks ─────────────────────────────────
    CommandPattern {
        category: "ad_attack",
        severity: CommandSeverity::High,
        needle: "certipy",
        description: "Certipy ADCS exploitation tool",
    },
    CommandPattern {
        category: "ad_recon",
        severity: CommandSeverity::High,
        needle: "bloodhound",
        description: "BloodHound AD enumeration",
    },
    CommandPattern {
        category: "ad_recon",
        severity: CommandSeverity::High,
        needle: "sharphound",
        description: "SharpHound AD data collector",
    },
    CommandPattern {
        category: "ad_recon",
        severity: CommandSeverity::Medium,
        needle: "get-adcomputer",
        description: "AD computer enumeration (often for LAPS)",
    },
    CommandPattern {
        category: "ad_recon",
        severity: CommandSeverity::Medium,
        needle: "get-aduser",
        description: "AD user enumeration",
    },
    // ── Lateral movement tools ───────────────────────────────────
    CommandPattern {
        category: "lateral_movement",
        severity: CommandSeverity::High,
        needle: "crackmapexec",
        description: "CrackMapExec AD/network exploitation",
    },
    CommandPattern {
        category: "lateral_movement",
        severity: CommandSeverity::High,
        needle: "smbexec",
        description: "Impacket SMBexec remote execution",
    },
    // ── Payload / C2 ─────────────────────────────────────────────
    CommandPattern {
        category: "payload",
        severity: CommandSeverity::High,
        needle: "msfvenom",
        description: "Metasploit payload generator",
    },
    CommandPattern {
        category: "payload",
        severity: CommandSeverity::High,
        needle: "meterpreter",
        description: "Metasploit Meterpreter payload",
    },
    CommandPattern {
        category: "payload",
        severity: CommandSeverity::Critical,
        needle: "reverse_shell",
        description: "Reverse shell payload pattern",
    },
    // ── PowerShell credential handling ───────────────────────────
    CommandPattern {
        category: "powershell_cred",
        severity: CommandSeverity::Medium,
        needle: "convertto-securestring",
        description: "PowerShell secure string conversion (credential handling)",
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
