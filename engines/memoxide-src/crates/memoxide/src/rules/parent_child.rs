//! Parent-child process relationship rules.
//!
//! Defines expected parent processes for critical Windows services.
//! Violations indicate potential process injection, masquerading, or
//! unauthorized service spawning.

/// A parent-child rule: which parents are expected for a given process.
pub struct ParentChildRule {
    /// Process name (case-insensitive match).
    pub child: &'static str,
    /// Expected parent process name(s).
    pub expected_parents: &'static [&'static str],
    /// Severity if violated: "critical", "high", "medium", "low".
    pub severity: &'static str,
    /// Whether this process should be a singleton (only one instance).
    pub singleton: bool,
    /// Whether the expected parent normally exits after spawning this process.
    /// When true and the parent is missing from pslist, the violation is
    /// downgraded to informational (normal Windows behavior).
    /// Examples: smss.exe session workers exit after creating csrss/wininit/winlogon;
    /// userinit.exe exits after launching explorer.exe.
    pub parent_may_exit: bool,
    /// Description of why this matters.
    pub description: &'static str,
}

/// All parent-child rules for Windows process validation.
pub static RULES: &[ParentChildRule] = &[
    // System processes
    ParentChildRule {
        child: "smss.exe",
        // Master smss.exe is started by System (PID 4).
        // Per-session worker smss.exe instances are started by the master smss.exe.
        expected_parents: &["System", "smss.exe"],
        severity: "critical",
        singleton: false, // Master + per-session workers
        parent_may_exit: false,
        description: "Session Manager should only be started by System (PID 4) or master smss.exe",
    },
    ParentChildRule {
        child: "csrss.exe",
        expected_parents: &["smss.exe"],
        severity: "critical",
        singleton: false, // One per session
        parent_may_exit: true, // smss.exe session worker exits after spawning
        description: "Client/Server Runtime should only be started by smss.exe",
    },
    ParentChildRule {
        child: "wininit.exe",
        expected_parents: &["smss.exe"],
        severity: "critical",
        singleton: true,
        parent_may_exit: true, // smss.exe session worker exits after spawning
        description: "Windows Init Process should only be started by smss.exe",
    },
    ParentChildRule {
        child: "winlogon.exe",
        expected_parents: &["smss.exe"],
        severity: "critical",
        singleton: false, // One per session
        parent_may_exit: true, // smss.exe session worker exits after spawning
        description: "Windows Logon should only be started by smss.exe",
    },
    ParentChildRule {
        child: "services.exe",
        expected_parents: &["wininit.exe"],
        severity: "critical",
        singleton: true,
        parent_may_exit: false,
        description: "Service Control Manager should only be started by wininit.exe",
    },
    ParentChildRule {
        child: "lsass.exe",
        expected_parents: &["wininit.exe"],
        severity: "critical",
        singleton: true,
        parent_may_exit: false,
        description: "LSASS should only be started by wininit.exe. Multiple instances = credential theft",
    },
    ParentChildRule {
        child: "lsaiso.exe",
        expected_parents: &["wininit.exe"],
        severity: "critical",
        singleton: true,
        parent_may_exit: false,
        description: "LSA Isolated should only be started by wininit.exe",
    },
    ParentChildRule {
        child: "svchost.exe",
        expected_parents: &["services.exe", "MsMpEng.exe"],
        severity: "high",
        singleton: false,
        parent_may_exit: false,
        description: "svchost.exe should be started by services.exe",
    },
    ParentChildRule {
        child: "taskhost.exe",
        expected_parents: &["services.exe", "svchost.exe"],
        severity: "medium",
        singleton: false,
        parent_may_exit: false,
        description: "Task Host should be started by services.exe or svchost.exe",
    },
    ParentChildRule {
        child: "taskhostw.exe",
        expected_parents: &["services.exe", "svchost.exe"],
        severity: "medium",
        singleton: false,
        parent_may_exit: false,
        description: "Task Host Window should be started by services.exe or svchost.exe",
    },
    ParentChildRule {
        child: "RuntimeBroker.exe",
        expected_parents: &["svchost.exe"],
        severity: "medium",
        singleton: false,
        parent_may_exit: false,
        description: "Runtime Broker should be started by svchost.exe",
    },
    ParentChildRule {
        child: "spoolsv.exe",
        expected_parents: &["services.exe"],
        severity: "medium",
        singleton: true,
        parent_may_exit: false,
        description: "Print Spooler should be started by services.exe",
    },
    // Explorer / user session
    ParentChildRule {
        child: "explorer.exe",
        expected_parents: &["userinit.exe", "winlogon.exe"],
        severity: "high",
        singleton: false, // One per user session
        parent_may_exit: true, // userinit.exe exits after launching explorer.exe
        description: "Explorer should be started by userinit.exe or winlogon.exe",
    },
    ParentChildRule {
        child: "userinit.exe",
        expected_parents: &["winlogon.exe"],
        severity: "high",
        singleton: false,
        parent_may_exit: false,
        description: "UserInit should be started by winlogon.exe",
    },
    // WMI
    ParentChildRule {
        child: "WmiPrvSE.exe",
        expected_parents: &["svchost.exe", "WmiPrvSE.exe"],
        severity: "medium",
        singleton: false,
        parent_may_exit: false,
        description: "WMI Provider should be started by svchost.exe",
    },
    // Defender
    ParentChildRule {
        child: "MsMpEng.exe",
        expected_parents: &["services.exe"],
        severity: "high",
        singleton: true,
        parent_may_exit: false,
        description: "Windows Defender engine should be started by services.exe",
    },
];

/// Find the rule for a given process name (case-insensitive).
pub fn find_rule(process_name: &str) -> Option<&'static ParentChildRule> {
    let lower = process_name.to_lowercase();
    RULES.iter().find(|r| r.child.to_lowercase() == lower)
}

/// Check if a parent is expected for a child process.
#[allow(dead_code)]
pub fn is_expected_parent(child_name: &str, parent_name: &str) -> Option<bool> {
    find_rule(child_name).map(|rule| {
        rule.expected_parents
            .iter()
            .any(|p| p.eq_ignore_ascii_case(parent_name))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_rule() {
        let rule = find_rule("lsass.exe");
        assert!(rule.is_some());
        let rule = rule.unwrap();
        assert!(rule.singleton);
        assert_eq!(rule.severity, "critical");
        assert!(rule.expected_parents.contains(&"wininit.exe"));
    }

    #[test]
    fn test_find_rule_case_insensitive() {
        assert!(find_rule("LSASS.EXE").is_some());
        assert!(find_rule("Svchost.exe").is_some());
    }

    #[test]
    fn test_is_expected_parent() {
        assert_eq!(is_expected_parent("svchost.exe", "services.exe"), Some(true));
        assert_eq!(is_expected_parent("svchost.exe", "cmd.exe"), Some(false));
        assert_eq!(is_expected_parent("unknown.exe", "anything"), None);
    }

    #[test]
    fn test_rules_count() {
        assert!(RULES.len() >= 15);
    }
}
