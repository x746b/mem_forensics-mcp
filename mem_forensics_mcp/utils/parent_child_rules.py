"""
Windows process parent-child relationship rules.

Defines known-good and suspicious process relationships for
detecting anomalies in memory forensics analysis.

References:
- https://www.sans.org/posters/hunt-evil/
- https://attack.mitre.org/techniques/T1055/
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class ProcessRule:
    """Rule defining expected behavior for a Windows process."""

    # Expected parent process names (any of these is valid)
    valid_parents: list[str]

    # Expected paths (case-insensitive, partial match)
    valid_paths: list[str]

    # Process should be unique (only one instance)
    singleton: bool = False

    # Process should not have child processes
    no_children: bool = False

    # Process should have specific command-line arguments
    requires_args: bool = False

    # Session 0 only (system service)
    session_zero_only: bool = False

    # Should not make network connections
    no_network: bool = False

    # Additional notes for analysts
    notes: str = ""


# Known Windows processes and their expected behavior
# Based on SANS Hunt Evil poster and Windows internals
WINDOWS_PROCESS_RULES: dict[str, ProcessRule] = {
    # System processes (always present)
    "system": ProcessRule(
        valid_parents=["idle"],  # Parent is Idle (PID 0)
        valid_paths=[""],  # No path
        singleton=True,
        notes="Always PID 4. Kernel threads host.",
    ),

    "smss.exe": ProcessRule(
        valid_parents=["system"],
        valid_paths=[r"\systemroot\system32\smss.exe", r"\windows\system32\smss.exe"],
        singleton=True,  # Master instance only, children exit
        session_zero_only=True,
        notes="Session Manager. Creates csrss.exe and wininit.exe for session 0.",
    ),

    "csrss.exe": ProcessRule(
        valid_parents=["smss.exe"],
        valid_paths=[r"\systemroot\system32\csrss.exe", r"\windows\system32\csrss.exe"],
        singleton=False,  # One per session
        session_zero_only=False,  # Exists in multiple sessions
        no_children=False,
        notes="Client/Server Runtime. Multiple instances (one per session).",
    ),

    "wininit.exe": ProcessRule(
        valid_parents=["smss.exe"],
        valid_paths=[r"\systemroot\system32\wininit.exe", r"\windows\system32\wininit.exe"],
        singleton=True,
        session_zero_only=True,
        notes="Windows Initialization. Starts services.exe, lsass.exe, lsaiso.exe.",
    ),

    "winlogon.exe": ProcessRule(
        valid_parents=["smss.exe"],
        valid_paths=[r"\systemroot\system32\winlogon.exe", r"\windows\system32\winlogon.exe"],
        singleton=False,  # One per interactive session
        notes="Windows Logon. Handles user logon/logoff. One per session.",
    ),

    "services.exe": ProcessRule(
        valid_parents=["wininit.exe"],
        valid_paths=[r"\systemroot\system32\services.exe", r"\windows\system32\services.exe"],
        singleton=True,
        session_zero_only=True,
        notes="Service Control Manager. Parent of all svchost.exe instances.",
    ),

    "lsass.exe": ProcessRule(
        valid_parents=["wininit.exe"],
        valid_paths=[r"\systemroot\system32\lsass.exe", r"\windows\system32\lsass.exe"],
        singleton=True,
        session_zero_only=True,
        no_children=True,  # Should not spawn processes
        notes="Local Security Authority. Handles authentication. HIGH VALUE TARGET.",
    ),

    "svchost.exe": ProcessRule(
        valid_parents=["services.exe"],
        valid_paths=[r"\systemroot\system32\svchost.exe", r"\windows\system32\svchost.exe"],
        singleton=False,  # Many instances
        session_zero_only=True,
        requires_args=True,  # Must have -k argument
        notes="Service Host. Multiple instances. MUST have -k argument. COMMONLY ABUSED.",
    ),

    "lsaiso.exe": ProcessRule(
        valid_parents=["wininit.exe"],
        valid_paths=[r"\systemroot\system32\lsaiso.exe", r"\windows\system32\lsaiso.exe"],
        singleton=True,
        session_zero_only=True,
        notes="Credential Guard isolated LSA. Only on systems with Credential Guard.",
    ),

    # User-mode processes
    "explorer.exe": ProcessRule(
        valid_parents=["userinit.exe", "explorer.exe"],  # Can self-restart
        valid_paths=[r"\windows\explorer.exe"],
        singleton=False,  # One per logged-in user
        notes="Windows Shell. Should not be session 0. Parent of user processes.",
    ),

    "userinit.exe": ProcessRule(
        valid_parents=["winlogon.exe"],
        valid_paths=[r"\systemroot\system32\userinit.exe", r"\windows\system32\userinit.exe"],
        notes="User Initialization. Starts explorer.exe, then exits quickly.",
    ),

    # Common system utilities
    "taskhostw.exe": ProcessRule(
        valid_parents=["svchost.exe"],
        valid_paths=[r"\systemroot\system32\taskhostw.exe", r"\windows\system32\taskhostw.exe"],
        session_zero_only=False,
        notes="Task Scheduler host. Runs scheduled tasks.",
    ),

    "runtimebroker.exe": ProcessRule(
        valid_parents=["svchost.exe"],
        valid_paths=[r"\systemroot\system32\runtimebroker.exe", r"\windows\system32\runtimebroker.exe"],
        notes="Runtime Broker for UWP apps.",
    ),

    "dllhost.exe": ProcessRule(
        valid_parents=["svchost.exe"],
        valid_paths=[r"\systemroot\system32\dllhost.exe", r"\windows\system32\dllhost.exe"],
        requires_args=True,  # Has /Processid: argument
        notes="COM Surrogate. Hosts COM objects.",
    ),

    "conhost.exe": ProcessRule(
        valid_parents=["csrss.exe"],  # Pre-Win7: csrss.exe, Win7+: conhost.exe
        valid_paths=[r"\systemroot\system32\conhost.exe", r"\windows\system32\conhost.exe"],
        notes="Console Host. One per console window.",
    ),

    # Security software (often targeted)
    "mpcmdrun.exe": ProcessRule(
        valid_parents=["svchost.exe", "services.exe"],
        valid_paths=[r"\programdata\microsoft\windows defender"],
        notes="Windows Defender command-line tool.",
    ),

    "msmpeng.exe": ProcessRule(
        valid_parents=["services.exe"],
        valid_paths=[r"\programdata\microsoft\windows defender"],
        notes="Windows Defender Antimalware Service.",
    ),
}

# Processes that should NEVER have network connections
PROCESSES_NO_NETWORK = {
    "notepad.exe",
    "calc.exe",
    "mspaint.exe",
    "write.exe",  # WordPad
    "charmap.exe",
    "magnify.exe",
    "narrator.exe",
    "osk.exe",  # On-screen keyboard
}

# Processes commonly abused for living-off-the-land
LOLBIN_PROCESSES = {
    "powershell.exe",
    "pwsh.exe",  # PowerShell Core
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "msiexec.exe",
    "installutil.exe",
    "msbuild.exe",
    "cmstp.exe",
    "wmic.exe",
}

# Known malware process names (exact match, case-insensitive)
KNOWN_MALWARE_NAMES = {
    "mimikatz.exe",
    "procdump.exe",  # Can be legitimate, but suspicious
    "psexec.exe",
    "psexesvc.exe",
    "beacon.exe",
    "payload.exe",
    "shell.exe",
    "reverse.exe",
    "meterpreter",
}


def get_process_rule(process_name: str) -> Optional[ProcessRule]:
    """
    Get the rule for a process by name.

    Args:
        process_name: Process name (case-insensitive)

    Returns:
        ProcessRule if known, None otherwise
    """
    name = process_name.lower()
    return WINDOWS_PROCESS_RULES.get(name)


def is_valid_parent(child_name: str, parent_name: str) -> tuple[bool, str]:
    """
    Check if a parent-child relationship is valid.

    Args:
        child_name: Child process name
        parent_name: Parent process name

    Returns:
        Tuple of (is_valid, reason)
    """
    child_lower = child_name.lower()
    parent_lower = parent_name.lower() if parent_name else ""

    rule = get_process_rule(child_lower)
    if rule is None:
        return True, "Unknown process - no rule defined"

    # Check if parent is in valid list
    valid_parents_lower = [p.lower() for p in rule.valid_parents]
    if parent_lower in valid_parents_lower:
        return True, "Valid parent-child relationship"

    return False, f"{child_name} should be spawned by {rule.valid_parents}, not {parent_name}"


def is_suspicious_name(process_name: str) -> tuple[bool, str]:
    """
    Check if a process name is known malware or suspicious.

    Args:
        process_name: Process name to check

    Returns:
        Tuple of (is_suspicious, reason)
    """
    name_lower = process_name.lower()

    # Known malware
    if name_lower in KNOWN_MALWARE_NAMES:
        return True, f"Known malware tool: {process_name}"

    # Check for name masquerading (extra spaces, lookalikes)
    # svchost.exe vs svch0st.exe vs svchost .exe
    if "svchost" in name_lower and name_lower != "svchost.exe":
        return True, f"Possible svchost.exe masquerading: {process_name}"

    if "lsass" in name_lower and name_lower != "lsass.exe":
        return True, f"Possible lsass.exe masquerading: {process_name}"

    if "csrss" in name_lower and name_lower != "csrss.exe":
        return True, f"Possible csrss.exe masquerading: {process_name}"

    return False, ""


def should_have_network(process_name: str) -> bool:
    """
    Check if a process is expected to make network connections.

    Args:
        process_name: Process name

    Returns:
        True if network is expected/acceptable, False if suspicious
    """
    return process_name.lower() not in PROCESSES_NO_NETWORK


def is_lolbin(process_name: str) -> bool:
    """
    Check if a process is a Living-off-the-Land binary.

    These are legitimate Windows tools commonly abused by attackers.

    Args:
        process_name: Process name

    Returns:
        True if it's a LOLBin
    """
    return process_name.lower() in LOLBIN_PROCESSES
