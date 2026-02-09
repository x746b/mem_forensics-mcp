"""
Command history extraction for memory forensics.

Recovers attacker commands from:
- cmd.exe console history (cmdscan, consoles)
- Process command lines (cmdline)
- PowerShell history artifacts
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from ..core.session import get_session
from ..core.vol3_runner import VOL3_AVAILABLE

logger = logging.getLogger(__name__)


@dataclass
class CommandFinding:
    """A finding about a command."""
    type: str  # PRIVILEGE_ESCALATION, RECON, LATERAL_MOVEMENT, etc.
    detail: str
    severity: str = "MEDIUM"


@dataclass
class CommandEntry:
    """A recovered command."""
    pid: int
    process_name: str
    command: str
    source: str  # cmdline, cmdscan, consoles
    timestamp: Optional[str] = None
    findings: list[CommandFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "process_name": self.process_name,
            "command": self.command,
            "source": self.source,
            "timestamp": self.timestamp,
            "findings": [
                {"type": f.type, "detail": f.detail, "severity": f.severity}
                for f in self.findings
            ],
        }


# Suspicious command patterns
SUSPICIOUS_PATTERNS = [
    # Reconnaissance
    (r"\bwhoami\b", "RECON", "User/privilege enumeration"),
    (r"\bnet\s+user\b", "RECON", "User enumeration"),
    (r"\bnet\s+group\b", "RECON", "Group enumeration"),
    (r"\bnet\s+localgroup\b", "RECON", "Local group enumeration"),
    (r"\bnet\s+share\b", "RECON", "Share enumeration"),
    (r"\bnet\s+view\b", "RECON", "Network enumeration"),
    (r"\bipconfig\b", "RECON", "Network configuration enumeration"),
    (r"\bsysteminfo\b", "RECON", "System information enumeration"),
    (r"\btasklist\b", "RECON", "Process enumeration"),
    (r"\bqprocess\b", "RECON", "Process enumeration"),
    (r"\bquery\s+user\b", "RECON", "User session enumeration"),
    (r"\bnltest\b", "RECON", "Domain trust enumeration"),
    (r"\bdsquery\b", "RECON", "Active Directory enumeration"),

    # Privilege Escalation
    (r"\bnet\s+.*\s+/add\b", "PRIVILEGE_ESCALATION", "Account/group modification"),
    (r"\bnet\s+localgroup\s+administrators\b.*\s+/add", "PRIVILEGE_ESCALATION", "Adding user to administrators"),
    (r"\brunas\b", "PRIVILEGE_ESCALATION", "Running as different user"),

    # Credential Access
    (r"\bmimikatz\b", "CREDENTIAL_ACCESS", "Mimikatz detected"),
    (r"\bsekurlsa\b", "CREDENTIAL_ACCESS", "Mimikatz sekurlsa module"),
    (r"\bprocdump\b.*\blsass\b", "CREDENTIAL_ACCESS", "LSASS memory dump"),
    (r"\bcomsvcs\.dll.*MiniDump\b", "CREDENTIAL_ACCESS", "LSASS dump via comsvcs"),
    (r"\breg\s+save\s+.*sam\b", "CREDENTIAL_ACCESS", "SAM registry export"),
    (r"\breg\s+save\s+.*system\b", "CREDENTIAL_ACCESS", "SYSTEM registry export"),
    (r"\bntdsutil\b", "CREDENTIAL_ACCESS", "NTDS.dit access"),

    # Lateral Movement
    (r"\bpsexec\b", "LATERAL_MOVEMENT", "PsExec remote execution"),
    (r"\bwmic\s+.*\/node\b", "LATERAL_MOVEMENT", "WMIC remote execution"),
    (r"\bwinrm\b", "LATERAL_MOVEMENT", "WinRM remote management"),
    (r"\benter-pssession\b", "LATERAL_MOVEMENT", "PowerShell remoting"),
    (r"\binvoke-command\b", "LATERAL_MOVEMENT", "PowerShell remote command"),
    (r"\bnew-pssession\b", "LATERAL_MOVEMENT", "PowerShell session creation"),
    (r"\bschtasks\s+.*\/s\b", "LATERAL_MOVEMENT", "Remote scheduled task"),

    # Persistence
    (r"\bschtasks\s+.*\/create\b", "PERSISTENCE", "Scheduled task creation"),
    (r"\breg\s+add\s+.*run\b", "PERSISTENCE", "Registry run key modification"),
    (r"\bsc\s+create\b", "PERSISTENCE", "Service creation"),
    (r"\bsc\s+config\b", "PERSISTENCE", "Service modification"),

    # Defense Evasion
    (r"\bdel\s+.*\.log\b", "DEFENSE_EVASION", "Log file deletion"),
    (r"\bwevtutil\s+cl\b", "DEFENSE_EVASION", "Event log clearing"),
    (r"\bclear-eventlog\b", "DEFENSE_EVASION", "PowerShell event log clearing"),
    (r"\bset-mppreference\b.*\bdisable\b", "DEFENSE_EVASION", "Defender modification"),
    (r"\bpowershell\b.*\b-enc\b", "DEFENSE_EVASION", "Encoded PowerShell"),
    (r"\bpowershell\b.*\b-e\s+[A-Za-z0-9+/=]{20,}", "DEFENSE_EVASION", "Base64 encoded PowerShell"),

    # Data Exfiltration
    (r"\bcertutil\b.*\b-urlcache\b", "EXFILTRATION", "Certutil download"),
    (r"\bbitsadmin\b.*\/transfer\b", "EXFILTRATION", "BITS transfer"),
    (r"\bInvoke-WebRequest\b", "EXFILTRATION", "PowerShell web request"),
    (r"\bwget\b", "EXFILTRATION", "Wget download"),
    (r"\bcurl\b", "EXFILTRATION", "Curl transfer"),

    # Execution
    (r"\bpowershell\b.*\b-nop\b", "EXECUTION", "PowerShell no profile"),
    (r"\bpowershell\b.*\b-w\s+hidden\b", "EXECUTION", "Hidden PowerShell window"),
    (r"\bcmd\b.*\/c\b", "EXECUTION", "cmd.exe command execution"),
    (r"\bwscript\b", "EXECUTION", "Windows Script Host"),
    (r"\bcscript\b", "EXECUTION", "Console Script Host"),
    (r"\bmshta\b", "EXECUTION", "MSHTA execution"),
    (r"\brundll32\b", "EXECUTION", "Rundll32 execution"),
    (r"\bregsvr32\b", "EXECUTION", "Regsvr32 execution"),
]


def get_command_history(
    image_path: str,
    pid: Optional[int] = None,
    include_benign: bool = False,
) -> dict[str, Any]:
    """
    Recover command history from memory.

    Aggregates commands from:
    - cmdline: Process command-line arguments
    - cmdscan: cmd.exe console command history
    - consoles: Console input/output buffers

    Args:
        image_path: Path to memory dump
        pid: Filter by specific PID
        include_benign: Include commands without suspicious indicators

    Returns:
        Dict with recovered commands and analysis
    """
    if not VOL3_AVAILABLE:
        return {"error": "volatility3 not installed"}

    session = get_session(image_path)
    if session is None:
        return {"error": "Failed to create session"}

    init_result = session.initialize()
    if not init_result.get("ready"):
        return {"error": init_result.get("error", "Failed to initialize")}

    if session.os_type != "windows":
        return {"error": f"Command history only supported for Windows (got: {session.os_type})"}

    commands: list[CommandEntry] = []

    # Get cmdline for all processes
    logger.info("Running cmdline...")
    try:
        cmdlines = session.run_plugin("windows.cmdline.CmdLine")
        for cmd in cmdlines:
            cmd_pid = cmd.get("PID")
            if pid is not None and cmd_pid != pid:
                continue

            args = cmd.get("Args", "")
            if not args:
                continue

            entry = CommandEntry(
                pid=cmd_pid,
                process_name=str(cmd.get("Process", "unknown")),
                command=str(args),
                source="cmdline",
            )

            # Analyze command
            _analyze_command(entry)

            if entry.findings or include_benign:
                commands.append(entry)

    except Exception as e:
        logger.warning(f"cmdline failed: {e}")

    # Try cmdscan for command history
    logger.info("Running cmdscan...")
    try:
        cmdscan_results = session.run_plugin("windows.cmdscan.CmdScan")
        for result in cmdscan_results:
            cmd_pid = result.get("PID")
            if pid is not None and cmd_pid != pid:
                continue

            cmd_text = result.get("Command", "")
            if not cmd_text:
                continue

            entry = CommandEntry(
                pid=cmd_pid,
                process_name=str(result.get("Process", "cmd.exe")),
                command=str(cmd_text),
                source="cmdscan",
            )

            _analyze_command(entry)

            if entry.findings or include_benign:
                commands.append(entry)

    except Exception as e:
        logger.warning(f"cmdscan failed: {e}")

    # Try consoles for console buffers
    logger.info("Running consoles...")
    try:
        consoles_results = session.run_plugin("windows.consoles.Consoles")
        for result in consoles_results:
            cmd_pid = result.get("PID")
            if pid is not None and cmd_pid != pid:
                continue

            # Consoles may have multiple fields with command data
            for field in ["Command", "CommandHistory", "Screen"]:
                cmd_text = result.get(field, "")
                if cmd_text:
                    entry = CommandEntry(
                        pid=cmd_pid,
                        process_name=str(result.get("Process", "console")),
                        command=str(cmd_text)[:500],  # Truncate long output
                        source="consoles",
                    )

                    _analyze_command(entry)

                    if entry.findings or include_benign:
                        commands.append(entry)

    except Exception as e:
        logger.warning(f"consoles failed: {e}")

    # Deduplicate commands
    seen = set()
    unique_commands = []
    for cmd in commands:
        key = (cmd.pid, cmd.command[:100])
        if key not in seen:
            seen.add(key)
            unique_commands.append(cmd)

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    unique_commands.sort(
        key=lambda c: min(
            (severity_order.get(f.severity, 4) for f in c.findings),
            default=5
        )
    )

    # Build summary
    finding_counts: dict[str, int] = {}
    for cmd in unique_commands:
        for f in cmd.findings:
            finding_counts[f.type] = finding_counts.get(f.type, 0) + 1

    summary_parts = []
    for ftype, count in sorted(finding_counts.items(), key=lambda x: -x[1]):
        summary_parts.append(f"{count} {ftype}")

    summary = f"Recovered {len(unique_commands)} commands"
    if summary_parts:
        summary += f" ({', '.join(summary_parts[:5])})"

    return {
        "image_path": str(session.image_path),
        "profile": session.profile,
        "commands_found": len(unique_commands),
        "commands": [c.to_dict() for c in unique_commands],
        "finding_summary": finding_counts,
        "summary": summary,
    }


def _analyze_command(entry: CommandEntry) -> None:
    """Analyze a command for suspicious patterns."""
    cmd_lower = entry.command.lower()

    for pattern, finding_type, description in SUSPICIOUS_PATTERNS:
        if re.search(pattern, cmd_lower, re.IGNORECASE):
            # Determine severity based on finding type
            severity = "MEDIUM"
            if finding_type in ("CREDENTIAL_ACCESS", "PRIVILEGE_ESCALATION"):
                severity = "CRITICAL"
            elif finding_type in ("LATERAL_MOVEMENT", "PERSISTENCE", "DEFENSE_EVASION"):
                severity = "HIGH"

            entry.findings.append(CommandFinding(
                type=finding_type,
                detail=description,
                severity=severity,
            ))
