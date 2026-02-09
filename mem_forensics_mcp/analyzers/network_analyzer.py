"""
Network connection analysis for memory forensics.

Detects:
- Suspicious connections from unexpected processes
- Known C2 ports and patterns
- Beaconing behavior indicators
- Process-network correlation
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from ..core.session import MemorySession, get_session
from ..core.vol3_runner import VOL3_AVAILABLE
from ..utils.parent_child_rules import PROCESSES_NO_NETWORK, is_lolbin

logger = logging.getLogger(__name__)


@dataclass
class NetworkFinding:
    """A finding about a network connection."""
    type: str  # UNEXPECTED_NETWORK, SUSPICIOUS_PORT, C2_INDICATOR, etc.
    detail: str
    severity: str = "MEDIUM"


@dataclass
class SuspiciousConnection:
    """A suspicious network connection."""
    pid: int
    process_name: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str
    protocol: str
    create_time: Optional[str]
    findings: list[NetworkFinding] = field(default_factory=list)
    risk_score: str = "LOW"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON output."""
        return {
            "pid": self.pid,
            "process_name": self.process_name,
            "local_addr": self.local_addr,
            "local_port": self.local_port,
            "remote_addr": self.remote_addr,
            "remote_port": self.remote_port,
            "state": self.state,
            "protocol": self.protocol,
            "create_time": self.create_time,
            "findings": [
                {"type": f.type, "detail": f.detail, "severity": f.severity}
                for f in self.findings
            ],
            "risk_score": self.risk_score,
        }


# Known suspicious ports (commonly used by malware/C2)
SUSPICIOUS_PORTS = {
    # Metasploit/Meterpreter defaults
    4444: "Metasploit default handler port",
    4445: "Common alternative C2 port",
    5555: "Common C2/RAT port",

    # Cobalt Strike
    50050: "Cobalt Strike team server default",

    # Common RAT ports
    1234: "Common RAT backdoor port",
    5678: "Common RAT backdoor port",
    6666: "Common RAT port",
    6667: "IRC (often used for C2)",
    7777: "Common RAT backdoor port",
    8080: "HTTP proxy (legitimate but often abused)",
    8443: "HTTPS alternate (legitimate but watch for odd processes)",
    9001: "Tor default",
    9050: "Tor SOCKS proxy",
    9999: "Common RAT backdoor port",

    # Reverse shell common ports
    1337: "Leet port (common in CTF/hacking)",
    31337: "Elite/Back Orifice port",
}

# Ports that are suspicious when non-browser processes use them
WEB_PORTS = {80, 443, 8080, 8443}

# Processes expected to make web connections
WEB_PROCESSES = {
    "chrome.exe",
    "firefox.exe",
    "msedge.exe",
    "iexplore.exe",
    "opera.exe",
    "brave.exe",
    "svchost.exe",  # Windows Update, etc.
    "microsoftedgeupdate.exe",
    "onedrive.exe",
    "teams.exe",
    "slack.exe",
    "outlook.exe",
    "searchhost.exe",
    "searchapp.exe",
    "runtimebroker.exe",
}

# Private IP ranges (for filtering)
PRIVATE_RANGES = [
    ("10.", "10."),
    ("172.16.", "172.31."),
    ("192.168.", "192.168."),
    ("127.", "127."),
    ("0.0.0.0", "0.0.0.0"),
    ("::", "::"),
]


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private range."""
    if not ip:
        return True
    for prefix, _ in PRIVATE_RANGES:
        if ip.startswith(prefix):
            return True
    return False


def find_c2_connections(
    image_path: str,
    include_legitimate: bool = False,
    include_listening: bool = False,
) -> dict[str, Any]:
    """
    Find suspicious network connections that may indicate C2 communication.

    Correlates network connections with process reputation to identify:
    - Unexpected processes making network connections
    - Connections to suspicious ports
    - Non-browser processes making web connections
    - LOLBins with network activity

    Args:
        image_path: Path to memory dump
        include_legitimate: Include likely legitimate connections
        include_listening: Include LISTENING state connections

    Returns:
        Dict with suspicious connections and summary
    """
    if not VOL3_AVAILABLE:
        return {
            "error": "volatility3 not installed",
            "hint": "Install with: pip install volatility3",
        }

    session = get_session(image_path)
    if session is None:
        return {"error": "Failed to create session"}

    init_result = session.initialize()
    if not init_result.get("ready"):
        return {
            "error": "Failed to initialize session",
            "detail": init_result.get("error", "Unknown error"),
        }

    if session.os_type != "windows":
        return {
            "error": f"Network analysis only supported for Windows (got: {session.os_type})",
        }

    # Get network connections
    logger.info("Running netscan...")
    try:
        connections = session.get_network_connections()
    except Exception as e:
        logger.error(f"netscan failed: {e}")
        return {"error": f"netscan plugin failed: {e}"}

    # Analyze connections
    suspicious: list[SuspiciousConnection] = []
    all_connections: list[dict] = []
    unique_remote_ips: set[str] = set()

    for conn in connections:
        pid = conn.get("PID")
        owner = conn.get("Owner", "unknown")
        local_addr = str(conn.get("LocalAddr", ""))
        local_port = conn.get("LocalPort", 0)
        foreign_addr = str(conn.get("ForeignAddr", ""))
        foreign_port = conn.get("ForeignPort", 0)
        state = str(conn.get("State", ""))
        proto = str(conn.get("Proto", "TCP"))
        create_time = conn.get("Created")

        # Skip listening if not requested
        if not include_listening and "LISTEN" in state.upper():
            continue

        # Track unique remote IPs
        if foreign_addr and not is_private_ip(foreign_addr):
            unique_remote_ips.add(foreign_addr)

        conn_obj = SuspiciousConnection(
            pid=pid or 0,
            process_name=str(owner),
            local_addr=local_addr,
            local_port=local_port or 0,
            remote_addr=foreign_addr,
            remote_port=foreign_port or 0,
            state=state,
            protocol=proto,
            create_time=str(create_time) if create_time else None,
        )

        process_lower = str(owner).lower()

        # Check 1: Process should not make network connections
        if process_lower in PROCESSES_NO_NETWORK:
            conn_obj.findings.append(NetworkFinding(
                type="UNEXPECTED_NETWORK",
                detail=f"{owner} should not make network connections",
                severity="HIGH",
            ))

        # Check 2: Suspicious remote port
        if foreign_port in SUSPICIOUS_PORTS:
            conn_obj.findings.append(NetworkFinding(
                type="SUSPICIOUS_PORT",
                detail=f"Connection to known suspicious port {foreign_port}: {SUSPICIOUS_PORTS[foreign_port]}",
                severity="HIGH",
            ))

        # Check 3: Non-web process making web connections
        if foreign_port in WEB_PORTS and process_lower not in WEB_PROCESSES:
            if not is_private_ip(foreign_addr):
                conn_obj.findings.append(NetworkFinding(
                    type="NON_BROWSER_WEB",
                    detail=f"{owner} is making web connections (port {foreign_port}) but is not a known web application",
                    severity="MEDIUM",
                ))

        # Check 4: LOLBin with network activity
        if is_lolbin(owner):
            conn_obj.findings.append(NetworkFinding(
                type="LOLBIN_NETWORK",
                detail=f"{owner} is a Living-off-the-Land binary with network activity - common for fileless malware",
                severity="MEDIUM",
            ))

        # Check 5: Suspicious listening port
        if "LISTEN" in state.upper() and local_port in SUSPICIOUS_PORTS:
            conn_obj.findings.append(NetworkFinding(
                type="SUSPICIOUS_LISTENER",
                detail=f"Process listening on suspicious port {local_port}: {SUSPICIOUS_PORTS[local_port]}",
                severity="HIGH",
            ))

        # Calculate risk score
        if conn_obj.findings:
            severities = [f.severity for f in conn_obj.findings]
            if "CRITICAL" in severities:
                conn_obj.risk_score = "CRITICAL"
            elif "HIGH" in severities:
                conn_obj.risk_score = "HIGH"
            elif "MEDIUM" in severities:
                conn_obj.risk_score = "MEDIUM"
            else:
                conn_obj.risk_score = "LOW"
            suspicious.append(conn_obj)
        elif include_legitimate:
            all_connections.append(conn_obj.to_dict())

    # Sort by risk score
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    suspicious.sort(key=lambda c: risk_order.get(c.risk_score, 4))

    # Build summary
    high_count = sum(1 for c in suspicious if c.risk_score in ("CRITICAL", "HIGH"))
    unexpected_net = sum(1 for c in suspicious if any(f.type == "UNEXPECTED_NETWORK" for f in c.findings))
    lolbin_net = sum(1 for c in suspicious if any(f.type == "LOLBIN_NETWORK" for f in c.findings))
    suspicious_ports = sum(1 for c in suspicious if any(f.type == "SUSPICIOUS_PORT" for f in c.findings))

    summary_parts = []
    if high_count:
        summary_parts.append(f"{high_count} HIGH risk")
    if unexpected_net:
        summary_parts.append(f"{unexpected_net} unexpected network access")
    if lolbin_net:
        summary_parts.append(f"{lolbin_net} LOLBin network")
    if suspicious_ports:
        summary_parts.append(f"{suspicious_ports} suspicious ports")

    summary = f"Found {len(suspicious)} suspicious connections"
    if summary_parts:
        summary += f" ({', '.join(summary_parts)})"

    result = {
        "image_path": str(session.image_path),
        "profile": session.profile,
        "total_connections": len(connections),
        "suspicious_connections": len(suspicious),
        "connections": [c.to_dict() for c in suspicious],
        "unique_remote_ips": list(unique_remote_ips),
        "summary": summary,
    }

    if include_legitimate:
        result["all_connections"] = all_connections

    return result
