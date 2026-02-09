"""
Process analysis for memory forensics.

Detects hidden processes, unusual parent-child relationships,
and other process anomalies.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from ..core.session import MemorySession, get_session
from ..core.vol3_runner import VOL3_AVAILABLE
from ..utils.parent_child_rules import (
    get_process_rule,
    is_valid_parent,
    is_suspicious_name,
    should_have_network,
    is_lolbin,
    PROCESSES_NO_NETWORK,
)

logger = logging.getLogger(__name__)


@dataclass
class ProcessFinding:
    """A single finding about a process."""
    type: str  # HIDDEN_PROCESS, UNUSUAL_PARENT, etc.
    detail: str
    severity: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL


@dataclass
class ProcessAnomaly:
    """Anomalous process with findings."""
    pid: int
    name: str
    ppid: Optional[int]
    parent_name: Optional[str]
    create_time: Optional[str]
    path: Optional[str]
    cmdline: Optional[str]
    findings: list[ProcessFinding] = field(default_factory=list)
    risk_score: str = "LOW"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON output."""
        return {
            "pid": self.pid,
            "name": self.name,
            "ppid": self.ppid,
            "parent_name": self.parent_name,
            "create_time": self.create_time,
            "path": self.path,
            "cmdline": self.cmdline,
            "findings": [
                {"type": f.type, "detail": f.detail, "severity": f.severity}
                for f in self.findings
            ],
            "risk_score": self.risk_score,
        }


def hunt_process_anomalies(
    image_path: str,
    include_normal: bool = False,
) -> dict[str, Any]:
    """
    Hunt for process anomalies in memory.

    Detects:
    - Hidden processes (in psscan but not pslist - DKOM/rootkit)
    - Unusual parent-child relationships
    - Suspicious process names (masquerading)
    - Processes that should be singletons but have multiple instances
    - lsass.exe with children (credential dumping indicator)

    Args:
        image_path: Path to memory dump
        include_normal: Include normal processes in output

    Returns:
        Dict with anomalies and summary
    """
    if not VOL3_AVAILABLE:
        return {
            "error": "volatility3 not installed",
            "hint": "Install with: pip install volatility3",
        }

    session = get_session(image_path)
    if session is None:
        return {"error": "Failed to create session"}

    # Initialize session
    init_result = session.initialize()
    if not init_result.get("ready"):
        return {
            "error": "Failed to initialize session",
            "detail": init_result.get("error", "Unknown error"),
        }

    if session.os_type != "windows":
        return {
            "error": f"Process anomaly detection only supported for Windows (got: {session.os_type})",
        }

    # Get processes from pslist
    logger.info("Running pslist...")
    pslist_procs = session.run_plugin("windows.pslist.PsList")

    # Build process lookup tables
    pid_to_proc: dict[int, dict] = {}
    pid_to_name: dict[int, str] = {}
    name_counts: dict[str, int] = {}

    for proc in pslist_procs:
        pid = proc.get("PID")
        name = proc.get("ImageFileName", "unknown")
        if pid is not None:
            pid_to_proc[pid] = proc
            pid_to_name[pid] = name
            name_lower = name.lower()
            name_counts[name_lower] = name_counts.get(name_lower, 0) + 1

    pslist_pids = set(pid_to_proc.keys())
    logger.info(f"Found {len(pslist_pids)} processes in pslist")

    # Get processes from psscan (includes hidden/terminated)
    logger.info("Running psscan...")
    psscan_procs = session.run_plugin("windows.psscan.PsScan")

    psscan_pids = set()
    psscan_by_pid: dict[int, dict] = {}
    for proc in psscan_procs:
        pid = proc.get("PID")
        if pid is not None:
            psscan_pids.add(pid)
            psscan_by_pid[pid] = proc

    logger.info(f"Found {len(psscan_pids)} processes in psscan")

    # Find anomalies
    anomalies: list[ProcessAnomaly] = []
    all_processes: list[dict] = []

    # Check processes in pslist
    for pid, proc in pid_to_proc.items():
        name = proc.get("ImageFileName", "unknown")
        ppid = proc.get("PPID")
        parent_name = pid_to_name.get(ppid, "unknown") if ppid else None
        create_time = proc.get("CreateTime")

        anomaly = ProcessAnomaly(
            pid=pid,
            name=name,
            ppid=ppid,
            parent_name=parent_name,
            create_time=str(create_time) if create_time else None,
            path=None,  # TODO: Get from cmdline or handles
            cmdline=None,
        )

        # Check for suspicious name
        is_suspicious, reason = is_suspicious_name(name)
        if is_suspicious:
            anomaly.findings.append(ProcessFinding(
                type="SUSPICIOUS_NAME",
                detail=reason,
                severity="HIGH",
            ))

        # Check parent-child relationship
        if parent_name and parent_name != "unknown":
            is_valid, reason = is_valid_parent(name, parent_name)
            if not is_valid:
                anomaly.findings.append(ProcessFinding(
                    type="UNUSUAL_PARENT",
                    detail=reason,
                    severity="HIGH",
                ))

        # Check singleton violations
        rule = get_process_rule(name)
        if rule and rule.singleton:
            count = name_counts.get(name.lower(), 0)
            if count > 1:
                anomaly.findings.append(ProcessFinding(
                    type="SINGLETON_VIOLATION",
                    detail=f"{name} should be unique but found {count} instances",
                    severity="HIGH",
                ))

        # Check if lsass has children
        if name.lower() == "lsass.exe":
            children = [p for p in pid_to_proc.values() if p.get("PPID") == pid]
            if children:
                child_names = [p.get("ImageFileName", "?") for p in children]
                anomaly.findings.append(ProcessFinding(
                    type="LSASS_HAS_CHILDREN",
                    detail=f"lsass.exe spawned processes: {child_names}. Possible credential dumping.",
                    severity="CRITICAL",
                ))

        # Mark LOLBins (informational)
        if is_lolbin(name):
            anomaly.findings.append(ProcessFinding(
                type="LOLBIN",
                detail=f"{name} is a Living-off-the-Land binary commonly abused by attackers",
                severity="LOW",
            ))

        # Calculate risk score
        if anomaly.findings:
            severities = [f.severity for f in anomaly.findings]
            if "CRITICAL" in severities:
                anomaly.risk_score = "CRITICAL"
            elif "HIGH" in severities:
                anomaly.risk_score = "HIGH"
            elif "MEDIUM" in severities:
                anomaly.risk_score = "MEDIUM"
            else:
                anomaly.risk_score = "LOW"
            anomalies.append(anomaly)
        elif include_normal:
            all_processes.append(anomaly.to_dict())

    # Check for hidden processes (in psscan but not pslist)
    hidden_pids = psscan_pids - pslist_pids
    for pid in hidden_pids:
        proc = psscan_by_pid.get(pid, {})
        name = proc.get("ImageFileName", "unknown")

        # Check if it's just a terminated process or truly hidden
        exit_time = proc.get("ExitTime")

        anomaly = ProcessAnomaly(
            pid=pid,
            name=name,
            ppid=proc.get("PPID"),
            parent_name=None,
            create_time=str(proc.get("CreateTime")) if proc.get("CreateTime") else None,
            path=None,
            cmdline=None,
        )

        if exit_time:
            # Process terminated - less suspicious
            anomaly.findings.append(ProcessFinding(
                type="TERMINATED_PROCESS",
                detail=f"Process terminated at {exit_time}. Found in psscan only.",
                severity="LOW",
            ))
            anomaly.risk_score = "LOW"
        else:
            # No exit time - possibly hidden via DKOM
            anomaly.findings.append(ProcessFinding(
                type="HIDDEN_PROCESS",
                detail="Process found in psscan but missing from pslist. Possible DKOM/rootkit hiding.",
                severity="CRITICAL",
            ))
            anomaly.risk_score = "CRITICAL"

        anomalies.append(anomaly)

    # Sort anomalies by risk score
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    anomalies.sort(key=lambda a: risk_order.get(a.risk_score, 4))

    # Build summary
    critical_count = sum(1 for a in anomalies if a.risk_score == "CRITICAL")
    high_count = sum(1 for a in anomalies if a.risk_score == "HIGH")
    hidden_count = sum(1 for a in anomalies if any(f.type == "HIDDEN_PROCESS" for f in a.findings))
    terminated_count = sum(1 for a in anomalies if any(f.type == "TERMINATED_PROCESS" for f in a.findings))

    summary_parts = []
    if critical_count:
        summary_parts.append(f"{critical_count} CRITICAL")
    if high_count:
        summary_parts.append(f"{high_count} HIGH")
    if hidden_count:
        summary_parts.append(f"{hidden_count} hidden via DKOM")
    if terminated_count:
        summary_parts.append(f"{terminated_count} terminated")

    summary = f"Found {len(anomalies)} anomalies"
    if summary_parts:
        summary += f" ({', '.join(summary_parts)})"

    result = {
        "image_path": str(session.image_path),
        "profile": session.profile,
        "total_processes": len(pslist_pids),
        "psscan_total": len(psscan_pids),
        "anomalies_found": len(anomalies),
        "anomalies": [a.to_dict() for a in anomalies],
        "summary": summary,
    }

    if include_normal:
        result["all_processes"] = all_processes

    return result


def get_process_tree(
    image_path: str,
    root_pid: Optional[int] = None,
    highlight_suspicious: bool = True,
) -> dict[str, Any]:
    """
    Get process tree showing parent-child relationships.

    Args:
        image_path: Path to memory dump
        root_pid: Start tree from this PID (None for full tree)
        highlight_suspicious: Mark suspicious processes

    Returns:
        Dict with process tree
    """
    if not VOL3_AVAILABLE:
        return {"error": "volatility3 not installed"}

    session = get_session(image_path)
    if session is None:
        return {"error": "Failed to create session"}

    init_result = session.initialize()
    if not init_result.get("ready"):
        return {"error": init_result.get("error", "Failed to initialize")}

    # Get processes
    processes = session.run_plugin("windows.pslist.PsList")

    # Build parent-child relationships
    pid_to_proc: dict[int, dict] = {}
    children: dict[int, list[int]] = {}

    for proc in processes:
        pid = proc.get("PID")
        ppid = proc.get("PPID")
        if pid is not None:
            pid_to_proc[pid] = {
                "pid": pid,
                "name": proc.get("ImageFileName", "unknown"),
                "ppid": ppid,
                "create_time": str(proc.get("CreateTime")) if proc.get("CreateTime") else None,
            }

            if ppid is not None:
                if ppid not in children:
                    children[ppid] = []
                children[ppid].append(pid)

    def build_tree(pid: int, depth: int = 0) -> Optional[dict]:
        """Recursively build process tree."""
        proc = pid_to_proc.get(pid)
        if proc is None:
            return None

        node = {
            "pid": proc["pid"],
            "name": proc["name"],
            "create_time": proc["create_time"],
            "depth": depth,
            "children": [],
        }

        # Check for suspicious indicators
        if highlight_suspicious:
            name = proc["name"]
            parent_name = pid_to_proc.get(proc.get("ppid"), {}).get("name")

            suspicious_indicators = []

            # Check parent-child
            if parent_name:
                is_valid, reason = is_valid_parent(name, parent_name)
                if not is_valid:
                    suspicious_indicators.append(f"Unusual parent: {reason}")

            # Check name
            is_suspicious, reason = is_suspicious_name(name)
            if is_suspicious:
                suspicious_indicators.append(reason)

            # Check LOLBin
            if is_lolbin(name):
                suspicious_indicators.append("LOLBin")

            if suspicious_indicators:
                node["suspicious"] = True
                node["indicators"] = suspicious_indicators

        # Add children
        for child_pid in children.get(pid, []):
            child_node = build_tree(child_pid, depth + 1)
            if child_node:
                node["children"].append(child_node)

        return node

    # Build tree(s)
    if root_pid is not None:
        # Single tree from specified root
        tree = build_tree(root_pid)
        if tree is None:
            return {"error": f"PID {root_pid} not found"}
        trees = [tree]
    else:
        # Find root processes (those without parents or parent not in dump)
        root_pids = [
            pid for pid, proc in pid_to_proc.items()
            if proc.get("ppid") not in pid_to_proc
        ]
        trees = [build_tree(pid) for pid in sorted(root_pids) if pid in pid_to_proc]
        trees = [t for t in trees if t is not None]

    return {
        "image_path": str(session.image_path),
        "profile": session.profile,
        "total_processes": len(pid_to_proc),
        "trees": trees,
    }
