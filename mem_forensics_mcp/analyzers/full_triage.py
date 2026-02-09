"""
Full triage orchestrator for memory forensics.

Runs all analyzers and produces an executive summary with:
- Risk level assessment
- Key findings prioritized by severity
- IOCs for handoff to disk forensics
- Recommended next steps
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from ..core.session import get_session
from ..core.vol3_runner import VOL3_AVAILABLE
from .process_analyzer import hunt_process_anomalies
from .injection_scanner import find_injected_code
from .network_analyzer import find_c2_connections
from .command_history import get_command_history
from .credential_extractor import extract_credentials

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """A finding from triage analysis."""
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    category: str  # process, injection, network, command, credential
    title: str
    detail: str
    iocs: list[dict[str, str]] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "detail": self.detail,
            "iocs": self.iocs,
            "recommendations": self.recommendations,
        }


def full_triage(
    image_path: str,
    quick_scan: bool = False,
) -> dict[str, Any]:
    """
    Run full automated triage of memory dump.

    Executes all analyzers and correlates findings into:
    - Executive summary
    - Prioritized findings
    - IOCs for disk forensics handoff
    - Recommended actions

    Args:
        image_path: Path to memory dump
        quick_scan: Skip slower analyses (credentials)

    Returns:
        Dict with triage results and recommendations
    """
    if not VOL3_AVAILABLE:
        return {"error": "volatility3 not installed"}

    session = get_session(image_path)
    if session is None:
        return {"error": "Failed to create session"}

    init_result = session.initialize()
    if not init_result.get("ready"):
        return {"error": init_result.get("error", "Failed to initialize")}

    findings: list[Finding] = []
    iocs: dict[str, list[str]] = {
        "sha256": [],
        "md5": [],
        "ip": [],
        "domain": [],
        "filename": [],
        "pid": [],
    }
    errors: list[str] = []

    # Track analysis results for correlation
    hidden_pids: set[int] = set()
    injection_pids: set[int] = set()
    c2_pids: set[int] = set()
    suspicious_commands: list[dict] = []

    # 1. Process Analysis
    logger.info("Running process anomaly detection...")
    try:
        process_result = hunt_process_anomalies(image_path, include_normal=False)
        if "error" not in process_result:
            for anomaly in process_result.get("anomalies", []):
                severity = anomaly.get("severity", "MEDIUM")
                atype = anomaly.get("type", "unknown")
                pid = anomaly.get("pid")
                process_name = anomaly.get("process", "unknown")

                title = f"{atype}: {process_name}"
                if pid:
                    title += f" (PID {pid})"

                detail = anomaly.get("detail", anomaly.get("reason", ""))

                finding = Finding(
                    severity=severity,
                    category="process",
                    title=title,
                    detail=detail,
                )

                if atype == "HIDDEN_PROCESS":
                    hidden_pids.add(pid)
                    finding.iocs = [{"type": "pid", "value": str(pid)}]
                    finding.recommendations = [
                        f"Dump process {pid} for analysis",
                        "Check for DKOM/rootkit indicators",
                    ]
                    iocs["pid"].append(str(pid))

                elif atype == "SUSPICIOUS_PARENT":
                    finding.recommendations = [
                        f"Investigate parent process lineage for PID {pid}",
                        "Check command line arguments",
                    ]

                findings.append(finding)
        else:
            errors.append(f"process_anomalies: {process_result.get('error')}")

    except Exception as e:
        logger.warning(f"Process analysis failed: {e}")
        errors.append(f"process_anomalies: {e}")

    # 2. Injection Analysis
    logger.info("Running injection detection...")
    try:
        injection_result = find_injected_code(image_path, yara_scan=True)
        if "error" not in injection_result:
            for inj in injection_result.get("injections", []):
                pid = inj.get("pid")
                process_name = inj.get("process_name", "unknown")
                inj_findings = inj.get("findings", [])

                # Extract finding types and details
                finding_types = [f.get("type", "") for f in inj_findings]
                finding_details = [f.get("detail", "") for f in inj_findings]

                # Determine severity based on findings
                severity = "HIGH"
                yara_rules = [f.get("yara_rule") for f in inj_findings if f.get("yara_rule")]
                if yara_rules or any("YARA" in t for t in finding_types):
                    severity = "CRITICAL"

                inj_type = "CODE_INJECTION"
                if any("SHELLCODE" in t for t in finding_types):
                    inj_type = "SHELLCODE_DETECTED"
                elif any("RWX" in t for t in finding_types):
                    inj_type = "RWX_MEMORY"

                title = f"{inj_type}: {process_name} (PID {pid})"
                detail_parts = []
                if finding_details:
                    detail_parts.append("; ".join(finding_details[:3]))
                if yara_rules:
                    detail_parts.append(f"YARA: {', '.join(yara_rules)}")
                detail = " | ".join(detail_parts) if detail_parts else "Suspicious memory region detected"

                finding = Finding(
                    severity=severity,
                    category="injection",
                    title=title,
                    detail=detail,
                    iocs=[{"type": "pid", "value": str(pid)}],
                    recommendations=[
                        f"Dump injected memory from PID {pid}",
                        "Extract and analyze payload",
                        "Check for persistence mechanisms",
                    ],
                )
                findings.append(finding)
                injection_pids.add(pid)
                iocs["pid"].append(str(pid))

                # Add filenames if available
                if process_name and process_name != "unknown":
                    iocs["filename"].append(process_name)

        else:
            errors.append(f"injection_scanner: {injection_result.get('error')}")

    except Exception as e:
        logger.warning(f"Injection analysis failed: {e}")
        errors.append(f"injection_scanner: {e}")

    # 3. Network Analysis
    logger.info("Running C2 connection detection...")
    try:
        network_result = find_c2_connections(image_path, include_legitimate=False)
        if "error" not in network_result:
            for conn in network_result.get("connections", []):
                pid = conn.get("pid")
                process_name = conn.get("process_name", "unknown")
                remote_ip = conn.get("remote_addr", "")
                remote_port = conn.get("remote_port", "")
                conn_findings = conn.get("findings", [])

                # Extract finding types for analysis
                finding_types = [f.get("type", "") for f in conn_findings]
                finding_details = [f.get("detail", "") for f in conn_findings]

                severity = "HIGH"
                if any("UNEXPECTED" in t for t in finding_types):
                    severity = "CRITICAL"
                if any("SUSPICIOUS_PORT" in t for t in finding_types):
                    severity = "HIGH"

                title = f"Suspicious connection: {process_name} -> {remote_ip}:{remote_port}"
                detail = "; ".join(finding_details) if finding_details else "Unusual network activity"

                finding = Finding(
                    severity=severity,
                    category="network",
                    title=title,
                    detail=detail,
                    iocs=[
                        {"type": "ip", "value": remote_ip},
                        {"type": "pid", "value": str(pid)},
                    ],
                    recommendations=[
                        f"Block outbound to {remote_ip}",
                        "Capture network traffic for analysis",
                        f"Investigate process {pid}",
                    ],
                )
                findings.append(finding)
                c2_pids.add(pid)
                if remote_ip:
                    iocs["ip"].append(remote_ip)

        else:
            errors.append(f"c2_connections: {network_result.get('error')}")

    except Exception as e:
        logger.warning(f"Network analysis failed: {e}")
        errors.append(f"c2_connections: {e}")

    # 4. Command History
    logger.info("Running command history analysis...")
    try:
        command_result = get_command_history(image_path, include_benign=False)
        if "error" not in command_result:
            for cmd in command_result.get("commands", []):
                cmd_findings = cmd.get("findings", [])
                if not cmd_findings:
                    continue

                command_text = cmd.get("command", "")[:100]
                pid = cmd.get("pid")
                process_name = cmd.get("process_name", "unknown")

                # Get highest severity from findings
                severity = "MEDIUM"
                categories = []
                for f in cmd_findings:
                    categories.append(f.get("type", ""))
                    if f.get("severity") == "CRITICAL":
                        severity = "CRITICAL"
                    elif f.get("severity") == "HIGH" and severity != "CRITICAL":
                        severity = "HIGH"

                title = f"Suspicious command: {process_name} (PID {pid})"
                detail = f"Command: {command_text}\nCategories: {', '.join(set(categories))}"

                finding = Finding(
                    severity=severity,
                    category="command",
                    title=title,
                    detail=detail,
                    recommendations=[
                        "Correlate with timeline",
                        "Check for related persistence",
                    ],
                )
                findings.append(finding)
                suspicious_commands.append(cmd)

        else:
            errors.append(f"command_history: {command_result.get('error')}")

    except Exception as e:
        logger.warning(f"Command history analysis failed: {e}")
        errors.append(f"command_history: {e}")

    # 5. Credential Extraction (skip in quick scan)
    if not quick_scan:
        logger.info("Running credential extraction...")
        try:
            cred_result = extract_credentials(image_path)
            if "error" not in cred_result:
                cred_count = cred_result.get("credentials_found", 0)
                risk_level = cred_result.get("risk_level", "LOW")

                if cred_count > 0 and risk_level in ("HIGH", "CRITICAL"):
                    finding = Finding(
                        severity=risk_level,
                        category="credential",
                        title=f"Credential artifacts found ({cred_count})",
                        detail="; ".join(cred_result.get("risk_reasons", [])),
                        recommendations=[
                            "Rotate compromised credentials",
                            "Check for pass-the-hash activity",
                            "Audit service account usage",
                        ],
                    )
                    findings.append(finding)

            else:
                errors.append(f"credentials: {cred_result.get('error')}")

        except Exception as e:
            logger.warning(f"Credential extraction failed: {e}")
            errors.append(f"credentials: {e}")

    # Correlate findings
    correlated_pids = hidden_pids & injection_pids
    if correlated_pids:
        findings.append(Finding(
            severity="CRITICAL",
            category="correlation",
            title=f"Hidden process with code injection: PID {', '.join(map(str, correlated_pids))}",
            detail="Process is both hidden from pslist AND has injected code - strong indicator of rootkit/malware",
            iocs=[{"type": "pid", "value": str(p)} for p in correlated_pids],
            recommendations=[
                "Priority analysis target",
                "Full memory dump of process",
                "Disk forensics for related artifacts",
            ],
        ))

    injection_with_c2 = injection_pids & c2_pids
    if injection_with_c2:
        findings.append(Finding(
            severity="CRITICAL",
            category="correlation",
            title=f"Injected process with C2 connection: PID {', '.join(map(str, injection_with_c2))}",
            detail="Process has injected code AND active network connections - likely active compromise",
            iocs=[{"type": "pid", "value": str(p)} for p in injection_with_c2],
            recommendations=[
                "Immediate isolation recommended",
                "Capture network traffic",
                "Full forensic acquisition",
            ],
        ))

    # Sort findings by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: severity_order.get(f.severity, 4))

    # Determine overall risk level
    risk_level = "LOW"
    if any(f.severity == "CRITICAL" for f in findings):
        risk_level = "CRITICAL"
    elif any(f.severity == "HIGH" for f in findings):
        risk_level = "HIGH"
    elif any(f.severity == "MEDIUM" for f in findings):
        risk_level = "MEDIUM"

    # Build summary
    severity_counts = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    category_counts = {}
    for f in findings:
        category_counts[f.category] = category_counts.get(f.category, 0) + 1

    # Deduplicate IOCs
    for ioc_type in iocs:
        iocs[ioc_type] = list(set(iocs[ioc_type]))

    # Build recommended actions
    actions = []
    if risk_level == "CRITICAL":
        actions.append("IMMEDIATE: Consider system isolation")
    if injection_pids:
        actions.append(f"Dump and analyze injected processes: {', '.join(map(str, list(injection_pids)[:5]))}")
    if c2_pids:
        actions.append("Block identified C2 IP addresses")
    if hidden_pids:
        actions.append("Investigate rootkit/DKOM techniques")
    if iocs["ip"]:
        actions.append(f"Hunt IOCs on other systems: {len(iocs['ip'])} IPs, {len(iocs['pid'])} PIDs")

    return {
        "image_path": str(session.image_path),
        "profile": session.profile,
        "risk_level": risk_level,
        "summary": {
            "total_findings": len(findings),
            "by_severity": severity_counts,
            "by_category": category_counts,
        },
        "findings": [f.to_dict() for f in findings[:20]],  # Top 20 findings
        "iocs": {k: v for k, v in iocs.items() if v},  # Only non-empty
        "recommended_actions": actions,
        "analysis_errors": errors if errors else None,
    }
