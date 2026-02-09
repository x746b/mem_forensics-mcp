"""
Credential extraction for memory forensics.

Extracts authentication artifacts from:
- SAM database (hashdump)
- LSA secrets (lsadump)
- Cached domain credentials
- Kerberos tickets
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
class CredentialFinding:
    """A credential artifact found in memory."""
    type: str  # HASH, PLAINTEXT, TICKET, LSA_SECRET
    source: str  # hashdump, lsadump, cachedump, kerberos
    account: str
    value: str  # Hash, password, or ticket data
    domain: Optional[str] = None
    severity: str = "CRITICAL"
    detail: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "source": self.source,
            "account": self.account,
            "value": self.value,
            "domain": self.domain,
            "severity": self.severity,
            "detail": self.detail,
        }


def extract_credentials(
    image_path: str,
    include_machine_accounts: bool = False,
) -> dict[str, Any]:
    """
    Extract credential artifacts from memory.

    Runs multiple vol3 plugins to recover:
    - Local account hashes (SAM)
    - LSA secrets
    - Cached domain credentials
    - Kerberos tickets (if available)

    Args:
        image_path: Path to memory dump
        include_machine_accounts: Include machine account ($) hashes

    Returns:
        Dict with extracted credentials and analysis
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
        return {"error": f"Credential extraction only supported for Windows (got: {session.os_type})"}

    credentials: list[CredentialFinding] = []
    errors: list[str] = []

    # Try hashdump for SAM hashes
    logger.info("Running hashdump...")
    try:
        hashdump_results = session.run_plugin("windows.hashdump.Hashdump")
        for result in hashdump_results:
            user = str(result.get("User", ""))
            rid = result.get("rid", "")
            lm_hash = str(result.get("lmhash", ""))
            nt_hash = str(result.get("nthash", ""))

            # Skip machine accounts unless requested
            if user.endswith("$") and not include_machine_accounts:
                continue

            # Skip empty/disabled hashes
            if nt_hash in ("", "31d6cfe0d16ae931b73c59d7e0c089c0"):
                continue

            credentials.append(CredentialFinding(
                type="NTLM_HASH",
                source="hashdump",
                account=user,
                value=f"{lm_hash}:{nt_hash}",
                detail=f"RID: {rid}",
            ))

    except Exception as e:
        logger.warning(f"hashdump failed: {e}")
        errors.append(f"hashdump: {e}")

    # Try lsadump for LSA secrets
    logger.info("Running lsadump...")
    try:
        lsadump_results = session.run_plugin("windows.lsadump.Lsadump")
        for result in lsadump_results:
            key = str(result.get("Key", ""))
            secret = str(result.get("Secret", ""))
            hex_data = str(result.get("Hex", ""))

            if not key or key.startswith("$"):
                continue

            # Detect secret type
            secret_type = "LSA_SECRET"
            detail = None

            if "DefaultPassword" in key:
                secret_type = "AUTOLOGON_PASSWORD"
                detail = "AutoLogon credential"
            elif "DPAPI" in key:
                secret_type = "DPAPI_KEY"
                detail = "Data Protection API key"
            elif "_SC_" in key:
                secret_type = "SERVICE_ACCOUNT"
                detail = f"Service credential: {key.replace('_SC_', '')}"
            elif "NL$" in key:
                secret_type = "CACHED_DOMAIN"
                detail = "Cached domain credential"

            value = secret if secret and secret != "N/A" else hex_data

            credentials.append(CredentialFinding(
                type=secret_type,
                source="lsadump",
                account=key,
                value=value[:100] if value else "N/A",  # Truncate long values
                detail=detail,
            ))

    except Exception as e:
        logger.warning(f"lsadump failed: {e}")
        errors.append(f"lsadump: {e}")

    # Try cachedump for domain cached credentials
    logger.info("Running cachedump...")
    try:
        cachedump_results = session.run_plugin("windows.cachedump.Cachedump")
        for result in cachedump_results:
            user = str(result.get("UserName", result.get("User", "")))
            domain = str(result.get("Domain", result.get("DomainName", "")))
            hash_val = str(result.get("Hash", result.get("hash", "")))

            if not user or not hash_val:
                continue

            credentials.append(CredentialFinding(
                type="CACHED_DOMAIN_HASH",
                source="cachedump",
                account=user,
                value=hash_val,
                domain=domain,
                detail="Domain cached credential (DCC2)",
            ))

    except Exception as e:
        logger.warning(f"cachedump failed: {e}")
        errors.append(f"cachedump: {e}")

    # Analyze findings
    summary_parts = []
    type_counts: dict[str, int] = {}
    for cred in credentials:
        type_counts[cred.type] = type_counts.get(cred.type, 0) + 1

    for ctype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        summary_parts.append(f"{count} {ctype}")

    summary = f"Extracted {len(credentials)} credentials"
    if summary_parts:
        summary += f" ({', '.join(summary_parts[:4])})"

    # Risk assessment
    risk_level = "LOW"
    risk_reasons = []

    if any(c.type == "NTLM_HASH" for c in credentials):
        risk_level = "HIGH"
        risk_reasons.append("Local account hashes found - can be cracked or passed")

    if any(c.type == "CACHED_DOMAIN_HASH" for c in credentials):
        risk_level = "HIGH"
        risk_reasons.append("Domain cached credentials found - can be cracked offline")

    if any(c.type == "AUTOLOGON_PASSWORD" for c in credentials):
        risk_level = "CRITICAL"
        risk_reasons.append("Plaintext AutoLogon password found")

    if any(c.type == "SERVICE_ACCOUNT" for c in credentials):
        risk_level = max(risk_level, "MEDIUM", key=lambda x: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(x))
        risk_reasons.append("Service account credentials found")

    return {
        "image_path": str(session.image_path),
        "profile": session.profile,
        "credentials_found": len(credentials),
        "credentials": [c.to_dict() for c in credentials],
        "type_summary": type_counts,
        "risk_level": risk_level,
        "risk_reasons": risk_reasons,
        "summary": summary,
        "errors": errors if errors else None,
    }
