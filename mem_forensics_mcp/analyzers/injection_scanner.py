"""
Code injection detection for memory forensics.

Detects:
- RWX (Read-Write-Execute) memory regions
- Shellcode indicators
- Process hollowing
- Reflective DLL injection
- YARA signature matches (Cobalt Strike, Meterpreter, etc.)
"""
from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from ..core.session import MemorySession, get_session
from ..core.vol3_runner import VOL3_AVAILABLE

logger = logging.getLogger(__name__)

# Try to import YARA
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    yara = None


@dataclass
class InjectionFinding:
    """A finding about potential code injection."""
    type: str  # RWX_MEMORY, YARA_MATCH, SHELLCODE_INDICATOR, etc.
    detail: str
    severity: str = "MEDIUM"
    yara_rule: Optional[str] = None


@dataclass
class InjectedRegion:
    """A potentially injected memory region."""
    pid: int
    process_name: str
    vad_start: str  # Hex address
    vad_end: str
    vad_size: int
    protection: str
    tag: str
    findings: list[InjectionFinding] = field(default_factory=list)
    risk_score: str = "LOW"
    hexdump_preview: Optional[str] = None
    dump_path: Optional[str] = None
    dump_sha256: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON output."""
        return {
            "pid": self.pid,
            "process_name": self.process_name,
            "vad_start": self.vad_start,
            "vad_end": self.vad_end,
            "vad_size": self.vad_size,
            "protection": self.protection,
            "tag": self.tag,
            "findings": [
                {
                    "type": f.type,
                    "detail": f.detail,
                    "severity": f.severity,
                    "yara_rule": f.yara_rule,
                }
                for f in self.findings
            ],
            "risk_score": self.risk_score,
            "hexdump_preview": self.hexdump_preview,
            "dump_path": self.dump_path,
            "dump_sha256": self.dump_sha256,
        }


# Known shellcode signatures (first bytes)
SHELLCODE_SIGNATURES = {
    # x64 shellcode starters
    b"\x48\x31\xc9": "x64 XOR RCX, RCX (common shellcode start)",
    b"\x48\x83\xe4\xf0": "x64 Stack alignment (AND RSP, -0x10)",
    b"\x48\x89\xe5": "x64 MOV RBP, RSP (stack frame setup)",
    b"\xfc\x48\x83": "x64 Metasploit-style shellcode (CLD; SUB RSP)",

    # x86 shellcode starters
    b"\x31\xc9": "x86 XOR ECX, ECX",
    b"\x31\xc0": "x86 XOR EAX, EAX",
    b"\x31\xdb": "x86 XOR EBX, EBX",
    b"\x68": "x86 PUSH (common for string building)",
    b"\x60\x89\xe5": "x86 PUSHAD; MOV EBP, ESP",

    # NOP sleds
    b"\x90\x90\x90\x90": "NOP sled detected",

    # Cobalt Strike beacon markers
    b"\x4d\x5a\x41\x52": "MZ header with 'AR' (possible reflective DLL)",
}

# Protection flags that indicate injection
SUSPICIOUS_PROTECTIONS = {
    "PAGE_EXECUTE_READWRITE": "RWX - highly suspicious",
    "PAGE_EXECUTE_WRITECOPY": "Execute + WriteCopy - suspicious",
}


def find_injected_code(
    image_path: str,
    pid: Optional[int] = None,
    yara_scan: bool = True,
    yara_rules_path: Optional[str] = None,
    dump_payloads: bool = False,
    dump_dir: Optional[str] = None,
) -> dict[str, Any]:
    """
    Scan for code injection (shellcode, reflective DLLs, process hollowing).

    Uses malfind to find suspicious memory regions, then applies:
    - RWX protection detection
    - Shellcode signature matching
    - YARA signature scanning (if enabled)

    Args:
        image_path: Path to memory dump
        pid: Scan specific process only (None for all)
        yara_scan: Scan with YARA rules if available
        yara_rules_path: Custom YARA rules path (uses bundled if None)
        dump_payloads: Dump detected payloads to disk
        dump_dir: Directory for dumped payloads

    Returns:
        Dict with injection findings and summary
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
            "error": f"Injection scanning only supported for Windows (got: {session.os_type})",
        }

    # Run malfind
    logger.info("Running malfind...")
    try:
        malfind_results = session.run_plugin("windows.malfind.Malfind")
    except Exception as e:
        logger.error(f"malfind failed: {e}")
        return {"error": f"malfind plugin failed: {e}"}

    # Load YARA rules if scanning enabled
    yara_rules = None
    if yara_scan and YARA_AVAILABLE:
        yara_rules = _load_yara_rules(yara_rules_path)

    # Process malfind results
    injections: list[InjectedRegion] = []

    for result in malfind_results:
        result_pid = result.get("PID")

        # Filter by PID if specified
        if pid is not None and result_pid != pid:
            continue

        process_name = result.get("Process", "unknown")
        vad_start = result.get("Start VPN", "0x0")
        vad_end = result.get("End VPN", "0x0")
        protection = result.get("Protection", "")
        tag = result.get("Tag", "")
        hexdump = result.get("Hexdump", "")
        disasm = result.get("Disasm", "")

        # Parse hexdump to bytes for analysis
        raw_bytes = _parse_hexdump(hexdump)

        # Calculate size
        try:
            start_int = int(vad_start, 16) if isinstance(vad_start, str) else int(vad_start)
            end_int = int(vad_end, 16) if isinstance(vad_end, str) else int(vad_end)
            vad_size = end_int - start_int
        except (ValueError, TypeError):
            vad_size = 0

        region = InjectedRegion(
            pid=result_pid,
            process_name=str(process_name),
            vad_start=hex(start_int) if isinstance(vad_start, int) else str(vad_start),
            vad_end=hex(end_int) if isinstance(vad_end, int) else str(vad_end),
            vad_size=vad_size,
            protection=str(protection),
            tag=str(tag),
            hexdump_preview=hexdump[:200] if hexdump else None,
        )

        # Check protection flags
        prot_str = str(protection)
        if "EXECUTE" in prot_str and "WRITE" in prot_str:
            severity = "HIGH" if "READWRITE" in prot_str else "MEDIUM"
            region.findings.append(InjectionFinding(
                type="RWX_MEMORY",
                detail=f"Memory region has {prot_str} protection - suspicious for code execution",
                severity=severity,
            ))

        # Check for shellcode signatures
        if raw_bytes:
            for sig_bytes, description in SHELLCODE_SIGNATURES.items():
                if raw_bytes.startswith(sig_bytes):
                    region.findings.append(InjectionFinding(
                        type="SHELLCODE_INDICATOR",
                        detail=description,
                        severity="HIGH",
                    ))
                    break

            # Check for MZ header (PE file in memory)
            if raw_bytes[:2] == b"MZ":
                region.findings.append(InjectionFinding(
                    type="PE_HEADER_DETECTED",
                    detail="PE file (MZ header) found in memory region - possible reflective DLL or process hollowing",
                    severity="CRITICAL",
                ))

        # YARA scanning
        if yara_rules and raw_bytes:
            matches = yara_rules.match(data=raw_bytes)
            for match in matches:
                region.findings.append(InjectionFinding(
                    type="YARA_MATCH",
                    detail=f"YARA rule matched: {match.rule}",
                    severity="CRITICAL",
                    yara_rule=match.rule,
                ))

        # Calculate risk score based on findings
        if region.findings:
            severities = [f.severity for f in region.findings]
            if "CRITICAL" in severities:
                region.risk_score = "CRITICAL"
            elif "HIGH" in severities:
                region.risk_score = "HIGH"
            elif "MEDIUM" in severities:
                region.risk_score = "MEDIUM"
            else:
                region.risk_score = "LOW"

            # Dump payload if requested
            if dump_payloads and raw_bytes:
                region.dump_path, region.dump_sha256 = _dump_payload(
                    raw_bytes, result_pid, region.vad_start, dump_dir
                )

            injections.append(region)

    # Sort by risk score
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    injections.sort(key=lambda i: risk_order.get(i.risk_score, 4))

    # Build summary
    critical_count = sum(1 for i in injections if i.risk_score == "CRITICAL")
    high_count = sum(1 for i in injections if i.risk_score == "HIGH")
    yara_matches = sum(1 for i in injections if any(f.type == "YARA_MATCH" for f in i.findings))
    pe_headers = sum(1 for i in injections if any(f.type == "PE_HEADER_DETECTED" for f in i.findings))

    summary_parts = []
    if critical_count:
        summary_parts.append(f"{critical_count} CRITICAL")
    if high_count:
        summary_parts.append(f"{high_count} HIGH")
    if yara_matches:
        summary_parts.append(f"{yara_matches} YARA matches")
    if pe_headers:
        summary_parts.append(f"{pe_headers} PE headers (reflective DLL/hollowing)")

    summary = f"Found {len(injections)} potential code injections"
    if summary_parts:
        summary += f" ({', '.join(summary_parts)})"

    return {
        "image_path": str(session.image_path),
        "profile": session.profile,
        "yara_available": YARA_AVAILABLE,
        "yara_rules_loaded": yara_rules is not None,
        "injections_found": len(injections),
        "injections": [i.to_dict() for i in injections],
        "summary": summary,
    }


def _parse_hexdump(hexdump: str) -> bytes:
    """Parse volatility hexdump output to raw bytes."""
    if not hexdump:
        return b""

    raw = []
    for line in hexdump.split("\n"):
        # Format: "0x00000000  48 83 ec 28 48 8b ..."
        parts = line.split()
        for part in parts[1:]:  # Skip address
            if len(part) == 2:
                try:
                    raw.append(int(part, 16))
                except ValueError:
                    break
    return bytes(raw)


def _load_yara_rules(rules_path: Optional[str] = None) -> Optional["yara.Rules"]:
    """Load YARA rules from file or bundled rules."""
    if not YARA_AVAILABLE:
        return None

    if rules_path:
        path = Path(rules_path)
        if path.exists():
            try:
                return yara.compile(filepath=str(path))
            except yara.Error as e:
                logger.warning(f"Failed to compile YARA rules from {path}: {e}")
                return None

    # Try bundled rules (repo_root/rules/memory_yara/)
    bundled_path = Path(__file__).parent.parent.parent / "rules" / "memory_yara"
    if bundled_path.exists():
        try:
            # Compile all .yar files in the directory
            rule_files = list(bundled_path.glob("*.yar"))
            if rule_files:
                filepaths = {f.stem: str(f) for f in rule_files}
                return yara.compile(filepaths=filepaths)
        except yara.Error as e:
            logger.warning(f"Failed to compile bundled YARA rules: {e}")

    return None


def _dump_payload(
    data: bytes,
    pid: int,
    vad_start: str,
    dump_dir: Optional[str] = None,
) -> tuple[Optional[str], Optional[str]]:
    """
    Dump payload bytes to file.

    Returns:
        Tuple of (dump_path, sha256_hash)
    """
    if not data:
        return None, None

    # Calculate hash
    sha256 = hashlib.sha256(data).hexdigest()

    # Determine dump directory
    if dump_dir:
        dump_path = Path(dump_dir)
    else:
        dump_path = Path("/tmp/memory_dumps")

    dump_path.mkdir(parents=True, exist_ok=True)

    # Create filename
    vad_clean = vad_start.replace("0x", "")
    filename = f"injection_{pid}_{vad_clean}.bin"
    filepath = dump_path / filename

    try:
        with open(filepath, "wb") as f:
            f.write(data)
        return str(filepath), sha256
    except Exception as e:
        logger.error(f"Failed to dump payload: {e}")
        return None, sha256
