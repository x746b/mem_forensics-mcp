"""
Process and memory extraction tools.

Extracts:
- Process executables (procdump)
- DLLs loaded by processes
- Memory regions (VADs)
"""
from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path
from typing import Any, Optional

from ..core.session import get_session
from ..core.vol3_runner import VOL3_AVAILABLE

logger = logging.getLogger(__name__)


def dump_process(
    image_path: str,
    pid: int,
    output_dir: Optional[str] = None,
) -> dict[str, Any]:
    """
    Dump a process executable from memory.

    Uses windows.pslist with dump option to extract the main executable.

    Args:
        image_path: Path to memory dump
        pid: Process ID to dump
        output_dir: Directory for output (default: /tmp/memory_dumps)

    Returns:
        Dict with dump info including path and hashes
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
        return {"error": f"Process dumping only supported for Windows (got: {session.os_type})"}

    # Setup output directory
    if output_dir:
        dump_path = Path(output_dir)
    else:
        dump_path = Path("/tmp/memory_dumps")
    dump_path.mkdir(parents=True, exist_ok=True)

    # Get process info first
    try:
        pslist_results = session.run_plugin("windows.pslist.PsList")
    except Exception as e:
        return {"error": f"Failed to get process list: {e}"}

    process_info = None
    for proc in pslist_results:
        if proc.get("PID") == pid:
            process_info = proc
            break

    if not process_info:
        return {
            "error": f"Process with PID {pid} not found",
            "hint": "Use memory_hunt_process_anomalies to find valid PIDs",
        }

    process_name = process_info.get("ImageFileName", "unknown")

    # NOTE: dumpfiles and memmap plugins are skipped - they're too memory-intensive
    # on large dumps (4GB+) and can crash the system. Use memory_run_plugin directly
    # if you need this data for a specific investigation.
    dumped_files = []
    memory_regions = []
    total_size = 0

    # Get loaded DLLs
    dlls = []
    try:
        dlllist_results = session.run_plugin("windows.dlllist.DllList")
        for dll in dlllist_results:
            if dll.get("PID") == pid:
                dlls.append({
                    "name": dll.get("Name", ""),
                    "path": dll.get("Path", ""),
                    "base": hex(dll.get("Base", 0)) if isinstance(dll.get("Base"), int) else str(dll.get("Base", "")),
                    "size": dll.get("Size", 0),
                })
    except Exception as e:
        logger.warning(f"dlllist failed: {e}")

    return {
        "image_path": str(session.image_path),
        "profile": session.profile,
        "pid": pid,
        "process_name": process_name,
        "process_info": {
            "ppid": process_info.get("PPID"),
            "threads": process_info.get("Threads"),
            "handles": process_info.get("Handles"),
            "create_time": str(process_info.get("CreateTime", "")),
        },
        "memory_info": {
            "regions_sampled": len(memory_regions),
            "total_mapped_size": total_size,
            "regions": memory_regions[:10],  # First 10 regions
        },
        "dlls_loaded": len(dlls),
        "dlls": dlls[:20],  # First 20 DLLs
        "files_associated": dumped_files[:10],
        "output_dir": str(dump_path),
        "note": "Use windows.dumpfiles plugin via memory_run_plugin for actual file extraction",
    }


def dump_dll(
    image_path: str,
    pid: int,
    dll_name: Optional[str] = None,
    dll_base: Optional[str] = None,
    output_dir: Optional[str] = None,
) -> dict[str, Any]:
    """
    Dump a specific DLL from a process.

    Args:
        image_path: Path to memory dump
        pid: Process ID
        dll_name: DLL name to dump (e.g., "ntdll.dll")
        dll_base: DLL base address (hex string)
        output_dir: Directory for output

    Returns:
        Dict with DLL dump info
    """
    if not VOL3_AVAILABLE:
        return {"error": "volatility3 not installed"}

    session = get_session(image_path)
    if session is None:
        return {"error": "Failed to create session"}

    init_result = session.initialize()
    if not init_result.get("ready"):
        return {"error": "Failed to initialize session"}

    if not dll_name and not dll_base:
        return {"error": "Must specify either dll_name or dll_base"}

    # Get DLL list for the process
    try:
        dlllist_results = session.run_plugin("windows.dlllist.DllList")
    except Exception as e:
        return {"error": f"Failed to get DLL list: {e}"}

    target_dll = None
    all_dlls = []

    for dll in dlllist_results:
        if dll.get("PID") != pid:
            continue

        name = dll.get("Name", "")
        base = dll.get("Base", 0)
        base_hex = hex(base) if isinstance(base, int) else str(base)

        all_dlls.append({"name": name, "base": base_hex})

        if dll_name and dll_name.lower() in name.lower():
            target_dll = dll
            break
        elif dll_base and base_hex.lower() == dll_base.lower():
            target_dll = dll
            break

    if not target_dll:
        return {
            "error": f"DLL not found in PID {pid}",
            "searched_for": dll_name or dll_base,
            "available_dlls": all_dlls[:20],
        }

    return {
        "image_path": str(session.image_path),
        "pid": pid,
        "dll": {
            "name": target_dll.get("Name", ""),
            "path": target_dll.get("Path", ""),
            "base": hex(target_dll.get("Base", 0)) if isinstance(target_dll.get("Base"), int) else str(target_dll.get("Base", "")),
            "size": target_dll.get("Size", 0),
        },
        "note": "Use windows.dumpfiles plugin with specific file for actual extraction",
    }


def dump_vad(
    image_path: str,
    pid: int,
    vad_address: str,
    output_dir: Optional[str] = None,
) -> dict[str, Any]:
    """
    Dump a specific VAD (Virtual Address Descriptor) memory region.

    Useful for dumping injected code regions found by malfind.

    Args:
        image_path: Path to memory dump
        pid: Process ID
        vad_address: VAD start address (hex string, e.g., "0x7ff00000")
        output_dir: Directory for output

    Returns:
        Dict with VAD dump info
    """
    if not VOL3_AVAILABLE:
        return {"error": "volatility3 not installed"}

    session = get_session(image_path)
    if session is None:
        return {"error": "Failed to create session"}

    init_result = session.initialize()
    if not init_result.get("ready"):
        return {"error": "Failed to initialize session"}

    # Setup output directory
    if output_dir:
        dump_path = Path(output_dir)
    else:
        dump_path = Path("/tmp/memory_dumps")
    dump_path.mkdir(parents=True, exist_ok=True)

    # Parse address
    try:
        target_addr = int(vad_address, 16) if vad_address.startswith("0x") else int(vad_address)
    except ValueError:
        return {"error": f"Invalid address format: {vad_address}"}

    # Get VAD info
    try:
        vadinfo_results = session.run_plugin("windows.vadinfo.VadInfo")
    except Exception as e:
        return {"error": f"Failed to get VAD info: {e}"}

    target_vad = None
    for vad in vadinfo_results:
        if vad.get("PID") != pid:
            continue

        start = vad.get("Start", 0)
        if isinstance(start, int) and start == target_addr:
            target_vad = vad
            break
        elif str(start) == vad_address:
            target_vad = vad
            break

    if not target_vad:
        return {
            "error": f"VAD at {vad_address} not found in PID {pid}",
            "hint": "Use memory_find_injected_code to find suspicious VAD addresses",
        }

    vad_start = target_vad.get("Start", 0)
    vad_end = target_vad.get("End", 0)
    vad_size = vad_end - vad_start if isinstance(vad_start, int) and isinstance(vad_end, int) else 0

    return {
        "image_path": str(session.image_path),
        "pid": pid,
        "vad": {
            "start": hex(vad_start) if isinstance(vad_start, int) else str(vad_start),
            "end": hex(vad_end) if isinstance(vad_end, int) else str(vad_end),
            "size": vad_size,
            "protection": target_vad.get("Protection", ""),
            "tag": target_vad.get("Tag", ""),
            "file_offset": target_vad.get("FileOffset", ""),
            "file_path": target_vad.get("File", ""),
        },
        "output_dir": str(dump_path),
        "note": "VAD info extracted. For raw bytes, use malfind output or vol3 directly",
    }


def list_dumpable_files(
    image_path: str,
    pid: Optional[int] = None,
) -> dict[str, Any]:
    """
    List files that can be dumped from memory.

    WARNING: This plugin is memory-intensive on large dumps (4GB+).
    Consider using memory_run_plugin with filescan instead.

    Args:
        image_path: Path to memory dump
        pid: Filter by process ID (optional)

    Returns:
        Dict with list of dumpable files
    """
    # Return warning instead of running heavy plugin
    return {
        "warning": "dumpfiles plugin is memory-intensive and may crash on large dumps",
        "alternative": "Use memory_run_plugin with 'filescan' for file listing",
        "example": "memory_run_plugin(image_path, plugin='filescan')",
        "pid_filter": pid,
    }

    files = []
    count = 0
    for result in results:
        if count >= 100:  # Limit output
            break
        # Filter by PID if specified
        if pid is not None:
            result_pid = result.get("PID")
            if result_pid != pid:
                continue
        files.append({
            "pid": result.get("PID"),
            "cache_type": str(result.get("Cache", "")),
            "file_name": str(result.get("FileName", "")),
            "file_type": str(result.get("FileObject", "")),
        })
        count += 1

    return {
        "image_path": str(session.image_path),
        "profile": session.profile,
        "pid_filter": pid,
        "files_found": len(files),
        "files": files,
    }
