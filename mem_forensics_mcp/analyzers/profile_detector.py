"""
Profile detection for memory images.

Automatically detects the OS type, version, and architecture from
a memory dump. This is the first step in any memory analysis.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

from ..core.session import MemorySession, get_session
from ..core.vol3_runner import VOL3_AVAILABLE

logger = logging.getLogger(__name__)


def analyze_image_profile(
    image_path: str | Path,
) -> dict[str, Any]:
    """
    Analyze a memory image and detect its OS profile.

    This is the entry point for memory analysis. It:
    1. Validates the memory image file exists
    2. Creates/retrieves a session for the image
    3. Auto-detects the OS type (Windows/Linux/Mac)
    4. Extracts version and architecture information

    Args:
        image_path: Path to the memory dump file
            Supported formats: .raw, .vmem, .dmp, .lime, .mem

    Returns:
        Dict containing:
        - session_id: Unique ID for this analysis session
        - image_path: Absolute path to the image
        - file_size_gb: Image size in gigabytes
        - profile: OS profile information
            - os: Operating system (Windows, Linux, Mac)
            - version: OS version
            - build: Build number (Windows)
            - arch: Architecture (x86, x64, arm64)
        - ready: Whether the image is ready for analysis
        - available_analyses: List of analyses available for this OS
        - error: Error message if initialization failed

    Example:
        >>> result = analyze_image_profile("/evidence/memory.raw")
        >>> print(result)
        {
            "session_id": "mem_abc123",
            "image_path": "/evidence/memory.raw",
            "file_size_gb": 8.2,
            "profile": {
                "os": "Windows",
                "version": "10",
                "build": "19041",
                "arch": "x64"
            },
            "ready": True,
            "available_analyses": [
                "process_anomalies",
                "code_injection",
                "network_connections",
                "command_history",
                "credentials"
            ]
        }
    """
    image_path = Path(image_path)

    # Validate file exists
    if not image_path.exists():
        return {
            "image_path": str(image_path),
            "ready": False,
            "error": f"Memory image not found: {image_path}",
        }

    # Check file size
    try:
        file_size = image_path.stat().st_size
        file_size_gb = round(file_size / (1024 ** 3), 2)
    except OSError as e:
        return {
            "image_path": str(image_path),
            "ready": False,
            "error": f"Cannot read file: {e}",
        }

    # Warn about small files (likely not valid memory dumps)
    if file_size < 10 * 1024 * 1024:  # Less than 10MB
        logger.warning(f"File is very small ({file_size} bytes), may not be a valid memory dump")

    # Check Volatility availability
    if not VOL3_AVAILABLE:
        return {
            "image_path": str(image_path.absolute()),
            "file_size_bytes": file_size,
            "file_size_gb": file_size_gb,
            "ready": False,
            "error": "volatility3 not installed. Install with: pip install volatility3",
            "hint": "Memory analysis requires the volatility3 library",
        }

    # Get or create session
    session = get_session(image_path)
    if session is None:
        return {
            "image_path": str(image_path.absolute()),
            "file_size_bytes": file_size,
            "file_size_gb": file_size_gb,
            "ready": False,
            "error": "Failed to create analysis session",
        }

    # Initialize the session
    result = session.initialize()

    # Enhance the result with analysis availability
    if result.get("ready"):
        result["available_analyses"] = _get_available_analyses(session.os_type)
        result["next_steps"] = _get_next_steps(session.os_type)

    return result


def _get_available_analyses(os_type: Optional[str]) -> list[str]:
    """Get list of available analyses for the OS type."""
    if os_type == "windows":
        return [
            "process_anomalies",
            "code_injection",
            "network_connections",
            "command_history",
            "credentials",
            "full_triage",
        ]
    elif os_type == "linux":
        return [
            "process_list",
            "network_connections",
            "bash_history",
        ]
    else:
        return []


def _get_next_steps(os_type: Optional[str]) -> list[str]:
    """Get recommended next steps based on OS type."""
    if os_type == "windows":
        return [
            "Run memory_full_triage() for automated investigation",
            "Or run memory_hunt_process_anomalies() to find hidden processes",
            "Use memory_find_injected_code() to detect malware injection",
        ]
    elif os_type == "linux":
        return [
            "Run memory_get_processes() to list running processes",
            "Check memory_get_network_connections() for active connections",
        ]
    else:
        return [
            "OS type could not be determined",
            "Verify the memory dump is valid and complete",
        ]


def get_supported_formats() -> dict[str, Any]:
    """
    Get information about supported memory dump formats.

    Returns:
        Dict with format information
    """
    return {
        "supported_formats": [
            {
                "extension": ".raw",
                "description": "Raw memory dump (dd-style)",
                "common_sources": ["FTK Imager", "dd", "Magnet RAM Capture"],
            },
            {
                "extension": ".vmem",
                "description": "VMware virtual machine memory",
                "common_sources": ["VMware Workstation/Fusion", "ESXi"],
            },
            {
                "extension": ".dmp",
                "description": "Windows crash dump",
                "common_sources": ["Windows BSOD", "livekd", "WinDbg"],
            },
            {
                "extension": ".lime",
                "description": "Linux Memory Extractor format",
                "common_sources": ["LiME kernel module"],
            },
            {
                "extension": ".mem",
                "description": "Generic memory dump",
                "common_sources": ["Various tools"],
            },
            {
                "extension": ".bin",
                "description": "Binary memory dump",
                "common_sources": ["Various tools"],
            },
        ],
        "notes": [
            "Volatility3 auto-detects format in most cases",
            "Compressed files must be decompressed first",
            "Hibernation files (hiberfil.sys) are supported",
        ],
    }
