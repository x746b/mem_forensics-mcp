"""
mem-forensics-mcp: Unified Memory Forensics MCP Server

Multi-tier architecture combining:
  - Tier 1: Rust engine (memoxide) for fast native analysis
  - Tier 2: Python analyzers for smart correlation and VT integration
  - Tier 3: Volatility3 fallback for full plugin access

Example:
    # Start server
    python -m mem_forensics_mcp.server

    # Or use as library
    from mem_forensics_mcp.engine import MemoxideClient
    from mem_forensics_mcp.core import get_session, VOL3_AVAILABLE
"""
from . import config as _config  # noqa: F401 — must load before core (sets VOLATILITY3_PATH)
from .core import (
    MemorySession,
    get_session,
    clear_sessions,
    VOL3_AVAILABLE,
)
from .analyzers import (
    analyze_image_profile,
)

__version__ = "0.1.0"
__all__ = [
    "MemorySession",
    "get_session",
    "clear_sessions",
    "VOL3_AVAILABLE",
    "analyze_image_profile",
]
