"""
Utility functions for memory forensics.
"""

from .virustotal_client import (
    VT_AVAILABLE,
    lookup_hash as vt_lookup_hash,
    lookup_ip as vt_lookup_ip,
    lookup_domain as vt_lookup_domain,
    lookup_file as vt_lookup_file,
    clear_cache as vt_clear_cache,
    get_cache_stats as vt_cache_stats,
)

__all__ = [
    "VT_AVAILABLE",
    "vt_lookup_hash",
    "vt_lookup_ip",
    "vt_lookup_domain",
    "vt_lookup_file",
    "vt_clear_cache",
    "vt_cache_stats",
]
