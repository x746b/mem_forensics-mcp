"""
Unified memory analysis session management.

Manages state for memory image analysis across both Rust (memoxide) and
Python (Vol3) engines. Sessions are created once per image and track
both engine states, with lazy initialization for each tier.
"""
from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .vol3_runner import Vol3Runner, VOL3_AVAILABLE

logger = logging.getLogger(__name__)

# Global session cache
_sessions: dict[str, "MemorySession"] = {}


@dataclass
class CachedResult:
    """Cached plugin result with timestamp."""
    data: Any
    timestamp: float
    plugin_name: str


class MemorySession:
    """
    Unified session managing both Rust (memoxide) and Python (Vol3) engines.

    - Rust session ID is tracked for Tier 1 calls
    - Vol3 runner is lazy-loaded only when Tier 2/3 is needed
    - Plugin results are cached to avoid redundant processing
    """

    def __init__(self, image_path: str | Path):
        self.image_path = Path(image_path).absolute()
        self._session_id = self._generate_session_id()
        self._runner: Optional[Vol3Runner] = None
        self._cache: dict[str, CachedResult] = {}
        self._initialized = False
        self._profile: dict[str, Any] = {}
        self._created_at = time.time()

        # Rust engine state
        self._rust_session_id: Optional[str] = None
        self._rust_initialized = False
        self._rust_profile: Optional[dict] = None

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def is_initialized(self) -> bool:
        return self._initialized

    @property
    def profile(self) -> dict[str, Any]:
        return self._profile

    @property
    def os_type(self) -> Optional[str]:
        if self._runner:
            return self._runner.os_type
        if isinstance(self._profile, dict):
            return self._profile.get("os", "").lower() or None
        # Profile is a string (e.g. ISF path from Rust) — infer OS
        if isinstance(self._profile, str) and "windows" in self._profile.lower():
            return "windows"
        return None

    @property
    def rust_session_id(self) -> Optional[str]:
        """Rust engine session ID (set after successful Rust init)."""
        return self._rust_session_id

    @property
    def rust_initialized(self) -> bool:
        return self._rust_initialized

    def set_rust_session(self, session_id: str, profile: dict) -> None:
        """Set the Rust engine session info after successful init."""
        self._rust_session_id = session_id
        self._rust_initialized = True
        self._rust_profile = profile

        # If we haven't initialized Vol3 yet, use Rust profile
        if not self._initialized:
            self._profile = profile
            self._initialized = True

    def _generate_session_id(self) -> str:
        hash_input = f"{self.image_path}:{time.time()}"
        return f"mem_{hashlib.md5(hash_input.encode()).hexdigest()[:12]}"

    def initialize(self) -> dict[str, Any]:
        """
        Initialize the Vol3 session and detect OS profile.

        Note: Rust initialization is done separately via the server layer.
        This method handles Vol3 (Tier 2/3) initialization.
        """
        if self._initialized:
            return {
                "session_id": self._session_id,
                "image_path": str(self.image_path),
                "profile": self._profile,
                "ready": True,
                "from_cache": True,
                "rust_session_id": self._rust_session_id,
            }

        logger.info(f"Initializing Vol3 session for: {self.image_path}")

        if not VOL3_AVAILABLE:
            # If Rust is available, we may still be usable
            if self._rust_initialized:
                return {
                    "session_id": self._session_id,
                    "image_path": str(self.image_path),
                    "profile": self._profile,
                    "ready": True,
                    "rust_session_id": self._rust_session_id,
                    "vol3_available": False,
                }
            return {
                "session_id": self._session_id,
                "image_path": str(self.image_path),
                "ready": False,
                "error": "volatility3 not installed and Rust engine not initialized",
            }

        try:
            self._runner = Vol3Runner(self.image_path)
            self._profile = self._runner.initialize()
            self._initialized = True

            file_size = self.image_path.stat().st_size
            file_size_gb = round(file_size / (1024 ** 3), 2)

            return {
                "session_id": self._session_id,
                "image_path": str(self.image_path),
                "file_size_bytes": file_size,
                "file_size_gb": file_size_gb,
                "profile": self._profile,
                "ready": True,
                "from_cache": False,
                "rust_session_id": self._rust_session_id,
            }

        except Exception as e:
            logger.error(f"Failed to initialize Vol3 session: {e}")
            # If Rust is available, we can still work
            if self._rust_initialized:
                return {
                    "session_id": self._session_id,
                    "image_path": str(self.image_path),
                    "profile": self._profile,
                    "ready": True,
                    "rust_session_id": self._rust_session_id,
                    "vol3_error": str(e),
                }
            return {
                "session_id": self._session_id,
                "image_path": str(self.image_path),
                "ready": False,
                "error": str(e),
            }

    def ensure_vol3_initialized(self) -> bool:
        """
        Ensure Vol3 is ready. Lazy-init if not yet done.

        Returns:
            True if Vol3 is available and initialized.
        """
        if self._runner and self._runner.is_initialized:
            return True

        if not VOL3_AVAILABLE:
            return False

        # Create Vol3 runner directly (bypass initialize() which may
        # return early if session was already initialized by Rust)
        try:
            self._runner = Vol3Runner(self.image_path)
            vol3_profile = self._runner.initialize()
            # Merge Vol3 profile info if we only had Rust profile
            if isinstance(self._profile, dict) and isinstance(vol3_profile, dict):
                self._profile.update(vol3_profile)
            elif isinstance(vol3_profile, dict):
                self._profile = vol3_profile
            return True
        except Exception as e:
            logger.error(f"Failed to initialize Vol3 runner: {e}")
            return False

    def _ensure_initialized(self) -> None:
        """Ensure the session is initialized (either engine)."""
        if not self._initialized:
            result = self.initialize()
            if not result.get("ready"):
                raise RuntimeError(
                    f"Session initialization failed: {result.get('error', 'unknown error')}"
                )

    def run_plugin(
        self,
        plugin_name: str,
        use_cache: bool = True,
        **kwargs
    ) -> list[dict[str, Any]]:
        """Run a Vol3 plugin. For Rust plugins, use the server tier routing."""
        self._ensure_initialized()

        # Lazy-init Vol3 runner if not yet created (e.g. Rust initialized first)
        if not self._runner:
            if not self.ensure_vol3_initialized():
                raise RuntimeError("Vol3 not available for this session")

        def make_hashable(v):
            if isinstance(v, dict):
                return tuple(sorted(v.items()))
            if isinstance(v, list):
                return tuple(v)
            return v
        cache_items = tuple((k, make_hashable(v)) for k, v in sorted(kwargs.items()))
        cache_key = f"{plugin_name}:{hash(cache_items)}"
        if use_cache and cache_key in self._cache:
            cached = self._cache[cache_key]
            logger.debug(f"Using cached result for {plugin_name}")
            return cached.data

        logger.info(f"Running Vol3 plugin: {plugin_name}")
        results = list(self._runner.run_plugin(plugin_name, **kwargs))

        self._cache[cache_key] = CachedResult(
            data=results,
            timestamp=time.time(),
            plugin_name=plugin_name,
        )

        return results

    def get_processes(self, include_terminated: bool = False) -> list[dict[str, Any]]:
        self._ensure_initialized()

        if self.os_type != "windows":
            raise NotImplementedError("Process listing only implemented for Windows")

        processes = self.run_plugin("windows.pslist.PsList")

        if include_terminated:
            psscan_results = self.run_plugin("windows.psscan.PsScan")
            pslist_pids = {p.get("PID") for p in processes}
            for proc in psscan_results:
                pid = proc.get("PID")
                if pid not in pslist_pids:
                    proc["_from_psscan"] = True
                    proc["_hidden"] = True
                    processes.append(proc)

        return processes

    def get_network_connections(self) -> list[dict[str, Any]]:
        self._ensure_initialized()
        if self.os_type != "windows":
            raise NotImplementedError("Network listing only implemented for Windows")
        return self.run_plugin("windows.netscan.NetScan")

    def get_command_history(self) -> list[dict[str, Any]]:
        self._ensure_initialized()
        if self.os_type != "windows":
            raise NotImplementedError("Command history only implemented for Windows")

        results = []
        try:
            cmdscan = self.run_plugin("windows.cmdscan.CmdScan")
            results.extend(cmdscan)
        except Exception as e:
            logger.debug(f"cmdscan failed: {e}")

        try:
            cmdline = self.run_plugin("windows.cmdline.CmdLine")
            results.extend(cmdline)
        except Exception as e:
            logger.debug(f"cmdline failed: {e}")

        return results

    def clear_cache(self, plugin_name: Optional[str] = None) -> int:
        if plugin_name is None:
            count = len(self._cache)
            self._cache.clear()
            return count

        keys_to_remove = [k for k in self._cache if k.startswith(f"{plugin_name}:")]
        for key in keys_to_remove:
            del self._cache[key]
        return len(keys_to_remove)

    def get_cache_stats(self) -> dict[str, Any]:
        return {
            "entries": len(self._cache),
            "plugins_cached": list(set(c.plugin_name for c in self._cache.values())),
            "session_age_seconds": time.time() - self._created_at,
            "rust_session": self._rust_session_id,
            "rust_initialized": self._rust_initialized,
        }


def get_session(image_path: str | Path, create: bool = True) -> Optional[MemorySession]:
    """Get or create a session for a memory image."""
    image_path = str(Path(image_path).absolute())

    for session in _sessions.values():
        if str(session.image_path) == image_path:
            return session

    if create:
        session = MemorySession(image_path)
        _sessions[session.session_id] = session
        return session

    return None


def get_session_by_id(session_id: str) -> Optional[MemorySession]:
    """Get a session by its ID."""
    return _sessions.get(session_id)


def clear_sessions(max_age_seconds: Optional[int] = None) -> int:
    """Clear sessions from the cache."""
    if max_age_seconds is None:
        count = len(_sessions)
        _sessions.clear()
        return count

    current_time = time.time()
    to_remove = []
    for session_id, session in _sessions.items():
        age = current_time - session._created_at
        if age > max_age_seconds:
            to_remove.append(session_id)

    for session_id in to_remove:
        del _sessions[session_id]

    return len(to_remove)


def list_sessions() -> list[dict[str, Any]]:
    """List all active sessions."""
    return [
        {
            "session_id": session.session_id,
            "image_path": str(session.image_path),
            "initialized": session.is_initialized,
            "os_type": session.os_type,
            "cache_entries": len(session._cache),
            "age_seconds": time.time() - session._created_at,
            "rust_session_id": session.rust_session_id,
            "rust_initialized": session.rust_initialized,
        }
        for session in _sessions.values()
    ]
