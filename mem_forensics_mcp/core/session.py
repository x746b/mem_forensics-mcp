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

_sessions: dict[str, "MemorySession"] = {}

_KNOWN_OS_TYPES = {"windows", "linux", "mac"}


def normalize_os_type(value: Any) -> Optional[str]:
    """Normalize engine/profile OS labels to the names used by Volatility."""
    if value is None:
        return None

    normalized = str(value).strip().lower()
    if not normalized or normalized == "unknown":
        return None
    if "windows" in normalized or normalized.startswith("win"):
        return "windows"
    if "linux" in normalized or "ubuntu" in normalized or "debian" in normalized:
        return "linux"
    if "darwin" in normalized or "macos" in normalized or normalized == "mac":
        return "mac"
    return normalized if normalized in _KNOWN_OS_TYPES else None


def detect_image_os(image_path: str | Path) -> Optional[str]:
    """Detect OS-independent image markers without requiring symbols."""
    try:
        with Path(image_path).open("rb") as image:
            if image.read(4) == b"EMiL":
                return "linux"
    except OSError:
        pass
    return None


def _profile_os_type(profile: Any) -> Optional[str]:
    if isinstance(profile, dict):
        for key in ("os", "os_type", "platform", "operating_system"):
            detected = normalize_os_type(profile.get(key))
            if detected:
                return detected
        for key in ("profile", "isf_path", "name"):
            detected = normalize_os_type(profile.get(key))
            if detected:
                return detected
    return normalize_os_type(profile)


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
        self._profile: Any = {}
        self._detected_os = detect_image_os(self.image_path)
        self._created_at = time.time()

        self._rust_session_id: Optional[str] = None
        self._rust_initialized = False
        self._rust_profile: Any = None
        self._rust_metadata: dict[str, Any] = {}

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def is_initialized(self) -> bool:
        return self._initialized

    @property
    def profile(self) -> Any:
        return self._profile

    @property
    def os_type(self) -> Optional[str]:
        if self._runner:
            runner_os = normalize_os_type(self._runner.os_type)
            if runner_os:
                return runner_os
        return _profile_os_type(self._profile) or self._detected_os

    @property
    def session_ready(self) -> bool:
        """Whether at least one engine opened/initialized the image."""
        return bool(
            self._rust_initialized
            or self._initialized
            or (self._runner and self._runner.is_initialized)
        )

    @property
    def raw_ready(self) -> bool:
        """Whether OS-agnostic raw Rust operations are available."""
        return self._rust_initialized

    @property
    def vol3_ready(self) -> bool:
        """Whether Volatility initialized a recognized OS layer."""
        return bool(
            self._runner
            and self._runner.is_initialized
            and normalize_os_type(self._runner.os_type)
        )

    @property
    def structured_ready(self) -> bool:
        """Whether an engine has symbols and a usable structured memory layer."""
        rust_ready = bool(
            self._rust_initialized
            and self.os_type == "windows"
            and self._rust_profile
            and self._rust_metadata.get("virtual_memory")
        )
        return self.vol3_ready or rust_ready

    def readiness(self) -> dict[str, Any]:
        """Return the public readiness/capability contract for this session."""
        capabilities: list[str] = []
        if self.raw_ready:
            capabilities.extend(["search", "readraw"])
        if self.structured_ready:
            capabilities.append("structured_plugins")

        warnings: list[str] = []
        if self.session_ready and not self.structured_ready:
            if self.os_type == "linux":
                warnings.append(
                    "Linux image detected; a matching Linux ISF is required for "
                    "structure-aware plugins"
                )
            elif self.os_type == "windows":
                warnings.append(
                    "Windows profile/DTB is incomplete; structure-aware plugins are unavailable"
                )
            else:
                warnings.append(
                    "OS type could not be determined; structure-aware plugins are disabled"
                )

        return {
            # Backward compatibility: ready means the session can be used, not
            # that structured parsing is available.
            "ready": self.session_ready,
            "session_ready": self.session_ready,
            "raw_ready": self.raw_ready,
            "structured_ready": self.structured_ready,
            "os_type": self.os_type,
            "capabilities": capabilities,
            "warnings": warnings,
        }

    def structured_analysis_error(
        self,
        operation: str,
        supported_os: Optional[set[str]] = None,
    ) -> Optional[dict[str, Any]]:
        """Return an actionable error when a structured helper cannot run."""
        readiness = self.readiness()
        if not self.structured_ready:
            reason = readiness["warnings"][0] if readiness["warnings"] else (
                "structure-aware analysis is unavailable"
            )
            return {
                "error": f"{operation} unavailable: {reason}",
                **readiness,
            }

        if supported_os and self.os_type not in supported_os:
            expected = ", ".join(sorted(supported_os))
            return {
                "error": (
                    f"{operation} is not implemented for {self.os_type or 'unknown'} "
                    f"images (supported: {expected})"
                ),
                **readiness,
            }
        return None

    @property
    def rust_session_id(self) -> Optional[str]:
        """Rust engine session ID (set after successful Rust init)."""
        return self._rust_session_id

    @property
    def rust_initialized(self) -> bool:
        return self._rust_initialized

    def set_rust_session(
        self,
        session_id: str,
        profile: Any,
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        """Set the Rust engine session info after successful init."""
        self._rust_session_id = session_id
        self._rust_initialized = True
        self._rust_profile = profile
        self._rust_metadata = dict(metadata or {})

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
            result = {
                "session_id": self._session_id,
                "image_path": str(self.image_path),
                "profile": self._profile,
                "from_cache": True,
                "rust_session_id": self._rust_session_id,
            }
            result.update(self.readiness())
            return result

        logger.info(f"Initializing Vol3 session for: {self.image_path}")

        if not VOL3_AVAILABLE:
            # If Rust is available, we may still be usable
            if self._rust_initialized:
                result = {
                    "session_id": self._session_id,
                    "image_path": str(self.image_path),
                    "profile": self._profile,
                    "rust_session_id": self._rust_session_id,
                    "vol3_available": False,
                }
                result.update(self.readiness())
                return result
            result = {
                "session_id": self._session_id,
                "image_path": str(self.image_path),
                "error": "volatility3 not installed and Rust engine not initialized",
            }
            result.update(self.readiness())
            return result

        try:
            self._runner = Vol3Runner(self.image_path)
            self._profile = self._runner.initialize()
            self._initialized = True

            file_size = self.image_path.stat().st_size
            file_size_gb = round(file_size / (1024 ** 3), 2)

            result = {
                "session_id": self._session_id,
                "image_path": str(self.image_path),
                "file_size_bytes": file_size,
                "file_size_gb": file_size_gb,
                "profile": self._profile,
                "from_cache": False,
                "rust_session_id": self._rust_session_id,
            }
            result.update(self.readiness())
            return result

        except Exception as e:
            logger.error(f"Failed to initialize Vol3 session: {e}")
            # If Rust is available, we can still work
            if self._rust_initialized:
                result = {
                    "session_id": self._session_id,
                    "image_path": str(self.image_path),
                    "profile": self._profile,
                    "rust_session_id": self._rust_session_id,
                    "vol3_error": str(e),
                }
                result.update(self.readiness())
                return result
            result = {
                "session_id": self._session_id,
                "image_path": str(self.image_path),
                "error": str(e),
            }
            result.update(self.readiness())
            return result

    def ensure_vol3_initialized(self) -> bool:
        """
        Ensure Vol3 is ready. Lazy-init if not yet done.

        Returns:
            True if Vol3 is available and initialized.
        """
        if self._runner and self._runner.is_initialized:
            return self.vol3_ready

        if not VOL3_AVAILABLE:
            return False

        # Create Vol3 runner directly (bypass initialize() which may
        # return early if session was already initialized by Rust)
        try:
            self._runner = Vol3Runner(self.image_path)
            vol3_profile = self._runner.initialize()
            self._initialized = True
            # Merge Vol3 profile info if we only had Rust profile
            if isinstance(self._profile, dict) and isinstance(vol3_profile, dict):
                self._profile.update(vol3_profile)
            elif isinstance(vol3_profile, dict):
                self._profile = vol3_profile
            return self.vol3_ready
        except Exception as e:
            logger.error(f"Failed to initialize Vol3 runner: {e}")
            return False

    def _ensure_initialized(self) -> None:
        if not self.session_ready:
            result = self.initialize()
            if not result.get("session_ready", result.get("ready")):
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

        # Lazy-init Vol3 runner if not yet usable (e.g. Rust raw session first).
        if not self.vol3_ready:
            if not self.ensure_vol3_initialized():
                readiness = self.readiness()
                reason = readiness["warnings"][0] if readiness["warnings"] else (
                    "Volatility could not initialize structured parsing"
                )
                raise RuntimeError(reason)

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
            "cache_entries": len(session._cache),
            "age_seconds": time.time() - session._created_at,
            "rust_session_id": session.rust_session_id,
            "rust_initialized": session.rust_initialized,
            **session.readiness(),
        }
        for session in _sessions.values()
    ]
