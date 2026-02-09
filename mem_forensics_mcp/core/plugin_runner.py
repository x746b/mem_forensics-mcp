"""
Generic Volatility3 plugin runner.

Allows calling any vol3 plugin directly through the MCP.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from .session import get_session
from .vol3_runner import VOL3_AVAILABLE, run_vol3_cli

logger = logging.getLogger(__name__)


def list_available_plugins(image_path: str) -> dict[str, Any]:
    """
    List all available vol3 plugins for the detected OS.

    Args:
        image_path: Path to memory dump

    Returns:
        Dict with available plugins grouped by category
    """
    if not VOL3_AVAILABLE:
        return {"error": "volatility3 not installed"}

    session = get_session(image_path)
    if session is None:
        return {"error": "Failed to create session"}

    init_result = session.initialize()
    if not init_result.get("ready"):
        return {"error": init_result.get("error", "Failed to initialize")}

    os_type = session.os_type

    plugins = {
        "os_type": os_type,
        "plugins": {},
    }

    # Get plugins based on OS
    try:
        if os_type == "windows":
            from volatility3.plugins import windows
            plugins["plugins"] = _get_plugin_list(windows, "windows")
        elif os_type == "linux":
            from volatility3.plugins import linux
            plugins["plugins"] = _get_plugin_list(linux, "linux")
        elif os_type == "mac":
            from volatility3.plugins import mac
            plugins["plugins"] = _get_plugin_list(mac, "mac")
    except ImportError as e:
        plugins["error"] = f"Failed to import plugins: {e}"

    return plugins


def _get_plugin_list(module, os_name: str) -> dict[str, list[str]]:
    """Extract plugin names from a vol3 plugin module."""
    import importlib
    import pkgutil

    plugins_by_category: dict[str, list[str]] = {}

    # Get submodules (categories)
    try:
        for importer, modname, ispkg in pkgutil.iter_modules(module.__path__):
            if ispkg:
                # It's a category (subpackage)
                category = modname
                try:
                    submodule = importlib.import_module(f"volatility3.plugins.{os_name}.{modname}")
                    # Get plugin classes in this category
                    plugin_names = []
                    for name in dir(submodule):
                        obj = getattr(submodule, name)
                        if isinstance(obj, type) and hasattr(obj, 'run') and hasattr(obj, '_required_framework_version'):
                            plugin_names.append(f"{os_name}.{modname}.{name}")
                    if plugin_names:
                        plugins_by_category[category] = sorted(plugin_names)
                except Exception:
                    pass
            else:
                # It's a direct plugin module
                try:
                    submodule = importlib.import_module(f"volatility3.plugins.{os_name}.{modname}")
                    for name in dir(submodule):
                        obj = getattr(submodule, name)
                        if isinstance(obj, type) and hasattr(obj, 'run') and hasattr(obj, '_required_framework_version'):
                            category = "general"
                            if category not in plugins_by_category:
                                plugins_by_category[category] = []
                            plugins_by_category[category].append(f"{os_name}.{modname}.{name}")
                except Exception:
                    pass
    except Exception as e:
        logger.debug(f"Error listing plugins: {e}")

    return plugins_by_category


def run_plugin(
    image_path: str,
    plugin: str,
    pid: Optional[int] = None,
    offset: Optional[str] = None,
    dump: bool = False,
    dump_dir: Optional[str] = None,
    **kwargs
) -> dict[str, Any]:
    """
    Run any Volatility3 plugin and return structured results.

    Args:
        image_path: Path to memory dump
        plugin: Plugin name (e.g., "windows.pslist.PsList", "windows.malfind.Malfind")
        pid: Filter by PID (if plugin supports it)
        offset: Filter by offset (if plugin supports it)
        dump: Enable file dumping (if plugin supports it)
        dump_dir: Directory for dumped files
        **kwargs: Additional plugin-specific arguments

    Returns:
        Dict with plugin results
    """
    if not VOL3_AVAILABLE:
        return {"error": "volatility3 not installed"}

    session = get_session(image_path)
    if session is None:
        return {"error": "Failed to create session"}

    init_result = session.initialize()
    if not init_result.get("ready"):
        return {"error": init_result.get("error", "Failed to initialize")}

    # Normalize plugin name
    plugin_name = _normalize_plugin_name(plugin, session.os_type)

    logger.info(f"Running plugin: {plugin_name}")

    # Build vol3 kwargs from explicit params + extras
    vol3_kwargs = dict(kwargs)
    if dump_dir:
        vol3_kwargs["output_dir"] = dump_dir
    if offset:
        # Convert offset to list format for vol3 plugins that expect ListRequirement
        offset_int = int(offset, 16) if isinstance(offset, str) and offset.startswith("0x") else int(offset)
        vol3_kwargs["physaddr"] = [offset_int]

    # Check if any param is a list — vol3 library API mishandles ListRequirement
    # config values, so fall back to CLI subprocess for reliable param passing
    has_list_params = any(isinstance(v, list) for v in vol3_kwargs.values())

    if has_list_params:
        return _run_via_cli(image_path, plugin_name, pid, dump_dir, session, vol3_kwargs)

    try:
        # Run the plugin via library API
        results = session.run_plugin(plugin_name, **vol3_kwargs)

        # Convert to list for JSON serialization
        results_list = list(results)

        # Filter by PID if specified
        if pid is not None:
            results_list = [r for r in results_list if r.get("PID") == pid]

        result = {
            "image_path": str(session.image_path),
            "plugin": plugin_name,
            "profile": session.profile,
            "result_count": len(results_list),
            "results": results_list,
        }

        if dump_dir:
            result["dump_dir"] = dump_dir

        return result

    except ValueError as e:
        return {
            "error": f"Plugin not found: {plugin_name}",
            "detail": str(e),
            "hint": "Use memory_list_plugins to see available plugins",
        }
    except Exception as e:
        logger.exception(f"Plugin {plugin_name} failed")
        return {
            "error": f"Plugin execution failed: {e}",
            "plugin": plugin_name,
        }


def _run_via_cli(
    image_path: str,
    plugin_name: str,
    pid: Optional[int],
    dump_dir: Optional[str],
    session,
    vol3_kwargs: dict,
) -> dict[str, Any]:
    """Run plugin via vol3 CLI subprocess (handles ListRequirement params correctly)."""
    # Build CLI kwargs (exclude output_dir which maps to -o flag)
    cli_kwargs = {}
    for k, v in vol3_kwargs.items():
        if k == "output_dir":
            continue
        cli_kwargs[k] = v
    if pid is not None:
        cli_kwargs["pid"] = [pid]

    try:
        results_list = run_vol3_cli(
            image_path=image_path,
            plugin_name=plugin_name,
            output_dir=dump_dir,
            **cli_kwargs,
        )

        result = {
            "image_path": str(image_path),
            "plugin": plugin_name,
            "profile": session.profile if session else {},
            "result_count": len(results_list),
            "results": results_list,
            "engine_mode": "vol3-cli",
        }

        if dump_dir:
            result["dump_dir"] = dump_dir

        return result

    except Exception as e:
        logger.exception(f"Vol3 CLI failed for {plugin_name}")
        return {
            "error": f"Vol3 CLI failed: {e}",
            "plugin": plugin_name,
        }


def _normalize_plugin_name(plugin: str, os_type: Optional[str]) -> str:
    """
    Normalize plugin name to full format.

    Accepts:
    - "windows.pslist.PsList" -> as-is
    - "pslist.PsList" -> "windows.pslist.PsList" (adds OS prefix)
    - "pslist" -> "windows.pslist.PsList" (adds OS prefix and class name)
    - "malfind" -> "windows.malfind.Malfind"
    """
    parts = plugin.split(".")

    # Already full format
    if len(parts) == 3:
        return plugin

    # Has module.Class format, add OS prefix
    if len(parts) == 2:
        if os_type:
            return f"{os_type}.{plugin}"
        return plugin

    # Just module name, try to infer class name
    if len(parts) == 1:
        module_name = parts[0].lower()
        # Common class name patterns
        class_name = parts[0].capitalize()

        # Handle special cases
        class_mappings = {
            "pslist": "PsList",
            "psscan": "PsScan",
            "pstree": "PsTree",
            "netscan": "NetScan",
            "netstat": "NetStat",
            "malfind": "Malfind",
            "cmdline": "CmdLine",
            "dlllist": "DllList",
            "handles": "Handles",
            "filescan": "FileScan",
            "dumpfiles": "DumpFiles",
            "envars": "Envars",
            "hashdump": "Hashdump",
            "hivelist": "HiveList",
            "printkey": "PrintKey",
            "svcscan": "SvcScan",
            "ssdt": "SSDT",
            "callbacks": "Callbacks",
            "driverscan": "DriverScan",
            "modules": "Modules",
            "modscan": "ModScan",
            "vadinfo": "VadInfo",
            "vadwalk": "VadWalk",
            "memmap": "Memmap",
            "strings": "Strings",
            "yarascan": "YaraScan",
            "info": "Info",
            "verinfo": "VerInfo",
        }

        class_name = class_mappings.get(module_name, class_name)

        if os_type:
            return f"{os_type}.{module_name}.{class_name}"
        return f"{module_name}.{class_name}"

    return plugin
