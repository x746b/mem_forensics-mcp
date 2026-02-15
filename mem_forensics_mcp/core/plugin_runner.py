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

    try:
        for importer, modname, ispkg in pkgutil.iter_modules(module.__path__):
            if ispkg:
                category = modname
                try:
                    submodule = importlib.import_module(f"volatility3.plugins.{os_name}.{modname}")
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

    plugin_name = _normalize_plugin_name(plugin, session.os_type)

    logger.info(f"Running plugin: {plugin_name}")

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
        results = session.run_plugin(plugin_name, **vol3_kwargs)

        results_list = list(results)

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

    except Exception as e:
        # Library API failed — try CLI fallback before giving up
        logger.info(f"Library API failed for {plugin_name}: {e}, trying CLI fallback")
        cli_result = _run_via_cli(image_path, plugin_name, pid, dump_dir, session, vol3_kwargs)
        if "error" not in cli_result:
            return cli_result
        logger.warning(f"Both library API and CLI failed for {plugin_name}")
        suggestions = _suggest_plugins(plugin, session.os_type if session else None)
        result = {
            "error": f"Plugin failed: {plugin_name}",
            "detail": str(e),
            "cli_error": cli_result.get("error"),
            "hint": "Use memory_list_plugins to see available plugins",
        }
        if suggestions:
            result["suggestions"] = suggestions
        return result


def _run_via_cli(
    image_path: str,
    plugin_name: str,
    pid: Optional[int],
    dump_dir: Optional[str],
    session,
    vol3_kwargs: dict,
) -> dict[str, Any]:
    """Run plugin via vol3 CLI subprocess (handles ListRequirement params correctly)."""
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

    if len(parts) == 3:
        return plugin

    if len(parts) == 2:
        if os_type:
            return f"{os_type}.{plugin}"
        return plugin

    if len(parts) == 1:
        module_name = parts[0].lower()
        class_name = parts[0].capitalize()

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

        if module_name in class_mappings:
            class_name = class_mappings[module_name]
        else:
            resolved = _resolve_plugin_class(module_name, os_type)
            if resolved:
                class_name = resolved

        if os_type:
            return f"{os_type}.{module_name}.{class_name}"
        return f"{module_name}.{class_name}"

    return plugin


def _resolve_plugin_class(module_name: str, os_type: Optional[str]) -> Optional[str]:
    """Resolve plugin class name by introspecting Vol3 modules.

    Returns the actual class name with correct casing, or None if not found.
    """
    if not os_type:
        return None

    try:
        import importlib
        mod = importlib.import_module(f"volatility3.plugins.{os_type}.{module_name}")
        for name in dir(mod):
            obj = getattr(mod, name)
            if (isinstance(obj, type)
                    and hasattr(obj, 'run')
                    and hasattr(obj, '_required_framework_version')):
                return name
    except (ImportError, Exception):
        pass

    return None


def _suggest_plugins(query: str, os_type: Optional[str]) -> list[str]:
    """Find plugins whose names contain the query substring."""
    if not os_type:
        return []
    try:
        result = list_available_plugins("")  # needs image_path but we just need the plugin list
    except Exception:
        pass

    # Fall back to direct introspection
    try:
        import importlib
        import pkgutil
        plugins_module = importlib.import_module(f"volatility3.plugins.{os_type}")
        matches = []
        query_lower = query.lower()
        for _importer, modname, _ispkg in pkgutil.iter_modules(plugins_module.__path__):
            if query_lower in modname.lower():
                try:
                    submod = importlib.import_module(f"volatility3.plugins.{os_type}.{modname}")
                    for name in dir(submod):
                        obj = getattr(submod, name)
                        if (isinstance(obj, type)
                                and hasattr(obj, 'run')
                                and hasattr(obj, '_required_framework_version')):
                            matches.append(f"{os_type}.{modname}.{name}")
                except Exception:
                    matches.append(f"{os_type}.{modname}.*")
        return matches[:5]
    except Exception:
        return []
