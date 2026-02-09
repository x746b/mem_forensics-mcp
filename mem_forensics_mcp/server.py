"""
Unified Memory Forensics MCP Server

Multi-tier architecture:
  Tier 1: Rust (memoxide) — fast native plugins, no Python overhead
  Tier 2: Python analyzers — smart correlation, VT integration, YARA
  Tier 3: Raw Vol3 fallback — full Vol3 plugin access for anything else
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    TextContent,
    Tool,
)

from .config import MAX_RESPONSE_SIZE
from .engine import MemoxideClient
from .core import (
    VOL3_AVAILABLE,
    VOL3_PATH,
    get_session,
    list_sessions,
    clear_sessions,
    run_plugin as vol3_run_plugin,
    list_available_plugins,
)
from .analyzers import (
    analyze_image_profile,
    hunt_process_anomalies,
    get_process_tree,
    find_injected_code,
    find_c2_connections,
    get_command_history,
    extract_credentials,
    full_triage,
)
from .utils import (
    VT_AVAILABLE,
    vt_lookup_hash,
    vt_lookup_ip,
    vt_lookup_domain,
    vt_lookup_file,
)
from .extractors import (
    dump_process,
    dump_vad,
    list_dumpable_files,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Create MCP server
server = Server("mem-forensics-mcp")

# Rust engine client (singleton)
_memoxide: MemoxideClient | None = None

# Plugins supported by the Rust engine
RUST_PLUGINS = {
    "pslist", "psscan", "cmdline", "dlllist", "malfind",
    "netscan", "cmdscan", "search", "readraw", "rsds",
}


def _get_memoxide() -> MemoxideClient:
    """Get or create the global MemoxideClient."""
    global _memoxide
    if _memoxide is None:
        _memoxide = MemoxideClient()
    return _memoxide


def truncate_response(data: dict[str, Any], max_size: int = MAX_RESPONSE_SIZE) -> dict[str, Any]:
    """Truncate response if it exceeds max size."""
    json_str = json.dumps(data, indent=2, default=str)

    if len(json_str) <= max_size:
        return data

    # Progressively truncate lists until under limit
    for keep_count in [500, 200, 100, 50, 20]:
        for key in list(data.keys()):
            value = data[key]
            if isinstance(value, list) and len(value) > keep_count:
                original_len = len(value)
                data[key] = value[:keep_count]
                data.setdefault("_truncation", {})[f"{key}_truncated"] = f"Showing {keep_count} of {original_len}. Use 'filter' param to narrow results."

        check = json.dumps(data, indent=2, default=str)
        if len(check) <= max_size:
            return data

    data.setdefault("_truncation", {})["truncated"] = True
    data["_truncation"]["message"] = "Response truncated. Use 'filter' param to narrow results."
    return data


def _apply_filter(data: dict[str, Any], filter_str: str) -> dict[str, Any]:
    """Apply case-insensitive substring filter to list values in response."""
    filter_lower = filter_str.lower()
    for key, value in list(data.items()):
        if isinstance(value, list):
            original_len = len(value)
            filtered = []
            for item in value:
                item_str = json.dumps(item, default=str).lower() if isinstance(item, dict) else str(item).lower()
                if filter_lower in item_str:
                    filtered.append(item)
            data[key] = filtered
            if len(filtered) < original_len:
                data.setdefault("_filter_info", {})[key] = f"Matched {len(filtered)} of {original_len} (filter: '{filter_str}')"
    return data


def json_response(data: dict[str, Any]) -> list[TextContent]:
    """Format data as JSON response."""
    data = truncate_response(data)
    return [TextContent(type="text", text=json.dumps(data, indent=2, default=str))]


async def _try_rust_analyze(image_path: str, **kwargs) -> dict[str, Any] | None:
    """
    Try to analyze image via Rust engine (Tier 1).

    Returns result dict with rust_session_id, or None if failed.
    """
    memoxide = _get_memoxide()
    if not memoxide.binary_available:
        return None

    result = await memoxide.analyze_image(image_path, **kwargs)
    if result and result.get("session_id"):
        # Store rust session in our unified session
        session = get_session(image_path)
        if session:
            profile = result.get("profile", result.get("detection", {}))
            session.set_rust_session(result["session_id"], profile)
        return result
    return None


async def _try_rust_plugin(session, plugin: str, params: dict | None = None) -> dict[str, Any] | None:
    """
    Try to run a plugin via Rust engine (Tier 1).

    Returns result dict, or None if Rust unavailable/failed.
    """
    if not session.rust_initialized:
        return None

    memoxide = _get_memoxide()
    if not memoxide.is_available():
        return None

    result = await memoxide.run_plugin(session.rust_session_id, plugin, params)
    return result


@server.list_tools()
async def list_tools() -> list[Tool]:
    """List available MCP tools."""
    tools = []

    # Full Triage (Primary Entry Point)
    tools.append(Tool(
        name="memory_full_triage",
        description="Run complete automated triage of memory dump. Uses Rust engine for fast data collection and Python analyzers for correlation. Produces executive summary with risk level, prioritized findings, and IOCs.",
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {
                    "type": "string",
                    "description": "Path to memory dump file",
                },
                "quick_scan": {
                    "type": "boolean",
                    "default": False,
                    "description": "Skip slower analyses (credentials) for faster results",
                },
            },
            "required": ["image_path"],
        },
    ))

    # Session Management
    tools.append(Tool(
        name="memory_analyze_image",
        description="Initialize memory image analysis. Tries Rust engine first (fast ISF auto-detection), falls back to Vol3. Returns session ID for subsequent operations.",
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {
                    "type": "string",
                    "description": "Path to memory dump file (.raw, .vmem, .dmp, .lime, .mem)",
                },
                "dtb": {
                    "type": "string",
                    "description": "Override DTB (hex or decimal, e.g., '0x1ad000')",
                },
                "kernel_base": {
                    "type": "string",
                    "description": "Override kernel base address (hex or decimal)",
                },
            },
            "required": ["image_path"],
        },
    ))

    tools.append(Tool(
        name="memory_list_sessions",
        description="List all active memory analysis sessions. Shows session IDs, image paths, and engine status.",
        inputSchema={"type": "object", "properties": {}},
    ))

    tools.append(Tool(
        name="memory_get_status",
        description="Get status and capabilities. Shows available engines (Rust/Vol3) and what analyses can be performed.",
        inputSchema={"type": "object", "properties": {}},
    ))

    # Process Analysis
    tools.append(Tool(
        name="memory_hunt_process_anomalies",
        description="Detect hidden processes, unusual parent-child relationships, and suspicious process attributes. Uses Rust pslist+psscan for data, Python analyzer for correlation.",
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {"type": "string", "description": "Path to memory dump file"},
                "include_normal": {"type": "boolean", "default": False, "description": "Include normal processes"},
            },
            "required": ["image_path"],
        },
    ))

    tools.append(Tool(
        name="memory_get_process_tree",
        description="Get process tree showing parent-child relationships. Highlights suspicious processes.",
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {"type": "string", "description": "Path to memory dump file"},
                "root_pid": {"type": "integer", "description": "Show tree from this PID"},
                "highlight_suspicious": {"type": "boolean", "default": True},
            },
            "required": ["image_path"],
        },
    ))

    # Malware Detection
    tools.append(Tool(
        name="memory_find_injected_code",
        description="Scan for code injection. Uses Rust malfind (fast), falls back to Vol3 malfind + YARA.",
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {"type": "string", "description": "Path to memory dump file"},
                "pid": {"type": "integer", "description": "Scan specific process only"},
                "yara_scan": {"type": "boolean", "default": True},
                "dump_payloads": {"type": "boolean", "default": False},
            },
            "required": ["image_path"],
        },
    ))

    tools.append(Tool(
        name="memory_find_c2_connections",
        description="Find suspicious network connections. Uses Rust netscan for data, Python for C2 analysis.",
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {"type": "string", "description": "Path to memory dump file"},
                "include_legitimate": {"type": "boolean", "default": False},
                "include_listening": {"type": "boolean", "default": False},
            },
            "required": ["image_path"],
        },
    ))

    # Forensic Artifacts
    tools.append(Tool(
        name="memory_get_command_history",
        description="Recover attacker commands from cmd.exe history and process command lines. Uses Rust cmdscan, enriched by Vol3.",
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {"type": "string", "description": "Path to memory dump file"},
                "pid": {"type": "integer", "description": "Filter by PID"},
                "include_benign": {"type": "boolean", "default": False},
            },
            "required": ["image_path"],
        },
    ))

    tools.append(Tool(
        name="memory_extract_credentials",
        description="Extract credential artifacts via Vol3: NTLM hashes (SAM), LSA secrets, cached domain credentials.",
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {"type": "string", "description": "Path to memory dump file"},
                "include_machine_accounts": {"type": "boolean", "default": False},
            },
            "required": ["image_path"],
        },
    ))

    # Raw Plugin Access (Tier 1 + Tier 3)
    tools.append(Tool(
        name="memory_run_plugin",
        description="Run a forensics plugin. Supported Rust plugins (fast): pslist, psscan, cmdline, dlllist, malfind, netscan, cmdscan, search, readraw, rsds. Any other name runs via Vol3. Use 'filter' to grep results server-side (avoids truncation).",
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {"type": "string", "description": "Path to memory dump file"},
                "plugin": {"type": "string", "description": "Plugin name (e.g., 'pslist', 'malfind', 'filescan')"},
                "pid": {"type": "integer", "description": "Filter by PID"},
                "params": {"type": "object", "description": "Additional plugin parameters"},
                "filter": {"type": "string", "description": "Case-insensitive substring filter applied to results before returning. Useful for large result sets like filescan."},
            },
            "required": ["image_path", "plugin"],
        },
    ))

    tools.append(Tool(
        name="memory_list_plugins",
        description="List all available plugins (Rust + Vol3).",
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {"type": "string", "description": "Path to memory dump file"},
            },
            "required": ["image_path"],
        },
    ))

    # Extraction Tools
    tools.append(Tool(
        name="memory_dump_process",
        description="Get process info including memory regions and loaded DLLs.",
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {"type": "string", "description": "Path to memory dump file"},
                "pid": {"type": "integer", "description": "Process ID to dump"},
                "output_dir": {"type": "string", "description": "Directory for output files"},
            },
            "required": ["image_path", "pid"],
        },
    ))

    tools.append(Tool(
        name="memory_dump_vad",
        description="Examine a specific VAD (memory region). Useful for injected code regions.",
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {"type": "string", "description": "Path to memory dump file"},
                "pid": {"type": "integer", "description": "Process ID"},
                "vad_address": {"type": "string", "description": "VAD start address (hex)"},
            },
            "required": ["image_path", "pid", "vad_address"],
        },
    ))

    tools.append(Tool(
        name="memory_list_dumpable_files",
        description="List files that can be extracted from memory cache.",
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {"type": "string", "description": "Path to memory dump file"},
                "pid": {"type": "integer", "description": "Filter by process ID"},
            },
            "required": ["image_path"],
        },
    ))

    # VirusTotal Integration
    if VT_AVAILABLE:
        tools.append(Tool(
            name="vt_lookup_hash",
            description="Look up file hash (MD5/SHA1/SHA256) on VirusTotal. Requires VIRUSTOTAL_API_KEY env var.",
            inputSchema={
                "type": "object",
                "properties": {"file_hash": {"type": "string", "description": "MD5/SHA1/SHA256 hash"}},
                "required": ["file_hash"],
            },
        ))
        tools.append(Tool(
            name="vt_lookup_ip",
            description="Look up IP address reputation on VirusTotal.",
            inputSchema={
                "type": "object",
                "properties": {"ip_address": {"type": "string", "description": "IPv4 or IPv6 address"}},
                "required": ["ip_address"],
            },
        ))
        tools.append(Tool(
            name="vt_lookup_domain",
            description="Look up domain reputation on VirusTotal.",
            inputSchema={
                "type": "object",
                "properties": {"domain": {"type": "string", "description": "Domain name"}},
                "required": ["domain"],
            },
        ))
        tools.append(Tool(
            name="vt_lookup_file",
            description="Hash local file and look up on VirusTotal.",
            inputSchema={
                "type": "object",
                "properties": {"file_path": {"type": "string", "description": "Path to file"}},
                "required": ["file_path"],
            },
        ))

    return tools


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool calls with tier routing."""
    logger.info(f"Tool called: {name}")

    try:
        # === Session / Status ===

        if name == "memory_analyze_image":
            image_path = arguments["image_path"]
            dtb = arguments.get("dtb")
            kernel_base = arguments.get("kernel_base")

            # Tier 1: Try Rust engine first
            rust_result = await _try_rust_analyze(
                image_path, dtb=dtb, kernel_base=kernel_base,
            )

            if rust_result and rust_result.get("session_id"):
                # Rust succeeded - return combined info
                session = get_session(image_path)
                result = {
                    "session_id": session.session_id if session else rust_result["session_id"],
                    "image_path": image_path,
                    "engine": "rust (memoxide)",
                    "rust_session_id": rust_result["session_id"],
                    "profile": rust_result.get("profile", rust_result.get("detection", {})),
                    "ready": True,
                }
                # Add file size if available
                if "file_size_bytes" in rust_result:
                    result["file_size_bytes"] = rust_result["file_size_bytes"]
                    result["file_size_gb"] = rust_result.get("file_size_gb")
                return json_response(result)

            # Tier 2: Fall back to Vol3
            result = analyze_image_profile(image_path=image_path)
            if result.get("ready"):
                result["engine"] = "vol3"
            return json_response(result)

        elif name == "memory_list_sessions":
            sessions = list_sessions()
            return json_response({
                "active_sessions": len(sessions),
                "sessions": sessions,
            })

        elif name == "memory_get_status":
            memoxide = _get_memoxide()
            return json_response({
                "rust_engine": {
                    "binary_available": memoxide.binary_available,
                    "running": memoxide.is_available(),
                    "supported_plugins": sorted(RUST_PLUGINS),
                },
                "volatility3": {
                    "available": VOL3_AVAILABLE,
                    "path": VOL3_PATH,
                },
                "virustotal_available": VT_AVAILABLE,
                "server_version": "0.1.0",
                "architecture": "Three-tier: Rust (fast) → Python analyzers → Vol3 (fallback)",
            })

        # === Plugin Execution (Tier 1 → Tier 3) ===

        elif name == "memory_run_plugin":
            image_path = arguments["image_path"]
            plugin = arguments["plugin"]
            pid = arguments.get("pid")
            params = arguments.get("params")
            result_filter = arguments.get("filter")

            session = get_session(image_path)
            if session is None:
                return json_response({"error": "Failed to create session"})

            # Tier 1: Try Rust for supported plugins
            plugin_lower = plugin.lower()
            if plugin_lower in RUST_PLUGINS:
                # Ensure Rust session exists
                if not session.rust_initialized:
                    await _try_rust_analyze(image_path)

                rust_params = dict(params) if params else {}
                if pid is not None:
                    rust_params["pid"] = pid

                rust_result = await _try_rust_plugin(session, plugin_lower, rust_params if rust_params else None)
                if rust_result is not None:
                    rust_result["engine"] = "rust"
                    if result_filter:
                        rust_result = _apply_filter(rust_result, result_filter)
                    return json_response(rust_result)

            # Tier 3: Vol3 fallback
            vol3_kwargs = {}
            if params:
                for k, v in params.items():
                    vol3_kwargs[k] = v
            # Extract dump-dir for file output handling
            dump_dir = vol3_kwargs.pop("dump-dir", vol3_kwargs.pop("dump_dir", None))
            result = vol3_run_plugin(
                image_path=image_path,
                plugin=plugin,
                pid=pid,
                dump_dir=dump_dir,
                **vol3_kwargs,
            )
            if "error" not in result:
                result["engine"] = "vol3"
            if result_filter:
                result = _apply_filter(result, result_filter)
            return json_response(result)

        elif name == "memory_list_plugins":
            rust_plugins = sorted(RUST_PLUGINS)
            vol3_result = list_available_plugins(image_path=arguments["image_path"])

            return json_response({
                "rust_plugins": rust_plugins,
                "vol3_plugins": vol3_result.get("plugins", {}),
                "os_type": vol3_result.get("os_type"),
            })

        # === Analysis Tools (Tier 2, using Tier 1 data) ===

        elif name == "memory_full_triage":
            return json_response(await _run_full_triage(
                image_path=arguments["image_path"],
                quick_scan=arguments.get("quick_scan", False),
            ))

        elif name == "memory_hunt_process_anomalies":
            # This uses Vol3 pslist+psscan internally, but could be enhanced
            # to use Rust data when available
            result = hunt_process_anomalies(
                image_path=arguments["image_path"],
                include_normal=arguments.get("include_normal", False),
            )
            return json_response(result)

        elif name == "memory_get_process_tree":
            result = get_process_tree(
                image_path=arguments["image_path"],
                root_pid=arguments.get("root_pid"),
                highlight_suspicious=arguments.get("highlight_suspicious", True),
            )
            return json_response(result)

        elif name == "memory_find_injected_code":
            result = find_injected_code(
                image_path=arguments["image_path"],
                pid=arguments.get("pid"),
                yara_scan=arguments.get("yara_scan", True),
                dump_payloads=arguments.get("dump_payloads", False),
            )
            return json_response(result)

        elif name == "memory_find_c2_connections":
            result = find_c2_connections(
                image_path=arguments["image_path"],
                include_legitimate=arguments.get("include_legitimate", False),
                include_listening=arguments.get("include_listening", False),
            )
            return json_response(result)

        elif name == "memory_get_command_history":
            result = get_command_history(
                image_path=arguments["image_path"],
                pid=arguments.get("pid"),
                include_benign=arguments.get("include_benign", False),
            )
            return json_response(result)

        elif name == "memory_extract_credentials":
            result = extract_credentials(
                image_path=arguments["image_path"],
                include_machine_accounts=arguments.get("include_machine_accounts", False),
            )
            return json_response(result)

        # === Extraction Tools ===

        elif name == "memory_dump_process":
            result = dump_process(
                image_path=arguments["image_path"],
                pid=arguments["pid"],
                output_dir=arguments.get("output_dir"),
            )
            return json_response(result)

        elif name == "memory_dump_vad":
            result = dump_vad(
                image_path=arguments["image_path"],
                pid=arguments["pid"],
                vad_address=arguments["vad_address"],
                output_dir=arguments.get("output_dir"),
            )
            return json_response(result)

        elif name == "memory_list_dumpable_files":
            result = list_dumpable_files(
                image_path=arguments["image_path"],
                pid=arguments.get("pid"),
            )
            return json_response(result)

        # === VirusTotal Tools ===

        elif name == "vt_lookup_hash":
            if not VT_AVAILABLE:
                return json_response({"error": "vt-py library not installed"})
            try:
                return json_response(vt_lookup_hash(arguments["file_hash"]))
            except (ValueError, RuntimeError) as e:
                return json_response({"error": str(e)})

        elif name == "vt_lookup_ip":
            if not VT_AVAILABLE:
                return json_response({"error": "vt-py library not installed"})
            try:
                return json_response(vt_lookup_ip(arguments["ip_address"]))
            except (ValueError, RuntimeError) as e:
                return json_response({"error": str(e)})

        elif name == "vt_lookup_domain":
            if not VT_AVAILABLE:
                return json_response({"error": "vt-py library not installed"})
            try:
                return json_response(vt_lookup_domain(arguments["domain"]))
            except (ValueError, RuntimeError) as e:
                return json_response({"error": str(e)})

        elif name == "vt_lookup_file":
            if not VT_AVAILABLE:
                return json_response({"error": "vt-py library not installed"})
            try:
                return json_response(vt_lookup_file(arguments["file_path"]))
            except (ValueError, RuntimeError, FileNotFoundError) as e:
                return json_response({"error": str(e)})

        else:
            return json_response({"error": f"Unknown tool: {name}"})

    except FileNotFoundError as e:
        return json_response({"error": "File not found", "detail": str(e)})

    except ImportError as e:
        return json_response({
            "error": "Missing dependency",
            "detail": str(e),
            "hint": "Install volatility3: pip install volatility3",
        })

    except Exception as e:
        logger.exception(f"Error in tool {name}")
        return json_response({
            "error": "Internal error",
            "detail": str(e),
            "tool": name,
        })


async def _run_full_triage(image_path: str, quick_scan: bool = False) -> dict[str, Any]:
    """
    Full triage using Rust for fast data + Python for analysis.

    Tries Rust engine first for speed; falls back to Vol3 for each step.
    """
    session = get_session(image_path)
    if session is None:
        return {"error": "Failed to create session"}

    # Step 1: Initialize via Rust if possible
    if not session.rust_initialized:
        await _try_rust_analyze(image_path)

    # Step 2: Try Rust full_triage if available (it has its own orchestrator)
    if session.rust_initialized:
        memoxide = _get_memoxide()
        rust_triage = await memoxide.full_triage(session.rust_session_id)
        if rust_triage and "error" not in rust_triage:
            # Enrich with Vol3-only data (credentials)
            if not quick_scan:
                try:
                    cred_result = extract_credentials(image_path)
                    if "error" not in cred_result and cred_result.get("credentials_found", 0) > 0:
                        rust_triage["credentials"] = cred_result
                except Exception as e:
                    logger.warning(f"Credential extraction failed: {e}")

            rust_triage["engine"] = "rust+python"
            return rust_triage

    # Step 3: Fall back to pure Vol3 triage
    if VOL3_AVAILABLE:
        result = full_triage(image_path=image_path, quick_scan=quick_scan)
        result["engine"] = "vol3"
        return result

    return {"error": "No analysis engine available. Install volatility3 or provide memoxide binary."}


async def main():
    """Run the MCP server."""
    logger.info("Starting mem-forensics-mcp server (unified)")

    memoxide = _get_memoxide()
    logger.info(f"Rust engine (memoxide): {'available' if memoxide.binary_available else 'not found'}")
    logger.info(f"Volatility3: {'available' if VOL3_AVAILABLE else 'not installed'}")

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def run():
    """Entry point for the server."""
    asyncio.run(main())


if __name__ == "__main__":
    run()
