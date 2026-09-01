import asyncio
import json
from unittest.mock import AsyncMock, patch

import pytest

from mem_forensics_mcp.analyzers.command_history import get_command_history
from mem_forensics_mcp.analyzers.process_analyzer import get_process_tree
from mem_forensics_mcp.core.session import MemorySession, clear_sessions, get_session
from mem_forensics_mcp import server as server_module


@pytest.fixture(autouse=True)
def reset_sessions():
    clear_sessions()
    yield
    clear_sessions()


def make_image(tmp_path, name="memory.raw", header=b"RAW0"):
    image = tmp_path / name
    image.write_bytes(header + (b"\x00" * 64))
    return image


def decode_response(contents):
    return json.loads(contents[0].text)


def test_lime_header_marks_raw_session_as_linux(tmp_path):
    image = make_image(tmp_path, name="memory.lime", header=b"EMiL")
    session = MemorySession(image)
    session.set_rust_session(
        "rust-linux",
        None,
        metadata={"profile": None, "virtual_memory": False},
    )

    readiness = session.readiness()

    assert session.os_type == "linux"
    assert readiness["ready"] is True
    assert readiness["session_ready"] is True
    assert readiness["raw_ready"] is True
    assert readiness["structured_ready"] is False
    assert readiness["capabilities"] == ["search", "readraw"]
    assert "Linux ISF" in readiness["warnings"][0]


def test_null_profile_rust_session_is_not_structured_ready(tmp_path):
    image = make_image(tmp_path)
    session = MemorySession(image)
    session.set_rust_session(
        "rust-unknown",
        None,
        metadata={"profile": None, "virtual_memory": False},
    )

    readiness = session.readiness()

    assert readiness["session_ready"] is True
    assert readiness["raw_ready"] is True
    assert readiness["structured_ready"] is False
    assert readiness["os_type"] is None
    assert "could not be determined" in readiness["warnings"][0]


def test_windows_rust_session_with_symbols_and_vm_is_structured_ready(tmp_path):
    image = make_image(tmp_path)
    session = MemorySession(image)
    session.set_rust_session(
        "rust-windows",
        {"os": "Windows", "isf_path": "symbols/windows/kernel.json"},
        metadata={"virtual_memory": True},
    )

    readiness = session.readiness()

    assert session.os_type == "windows"
    assert readiness["structured_ready"] is True
    assert "structured_plugins" in readiness["capabilities"]
    assert readiness["warnings"] == []


def test_process_tree_never_calls_windows_plugin_for_raw_linux(tmp_path):
    image = make_image(tmp_path, name="memory.lime", header=b"EMiL")
    session = get_session(image)
    session.set_rust_session("rust-linux", None, metadata={"virtual_memory": False})

    with (
        patch("mem_forensics_mcp.analyzers.process_analyzer.VOL3_AVAILABLE", True),
        patch("mem_forensics_mcp.analyzers.process_analyzer.get_session", return_value=session),
        patch.object(session, "run_plugin") as run_plugin,
    ):
        result = get_process_tree(str(image))

    run_plugin.assert_not_called()
    assert result["os_type"] == "linux"
    assert result["structured_ready"] is False
    assert "Linux ISF" in result["error"]


def test_process_tree_never_calls_windows_plugin_for_unknown_os(tmp_path):
    image = make_image(tmp_path)
    session = get_session(image)
    session.set_rust_session("rust-unknown", None, metadata={"virtual_memory": False})

    with (
        patch("mem_forensics_mcp.analyzers.process_analyzer.VOL3_AVAILABLE", True),
        patch("mem_forensics_mcp.analyzers.process_analyzer.get_session", return_value=session),
        patch.object(session, "run_plugin") as run_plugin,
    ):
        result = get_process_tree(str(image))

    run_plugin.assert_not_called()
    assert result["os_type"] is None
    assert "could not be determined" in result["error"]


def test_command_history_never_calls_windows_plugin_for_raw_linux(tmp_path):
    image = make_image(tmp_path, name="memory.lime", header=b"EMiL")
    session = get_session(image)
    session.set_rust_session("rust-linux", None, metadata={"virtual_memory": False})

    with (
        patch("mem_forensics_mcp.analyzers.command_history.VOL3_AVAILABLE", True),
        patch("mem_forensics_mcp.analyzers.command_history.get_session", return_value=session),
        patch.object(session, "run_plugin") as run_plugin,
    ):
        result = get_command_history(str(image))

    run_plugin.assert_not_called()
    assert result["os_type"] == "linux"
    assert result["raw_ready"] is True
    assert "Linux ISF" in result["error"]


def test_windows_process_tree_behavior_is_preserved(tmp_path):
    image = make_image(tmp_path)
    session = get_session(image)
    session.set_rust_session(
        "rust-windows",
        {"os": "Windows", "isf_path": "symbols/windows/kernel.json"},
        metadata={"virtual_memory": True},
    )
    processes = [
        {"PID": 4, "PPID": 0, "ImageFileName": "System", "CreateTime": "t0"},
        {"PID": 500, "PPID": 4, "ImageFileName": "smss.exe", "CreateTime": "t1"},
    ]

    with (
        patch("mem_forensics_mcp.analyzers.process_analyzer.VOL3_AVAILABLE", True),
        patch("mem_forensics_mcp.analyzers.process_analyzer.get_session", return_value=session),
        patch.object(session, "run_plugin", return_value=processes) as run_plugin,
    ):
        result = get_process_tree(str(image), highlight_suspicious=False)

    run_plugin.assert_called_once_with("windows.pslist.PsList")
    assert result["total_processes"] == 2
    assert result["trees"][0]["pid"] == 4
    assert result["trees"][0]["children"][0]["pid"] == 500


def test_analyze_image_reports_linux_raw_readiness(tmp_path):
    image = make_image(tmp_path, name="memory.lime", header=b"EMiL")

    async def fake_rust_analyze(image_path, **kwargs):
        session = get_session(image_path)
        rust_result = {
            "session_id": "rust-linux",
            "image_size": image.stat().st_size,
            "profile": None,
            "virtual_memory": False,
            "status": "ready",
        }
        session.set_rust_session("rust-linux", None, metadata=rust_result)
        return rust_result

    with (
        patch.object(server_module, "_try_rust_analyze", side_effect=fake_rust_analyze),
        patch.object(
            server_module,
            "_detect_linux_banner_with_rust",
            new=AsyncMock(return_value=True),
        ),
    ):
        result = decode_response(asyncio.run(server_module.call_tool(
            "memory_analyze_image",
            {"image_path": str(image)},
        )))

    assert result["ready"] is True
    assert result["session_ready"] is True
    assert result["raw_ready"] is True
    assert result["structured_ready"] is False
    assert result["os_type"] == "linux"
    assert result["profile"] is None
    assert result["capabilities"] == ["search", "readraw"]


def test_raw_search_remains_available_without_isf(tmp_path):
    image = make_image(tmp_path, name="memory.lime", header=b"EMiL")
    session = get_session(image)
    session.set_rust_session("rust-linux", None, metadata={"virtual_memory": False})

    rust_plugin = AsyncMock(return_value={"matches": [{"offset": 16, "text": "marker"}]})
    with patch.object(server_module, "_try_rust_plugin", rust_plugin):
        result = decode_response(asyncio.run(server_module.call_tool(
            "memory_run_plugin",
            {
                "image_path": str(image),
                "plugin": "search",
                "params": {"pattern": "marker"},
            },
        )))

    rust_plugin.assert_awaited_once()
    assert result["engine"] == "rust"
    assert result["matches"][0]["text"] == "marker"


def test_linux_pslist_does_not_call_windows_rust_plugin_without_symbols(tmp_path):
    image = make_image(tmp_path, name="memory.lime", header=b"EMiL")
    session = get_session(image)
    session.set_rust_session("rust-linux", None, metadata={"virtual_memory": False})

    rust_plugin = AsyncMock(side_effect=AssertionError("Windows Rust plugin was called"))
    with (
        patch.object(server_module, "_try_rust_plugin", rust_plugin),
        patch.object(session, "ensure_vol3_initialized", return_value=False),
    ):
        result = decode_response(asyncio.run(server_module.call_tool(
            "memory_run_plugin",
            {"image_path": str(image), "plugin": "pslist"},
        )))

    rust_plugin.assert_not_awaited()
    assert result["os_type"] == "linux"
    assert result["structured_ready"] is False
    assert "Linux ISF" in result["error"]


def test_plugin_listing_separates_raw_and_structured_capabilities(tmp_path):
    image = make_image(tmp_path, name="memory.lime", header=b"EMiL")
    session = get_session(image)
    session.set_rust_session("rust-linux", None, metadata={"virtual_memory": False})

    with patch.object(session, "ensure_vol3_initialized", return_value=False):
        result = decode_response(asyncio.run(server_module.call_tool(
            "memory_list_plugins",
            {"image_path": str(image)},
        )))

    assert result["raw_plugins"] == ["readraw", "rsds", "search"]
    assert result["structured_plugins"] == {"rust": [], "vol3": {}}
    assert result["os_type"] == "linux"
    assert result["structured_ready"] is False


def test_linux_raw_session_skips_windows_rust_orchestrators(tmp_path):
    image = make_image(tmp_path, name="memory.lime", header=b"EMiL")
    session = get_session(image)
    session.set_rust_session("rust-linux", None, metadata={"virtual_memory": False})

    memoxide = AsyncMock()
    with patch.object(server_module, "_get_memoxide", return_value=memoxide):
        triage = asyncio.run(server_module._run_full_triage(str(image)))
        c2 = asyncio.run(server_module._run_find_c2_connections(str(image)))

    memoxide.full_triage.assert_not_awaited()
    memoxide.find_c2_connections.assert_not_awaited()
    assert triage["os_type"] == "linux"
    assert c2["os_type"] == "linux"
    assert "Linux ISF" in triage["error"]
    assert "Linux ISF" in c2["error"]
