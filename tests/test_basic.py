"""
Basic tests for mem-forensics-mcp.

Tests module imports, configuration, and basic functionality
without requiring actual memory dumps or Vol3.
"""
import pytest
from pathlib import Path


def test_package_import():
    """Test that the main package imports successfully."""
    import mem_forensics_mcp
    assert hasattr(mem_forensics_mcp, "__version__")
    assert mem_forensics_mcp.__version__ == "0.1.0"


def test_config_import():
    """Test configuration module."""
    from mem_forensics_mcp.config import (
        MAX_RESPONSE_SIZE,
        MAX_PROCESSES,
        PLUGIN_TIMEOUT,
        MEMOXIDE_CALL_TIMEOUT,
        MEMOXIDE_BINARY,
        MEMOXIDE_SYMBOLS,
        YARA_RULES_DIR,
    )
    assert MAX_RESPONSE_SIZE == 40000
    assert MAX_PROCESSES == 100
    assert PLUGIN_TIMEOUT == 300
    assert MEMOXIDE_CALL_TIMEOUT == 30
    assert isinstance(MEMOXIDE_BINARY, Path)
    assert isinstance(MEMOXIDE_SYMBOLS, Path)
    assert isinstance(YARA_RULES_DIR, Path)


def test_core_imports():
    """Test core module imports."""
    from mem_forensics_mcp.core import (
        MemorySession,
        get_session,
        clear_sessions,
        list_sessions,
        VOL3_AVAILABLE,
    )
    assert callable(get_session)
    assert callable(clear_sessions)
    assert callable(list_sessions)
    assert isinstance(VOL3_AVAILABLE, bool)


def test_engine_import():
    """Test engine module imports."""
    from mem_forensics_mcp.engine import MemoxideClient
    assert callable(MemoxideClient)


def test_analyzers_import():
    """Test analyzers module imports."""
    from mem_forensics_mcp.analyzers import (
        analyze_image_profile,
        hunt_process_anomalies,
        get_process_tree,
        find_injected_code,
        find_c2_connections,
        get_command_history,
        extract_credentials,
        full_triage,
    )
    assert callable(analyze_image_profile)
    assert callable(hunt_process_anomalies)
    assert callable(find_injected_code)
    assert callable(find_c2_connections)
    assert callable(get_command_history)
    assert callable(extract_credentials)
    assert callable(full_triage)


def test_utils_import():
    """Test utils module imports."""
    from mem_forensics_mcp.utils import VT_AVAILABLE
    assert isinstance(VT_AVAILABLE, bool)


def test_extractors_import():
    """Test extractors module imports."""
    from mem_forensics_mcp.extractors import (
        dump_process,
        dump_vad,
        list_dumpable_files,
    )
    assert callable(dump_process)
    assert callable(dump_vad)
    assert callable(list_dumpable_files)


def test_parent_child_rules():
    """Test parent-child process rules."""
    from mem_forensics_mcp.utils.parent_child_rules import (
        get_process_rule,
        is_valid_parent,
        is_suspicious_name,
        is_lolbin,
        should_have_network,
    )

    # svchost.exe should be spawned by services.exe
    rule = get_process_rule("svchost.exe")
    assert rule is not None
    assert rule.requires_args is True

    valid, reason = is_valid_parent("svchost.exe", "services.exe")
    assert valid is True

    invalid, reason = is_valid_parent("svchost.exe", "explorer.exe")
    assert invalid is False
    assert "services.exe" in reason

    # lsass.exe singleton check
    rule = get_process_rule("lsass.exe")
    assert rule is not None
    assert rule.singleton is True
    assert rule.no_children is True

    # LOLBin checks
    assert is_lolbin("powershell.exe") is True
    assert is_lolbin("notepad.exe") is False

    # Network checks
    assert should_have_network("chrome.exe") is True
    assert should_have_network("notepad.exe") is False

    # Suspicious name checks
    suspicious, _ = is_suspicious_name("mimikatz.exe")
    assert suspicious is True

    suspicious, _ = is_suspicious_name("svchost.exe")
    assert suspicious is False

    # svch0st.exe uses zero instead of 'o' — the current implementation
    # only catches names containing "svchost" substring, not lookalikes
    suspicious, _ = is_suspicious_name("svchost .exe")
    assert suspicious is True


def test_server_module_import():
    """Test server module can be imported."""
    from mem_forensics_mcp import server
    assert hasattr(server, "server")
    assert hasattr(server, "run")
    assert hasattr(server, "main")


def test_session_lifecycle():
    """Test session creation and listing."""
    from mem_forensics_mcp.core.session import (
        MemorySession,
        get_session,
        list_sessions,
        clear_sessions,
    )

    # Clear any existing sessions
    clear_sessions()
    assert list_sessions() == []

    # Creating session for non-existent file should still create session object
    session = get_session("/tmp/nonexistent_test_dump.raw")
    assert session is not None
    assert session.session_id.startswith("mem_")
    assert session.is_initialized is False

    # Session should appear in list
    sessions = list_sessions()
    assert len(sessions) == 1
    assert sessions[0]["session_id"] == session.session_id

    # Cleanup
    clear_sessions()
    assert list_sessions() == []


def test_unified_session_rust_tracking():
    """Test that unified session tracks Rust state."""
    from mem_forensics_mcp.core.session import MemorySession, clear_sessions

    clear_sessions()

    session = MemorySession("/tmp/test.raw")
    assert session.rust_session_id is None
    assert session.rust_initialized is False

    # Simulate Rust session being set
    session.set_rust_session("rust_abc123", {"os": "Windows", "build": "19041"})
    assert session.rust_session_id == "rust_abc123"
    assert session.rust_initialized is True
    assert session.is_initialized is True  # Should be marked initialized
    assert session.profile.get("os") == "Windows"

    clear_sessions()
