"""
Configuration settings for mem-forensics-mcp.

Adjustable limits and paths for memory forensics analysis.
"""
from pathlib import Path

# Response size limits (to prevent LLM context overflow)
MAX_RESPONSE_SIZE = 40000  # ~10k tokens
MAX_PROCESSES = 100  # Max processes to return
MAX_CONNECTIONS = 50  # Max network connections to return
MAX_INJECTIONS = 20  # Max injection findings to return
MAX_COMMANDS = 50  # Max command history entries
MAX_CREDENTIALS = 30  # Max credential entries

# Timeouts (seconds)
PLUGIN_TIMEOUT = 300  # 5 minutes per plugin
YARA_SCAN_TIMEOUT = 60  # 1 minute for YARA scans
MEMOXIDE_CALL_TIMEOUT = 30  # 30 seconds per Rust call

# Paths
DEFAULT_DUMP_DIR = Path("/tmp/memoryforensics_dumps")
YARA_RULES_DIR = Path(__file__).parent.parent / "rules" / "memory_yara"
MEMOXIDE_BINARY = Path(__file__).parent.parent / "engines" / "memoxide" / "memoxide"
MEMOXIDE_SYMBOLS = Path(__file__).parent.parent / "engines" / "memoxide" / "symbols"

# Process reputation - known legitimate Windows processes
# Used for anomaly detection
SYSTEM_PROCESSES = {
    "System": {
        "pid": 4,
        "parent": None,
        "path": None,
        "session": 0,
    },
    "Registry": {
        "parent": "System",
        "path": None,
        "session": 0,
    },
    "smss.exe": {
        "parent": "System",
        "path": r"\SystemRoot\System32\smss.exe",
        "session": 0,
        "singleton": True,
    },
    "csrss.exe": {
        "parent": "smss.exe",
        "path": r"\SystemRoot\System32\csrss.exe",
        "multiple_allowed": True,  # One per session
    },
    "wininit.exe": {
        "parent": "smss.exe",
        "path": r"\SystemRoot\System32\wininit.exe",
        "session": 0,
        "singleton": True,
    },
    "winlogon.exe": {
        "parent": "smss.exe",
        "path": r"\SystemRoot\System32\winlogon.exe",
        "multiple_allowed": True,  # One per session
    },
    "services.exe": {
        "parent": "wininit.exe",
        "path": r"\SystemRoot\System32\services.exe",
        "session": 0,
        "singleton": True,
    },
    "lsass.exe": {
        "parent": "wininit.exe",
        "path": r"\SystemRoot\System32\lsass.exe",
        "session": 0,
        "singleton": True,
        "no_children": True,
    },
    "lsaiso.exe": {
        "parent": "wininit.exe",
        "path": r"\SystemRoot\System32\lsaiso.exe",
        "session": 0,
        "optional": True,  # Only on Credential Guard systems
    },
    "svchost.exe": {
        "parent": "services.exe",
        "path": r"\SystemRoot\System32\svchost.exe",
        "must_have_args": True,  # Always has -k argument
        "multiple_allowed": True,
    },
    "RuntimeBroker.exe": {
        "parent": "svchost.exe",
        "multiple_allowed": True,
    },
    "taskhostw.exe": {
        "parent": "svchost.exe",
        "multiple_allowed": True,
    },
    "explorer.exe": {
        "parent": "userinit.exe",  # Or can be orphaned after userinit exits
        "multiple_allowed": True,  # One per user session
        "allow_orphan": True,
    },
    "userinit.exe": {
        "parent": "winlogon.exe",
        "short_lived": True,  # Exits after starting explorer
    },
}

# Suspicious parent-child combinations
SUSPICIOUS_ANCESTRY = {
    "svchost.exe": {
        "invalid_parents": [
            "explorer.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
            "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
        ],
    },
    "lsass.exe": {
        "invalid_parents": ["*"],  # Only wininit.exe is valid
        "valid_parents": ["wininit.exe"],
    },
    "services.exe": {
        "invalid_parents": ["*"],
        "valid_parents": ["wininit.exe"],
    },
    "csrss.exe": {
        "invalid_parents": ["*"],
        "valid_parents": ["smss.exe"],
    },
}

# Processes that should NOT make network connections
NO_NETWORK_PROCESSES = [
    "notepad.exe",
    "calc.exe",
    "mspaint.exe",
    "wordpad.exe",
    "write.exe",
    "charmap.exe",
    "magnify.exe",
    "narrator.exe",
    "osk.exe",
]

# Suspicious ports for C2 detection
SUSPICIOUS_PORTS = [
    4444,   # Meterpreter default
    5555,   # Common RAT
    6666,   # Common RAT
    1337,   # Leet port
    31337,  # Leet port
    8080,   # Alt HTTP (suspicious for non-browsers)
    8443,   # Alt HTTPS
    9001,   # Tor
    9050,   # Tor SOCKS
]

# Common C2 ports that need process context
C2_CANDIDATE_PORTS = [
    80,     # HTTP - suspicious if not browser
    443,    # HTTPS - suspicious if not browser
    53,     # DNS - suspicious if not dns client
    8080,
    8443,
]
