# Plan: Multi-Tier Memory Forensics MCP (`mem_forensics-mcp`)

## Context

Two existing MCP servers for memory forensics:

- **memoxide_mcp** (Rust): Pure-Rust memory forensics — fast ISF-based plugins (pslist, psscan, cmdline, dlllist, malfind, netscan, cmdscan, search, readraw), auto-detection (RSDS/PDB), risk scoring. 173 tests, 0 warnings. ~5MB binary.
- **memoryforensics_mcp** (Python): Vol3-based forensics — wraps Volatility3 Python API, adds process analysis, injection scanning, credential extraction (hashdump + lsadump + cachedump), VirusTotal integration, process/VAD dumping.

Goal: Create `/opt/mem_forensics-mcp` — a **single unified MCP server** (Python) that combines both, dispatching to the fastest/best engine per tool via a three-tier architecture:

```
Tier 1: Rust (memoxide binary)  — fast native plugins, no Python overhead
Tier 2: Python analyzers        — smart correlation, VT integration, YARA
Tier 3: Raw Vol3 fallback       — full Vol3 plugin access for anything else
```

---

## Architecture

### Single Python MCP Server

The unified server is a **Python MCP server** that:
1. Spawns memoxide as a **child process** (stdio MCP) and communicates via JSON-RPC
2. Has direct Python access to Vol3 for Tier 2/3
3. Exposes a single set of MCP tools to the LLM

```
LLM ←→ [mem_forensics-mcp (Python)] ←→ memoxide (Rust child, stdio MCP)
                                    ←→ Volatility3 (Python library)
```

### Tier Routing Logic

Each MCP tool has a **preferred tier** and **fallback**:

| Tool | Tier 1 (Rust) | Tier 2 (Python+Vol3) | Tier 3 (Raw Vol3) |
|------|:---:|:---:|:---:|
| `memory_analyze_image` | **PRIMARY** — auto-detect ISF, DTB, kernel_base | FALLBACK — Vol3 `windows.info` if Rust fails | — |
| `memory_run_plugin` (pslist) | **PRIMARY** | — | FALLBACK |
| `memory_run_plugin` (psscan) | **PRIMARY** | — | FALLBACK |
| `memory_run_plugin` (cmdline) | **PRIMARY** | — | FALLBACK |
| `memory_run_plugin` (dlllist) | **PRIMARY** | — | FALLBACK |
| `memory_run_plugin` (malfind) | **PRIMARY** | — | FALLBACK |
| `memory_run_plugin` (netscan) | **PRIMARY** | — | FALLBACK |
| `memory_run_plugin` (cmdscan) | **PRIMARY** | — | — |
| `memory_run_plugin` (search) | **PRIMARY** (unique) | — | — |
| `memory_run_plugin` (readraw) | **PRIMARY** (unique) | — | — |
| `memory_run_plugin` (rsds) | **PRIMARY** (unique) | — | — |
| `memory_run_plugin` (other) | — | — | **PRIMARY** (any Vol3 plugin) |
| `memory_hunt_process_anomalies` | Rust pslist+psscan → | **PRIMARY** Python analyzer | — |
| `memory_find_injected_code` | **PRIMARY** (Rust malfind) | FALLBACK (Vol3 malfind + YARA) | — |
| `memory_find_c2_connections` | Rust netscan → | **PRIMARY** Python analyzer | — |
| `memory_get_command_history` | **PRIMARY** (Rust cmdscan) | ENRICH (Vol3 consoles if available) | — |
| `memory_extract_credentials` | — | **PRIMARY** (Vol3 hashdump+lsadump+cachedump) | — |
| `memory_full_triage` | Rust plugins for data → | **PRIMARY** Python orchestrator | — |
| `memory_dump_process` | — | **PRIMARY** (Vol3 dumpfiles) | — |
| `memory_dump_vad` | — | **PRIMARY** (Vol3 vadinfo) | — |
| `memory_list_dumpable_files` | — | **PRIMARY** (Vol3 filescan) | — |
| `memory_get_process_tree` | Rust pslist → | **PRIMARY** Python tree builder | — |
| `vt_lookup_*` | — | **PRIMARY** (Python VT client) | — |

### Tier 1: Rust Engine (memoxide)

- The memoxide **release binary** is included in the repo at `engines/memoxide` (copied from build)
- Python spawns it as a subprocess with stdio MCP transport
- A `MemoxideClient` class sends JSON-RPC tool calls and reads responses
- Session IDs are managed by the Python layer; Rust sessions are created/tracked internally
- If memoxide crashes or fails, Tier 2/3 handles the request

### Tier 2: Python Analyzers

- Ported from `memoryforensics_mcp/analyzers/` and `memoryforensics_mcp/utils/`
- Process anomaly detection, network analysis, command history analysis
- Credential extraction via Vol3
- VirusTotal integration
- YARA scanning
- Full triage orchestrator that uses Rust data + Python analysis

### Tier 3: Raw Vol3 Fallback

- Ported from `memoryforensics_mcp/core/vol3_runner.py`
- Direct Vol3 Python API for any plugin not in Tier 1
- Fallback when Rust engine is unavailable or fails
- Exposes ALL Vol3 plugins via `memory_run_plugin`

---

## Project Structure

```
/opt/mem_forensics-mcp/
├── pyproject.toml                    # Project metadata, dependencies
├── README.md                         # Usage documentation
├── CLAUDE.md                         # Investigation workflow for LLM
├── LICENSE                           # MIT
│
├── engines/
│   └── memoxide/                     # Rust engine (copied from memoxide_mcp build)
│       ├── memoxide                  # Release binary
│       └── symbols/                  # Symlink or copy of ISF symbol store
│
├── mem_forensics_mcp/                # Main Python package
│   ├── __init__.py
│   ├── server.py                     # MCP server — tool definitions + routing
│   ├── config.py                     # Configuration (from memoryforensics_mcp)
│   │
│   ├── engine/                       # Tier 1: Rust engine client
│   │   ├── __init__.py
│   │   └── memoxide_client.py        # Subprocess MCP client for memoxide binary
│   │
│   ├── core/                         # Tier 3: Vol3 integration
│   │   ├── __init__.py
│   │   ├── vol3_runner.py            # Vol3 wrapper (from memoryforensics_mcp)
│   │   ├── session.py                # Unified session management
│   │   └── plugin_runner.py          # Generic plugin dispatch
│   │
│   ├── analyzers/                    # Tier 2: Smart analysis
│   │   ├── __init__.py
│   │   ├── process_analyzer.py       # Process anomaly detection
│   │   ├── injection_scanner.py      # Code injection + YARA
│   │   ├── network_analyzer.py       # C2 detection
│   │   ├── command_history.py        # Command recovery + classification
│   │   ├── credential_extractor.py   # Hash/secret extraction via Vol3
│   │   └── full_triage.py            # Orchestrator (calls Rust + Python)
│   │
│   ├── extractors/                   # Extraction tools
│   │   ├── __init__.py
│   │   └── process_dumper.py         # Binary extraction via Vol3
│   │
│   └── utils/                        # Utilities
│       ├── __init__.py
│       ├── parent_child_rules.py     # Process rules (from memoryforensics_mcp)
│       └── virustotal_client.py      # VT API client (from memoryforensics_mcp)
│
├── rules/
│   └── memory_yara/                  # YARA rules directory
│
└── tests/
    ├── test_basic.py
    ├── test_memoxide_client.py
    ├── test_tier_routing.py
    └── *.raw / *.mem                 # Symlinks to test dumps
```

---

## Key Components

### 1. `MemoxideClient` (`engine/memoxide_client.py`) — NEW

Subprocess MCP client that communicates with the memoxide binary:

```python
class MemoxideClient:
    def __init__(self, binary_path, symbols_root):
        # Spawn memoxide as subprocess (stdin/stdout JSON-RPC)

    async def call_tool(self, tool_name, params) -> dict:
        # Send JSON-RPC request, read response

    async def analyze_image(self, image_path, **kwargs) -> dict:
        # Call memory_analyze_image, return session info

    async def run_plugin(self, session_id, plugin, params=None) -> dict:
        # Call memory_run_plugin

    async def full_triage(self, session_id) -> dict:
        # Call memory_full_triage (Rust-only triage for data)

    def is_available(self) -> bool:
        # Check if memoxide process is running
```

### 2. Unified Session (`core/session.py`) — MODIFIED

Wraps both Rust and Python sessions:

```python
class UnifiedSession:
    rust_session_id: Optional[str]     # memoxide session
    vol3_runner: Optional[Vol3Runner]   # Vol3 context (lazy-loaded)
    image_path: str
    profile: Optional[str]
    dtb: Optional[int]
    kernel_base: Optional[int]
```

### 3. Server Router (`server.py`) — NEW

The main MCP server that routes to the correct tier:

```python
# Tier 1: Try Rust first for supported plugins
RUST_PLUGINS = {"pslist", "psscan", "cmdline", "dlllist", "malfind",
                "netscan", "cmdscan", "search", "readraw", "rsds"}

async def handle_run_plugin(session, plugin, params):
    if plugin in RUST_PLUGINS and memoxide.is_available():
        result = await memoxide.run_plugin(session.rust_id, plugin, params)
        if result is not None:
            return result
    # Fallback to Vol3
    return await vol3_run_plugin(session, plugin, params)
```

### 4. Full Triage Orchestrator (`analyzers/full_triage.py`) — MODIFIED

Uses Rust for fast data collection, Python for analysis:

```python
async def full_triage(session):
    # Step 1: Fast data via Rust (Tier 1)
    processes = await memoxide.run_plugin(sid, "pslist")
    psscan = await memoxide.run_plugin(sid, "psscan")
    cmdlines = await memoxide.run_plugin(sid, "cmdline")
    netscan = await memoxide.run_plugin(sid, "netscan")
    malfind = await memoxide.run_plugin(sid, "malfind")
    cmdscan = await memoxide.run_plugin(sid, "cmdscan")

    # Step 2: Vol3-only data (Tier 2)
    credentials = await vol3_extract_credentials(session)

    # Step 3: Python analysis (Tier 2)
    anomalies = analyze_processes(processes, psscan, cmdlines)
    c2 = analyze_network(netscan, processes)
    injections = analyze_injections(malfind)
    commands = analyze_commands(cmdscan, cmdlines)

    # Step 4: Correlate + score + IOCs
    return build_triage_report(...)
```

---

## Source File Mapping

All operations are **COPY** (never move):

| Source | Destination | Notes |
|--------|------------|-------|
| `/opt/memoryforensics_mcp/memoryforensics_mcp/server.py` | `mem_forensics_mcp/server.py` | Rewrite with tier routing |
| `/opt/memoryforensics_mcp/memoryforensics_mcp/config.py` | `mem_forensics_mcp/config.py` | Copy as-is |
| `/opt/memoryforensics_mcp/memoryforensics_mcp/core/vol3_runner.py` | `mem_forensics_mcp/core/vol3_runner.py` | Copy as-is |
| `/opt/memoryforensics_mcp/memoryforensics_mcp/core/session.py` | `mem_forensics_mcp/core/session.py` | Modify for unified sessions |
| `/opt/memoryforensics_mcp/memoryforensics_mcp/core/plugin_runner.py` | `mem_forensics_mcp/core/plugin_runner.py` | Copy as-is |
| `/opt/memoryforensics_mcp/memoryforensics_mcp/analyzers/*.py` | `mem_forensics_mcp/analyzers/*.py` | Copy, modify full_triage.py |
| `/opt/memoryforensics_mcp/memoryforensics_mcp/extractors/*.py` | `mem_forensics_mcp/extractors/*.py` | Copy as-is |
| `/opt/memoryforensics_mcp/memoryforensics_mcp/utils/*.py` | `mem_forensics_mcp/utils/*.py` | Copy as-is |
| `/opt/memoxide_mcp/target/release/memoxide` | `engines/memoxide/memoxide` | Copy binary |
| `/opt/memoxide_mcp/symbols/` | `engines/memoxide/symbols` | Symlink |
| `/opt/memoxide_mcp/crates/` | NOT COPIED | Rust source stays in memoxide_mcp |

---

## Implementation Steps

### Step 1: Create repo structure
- `mkdir -p /opt/mem_forensics-mcp/{mem_forensics_mcp/{engine,core,analyzers,extractors,utils},engines/memoxide,rules/memory_yara,tests}`
- Create `__init__.py` files
- Create `pyproject.toml` with dependencies

### Step 2: Copy Python sources from memoryforensics_mcp
- Copy `config.py`, `core/`, `analyzers/`, `extractors/`, `utils/`
- Fix import paths (`memoryforensics_mcp` → `mem_forensics_mcp`)

### Step 3: Copy Rust binary + symbols
- Build memoxide release: `cargo build --release` in memoxide_mcp
- Copy binary to `engines/memoxide/memoxide`
- Symlink symbols: `ln -s /opt/memoxide_mcp/symbols engines/memoxide/symbols`

### Step 4: Implement MemoxideClient
- Subprocess management (spawn, health check, restart)
- JSON-RPC request/response over stdin/stdout
- Timeout handling (30s per call)
- Graceful degradation when binary unavailable

### Step 5: Implement unified session management
- `UnifiedSession` that tracks both Rust and Vol3 sessions
- Lazy Vol3 initialization (only when Tier 2/3 needed)
- Session reuse across tiers

### Step 6: Implement server.py with tier routing
- All 17+ MCP tools from both projects
- Tier routing per tool
- Response format normalization (Rust JSON → Python dict)

### Step 7: Modify full_triage.py
- Use Rust for fast data collection
- Keep Python analyzers for correlation
- Merge both triage report formats

### Step 8: Init git repo
- `git init /opt/mem_forensics-mcp`
- Add all files, initial commit

---

## Verification

1. `cd /opt/mem_forensics-mcp && python -m mem_forensics_mcp.server` — starts without errors
2. Test Tier 1: `memory_analyze_image` → creates Rust session, returns DTB/profile
3. Test Tier 1: `memory_run_plugin(plugin="pslist")` → fast Rust response
4. Test Tier 1: `memory_run_plugin(plugin="search", params={...})` → Rust-only search
5. Test Tier 2: `memory_hunt_process_anomalies` → Rust pslist + Python analysis
6. Test Tier 2: `vt_lookup_hash` → Python VT client
7. Test Tier 3: `memory_run_plugin(plugin="filescan")` → Vol3 fallback
8. Test Tier 2+1: `memory_full_triage` → Rust data + Python correlation
9. All test dumps should produce comparable results to both original servers
