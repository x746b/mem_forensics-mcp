# mem-forensics-mcp

> **Unified Memory Forensics MCP Server** - Multi-tier engine combining Rust speed with Vol3 coverage.

---

## Architecture

Three-tier engine automatically routes each tool to the fastest backend:

```
LLM <-> [mem-forensics-mcp (Python)] <-> memoxide (Rust child, stdio MCP)
                                     <-> Volatility3 (Python library)
```

| Tier | Engine | Speed | Coverage |
|------|--------|-------|----------|
| **Tier 1** | Rust (memoxide) | Fast | pslist, psscan, cmdline, dlllist, malfind, netscan, cmdscan, search, readraw, rsds |
| **Tier 2** | Python analyzers | Medium | Process anomalies, C2 detection, credentials, YARA, VT integration |
| **Tier 3** | Volatility3 | Slower | Any vol3 plugin (filescan, handles, svcscan, driverscan, ...) |

---

## Installation

### Prerequisites

```bash
# Install uv (fast Python package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Ensure Python 3.10+
python3 --version
```

### Install

```bash
git clone https://github.com/x746b/mem_forensics-mcp.git
cd mem_forensics-mcp

# Full install (recommended)
uv sync --extra full

# Minimal (Vol3 only, no YARA/VT)
uv sync --extra volatility3
```

### Build Rust Engine (optional)

A prebuilt `aarch64-linux` binary ships in `engines/memoxide/`. To build for your platform:

```bash
# Requires Rust toolchain (https://rustup.rs)
cd engines/memoxide-src
cargo build --release

# Binary lands at engines/memoxide-src/target/release/memoxide
# The server auto-detects it (prefers local build over prebuilt)
```

### Configure Volatility3 (optional)

If Vol3 is installed at `/opt/volatility3` it's auto-detected. Otherwise set the env var:

```bash
# Point to repo root or site-packages directory
export VOLATILITY3_PATH="/path/to/volatility3"
```

### Verify

```bash
uv run python -m mem_forensics_mcp.server
# Should show: Rust engine: available, Volatility3: available
```

---

## Adding to Claude CLI

```bash
claude mcp add mem-forensics-mcp \
  --scope user \
  -- uv run --directory /opt/mem_forensics-mcp python -m mem_forensics_mcp.server
```

With custom Volatility3 path:

```bash
claude mcp add mem-forensics-mcp \
  --scope user \
  -e VOLATILITY3_PATH=/opt/volatility3 \
  -- uv run --directory /opt/mem_forensics-mcp python -m mem_forensics_mcp.server
```

---

## Quick Start

### 1. Initialize Memory Image

```
memory_analyze_image(image_path="/evidence/memory.raw")
```

### 2. Run Full Triage

```
memory_full_triage(image_path="/evidence/memory.raw")
```

### 3. Drill Down

```
memory_run_plugin(image_path="/evidence/memory.raw", plugin="malfind", pid=1234)
```

---

## Tool Reference

### Core

| Tool | Tier | Description |
|------|------|-------------|
| `memory_analyze_image` | 1->2 | Initialize image, auto-detect profile |
| `memory_run_plugin` | 1->3 | Run any plugin (Rust or Vol3) |
| `memory_list_plugins` | - | List available plugins |
| `memory_list_sessions` | - | List active sessions |
| `memory_get_status` | - | Show engine status |

### Analysis

| Tool | Tier | Description |
|------|------|-------------|
| `memory_full_triage` | 1+2 | Complete automated investigation |
| `memory_hunt_process_anomalies` | 2 | DKOM detection, parent-child validation |
| `memory_get_process_tree` | 2 | Process tree with suspicious highlighting |
| `memory_find_injected_code` | 1->2 | Code injection + YARA scanning |
| `memory_find_c2_connections` | 1+2 | Network C2 detection |
| `memory_get_command_history` | 1+2 | Command recovery + classification |
| `memory_extract_credentials` | 2 | Hash/secret extraction via Vol3 |

### Extraction

| Tool | Tier | Description |
|------|------|-------------|
| `memory_dump_process` | 2 | Process info and loaded DLLs |
| `memory_dump_vad` | 2 | Examine memory region details |
| `memory_list_dumpable_files` | 3 | List cached files |

### Threat Intelligence

| Tool | Description |
|------|-------------|
| `vt_lookup_hash` | VirusTotal hash lookup |
| `vt_lookup_ip` | VirusTotal IP reputation |
| `vt_lookup_domain` | VirusTotal domain reputation |
| `vt_lookup_file` | Hash file + VT lookup |

---

## Example: Full Triage Output

Running `memory_full_triage` on a Windows 10 memory dump (Win10 19041, x64, VMware):

```json
{
  "threat_level": "critical",
  "risk_score": 100,
  "summary": "Processes: 115 found. Process Anomalies: 4 info-level. Network: 4 flagged of 79 connections. Commands: 52 suspicious fragments. Injected Code: 12 RWX regions. Correlations: 2 critical.",
  "engine": "rust+python"
}
```

**Tier routing in action:**
- Rust (Tier 1) collected process list, psscan, cmdlines, netscan, malfind, cmdscan in ~2s
- Python (Tier 2) correlated findings: parent-child validation, C2 detection, injection analysis, risk scoring

**Key findings from the triage:**

| Category | Detail |
|----------|--------|
| Suspicious process | `mmc.exe` (PID 3120) launched from explorer.exe, loading `family_image.msc` from Edge downloads |
| Injected code | 4 RWX private memory regions in mmc.exe, 2 in EXCEL.EXE |
| Child process | `dllhost.exe` (PID 7736) spawned by mmc.exe with executable RWX region |
| Network | svchost.exe connections to external IPs on ports 443/80 |
| Correlations | `active_implant` + `active_c2_session` flagged as critical |
| IOCs | `40.113.110.67:443`, `104.81.141.145:80` |

**Drill-down with filtered filescan:**
```
memory_run_plugin(image_path="memory.raw", plugin="filescan", filter="notepad")
# Returns: 2 of 7612 results matched (server-side grep before truncation)
```

**Targeted file extraction with CLI fallback:**
```
memory_run_plugin(image_path="memory.raw", plugin="dumpfiles",
                  params={"virtaddr": [0xa7850eb98de0], "dump_dir": "/tmp/out"})
# Returns: 1 result — Notepad.lnk extracted to /tmp/out/
# (auto-routes to vol3 CLI for ListRequirement params)
```

---

## Why Multi-Tier? Real-World Testing Observations

Tested on several different memory dumps (Win7 SP1 through Win11, x64, both VirtualBox and VMware images).

### Tier 1 (Rust) — Speed Where It Matters

The Rust engine handles the plugins that get called most frequently during investigation. The `search` plugin is the standout:

- **Full-dump byte search** scans 500MB-1GB dumps in seconds, finding ASCII and UTF-16LE strings anywhere in physical memory
- A single `search` call can locate email content, browser JSON blobs, embedded URLs, and credential fragments buried deep in physical memory — data that would otherwise require chaining multiple Vol3 plugins (pslist, memdump, strings) to extract
- Process listing (`pslist`), command lines (`cmdline`), and network connections (`netscan`) return instantly, enabling rapid triage of 50-100+ process dumps

The speed advantage compounds during `full_triage`, where Tier 1 collects pslist + psscan + cmdline + netscan + malfind + cmdscan data in ~2s, compared to ~30s+ for Vol3 equivalents.

### Tier 2 (Python Analyzers) — Intelligence Layer

Raw plugin output is data. Tier 2 turns it into findings:

- **Process anomaly detection** cross-references pslist vs psscan (DKOM detection) and validates parent-child relationships against Windows rules — reduces 50+ processes to a handful of actionable anomalies
- **PID reuse handling** distinguishes terminated parent processes from truly suspicious orphans, eliminating false positives that plague naive parent-child checks
- **Full triage orchestrator** correlates across all data sources: processes with RWX regions + external network connections = "active implant" correlation. This multi-source correlation elevates raw data into risk scores and IOC lists
- **C2 detection** enriches netscan results with process context — svchost connecting to external IPs on unusual ports gets flagged, while the same connection from a browser does not

### Tier 3 (Vol3) — Coverage for Everything Else

Vol3 handles the long tail of forensic needs:

- `filescan` + `dumpfiles` for file extraction from memory cache (documents, archives, browser databases)
- `handles`, `svcscan`, `driverscan` for deep-dive investigation
- Server-side `filter` parameter greps results before returning — e.g. `filescan` with `filter="keyword"` returns matching entries from thousands of cached files
- CLI fallback for `ListRequirement` params (e.g., `dumpfiles` with `physaddr` lists) that Vol3's Python API mishandles

### Tier Routing Is Invisible

The key design principle: the LLM (or analyst) never needs to know which tier handles a request. `memory_run_plugin(plugin="pslist")` routes to Rust; `memory_run_plugin(plugin="filescan")` routes to Vol3. If Rust fails, Vol3 takes over. The routing is an implementation detail, not a user concern.

---

## Related Projects

| Project | Focus |
|---------|-------|
| **winforensics-mcp** | Windows disk forensics - EVTX, Registry, MFT, Prefetch, YARA, PCAP |
| **mac_forensics-mcp** | macOS DFIR - Unified Logs, FSEvents, Spotlight, Plists |

---

## License

MIT License
