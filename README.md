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

### Verify

```bash
uv run python -m mem_forensics_mcp.server
# Should start without errors (Ctrl+C to exit)
```

---

## Adding to Claude CLI

```bash
claude mcp add mem-forensics-mcp \
  --scope user \
  -- uv run --directory /opt/mem_forensics-mcp python -m mem_forensics_mcp.server
```

With external Volatility3:

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

## Related Projects

| Project | Focus |
|---------|-------|
| **winforensics-mcp** | Windows disk forensics - EVTX, Registry, MFT, Prefetch, YARA, PCAP |
| **mac_forensics-mcp** | macOS DFIR - Unified Logs, FSEvents, Spotlight, Plists |

---

## License

MIT License
