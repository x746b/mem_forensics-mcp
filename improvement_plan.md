# mem-forensics-mcp Improvement Plan

Based on verified findings from `improvements.md` — tested against MemLabs Labs 2, 4, and 6.

---

## Phase 1: Fix Error Handling (Low Risk, High Impact)

These changes fix misleading errors and type bugs without altering core logic.

### 1.1 Fix ValueError catch conflating "not found" with "execution failed"

**File**: `mem_forensics_mcp/core/plugin_runner.py:186-197`

**Problem**: The `ValueError` handler wraps ALL ValueErrors as `"Plugin not found"`. When `dumpfiles` crashes with a "seek" ValueError during execution, it's reported as "not found" even though the plugin was found and started running.

**Change**: Catch `ValueError` only from `session.run_plugin()` resolution, not from plugin execution. Or better — let the existing `Exception` handler (line 192) catch execution-phase errors with a truthful message.

```python
# Current (broken):
except ValueError as e:
    return {
        "error": f"Plugin not found: {plugin_name}",
        "detail": str(e),
        "hint": "Use memory_list_plugins to see available plugins",
    }

# Fixed — try library API, fall back to CLI on ANY failure:
except Exception as e:
    logger.info(f"Library API failed for {plugin_name}: {e}, trying CLI fallback")
    cli_result = _run_via_cli(image_path, plugin_name, pid, dump_dir, session, vol3_kwargs)
    if "error" not in cli_result:
        return cli_result
    # Both paths failed — return informative error
    return {
        "error": f"Plugin failed: {plugin_name}",
        "detail": str(e),
        "hint": "Library API and CLI fallback both failed",
        "cli_error": cli_result.get("error"),
    }
```

This also fixes **dumpfiles** (issue #2) — if the library API crashes with "seek", the CLI fallback gets a chance to run `vol.py -f dump.raw windows.dumpfiles.DumpFiles`.

**Verification**: Run `memory_run_plugin(plugin="dumpfiles")` against any test dump. Should attempt CLI fallback instead of returning "Plugin not found".

### 1.2 Fix `memory_dump_process` PID type coercion bug

**File**: `mem_forensics_mcp/server.py:364`

**Problem**: MCP transport coerces integer arguments to strings. Schema says `"type": "integer"` but `pid: 3008` arrives as `"3008"` → validation error `"'3008' is not of type 'integer'"`.

**Change**: Accept both types in schema or coerce in the handler:

```python
# In the handler, before calling dump_process:
pid = arguments["pid"]
if isinstance(pid, str):
    pid = int(pid)
```

Apply the same fix to `memory_dump_vad` (line 378) and any other tool with integer PID parameters.

**Verification**: `memory_dump_process(image_path=..., pid=3008)` should no longer error with type mismatch.

### 1.3 Fix `memory_dump_process` note pointing to broken dumpfiles

**File**: `mem_forensics_mcp/extractors/process_dumper.py:130`

**Change**:
```python
# Current:
"note": "Use windows.dumpfiles plugin via memory_run_plugin for actual file extraction",

# Fixed:
"note": "Use memory_run_plugin(plugin='memmap', pid=<PID>) or memory_dump_vad for memory content extraction",
```

### 1.4 Add fallback guidance to Tier 2 error responses

**File**: `mem_forensics_mcp/analyzers/credential_extractor.py:109-111`

When all three credential plugins fail, the returned `errors` list should include actionable fallback:

```python
if not credentials and errors:
    return {
        ...
        "fallback_hint": "All credential plugins failed via library API. Try: memory_run_plugin(plugin='hashdump'), memory_run_plugin(plugin='lsadump'), memory_run_plugin(plugin='cachedump') — these use CLI fallback which may succeed.",
    }
```

Same pattern for `process_dumper.py` when regions_sampled is 0.

---

## Phase 2: Improve Plugin Name Resolution (Medium Risk, High Impact)

These changes extend `_normalize_plugin_name` to eliminate LLM round-trips.

### 2.1 Dynamic plugin name resolution via Vol3 introspection

**File**: `mem_forensics_mcp/core/plugin_runner.py:248-314`

**Problem**: `_normalize_plugin_name` uses a hardcoded `class_mappings` dict with 26 entries. Plugins not in the dict (like `mftscan`) get `.capitalize()` which generates wrong case (`Mftscan` instead of `MFTScan`).

**Change**: When the static mapping fails, dynamically resolve by introspecting the actual Vol3 plugin list:

```python
def _normalize_plugin_name(plugin: str, os_type: Optional[str]) -> str:
    parts = plugin.split(".")

    # Already full format (3 parts)
    if len(parts) == 3:
        return plugin

    # Has module.Class format (2 parts), add OS prefix
    if len(parts) == 2:
        return f"{os_type}.{plugin}" if os_type else plugin

    # Single name — try static mapping first, then dynamic resolution
    module_name = parts[0].lower()

    # Static mappings (fast path)
    class_mappings = { ... }  # existing dict

    if module_name in class_mappings:
        class_name = class_mappings[module_name]
    else:
        # Dynamic resolution: introspect Vol3 for the real class name
        class_name = _resolve_plugin_class(module_name, os_type)

    if os_type:
        return f"{os_type}.{module_name}.{class_name}"
    return f"{module_name}.{class_name}"


def _resolve_plugin_class(module_name: str, os_type: Optional[str]) -> str:
    """Resolve plugin class name by introspecting Vol3 modules."""
    if not os_type:
        return module_name.capitalize()

    try:
        import importlib
        mod = importlib.import_module(f"volatility3.plugins.{os_type}.{module_name}")
        for name in dir(mod):
            obj = getattr(mod, name)
            if (isinstance(obj, type)
                and hasattr(obj, 'run')
                and hasattr(obj, '_required_framework_version')):
                return name  # Return the actual class name with correct casing
    except (ImportError, Exception):
        pass

    return module_name.capitalize()  # Last resort fallback
```

This fixes `mftscan` → `windows.mftscan.MFTScan` automatically, and handles any future Vol3 plugins without needing to update the static dict.

### 2.2 Include fuzzy suggestions in "Plugin not found" errors

**File**: `mem_forensics_mcp/core/plugin_runner.py:186-191` (after Phase 1 changes)

When both library API and CLI fallback fail, include fuzzy-matched suggestions from the known plugin list:

```python
def _suggest_plugins(query: str, os_type: Optional[str]) -> list[str]:
    """Find plugins whose names contain the query substring."""
    if not os_type:
        return []
    try:
        result = list_available_plugins_flat(os_type)  # helper that returns flat list
        return [p for p in result if query.lower() in p.lower()][:5]
    except Exception:
        return []
```

Include in error response:
```python
"suggestions": _suggest_plugins(plugin, session.os_type)
```

---

## Phase 3: Improve Tool Descriptions & Documentation (Zero Risk)

### 3.1 Update `memory_run_plugin` tool description

**File**: `mem_forensics_mcp/server.py:330`

**Current**:
```
"Run a forensics plugin. Supported Rust plugins (fast): pslist, psscan, ..."
```

**Proposed**:
```
"Run a forensics plugin. Tier 1 (Rust, fast): pslist, psscan, cmdline, dlllist, malfind, netscan, cmdscan, search, readraw, rsds — use short names. Tier 3 (Vol3): any other plugin — short names auto-resolve (e.g. 'filescan', 'handles', 'envars'). For Vol3 plugins not in the auto-resolver, use full path: 'windows.category.PluginName'. Use 'filter' param to grep results server-side (avoids truncation). For search: use params={\"pattern\": \"text\", \"encoding\": \"ascii|utf16le|hex\", \"limit\": N, \"context\": N}."
```

### 3.2 Update `CLAUDE.md` with tier addressing and fallback guidance

**File**: `CLAUDE.md`

Add section:

```markdown
## Plugin Naming

| Tier | How to call | Example |
|------|-------------|---------|
| 1 (Rust) | Short name | `memory_run_plugin(plugin="pslist")` |
| 3 (Vol3) | Short name (auto-resolved) | `memory_run_plugin(plugin="filescan")` |
| 3 (Vol3) | Full path (when auto-resolve fails) | `memory_run_plugin(plugin="windows.mftscan.MFTScan")` |

## Fallback Strategy

If a Tier 2 analyzer fails (e.g. `memory_extract_credentials`), try the underlying Vol3 plugin directly:
- Credentials: `memory_run_plugin(plugin="hashdump")`, `memory_run_plugin(plugin="lsadump")`
- Process dump: `memory_run_plugin(plugin="memmap", pid=X)`, `memory_dump_vad`
- File extraction: `memory_run_plugin(plugin="dumpfiles", pid=X)`

## Search Parameters

`memory_run_plugin(plugin="search", params={...})`
- `pattern` (required): search string
- `encoding`: `ascii` (default), `utf16le`, `hex`
- `limit`: max results (default 20, raise for broad searches)
- `context`: bytes of surrounding data per match (default 64)
```

### 3.3 Fix `search` error message for wrong parameter format

**File**: Rust source `engines/memoxide-src/crates/memoxide/src/server/tools.rs`

When `pattern` is missing from `params`, return:
```
"'pattern' is required in params dict. Usage: params={\"pattern\": \"text\", \"encoding\": \"ascii|utf16le|hex\", \"limit\": 100, \"context\": 64}. Do NOT use extra_args."
```

---

## Phase 4: Tier 2 → Tier 3 Routing (Medium Risk, High Impact)

### 4.1 Route Tier 2 analyzers through plugin_runner

**Files**:
- `mem_forensics_mcp/analyzers/credential_extractor.py` (lines 86, 116, 159)
- Other analyzers that call `session.run_plugin()` directly

**Problem**: Tier 2 analyzers call `session.run_plugin()` (raw Vol3 library API) instead of routing through `plugin_runner.run_plugin()` which has CLI fallback.

**Change**: Replace direct `session.run_plugin()` calls with `plugin_runner.run_plugin()`:

```python
# Current:
hashdump_results = session.run_plugin("windows.hashdump.Hashdump")

# Fixed:
from ..core.plugin_runner import run_plugin
result = run_plugin(image_path, "hashdump")
hashdump_results = result.get("results", [])
```

This gives credential extraction the CLI fallback path for free. The `run_plugin` function handles:
- Plugin name normalization
- Library API attempt
- CLI fallback on failure
- Proper error messages

**Risk**: The result format from `plugin_runner.run_plugin()` wraps results in a dict with `"results"` key, while `session.run_plugin()` returns a generator directly. Each caller needs to unwrap correctly.

**Verification**: Run `memory_extract_credentials` — should attempt CLI fallback when library API fails for hashdump/lsadump/cachedump.

---

## Phase 5: Raise Search Defaults (Low Risk)

### 5.1 Raise default search limit

**File**: `engines/memoxide-src/crates/memoxide/src/server/tools.rs:460-465`

**Change**: Default `limit` from 20 → 100.

### 5.2 Document `context` parameter

Already addressed in Phase 3.1 tool description update.

### 5.3 Alias `max_results` → `limit`

**File**: `engines/memoxide-src/crates/memoxide/src/server/tools.rs`

Accept both `params.limit` and `params.max_results`, with `limit` taking precedence:

```rust
let limit = params.limit
    .or(params.max_results)
    .unwrap_or(100);
```

---

## Phase 6: New Capabilities (Higher Effort)

### 6.1 Rust-tier MFT scanner

Scan physical memory for MFT entries (`FILE0` magic at aligned offsets), parse `$FILE_NAME` attribute, flag deleted entries. This enables deleted file recovery without Vol3's `mftscan` plugin.

### 6.2 Rust-tier file carver

Given a physical offset (from `filescan` or `search`), read file data with page table translation. Handles scattered pages that `readraw` can't reassemble.

### 6.3 `memory_dump_vad` bulk mode

Make `vad_address` optional. When omitted, dump all executable/private VADs for the given PID.

### 6.4 Process memory strings extraction

New tool or enhancement to `memory_dump_process`: extract printable ASCII/UTF-16 strings from a process's virtual address space (via VAD walk + readraw).

---

## Phase 7: Fix Rust Engine Starvation (Critical, Found During Testing)

### 7.1 Wrap all blocking Vol3 calls with `asyncio.to_thread()`

**File**: `mem_forensics_mcp/server.py` — all tool handlers

**Problem**: All Vol3/Tier 2/3 function calls (`vol3_run_plugin`, `extract_credentials`, `dump_process`, `hunt_process_anomalies`, etc.) ran **synchronously** inside async MCP handlers. When CLI fallback triggered (e.g. `dumpfiles` via `subprocess.run(..., timeout=300)`), the asyncio event loop was blocked for the entire subprocess duration. During the block, the memoxide `_read_responses` coroutine couldn't drain the Rust process's stdout pipe. The pipe buffer fills (64KB on Linux), memoxide blocks on write, and `is_available()` returns False — killing all Rust-tier plugins (`search`, `readraw`, `pslist`, etc.) for the rest of the session.

**Symptom**: After running `dumpfiles` (CLI fallback), `search` fails with `"Plugin 'search' requires the Rust engine (memoxide) which is not available"`, even though `memory_list_sessions` shows `rust_initialized: true`. Shared plugins like `pslist` silently fall through to Vol3 (slower).

**Fix**: Wrap every blocking call with `asyncio.to_thread()` so Vol3 work runs in a thread pool while the event loop stays alive to service the memoxide reader:

```python
# Before (blocks event loop):
result = vol3_run_plugin(image_path=image_path, plugin=plugin, ...)

# After (runs in thread, event loop stays free):
result = await asyncio.to_thread(vol3_run_plugin, image_path=image_path, plugin=plugin, ...)
```

**Affected calls** (all wrapped):
- `vol3_run_plugin` (Tier 3 fallback in `memory_run_plugin`)
- `analyze_image_profile` (Vol3 fallback in `memory_analyze_image`)
- `list_available_plugins` (in `memory_list_plugins`)
- `hunt_process_anomalies`, `get_process_tree`, `find_injected_code`
- `find_c2_connections`, `get_command_history`, `extract_credentials`
- `dump_process`, `dump_vad`, `list_dumpable_files`
- `full_triage` (Vol3 fallback in `_run_full_triage`)
- `extract_credentials` (enrichment call in `_run_full_triage`)

**Verification**: Run `dumpfiles` (triggers CLI fallback), then immediately run `search` — Rust engine should still be alive and responsive.

---

## Implementation Order

| Order | Phase | Items | Status | Effort | Impact |
|-------|-------|-------|--------|--------|--------|
| 1 | 1.1 | CLI fallback on all plugin failures | **DONE** | ~30 min | Fixes dumpfiles + future plugin crashes |
| 2 | 1.2 | PID type coercion fix | **DONE** | ~10 min | Fixes dump_process type bug |
| 3 | 1.3 | Fix note text | **DONE** | ~5 min | Stops pointing to broken tool |
| 4 | 1.4 | Fallback hints in Tier 2 errors | **DONE** | ~20 min | LLM self-recovery |
| 5 | 3.1–3.2 | Tool descriptions + CLAUDE.md | **DONE** | ~20 min | Zero-risk, immediate LLM improvement |
| 6 | 2.1 | Dynamic plugin resolution | **DONE** | ~30 min | Eliminates normalizer gaps |
| 7 | 2.2 | Fuzzy suggestions in errors | **DONE** | ~20 min | Better error recovery |
| 8 | 5.1–5.3 | Search defaults + alias | **DONE** | ~15 min | Better search UX |
| 9 | 4.1 | Tier 2 → plugin_runner routing | **DONE** | ~1 hr | Core architecture fix |
| 10 | 3.3 | Search error message (Rust) | **DONE** | ~15 min | Better error UX |
| 11 | 7.1 | asyncio.to_thread for all Vol3 calls | **DONE** | ~30 min | Prevents Rust engine starvation |
| 12 | 6.x | New capabilities | Planned | Days | New forensics capabilities |

## Expected Outcomes

After Phases 1–3 (quick wins):
- `dumpfiles` works via CLI fallback (or gives truthful error)
- `memory_dump_process` PID accepts string/int
- LLM knows how to address each tier and fall back manually
- Search params documented, limit raised

After Phases 4–5:
- Tier 2 analyzers (credentials, process dump) get CLI fallback automatically
- Search UX improved with sensible defaults

After Phase 6:
- MFT scanning and file carving fill the extraction gap
- VAD bulk dump simplifies process investigation
