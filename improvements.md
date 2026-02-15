# mem-forensics-mcp Improvements

Feedback from MemLabs Lab 4 (Obsession), Lab 2 (A New World), and Lab 6 (The Reckoning) investigation sessions.

## Architecture Context

The server uses a three-tier engine:
```
Tier 1: Rust (memoxide)  — fast native plugins (pslist, psscan, malfind, netscan, cmdscan, search, readraw)
Tier 2: Python analyzers — smart correlation (credential_extractor, process_dumper, c2_finder, etc.)
Tier 3: Vol3 wrapper     — memory_run_plugin() with plugin normalization + CLI fallback
```

**Key design principle**: When a higher tier fails, the LLM should fall back to lower tiers. `memory_run_plugin` (Tier 3) is the universal escape hatch — it can run any Vol3 plugin with CLI fallback mode.

## Critical Gaps

### 1. Tier 2 analyzers don't fall back to Tier 3

**Root cause**: Tier 2 Python analyzers (e.g. `credential_extractor.py`) call `session.run_plugin()` directly, bypassing the more robust `memory_run_plugin` path which has:
- Plugin name normalization (`_normalize_plugin_name`)
- CLI fallback mode (`_run_via_cli`) when the Vol3 library API fails
- Better error handling and result formatting

**Example — `memory_extract_credentials`**:
- Internally calls `session.run_plugin("windows.hashdump.Hashdump")` (raw Vol3 library API)
- All three sub-plugins fail: hashdump, lsadump, cachedump → "Plugin not found"
- No attempt to use the CLI fallback path that `memory_run_plugin` provides
- The LLM should be guided to try `memory_run_plugin(plugin="hashdump")` directly when the Tier 2 tool fails

**Fix options**:
- A) Make Tier 2 analyzers route through the same plugin runner that `memory_run_plugin` uses (gets CLI fallback for free)
- B) Add explicit Tier 3 fallback guidance in tool error responses: `"Try: memory_run_plugin(plugin='hashdump')"`
- C) Document the fallback pattern in CLAUDE.md so the LLM knows to try Tier 3 manually

### 2. `dumpfiles` broken — error wrapping is misleading
`windows.dumpfiles.DumpFiles` IS listed in `memory_list_plugins` output (verified) and IS found by the normalizer (`class_mappings` has `"dumpfiles": "DumpFiles"`). But it **crashes at runtime** with a "seek" error. The ValueError handler wraps this as `"Plugin not found"` which is wrong — the plugin was found, it failed during execution.
- Actual error: `{"error": "Plugin not found: windows.dumpfiles.DumpFiles", "detail": "seek"}` — misleading
- Reproduced across all three test dumps (Labs 2, 4, 6) — consistent failure
- CLI fallback (`vol.py -f dump.raw windows.dumpfiles.DumpFiles`) may work — needs testing
- **Bug**: the ValueError catch in `plugin_runner.py:186-191` conflates "plugin not found" with "plugin execution failed"

### 3. No MFT scanning — also a normalizer gap
`windows.mftscan.MFTScan` isn't in the Vol3 plugin list (verified via `memory_list_plugins`). Additionally, `mftscan` is NOT in the `_normalize_plugin_name` `class_mappings` dict, so the normalizer generates `windows.mftscan.Mftscan` (wrong case — should be `MFTScan`). Even if the plugin were installed, the wrong case would prevent finding it.
- For deleted file recovery, consider adding to Rust tier:
  - Scan for MFT entries (`FILE0` signatures) in physical memory
  - Parse `$FILE_NAME` and resident `$DATA` attributes
  - Flag deleted entries (allocation flag = 0x00)

### 4. `memory_dump_process` — dual failure modes
- **Lab 4**: PID 2432 (StikyNot.exe) → `regions_sampled: 0`, DLL info only, no actual memory content
- **Lab 2**: PID 3008 (KeePass.exe) → type validation bug: `"'3008' is not of type 'integer'"` (MCP transport coerces int to string)
- Code intentionally skips dumpfiles/memmap (comment: "too memory-intensive on large dumps (4GB+) and can crash the system") and returns metadata only
- The `note` field says `"Use windows.dumpfiles plugin via memory_run_plugin"` — which is itself broken (issue #2)
- Should instead suggest `memory_run_plugin(plugin="memmap", pid=<PID>)` or `memory_run_plugin(plugin="vadinfo", pid=<PID>)` as working Tier 3 alternatives

### 5. No file carving capability
`filescan` finds files with physical offsets. `search` finds file headers (e.g. PNG `89504e470d0a1a0a`). But no tool can **extract/carve** a file given its offset.
- `readraw` works for small contiguous reads but can't reconstruct multi-page scattered files
- A Rust-tier file carver that uses page table translation would close this gap

## Usability Issues

### 6. `search` plugin error messages are unhelpful
When passed `extra_args: "--pattern inctf{"`, it just said `'pattern' parameter is required`. Should say: `"Use params dict: {"pattern": "...", "encoding": "ascii|utf16le|hex"}"`.

### 7. Search result limit defaults and response truncation
Verified from Rust source (`tools.rs:460-465`): default `limit=20`, default `context=64` bytes per side.
- `max_results` parameter name is silently ignored — only `limit` works (no `max_results` in Python or Rust code)
- `context` parameter IS supported but undocumented to the LLM — `params.context` controls bytes of surrounding data per match
- Python-side `truncate_response` (MAX_RESPONSE_SIZE=40000 chars) progressively truncates result LISTS to 500→200→100→50→20 items to fit under 40KB. This is what causes "Showing 50 of 100" — it's response-level truncation, not search-level
- Default limit of 20 is too low for carving or broad searches

### 8. `memory_dump_vad` requires `vad_address`
Should support dumping all VADs for a PID. Current workflow (vadinfo → pick address → dump) is cumbersome.

### 9. Tier 2 tool errors don't guide LLM to Tier 3
When a Tier 2 tool fails, the error response should include actionable fallback suggestions, e.g.:
- `memory_extract_credentials` fails → suggest `memory_run_plugin(plugin="hashdump")`
- `memory_dump_process` fails → suggest `memory_run_plugin(plugin="memmap", pid=X)` or `memory_dump_vad`
- This enables the LLM to self-recover without the user needing to understand the internals

### 10. Plugin name format undocumented — LLM doesn't know how to address each tier

Each tier uses a different naming convention, but this isn't documented anywhere the LLM can see:

| Tier | Format | Example |
|------|--------|---------|
| 1 (Rust) | short name | `pslist`, `search`, `readraw` |
| 2 (Python) | high-level tool name | `process_anomalies`, `credential_extractor` |
| 3 (Vol3) | full dotted path, case-sensitive | `windows.mftscan.MFTScan` |

**Fix**: Add this to the `memory_run_plugin` tool description and to CLAUDE.md so the LLM knows:
- Short names route to Tier 1/2 automatically
- Vol3 plugins require full `windows.category.PluginName` format
- If a short name fails, retry with the full Vol3 path

### 11. "Plugin not found" error is misleading — suggests `memory_list_plugins` but doesn't help resolve the name

When `memory_run_plugin` fails with "Plugin not found", the error says:
```
"hint": "Use memory_list_plugins to see available plugins"
```

Problems:
- Forces an extra round-trip — the LLM must call `memory_list_plugins`, scan a large list, then retry
- Doesn't suggest the likely correct Vol3 full name (e.g. `mftscan` → `windows.mftscan.MFTScan`)
- `memory_list_plugins` **does** list Vol3 plugins (verified: it introspects `volatility3.plugins.windows.*` via `pkgutil.iter_modules`), but the LLM has no way to fuzzy-search it

**Fix options** (in order of preference):
- A) **Fuzzy match in `_normalize_plugin_name`** — extend the existing normalizer to search the Vol3 plugin list when short names fail. e.g. `mftscan` → auto-resolve to `windows.mftscan.MFTScan`. Eliminates the problem entirely with zero extra LLM round-trips.
- B) **Include nearby matches in the error** — when plugin not found, fuzzy-match against the known list and include suggestions: `"Did you mean: windows.mftscan.MFTScan?"`. One round-trip instead of two.
- C) **Add `memory_find_plugin(query="mft")`** — dedicated fuzzy search tool. Works but adds a new tool when fixing the existing path (A or B) would be cleaner.

## What Worked Well

- **`readraw`** — Essential escape hatch for reading raw bytes at physical offsets. Workaround for search truncation — can recover full strings that `search` context clips at ~50 chars.
- **`filter` on `memory_run_plugin`** — Server-side filtering on filescan/handles/envars avoids result truncation. Effective for narrowing large result sets before they hit display limits.
- **Rust-tier `search`** — Fast full-dump string search with multi-encoding (ascii, utf16le, hex). MVP tool across all three labs — handles browser history, conversation data, URLs, encoded data reliably.
- **`memory_full_triage`** — Good starting overview. Correctly identified key processes and threat indicators in all three labs.
- **`cmdline` via Rust** — Critical for user activity reconstruction. Shows what files each process had open.
- **`envars` via Vol3 with filter** — Useful for finding hidden data in environment variables.
- **Tier 1→3 fallback in `memory_run_plugin`** — When Rust plugins fail for shared plugins, the automatic Vol3 fallback works transparently.
- **Tier 1 tools handle discovery-heavy investigations end-to-end** — Lab 6 (browser forensics, chat history, email) was fully solvable with just Rust search + readraw + cmdline + filescan. Tier 2 failures only surface when credential extraction or process dumping is needed.

## Feature Suggestions

| Priority | Feature | Why |
|----------|---------|-----|
| **Critical** | Tier 2→3 fallback (route analyzers through plugin runner) | Credential extraction, process dumping all fail without CLI fallback path |
| **Critical** | Fix dumpfiles (test CLI fallback path) | File extraction blocked investigations in all three labs |
| **Critical** | Fix `memory_dump_process` PID type bug | MCP transport int→string coercion breaks the call entirely |
| High | Add fallback guidance to Tier 2 error responses | LLM can self-recover if told what Tier 3 call to try |
| High | Rust-tier MFT scanner | Deleted file recovery is bread-and-butter forensics |
| High | Rust-tier file carver | Given filescan offset, reconstruct file from memory pages |
| High | Fuzzy plugin name resolution in `_normalize_plugin_name` | `mftscan` should auto-resolve to `windows.mftscan.MFTScan` — eliminates extra LLM round-trips |
| High | Document plugin naming per tier in tool description + CLAUDE.md | LLM doesn't know Vol3 needs `windows.category.PluginName` format |
| Medium | Process memory strings | Extract printable strings from a PID's address space |
| Medium | Fix search display truncation | Results above 50 are silently dropped |
| Medium | Raise default search limit | Default 20 is too low; `max_results` param silently ignored |
| Medium | Include fuzzy matches in "Plugin not found" errors | Suggest `windows.mftscan.MFTScan` instead of just "use memory_list_plugins" |
| Low | Better error messages | Show expected param format on validation errors |

## Summary

The architecture is sound — the three-tier design (Rust → Python → Vol3) is the right approach. The problem is that **the tiers are too isolated**:

1. **Tier 2 analyzers bypass the robust Tier 3 path** — they call `session.run_plugin()` directly instead of routing through the plugin runner that has CLI fallback
2. **Error responses don't guide the LLM downward** — when a higher tier fails, the LLM has no indication that a lower tier might work
3. **The only working extraction method is `readraw`** — every other extraction path (dumpfiles, dump_process, credentials) fails at some level

The tools excel at **discovery** (finding processes, files, strings, command lines, env vars). The gap is **extraction** — getting actual bytes/files/credentials out of memory. Closing the Tier 2→3 fallback gap would likely fix several issues at once, since the CLI fallback in `memory_run_plugin` may succeed where the library API fails.

Lab 6 confirmed that discovery-only investigations work well — Tier 1 Rust tools (search, readraw, cmdline, filescan) handled the entire evidence chain without hitting Tier 2 failures. The extraction gap (dumpfiles, file carving) remains the consistent blocker across all three labs.

## Verification Results

### Lab 4 — MemLabs Obsession (`MemoryDump_Lab4.raw`)

| # | Claim | Status | Test Detail |
|---|-------|--------|-------------|
| 1 | `dumpfiles` broken | **Confirmed** | `memory_run_plugin(plugin="dumpfiles")` → "Plugin not found", detail: "seek" |
| 2 | No MFT scanning | **Confirmed** | `memory_run_plugin(plugin="windows.mftscan.MFTScan")` → "Plugin not found" |
| 3 | `memory_dump_process` empty | **Confirmed** | PID 2432 → `regions_sampled: 0`, DLL info only |
| 4 | Search error unhelpful | **Confirmed** | `extra_args: "--pattern FILE0"` → `'pattern' parameter is required` |
| 5 | Search limit behavior | **Corrected** | `limit` works in `params` dict. `max_results` silently ignored. Display truncates at 50. |
| 6 | `dump_vad` requires address | **Confirmed** | Schema requires `vad_address`, no dump-all option |

### Lab 2 — A New World (`MemoryDump_Lab2.raw`)

| # | Claim | Status | Test Detail |
|---|-------|--------|-------------|
| 1 | `dumpfiles` broken | **Confirmed** | Same "seek" error — reproducible across dumps |
| 2 | Credential extraction fails | **Confirmed** | `memory_extract_credentials` → hashdump, lsadump, cachedump all "Plugin not found" |
| 3 | `memory_dump_process` type bug | **Confirmed** | `pid: 3008` → `"'3008' is not of type 'integer'"` — tried twice |
| 4 | No file carving | **Confirmed** | Found Password.png (offset 1070472304) and Hidden.kdbx (offset 1068569248) via filescan — no extraction path |
| 5 | Tier 2→3 fallback missing | **Confirmed** | `memory_extract_credentials` fails, doesn't suggest `memory_run_plugin(plugin="hashdump")` |

### Lab 6 — The Reckoning (`MemoryDump_Lab6.raw`)

| # | Claim | Status | Test Detail |
|---|-------|--------|-------------|
| 1 | Search result truncation | **Corrected** | Context is 64 bytes/side (not "~50 chars"). The key was actually visible in context_ascii. Earlier session truncation was likely from Python-side `truncate_response` cutting the results list, not per-match context. `readraw` was used as workaround for result list truncation. |
| 2 | `dumpfiles` broken | **Confirmed** | `flag.rar` and `flag.zip` found via `filescan` with offsets — no extraction path available |
| 3 | No file carving | **Confirmed** | RAR headers found via hex search (`526172211a0700`) — cannot reconstruct files from memory pages |
| 4 | Tier 1 tools sufficient for discovery | **Confirmed** | Entire investigation (browser history, Hangouts data, email, URLs, encryption keys) handled by Rust `search` + `readraw` + `cmdline` + `filescan` without needing Tier 2 |
| 5 | Tier 2→3 fallback gap | **Not triggered** | Investigation didn't require credential extraction or process dumping |
| 6 | `memory_dump_process` bugs | **Not triggered** | Not needed for this investigation |
