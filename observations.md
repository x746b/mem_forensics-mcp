# MCP Observations — Lab 4 Retest (Post-Improvements)

## What Improved

### 1. Credentials now work (Phase 4 fix confirmed)
- `memory_full_triage` → `memory_extract_credentials` successfully extracted 4 credentials:
  - 2 NTLM hashes (eminem, SlimShady) via hashdump
  - 1 AutoLogon password via lsadump
  - 1 DPAPI key via lsadump
- **Before**: All 3 sub-plugins failed with "Plugin not found", no CLI fallback
- **After**: Routing through `plugin_runner_run` gives CLI fallback — hashdump and lsadump now succeed

### 2. dumpfiles works via CLI fallback (Phase 1.1 fix confirmed)
- `memory_run_plugin(plugin="dumpfiles", pid=2432)` → **39 files extracted** including `StickyNotes.snt`
- `engine_mode: "vol3-cli"` — confirms CLI fallback path activated
- **Before**: Crashed with misleading `"Plugin not found: windows.dumpfiles.DumpFiles"` + `"detail": "seek"`
- **After**: Library API fails → CLI fallback runs → files extracted successfully

### 3. Updated tool description visible
- `memory_run_plugin` description now shows tier info, search params format, and Vol3 full-path guidance

## Issues Found & Fixed

### 4. Rust engine starvation after Vol3 CLI fallback (Phase 7 — FIXED)
- **Symptom**: After `dumpfiles` ran via CLI fallback, `search` plugin failed with `"requires Rust engine which is not available"`, `pslist` silently fell through to Vol3
- **Root cause**: All Vol3/Tier 2 calls ran synchronously in async handlers. `subprocess.run()` in CLI fallback blocked the event loop, starving the memoxide reader coroutine. Stdout pipe buffer filled → memoxide blocked on write → `is_available()` returned False
- **Fix**: Wrapped all blocking Vol3 calls with `asyncio.to_thread()` so they run in thread pool while event loop stays responsive
- **Retest result**: After fix, ran `dumpfiles` (CLI fallback) then immediately `search` and `pslist` — both returned `engine: "rust"`. Rust engine stays alive through the entire investigation.

### 5. StickyNotes.snt dump truncated at 4096 bytes
- `dumpfiles` extracted `StickyNotes.snt` but only 4096 bytes (1 page)
- The OLE Compound Document header is present and RTF content starts at offset 2496 but is cut off mid-header
- Sticky Notes content is multi-page — the remaining pages weren't reconstructed
- This is a Vol3 dumpfiles limitation, not an MCP bug per se

## Retest Verification (Post Phase 7 Fix)

| Test | Result | Engine |
|------|--------|--------|
| `memory_analyze_image` | Session created | rust (memoxide) |
| `dumpfiles --pid 2432` | 39 files extracted, StickyNotes.snt recovered | vol3-cli |
| `search "Important.txt"` (AFTER dumpfiles) | 5 matches found | **rust** |
| `pslist` (AFTER dumpfiles) | 41 processes | **rust** |

All three tiers coexist correctly — Vol3 CLI fallback no longer kills Rust sessions.

## Summary

All Phase 1–5 and Phase 7 improvements validated. The three-tier architecture now works as designed:
- **Tier 1 (Rust)**: Fast plugins stay alive throughout the session, even after Tier 3 CLI fallback
- **Tier 2 (Python)**: Credential extraction routes through plugin_runner, gets CLI fallback for free
- **Tier 3 (Vol3)**: CLI fallback activates when library API fails, runs in thread pool without blocking event loop
