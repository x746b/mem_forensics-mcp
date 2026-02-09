//! MCP tool definitions for the memoxide server.

use crate::analyzers::{full_triage, network_analyzer, process_anomalies};
use crate::memory::image::MemoryImage;
use crate::plugins::{cmdline, cmdscan, dlllist, malfind, memsearch, netscan, pslist, psscan};
use crate::profile::{detector, kdbg, kuser, rsds};
use crate::server::session::SessionStore;
use crate::server::types::*;
use rmcp::handler::server::{router::tool::ToolRouter, wrapper::Parameters};
use rmcp::model::*;
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};
use serde_json::json;
use tracing::info;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_WINDOWS_SYMBOLS_ROOT: &str = "symbols/windows";
const AUTO_PSSCAN_PROBE_BYTES: u64 = 256 * 1024 * 1024; // 256MB
const AUTO_RSDS_SCAN_BYTES: u64 = u64::MAX; // Scan entire image — RSDS scan is cheap (memchr 4-byte sig)

/// Available plugins.
const PLUGINS: &[(&str, &str, &str)] = &[
    ("pslist", "List processes by walking ActiveProcessLinks", "processes"),
    ("psscan", "Scan for processes by pool tag", "processes"),
    ("cmdline", "Extract process command lines from PEB", "processes"),
    ("dlllist", "List loaded DLLs per process from PEB", "processes"),
    ("malfind", "Find injected code (RWX regions)", "malware"),
    ("netscan", "Scan for network connections", "network"),
    ("cmdscan", "Scan for command history buffers", "commands"),
    ("search", "Search physical memory for byte patterns (ascii/utf16le/hex)", "memory"),
    ("readraw", "Read raw bytes at a physical offset (hex dump)", "memory"),
    ("rsds", "Scan for RSDS debug directory entries (PDB GUID) in kernel PE images", "profile"),
];

/// Default chunk size for physical memory scanning (16 MB).
const SCAN_CHUNK_SIZE: usize = 16 * 1024 * 1024;

/// Format a byte slice as a classic hex dump with offset markers and ASCII sidebar.
fn format_hex_dump(data: &[u8], base_offset: u64) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        let addr = base_offset + (i * 16) as u64;
        write!(out, "{:08x}  ", addr).unwrap();

        // Hex bytes
        for (j, byte) in chunk.iter().enumerate() {
            if j == 8 {
                out.push(' ');
            }
            write!(out, "{:02x} ", byte).unwrap();
        }
        // Pad if last line is short
        if chunk.len() < 16 {
            for j in chunk.len()..16 {
                if j == 8 {
                    out.push(' ');
                }
                out.push_str("   ");
            }
        }

        out.push(' ');
        out.push('|');
        for &b in chunk {
            if b.is_ascii_graphic() || b == b' ' {
                out.push(b as char);
            } else {
                out.push('.');
            }
        }
        out.push('|');
        out.push('\n');
    }
    out
}

fn netscan_offsets_best_effort(symbols: &isf::IsfSymbols) -> netscan::NetscanOffsets {
    if let Some(o) = netscan::NetscanOffsets::from_isf(symbols) {
        return o;
    }

    // If the loaded ISF isn't a netscan-specific file, the needed types may be missing.
    // Fall back using Windows build metadata when available.
    if let Some(win) = symbols.metadata.windows.as_ref() {
        if let Some(build) = win.build {
            // Win7 SP1 is 7601; treat <=7601 as "win7-ish" for offsets.
            if build <= 7601 && symbols.pointer_size == 8 {
                return netscan::NetscanOffsets::win7_x64();
            }
        }
    }

    // Default to the most common modern x64 layout used in tests.
    netscan::NetscanOffsets::win10_19041_x64()
}

/// The memoxide MCP server.
#[derive(Clone)]
pub struct MemoxideServer {
    sessions: SessionStore,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl MemoxideServer {
    pub fn new() -> Self {
        MemoxideServer {
            sessions: SessionStore::new(),
            tool_router: Self::tool_router(),
        }
    }

    /// Initialize a memory analysis session.
    #[tool(description = "Initialize a memory forensics analysis session by opening a memory dump file. Returns a session_id for subsequent analysis. Fields: image_path (path to .raw/.vmem/.dmp file), isf_path (optional ISF symbol file), dtb (optional Directory Table Base override), kernel_base (optional kernel base address for symbol relocation).")]
    async fn memory_analyze_image(
        &self,
        Parameters(req): Parameters<AnalyzeImageRequest>,
    ) -> Result<CallToolResult, McpError> {
        info!("Opening memory image: {}", req.image_path);

        let image = MemoryImage::open(&req.image_path).map_err(|e| {
            McpError::internal_error(format!("Failed to open image: {}", e), None)
        })?;

        let image_size = image.size();
        let session_id = self.sessions.create_session(req.image_path.clone(), image).await;

        // Load ISF symbols if provided, otherwise attempt auto-selection from local symbol store.
        if let Some(ref isf_path) = req.isf_path {
            match isf::parse_isf_file(isf_path) {
                Ok(symbols) => {
                    if let Some(session_lock) = self.sessions.get_session(&session_id).await {
                        let mut session = session_lock.write().await;
                        session.symbols = Some(std::sync::Arc::new(symbols));
                        session.profile = Some(isf_path.clone());
                    }
                    info!("Loaded ISF symbols from {}", isf_path);
                }
                Err(e) => info!("Warning: Failed to load ISF {}: {}", isf_path, e),
            }
        }

        // Set DTB and kernel_base if provided
        if let Some(session_lock) = self.sessions.get_session(&session_id).await {
            let mut session = session_lock.write().await;

            if let Some(dtb_val) = req.dtb {
                session.dtb = Some(dtb_val);
            }
            if let Some(kb) = req.kernel_base {
                session.kernel_base = Some(kb);
            }

            // Auto-detect KDBG (Win7/8 plaintext) if needed for kernel_base and/or profile selection.
            let mut best_kdbg = None;
            if session.kernel_base.is_none() || session.symbols.is_none() || session.ps_active_process_head.is_none() {
                match kdbg::scan_for_kdbg(&session.image) {
                    Ok(kdbgs) if !kdbgs.is_empty() => {
                        best_kdbg = Some(kdbgs[0].clone());
                        let best = best_kdbg.as_ref().unwrap();
                        if session.kernel_base.is_none() {
                            session.kernel_base = Some(best.kern_base);
                            info!(
                                "Auto-detected kernel base: {:#x} from KDBG at {:#x}",
                                best.kern_base, best.kdbg_address
                            );
                        }
                        if session.ps_active_process_head.is_none() {
                            session.ps_active_process_head = Some(best.ps_active_process_head);
                            info!(
                                "Auto-detected PsActiveProcessHead: {:#x}",
                                best.ps_active_process_head
                            );
                        }
                    }
                    Ok(_) => info!("No plaintext KDBG found (Win10+ KDBG may be encoded)"),
                    Err(e) => info!("KDBG scan failed: {}", e),
                }
            }

            // Auto-load kernel ISF if not provided and we have KDBG.SizeEProcess to match on.
            if session.symbols.is_none() {
                if let Some(k) = best_kdbg.as_ref() {
                    let root = std::path::Path::new(DEFAULT_WINDOWS_SYMBOLS_ROOT);
                    match detector::select_symbols_for_kdbg(root, k) {
                        Ok(Some(sel)) => {
                            session.profile = Some(sel.isf_path.clone());
                            session.symbols = Some(std::sync::Arc::new(sel.symbols));
                            info!("Auto-loaded ISF symbols from {}", sel.isf_path);
                        }
                        Ok(None) => info!(
                            "No matching ISF found under {} (need x64 kernel ISF with _EPROCESS size {}).",
                            DEFAULT_WINDOWS_SYMBOLS_ROOT,
                            k.size_eprocess
                        ),
                        Err(e) => info!("Auto ISF selection failed: {}", e),
                    }
                }
            }

            // RSDS-based ISF selection: scan for kernel PE debug directory entries.
            // This is the most reliable method for Win10+ where KDBG is encoded.
            // If a kernel GUID is found, we skip the psscan probe fallback (even if
            // download/conversion fails) since probing 3000+ ISFs won't help.
            let mut rsds_found_kernel_guid = false;
            if session.symbols.is_none() {
                let root = std::path::Path::new(DEFAULT_WINDOWS_SYMBOLS_ROOT);
                match detector::select_symbols_by_rsds(root, &session.image, AUTO_RSDS_SCAN_BYTES) {
                    Ok(result) => {
                        rsds_found_kernel_guid = result.kernel_guid_found;
                        if let Some(sel) = result.symbols {
                            session.profile = Some(sel.isf_path.clone());
                            session.symbols = Some(std::sync::Arc::new(sel.symbols));
                            info!("Auto-loaded ISF symbols from {} via RSDS GUID", sel.isf_path);
                        } else if result.kernel_guid_found {
                            info!("RSDS found kernel GUID but no matching ISF resolved (download/convert may have failed)");
                        } else {
                            info!("No matching ISF found via RSDS GUID lookup");
                        }
                    }
                    Err(e) => info!("RSDS-based ISF selection failed: {}", e),
                }
            }

            // Win10+ fallback: if KDBG is missing/encoded, try selecting an ISF by probing
            // psscan validity on a limited prefix of physical memory.
            // SKIP if RSDS found a kernel GUID — probing 3000+ ISFs won't help when we
            // know the exact GUID but couldn't resolve it.
            if session.symbols.is_none() && !rsds_found_kernel_guid {
                let root = std::path::Path::new(DEFAULT_WINDOWS_SYMBOLS_ROOT);
                match detector::select_symbols_by_psscan_probe(
                    root,
                    &session.image,
                    8, // x64 only for now
                    AUTO_PSSCAN_PROBE_BYTES,
                ) {
                    Ok(Some(sel)) => {
                        session.profile = Some(sel.isf_path.clone());
                        session.symbols = Some(std::sync::Arc::new(sel.symbols));
                        info!(
                            "Auto-loaded ISF symbols from {} via psscan probe",
                            sel.isf_path
                        );
                    }
                    Ok(None) => info!(
                        "Auto ISF selection via psscan probe failed (scanned first {} bytes).",
                        AUTO_PSSCAN_PROBE_BYTES
                    ),
                    Err(e) => info!("Auto ISF selection (psscan probe) failed: {}", e),
                }
            }

            // Auto-detect DTB from System process if not provided.
            // This requires symbols (to validate/parse EPROCESS via psscan).
            if session.dtb.is_none() && session.symbols.is_some() {
                let symbols = session.symbols.as_ref().unwrap().clone();
                match kdbg::find_system_dtb(&symbols, &session.image) {
                    Ok(Some(dtb)) => {
                        session.dtb = Some(dtb);
                        info!("Auto-detected DTB: {:#x}", dtb);
                    }
                    Ok(None) => {
                        // Fallback: direct System process scan.
                        // On Win11+ segment heap eliminates inline pool tags,
                        // so pool-tag-based psscan finds nothing. Scan for
                        // "System\0" in ImageFileName field instead.
                        info!("Pool tag scan found no System process. Trying direct scan...");
                        match psscan::find_system_dtb_direct(
                            &symbols,
                            &session.image,
                            SCAN_CHUNK_SIZE,
                        ) {
                            Ok(Some((dtb, _proc))) => {
                                session.dtb = Some(dtb);
                                info!("Auto-detected DTB via direct scan: {:#x}", dtb);
                            }
                            Ok(None) => info!("Could not auto-detect DTB (direct scan)"),
                            Err(e) => info!("Direct DTB scan failed: {}", e),
                        }
                    }
                    Err(e) => info!("DTB detection failed: {}", e),
                }
            }

            // Initialize virtual memory if DTB is available
            if session.dtb.is_some() {
                match session.init_virtual_memory() {
                    Ok(()) => info!("Virtual memory initialized with DTB {:#x}", session.dtb.unwrap()),
                    Err(e) => info!("Warning: Failed to init virtual memory: {}", e),
                }
            }

            // With a working VM, try to read Windows build + kernel base if still missing.
            // Clone the Arc to avoid borrow conflicts while mutating the session.
            let vm = session.virtual_memory.clone();
            if let Some(vm) = vm.as_ref() {
                if session.windows_build.is_none() {
                    if let Some(build) = kuser::read_nt_build_number(vm.as_ref()) {
                        session.windows_build = Some(build);
                        info!("Detected Windows build via KUSER_SHARED_DATA: {}", build);
                    }
                }

                if session.kernel_base.is_none() {
                    let sym_ref = session.symbols.as_deref();
                    if let Some(base) = detector::find_kernel_base_pe_scan(vm.as_ref(), sym_ref) {
                        session.kernel_base = Some(base);
                    }
                }
            }
        }

        // Build response with detected parameters
        let (dtb, kernel_base, has_vm, profile, windows_build) = if let Some(session_lock) = self.sessions.get_session(&session_id).await {
            let session = session_lock.read().await;
            (
                session.dtb,
                session.kernel_base,
                session.virtual_memory.is_some(),
                session.profile.clone(),
                session.windows_build,
            )
        } else {
            (None, None, false, None, None)
        };

        let response = json!({
            "session_id": session_id,
            "image_path": req.image_path,
            "image_size": image_size,
            "profile": profile,
            "dtb": dtb.map(|d| format!("{:#x}", d)),
            "kernel_base": kernel_base.map(|k| format!("{:#x}", k)),
            "windows_build": windows_build,
            "virtual_memory": has_vm,
            "status": "ready"
        });

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&response).unwrap(),
        )]))
    }

    /// List all active analysis sessions.
    #[tool(description = "List all active memory analysis sessions with their details (image path, size, profile, creation time).")]
    async fn memory_list_sessions(&self) -> Result<CallToolResult, McpError> {
        let sessions = self.sessions.list_sessions().await;
        let infos: Vec<SessionInfo> = sessions
            .into_iter()
            .map(|(id, path, size, profile, created)| SessionInfo {
                session_id: id,
                image_path: path,
                image_size: size,
                profile,
                created_at: created,
            })
            .collect();

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&infos).unwrap(),
        )]))
    }

    /// Get server status and capabilities.
    #[tool(description = "Get memoxide server status including version, active session count, and available analysis plugins.")]
    async fn memory_get_status(&self) -> Result<CallToolResult, McpError> {
        let status = ServerStatus {
            version: VERSION.to_string(),
            active_sessions: self.sessions.count().await,
            available_plugins: PLUGINS.iter().map(|(n, _, _)| n.to_string()).collect(),
            engine: "memoxide (pure Rust)".to_string(),
        };

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&status).unwrap(),
        )]))
    }

    /// List available analysis plugins.
    #[tool(description = "List all available memory forensics analysis plugins with descriptions and categories.")]
    async fn memory_list_plugins(&self) -> Result<CallToolResult, McpError> {
        let plugins: Vec<PluginInfo> = PLUGINS
            .iter()
            .map(|(name, desc, cat)| PluginInfo {
                name: name.to_string(),
                description: desc.to_string(),
                category: cat.to_string(),
            })
            .collect();

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&plugins).unwrap(),
        )]))
    }

    /// Run a specific analysis plugin.
    #[tool(description = "Run a memory forensics plugin on an active session. Fields: session_id, plugin (pslist/psscan/cmdline/dlllist/malfind/netscan/cmdscan/search/readraw/rsds), params (optional JSON, e.g. {\"pid\": [1234]} to filter by PID).\n\nFor 'search': params={\"pattern\": \"text\", \"encoding\": \"ascii|utf16le|hex\", \"context\": 64, \"limit\": 20}.\nFor 'readraw': params={\"offset\": 12345, \"length\": 256}. Offset can be decimal number or hex string like \"0x3bd8ac00\". Max length 4096.")]
    async fn memory_run_plugin(
        &self,
        Parameters(mut req): Parameters<RunPluginRequest>,
    ) -> Result<CallToolResult, McpError> {
        // Coerce params from JSON string to object if needed.
        // Some MCP clients (e.g. Codex) send params as "{\"pattern\":\"text\"}" (a string)
        // instead of {"pattern":"text"} (an object). Parse the string into a Value.
        if let Some(serde_json::Value::String(s)) = &req.params {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(s) {
                req.params = Some(parsed);
            }
        }

        let session_lock = self.sessions.get_session(&req.session_id).await.ok_or_else(|| {
            McpError::invalid_params(format!("Session not found: {}", req.session_id), None)
        })?;

        let session = session_lock.read().await;

        // --- Plugins that do NOT require ISF symbols ---
        match req.plugin.as_str() {
            "search" => {
                let pattern_str = req.params
                    .as_ref()
                    .and_then(|p| p.get("pattern"))
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::invalid_params("'pattern' parameter is required", None))?
                    .to_string();

                let encoding = req.params
                    .as_ref()
                    .and_then(|p| p.get("encoding"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("ascii");

                let pattern_bytes: Vec<u8> = match encoding {
                    "ascii" => pattern_str.as_bytes().to_vec(),
                    "utf16le" => pattern_str
                        .encode_utf16()
                        .flat_map(|c| c.to_le_bytes())
                        .collect(),
                    "hex" => {
                        let hex_clean: String = pattern_str.chars().filter(|c| !c.is_whitespace()).collect();
                        hex::decode(&hex_clean).map_err(|e| {
                            McpError::invalid_params(format!("Invalid hex pattern: {}", e), None)
                        })?
                    }
                    other => {
                        return Err(McpError::invalid_params(
                            format!("Unknown encoding '{}'. Use ascii, utf16le, or hex.", other),
                            None,
                        ));
                    }
                };

                let context_bytes = req.params
                    .as_ref()
                    .and_then(|p| p.get("context"))
                    .and_then(|v| v.as_u64())
                    .map(|v| v as usize)
                    .unwrap_or(64);

                let limit = req.params
                    .as_ref()
                    .and_then(|p| p.get("limit"))
                    .and_then(|v| v.as_u64())
                    .map(|v| v as usize)
                    .unwrap_or(20);

                let result = memsearch::run(
                    &session.image,
                    &pattern_bytes,
                    SCAN_CHUNK_SIZE,
                    limit,
                    context_bytes,
                )
                .map_err(|e| McpError::internal_error(format!("search error: {}", e), None))?;

                return Ok(CallToolResult::success(vec![Content::text(json!({
                    "plugin": "search",
                    "session_id": req.session_id,
                    "encoding": encoding,
                    "pattern": pattern_str,
                    "pattern_len": result.pattern_len,
                    "total_matches": result.total_matches,
                    "matches": result.matches,
                }).to_string())]));
            }

            "rsds" => {
                let max_scan = req.params
                    .as_ref()
                    .and_then(|p| p.get("max_scan_bytes"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(session.image.size());

                let max_results = req.params
                    .as_ref()
                    .and_then(|p| p.get("limit"))
                    .and_then(|v| v.as_u64())
                    .map(|v| v as usize)
                    .unwrap_or(50);

                let entries = rsds::scan_rsds_limited(
                    &session.image,
                    SCAN_CHUNK_SIZE,
                    max_scan,
                    max_results,
                )
                .map_err(|e| McpError::internal_error(format!("rsds scan error: {}", e), None))?;

                let kernel_entries: Vec<_> = entries.iter()
                    .filter(|e| rsds::is_kernel_pdb(&e.pdb_name))
                    .collect();

                return Ok(CallToolResult::success(vec![Content::text(json!({
                    "plugin": "rsds",
                    "session_id": req.session_id,
                    "total_entries": entries.len(),
                    "kernel_entries": kernel_entries.len(),
                    "entries": entries,
                    "kernel_pdb_entries": kernel_entries,
                }).to_string())]));
            }

            "readraw" => {
                let offset_val = req.params
                    .as_ref()
                    .and_then(|p| p.get("offset"))
                    .ok_or_else(|| McpError::invalid_params("'offset' parameter is required", None))?;

                let offset: u64 = if let Some(n) = offset_val.as_u64() {
                    n
                } else if let Some(s) = offset_val.as_str() {
                    let s = s.trim();
                    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                        u64::from_str_radix(hex, 16).map_err(|e| {
                            McpError::invalid_params(format!("Invalid hex offset: {}", e), None)
                        })?
                    } else {
                        s.parse::<u64>().map_err(|e| {
                            McpError::invalid_params(format!("Invalid offset: {}", e), None)
                        })?
                    }
                } else {
                    return Err(McpError::invalid_params("'offset' must be a number or hex string", None));
                };

                let length = req.params
                    .as_ref()
                    .and_then(|p| p.get("length"))
                    .and_then(|v| v.as_u64())
                    .map(|v| v as usize)
                    .unwrap_or(256)
                    .min(4096);

                let data = session.image.read_padded(offset, length);

                // Build a classic hex dump with offset markers and ASCII sidebar.
                let hex_dump = format_hex_dump(&data, offset);

                return Ok(CallToolResult::success(vec![Content::text(json!({
                    "plugin": "readraw",
                    "session_id": req.session_id,
                    "offset": format!("{:#x}", offset),
                    "length": data.len(),
                    "hex_dump": hex_dump,
                }).to_string())]));
            }

            _ => {} // fall through to ISF-requiring plugins
        }

        if session.symbols.is_none() {
            return Ok(CallToolResult::success(vec![Content::text(json!({
                "error": "No ISF symbols loaded. Provide isf_path when calling memory_analyze_image.",
                "session_id": req.session_id,
                "plugin": req.plugin
            }).to_string())]));
        }

        let symbols = session.symbols.as_ref().unwrap();

        // Extract optional PID filter from params
        let pid_filter: Option<Vec<u64>> = req.params
            .as_ref()
            .and_then(|p| p.get("pid"))
            .and_then(|v| {
                if let Some(arr) = v.as_array() {
                    Some(arr.iter().filter_map(|x| x.as_u64()).collect())
                } else if let Some(single) = v.as_u64() {
                    Some(vec![single])
                } else {
                    None
                }
            });

        match req.plugin.as_str() {
            "pslist" => {
                let vm = session.virtual_memory.as_ref().ok_or_else(|| {
                    McpError::invalid_params(
                        "pslist requires DTB for virtual memory. Provide dtb when calling memory_analyze_image.".to_string(),
                        None,
                    )
                })?;

                let limit = req.params
                    .as_ref()
                    .and_then(|p| p.get("limit"))
                    .and_then(|v| v.as_u64())
                    .map(|v| v as usize)
                    .unwrap_or(500);

                let kernel_base = session.kernel_base;
                let ps_head = session.ps_active_process_head;
                let mut result = pslist::run_with_head(symbols, vm.as_ref(), kernel_base, ps_head)
                    .map_err(|e| McpError::internal_error(format!("pslist error: {}", e), None))?;

                let total = result.len();
                result.truncate(limit);

                Ok(CallToolResult::success(vec![Content::text(json!({
                    "plugin": "pslist",
                    "session_id": req.session_id,
                    "process_count": result.len(),
                    "total_processes": total,
                    "limit": limit,
                    "truncated": total > limit,
                    "processes": result
                }).to_string())]))
            }

            "psscan" => {
                let chunk_size = req.params
                    .as_ref()
                    .and_then(|p| p.get("chunk_size"))
                    .and_then(|v| v.as_u64())
                    .map(|v| v as usize)
                    .unwrap_or(SCAN_CHUNK_SIZE);

                let max_results = req.params
                    .as_ref()
                    .and_then(|p| p.get("limit"))
                    .and_then(|v| v.as_u64())
                    .map(|v| v as usize)
                    .unwrap_or(200);

                let result = psscan::run_limited(symbols, &session.image, chunk_size, None, Some(max_results))
                    .map_err(|e| McpError::internal_error(format!("psscan error: {}", e), None))?;

                Ok(CallToolResult::success(vec![Content::text(json!({
                    "plugin": "psscan",
                    "session_id": req.session_id,
                    "process_count": result.len(),
                    "limit": max_results,
                    "processes": result
                }).to_string())]))
            }

            "cmdline" => {
                let vm = session.virtual_memory.as_ref().ok_or_else(|| {
                    McpError::invalid_params(
                        "cmdline requires DTB for virtual memory.".to_string(),
                        None,
                    )
                })?;

                let limit = req.params
                    .as_ref()
                    .and_then(|p| p.get("limit"))
                    .and_then(|v| v.as_u64())
                    .map(|v| v as usize)
                    .unwrap_or(500);

                let physical = session.image.physical_layer();
                let kernel_base = session.kernel_base;
                let ps_head = session.ps_active_process_head;
                let pid_refs = pid_filter.as_deref();

                let mut result = cmdline::run_with_head(symbols, vm.as_ref(), physical, kernel_base, pid_refs, ps_head)
                    .map_err(|e| McpError::internal_error(format!("cmdline error: {}", e), None))?;

                let total = result.len();
                result.truncate(limit);

                Ok(CallToolResult::success(vec![Content::text(json!({
                    "plugin": "cmdline",
                    "session_id": req.session_id,
                    "process_count": result.len(),
                    "total_processes": total,
                    "limit": limit,
                    "truncated": total > limit,
                    "cmdlines": result
                }).to_string())]))
            }

            "dlllist" => {
                let vm = session.virtual_memory.as_ref().ok_or_else(|| {
                    McpError::invalid_params(
                        "dlllist requires DTB for virtual memory.".to_string(),
                        None,
                    )
                })?;

                let limit = req.params
                    .as_ref()
                    .and_then(|p| p.get("limit"))
                    .and_then(|v| v.as_u64())
                    .map(|v| v as usize)
                    .unwrap_or(200);

                let physical = session.image.physical_layer();
                let kernel_base = session.kernel_base;
                let ps_head = session.ps_active_process_head;
                let pid_refs = pid_filter.as_deref();

                let mut result = dlllist::run_with_head(symbols, vm.as_ref(), physical, kernel_base, pid_refs, ps_head)
                    .map_err(|e| McpError::internal_error(format!("dlllist error: {}", e), None))?;

                let total_procs = result.len();
                result.truncate(limit);
                let total_dlls: usize = result.iter().map(|p| p.dlls.len()).sum();

                Ok(CallToolResult::success(vec![Content::text(json!({
                    "plugin": "dlllist",
                    "session_id": req.session_id,
                    "process_count": result.len(),
                    "total_processes": total_procs,
                    "total_dlls": total_dlls,
                    "limit": limit,
                    "truncated": total_procs > limit,
                    "processes": result
                }).to_string())]))
            }

            "netscan" => {
                let chunk_size = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("chunk_size"))
                    .and_then(|v| v.as_u64())
                    .map(|v| v as usize)
                    .unwrap_or(SCAN_CHUNK_SIZE);

                // Prefer offsets loaded from ISF if available; otherwise fall back based on
                // Windows build metadata (best-effort) or Win10-19041 defaults.
                let offsets = netscan_offsets_best_effort(symbols);
                let kernel_vm: Option<&dyn isf::MemoryAccess> = session
                    .virtual_memory
                    .as_ref()
                    .map(|vm| vm.as_ref() as &dyn isf::MemoryAccess);

                let result = netscan::run(
                    symbols,
                    &session.image,
                    kernel_vm,
                    &offsets,
                    chunk_size,
                )
                .map_err(|e| McpError::internal_error(format!("netscan error: {}", e), None))?;

                Ok(CallToolResult::success(vec![Content::text(
                    json!({
                        "plugin": "netscan",
                        "session_id": req.session_id,
                        "total": result.total,
                        "tcp_listeners": result.tcp_listeners,
                        "tcp_endpoints": result.tcp_endpoints,
                        "udp_endpoints": result.udp_endpoints,
                        "connections": result.connections,
                    })
                    .to_string(),
                )]))
            }

            "cmdscan" => {
                let chunk_size = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("chunk_size"))
                    .and_then(|v| v.as_u64())
                    .map(|v| v as usize)
                    .unwrap_or(SCAN_CHUNK_SIZE);

                let max_hits = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("max_hits"))
                    .and_then(|v| v.as_u64())
                    .map(|v| v as usize)
                    .unwrap_or(50);

                let result = cmdscan::run(&session.image, chunk_size, max_hits)
                    .map_err(|e| McpError::internal_error(format!("cmdscan error: {}", e), None))?;

                Ok(CallToolResult::success(vec![Content::text(
                    json!({
                        "plugin": "cmdscan",
                        "session_id": req.session_id,
                        "total_hits": result.total_hits,
                        "hits": result.hits,
                    })
                    .to_string(),
                )]))
            }

            "malfind" => {
                let vm = session.virtual_memory.as_ref().ok_or_else(|| {
                    McpError::invalid_params(
                        "malfind requires DTB for virtual memory.".to_string(),
                        None,
                    )
                })?;

                let limit = req.params
                    .as_ref()
                    .and_then(|p| p.get("limit"))
                    .and_then(|v| v.as_u64())
                    .map(|v| v as usize)
                    .unwrap_or(200);

                let physical = session.image.physical_layer();
                let kernel_base = session.kernel_base;
                let ps_head = session.ps_active_process_head;
                let pid_refs = pid_filter.as_deref();

                let result = malfind::run(symbols, vm.as_ref(), physical, kernel_base, pid_refs, ps_head, limit)
                    .map_err(|e| McpError::internal_error(format!("malfind error: {}", e), None))?;

                let pe_count = result.iter().filter(|r| r.has_pe_header).count();

                Ok(CallToolResult::success(vec![Content::text(json!({
                    "plugin": "malfind",
                    "session_id": req.session_id,
                    "total_findings": result.len(),
                    "pe_header_count": pe_count,
                    "limit": limit,
                    "regions": result
                }).to_string())]))
            }

            _ => Err(McpError::invalid_params(
                format!("Unknown plugin: {}", req.plugin),
                None,
            )),
        }
    }

    /// Scan for KDBG structures in physical memory.
    #[tool(description = "Scan physical memory for Windows KDBG (Kernel Debugger Data Block) structures. Returns kernel base address, PsActiveProcessHead, SizeEProcess, and other kernel parameters. Works on Win7/8 (Win10+ KDBG is typically encoded). Requires session_id.")]
    async fn memory_scan_kdbg(
        &self,
        Parameters(req): Parameters<SessionRequest>,
    ) -> Result<CallToolResult, McpError> {
        let session_lock = self.sessions.get_session(&req.session_id).await.ok_or_else(|| {
            McpError::invalid_params(format!("Session not found: {}", req.session_id), None)
        })?;

        let session = session_lock.read().await;
        let results = kdbg::scan_for_kdbg(&session.image)
            .map_err(|e| McpError::internal_error(format!("KDBG scan error: {}", e), None))?;

        Ok(CallToolResult::success(vec![Content::text(json!({
            "session_id": req.session_id,
            "kdbg_count": results.len(),
            "kdbg_entries": results
        }).to_string())]))
    }

    /// Hunt for process anomalies.
    #[tool(description = "Analyze processes for anomalies: hidden processes (psscan vs pslist), suspicious parent-child relationships, singleton violations (multiple lsass.exe), LOLBin abuse with suspicious arguments, lsass.exe children, name masquerading. Requires session_id with ISF symbols and DTB.")]
    async fn memory_hunt_process_anomalies(
        &self,
        Parameters(req): Parameters<SessionRequest>,
    ) -> Result<CallToolResult, McpError> {
        let session_lock = self.sessions.get_session(&req.session_id).await.ok_or_else(|| {
            McpError::invalid_params(format!("Session not found: {}", req.session_id), None)
        })?;

        let session = session_lock.read().await;

        if session.symbols.is_none() {
            return Ok(CallToolResult::success(vec![Content::text(json!({
                "error": "No ISF symbols loaded."
            }).to_string())]));
        }

        let symbols = session.symbols.as_ref().unwrap();

        // Get pslist results (requires VM)
        let pslist_procs = if let Some(vm) = session.virtual_memory.as_ref() {
            pslist::run_with_head(symbols, vm.as_ref(), session.kernel_base, session.ps_active_process_head).unwrap_or_default()
        } else {
            Vec::new()
        };

        // Get psscan results (physical memory)
        let psscan_procs = psscan::run(symbols, &session.image, SCAN_CHUNK_SIZE)
            .unwrap_or_default();

        // Get cmdlines if VM available
        let cmdlines = if let Some(vm) = session.virtual_memory.as_ref() {
            let physical = session.image.physical_layer();
            cmdline::run_with_head(symbols, vm.as_ref(), physical, session.kernel_base, None, session.ps_active_process_head)
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        let cmdlines_ref = if cmdlines.is_empty() { None } else { Some(cmdlines.as_slice()) };

        // Run anomaly detection
        let report = process_anomalies::analyze(
            &pslist_procs,
            Some(&psscan_procs),
            cmdlines_ref,
        );

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&report).unwrap(),
        )]))
    }

    /// Find injected code.
    #[tool(description = "Scan process memory for injected code by walking VAD trees. Detects RWX (executable+writable) memory regions, PE headers (MZ) in non-image memory, and private executable regions. Requires session_id with ISF symbols and DTB.")]
    async fn memory_find_injected_code(
        &self,
        Parameters(req): Parameters<SessionRequest>,
    ) -> Result<CallToolResult, McpError> {
        let session_lock = self.sessions.get_session(&req.session_id).await.ok_or_else(|| {
            McpError::invalid_params(format!("Session not found: {}", req.session_id), None)
        })?;

        let session = session_lock.read().await;

        let symbols = session.symbols.as_ref().ok_or_else(|| {
            McpError::invalid_params(
                "No ISF symbols loaded. Provide isf_path when calling memory_analyze_image."
                    .to_string(),
                None,
            )
        })?;

        let vm = session.virtual_memory.as_ref().ok_or_else(|| {
            McpError::invalid_params(
                "Requires DTB for virtual memory. Provide dtb when calling memory_analyze_image."
                    .to_string(),
                None,
            )
        })?;

        let physical = session.image.physical_layer();
        let result = malfind::run(
            symbols,
            vm.as_ref(),
            physical,
            session.kernel_base,
            None,
            session.ps_active_process_head,
            200,
        )
        .map_err(|e| McpError::internal_error(format!("malfind error: {}", e), None))?;

        let pe_count = result.iter().filter(|r| r.has_pe_header).count();

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&json!({
                "session_id": req.session_id,
                "total_findings": result.len(),
                "pe_header_count": pe_count,
                "regions": result,
            }))
            .unwrap(),
        )]))
    }

    /// Find C2 connections.
    #[tool(description = "Scan for C2 network connections: suspicious ports, LOLBin network activity, C2 indicators. Requires session_id.")]
    async fn memory_find_c2_connections(
        &self,
        Parameters(req): Parameters<SessionRequest>,
    ) -> Result<CallToolResult, McpError> {
        let session_lock = self.sessions.get_session(&req.session_id).await.ok_or_else(|| {
            McpError::invalid_params(format!("Session not found: {}", req.session_id), None)
        })?;

        let session = session_lock.read().await;

        let symbols = session.symbols.as_ref().ok_or_else(|| {
            McpError::invalid_params(
                "No ISF symbols loaded. Provide isf_path when calling memory_analyze_image."
                    .to_string(),
                None,
            )
        })?;

        let offsets = netscan_offsets_best_effort(symbols);
        let kernel_vm: Option<&dyn isf::MemoryAccess> = session
            .virtual_memory
            .as_ref()
            .map(|vm| vm.as_ref() as &dyn isf::MemoryAccess);

        let netscan_result = netscan::run(
            symbols,
            &session.image,
            kernel_vm,
            &offsets,
            SCAN_CHUNK_SIZE,
        )
        .map_err(|e| McpError::internal_error(format!("netscan error: {}", e), None))?;

        // Best-effort cmdline enrichment (used for LOLBin heuristics).
        let cmdlines = if let Some(vm) = session.virtual_memory.as_ref() {
            let physical = session.image.physical_layer();
            cmdline::run_with_head(symbols, vm.as_ref(), physical, session.kernel_base, None, session.ps_active_process_head)
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        let report = network_analyzer::analyze(
            &netscan_result.connections,
            if cmdlines.is_empty() { None } else { Some(cmdlines.as_slice()) },
        );

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&json!({
                "session_id": req.session_id,
                "total_connections": report.total_connections,
                "flagged_connections": report.flagged_connections,
                "critical_count": report.critical_count,
                "high_count": report.high_count,
                "medium_count": report.medium_count,
                "low_count": report.low_count,
                "flagged": report.flagged,
            }))
            .unwrap(),
        )]))
    }

    /// Get command history.
    #[tool(description = "Extract command-line history from console buffers: cmd.exe and PowerShell commands. Flags suspicious commands. Requires session_id.")]
    async fn memory_get_command_history(
        &self,
        Parameters(req): Parameters<SessionRequest>,
    ) -> Result<CallToolResult, McpError> {
        let session_lock = self.sessions.get_session(&req.session_id).await.ok_or_else(|| {
            McpError::invalid_params(format!("Session not found: {}", req.session_id), None)
        })?;

        let session = session_lock.read().await;

        // CmdScan-lite: scan for suspicious command substrings (ASCII + UTF-16LE).
        let result = cmdscan::run(&session.image, SCAN_CHUNK_SIZE, 50)
            .map_err(|e| McpError::internal_error(format!("cmdscan error: {}", e), None))?;

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&json!({
                "session_id": req.session_id,
                "source": "cmdscan_lite",
                "total_hits": result.total_hits,
                "hits": result.hits,
            }))
            .unwrap(),
        )]))
    }

    /// Get process tree.
    #[tool(description = "Build and display the process tree showing parent-child relationships with anomaly indicators. Requires session_id with ISF symbols. Uses pslist (with DTB) or psscan (physical-only fallback).")]
    async fn memory_get_process_tree(
        &self,
        Parameters(req): Parameters<SessionRequest>,
    ) -> Result<CallToolResult, McpError> {
        let session_lock = self.sessions.get_session(&req.session_id).await.ok_or_else(|| {
            McpError::invalid_params(format!("Session not found: {}", req.session_id), None)
        })?;

        let session = session_lock.read().await;

        if session.symbols.is_none() {
            return Ok(CallToolResult::success(vec![Content::text(json!({
                "error": "No ISF symbols loaded."
            }).to_string())]));
        }

        let symbols = session.symbols.as_ref().unwrap();

        // Try pslist first, fall back to psscan
        let procs = if let Some(vm) = session.virtual_memory.as_ref() {
            pslist::run_with_head(symbols, vm.as_ref(), session.kernel_base, session.ps_active_process_head).unwrap_or_default()
        } else {
            psscan::run(symbols, &session.image, SCAN_CHUNK_SIZE).unwrap_or_default()
        };

        let tree = process_anomalies::build_process_tree(&procs, &[]);

        Ok(CallToolResult::success(vec![Content::text(json!({
            "session_id": req.session_id,
            "process_count": procs.len(),
            "source": if session.virtual_memory.is_some() { "pslist" } else { "psscan" },
            "tree": tree
        }).to_string())]))
    }

    /// Run a full automated triage.
    #[tool(description = "Run comprehensive automated triage on a memory image. Executes ALL analysis plugins (pslist, psscan, cmdline, netscan, cmdscan), runs anomaly detection and C2 analysis, cross-correlates findings (rootkit detection, credential theft, living-off-the-land attacks), extracts IOCs, computes risk score, and generates recommended response actions. This is the primary entry point for automated forensic analysis. Requires session_id with ISF symbols loaded.")]
    async fn memory_full_triage(
        &self,
        Parameters(req): Parameters<SessionRequest>,
    ) -> Result<CallToolResult, McpError> {
        let session_lock = self.sessions.get_session(&req.session_id).await.ok_or_else(|| {
            McpError::invalid_params(format!("Session not found: {}", req.session_id), None)
        })?;

        let session = session_lock.read().await;

        let symbols = session.symbols.as_ref().ok_or_else(|| {
            McpError::invalid_params(
                "No ISF symbols loaded. Provide isf_path when calling memory_analyze_image."
                    .to_string(),
                None,
            )
        })?;

        let report = full_triage::run_with_head(
            symbols,
            &session.image,
            session.virtual_memory.as_ref(),
            session.kernel_base,
            SCAN_CHUNK_SIZE,
            session.ps_active_process_head,
        );

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&report).unwrap(),
        )]))
    }
}

#[tool_handler]
impl ServerHandler for MemoxideServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "memoxide: Pure Rust memory forensics MCP server. \
                 Analyze Windows memory dumps for processes, malware, \
                 network connections, and credentials. \
                 Start by calling memory_analyze_image with a dump file path.\n\
                 For full automated analysis: call memory_full_triage (runs all plugins + correlates findings).\n\
                 For pslist/cmdline/dlllist: provide isf_path and dtb (Directory Table Base).\n\
                 For psscan: provide isf_path (no DTB needed, scans physical memory).\n\
                 For anomaly detection: call memory_hunt_process_anomalies (runs pslist + psscan + cmdline automatically)."
                    .into(),
            ),
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .build(),
            ..Default::default()
        }
    }
}
