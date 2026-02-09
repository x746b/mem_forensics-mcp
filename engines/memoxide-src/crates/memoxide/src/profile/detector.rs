//! Profile auto-detection helpers.
//!
//! Current approach (pragmatic):
//! - Use plaintext KDBG scanning (works on Win7/8; Win10+ KDBG is often encoded)
//! - Use KDBG.SizeEProcess (runtime _EPROCESS size) to select a matching kernel ISF
//!   from the local symbol store under `symbols/windows/`.
//! - If KDBG is missing/encoded: select a kernel ISF by probing psscan validity on a
//!   limited prefix of physical memory (try multiple ISFs cheaply).
//!
//! This is intentionally conservative: it only auto-loads an ISF when we can
//! match pointer size and pick a best candidate by _EPROCESS size.

use crate::profile::kdbg::KdbgInfo;
use crate::profile::{pdbconv, rsds, symserver};
use crate::plugins::psscan;
use crate::memory::image::MemoryImage;
use isf::IsfSymbols;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

#[derive(Debug)]
pub struct SelectedSymbols {
    pub isf_path: String,
    pub symbols: IsfSymbols,
}

/// Result of RSDS-based ISF detection.
#[derive(Debug)]
pub struct RsdsDetectionResult {
    /// The selected symbols, if found (locally or via download+convert).
    pub symbols: Option<SelectedSymbols>,
    /// True if an RSDS entry for a kernel PDB was found in memory,
    /// regardless of whether a matching ISF was resolved.
    pub kernel_guid_found: bool,
}

/// Select and parse the best-matching ISF under `symbols_root` for the given KDBG.
pub fn select_symbols_for_kdbg(
    symbols_root: &Path,
    kdbg: &KdbgInfo,
) -> Result<Option<SelectedSymbols>, String> {
    // Our KDBG scanner is KDDEBUGGER_DATA64 (x64).
    let pointer_size = 8usize;
    select_symbols_by_eprocess_size(symbols_root, kdbg.size_eprocess as usize, pointer_size)
}

/// Select and parse an ISF by probing psscan validity on a limited prefix of the dump.
///
/// Useful for Win10+ where plaintext KDBG may be unavailable.
pub fn select_symbols_by_psscan_probe(
    symbols_root: &Path,
    image: &MemoryImage,
    pointer_size: usize,
    max_scan_bytes: u64,
) -> Result<Option<SelectedSymbols>, String> {
    let mut files = Vec::new();
    collect_isf_files(symbols_root, &mut files)?;
    if files.is_empty() {
        return Ok(None);
    }

    let mut best: Option<(u64, PathBuf, IsfSymbols)> = None; // (score, path, symbols)

    for path in files {
        let path_str = match path.to_str() {
            Some(s) => s.to_string(),
            None => continue,
        };

        let symbols = match isf::parse_isf_file(&path_str) {
            Ok(s) => s,
            Err(e) => {
                debug!("ISF parse failed for {}: {}", path_str, e);
                continue;
            }
        };

        if symbols.pointer_size != pointer_size {
            continue;
        }

        // Need at least EPROCESS + POOL_HEADER to even attempt psscan.
        if symbols.get_type("_EPROCESS").is_none() || symbols.get_type("_POOL_HEADER").is_none() {
            continue;
        }

        // Probe: scan a prefix and score validated EPROCESS hits + plausibility checks.
        let procs = match psscan::run_limited(
            &symbols,
            image,
            16 * 1024 * 1024,
            Some(max_scan_bytes),
            Some(32),
        ) {
            Ok(p) => p,
            Err(e) => {
                debug!("psscan probe failed for {}: {}", path_str, e);
                continue;
            }
        };

        let score = score_psscan_probe(&symbols, image, &procs);
        debug!(
            "psscan probe {} => processes={} score={}",
            path_str,
            procs.len(),
            score
        );

        match &best {
            None => best = Some((score, path.clone(), symbols)),
            Some((best_score, _, _)) => {
                if score > *best_score {
                    best = Some((score, path.clone(), symbols));
                }
            }
        }
    }

    let Some((score, path, symbols)) = best else {
        return Ok(None);
    };

    if score == 0 {
        return Ok(None);
    }

    info!(
        "Auto-selected ISF by psscan probe: score={} path={}",
        score,
        path.display()
    );

    Ok(Some(SelectedSymbols {
        isf_path: path.to_string_lossy().into_owned(),
        symbols,
    }))
}

fn score_psscan_probe(
    symbols: &IsfSymbols,
    image: &MemoryImage,
    procs: &[crate::server::types::ProcessInfo],
) -> u64 {
    // Base score: more validated processes is better, but cap to avoid over-weighting.
    let mut score = (procs.len().min(32) as u64) * 10;

    // More discriminative checks over a small sample.
    for p in procs.iter().take(16) {
        // ActiveProcessLinks plausibility: LIST_ENTRY.Flink/Blink are kernel VAs.
        if let Some(links_off) = symbols.field_offset("_EPROCESS", "ActiveProcessLinks") {
            let list_entry = p.offset + links_off as u64;
            if let (Ok(flink), Ok(blink)) = (
                read_ptr_phys(image, list_entry, symbols.pointer_size),
                read_ptr_phys(
                    image,
                    list_entry + symbols.pointer_size as u64,
                    symbols.pointer_size,
                ),
            ) {
                if is_kernel_address(flink, symbols.pointer_size) {
                    score += 3;
                }
                if is_kernel_address(blink, symbols.pointer_size) {
                    score += 3;
                }
            }
        }

        // DirectoryTableBase plausibility: page-aligned physical address within image bounds.
        let dtb_off = symbols
            .field_offset("_KPROCESS", "DirectoryTableBase")
            .map(|o| o + symbols.field_offset("_EPROCESS", "Pcb").unwrap_or(0))
            .unwrap_or(0x28);
        if let Ok(dtb) = read_u64_phys(image, p.offset + dtb_off as u64) {
            let dtb = dtb & !0xfff;
            if dtb != 0 && dtb < image.size() && (dtb & 0xfff) == 0 {
                score += 5;
            }
        }
    }

    score
}

fn read_u64_phys(image: &MemoryImage, addr: u64) -> Result<u64, String> {
    let b = image
        .read(addr, 8)
        .map_err(|e| format!("read_u64 {:#x}: {}", addr, e))?;
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

fn read_ptr_phys(image: &MemoryImage, addr: u64, ptr_size: usize) -> Result<u64, String> {
    let b = image
        .read(addr, ptr_size)
        .map_err(|e| format!("read_ptr {:#x}: {}", addr, e))?;
    match ptr_size {
        8 => Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ])),
        4 => Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64),
        _ => Err(format!("unsupported ptr size: {}", ptr_size)),
    }
}

fn is_kernel_address(addr: u64, ptr_size: usize) -> bool {
    if addr == 0 {
        return false;
    }
    match ptr_size {
        8 => addr >= 0xFFFF_8000_0000_0000,
        4 => addr >= 0x8000_0000 && addr <= 0xFFFF_FFFF,
        _ => false,
    }
}

/// Select and parse ISF by matching RSDS GUID from the kernel PE debug directory.
///
/// Scans physical memory for RSDS entries, filters to kernel PDB names, and looks
/// up the matching ISF file under `{symbols_root}/{pdb_name}/{GUID}-{age}.json.xz`.
///
/// If no local ISF is found, attempts to download the PDB from Microsoft's Symbol
/// Server and convert it to ISF format on-the-fly, caching the result locally.
pub fn select_symbols_by_rsds(
    symbols_root: &Path,
    image: &MemoryImage,
    max_scan_bytes: u64,
) -> Result<RsdsDetectionResult, String> {
    // Use a very high result limit — the byte scan limit (max_scan_bytes) is the
    // real bound. We need to collect enough RSDS entries to find kernel PDBs which
    // may be at high physical offsets past hundreds of DLL RSDS entries.
    let entries =
        rsds::scan_rsds_limited(image, 16 * 1024 * 1024, max_scan_bytes, usize::MAX)?;

    let kernel_entries: Vec<_> = entries
        .iter()
        .filter(|e| rsds::is_kernel_pdb(&e.pdb_name))
        .collect();

    if kernel_entries.is_empty() {
        debug!("RSDS scan: no kernel PDB entries found");
        return Ok(RsdsDetectionResult {
            symbols: None,
            kernel_guid_found: false,
        });
    }

    // We found at least one kernel GUID.
    for entry in &kernel_entries {
        let isf_name = rsds::isf_filename(entry);
        // Try under {symbols_root}/{pdb_name}/{GUID}-{age}.json.xz
        let xz_path = symbols_root.join(&entry.pdb_name).join(&isf_name);
        // Also try uncompressed .json variant
        let json_name = format!("{}-{}.json", entry.guid, entry.age);
        let json_path = symbols_root.join(&entry.pdb_name).join(&json_name);

        for path in [&xz_path, &json_path] {
            if path.is_file() {
                let path_str = path.to_string_lossy().into_owned();
                match isf::parse_isf_file(&path_str) {
                    Ok(symbols) => {
                        info!(
                            "Auto-selected ISF by RSDS GUID: {} (pdb={}, age={}) path={}",
                            entry.guid, entry.pdb_name, entry.age, path_str
                        );
                        return Ok(RsdsDetectionResult {
                            symbols: Some(SelectedSymbols {
                                isf_path: path_str,
                                symbols,
                            }),
                            kernel_guid_found: true,
                        });
                    }
                    Err(e) => {
                        warn!("ISF parse failed for {}: {}", path_str, e);
                    }
                }
            }
        }

        // No local ISF found — attempt download + convert.
        info!(
            "No local ISF for RSDS {}-{} (pdb={}). Downloading PDB from Microsoft...",
            entry.guid, entry.age, entry.pdb_name
        );

        match symserver::download_pdb(&entry.pdb_name, &entry.guid, entry.age) {
            Ok(pdb_bytes) => {
                match pdbconv::convert_pdb_to_isf(
                    &pdb_bytes,
                    &entry.pdb_name,
                    &entry.guid,
                    entry.age,
                ) {
                    Ok(isf_json) => {
                        // Cache the converted ISF to the local symbol store.
                        let cache_dir = symbols_root.join(&entry.pdb_name);
                        let _ = fs::create_dir_all(&cache_dir);
                        let cache_path = cache_dir.join(&json_name);
                        if let Err(e) = fs::write(&cache_path, &isf_json) {
                            warn!("Failed to cache ISF to {}: {}", cache_path.display(), e);
                        } else {
                            info!("Cached converted ISF to {}", cache_path.display());
                        }

                        match isf::parse_isf_str(&isf_json) {
                            Ok(symbols) => {
                                let cache_str = cache_path.to_string_lossy().into_owned();
                                info!(
                                    "Auto-selected ISF by PDB download+convert: {} (pdb={}, age={})",
                                    entry.guid, entry.pdb_name, entry.age
                                );
                                return Ok(RsdsDetectionResult {
                                    symbols: Some(SelectedSymbols {
                                        isf_path: cache_str,
                                        symbols,
                                    }),
                                    kernel_guid_found: true,
                                });
                            }
                            Err(e) => {
                                warn!("Converted ISF failed validation: {}", e);
                            }
                        }
                    }
                    Err(e) => warn!("PDB→ISF conversion failed: {}", e),
                }
            }
            Err(e) => info!("PDB download failed: {}", e),
        }
    }

    Ok(RsdsDetectionResult {
        symbols: None,
        kernel_guid_found: true,
    })
}

/// Select and parse the best-matching ISF under `symbols_root` for the given
/// `_EPROCESS` size + pointer size.
pub fn select_symbols_by_eprocess_size(
    symbols_root: &Path,
    eprocess_size: usize,
    pointer_size: usize,
) -> Result<Option<SelectedSymbols>, String> {
    let mut files = Vec::new();
    collect_isf_files(symbols_root, &mut files)?;
    if files.is_empty() {
        return Ok(None);
    }

    let mut best: Option<(usize, PathBuf, IsfSymbols)> = None; // (score, path, symbols)

    for path in files {
        let path_str = match path.to_str() {
            Some(s) => s.to_string(),
            None => continue,
        };

        let symbols = match isf::parse_isf_file(&path_str) {
            Ok(s) => s,
            Err(e) => {
                debug!("ISF parse failed for {}: {}", path_str, e);
                continue;
            }
        };

        if symbols.pointer_size != pointer_size {
            continue;
        }

        let Some(sz) = symbols.type_size("_EPROCESS") else {
            continue;
        };

        // Basic sanity: must have PsActiveProcessHead and EPROCESS PID field.
        if symbols.get_symbol("PsActiveProcessHead").is_none() {
            continue;
        }
        if symbols.field_offset("_EPROCESS", "UniqueProcessId").is_none() {
            continue;
        }

        let score = sz.abs_diff(eprocess_size);
        let exact = score == 0;

        // Prefer exact match; otherwise minimal diff.
        match &best {
            None => best = Some((score, path.clone(), symbols)),
            Some((best_score, _, _)) => {
                if exact && *best_score != 0 {
                    best = Some((score, path.clone(), symbols));
                } else if score < *best_score {
                    best = Some((score, path.clone(), symbols));
                }
            }
        }
    }

    let Some((score, path, symbols)) = best else {
        return Ok(None);
    };

    if score == 0 {
        info!(
            "Auto-selected ISF by exact _EPROCESS size match: size={} path={}",
            eprocess_size,
            path.display()
        );
    } else {
            warn!(
                "Auto-selected ISF by closest _EPROCESS size (no exact match): want={} got={} diff={} path={}",
                eprocess_size,
                symbols.type_size("_EPROCESS").unwrap_or(0),
                score,
                path.display()
            );
        }

    Ok(Some(SelectedSymbols {
        isf_path: path.to_string_lossy().into_owned(),
        symbols,
    }))
}

fn collect_isf_files(root: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let md = fs::metadata(root).map_err(|e| format!("symbols root {}: {}", root.display(), e))?;
    if !md.is_dir() {
        return Ok(());
    }

    let entries = fs::read_dir(root)
        .map_err(|e| format!("read_dir {}: {}", root.display(), e))?;
    for ent in entries {
        let ent = ent.map_err(|e| format!("read_dir entry {}: {}", root.display(), e))?;
        let path = ent.path();
        let md = match ent.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if md.is_dir() {
            collect_isf_files(&path, out)?;
            continue;
        }
        if !md.is_file() {
            continue;
        }
        let name = match path.file_name().and_then(|s| s.to_str()) {
            Some(n) => n,
            None => continue,
        };
        // Accept both `.json` and `.json.xz`.
        if name.ends_with(".json") || name.ends_with(".json.xz") {
            out.push(path);
        }
    }
    Ok(())
}

/// Best-effort kernel base discovery by scanning common kernel VA ranges for a PE header.
///
/// This requires a working kernel DTB (virtual memory) and is mainly useful on Win10+
/// where plaintext KDBG is unavailable.
///
/// Uses a **two-pass** approach to handle ASLR on Win10+:
///
/// **Pass 1 (coarse, 2MB step):** Quickly scans the 64GB kernel VA range. For each PE
/// found, validates it with `PsActiveProcessHead` if symbols are available. Returns
/// immediately if validated. Collects unvalidated candidates for pass 2.
///
/// **Pass 2 (fine, 4KB step):** For each unvalidated coarse candidate, scans ±32MB
/// around it at 4KB steps (skipping already-checked 2MB-aligned addresses). This catches
/// kernels placed at ASLR-randomized 4KB-aligned addresses that don't land on 2MB
/// boundaries (common on Win10+ where the kernel is at e.g. `0xfffff8021ec0f000`).
///
/// **Fallback:** If no PE validates, returns the first coarse candidate.
pub fn find_kernel_base_pe_scan(
    vm: &dyn isf::MemoryAccess,
    symbols: Option<&IsfSymbols>,
) -> Option<u64> {
    const START: u64 = 0xFFFF_F800_0000_0000;
    const END: u64 = 0xFFFF_F810_0000_0000; // scan 64GB of kernel region
    const COARSE_STEP: u64 = 0x20_0000; // 2MB alignment
    const FINE_STEP: u64 = 0x1000; // 4KB alignment (ASLR granularity)
    const FINE_RADIUS: u64 = 32 * 1024 * 1024; // ±32MB around each coarse candidate

    // Get PsActiveProcessHead RVA for validation (if symbols available).
    let ps_head_rva = symbols.and_then(|s| s.get_symbol("PsActiveProcessHead"));

    // ── Pass 1: coarse scan (2MB step) ──
    let mut coarse_candidates: Vec<u64> = Vec::new();
    let mut first_pe: Option<u64> = None;
    let mut addr = START;
    while addr < END {
        if let Ok(bytes) = vm.read(addr, 0x1000) {
            if looks_like_pe64(&bytes) {
                if let Some(rva) = ps_head_rva {
                    if validate_kernel_base(vm, addr, rva) {
                        info!(
                            "Auto-detected kernel base via PE scan (pass 1) at {:#x}",
                            addr
                        );
                        return Some(addr);
                    }
                    // Not validated — save for pass 2
                    coarse_candidates.push(addr);
                    if first_pe.is_none() {
                        first_pe = Some(addr);
                    }
                } else {
                    // No symbols to validate — return first PE found.
                    info!("Auto-detected kernel base via PE scan at {:#x}", addr);
                    return Some(addr);
                }
            }
        }
        addr = addr.wrapping_add(COARSE_STEP);
    }

    // ── Pass 2: fine scan (4KB step) around coarse candidates ──
    if ps_head_rva.is_some() && !coarse_candidates.is_empty() {
        let rva = ps_head_rva.unwrap();
        debug!(
            "PE scan pass 2: fine-scanning around {} coarse candidates",
            coarse_candidates.len()
        );

        for &candidate in &coarse_candidates {
            let fine_start = candidate.saturating_sub(FINE_RADIUS).max(START);
            let fine_end = candidate.saturating_add(FINE_RADIUS).min(END);

            let mut fine_addr = fine_start;
            while fine_addr < fine_end {
                // Skip 2MB-aligned addresses — already checked in pass 1
                if fine_addr % COARSE_STEP == 0 {
                    fine_addr = fine_addr.wrapping_add(FINE_STEP);
                    continue;
                }

                if let Ok(bytes) = vm.read(fine_addr, 0x1000) {
                    if looks_like_pe64(&bytes) && validate_kernel_base(vm, fine_addr, rva) {
                        info!(
                            "Auto-detected kernel base via PE scan (pass 2) at {:#x} \
                             (near coarse candidate {:#x})",
                            fine_addr, candidate
                        );
                        return Some(fine_addr);
                    }
                }
                fine_addr = fine_addr.wrapping_add(FINE_STEP);
            }
        }
    }

    // Fallback: return first coarse PE (unvalidated)
    if let Some(addr) = first_pe {
        info!(
            "Auto-detected kernel base via PE scan at {:#x} (unvalidated fallback)",
            addr
        );
    }
    first_pe
}

/// Validate that a candidate PE base is the real kernel by checking PsActiveProcessHead.
///
/// Performs a **strong validation** of the `_LIST_ENTRY` at `base + ps_head_rva`:
/// 1. Both Flink and Blink must be kernel-mode VAs
/// 2. Following Flink and reading its Blink must point back to `ps_head_va`
///    (doubly-linked list circular integrity check)
///
/// This eliminates false positives from driver PEs where random data at the
/// PsActiveProcessHead offset happens to look like a kernel VA.
fn validate_kernel_base(vm: &dyn isf::MemoryAccess, base: u64, ps_head_rva: u64) -> bool {
    let ps_head_va = base.wrapping_add(ps_head_rva);

    // Read both Flink (8 bytes) and Blink (8 bytes) of the LIST_ENTRY
    let b = match vm.read(ps_head_va, 16) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let flink = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
    let blink = u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);

    // Both must be kernel VAs
    if flink < 0xFFFF_8000_0000_0000 || blink < 0xFFFF_8000_0000_0000 {
        return false;
    }

    // Follow Flink → read its Blink (offset +8 in the _LIST_ENTRY pointed to)
    // In a valid doubly-linked list, target.Blink should point back to ps_head_va
    let target_blink = match vm.read(flink.wrapping_add(8), 8) {
        Ok(b) => u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
        Err(_) => return false,
    };

    target_blink == ps_head_va
}

/// Extract SizeOfImage from a PE64 header, if valid.
/// Returns None if the bytes don't contain a valid PE or the offset is out of range.
#[allow(dead_code)]
fn pe64_size_of_image(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 0x100 || &bytes[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]])
        as usize;
    // SizeOfImage is at optional_header + 56 = e_lfanew + 24 + 56 = e_lfanew + 80
    let size_offset = e_lfanew + 80;
    if size_offset + 4 > bytes.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        bytes[size_offset],
        bytes[size_offset + 1],
        bytes[size_offset + 2],
        bytes[size_offset + 3],
    ]))
}

fn looks_like_pe64(bytes: &[u8]) -> bool {
    if bytes.len() < 0x100 {
        return false;
    }
    if &bytes[0..2] != b"MZ" {
        return false;
    }
    let e_lfanew = u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]])
        as usize;
    if e_lfanew < 0x40 || e_lfanew > 0x800 {
        return false;
    }
    if e_lfanew + 0x40 > bytes.len() {
        return false;
    }
    if &bytes[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return false;
    }
    let number_of_sections =
        u16::from_le_bytes([bytes[e_lfanew + 6], bytes[e_lfanew + 7]]) as usize;
    if number_of_sections == 0 || number_of_sections > 128 {
        return false;
    }
    // Optional header starts at e_lfanew + 24
    let opt_magic =
        u16::from_le_bytes([bytes[e_lfanew + 24], bytes[e_lfanew + 25]]);
    // 0x20b = PE32+ (64-bit)
    opt_magic == 0x20b
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_select_symbols_by_eprocess_size_from_local_store() {
        let root = Path::new("symbols/windows");
        if !root.exists() {
            // In some CI layouts, symbols may be absent.
            return;
        }

        // Pick an existing ISF, parse it, then require the selector can find an ISF
        // with that exact _EPROCESS size.
        let mut files = Vec::new();
        collect_isf_files(root, &mut files).unwrap();
        assert!(!files.is_empty());

        let first = files[0].to_string_lossy().into_owned();
        let symbols = isf::parse_isf_file(&first).unwrap();
        let eprocess_size = symbols.type_size("_EPROCESS").unwrap_or(0);
        assert!(eprocess_size > 0);

        let selected = select_symbols_by_eprocess_size(root, eprocess_size, symbols.pointer_size)
            .unwrap()
            .unwrap();
        assert_eq!(
            selected.symbols.type_size("_EPROCESS").unwrap(),
            eprocess_size
        );
        assert_eq!(selected.symbols.pointer_size, symbols.pointer_size);
    }

    #[test]
    fn test_looks_like_pe64_basic() {
        let mut b = vec![0u8; 0x1000];
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3c..0x40].copy_from_slice(&(0x80u32.to_le_bytes()));
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        // number_of_sections at e_lfanew + 6
        b[0x86..0x88].copy_from_slice(&(3u16.to_le_bytes()));
        // optional header magic at e_lfanew + 24
        b[0x98..0x9a].copy_from_slice(&(0x20bu16.to_le_bytes()));
        assert!(looks_like_pe64(&b));
    }
}
