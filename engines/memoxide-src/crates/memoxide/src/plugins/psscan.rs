//! PsScan plugin — scan physical memory for process pool tags.
//!
//! Scans physical memory for `Proc` (Win7) or `Pro\xc3` (Win10+) pool tags
//! in `_POOL_HEADER` structures, then validates the surrounding memory as
//! `_EPROCESS` structures. This finds hidden/unlinked processes that pslist misses.

use crate::memory::image::MemoryImage;
use crate::server::types::ProcessInfo;
use isf::{IsfSymbols, MemoryAccess, StructReader};
use tracing::debug;

/// Pool tags used by the Windows kernel for process objects.
/// The last byte has the "protected" bit (0x80) set for kernel objects.
const POOL_TAG_PROC: &[u8] = b"Proc"; // Unprotected (rare)
const POOL_TAG_PROC_PROTECTED: &[u8] = b"Pro\xe3"; // Win7/8 ('c' | 0x80)
const POOL_TAG_PROC_WIN10: &[u8] = b"Pro\xc3"; // Win10+ ('C' | 0x80)

/// Minimum valid PID (System = 4, Idle = 0).
const MAX_REASONABLE_PID: u64 = 0x10000;

/// Scan physical memory for process pool tags and validate as _EPROCESS.
///
/// # Arguments
/// * `symbols` - Parsed ISF symbols
/// * `image` - Physical memory image
/// * `chunk_size` - Size of chunks to read at a time (default: 16MB)
pub fn run(
    symbols: &IsfSymbols,
    image: &MemoryImage,
    chunk_size: usize,
) -> Result<Vec<ProcessInfo>, String> {
    run_limited(symbols, image, chunk_size, None, None)
}

/// Scan like [`run`], but optionally limit scan bytes and/or number of results.
///
/// This is used for profile auto-detection: try multiple symbol files cheaply.
pub fn run_limited(
    symbols: &IsfSymbols,
    image: &MemoryImage,
    chunk_size: usize,
    max_scan_bytes: Option<u64>,
    max_results: Option<usize>,
) -> Result<Vec<ProcessInfo>, String> {
    let image_size = image.size();
    let limit = max_scan_bytes.unwrap_or(image_size).min(image_size);

    // Determine _POOL_HEADER size from ISF
    let pool_header_size = symbols
        .type_size("_POOL_HEADER")
        .unwrap_or(pool_header_size_default(symbols.pointer_size));

    debug!(
        "psscan: scanning {} bytes (limit {}), pool_header_size={}, pointer_size={}",
        image_size,
        limit,
        pool_header_size,
        symbols.pointer_size
    );

    let mut processes = Vec::new();
    let mut seen_offsets = std::collections::HashSet::new();
    let overlap = 256; // overlap between chunks to catch tags at boundaries

    let mut offset: u64 = 0;
    while offset < limit {
        if let Some(max) = max_results {
            if processes.len() >= max {
                break;
            }
        }

        let remaining = limit - offset;
        let read_len = std::cmp::min(chunk_size + overlap, remaining as usize);
        let chunk = match image.read(offset, read_len) {
            Ok(c) => c,
            Err(_) => {
                offset += chunk_size as u64;
                continue;
            }
        };

        // Scan for all pool tag variants
        for tag in &[POOL_TAG_PROC, POOL_TAG_PROC_PROTECTED, POOL_TAG_PROC_WIN10] {
            scan_chunk_for_tag(
                &chunk,
                offset,
                tag,
                pool_header_size,
                symbols,
                image,
                &mut processes,
                &mut seen_offsets,
                chunk_size,
                max_results,
            );
        }

        offset += chunk_size as u64;
    }

    debug!("psscan found {} processes", processes.len());
    Ok(processes)
}

/// Pool alignment: 16 bytes on x64, 8 on x86.
fn pool_alignment(pointer_size: usize) -> usize {
    match pointer_size {
        8 => 16,
        4 => 8,
        _ => 16,
    }
}

/// Scan a chunk for pool tag matches and validate each as _EPROCESS.
fn scan_chunk_for_tag(
    chunk: &[u8],
    chunk_offset: u64,
    tag: &[u8],
    pool_header_size: usize,
    symbols: &IsfSymbols,
    image: &MemoryImage,
    processes: &mut Vec<ProcessInfo>,
    seen_offsets: &mut std::collections::HashSet<u64>,
    max_scan_offset: usize,
    max_results: Option<usize>,
) {
    // Pool tag is at offset 4 within _POOL_HEADER (PoolTag field)
    // On x64: _POOL_HEADER is 16 bytes, tag at offset 4
    let tag_offset_in_header = 4usize;
    let eprocess_size = symbols.type_size("_EPROCESS").unwrap_or(0);
    let alignment = pool_alignment(symbols.pointer_size);

    // Search for the tag in the chunk
    let mut pos = 0;
    while pos + tag.len() <= chunk.len() {
        // Early exit if we've hit the result limit
        if let Some(max) = max_results {
            if processes.len() >= max {
                return;
            }
        }

        if let Some(found) = memchr_find(tag, &chunk[pos..]) {
            let abs_pos = pos + found;
            pos = abs_pos + 1;

            // Only process hits in the non-overlap portion
            if abs_pos >= max_scan_offset {
                continue;
            }

            // The pool header starts tag_offset_in_header bytes before the tag
            if abs_pos < tag_offset_in_header {
                continue;
            }
            let pool_header_addr = chunk_offset + (abs_pos - tag_offset_in_header) as u64;
            let local_pool_offset = abs_pos - tag_offset_in_header;

            // Pool headers must be aligned to pool alignment boundary
            if pool_header_addr % alignment as u64 != 0 {
                continue;
            }

            // Validate pool header fields (BlockSize, PoolType) before expensive EPROCESS parse
            if eprocess_size > 0 && !validate_pool_header(chunk, local_pool_offset, eprocess_size, alignment) {
                continue;
            }

            // Read BlockSize from _POOL_HEADER (bits 16-23 of the first u32)
            // and calculate the _EPROCESS address at the END of the allocation:
            //   _EPROCESS_addr = pool_header_addr + (BlockSize * alignment) - sizeof(_EPROCESS)
            //
            // Windows pool layout: [_POOL_HEADER][optional_headers][_OBJECT_HEADER][Object Body]
            // The object body (_EPROCESS) is always at the END of the pool allocation.
            let eprocess_addr = if eprocess_size > 0 && local_pool_offset + 4 <= chunk.len() {
                let ulong1 = u32::from_le_bytes([
                    chunk[local_pool_offset],
                    chunk[local_pool_offset + 1],
                    chunk[local_pool_offset + 2],
                    chunk[local_pool_offset + 3],
                ]);
                let block_size = ((ulong1 >> 16) & 0xFF) as usize;
                let alloc_size = block_size * alignment;
                // validate_pool_header already ensured block_size > 0 and alloc_size is reasonable
                pool_header_addr + alloc_size as u64 - eprocess_size as u64
            } else {
                // No _EPROCESS size in ISF — fall back to old method
                pool_header_addr + pool_header_size as u64
            };

            // Skip duplicates
            if !seen_offsets.insert(eprocess_addr) {
                continue;
            }

            // Validate this looks like a real _EPROCESS
            match validate_eprocess(symbols, image, eprocess_addr) {
                Ok(Some(proc)) => {
                    debug!(
                        "psscan: found {} (PID {}) at {:#x}",
                        proc.name, proc.pid, eprocess_addr
                    );
                    processes.push(proc);
                }
                Ok(None) => {} // Not a valid process
                Err(e) => {
                    debug!("psscan: validation error at {:#x}: {}", eprocess_addr, e);
                }
            }
        } else {
            break;
        }
    }
}

/// Validate pool header before attempting _EPROCESS parse.
/// Checks PoolType and BlockSize for sanity.
fn validate_pool_header(chunk: &[u8], local_offset: usize, eprocess_size: usize, alignment: usize) -> bool {
    if local_offset + 4 > chunk.len() {
        return false;
    }
    let ulong1 = u32::from_le_bytes([
        chunk[local_offset],
        chunk[local_offset + 1],
        chunk[local_offset + 2],
        chunk[local_offset + 3],
    ]);
    let block_size = ((ulong1 >> 16) & 0xFF) as usize;
    let pool_type = ((ulong1 >> 24) & 0xFF) as u8;

    // BlockSize must be large enough for _EPROCESS + pool header + object header
    if block_size == 0 {
        return false;
    }
    let alloc_bytes = block_size * alignment;
    // Minimum: pool_header(16) + object_header_body(48) + eprocess
    if alloc_bytes < 16 + 48 + eprocess_size {
        return false;
    }
    // Process pool allocation is typically ~1300-1400 bytes on x64.
    // Allow up to eprocess_size + 512 bytes of overhead (headers + padding).
    if alloc_bytes > eprocess_size + 512 {
        return false;
    }

    // PoolType: bit 0-1 = pool type, bit 2 = allocated flag
    // Allocated blocks should have PoolType >= 2 (bit 1 set = allocated)
    // Free blocks have PoolType 0, which we skip
    if pool_type == 0 {
        return false;
    }
    // PoolType should be reasonable (< 16)
    if pool_type > 15 {
        return false;
    }

    true
}

/// Common DTB offsets to try when the ISF-derived offset doesn't match the
/// actual kernel build (hotfix/patch level differences).
const DTB_FALLBACK_OFFSETS: &[usize] = &[0x28]; // x64 Win10 _KPROCESS.DirectoryTableBase

/// Try reading the DTB at the ISF-derived offset first, then fall back to
/// common hardcoded offsets. Returns Some(dtb_value) if any offset yields a
/// page-aligned, non-zero DTB.
fn try_read_dtb(reader: &StructReader, symbols: &IsfSymbols) -> Option<u64> {
    let pcb_offset = symbols.field_offset("_EPROCESS", "Pcb").unwrap_or(0);
    let isf_dtb_offset = symbols.field_offset("_KPROCESS", "DirectoryTableBase").unwrap_or(0x28);

    // Collect offsets to try: ISF first, then fallbacks (deduplicated)
    let mut offsets = vec![pcb_offset + isf_dtb_offset];
    for &fb in DTB_FALLBACK_OFFSETS {
        let candidate = pcb_offset + fb;
        if !offsets.contains(&candidate) {
            offsets.push(candidate);
        }
    }

    for off in offsets {
        if let Ok(b) = reader.read_at_offset(off, 8) {
            let dtb = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
            if dtb != 0 && dtb & 0xFFF == 0 {
                return Some(dtb);
            }
        }
    }
    None
}

/// Validate a candidate _EPROCESS at a physical address.
/// Returns Some(ProcessInfo) if valid, None if not a real process.
///
/// Uses a **score-based** approach to handle ISF offset mismatches:
/// - Hard requirements: PID (multiple of 4, < 0x10000) and name (printable ASCII, >= 3 chars)
/// - Soft checks (each +1 score): DTB page-aligned, Flink in kernel space, PPID reasonable
/// - Must pass at least 1 soft check to be accepted
fn validate_eprocess(
    symbols: &IsfSymbols,
    image: &dyn MemoryAccess,
    addr: u64,
) -> Result<Option<ProcessInfo>, String> {
    let reader = match StructReader::new(symbols, image, addr, "_EPROCESS") {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };

    // ── Hard requirement: PID ──
    let pid = match reader.read_pointer("UniqueProcessId") {
        Ok(p) => p,
        Err(_) => return Ok(None),
    };

    if pid > MAX_REASONABLE_PID {
        return Ok(None);
    }

    // Windows PIDs are always multiples of 4 (except Idle = 0)
    if pid != 0 && pid % 4 != 0 {
        return Ok(None);
    }

    // ── Hard requirement: Name ──
    let name = match reader.read_string("ImageFileName", 15) {
        Ok(n) => n,
        Err(_) => return Ok(None),
    };

    // Name must be at least 3 chars for ALL processes
    if name.len() < 3 {
        return Ok(None);
    }

    // Name must be printable ASCII only (0x20-0x7e)
    if !name.bytes().all(|b| b >= 0x20 && b <= 0x7e) {
        return Ok(None);
    }

    // Reject names containing path separators or spaces
    if name.contains('\\') || name.contains('/') || name.contains(' ') {
        return Ok(None);
    }

    // ── Soft checks (score-based) ──
    let mut score: u32 = 0;

    // Soft check 1: PPID
    let ppid = reader
        .read_pointer("InheritedFromUniqueProcessId")
        .unwrap_or(0);

    if ppid <= MAX_REASONABLE_PID && (ppid == 0 || ppid % 4 == 0) {
        score += 1;
    }

    // Soft check 2: DTB (try ISF offset + fallbacks)
    if pid == 0 {
        // Idle process — DTB check not applicable, give free point
        score += 1;
    } else if try_read_dtb(&reader, symbols).is_some() {
        score += 1;
    }

    // Soft check 3: ActiveProcessLinks.Flink looks like kernel VA
    if let Some(apl_offset) = symbols.field_offset("_EPROCESS", "ActiveProcessLinks") {
        if let Ok(flink_bytes) = reader.read_at_offset(apl_offset, 8) {
            let flink = u64::from_le_bytes([
                flink_bytes[0], flink_bytes[1], flink_bytes[2], flink_bytes[3],
                flink_bytes[4], flink_bytes[5], flink_bytes[6], flink_bytes[7],
            ]);
            if symbols.pointer_size == 8 {
                // Flink of 0 (exited/unlinked) or valid kernel VA
                if flink == 0 || flink >= 0xFFFF_8000_0000_0000 {
                    score += 1;
                }
            } else {
                // x86: kernel addresses >= 0x80000000
                if flink == 0 || flink >= 0x8000_0000 {
                    score += 1;
                }
            }
        }
    }

    // Must pass at least 1 soft check
    if score == 0 {
        return Ok(None);
    }

    // Thread count
    let threads = reader.read_u32("ActiveThreads").ok();

    // Read create time
    let create_time = reader
        .read_u64("CreateTime")
        .ok()
        .and_then(|t| super::pslist::filetime_to_iso(t));

    // Read exit time
    let exit_time = reader
        .read_u64("ExitTime")
        .ok()
        .and_then(|t| super::pslist::filetime_to_iso(t));

    // Session ID
    let session_id = if symbols.field_offset("_EPROCESS", "SessionId").is_some() {
        reader.read_u32("SessionId").ok()
    } else {
        None
    };

    Ok(Some(ProcessInfo {
        pid,
        ppid,
        name,
        offset: addr,
        create_time,
        exit_time,
        threads,
        handles: None,
        session_id,
        wow64: None,
    }))
}

/// Simple byte pattern search (using memchr for the first byte then verify).
fn memchr_find(needle: &[u8], haystack: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let first = needle[0];
    let mut pos = 0;
    while pos + needle.len() <= haystack.len() {
        if let Some(idx) = memchr::memchr(first, &haystack[pos..]) {
            let abs = pos + idx;
            if abs + needle.len() > haystack.len() {
                return None;
            }
            if haystack[abs..abs + needle.len()] == *needle {
                return Some(abs);
            }
            pos = abs + 1;
        } else {
            return None;
        }
    }
    None
}

/// Default _POOL_HEADER size when not in ISF.
fn pool_header_size_default(pointer_size: usize) -> usize {
    match pointer_size {
        8 => 16, // x64
        4 => 8,  // x86
        _ => 16,
    }
}

/// Find the System process DTB by directly scanning for "System\0" in ImageFileName.
///
/// On Win11+ (and some Win10 builds), the segment heap replaces traditional pool
/// headers for large allocations like _EPROCESS, so pool tag scanning (`Pro\xc3`)
/// finds nothing. This function bypasses pool tags entirely by:
///
/// 1. Searching physical memory for the string "System\0" (SIMD-accelerated)
/// 2. For each match, computing the candidate _EPROCESS base from the ImageFileName offset
/// 3. Quick-checking PID == 4 before expensive validation
/// 4. Extracting the DTB from the validated System _EPROCESS
///
/// Returns `(dtb, ProcessInfo)` for the System process, or None if not found.
pub fn find_system_dtb_direct(
    symbols: &IsfSymbols,
    image: &MemoryImage,
    chunk_size: usize,
) -> Result<Option<(u64, ProcessInfo)>, String> {
    let image_filename_offset = symbols
        .field_offset("_EPROCESS", "ImageFileName")
        .ok_or("No ImageFileName field in _EPROCESS")?;
    let pid_offset = symbols
        .field_offset("_EPROCESS", "UniqueProcessId")
        .ok_or("No UniqueProcessId field in _EPROCESS")?;

    let needle = b"System\0";
    let image_size = image.size();
    let overlap = 256;
    let mut offset: u64 = 0;

    debug!(
        "Direct System scan: ImageFileName offset={}, scanning {} bytes",
        image_filename_offset, image_size
    );

    while offset < image_size {
        let remaining = image_size - offset;
        let read_len = std::cmp::min(chunk_size + overlap, remaining as usize);
        let chunk = match image.read(offset, read_len) {
            Ok(c) => c,
            Err(_) => {
                offset += chunk_size as u64;
                continue;
            }
        };

        let max_scan = if offset + read_len as u64 >= image_size {
            chunk.len()
        } else {
            chunk_size
        };
        let mut pos = 0;

        while pos + needle.len() <= chunk.len() && pos < max_scan {
            if let Some(found) = memchr_find(needle, &chunk[pos..]) {
                let abs_pos = pos + found;
                pos = abs_pos + 1;

                if abs_pos >= max_scan {
                    continue;
                }

                // Compute candidate _EPROCESS base address.
                let string_phys = offset + abs_pos as u64;
                if string_phys < image_filename_offset as u64 {
                    continue;
                }
                let candidate_base = string_phys - image_filename_offset as u64;

                // Quick PID check: read 8 bytes at UniqueProcessId offset.
                // Only proceed to full validation if PID == 4.
                let pid_addr = candidate_base + pid_offset as u64;
                match image.read(pid_addr, 8) {
                    Ok(b) => {
                        let pid = u64::from_le_bytes([
                            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                        ]);
                        if pid != 4 {
                            continue;
                        }
                    }
                    Err(_) => continue,
                }

                // Full validation
                match validate_eprocess(symbols, image, candidate_base) {
                    Ok(Some(proc)) => {
                        if proc.pid == 4 && proc.name == "System" {
                            let reader = match StructReader::new(
                                symbols,
                                image,
                                candidate_base,
                                "_EPROCESS",
                            ) {
                                Ok(r) => r,
                                Err(_) => continue,
                            };
                            if let Some(dtb) = try_read_dtb(&reader, symbols) {
                                if dtb < image.size() {
                                    debug!(
                                        "Direct scan: found System (PID 4) at {:#x}, DTB={:#x}",
                                        candidate_base, dtb
                                    );
                                    return Ok(Some((dtb, proc)));
                                }
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(_) => {}
                }
            } else {
                break;
            }
        }

        offset += chunk_size as u64;
    }

    debug!("Direct System scan: System process not found");
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memchr_find() {
        let data = b"hello Proc world";
        assert_eq!(memchr_find(b"Proc", data), Some(6));
        assert_eq!(memchr_find(b"world", data), Some(11));
        assert_eq!(memchr_find(b"xyz", data), None);
        assert_eq!(memchr_find(b"", data), None);
    }

    #[test]
    fn test_pool_header_defaults() {
        assert_eq!(pool_header_size_default(8), 16);
        assert_eq!(pool_header_size_default(4), 8);
    }
}
