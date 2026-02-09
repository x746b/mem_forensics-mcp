//! KDBG scanner — find _KDDEBUGGER_DATA64 in physical memory.
//!
//! The KDBG (Kernel Debugger Data Block) contains critical kernel parameters:
//! - KernBase: kernel image base address
//! - PsActiveProcessHead: head of the process linked list
//! - PsLoadedModuleList: head of loaded modules list
//! - Directory Table Base can be extracted from the System process
//!
//! On Windows 7/8, the KDBG tag (`KDBG` = 0x4742444B) is stored in plaintext
//! at offset 16 of the _KDDEBUGGER_DATA64 header (in the OwnerTag field).
//!
//! On Windows 10+, the KDBG is encoded/encrypted using KiWaitNever/KiWaitAlways.
//! For Win10+, we fall back to manual specification of DTB + kernel symbols.

use crate::memory::image::MemoryImage;
use isf::{IsfSymbols, MemoryAccess};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

/// KDBG tag bytes: "KDBG" in little-endian = 0x4742444B.
const KDBG_TAG: &[u8; 4] = b"KDBG";

/// _KDDEBUGGER_DATA64 field offsets (from kdbg.json).
/// Header._DBGKD_DEBUG_DATA_HEADER64.OwnerTag is at offset 16.
const KDBG_OWNER_TAG_OFFSET: usize = 16;
const KDBG_KERN_BASE_OFFSET: usize = 24;
const KDBG_PS_LOADED_MODULE_LIST_OFFSET: usize = 72;
const KDBG_PS_ACTIVE_PROCESS_HEAD_OFFSET: usize = 80;
const KDBG_SIZE_EPROCESS_OFFSET: usize = 680;
const KDBG_NT_BUILD_LAB_OFFSET: usize = 520;

/// Result of KDBG scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdbgInfo {
    /// Physical address of the KDBG structure.
    pub kdbg_address: u64,
    /// Kernel base virtual address.
    pub kern_base: u64,
    /// Virtual address of PsActiveProcessHead.
    pub ps_active_process_head: u64,
    /// Virtual address of PsLoadedModuleList.
    pub ps_loaded_module_list: u64,
    /// Size of _EPROCESS structure (useful for profile identification).
    pub size_eprocess: u16,
    /// NtBuildLab pointer (virtual address).
    pub nt_build_lab: u64,
}

/// Scan physical memory for KDBG structures.
///
/// Searches for the "KDBG" tag in physical memory and validates each candidate
/// by checking that critical fields contain plausible kernel-mode virtual addresses.
///
/// Returns all valid KDBG candidates found (usually just one).
pub fn scan_for_kdbg(image: &MemoryImage) -> Result<Vec<KdbgInfo>, String> {
    let image_size = image.size();
    let chunk_size: usize = 16 * 1024 * 1024; // 16 MB
    let mut results = Vec::new();
    let mut offset: u64 = 0;

    info!("Scanning {} bytes for KDBG tag...", image_size);

    while offset < image_size {
        let read_len = std::cmp::min(chunk_size, (image_size - offset) as usize);
        let chunk = match image.read(offset, read_len) {
            Ok(c) => c,
            Err(_) => {
                offset += chunk_size as u64;
                continue;
            }
        };

        // Search for KDBG tag in this chunk
        let mut pos = 0;
        while pos + 4 <= chunk.len() {
            if let Some(idx) = find_tag(&chunk[pos..], KDBG_TAG) {
                let abs_pos = pos + idx;
                let tag_phys_addr = offset + abs_pos as u64;
                pos = abs_pos + 1;

                // The KDBG tag is at OwnerTag offset (16) within the structure
                if tag_phys_addr < KDBG_OWNER_TAG_OFFSET as u64 {
                    continue;
                }
                let kdbg_base = tag_phys_addr - KDBG_OWNER_TAG_OFFSET as u64;

                // Try to validate this candidate
                match validate_kdbg(image, kdbg_base) {
                    Ok(Some(info)) => {
                        info!(
                            "Found valid KDBG at {:#x}: KernBase={:#x}, PsActiveProcessHead={:#x}, SizeEProcess={}",
                            kdbg_base, info.kern_base, info.ps_active_process_head, info.size_eprocess
                        );
                        results.push(info);
                    }
                    Ok(None) => {
                        debug!("Invalid KDBG candidate at {:#x}", kdbg_base);
                    }
                    Err(e) => {
                        debug!("KDBG validation error at {:#x}: {}", kdbg_base, e);
                    }
                }
            } else {
                break;
            }
        }

        offset += chunk_size as u64;
    }

    info!("KDBG scan complete: found {} valid candidates", results.len());
    Ok(results)
}

/// Validate a KDBG candidate at a physical address.
fn validate_kdbg(
    image: &dyn MemoryAccess,
    kdbg_base: u64,
) -> Result<Option<KdbgInfo>, String> {
    // Read KernBase (8 bytes at offset 24)
    let kern_base = read_u64(image, kdbg_base + KDBG_KERN_BASE_OFFSET as u64)?;

    // KernBase should be a kernel-mode virtual address
    // On x64: kernel addresses are >= 0xFFFF800000000000 (canonical high half)
    // On x86: kernel addresses are >= 0x80000000
    if !is_kernel_address(kern_base) {
        return Ok(None);
    }

    // Read PsActiveProcessHead
    let ps_active = read_u64(image, kdbg_base + KDBG_PS_ACTIVE_PROCESS_HEAD_OFFSET as u64)?;
    if !is_kernel_address(ps_active) {
        return Ok(None);
    }

    // Read PsLoadedModuleList
    let ps_modules = read_u64(image, kdbg_base + KDBG_PS_LOADED_MODULE_LIST_OFFSET as u64)?;
    if !is_kernel_address(ps_modules) {
        return Ok(None);
    }

    // Read SizeEProcess (u16 at offset 680)
    let size_eprocess = read_u16(image, kdbg_base + KDBG_SIZE_EPROCESS_OFFSET as u64)?;

    // _EPROCESS size should be reasonable (typically 700-2500 bytes)
    if size_eprocess < 500 || size_eprocess > 4096 {
        return Ok(None);
    }

    // Read NtBuildLab pointer
    let nt_build_lab = read_u64(image, kdbg_base + KDBG_NT_BUILD_LAB_OFFSET as u64).unwrap_or(0);

    Ok(Some(KdbgInfo {
        kdbg_address: kdbg_base,
        kern_base,
        ps_active_process_head: ps_active,
        ps_loaded_module_list: ps_modules,
        size_eprocess,
        nt_build_lab,
    }))
}

/// Check if an address looks like a kernel-mode virtual address.
fn is_kernel_address(addr: u64) -> bool {
    if addr == 0 {
        return false;
    }
    // x64: canonical high half (bit 47 set, sign-extended)
    if addr >= 0xFFFF_8000_0000_0000 {
        return true;
    }
    // x86: kernel addresses >= 0x80000000 (but only if fits in 32 bits)
    if addr >= 0x8000_0000 && addr <= 0xFFFF_FFFF {
        return true;
    }
    false
}

/// Extract DTB from the System process (PID 4).
///
/// Given a KDBG and virtual memory, reads PsActiveProcessHead, walks the
/// process list to find PID 4 (System), and reads its DirectoryTableBase.
///
/// This is a chicken-and-egg problem: we need DTB to do virtual reads, but we
/// need virtual reads to find DTB. The workaround is:
/// 1. Find KDBG in physical memory (already done)
/// 2. Scan for System process's _EPROCESS in physical memory
/// 3. Read DTB from the _EPROCESS.Pcb.DirectoryTableBase field
///
/// For now, we use psscan to find System process, then extract DTB.
pub fn find_system_dtb(
    symbols: &IsfSymbols,
    image: &MemoryImage,
) -> Result<Option<u64>, String> {
    // Use psscan to find processes
    let processes = crate::plugins::psscan::run(symbols, image, 16 * 1024 * 1024)?;

    // Find System (PID 4)
    for proc in &processes {
        if proc.pid == 4 {
            // DTB is at _EPROCESS.Pcb.DirectoryTableBase
            // _KPROCESS (Pcb) is at offset 0 of _EPROCESS
            // DirectoryTableBase offset within _KPROCESS varies:
            //   - Win7 x64: offset 0x28
            //   - Win10 x64: offset 0x28
            // We use the ISF to get the exact offset
            let dtb_offset = get_dtb_offset(symbols);
            if let Some(off) = dtb_offset {
                let dtb_addr = proc.offset + off as u64;
                let dtb = read_u64(image, dtb_addr)?;
                // DTB is a physical address, should be page-aligned and reasonable
                if dtb > 0 && dtb < image.size() && dtb & 0xFFF == 0 {
                    info!("Found System (PID 4) DTB: {:#x} at EPROCESS {:#x}", dtb, proc.offset);
                    return Ok(Some(dtb));
                }
            }
        }
    }

    Ok(None)
}

/// Get the offset of DirectoryTableBase within _EPROCESS.
/// Path: _EPROCESS.Pcb (_KPROCESS at offset 0) → DirectoryTableBase
fn get_dtb_offset(symbols: &IsfSymbols) -> Option<usize> {
    // Try _KPROCESS.DirectoryTableBase
    if let Some(pcb_offset) = symbols.field_offset("_EPROCESS", "Pcb") {
        if let Some(dtb_offset) = symbols.field_offset("_KPROCESS", "DirectoryTableBase") {
            return Some(pcb_offset + dtb_offset);
        }
    }

    // Fallback: some ISF files have it directly on _EPROCESS
    // Common offsets for x64 Windows:
    // Win7-Win10: Pcb is at offset 0, DTB within _KPROCESS at 0x28
    // So absolute offset = 0x28
    Some(0x28)
}

fn read_u64(memory: &dyn MemoryAccess, addr: u64) -> Result<u64, String> {
    let bytes = memory
        .read(addr, 8)
        .map_err(|e| format!("read u64 at {:#x}: {}", addr, e))?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn read_u16(memory: &dyn MemoryAccess, addr: u64) -> Result<u16, String> {
    let bytes = memory
        .read(addr, 2)
        .map_err(|e| format!("read u16 at {:#x}: {}", addr, e))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// Find a 4-byte tag in a data slice.
fn find_tag(data: &[u8], tag: &[u8; 4]) -> Option<usize> {
    if data.len() < 4 {
        return None;
    }
    let first = tag[0];
    let mut pos = 0;
    while pos + 4 <= data.len() {
        if let Some(idx) = memchr::memchr(first, &data[pos..]) {
            let abs = pos + idx;
            if abs + 4 > data.len() {
                return None;
            }
            if data[abs..abs + 4] == *tag {
                return Some(abs);
            }
            pos = abs + 1;
        } else {
            return None;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_kernel_address() {
        // x64 kernel addresses
        assert!(is_kernel_address(0xFFFFF800_00000000));
        assert!(is_kernel_address(0xFFFFF802_12345678));
        assert!(is_kernel_address(0xFFFFFFFF_FFFFFFFF));

        // x86 kernel addresses
        assert!(is_kernel_address(0x80000000));
        assert!(is_kernel_address(0xBF000000));

        // User-mode addresses (invalid)
        assert!(!is_kernel_address(0));
        assert!(!is_kernel_address(0x00007FFE_00000000));
        assert!(!is_kernel_address(0x00400000));
    }

    #[test]
    fn test_find_tag() {
        let data = b"\x00\x00\x00\x00KDBG\x00\x00\x00\x00";
        assert_eq!(find_tag(data, b"KDBG"), Some(4));

        let data = b"no tag here";
        assert_eq!(find_tag(data, b"KDBG"), None);

        let data = b"KDBG";
        assert_eq!(find_tag(data, b"KDBG"), Some(0));
    }

    #[test]
    fn test_find_tag_multiple() {
        let data = b"aaKDBGbbKDBGcc";
        assert_eq!(find_tag(data, b"KDBG"), Some(2));
    }
}
