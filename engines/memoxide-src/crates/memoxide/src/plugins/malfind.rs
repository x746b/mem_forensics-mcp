//! Malfind plugin — detect injected code via VAD tree analysis.
//!
//! Walks each process's VAD (Virtual Address Descriptor) tree to find regions
//! with executable+writable protection (PAGE_EXECUTE_READWRITE / PAGE_EXECUTE_WRITECOPY).
//! For each suspicious region, reads the first bytes to check for PE headers (MZ magic)
//! and builds a hex preview.
//!
//! Supports both Win10+ (`_RTL_AVL_TREE`) and Win7/8 (`_MM_AVL_TABLE`) VAD layouts.

use crate::memory::traits::MemoryLayer;
use crate::memory::virtual_memory::VirtualMemory;
use crate::plugins::{cmdline, pslist};
use crate::server::types::{InjectedRegion, ProcessInfo};
use isf::{IsfSymbols, MemoryAccess};
use std::collections::HashSet;
use std::sync::Arc;
use tracing::debug;

/// Maximum VAD nodes to visit per process (prevent infinite loops).
const MAX_VAD_NODES: usize = 4096;

/// Protection index to human-readable name.
fn protection_name(index: u8) -> &'static str {
    match index {
        0 => "PAGE_NOACCESS",
        1 => "PAGE_READONLY",
        2 => "PAGE_EXECUTE",
        3 => "PAGE_EXECUTE_READ",
        4 => "PAGE_READWRITE",
        5 => "PAGE_WRITECOPY",
        6 => "PAGE_EXECUTE_READWRITE",
        7 => "PAGE_EXECUTE_WRITECOPY",
        _ => "UNKNOWN",
    }
}

/// Returns true if the protection index indicates suspicious executable+writable.
/// PAGE_EXECUTE_READWRITE (6) is always suspicious.
/// PAGE_EXECUTE_WRITECOPY (7) is only suspicious when combined with private memory,
/// because non-private WRITECOPY is the normal protection for image-backed DLL mappings.
fn is_suspicious_protection(protection: u8, private_memory: bool) -> bool {
    match protection {
        6 => true,                // PAGE_EXECUTE_READWRITE — always suspicious
        7 => private_memory,      // PAGE_EXECUTE_WRITECOPY — only if private (not image-backed)
        _ => false,
    }
}

/// Extract `bit_len` bits starting at `bit_pos` from a u64 value.
fn extract_bits(value: u64, bit_pos: usize, bit_len: usize) -> u64 {
    (value >> bit_pos) & ((1u64 << bit_len) - 1)
}

/// Format bytes as hex string.
fn bytes_to_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
}

/// VAD version: Win10+ uses `_RTL_AVL_TREE`, Win7/8 uses `_MM_AVL_TABLE`.
#[derive(Debug, Clone, Copy)]
enum VadVersion {
    Win10,
    Win7,
}

/// All offsets needed to walk the VAD tree and extract flags.
#[derive(Debug, Clone)]
struct VadLayout {
    version: VadVersion,
    /// Offset of VadRoot within _EPROCESS.
    vad_root_offset: usize,
    /// For Win10: offset of Root pointer within _RTL_AVL_TREE (always 0).
    /// For Win7: offset of BalancedRoot.RightChild within _MM_AVL_TABLE.
    tree_root_offset: usize,
    /// Offset of Left child pointer within the node.
    left_offset: usize,
    /// Offset of Right child pointer within the node.
    right_offset: usize,
    /// Offset of StartingVpn within the VAD node.
    starting_vpn_offset: usize,
    /// Offset of EndingVpn within the VAD node.
    ending_vpn_offset: usize,
    /// For Win10: offset of StartingVpnHigh (u8).
    starting_vpn_high_offset: Option<usize>,
    /// For Win10: offset of EndingVpnHigh (u8).
    ending_vpn_high_offset: Option<usize>,
    /// Size of the VPN field (4 for Win10 u32, 8 for Win7 u64).
    vpn_size: usize,
    /// Offset of the `u` union (flags storage) within the VAD node.
    flags_offset: usize,
    /// Size of the flags word (4 bytes for Win10, 8 bytes for Win7).
    flags_size: usize,
    /// Bit position of Protection within the flags word.
    protection_bit_pos: usize,
    /// Bit length of Protection (always 5).
    protection_bit_len: usize,
    /// Bit position of PrivateMemory within the flags word.
    private_memory_bit_pos: usize,
}

/// Detect VAD version and compute all layout offsets from ISF.
fn detect_vad_layout(symbols: &IsfSymbols) -> Result<VadLayout, String> {
    // Check which VAD tree type exists
    let is_win10 = symbols.get_type("_RTL_AVL_TREE").is_some();
    let is_win7 = symbols.get_type("_MM_AVL_TABLE").is_some();

    // Get VadRoot offset from _EPROCESS
    let vad_root_offset = symbols
        .field_offset("_EPROCESS", "VadRoot")
        .ok_or("Field _EPROCESS.VadRoot not found in ISF")?;

    if is_win10 {
        // Win10+: _RTL_AVL_TREE.Root → pointer to _RTL_BALANCED_NODE
        let tree_root_offset = symbols
            .field_offset("_RTL_AVL_TREE", "Root")
            .unwrap_or(0);

        // _MMVAD_SHORT contains _RTL_BALANCED_NODE at offset 0 (VadNode field),
        // then StartingVpn, EndingVpn, etc.
        let left_offset = symbols
            .field_offset("_RTL_BALANCED_NODE", "Left")
            .unwrap_or(0);
        let right_offset = symbols
            .field_offset("_RTL_BALANCED_NODE", "Right")
            .unwrap_or(8);

        let starting_vpn_offset = symbols
            .field_offset("_MMVAD_SHORT", "StartingVpn")
            .unwrap_or(24);
        let ending_vpn_offset = symbols
            .field_offset("_MMVAD_SHORT", "EndingVpn")
            .unwrap_or(28);

        // VpnHigh fields exist in Win10+ for large address spaces
        let starting_vpn_high_offset = symbols
            .field_offset("_MMVAD_SHORT", "StartingVpnHigh")
            .or(Some(32));
        let ending_vpn_high_offset = symbols
            .field_offset("_MMVAD_SHORT", "EndingVpnHigh")
            .or(Some(33));

        // Flags union `u` in _MMVAD_SHORT
        let flags_offset = symbols
            .field_offset("_MMVAD_SHORT", "u")
            .unwrap_or(48);

        // Get bitfield positions from _MMVAD_FLAGS
        let (prot_bit_pos, prot_bit_len, priv_bit_pos) = get_mmvad_flags_bits(symbols, true);

        Ok(VadLayout {
            version: VadVersion::Win10,
            vad_root_offset,
            tree_root_offset,
            left_offset,
            right_offset,
            starting_vpn_offset,
            ending_vpn_offset,
            starting_vpn_high_offset,
            ending_vpn_high_offset,
            vpn_size: 4, // u32 in Win10+
            flags_offset,
            flags_size: 4, // u32 in Win10+
            protection_bit_pos: prot_bit_pos,
            protection_bit_len: prot_bit_len,
            private_memory_bit_pos: priv_bit_pos,
        })
    } else if is_win7 {
        // Win7/8: _MM_AVL_TABLE.BalancedRoot → embedded _MMADDRESS_NODE
        // Actual root = BalancedRoot.RightChild
        let balanced_root_offset = symbols
            .field_offset("_MM_AVL_TABLE", "BalancedRoot")
            .unwrap_or(0);
        let right_child_in_node = symbols
            .field_offset("_MMADDRESS_NODE", "RightChild")
            .unwrap_or(16);
        let tree_root_offset = balanced_root_offset + right_child_in_node;

        // _MMADDRESS_NODE layout
        let left_offset = symbols
            .field_offset("_MMADDRESS_NODE", "LeftChild")
            .unwrap_or(8);
        let right_offset = right_child_in_node;

        let starting_vpn_offset = symbols
            .field_offset("_MMADDRESS_NODE", "StartingVpn")
            .or_else(|| symbols.field_offset("_MMVAD_SHORT", "StartingVpn"))
            .unwrap_or(24);
        let ending_vpn_offset = symbols
            .field_offset("_MMADDRESS_NODE", "EndingVpn")
            .or_else(|| symbols.field_offset("_MMVAD_SHORT", "EndingVpn"))
            .unwrap_or(32);

        let flags_offset = symbols
            .field_offset("_MMVAD_SHORT", "u")
            .unwrap_or(40);

        let (prot_bit_pos, prot_bit_len, priv_bit_pos) = get_mmvad_flags_bits(symbols, false);

        Ok(VadLayout {
            version: VadVersion::Win7,
            vad_root_offset,
            tree_root_offset,
            left_offset,
            right_offset,
            starting_vpn_offset,
            ending_vpn_offset,
            starting_vpn_high_offset: None,
            ending_vpn_high_offset: None,
            vpn_size: 8, // u64 in Win7/8
            flags_offset,
            flags_size: 8, // u64 in Win7/8
            protection_bit_pos: prot_bit_pos,
            protection_bit_len: prot_bit_len,
            private_memory_bit_pos: priv_bit_pos,
        })
    } else {
        // Neither type found — try best-effort Win10 defaults
        debug!("No _RTL_AVL_TREE or _MM_AVL_TABLE found; using Win10 defaults");
        let (prot_bit_pos, prot_bit_len, priv_bit_pos) = get_mmvad_flags_bits(symbols, true);
        Ok(VadLayout {
            version: VadVersion::Win10,
            vad_root_offset,
            tree_root_offset: 0,
            left_offset: 0,
            right_offset: 8,
            starting_vpn_offset: 24,
            ending_vpn_offset: 28,
            starting_vpn_high_offset: Some(32),
            ending_vpn_high_offset: Some(33),
            vpn_size: 4,
            flags_offset: 48,
            flags_size: 4,
            protection_bit_pos: prot_bit_pos,
            protection_bit_len: prot_bit_len,
            private_memory_bit_pos: priv_bit_pos,
        })
    }
}

/// Extract Protection and PrivateMemory bitfield positions from _MMVAD_FLAGS.
/// Returns (protection_bit_pos, protection_bit_len, private_memory_bit_pos).
fn get_mmvad_flags_bits(symbols: &IsfSymbols, is_win10: bool) -> (usize, usize, usize) {
    if let Some(flags_type) = symbols.get_type("_MMVAD_FLAGS") {
        let prot = flags_type.fields.get("Protection");
        let priv_mem = flags_type.fields.get("PrivateMemory");

        let prot_bit_pos = prot
            .and_then(|f| f.type_info.bit_position)
            .unwrap_or(if is_win10 { 3 } else { 56 });
        let prot_bit_len = prot
            .and_then(|f| f.type_info.bit_length)
            .unwrap_or(5);
        let priv_bit_pos = priv_mem
            .and_then(|f| f.type_info.bit_position)
            .unwrap_or(if is_win10 { 15 } else { 63 });

        (prot_bit_pos, prot_bit_len, priv_bit_pos)
    } else {
        // Hardcoded fallbacks
        if is_win10 {
            (3, 5, 15)
        } else {
            (56, 5, 63)
        }
    }
}

/// Read a pointer (4 or 8 bytes) from memory at the given address.
fn read_ptr(memory: &dyn MemoryAccess, addr: u64, ptr_size: usize) -> Result<u64, String> {
    let bytes = memory
        .read(addr, ptr_size)
        .map_err(|e| format!("read pointer at {:#x}: {}", addr, e))?;
    match ptr_size {
        4 => Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64),
        8 => Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])),
        _ => Err(format!("unsupported pointer size: {}", ptr_size)),
    }
}

/// Read a u32 from memory.
fn read_u32_at(memory: &dyn MemoryAccess, addr: u64) -> Result<u32, String> {
    let bytes = memory
        .read(addr, 4)
        .map_err(|e| format!("read u32 at {:#x}: {}", addr, e))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Read a u64 from memory.
fn read_u64_at(memory: &dyn MemoryAccess, addr: u64) -> Result<u64, String> {
    let bytes = memory
        .read(addr, 8)
        .map_err(|e| format!("read u64 at {:#x}: {}", addr, e))?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

/// Read a u8 from memory.
fn read_u8_at(memory: &dyn MemoryAccess, addr: u64) -> Result<u8, String> {
    let bytes = memory
        .read(addr, 1)
        .map_err(|e| format!("read u8 at {:#x}: {}", addr, e))?;
    Ok(bytes[0])
}

/// A single VAD entry extracted from the tree.
struct VadEntry {
    start_va: u64,
    end_va: u64,
    protection: u8,
    private_memory: bool,
}

/// Walk the VAD tree for a single process and collect all entries.
fn walk_vad_tree(
    kernel_vm: &dyn MemoryAccess,
    layout: &VadLayout,
    root_ptr: u64,
    ptr_size: usize,
) -> Vec<VadEntry> {
    let mut entries = Vec::new();
    let mut stack: Vec<u64> = Vec::new();
    let mut visited = HashSet::new();

    if root_ptr == 0 {
        return entries;
    }
    stack.push(root_ptr);

    while let Some(node_addr) = stack.pop() {
        if node_addr == 0 || !visited.insert(node_addr) || visited.len() > MAX_VAD_NODES {
            continue;
        }

        // Read left/right child pointers and push onto stack
        if let Ok(left) = read_ptr(kernel_vm, node_addr + layout.left_offset as u64, ptr_size) {
            if left != 0 {
                stack.push(left);
            }
        }
        if let Ok(right) = read_ptr(kernel_vm, node_addr + layout.right_offset as u64, ptr_size) {
            if right != 0 {
                stack.push(right);
            }
        }

        // Read VPN fields
        let (start_vpn, end_vpn) = match layout.vpn_size {
            4 => {
                let s = read_u32_at(kernel_vm, node_addr + layout.starting_vpn_offset as u64)
                    .unwrap_or(0) as u64;
                let e = read_u32_at(kernel_vm, node_addr + layout.ending_vpn_offset as u64)
                    .unwrap_or(0) as u64;

                // Win10+ has VpnHigh fields for large address support
                let s_high = layout.starting_vpn_high_offset
                    .and_then(|off| read_u8_at(kernel_vm, node_addr + off as u64).ok())
                    .unwrap_or(0) as u64;
                let e_high = layout.ending_vpn_high_offset
                    .and_then(|off| read_u8_at(kernel_vm, node_addr + off as u64).ok())
                    .unwrap_or(0) as u64;

                ((s_high << 32) | s, (e_high << 32) | e)
            }
            8 => {
                let s = read_u64_at(kernel_vm, node_addr + layout.starting_vpn_offset as u64)
                    .unwrap_or(0);
                let e = read_u64_at(kernel_vm, node_addr + layout.ending_vpn_offset as u64)
                    .unwrap_or(0);
                (s, e)
            }
            _ => continue,
        };

        let start_va = start_vpn << 12;
        let end_va = ((end_vpn + 1) << 12) - 1; // inclusive end

        // Read flags
        let flags_addr = node_addr + layout.flags_offset as u64;
        let flags_value = match layout.flags_size {
            4 => read_u32_at(kernel_vm, flags_addr).unwrap_or(0) as u64,
            8 => read_u64_at(kernel_vm, flags_addr).unwrap_or(0),
            _ => continue,
        };

        let protection = extract_bits(flags_value, layout.protection_bit_pos, layout.protection_bit_len) as u8;
        let private_memory = extract_bits(flags_value, layout.private_memory_bit_pos, 1) != 0;

        entries.push(VadEntry {
            start_va,
            end_va,
            protection,
            private_memory,
        });
    }

    entries
}

/// Run malfind: detect injected code in process VAD trees.
///
/// # Arguments
/// * `symbols` - ISF symbols
/// * `kernel_vm` - Kernel virtual memory (for reading EPROCESS and VAD tree)
/// * `physical` - Physical memory layer (for creating per-process VMs)
/// * `kernel_base` - Optional kernel base for symbol relocation
/// * `pid_filter` - Optional list of PIDs to restrict to
/// * `ps_head_override` - Optional PsActiveProcessHead VA override
/// * `limit` - Maximum number of results to return
pub fn run(
    symbols: &IsfSymbols,
    kernel_vm: &dyn MemoryAccess,
    physical: Arc<dyn MemoryLayer>,
    kernel_base: Option<u64>,
    pid_filter: Option<&[u64]>,
    ps_head_override: Option<u64>,
    limit: usize,
) -> Result<Vec<InjectedRegion>, String> {
    let layout = detect_vad_layout(symbols)?;
    debug!("VAD layout: {:?}, vad_root_offset={}, flags_offset={}, prot_bits={}:{}",
        layout.version, layout.vad_root_offset, layout.flags_offset,
        layout.protection_bit_pos, layout.protection_bit_len);

    let processes = pslist::run_with_head(symbols, kernel_vm, kernel_base, ps_head_override)?;

    let ptr_size = symbols.pointer_size;
    let mut results = Vec::new();

    for proc in &processes {
        // Apply PID filter
        if let Some(pids) = pid_filter {
            if !pids.contains(&proc.pid) {
                continue;
            }
        }

        // Skip System/Idle — no user-space VADs
        if proc.pid == 0 || proc.pid == 4 {
            continue;
        }

        match scan_process_vads(
            symbols, kernel_vm, &physical, &layout, proc, ptr_size,
        ) {
            Ok(regions) => {
                for r in regions {
                    results.push(r);
                    if results.len() >= limit {
                        return Ok(results);
                    }
                }
            }
            Err(e) => {
                debug!("malfind: failed to scan PID {}: {}", proc.pid, e);
            }
        }
    }

    Ok(results)
}

/// Scan a single process's VAD tree for injected regions.
fn scan_process_vads(
    symbols: &IsfSymbols,
    kernel_vm: &dyn MemoryAccess,
    physical: &Arc<dyn MemoryLayer>,
    layout: &VadLayout,
    proc: &ProcessInfo,
    ptr_size: usize,
) -> Result<Vec<InjectedRegion>, String> {
    let eprocess_addr = proc.offset;

    // Get the VAD tree root pointer
    let root_ptr = match layout.version {
        VadVersion::Win10 => {
            // _EPROCESS.VadRoot is _RTL_AVL_TREE, Root is the first pointer
            let avl_tree_addr = eprocess_addr + layout.vad_root_offset as u64;
            read_ptr(kernel_vm, avl_tree_addr + layout.tree_root_offset as u64, ptr_size)?
        }
        VadVersion::Win7 => {
            // _EPROCESS.VadRoot is _MM_AVL_TABLE, BalancedRoot.RightChild is the actual root
            let avl_table_addr = eprocess_addr + layout.vad_root_offset as u64;
            read_ptr(kernel_vm, avl_table_addr + layout.tree_root_offset as u64, ptr_size)?
        }
    };

    if root_ptr == 0 {
        return Ok(Vec::new());
    }

    // Walk the VAD tree via kernel VM (VAD nodes are in kernel space)
    let vad_entries = walk_vad_tree(kernel_vm, layout, root_ptr, ptr_size);

    // Filter for RWX regions and inspect content
    let mut regions = Vec::new();

    // Read DTB for per-process VM
    let dtb = match cmdline::read_process_dtb(symbols, kernel_vm, eprocess_addr) {
        Ok(d) => d,
        Err(e) => {
            debug!("malfind: cannot read DTB for PID {}: {}", proc.pid, e);
            return Ok(Vec::new());
        }
    };

    let proc_vm = match VirtualMemory::with_dtb(physical.clone(), dtb) {
        Ok(vm) => vm,
        Err(e) => {
            debug!("malfind: cannot create VM for PID {}: {}", proc.pid, e);
            return Ok(Vec::new());
        }
    };

    for vad in &vad_entries {
        if !is_suspicious_protection(vad.protection, vad.private_memory) {
            continue;
        }

        let region_size = vad.end_va.saturating_sub(vad.start_va) + 1;

        // Skip very large regions (likely false positives from kernel mappings)
        if region_size > 256 * 1024 * 1024 {
            continue;
        }

        // Read first 256 bytes from process address space
        let read_size = std::cmp::min(256, region_size as usize);
        let content = match proc_vm.read_virtual(vad.start_va, read_size) {
            Ok(data) => data,
            Err(_) => continue, // Paged out or inaccessible — skip
        };

        // Skip if all zeros (uncommitted/zeroed page)
        if content.iter().all(|&b| b == 0) {
            continue;
        }

        let has_pe_header = content.len() >= 2 && content[0] == 0x4D && content[1] == 0x5A;

        let preview_len = std::cmp::min(64, content.len());
        let hex_preview = bytes_to_hex(&content[..preview_len]);

        let tag = if has_pe_header {
            "MZ_HEADER_IN_RWX".to_string()
        } else if vad.private_memory {
            "RWX_PRIVATE_MEMORY".to_string()
        } else {
            "RWX_REGION".to_string()
        };

        regions.push(InjectedRegion {
            pid: proc.pid,
            process_name: proc.name.clone(),
            vad_start: vad.start_va,
            vad_end: vad.end_va,
            region_size,
            protection: protection_name(vad.protection).to_string(),
            protection_value: vad.protection,
            private_memory: vad.private_memory,
            has_pe_header,
            hex_preview,
            tag,
        });
    }

    Ok(regions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_bits() {
        // Protection at bit_pos=3, bit_len=5 in a u32
        // Value 6 (PAGE_EXECUTE_READWRITE) at bits 3..7 = 6 << 3 = 48
        let flags: u64 = 6 << 3; // 0b00110000 = 48
        assert_eq!(extract_bits(flags, 3, 5), 6);

        // PrivateMemory at bit_pos=15 (single bit)
        let flags2: u64 = (1 << 15) | (6 << 3);
        assert_eq!(extract_bits(flags2, 3, 5), 6);
        assert_eq!(extract_bits(flags2, 15, 1), 1);
    }

    #[test]
    fn test_extract_bits_win7() {
        // Win7: Protection at bit_pos=56, bit_len=5 in a u64
        let flags: u64 = 6u64 << 56;
        assert_eq!(extract_bits(flags, 56, 5), 6);

        // PrivateMemory at bit_pos=63
        let flags2: u64 = (1u64 << 63) | (7u64 << 56);
        assert_eq!(extract_bits(flags2, 56, 5), 7);
        assert_eq!(extract_bits(flags2, 63, 1), 1);
    }

    #[test]
    fn test_protection_names() {
        assert_eq!(protection_name(0), "PAGE_NOACCESS");
        assert_eq!(protection_name(1), "PAGE_READONLY");
        assert_eq!(protection_name(4), "PAGE_READWRITE");
        assert_eq!(protection_name(6), "PAGE_EXECUTE_READWRITE");
        assert_eq!(protection_name(7), "PAGE_EXECUTE_WRITECOPY");
        assert_eq!(protection_name(8), "UNKNOWN");
    }

    #[test]
    fn test_is_suspicious_protection() {
        // Non-executable protections are never suspicious
        assert!(!is_suspicious_protection(0, false));
        assert!(!is_suspicious_protection(0, true));
        assert!(!is_suspicious_protection(1, false));
        assert!(!is_suspicious_protection(4, true));
        assert!(!is_suspicious_protection(5, false));

        // PAGE_EXECUTE_READWRITE (6) is always suspicious
        assert!(is_suspicious_protection(6, false));
        assert!(is_suspicious_protection(6, true));

        // PAGE_EXECUTE_WRITECOPY (7) only suspicious if private memory
        assert!(!is_suspicious_protection(7, false)); // image-backed DLL — normal
        assert!(is_suspicious_protection(7, true));   // private WRITECOPY — suspicious
    }

    #[test]
    fn test_vpn_to_va_win10() {
        // Win10: VA = ((VpnHigh << 32) | Vpn) << 12
        let vpn: u64 = 0x7FFE0;
        let vpn_high: u64 = 0;
        let va = ((vpn_high << 32) | vpn) << 12;
        assert_eq!(va, 0x7FFE0000);

        // With VpnHigh
        let vpn2: u64 = 0xABCDE;
        let vpn_high2: u64 = 0x01;
        let va2 = ((vpn_high2 << 32) | vpn2) << 12;
        assert_eq!(va2, 0x1_000A_BCDE_000);
    }

    #[test]
    fn test_vpn_to_va_win7() {
        // Win7: VA = Vpn << 12
        let vpn: u64 = 0x7FFE0;
        let va = vpn << 12;
        assert_eq!(va, 0x7FFE0000);
    }

    #[test]
    fn test_injected_region_serialize() {
        let region = InjectedRegion {
            pid: 1234,
            process_name: "malware.exe".to_string(),
            vad_start: 0x400000,
            vad_end: 0x401FFF,
            region_size: 0x2000,
            protection: "PAGE_EXECUTE_READWRITE".to_string(),
            protection_value: 6,
            private_memory: true,
            has_pe_header: true,
            hex_preview: "4d 5a 90 00".to_string(),
            tag: "MZ_HEADER_IN_RWX".to_string(),
        };
        let json = serde_json::to_string(&region).unwrap();
        assert!(json.contains("malware.exe"));
        assert!(json.contains("MZ_HEADER_IN_RWX"));
        assert!(json.contains("PAGE_EXECUTE_READWRITE"));
        assert!(json.contains("4d 5a 90 00"));
    }

    #[test]
    fn test_bytes_to_hex() {
        assert_eq!(bytes_to_hex(&[0x4D, 0x5A, 0x90]), "4d 5a 90");
        assert_eq!(bytes_to_hex(&[0x00]), "00");
        assert_eq!(bytes_to_hex(&[]), "");
    }
}
