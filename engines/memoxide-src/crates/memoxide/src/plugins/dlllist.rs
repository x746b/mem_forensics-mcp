//! DllList plugin — list loaded DLLs per process.
//!
//! Walks each process's PEB → Ldr → InLoadOrderModuleList to enumerate
//! loaded DLLs. Each entry is a `_LDR_DATA_TABLE_ENTRY` containing:
//! - BaseDllName (UNICODE_STRING) — just the filename
//! - FullDllName (UNICODE_STRING) — full path
//! - DllBase — load address
//! - SizeOfImage — mapped size
//!
//! Like cmdline, this requires per-process virtual memory.

use crate::memory::virtual_memory::VirtualMemory;
use crate::server::types::ProcessInfo;
use isf::{IsfSymbols, MemoryAccess, StructReader};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tracing::debug;

/// Information about a loaded DLL.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DllInfo {
    pub base: u64,
    pub size: u64,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// DLL list for a single process.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProcessDllList {
    pub pid: u64,
    pub name: String,
    pub dlls: Vec<DllInfo>,
}

/// Extract DLL lists for all processes.
///
/// # Arguments
/// * `symbols` - ISF symbols
/// * `kernel_vm` - Kernel virtual memory (for reading _EPROCESS fields)
/// * `physical` - Physical memory layer (for creating per-process VMs)
/// * `kernel_base` - Optional kernel base for symbol relocation
/// * `pid_filter` - Optional list of PIDs to restrict to
#[allow(dead_code)]
pub fn run(
    symbols: &IsfSymbols,
    kernel_vm: &dyn MemoryAccess,
    physical: Arc<dyn crate::memory::traits::MemoryLayer>,
    kernel_base: Option<u64>,
    pid_filter: Option<&[u64]>,
) -> Result<Vec<ProcessDllList>, String> {
    run_with_head(symbols, kernel_vm, physical, kernel_base, pid_filter, None)
}

/// Like [`run`], but with a PsActiveProcessHead override.
pub fn run_with_head(
    symbols: &IsfSymbols,
    kernel_vm: &dyn MemoryAccess,
    physical: Arc<dyn crate::memory::traits::MemoryLayer>,
    kernel_base: Option<u64>,
    pid_filter: Option<&[u64]>,
    ps_head_override: Option<u64>,
) -> Result<Vec<ProcessDllList>, String> {
    let processes = super::pslist::run_with_head(symbols, kernel_vm, kernel_base, ps_head_override)?;
    let mut results = Vec::new();

    for proc in &processes {
        if let Some(pids) = pid_filter {
            if !pids.contains(&proc.pid) {
                continue;
            }
        }

        // Skip System/Idle — no user-space DLLs
        if proc.pid == 0 || proc.pid == 4 {
            results.push(ProcessDllList {
                pid: proc.pid,
                name: proc.name.clone(),
                dlls: Vec::new(),
            });
            continue;
        }

        match extract_dlls(symbols, kernel_vm, &physical, proc) {
            Ok(dll_list) => results.push(dll_list),
            Err(e) => {
                debug!("Failed to read DLLs for PID {}: {}", proc.pid, e);
                results.push(ProcessDllList {
                    pid: proc.pid,
                    name: proc.name.clone(),
                    dlls: Vec::new(),
                });
            }
        }
    }

    Ok(results)
}

/// Extract DLLs for a single process.
fn extract_dlls(
    symbols: &IsfSymbols,
    kernel_vm: &dyn MemoryAccess,
    physical: &Arc<dyn crate::memory::traits::MemoryLayer>,
    proc: &ProcessInfo,
) -> Result<ProcessDllList, String> {
    let reader = StructReader::new(symbols, kernel_vm, proc.offset, "_EPROCESS")
        .map_err(|e| format!("StructReader: {}", e))?;

    // Read process DTB
    let dtb = super::cmdline::read_process_dtb(symbols, kernel_vm, proc.offset)?;

    // Read PEB pointer
    let peb_addr = reader
        .read_pointer("Peb")
        .map_err(|e| format!("read Peb: {}", e))?;

    if peb_addr == 0 {
        return Ok(ProcessDllList {
            pid: proc.pid,
            name: proc.name.clone(),
            dlls: Vec::new(),
        });
    }

    // Create per-process VM
    let proc_vm = VirtualMemory::with_dtb(physical.clone(), dtb)
        .map_err(|e| format!("create process VM: {}", e))?;

    // Read _PEB.Ldr pointer
    let peb_reader = StructReader::new(symbols, &proc_vm, peb_addr, "_PEB")
        .map_err(|e| format!("PEB reader: {}", e))?;

    let ldr_addr = peb_reader
        .read_pointer("Ldr")
        .map_err(|e| format!("read Ldr: {}", e))?;

    if ldr_addr == 0 {
        return Ok(ProcessDllList {
            pid: proc.pid,
            name: proc.name.clone(),
            dlls: Vec::new(),
        });
    }

    // Walk InLoadOrderModuleList from _PEB_LDR_DATA
    let dlls = walk_module_list(symbols, &proc_vm, ldr_addr)?;

    Ok(ProcessDllList {
        pid: proc.pid,
        name: proc.name.clone(),
        dlls,
    })
}

/// Walk _PEB_LDR_DATA.InLoadOrderModuleList → _LDR_DATA_TABLE_ENTRY chain.
fn walk_module_list(
    symbols: &IsfSymbols,
    proc_vm: &dyn MemoryAccess,
    ldr_addr: u64,
) -> Result<Vec<DllInfo>, String> {
    // Get the InLoadOrderModuleList field within _PEB_LDR_DATA
    let list_field_offset = symbols
        .field_offset("_PEB_LDR_DATA", "InLoadOrderModuleList")
        .ok_or("field _PEB_LDR_DATA.InLoadOrderModuleList not found")?;

    let list_head_addr = ldr_addr + list_field_offset as u64;

    // The list entry offset within _LDR_DATA_TABLE_ENTRY
    let entry_offset = symbols
        .field_offset("_LDR_DATA_TABLE_ENTRY", "InLoadOrderLinks")
        .unwrap_or(0); // InLoadOrderLinks is typically at offset 0

    let ptr_size = symbols.pointer_size;
    let mut dlls = Vec::new();
    let mut current = read_pointer_raw(proc_vm, list_head_addr, ptr_size)?;
    let mut visited = HashSet::new();
    visited.insert(list_head_addr); // Mark head so cycle back is detected
    const MAX_DLLS: usize = 4096;

    while current != 0 && dlls.len() < MAX_DLLS {
        if !visited.insert(current) {
            break; // Cycle detected
        }

        // _LDR_DATA_TABLE_ENTRY base = current - entry_offset
        let entry_addr = current - entry_offset as u64;

        match read_ldr_entry(symbols, proc_vm, entry_addr) {
            Ok(dll) => dlls.push(dll),
            Err(e) => {
                debug!("Failed to read LDR entry at {:#x}: {}", entry_addr, e);
                break;
            }
        }

        // Follow Flink to next entry
        match read_pointer_raw(proc_vm, current, ptr_size) {
            Ok(next) => current = next,
            Err(e) => {
                debug!("Failed to read Flink at {:#x}: {}", current, e);
                break;
            }
        }
    }

    Ok(dlls)
}

/// Read a _LDR_DATA_TABLE_ENTRY and extract DLL info.
fn read_ldr_entry(
    symbols: &IsfSymbols,
    memory: &dyn MemoryAccess,
    addr: u64,
) -> Result<DllInfo, String> {
    let reader = StructReader::new(symbols, memory, addr, "_LDR_DATA_TABLE_ENTRY")
        .map_err(|e| format!("LDR entry reader: {}", e))?;

    // DllBase
    let base = reader.read_pointer("DllBase").unwrap_or(0);

    // SizeOfImage
    let size = reader.read_u32("SizeOfImage").unwrap_or(0) as u64;

    // BaseDllName (UNICODE_STRING — just the filename)
    let name = reader
        .read_unicode_string("BaseDllName")
        .unwrap_or_default();

    // FullDllName (UNICODE_STRING — full path)
    let path = reader
        .read_unicode_string("FullDllName")
        .ok()
        .filter(|s| !s.is_empty());

    Ok(DllInfo {
        base,
        size,
        name,
        path,
    })
}

/// Read a raw pointer from memory.
fn read_pointer_raw(
    memory: &dyn MemoryAccess,
    addr: u64,
    ptr_size: usize,
) -> Result<u64, String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dll_info_serialize() {
        let dll = DllInfo {
            base: 0x7FF6_0000_0000,
            size: 0x10000,
            name: "ntdll.dll".to_string(),
            path: Some("C:\\Windows\\System32\\ntdll.dll".to_string()),
        };
        let json = serde_json::to_string(&dll).unwrap();
        assert!(json.contains("ntdll.dll"));
    }

    #[test]
    fn test_process_dll_list_serialize() {
        let pdl = ProcessDllList {
            pid: 100,
            name: "test.exe".to_string(),
            dlls: vec![DllInfo {
                base: 0x1000,
                size: 0x2000,
                name: "test.dll".to_string(),
                path: None,
            }],
        };
        let json = serde_json::to_string(&pdl).unwrap();
        assert!(json.contains("test.dll"));
        assert!(!json.contains("path")); // None should be skipped
    }
}
