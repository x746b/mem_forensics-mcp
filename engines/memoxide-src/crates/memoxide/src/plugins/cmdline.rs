//! CmdLine plugin — extract process command lines from PEB.
//!
//! Reads each process's command line from its Process Environment Block:
//! `_EPROCESS.Peb` → `_PEB.ProcessParameters` → `_RTL_USER_PROCESS_PARAMETERS.CommandLine`
//!
//! Since PEB and command lines live in user-space, each process needs its own
//! virtual memory layer (its own DTB/page tables).

use crate::memory::image::MemoryImage;
use crate::memory::virtual_memory::VirtualMemory;
use crate::server::types::ProcessInfo;
use isf::{IsfSymbols, MemoryAccess, StructReader};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::debug;

/// Command line information for a process.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CmdlineInfo {
    pub pid: u64,
    pub name: String,
    pub cmdline: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_path: Option<String>,
}

/// Extract command lines for all processes.
///
/// Uses the kernel virtual memory to walk the process list and read each
/// process's DTB, then creates per-process virtual memory to read the PEB.
///
/// # Arguments
/// * `symbols` - ISF symbols
/// * `kernel_vm` - Kernel virtual memory (for reading _EPROCESS)
/// * `physical` - Physical memory layer (for creating per-process VMs)
/// * `kernel_base` - Optional kernel base for symbol relocation
/// * `pid_filter` - Optional list of PIDs to restrict to
/// * `ps_head_override` - Optional PsActiveProcessHead VA override (from KDBG)
#[allow(dead_code)]
pub fn run(
    symbols: &IsfSymbols,
    kernel_vm: &dyn MemoryAccess,
    physical: Arc<dyn crate::memory::traits::MemoryLayer>,
    kernel_base: Option<u64>,
    pid_filter: Option<&[u64]>,
) -> Result<Vec<CmdlineInfo>, String> {
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
) -> Result<Vec<CmdlineInfo>, String> {
    // Get process list using pslist
    let processes = super::pslist::run_with_head(symbols, kernel_vm, kernel_base, ps_head_override)?;

    let mut results = Vec::new();

    for proc in &processes {
        // Filter by PID if requested
        if let Some(pids) = pid_filter {
            if !pids.contains(&proc.pid) {
                continue;
            }
        }

        // Skip System (PID 0/4) — no user-space PEB
        if proc.pid == 0 || proc.pid == 4 {
            results.push(CmdlineInfo {
                pid: proc.pid,
                name: proc.name.clone(),
                cmdline: String::new(),
                image_path: None,
            });
            continue;
        }

        match extract_cmdline(symbols, kernel_vm, &physical, proc) {
            Ok(info) => results.push(info),
            Err(e) => {
                debug!("Failed to read cmdline for PID {}: {}", proc.pid, e);
                results.push(CmdlineInfo {
                    pid: proc.pid,
                    name: proc.name.clone(),
                    cmdline: format!("<error: {}>", e),
                    image_path: None,
                });
            }
        }
    }

    Ok(results)
}

/// Extract command line for a single process.
fn extract_cmdline(
    symbols: &IsfSymbols,
    kernel_vm: &dyn MemoryAccess,
    physical: &Arc<dyn crate::memory::traits::MemoryLayer>,
    proc: &ProcessInfo,
) -> Result<CmdlineInfo, String> {
    // Read _EPROCESS at the process's virtual address
    let reader = StructReader::new(symbols, kernel_vm, proc.offset, "_EPROCESS")
        .map_err(|e| format!("StructReader: {}", e))?;

    // Get the process's DTB from _EPROCESS.Pcb.DirectoryTableBase
    let dtb = read_process_dtb(symbols, kernel_vm, proc.offset)?;

    // Get PEB pointer (this is a user-space VA)
    let peb_addr = reader
        .read_pointer("Peb")
        .map_err(|e| format!("read Peb: {}", e))?;

    if peb_addr == 0 {
        return Ok(CmdlineInfo {
            pid: proc.pid,
            name: proc.name.clone(),
            cmdline: String::new(),
            image_path: None,
        });
    }

    // Create per-process virtual memory
    let proc_vm = VirtualMemory::with_dtb(physical.clone(), dtb)
        .map_err(|e| format!("create process VM: {}", e))?;

    // Read _PEB.ProcessParameters pointer
    let peb_reader = StructReader::new(symbols, &proc_vm, peb_addr, "_PEB")
        .map_err(|e| format!("PEB reader: {}", e))?;

    let params_addr = peb_reader
        .read_pointer("ProcessParameters")
        .map_err(|e| format!("read ProcessParameters: {}", e))?;

    if params_addr == 0 {
        return Ok(CmdlineInfo {
            pid: proc.pid,
            name: proc.name.clone(),
            cmdline: String::new(),
            image_path: None,
        });
    }

    // Read _RTL_USER_PROCESS_PARAMETERS
    let params_reader =
        StructReader::new(symbols, &proc_vm, params_addr, "_RTL_USER_PROCESS_PARAMETERS")
            .map_err(|e| format!("params reader: {}", e))?;

    // Read CommandLine (_UNICODE_STRING)
    let cmdline = params_reader
        .read_unicode_string("CommandLine")
        .unwrap_or_default();

    // Read ImagePathName (_UNICODE_STRING)
    let image_path = params_reader
        .read_unicode_string("ImagePathName")
        .ok()
        .filter(|s| !s.is_empty());

    Ok(CmdlineInfo {
        pid: proc.pid,
        name: proc.name.clone(),
        cmdline,
        image_path,
    })
}

/// Read a process's DTB from _EPROCESS.Pcb.DirectoryTableBase.
///
/// _EPROCESS starts with _KPROCESS (the Pcb field at offset 0),
/// and DirectoryTableBase is within _KPROCESS.
pub fn read_process_dtb(
    symbols: &IsfSymbols,
    memory: &dyn MemoryAccess,
    eprocess_addr: u64,
) -> Result<u64, String> {
    // Try ISF-based offset: _EPROCESS.Pcb → _KPROCESS.DirectoryTableBase
    let pcb_offset = symbols.field_offset("_EPROCESS", "Pcb").unwrap_or(0);
    let dtb_offset = symbols
        .field_offset("_KPROCESS", "DirectoryTableBase")
        .unwrap_or(0x28); // Fallback: common x64 offset

    let dtb_addr = eprocess_addr + pcb_offset as u64 + dtb_offset as u64;

    let bytes = memory
        .read(dtb_addr, 8)
        .map_err(|e| format!("read DTB at {:#x}: {}", dtb_addr, e))?;

    let dtb = u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);

    // DTB should be page-aligned
    if dtb == 0 {
        return Err("DTB is zero".to_string());
    }

    // Mask off any PCID bits (lower 12 bits are flags on some CPUs)
    Ok(dtb & !0xFFF)
}

/// Extract command lines using physical memory (psscan-based).
/// For processes found via psscan where we have physical _EPROCESS offsets.
#[allow(dead_code)]
pub fn run_physical(
    symbols: &IsfSymbols,
    image: &MemoryImage,
    physical: Arc<dyn crate::memory::traits::MemoryLayer>,
    processes: &[ProcessInfo],
) -> Result<Vec<CmdlineInfo>, String> {
    let mut results = Vec::new();

    for proc in processes {
        if proc.pid == 0 || proc.pid == 4 {
            results.push(CmdlineInfo {
                pid: proc.pid,
                name: proc.name.clone(),
                cmdline: String::new(),
                image_path: None,
            });
            continue;
        }

        match extract_cmdline_physical(symbols, image, &physical, proc) {
            Ok(info) => results.push(info),
            Err(e) => {
                debug!(
                    "Failed to read cmdline for PID {} (physical): {}",
                    proc.pid, e
                );
                results.push(CmdlineInfo {
                    pid: proc.pid,
                    name: proc.name.clone(),
                    cmdline: format!("<error: {}>", e),
                    image_path: None,
                });
            }
        }
    }

    Ok(results)
}

/// Extract command line for a process at a physical _EPROCESS address.
#[allow(dead_code)]
fn extract_cmdline_physical(
    symbols: &IsfSymbols,
    image: &MemoryImage,
    physical: &Arc<dyn crate::memory::traits::MemoryLayer>,
    proc: &ProcessInfo,
) -> Result<CmdlineInfo, String> {
    // Read DTB from physical _EPROCESS
    let dtb = read_process_dtb(symbols, image, proc.offset)?;

    // Read PEB pointer from physical memory
    let peb_offset = symbols
        .field_offset("_EPROCESS", "Peb")
        .ok_or("field _EPROCESS.Peb not found")?;
    let peb_bytes = image
        .read(proc.offset + peb_offset as u64, 8)
        .map_err(|e| format!("read Peb: {}", e))?;
    let peb_addr = u64::from_le_bytes([
        peb_bytes[0],
        peb_bytes[1],
        peb_bytes[2],
        peb_bytes[3],
        peb_bytes[4],
        peb_bytes[5],
        peb_bytes[6],
        peb_bytes[7],
    ]);

    if peb_addr == 0 {
        return Ok(CmdlineInfo {
            pid: proc.pid,
            name: proc.name.clone(),
            cmdline: String::new(),
            image_path: None,
        });
    }

    // Create per-process virtual memory
    let proc_vm = VirtualMemory::with_dtb(physical.clone(), dtb)
        .map_err(|e| format!("create process VM: {}", e))?;

    // Read command line from PEB
    let peb_reader = StructReader::new(symbols, &proc_vm, peb_addr, "_PEB")
        .map_err(|e| format!("PEB reader: {}", e))?;

    let params_addr = peb_reader
        .read_pointer("ProcessParameters")
        .map_err(|e| format!("read ProcessParameters: {}", e))?;

    if params_addr == 0 {
        return Ok(CmdlineInfo {
            pid: proc.pid,
            name: proc.name.clone(),
            cmdline: String::new(),
            image_path: None,
        });
    }

    let params_reader =
        StructReader::new(symbols, &proc_vm, params_addr, "_RTL_USER_PROCESS_PARAMETERS")
            .map_err(|e| format!("params reader: {}", e))?;

    let cmdline = params_reader
        .read_unicode_string("CommandLine")
        .unwrap_or_default();

    let image_path = params_reader
        .read_unicode_string("ImagePathName")
        .ok()
        .filter(|s| !s.is_empty());

    Ok(CmdlineInfo {
        pid: proc.pid,
        name: proc.name.clone(),
        cmdline,
        image_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cmdline_info_serialize() {
        let info = CmdlineInfo {
            pid: 1234,
            name: "test.exe".to_string(),
            cmdline: "test.exe --flag".to_string(),
            image_path: Some("C:\\Windows\\test.exe".to_string()),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("test.exe --flag"));
        assert!(json.contains("1234"));
    }

    #[test]
    fn test_cmdline_info_no_image_path() {
        let info = CmdlineInfo {
            pid: 1,
            name: "a.exe".to_string(),
            cmdline: "a.exe".to_string(),
            image_path: None,
        };
        let json = serde_json::to_string(&info).unwrap();
        // image_path should be omitted when None
        assert!(!json.contains("image_path"));
    }
}
