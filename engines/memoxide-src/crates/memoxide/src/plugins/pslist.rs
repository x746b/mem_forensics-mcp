//! PsList plugin — list processes by walking ActiveProcessLinks.
//!
//! Walks the kernel's `_EPROCESS.ActiveProcessLinks` doubly-linked list
//! starting from `PsActiveProcessHead`. This is the same approach as
//! Volatility3's `windows.pslist.PsList` plugin.

use crate::server::types::ProcessInfo;
use isf::{IsfSymbols, MemoryAccess, StructReader};
use std::collections::HashSet;
use tracing::{debug, warn};

/// Walk `PsActiveProcessHead` → `_EPROCESS.ActiveProcessLinks` and collect process info.
///
/// # Arguments
/// * `symbols` - Parsed ISF symbols containing `_EPROCESS`, `_LIST_ENTRY`, etc.
/// * `memory` - Virtual memory accessor (kernel address space)
/// * `kernel_base` - Optional kernel base address for symbol relocation
/// * `ps_head_override` - Optional override for PsActiveProcessHead virtual address
///   (e.g., from KDBG). When provided, this takes priority over ISF symbol + kernel_base.
#[allow(dead_code)]
pub fn run(
    symbols: &IsfSymbols,
    memory: &dyn MemoryAccess,
    kernel_base: Option<u64>,
) -> Result<Vec<ProcessInfo>, String> {
    run_with_head(symbols, memory, kernel_base, None)
}

/// Like [`run`], but with an optional PsActiveProcessHead override address.
///
/// When `ps_head_override` is provided, it is used directly as the virtual address
/// of PsActiveProcessHead, bypassing the ISF symbol lookup. This is needed when
/// the ISF file's symbol addresses don't match the exact kernel build (common with
/// hotfix/patch level differences).
pub fn run_with_head(
    symbols: &IsfSymbols,
    memory: &dyn MemoryAccess,
    kernel_base: Option<u64>,
    ps_head_override: Option<u64>,
) -> Result<Vec<ProcessInfo>, String> {
    let ps_head_addr = if let Some(addr) = ps_head_override {
        debug!("Using KDBG PsActiveProcessHead override: {:#x}", addr);
        addr
    } else {
        // Get PsActiveProcessHead address from symbols
        let ps_head_rva = symbols
            .get_symbol("PsActiveProcessHead")
            .ok_or("Symbol PsActiveProcessHead not found in ISF")?;

        // Apply kernel base relocation if provided
        if let Some(base) = kernel_base {
            base + ps_head_rva
        } else {
            ps_head_rva
        }
    };

    debug!("PsActiveProcessHead at {:#x}", ps_head_addr);

    // Verify _EPROCESS type exists
    if symbols.get_type("_EPROCESS").is_none() {
        return Err("Type _EPROCESS not found in ISF symbols".to_string());
    }

    // Get the offset of ActiveProcessLinks within _EPROCESS
    let links_offset = symbols
        .field_offset("_EPROCESS", "ActiveProcessLinks")
        .ok_or("Field _EPROCESS.ActiveProcessLinks not found")?;

    debug!("ActiveProcessLinks offset: {}", links_offset);

    // Walk the doubly-linked list with cycle detection via visited set
    let mut processes = Vec::new();
    let mut current_flink = read_pointer(symbols, memory, ps_head_addr)?;
    let head_addr = ps_head_addr;
    let mut visited = HashSet::new();
    visited.insert(head_addr); // Mark head as visited so we detect the cycle back
    const MAX_PROCESSES: usize = 2000;

    while current_flink != 0 && processes.len() < MAX_PROCESSES {
        // Cycle detection: stop if we've seen this flink address before
        if !visited.insert(current_flink) {
            debug!("Cycle detected at flink {:#x}, stopping walk", current_flink);
            break;
        }

        // Calculate _EPROCESS base from the list entry address
        let eprocess_addr = current_flink - links_offset as u64;

        match read_eprocess(symbols, memory, eprocess_addr) {
            Ok(proc) => {
                debug!("Found process: PID={} name={} at {:#x}", proc.pid, proc.name, eprocess_addr);
                processes.push(proc);
            }
            Err(e) => {
                warn!("Failed to read _EPROCESS at {:#x}: {}", eprocess_addr, e);
                break;
            }
        }

        // Follow Flink to next entry
        match read_pointer(symbols, memory, current_flink) {
            Ok(next) => current_flink = next,
            Err(e) => {
                warn!("Failed to read Flink at {:#x}: {}", current_flink, e);
                break;
            }
        }
    }

    if processes.len() >= MAX_PROCESSES {
        warn!("pslist hit MAX_PROCESSES limit ({}), results may be truncated", MAX_PROCESSES);
    }

    debug!("pslist found {} processes", processes.len());
    Ok(processes)
}

/// Read an _EPROCESS structure and extract process info.
fn read_eprocess(
    symbols: &IsfSymbols,
    memory: &dyn MemoryAccess,
    addr: u64,
) -> Result<ProcessInfo, String> {
    let reader = StructReader::new(symbols, memory, addr, "_EPROCESS")
        .map_err(|e| format!("StructReader error: {}", e))?;

    // PID
    let pid = reader
        .read_pointer("UniqueProcessId")
        .map_err(|e| format!("read PID: {}", e))?;

    // PPID (InheritedFromUniqueProcessId)
    let ppid = reader
        .read_pointer("InheritedFromUniqueProcessId")
        .unwrap_or(0);

    // ImageFileName (15-byte ASCII)
    let name = reader.read_string("ImageFileName", 15).unwrap_or_default();

    // Create time (Windows FILETIME: 100ns intervals since 1601-01-01)
    let create_time = reader
        .read_u64("CreateTime")
        .ok()
        .and_then(|t| filetime_to_iso(t));

    // Exit time
    let exit_time = reader
        .read_u64("ExitTime")
        .ok()
        .and_then(|t| filetime_to_iso(t));

    // Thread count
    let threads = reader.read_u32("ActiveThreads").ok();

    // Session ID
    let session_id = if symbols.field_offset("_EPROCESS", "SessionId").is_some() {
        reader.read_u32("SessionId").ok()
    } else {
        // Older versions use Session pointer → _MM_SESSION_SPACE.SessionId
        None
    };

    // Wow64 (32-bit process on 64-bit OS)
    let wow64 = if symbols.field_offset("_EPROCESS", "Wow64Process").is_some() {
        reader.read_pointer("Wow64Process").ok().map(|v| v != 0)
    } else {
        None
    };

    Ok(ProcessInfo {
        pid,
        ppid,
        name,
        offset: addr,
        create_time,
        exit_time,
        threads,
        handles: None,
        session_id,
        wow64,
    })
}

/// Read a pointer-sized value from memory.
fn read_pointer(symbols: &IsfSymbols, memory: &dyn MemoryAccess, addr: u64) -> Result<u64, String> {
    let ptr_size = symbols.pointer_size;
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

/// Convert Windows FILETIME (100ns since 1601-01-01) to ISO 8601 string.
pub fn filetime_to_iso(filetime: u64) -> Option<String> {
    if filetime == 0 {
        return None;
    }
    // Windows epoch offset from Unix epoch: 11644473600 seconds
    const WINDOWS_EPOCH_OFFSET: u64 = 11_644_473_600;
    let seconds = filetime / 10_000_000;
    if seconds < WINDOWS_EPOCH_OFFSET {
        return None;
    }
    let unix_seconds = seconds - WINDOWS_EPOCH_OFFSET;
    let nanos = ((filetime % 10_000_000) * 100) as u32;

    chrono::DateTime::from_timestamp(unix_seconds as i64, nanos)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::RwLock;

    /// Mock memory for testing.
    struct MockMemory {
        data: RwLock<Vec<u8>>,
    }

    impl MockMemory {
        fn new(size: usize) -> Self {
            MockMemory {
                data: RwLock::new(vec![0u8; size]),
            }
        }

        fn write_u64(&self, addr: u64, val: u64) {
            let mut data = self.data.write().unwrap();
            let a = addr as usize;
            if a + 8 <= data.len() {
                data[a..a + 8].copy_from_slice(&val.to_le_bytes());
            }
        }

        fn write_bytes(&self, addr: u64, bytes: &[u8]) {
            let mut data = self.data.write().unwrap();
            let a = addr as usize;
            if a + bytes.len() <= data.len() {
                data[a..a + bytes.len()].copy_from_slice(bytes);
            }
        }
    }

    impl MemoryAccess for MockMemory {
        fn read(
            &self,
            offset: u64,
            length: usize,
        ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
            let data = self.data.read().unwrap();
            let a = offset as usize;
            if a + length <= data.len() {
                Ok(data[a..a + length].to_vec())
            } else {
                Err(format!("out of bounds: {:#x}+{}", offset, length).into())
            }
        }

        fn is_valid(&self, offset: u64, length: u64) -> bool {
            let data = self.data.read().unwrap();
            (offset + length) as usize <= data.len()
        }
    }

    fn test_symbols() -> IsfSymbols {
        // Minimal ISF for testing: _EPROCESS with key fields
        let isf_json = r#"{
            "metadata": { "format": "6.2.0" },
            "base_types": {
                "pointer": { "size": 8, "signed": false, "kind": "int", "endian": "little" },
                "unsigned long": { "size": 4, "signed": false, "kind": "int", "endian": "little" },
                "unsigned long long": { "size": 8, "signed": false, "kind": "int", "endian": "little" },
                "unsigned char": { "size": 1, "signed": false, "kind": "int", "endian": "little" }
            },
            "user_types": {
                "_EPROCESS": {
                    "size": 800,
                    "fields": {
                        "UniqueProcessId": { "offset": 440, "type": { "kind": "pointer" } },
                        "InheritedFromUniqueProcessId": { "offset": 528, "type": { "kind": "pointer" } },
                        "ActiveProcessLinks": { "offset": 448, "type": { "kind": "struct", "name": "_LIST_ENTRY" } },
                        "ImageFileName": { "offset": 736, "type": { "kind": "array", "count": 15, "subtype": { "kind": "base", "name": "unsigned char" } } },
                        "CreateTime": { "offset": 768, "type": { "kind": "base", "name": "unsigned long long" } },
                        "ExitTime": { "offset": 776, "type": { "kind": "base", "name": "unsigned long long" } },
                        "ActiveThreads": { "offset": 784, "type": { "kind": "base", "name": "unsigned long" } }
                    }
                },
                "_LIST_ENTRY": {
                    "size": 16,
                    "fields": {
                        "Flink": { "offset": 0, "type": { "kind": "pointer" } },
                        "Blink": { "offset": 8, "type": { "kind": "pointer" } }
                    }
                }
            },
            "symbols": {
                "PsActiveProcessHead": { "address": 100 }
            },
            "enums": {}
        }"#;
        isf::parse_isf_str(isf_json).unwrap()
    }

    #[test]
    fn test_pslist_with_two_processes() {
        let symbols = test_symbols();
        let links_offset: u64 = 448;

        // Memory layout:
        // 100: PsActiveProcessHead (_LIST_ENTRY, Flink/Blink)
        //   -> points to proc1.ActiveProcessLinks (1000 + 448 = 1448)
        // 1000: _EPROCESS for "System" PID 4
        //   -> ActiveProcessLinks.Flink points to proc2 (2000 + 448 = 2448)
        // 2000: _EPROCESS for "csrss.exe" PID 512
        //   -> ActiveProcessLinks.Flink points back to PsActiveProcessHead (100)

        let mem = MockMemory::new(4096);

        // PsActiveProcessHead at addr 100: Flink → proc1 links
        let proc1_links = 1000 + links_offset;
        let proc2_links = 2000 + links_offset;
        mem.write_u64(100, proc1_links); // Flink
        mem.write_u64(108, proc2_links); // Blink

        // Process 1 at 1000: System, PID 4, PPID 0
        mem.write_u64(1000 + 440, 4); // UniqueProcessId
        mem.write_u64(1000 + 528, 0); // InheritedFromUniqueProcessId
        mem.write_u64(proc1_links, proc2_links); // ActiveProcessLinks.Flink → proc2
        mem.write_u64(proc1_links + 8, 100); // ActiveProcessLinks.Blink → head
        mem.write_bytes(1000 + 736, b"System\0");
        mem.write_u64(1000 + 784, 120); // ActiveThreads (write as u64, read as u32)

        // Process 2 at 2000: csrss.exe, PID 512, PPID 4
        mem.write_u64(2000 + 440, 512); // UniqueProcessId
        mem.write_u64(2000 + 528, 4); // InheritedFromUniqueProcessId
        mem.write_u64(proc2_links, 100); // ActiveProcessLinks.Flink → back to head
        mem.write_u64(proc2_links + 8, proc1_links); // Blink → proc1
        mem.write_bytes(2000 + 736, b"csrss.exe\0");
        mem.write_u64(2000 + 784, 15);

        let result = run(&symbols, &mem, None).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].pid, 4);
        assert_eq!(result[0].name, "System");
        assert_eq!(result[0].ppid, 0);
        assert_eq!(result[1].pid, 512);
        assert_eq!(result[1].name, "csrss.exe");
        assert_eq!(result[1].ppid, 4);
    }

    #[test]
    fn test_pslist_empty_list() {
        let symbols = test_symbols();
        let mem = MockMemory::new(4096);

        // PsActiveProcessHead points to itself (empty list)
        mem.write_u64(100, 100); // Flink → self
        mem.write_u64(108, 100); // Blink → self

        let result = run(&symbols, &mem, None).unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_pslist_with_kernel_base() {
        let symbols = test_symbols();
        let links_offset: u64 = 448;
        let kernel_base: u64 = 0x10000;

        // PsActiveProcessHead RVA = 100, actual addr = kernel_base + 100 = 0x10064
        let head_addr = kernel_base + 100;
        let proc1_links = 1000 + links_offset;

        let mem = MockMemory::new(0x20000);

        // Head at kernel_base + 100
        mem.write_u64(head_addr, proc1_links);
        mem.write_u64(head_addr + 8, proc1_links);

        // Process 1 at 1000
        mem.write_u64(1000 + 440, 4);
        mem.write_u64(1000 + 528, 0);
        mem.write_u64(proc1_links, head_addr); // Flink → back to head
        mem.write_u64(proc1_links + 8, head_addr);
        mem.write_bytes(1000 + 736, b"System\0");

        let result = run(&symbols, &mem, Some(kernel_base)).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].pid, 4);
        assert_eq!(result[0].name, "System");
    }

    #[test]
    fn test_filetime_to_iso() {
        let unix_ts: u64 = 1705312200;
        let filetime = (unix_ts + 11_644_473_600) * 10_000_000;
        let result = filetime_to_iso(filetime);
        assert!(result.is_some());
        assert!(result.unwrap().starts_with("2024-01-15"));
    }

    #[test]
    fn test_filetime_zero() {
        assert!(filetime_to_iso(0).is_none());
    }

    #[test]
    fn test_filetime_invalid() {
        assert!(filetime_to_iso(100).is_none());
    }
}
