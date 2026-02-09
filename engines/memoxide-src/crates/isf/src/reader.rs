//! StructReader — reads Windows kernel structures from memory using ISF offsets.
//!
//! This is the bridge between ISF symbol definitions and raw memory. Given a
//! base address and a struct type name, it reads individual fields using the
//! offsets from the ISF file.

use crate::error::{IsfError, IsfResult};
use crate::types::IsfSymbols;

/// Trait for reading raw bytes from memory (physical or virtual).
/// This is intentionally identical in shape to voxide's `MemoryLayer` trait,
/// but defined here to avoid a crate dependency cycle.
pub trait MemoryAccess: Send + Sync {
    fn read(&self, offset: u64, length: usize) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>;
    fn is_valid(&self, offset: u64, length: u64) -> bool;
}

/// Reads fields from a kernel structure at a given base address.
///
/// # Example
///
/// ```rust,ignore
/// let reader = StructReader::new(&symbols, &memory, base_addr, "_EPROCESS")?;
/// let pid = reader.read_pointer("UniqueProcessId")?;
/// let links_reader = reader.nested("ActiveProcessLinks", "_LIST_ENTRY")?;
/// ```
pub struct StructReader<'a> {
    symbols: &'a IsfSymbols,
    memory: &'a dyn MemoryAccess,
    base_addr: u64,
    type_name: String,
}

impl<'a> StructReader<'a> {
    /// Create a new StructReader for a struct at the given virtual/physical address.
    pub fn new(
        symbols: &'a IsfSymbols,
        memory: &'a dyn MemoryAccess,
        base_addr: u64,
        type_name: &str,
    ) -> IsfResult<Self> {
        // Verify the type exists
        if !symbols.user_types.contains_key(type_name) {
            return Err(IsfError::TypeNotFound(type_name.to_string()));
        }
        Ok(StructReader {
            symbols,
            memory,
            base_addr,
            type_name: type_name.to_string(),
        })
    }

    /// The base address of this struct in memory.
    pub fn base_addr(&self) -> u64 {
        self.base_addr
    }

    /// The type name of this struct.
    pub fn type_name(&self) -> &str {
        &self.type_name
    }

    /// Get the offset of a field within this struct.
    fn field_offset(&self, field: &str) -> IsfResult<usize> {
        self.symbols
            .field_offset(&self.type_name, field)
            .ok_or_else(|| IsfError::FieldNotFound {
                type_name: self.type_name.clone(),
                field: field.to_string(),
            })
    }

    /// Read raw bytes at a field's offset.
    pub fn read_field_bytes(&self, field: &str, length: usize) -> IsfResult<Vec<u8>> {
        let offset = self.field_offset(field)?;
        let addr = self.base_addr + offset as u64;
        self.memory
            .read(addr, length)
            .map_err(|e| IsfError::MemoryRead {
                offset: addr,
                msg: e.to_string(),
            })
    }

    /// Read raw bytes at a specific offset from base.
    pub fn read_at_offset(&self, offset: usize, length: usize) -> IsfResult<Vec<u8>> {
        let addr = self.base_addr + offset as u64;
        self.memory
            .read(addr, length)
            .map_err(|e| IsfError::MemoryRead {
                offset: addr,
                msg: e.to_string(),
            })
    }

    /// Read a u8 field.
    pub fn read_u8(&self, field: &str) -> IsfResult<u8> {
        let bytes = self.read_field_bytes(field, 1)?;
        Ok(bytes[0])
    }

    /// Read a u16 (little-endian) field.
    pub fn read_u16(&self, field: &str) -> IsfResult<u16> {
        let bytes = self.read_field_bytes(field, 2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Read a u32 (little-endian) field.
    pub fn read_u32(&self, field: &str) -> IsfResult<u32> {
        let bytes = self.read_field_bytes(field, 4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read a u64 (little-endian) field.
    pub fn read_u64(&self, field: &str) -> IsfResult<u64> {
        let bytes = self.read_field_bytes(field, 8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Read an i32 (little-endian) field.
    pub fn read_i32(&self, field: &str) -> IsfResult<i32> {
        let bytes = self.read_field_bytes(field, 4)?;
        Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read an i64 (little-endian) field.
    pub fn read_i64(&self, field: &str) -> IsfResult<i64> {
        let bytes = self.read_field_bytes(field, 8)?;
        Ok(i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Read a pointer-sized value (4 or 8 bytes depending on ISF pointer_size).
    pub fn read_pointer(&self, field: &str) -> IsfResult<u64> {
        match self.symbols.pointer_size {
            4 => self.read_u32(field).map(|v| v as u64),
            8 => self.read_u64(field),
            n => Err(IsfError::MemoryRead {
                offset: self.base_addr,
                msg: format!("unsupported pointer size: {}", n),
            }),
        }
    }

    /// Read a pointer at a raw address (not field-based).
    pub fn read_pointer_at(&self, addr: u64) -> IsfResult<u64> {
        let length = self.symbols.pointer_size;
        let bytes = self.memory.read(addr, length).map_err(|e| IsfError::MemoryRead {
            offset: addr,
            msg: e.to_string(),
        })?;
        match length {
            4 => Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64),
            8 => Ok(u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3],
                bytes[4], bytes[5], bytes[6], bytes[7],
            ])),
            _ => Err(IsfError::MemoryRead {
                offset: addr,
                msg: format!("unsupported pointer size: {}", length),
            }),
        }
    }

    /// Read a fixed-size byte array field (e.g., ImageFileName[15]).
    pub fn read_bytes(&self, field: &str, length: usize) -> IsfResult<Vec<u8>> {
        self.read_field_bytes(field, length)
    }

    /// Read a null-terminated ASCII string from a byte array field.
    pub fn read_string(&self, field: &str, max_length: usize) -> IsfResult<String> {
        let bytes = self.read_field_bytes(field, max_length)?;
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
    }

    /// Read a `_UNICODE_STRING` structure: { Length: u16, MaximumLength: u16, Buffer: ptr }.
    ///
    /// Follows the Buffer pointer and reads `Length` bytes of UTF-16LE data.
    pub fn read_unicode_string(&self, field: &str) -> IsfResult<String> {
        let offset = self.field_offset(field)?;
        let addr = self.base_addr + offset as u64;

        // _UNICODE_STRING layout: Length (u16) | MaximumLength (u16) | [padding] | Buffer (ptr)
        let length_bytes = self.memory.read(addr, 2).map_err(|e| IsfError::MemoryRead {
            offset: addr,
            msg: e.to_string(),
        })?;
        let length = u16::from_le_bytes([length_bytes[0], length_bytes[1]]) as usize;

        if length == 0 {
            return Ok(String::new());
        }

        // Buffer pointer is at offset 8 on 64-bit (after Length u16, MaxLen u16, 4 bytes padding)
        // or offset 4 on 32-bit (after Length u16, MaxLen u16, no padding)
        let buf_ptr_offset = if self.symbols.pointer_size == 8 { 8 } else { 4 };
        let buf_ptr_addr = addr + buf_ptr_offset;
        let buf_ptr = self.read_pointer_at(buf_ptr_addr)?;

        if buf_ptr == 0 {
            return Ok(String::new());
        }

        // Read the UTF-16LE buffer
        let buf = self.memory.read(buf_ptr, length).map_err(|e| IsfError::MemoryRead {
            offset: buf_ptr,
            msg: e.to_string(),
        })?;

        // Decode UTF-16LE
        let u16_values: Vec<u16> = buf
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();

        Ok(String::from_utf16_lossy(&u16_values))
    }

    /// Create a sub-reader for an embedded (nested) struct field.
    ///
    /// The nested struct's base address = this struct's base + field offset.
    pub fn nested(&self, field: &str, nested_type: &str) -> IsfResult<StructReader<'a>> {
        let offset = self.field_offset(field)?;
        let nested_addr = self.base_addr + offset as u64;
        StructReader::new(self.symbols, self.memory, nested_addr, nested_type)
    }

    /// Create a reader for a struct at a pointer field's target address.
    ///
    /// Reads the pointer value, then creates a reader at that address.
    pub fn deref(&self, field: &str, target_type: &str) -> IsfResult<StructReader<'a>> {
        let ptr = self.read_pointer(field)?;
        if ptr == 0 {
            return Err(IsfError::InvalidPointer(0));
        }
        StructReader::new(self.symbols, self.memory, ptr, target_type)
    }

    /// Iterate over a doubly-linked list (`_LIST_ENTRY`).
    ///
    /// Starting from a `_LIST_ENTRY` field in this struct, follows `Flink` pointers
    /// until we loop back to the start. Returns the base addresses of the containing
    /// structs (adjusted by the list entry's offset within the containing struct).
    ///
    /// # Arguments
    ///
    /// * `field` - The `_LIST_ENTRY` field name in this struct
    /// * `containing_type` - The struct type that contains the list entry (e.g., `_EPROCESS`)
    /// * `containing_field` - The field name of the list entry within the containing type
    pub fn walk_list(
        &self,
        field: &str,
        containing_type: &str,
        containing_field: &str,
    ) -> IsfResult<ListIterator<'a>> {
        let list_offset = self.field_offset(field)?;
        let list_head_addr = self.base_addr + list_offset as u64;

        // The offset of the _LIST_ENTRY within the containing struct
        let entry_offset = self.symbols.field_offset(containing_type, containing_field)
            .ok_or_else(|| IsfError::FieldNotFound {
                type_name: containing_type.to_string(),
                field: containing_field.to_string(),
            })?;

        Ok(ListIterator {
            symbols: self.symbols,
            memory: self.memory,
            head_addr: list_head_addr,
            current_addr: list_head_addr,
            entry_offset: entry_offset as u64,
            containing_type: containing_type.to_string(),
            started: false,
            max_iterations: 65536, // Safety limit
            iteration_count: 0,
        })
    }
}

/// Iterator over a `_LIST_ENTRY` doubly-linked list.
///
/// Yields `StructReader` instances for each element in the list.
pub struct ListIterator<'a> {
    symbols: &'a IsfSymbols,
    memory: &'a dyn MemoryAccess,
    /// Address of the list head (sentinel).
    head_addr: u64,
    /// Current Flink pointer.
    current_addr: u64,
    /// Offset of the _LIST_ENTRY field within the containing struct.
    entry_offset: u64,
    /// The containing struct type name.
    containing_type: String,
    /// Whether we've read the first Flink yet.
    started: bool,
    /// Maximum iterations to prevent infinite loops on corrupted data.
    max_iterations: usize,
    iteration_count: usize,
}

impl<'a> ListIterator<'a> {
    /// Get the next entry in the list, or None if we've looped back.
    pub fn next_entry(&mut self) -> IsfResult<Option<StructReader<'a>>> {
        if self.iteration_count >= self.max_iterations {
            return Ok(None);
        }

        // Read the Flink pointer at current position
        let flink = {
            let ptr_size = self.symbols.pointer_size;
            let bytes = self.memory.read(self.current_addr, ptr_size).map_err(|e| {
                IsfError::MemoryRead {
                    offset: self.current_addr,
                    msg: e.to_string(),
                }
            })?;
            match ptr_size {
                4 => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
                8 => u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7],
                ]),
                _ => return Ok(None),
            }
        };

        if !self.started {
            self.started = true;
            self.current_addr = flink;

            // Check if the list is empty (Flink points to itself)
            if flink == self.head_addr || flink == 0 {
                return Ok(None);
            }
        } else {
            // We've been iterating — check if we've looped back
            if flink == self.head_addr || flink == 0 {
                return Ok(None);
            }
            self.current_addr = flink;
        }

        self.iteration_count += 1;

        // Calculate the containing struct's base address
        let struct_base = self.current_addr - self.entry_offset;

        let reader =
            StructReader::new(self.symbols, self.memory, struct_base, &self.containing_type)?;
        Ok(Some(reader))
    }

    /// Collect all entries into a vector.
    pub fn collect_all(&mut self) -> IsfResult<Vec<StructReader<'a>>> {
        let mut results = Vec::new();
        while let Some(entry) = self.next_entry()? {
            results.push(entry);
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_isf_str;
    use std::collections::HashMap;
    use std::sync::RwLock;

    /// Mock memory for testing.
    struct MockMemory {
        data: RwLock<HashMap<u64, Vec<u8>>>,
    }

    impl MockMemory {
        fn new() -> Self {
            MockMemory {
                data: RwLock::new(HashMap::new()),
            }
        }

        fn write(&self, addr: u64, bytes: &[u8]) {
            let mut data = self.data.write().unwrap();
            data.insert(addr, bytes.to_vec());
        }
    }

    impl MemoryAccess for MockMemory {
        fn read(&self, offset: u64, length: usize) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
            let data = self.data.read().unwrap();
            // Find the block that contains this offset
            for (&block_addr, block_data) in data.iter() {
                if offset >= block_addr && offset < block_addr + block_data.len() as u64 {
                    let start = (offset - block_addr) as usize;
                    let end = start + length;
                    if end <= block_data.len() {
                        return Ok(block_data[start..end].to_vec());
                    }
                }
            }
            Err(format!("no data at offset {:#x}", offset).into())
        }

        fn is_valid(&self, offset: u64, length: u64) -> bool {
            let data = self.data.read().unwrap();
            for (&block_addr, block_data) in data.iter() {
                if offset >= block_addr && offset + length <= block_addr + block_data.len() as u64 {
                    return true;
                }
            }
            false
        }
    }

    const TEST_ISF: &str = r#"{
        "metadata": { "format": "6.2.0" },
        "base_types": {
            "pointer": { "size": 8, "signed": false, "kind": "int", "endian": "little" },
            "unsigned long": { "size": 4, "signed": false, "kind": "int", "endian": "little" },
            "unsigned char": { "size": 1, "signed": false, "kind": "int", "endian": "little" }
        },
        "user_types": {
            "_EPROCESS": {
                "size": 800,
                "fields": {
                    "UniqueProcessId": { "offset": 440, "type": { "kind": "pointer" } },
                    "ActiveProcessLinks": { "offset": 448, "type": { "kind": "struct", "name": "_LIST_ENTRY" } },
                    "ImageFileName": { "offset": 736, "type": { "kind": "array", "count": 15, "subtype": { "kind": "base", "name": "unsigned char" } } }
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
            "PsActiveProcessHead": { "address": 1000 }
        },
        "enums": {}
    }"#;

    #[test]
    fn test_read_u32_field() {
        let symbols = parse_isf_str(TEST_ISF).unwrap();
        let mem = MockMemory::new();

        // Write a process at address 0x1000
        // UniqueProcessId (offset 440) = 1234
        let mut proc_data = vec![0u8; 800];
        let pid: u64 = 1234;
        proc_data[440..448].copy_from_slice(&pid.to_le_bytes());
        // ImageFileName (offset 736) = "System\0"
        let name = b"System\0";
        proc_data[736..736 + name.len()].copy_from_slice(name);
        mem.write(0x1000, &proc_data);

        let reader = StructReader::new(&symbols, &mem, 0x1000, "_EPROCESS").unwrap();

        // Read PID
        let pid = reader.read_pointer("UniqueProcessId").unwrap();
        assert_eq!(pid, 1234);

        // Read image name
        let name = reader.read_string("ImageFileName", 15).unwrap();
        assert_eq!(name, "System");
    }

    #[test]
    fn test_type_not_found() {
        let symbols = parse_isf_str(TEST_ISF).unwrap();
        let mem = MockMemory::new();

        let result = StructReader::new(&symbols, &mem, 0x1000, "_NONEXISTENT");
        assert!(result.is_err());
    }

    #[test]
    fn test_field_not_found() {
        let symbols = parse_isf_str(TEST_ISF).unwrap();
        let mem = MockMemory::new();
        mem.write(0x1000, &vec![0u8; 800]);

        let reader = StructReader::new(&symbols, &mem, 0x1000, "_EPROCESS").unwrap();
        let result = reader.read_u32("NonExistentField");
        assert!(result.is_err());
    }
}
