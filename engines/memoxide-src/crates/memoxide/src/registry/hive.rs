//! Registry hive discovery and parsing from memory.
//!
//! Two approaches:
//! 1. **Virtual memory (preferred)**: Use ISF `_CMHIVE` structures to find hives via
//!    kernel linked list, then read hive data through the kernel virtual address space.
//! 2. **Physical memory fallback**: Scan for `regf` (HBASE_BLOCK signature) in physical
//!    memory, then read contiguous bins from there.
//!
//! Registry on-disk/in-memory format:
//! ```text
//! +0x0000  HBASE_BLOCK ("regf" signature, 4096 bytes)
//!   +0x0000  Signature: "regf" (4 bytes)
//!   +0x0030  RootCellOffset (u32) — offset of root NK cell within hive data
//!   +0x0028  HiveLength (u32) — total hive data length
//! +0x1000  HBIN #0 ("hbin" signature)
//!   +0x0000  Signature: "hbin" (4 bytes)
//!   +0x0004  FileOffset (u32)
//!   +0x0008  Size (u32)
//!   Then cells: each cell is |size(i32)|data...|
//!     - Allocated cells have negative size (absolute value = cell size)
//!     - Free cells have positive size
//!   Cell types identified by 2-byte signature:
//!     "nk" — key node (CM_KEY_NODE)
//!     "vk" — key value (CM_KEY_VALUE)
//!     "lf"/"lh" — fast-leaf subkey list
//!     "ri" — index root (for large subkey counts)
//!     "li" — leaf index
//!     "sk" — security descriptor
//! ```

#[allow(unused_imports)]
use crate::memory::image::MemoryImage;
use isf::MemoryAccess;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::debug;

// ── Constants ────────────────────────────────────────────────────────

const REGF_SIGNATURE: &[u8; 4] = b"regf";
const HBIN_SIGNATURE: &[u8; 4] = b"hbin";
const NK_SIGNATURE: u16 = 0x6B6E; // "nk" little-endian
const VK_SIGNATURE: u16 = 0x6B76; // "vk" little-endian
const LF_SIGNATURE: u16 = 0x666C; // "lf" little-endian
const LH_SIGNATURE: u16 = 0x686C; // "lh" little-endian
const RI_SIGNATURE: u16 = 0x6972; // "ri" little-endian
const LI_SIGNATURE: u16 = 0x696C; // "li" little-endian

/// HBASE_BLOCK is always 4096 bytes.
const HBASE_BLOCK_SIZE: u64 = 4096;

/// Offset of RootCellOffset within HBASE_BLOCK.
const REGF_ROOT_CELL_OFFSET: u64 = 0x24;
/// Offset of hive data length in HBASE_BLOCK.
const REGF_HIVE_LENGTH: u64 = 0x28;

// NK cell offsets (relative to cell data start, after the 4-byte size + 2-byte sig)
const NK_FLAGS: usize = 2;        // u16 at offset 2 from sig
const NK_TIMESTAMP: usize = 4;    // FILETIME at offset 4 from sig
const NK_PARENT: usize = 16;      // u32 at offset 16 from sig  (parent cell offset)
const NK_SUBKEY_COUNT: usize = 20; // u32 at offset 20 from sig
const NK_SUBKEY_LIST: usize = 28;  // u32 at offset 28 from sig (subkey list cell offset)
const NK_VALUE_COUNT: usize = 36;  // u32 at offset 36 from sig
const NK_VALUE_LIST: usize = 40;   // u32 at offset 40 from sig (value list cell offset)
const NK_CLASS_NAME_OFFSET: usize = 48; // u32 at offset 48 from sig
const NK_CLASS_NAME_LENGTH: usize = 74; // u16 at offset 74 from sig (ClassLength)
const NK_NAME_LENGTH: usize = 72;  // u16 at offset 72 from sig
const NK_NAME_START: usize = 76;   // name bytes start here

/// NK flag: KEY_HIVE_ENTRY (root key of the hive).
const KEY_HIVE_ENTRY: u16 = 0x0004;
/// NK flag: KEY_COMP_NAME (name is ASCII, not UTF-16).
const KEY_COMP_NAME: u16 = 0x0020;

// VK cell offsets (relative to sig start)
const VK_NAME_LENGTH: usize = 2;   // u16
const VK_DATA_LENGTH: usize = 4;   // u32
const VK_DATA_OFFSET: usize = 8;   // u32 (cell offset of data, or inline if small)
const VK_TYPE: usize = 12;         // u32
const VK_FLAGS: usize = 16;        // u16
const VK_NAME_START: usize = 20;   // name bytes start here

/// VK flag: value name is ASCII (compressed).
const VALUE_COMP_NAME: u16 = 0x0001;

// ── Hive discovery ───────────────────────────────────────────────────

/// A discovered registry hive in memory.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RegistryHive {
    /// Physical offset of the HBASE_BLOCK ("regf" header).
    pub regf_offset: u64,
    /// Hive data length from the header.
    pub hive_length: u32,
    /// Root cell offset (relative to hive data, i.e., after HBASE_BLOCK).
    pub root_cell_offset: u32,
    /// Hive file name (from the header, e.g., `\REGISTRY\MACHINE\SAM`).
    pub hive_name: String,
    /// Whether the root NK cell is readable and has a valid NK signature.
    /// False means hive data is likely paged out.
    #[serde(default)]
    pub valid_root: bool,
}

/// Scan physical memory for registry hive base blocks ("regf" signatures).
pub fn find_hives(image: &MemoryImage, chunk_size: usize) -> Result<Vec<RegistryHive>, String> {
    let image_size = image.size();
    let mut hives = Vec::new();
    let mut offset: u64 = 0;

    debug!("registry: scanning {} bytes for regf signatures", image_size);

    while offset < image_size {
        let read_len = std::cmp::min(chunk_size, (image_size - offset) as usize);
        let chunk = match image.read(offset, read_len) {
            Ok(c) => c,
            Err(_) => {
                offset += chunk_size as u64;
                continue;
            }
        };

        // Scan for "regf" signature (page-aligned: regf headers are always at page boundaries)
        let mut pos = 0;
        while pos + 4 <= chunk.len() {
            if &chunk[pos..pos + 4] == REGF_SIGNATURE {
                let abs_offset = offset + pos as u64;

                // regf should be page-aligned
                if abs_offset % 4096 != 0 {
                    pos += 4096 - (pos % 4096).max(1);
                    continue;
                }

                if let Some(mut hive) = parse_regf_header(image, abs_offset) {
                    hive.valid_root = validate_root_nk(image, &hive);
                    debug!(
                        "registry: found hive '{}' at {:#x} (length={}, valid_root={})",
                        hive.hive_name, abs_offset, hive.hive_length, hive.valid_root
                    );
                    hives.push(hive);
                }
                pos += 4096;
            } else {
                // Skip to next page boundary
                pos += 4096 - (pos % 4096).max(1);
                if pos % 4096 != 0 {
                    pos = (pos + 4095) & !4095;
                }
            }
        }

        offset += chunk_size as u64;
    }

    debug!("registry: found {} hives", hives.len());
    Ok(hives)
}

/// Parse the HBASE_BLOCK (regf header) at the given physical offset.
fn parse_regf_header(image: &MemoryImage, offset: u64) -> Option<RegistryHive> {
    let header = image.read(offset, HBASE_BLOCK_SIZE as usize).ok()?;

    // Verify signature
    if &header[0..4] != REGF_SIGNATURE {
        return None;
    }

    // Sequence numbers at +0x04 and +0x08 should match (unless hive is dirty)
    let seq1 = u32::from_le_bytes(header[4..8].try_into().ok()?);
    let seq2 = u32::from_le_bytes(header[8..12].try_into().ok()?);

    // Root cell offset at +0x24
    let root_cell_offset = u32::from_le_bytes(header[0x24..0x28].try_into().ok()?);

    // Hive data length at +0x28
    let hive_length = u32::from_le_bytes(header[0x28..0x2C].try_into().ok()?);

    // Basic sanity: root_cell_offset should be within hive length, and both non-zero
    if root_cell_offset == 0 || hive_length == 0 {
        return None;
    }
    if root_cell_offset >= hive_length {
        return None;
    }

    // Hive path at +0x30 (UTF-16LE, up to 255 wchars = 510 bytes)
    let name_bytes = &header[0x30..std::cmp::min(0x30 + 510, header.len())];
    let hive_name = read_utf16le_string(name_bytes);

    // Relax sequence check — dirty hives can have mismatched sequences
    // but verify at least one is non-zero
    if seq1 == 0 && seq2 == 0 {
        return None;
    }

    Some(RegistryHive {
        regf_offset: offset,
        hive_length,
        root_cell_offset,
        hive_name,
        valid_root: false, // Caller sets this via validate_root_nk()
    })
}

/// Check if the root NK cell is readable and has the correct "nk" signature.
/// Returns false if hive data is paged out or corrupt.
fn validate_root_nk(image: &MemoryImage, hive: &RegistryHive) -> bool {
    // Root NK cell lives at: regf_offset + 0x1000 (HBASE_BLOCK) + root_cell_offset
    // Cell format: i32 size | u16 sig ("nk")  →  we need 6 bytes
    let addr = hive.regf_offset + HBASE_BLOCK_SIZE + hive.root_cell_offset as u64;
    match image.read(addr, 6) {
        Ok(bytes) => {
            let sig = u16::from_le_bytes([bytes[4], bytes[5]]);
            sig == NK_SIGNATURE
        }
        Err(_) => false,
    }
}

// ── In-memory hive reader ────────────────────────────────────────────

/// Reader for navigating a registry hive that's been found in memory.
/// Reads cells from the hive data area (starting at regf_offset + 0x1000).
pub struct HiveReader<'a> {
    /// The memory layer to read from (physical image or virtual memory).
    memory: &'a dyn MemoryAccess,
    /// Base address of hive data (regf_offset + HBASE_BLOCK_SIZE).
    hive_data_base: u64,
    /// Total hive data length.
    hive_length: u32,
}

/// A parsed registry key node.
#[derive(Debug, Clone)]
pub struct KeyNode {
    /// Cell offset (relative to hive data).
    pub cell_offset: u32,
    /// Key name.
    pub name: String,
    /// NK flags.
    pub flags: u16,
    /// Number of subkeys.
    pub subkey_count: u32,
    /// Subkey list cell offset.
    pub subkey_list_offset: u32,
    /// Number of values.
    pub value_count: u32,
    /// Value list cell offset.
    pub value_list_offset: u32,
    /// Class name (used for boot key extraction).
    pub class_name: Option<String>,
    /// Class name cell offset.
    pub class_name_offset: u32,
    /// Class name length.
    pub class_name_length: u16,
}

/// A parsed registry value.
#[derive(Debug, Clone)]
pub struct KeyValue {
    /// Value name (empty string = "(Default)" value).
    pub name: String,
    /// Value type (REG_SZ=1, REG_BINARY=3, REG_DWORD=4, etc.).
    pub value_type: u32,
    /// Raw value data bytes.
    pub data: Vec<u8>,
}

/// Registry value types.
#[allow(dead_code)]
pub mod reg_types {
    pub const REG_NONE: u32 = 0;
    pub const REG_SZ: u32 = 1;
    pub const REG_EXPAND_SZ: u32 = 2;
    pub const REG_BINARY: u32 = 3;
    pub const REG_DWORD: u32 = 4;
    pub const REG_DWORD_BIG_ENDIAN: u32 = 5;
    pub const REG_LINK: u32 = 6;
    pub const REG_MULTI_SZ: u32 = 7;
    pub const REG_QWORD: u32 = 11;
}

impl<'a> HiveReader<'a> {
    /// Create a reader for a hive found at the given physical offset.
    pub fn new(memory: &'a dyn MemoryAccess, hive: &RegistryHive) -> Self {
        HiveReader {
            memory,
            hive_data_base: hive.regf_offset + HBASE_BLOCK_SIZE,
            hive_length: hive.hive_length,
        }
    }

    /// Create a reader for a hive at a specific base address (e.g., virtual).
    pub fn from_base(memory: &'a dyn MemoryAccess, hive_data_base: u64, hive_length: u32) -> Self {
        HiveReader {
            memory,
            hive_data_base,
            hive_length,
        }
    }

    /// Read raw bytes at a cell offset (relative to hive data base).
    fn read_cell_bytes(&self, cell_offset: u32, length: usize) -> Result<Vec<u8>, String> {
        if cell_offset as u64 >= self.hive_length as u64 {
            return Err(format!(
                "cell offset {:#x} exceeds hive length {:#x}",
                cell_offset, self.hive_length
            ));
        }
        let addr = self.hive_data_base + cell_offset as u64;
        self.memory
            .read(addr, length)
            .map_err(|e| format!("read at hive offset {:#x}: {}", cell_offset, e))
    }

    /// Get the size of a cell at the given offset.
    /// Returns the absolute size (negative = allocated, we return positive).
    fn cell_size(&self, cell_offset: u32) -> Result<u32, String> {
        let bytes = self.read_cell_bytes(cell_offset, 4)?;
        let raw_size = i32::from_le_bytes(bytes[0..4].try_into().unwrap());
        // Allocated cells have negative size
        Ok(raw_size.unsigned_abs())
    }

    /// Read the root key node of this hive.
    pub fn root_key(&self, root_cell_offset: u32) -> Result<KeyNode, String> {
        self.read_key_node(root_cell_offset)
    }

    /// Read a key node (NK record) at the given cell offset.
    pub fn read_key_node(&self, cell_offset: u32) -> Result<KeyNode, String> {
        // Cell format: i32 size | u16 sig ("nk") | data...
        // We need at least 4 (size) + 76 + a few name bytes
        let cell = self.read_cell_bytes(cell_offset, 4 + 80)?;

        let sig = u16::from_le_bytes(cell[4..6].try_into().unwrap());
        if sig != NK_SIGNATURE {
            return Err(format!(
                "expected NK signature at {:#x}, got {:#04x}",
                cell_offset, sig
            ));
        }

        // All NK offsets are relative to the signature (cell[4..])
        let nk = &cell[4..]; // skip the 4-byte cell size prefix

        let flags = u16::from_le_bytes(nk[NK_FLAGS..NK_FLAGS + 2].try_into().unwrap());
        let subkey_count = u32::from_le_bytes(nk[NK_SUBKEY_COUNT..NK_SUBKEY_COUNT + 4].try_into().unwrap());
        let subkey_list_offset = u32::from_le_bytes(nk[NK_SUBKEY_LIST..NK_SUBKEY_LIST + 4].try_into().unwrap());
        let value_count = u32::from_le_bytes(nk[NK_VALUE_COUNT..NK_VALUE_COUNT + 4].try_into().unwrap());
        let value_list_offset = u32::from_le_bytes(nk[NK_VALUE_LIST..NK_VALUE_LIST + 4].try_into().unwrap());
        let class_name_offset = u32::from_le_bytes(nk[NK_CLASS_NAME_OFFSET..NK_CLASS_NAME_OFFSET + 4].try_into().unwrap());
        let class_name_length = u16::from_le_bytes(nk[NK_CLASS_NAME_LENGTH..NK_CLASS_NAME_LENGTH + 2].try_into().unwrap());
        let name_length = u16::from_le_bytes(nk[NK_NAME_LENGTH..NK_NAME_LENGTH + 2].try_into().unwrap()) as usize;

        // Read key name
        let name = if name_length > 0 {
            let name_data = self.read_cell_bytes(cell_offset, 4 + NK_NAME_START + name_length)?;
            let name_bytes = &name_data[4 + NK_NAME_START..4 + NK_NAME_START + name_length];
            if flags & KEY_COMP_NAME != 0 {
                // ASCII compressed name
                String::from_utf8_lossy(name_bytes).into_owned()
            } else {
                // UTF-16LE name
                read_utf16le_string(name_bytes)
            }
        } else {
            String::new()
        };

        // Read class name if present
        let class_name = if class_name_length > 0 && class_name_offset != 0xFFFFFFFF {
            self.read_class_name(class_name_offset, class_name_length).ok()
        } else {
            None
        };

        Ok(KeyNode {
            cell_offset,
            name,
            flags,
            subkey_count,
            subkey_list_offset,
            value_count,
            value_list_offset,
            class_name,
            class_name_offset,
            class_name_length,
        })
    }

    /// Read a class name from a cell.
    fn read_class_name(&self, cell_offset: u32, length: u16) -> Result<String, String> {
        let cell = self.read_cell_bytes(cell_offset, 4 + length as usize)?;
        let data = &cell[4..4 + length as usize];
        // Class names are stored as UTF-16LE
        Ok(read_utf16le_string(data))
    }

    /// Enumerate subkeys of a key node.
    pub fn subkeys(&self, key: &KeyNode) -> Result<Vec<KeyNode>, String> {
        if key.subkey_count == 0 || key.subkey_list_offset == 0xFFFFFFFF {
            return Ok(Vec::new());
        }

        let offsets = self.read_subkey_list(key.subkey_list_offset)?;
        let mut subkeys = Vec::with_capacity(offsets.len());
        for off in offsets {
            match self.read_key_node(off) {
                Ok(k) => subkeys.push(k),
                Err(e) => {
                    debug!("registry: skipping bad subkey at {:#x}: {}", off, e);
                }
            }
        }
        Ok(subkeys)
    }

    /// Read a subkey list (lf/lh/ri/li record) and return child cell offsets.
    fn read_subkey_list(&self, cell_offset: u32) -> Result<Vec<u32>, String> {
        // Cell: i32 size | u16 sig | u16 count | entries...
        let header = self.read_cell_bytes(cell_offset, 4 + 4)?;
        let sig = u16::from_le_bytes(header[4..6].try_into().unwrap());
        let count = u16::from_le_bytes(header[6..8].try_into().unwrap()) as usize;

        if count > 10000 {
            return Err(format!("subkey list count {} is unreasonably large", count));
        }

        match sig {
            LF_SIGNATURE | LH_SIGNATURE => {
                // Each entry: u32 cell_offset + u32 hash = 8 bytes
                let entry_size = 8;
                let data = self.read_cell_bytes(cell_offset, 4 + 4 + count * entry_size)?;
                let mut offsets = Vec::with_capacity(count);
                for i in 0..count {
                    let base = 8 + i * entry_size; // skip cell_size(4) + sig(2) + count(2)
                    let off = u32::from_le_bytes(data[base..base + 4].try_into().unwrap());
                    offsets.push(off);
                }
                Ok(offsets)
            }
            LI_SIGNATURE => {
                // Each entry: u32 cell_offset = 4 bytes (no hash)
                let entry_size = 4;
                let data = self.read_cell_bytes(cell_offset, 4 + 4 + count * entry_size)?;
                let mut offsets = Vec::with_capacity(count);
                for i in 0..count {
                    let base = 8 + i * entry_size;
                    let off = u32::from_le_bytes(data[base..base + 4].try_into().unwrap());
                    offsets.push(off);
                }
                Ok(offsets)
            }
            RI_SIGNATURE => {
                // Index root: each entry is a u32 cell offset pointing to another lf/lh/li list
                let entry_size = 4;
                let data = self.read_cell_bytes(cell_offset, 4 + 4 + count * entry_size)?;
                let mut offsets = Vec::new();
                for i in 0..count {
                    let base = 8 + i * entry_size;
                    let sub_list_offset =
                        u32::from_le_bytes(data[base..base + 4].try_into().unwrap());
                    // Recursively read sub-lists
                    match self.read_subkey_list(sub_list_offset) {
                        Ok(sub_offsets) => offsets.extend(sub_offsets),
                        Err(e) => {
                            debug!("registry: skipping bad ri sub-list at {:#x}: {}", sub_list_offset, e);
                        }
                    }
                }
                Ok(offsets)
            }
            _ => Err(format!(
                "unknown subkey list signature {:#04x} at {:#x}",
                sig, cell_offset
            )),
        }
    }

    /// Enumerate values of a key node.
    pub fn values(&self, key: &KeyNode) -> Result<Vec<KeyValue>, String> {
        if key.value_count == 0 || key.value_list_offset == 0xFFFFFFFF {
            return Ok(Vec::new());
        }
        if key.value_count > 10000 {
            return Err(format!("value count {} is unreasonably large", key.value_count));
        }

        // Value list is a cell containing an array of u32 cell offsets
        let list_size = key.value_count as usize * 4;
        let list_data = self.read_cell_bytes(key.value_list_offset, 4 + list_size)?;

        let mut values = Vec::with_capacity(key.value_count as usize);
        for i in 0..key.value_count as usize {
            let base = 4 + i * 4; // skip cell size prefix
            let vk_offset = u32::from_le_bytes(list_data[base..base + 4].try_into().unwrap());
            match self.read_value(vk_offset) {
                Ok(v) => values.push(v),
                Err(e) => {
                    debug!("registry: skipping bad value at {:#x}: {}", vk_offset, e);
                }
            }
        }
        Ok(values)
    }

    /// Read a single value (VK record).
    fn read_value(&self, cell_offset: u32) -> Result<KeyValue, String> {
        // Cell: i32 size | u16 sig ("vk") | data...
        let header = self.read_cell_bytes(cell_offset, 4 + 24)?;

        let sig = u16::from_le_bytes(header[4..6].try_into().unwrap());
        if sig != VK_SIGNATURE {
            return Err(format!(
                "expected VK signature at {:#x}, got {:#04x}",
                cell_offset, sig
            ));
        }

        let vk = &header[4..]; // skip cell size prefix

        let name_length = u16::from_le_bytes(vk[VK_NAME_LENGTH..VK_NAME_LENGTH + 2].try_into().unwrap()) as usize;
        let data_length_raw = u32::from_le_bytes(vk[VK_DATA_LENGTH..VK_DATA_LENGTH + 4].try_into().unwrap());
        let data_offset = u32::from_le_bytes(vk[VK_DATA_OFFSET..VK_DATA_OFFSET + 4].try_into().unwrap());
        let value_type = u32::from_le_bytes(vk[VK_TYPE..VK_TYPE + 4].try_into().unwrap());
        let vk_flags = u16::from_le_bytes(vk[VK_FLAGS..VK_FLAGS + 2].try_into().unwrap());

        // Read value name
        let name = if name_length > 0 {
            let name_data = self.read_cell_bytes(cell_offset, 4 + VK_NAME_START + name_length)?;
            let name_bytes = &name_data[4 + VK_NAME_START..4 + VK_NAME_START + name_length];
            if vk_flags & VALUE_COMP_NAME != 0 {
                String::from_utf8_lossy(name_bytes).into_owned()
            } else {
                read_utf16le_string(name_bytes)
            }
        } else {
            String::new() // (Default) value
        };

        // Read value data
        // Bit 31 of data_length indicates "data is stored inline in the data_offset field"
        let data_is_resident = data_length_raw & 0x80000000 != 0;
        let data_length = (data_length_raw & 0x7FFFFFFF) as usize;

        let data = if data_length == 0 {
            Vec::new()
        } else if data_is_resident {
            // Data is inline: stored in the 4 bytes of data_offset field itself
            let inline_len = std::cmp::min(data_length, 4);
            data_offset.to_le_bytes()[..inline_len].to_vec()
        } else {
            // Data is in a separate cell
            self.read_value_data(data_offset, data_length)?
        };

        Ok(KeyValue {
            name,
            value_type,
            data,
        })
    }

    /// Read value data from a data cell.
    fn read_value_data(&self, cell_offset: u32, length: usize) -> Result<Vec<u8>, String> {
        // Large data (>16344 bytes) uses a "big data" structure; for hashdump we won't
        // encounter this, but handle gracefully.
        let max_read = std::cmp::min(length, 1024 * 1024); // 1MB safety limit
        let cell = self.read_cell_bytes(cell_offset, 4 + max_read)?;
        let available = cell.len().saturating_sub(4);
        let actual = std::cmp::min(length, available);
        Ok(cell[4..4 + actual].to_vec())
    }

    /// Navigate to a subkey by path (e.g., `SAM\Domains\Account\Users`).
    /// Path components are separated by `\`.
    pub fn open_key(&self, root_cell_offset: u32, path: &str) -> Result<KeyNode, String> {
        let mut current = self.root_key(root_cell_offset)?;

        if path.is_empty() {
            return Ok(current);
        }

        for component in path.split('\\') {
            if component.is_empty() {
                continue;
            }
            let subkeys = self.subkeys(&current)?;
            let component_lower = component.to_lowercase();
            current = subkeys
                .into_iter()
                .find(|k| k.name.to_lowercase() == component_lower)
                .ok_or_else(|| {
                    format!("subkey '{}' not found under '{}'", component, current.name)
                })?;
        }

        Ok(current)
    }

    /// Get a named value from a key.
    pub fn get_value(&self, key: &KeyNode, name: &str) -> Result<KeyValue, String> {
        let values = self.values(key)?;
        let name_lower = name.to_lowercase();
        values
            .into_iter()
            .find(|v| v.name.to_lowercase() == name_lower)
            .ok_or_else(|| format!("value '{}' not found in key '{}'", name, key.name))
    }

    /// Get the (Default) value from a key.
    pub fn get_default_value(&self, key: &KeyNode) -> Result<KeyValue, String> {
        let values = self.values(key)?;
        values
            .into_iter()
            .find(|v| v.name.is_empty())
            .ok_or_else(|| format!("no default value in key '{}'", key.name))
    }

    /// Get a HashMap of all values (name → KeyValue).
    pub fn values_map(&self, key: &KeyNode) -> Result<HashMap<String, KeyValue>, String> {
        let values = self.values(key)?;
        Ok(values.into_iter().map(|v| (v.name.clone(), v)).collect())
    }

    /// Get subkeys as a HashMap (name → KeyNode).
    pub fn subkeys_map(&self, key: &KeyNode) -> Result<HashMap<String, KeyNode>, String> {
        let subkeys = self.subkeys(key)?;
        Ok(subkeys.into_iter().map(|k| (k.name.clone(), k)).collect())
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Decode a UTF-16LE string from raw bytes, stopping at first null or end.
fn read_utf16le_string(data: &[u8]) -> String {
    let chars: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&c| c != 0)
        .collect();
    String::from_utf16_lossy(&chars)
}

// ── Convenience: find specific hives ─────────────────────────────────

/// Find the SAM hive from a list of discovered hives.
pub fn find_sam_hive(hives: &[RegistryHive]) -> Option<&RegistryHive> {
    hives.iter().find(|h| {
        let name = h.hive_name.to_uppercase();
        name.contains("\\SAM") && !name.contains("SAM.LOG") && !name.contains(".SAV")
    })
}

/// Find the SYSTEM hive from a list of discovered hives.
pub fn find_system_hive(hives: &[RegistryHive]) -> Option<&RegistryHive> {
    hives.iter().find(|h| {
        let name = h.hive_name.to_uppercase();
        name.contains("\\SYSTEM") && !name.contains("SYSTEM.LOG") && !name.contains(".SAV")
    })
}

/// Find all SAM hive candidates, with valid-root ones first.
pub fn find_sam_hives(hives: &[RegistryHive]) -> Vec<&RegistryHive> {
    let mut matches: Vec<&RegistryHive> = hives.iter().filter(|h| {
        let name = h.hive_name.to_uppercase();
        name.contains("\\SAM") && !name.contains("SAM.LOG") && !name.contains(".SAV")
    }).collect();
    matches.sort_by(|a, b| b.valid_root.cmp(&a.valid_root));
    matches
}

/// Find all SYSTEM hive candidates, with valid-root ones first.
pub fn find_system_hives(hives: &[RegistryHive]) -> Vec<&RegistryHive> {
    let mut matches: Vec<&RegistryHive> = hives.iter().filter(|h| {
        let name = h.hive_name.to_uppercase();
        name.contains("\\SYSTEM") && !name.contains("SYSTEM.LOG") && !name.contains(".SAV")
    }).collect();
    matches.sort_by(|a, b| b.valid_root.cmp(&a.valid_root));
    matches
}

/// Find the SECURITY hive from a list of discovered hives.
pub fn find_security_hive(hives: &[RegistryHive]) -> Option<&RegistryHive> {
    hives.iter().find(|h| {
        let name = h.hive_name.to_uppercase();
        name.contains("\\SECURITY") && !name.contains("SECURITY.LOG") && !name.contains(".SAV")
    })
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utf16le_decode() {
        // "SAM" in UTF-16LE
        let data = [b'S', 0, b'A', 0, b'M', 0, 0, 0];
        assert_eq!(read_utf16le_string(&data), "SAM");
    }

    #[test]
    fn test_utf16le_decode_no_null() {
        let data = [b'H', 0, b'i', 0];
        assert_eq!(read_utf16le_string(&data), "Hi");
    }

    #[test]
    fn test_find_sam_hive() {
        let hives = vec![
            RegistryHive {
                regf_offset: 0x1000,
                hive_length: 0x10000,
                root_cell_offset: 0x20,
                hive_name: "\\REGISTRY\\MACHINE\\SYSTEM".to_string(),
                valid_root: true,
            },
            RegistryHive {
                regf_offset: 0x20000,
                hive_length: 0x8000,
                root_cell_offset: 0x20,
                hive_name: "\\REGISTRY\\MACHINE\\SAM".to_string(),
                valid_root: true,
            },
        ];
        let sam = find_sam_hive(&hives);
        assert!(sam.is_some());
        assert_eq!(sam.unwrap().regf_offset, 0x20000);
    }

    #[test]
    fn test_find_system_hive() {
        let hives = vec![
            RegistryHive {
                regf_offset: 0x1000,
                hive_length: 0x10000,
                root_cell_offset: 0x20,
                hive_name: "\\REGISTRY\\MACHINE\\SYSTEM".to_string(),
                valid_root: true,
            },
        ];
        assert!(find_system_hive(&hives).is_some());
        assert!(find_sam_hive(&hives).is_none());
    }

    /// Build a minimal in-memory regf+hbin+NK structure for testing the parser.
    fn build_test_hive() -> Vec<u8> {
        let mut hive = vec![0u8; 8192]; // 4096 regf header + 4096 hbin

        // HBASE_BLOCK at offset 0
        hive[0..4].copy_from_slice(b"regf");
        // Sequence numbers
        hive[4..8].copy_from_slice(&1u32.to_le_bytes());
        hive[8..12].copy_from_slice(&1u32.to_le_bytes());
        // Root cell offset at +0x24 = 0x20 (32 bytes into hive data)
        hive[0x24..0x28].copy_from_slice(&0x20u32.to_le_bytes());
        // Hive length at +0x28 = 4096 (one HBIN)
        hive[0x28..0x2C].copy_from_slice(&4096u32.to_le_bytes());
        // Hive name at +0x30 = "\\SAM" in UTF-16LE
        let name = "\\SAM";
        for (i, ch) in name.chars().enumerate() {
            let offset = 0x30 + i * 2;
            hive[offset] = ch as u8;
            hive[offset + 1] = 0;
        }

        // HBIN at offset 4096
        let hbin_base = 4096usize;
        hive[hbin_base..hbin_base + 4].copy_from_slice(b"hbin");
        hive[hbin_base + 4..hbin_base + 8].copy_from_slice(&0u32.to_le_bytes()); // file offset
        hive[hbin_base + 8..hbin_base + 12].copy_from_slice(&4096u32.to_le_bytes()); // size

        // Root NK cell at hive data offset 0x20 (= physical 4096 + 0x20 = 4128)
        let nk_offset = hbin_base + 0x20;
        // Cell size: negative = allocated, let's say -120
        hive[nk_offset..nk_offset + 4].copy_from_slice(&(-120i32).to_le_bytes());
        // NK signature
        hive[nk_offset + 4..nk_offset + 6].copy_from_slice(&NK_SIGNATURE.to_le_bytes());
        // Flags: KEY_HIVE_ENTRY | KEY_COMP_NAME
        let flags: u16 = KEY_HIVE_ENTRY | KEY_COMP_NAME;
        hive[nk_offset + 4 + NK_FLAGS..nk_offset + 4 + NK_FLAGS + 2]
            .copy_from_slice(&flags.to_le_bytes());
        // Subkey count = 0
        hive[nk_offset + 4 + NK_SUBKEY_COUNT..nk_offset + 4 + NK_SUBKEY_COUNT + 4]
            .copy_from_slice(&0u32.to_le_bytes());
        // Subkey list = 0xFFFFFFFF (none)
        hive[nk_offset + 4 + NK_SUBKEY_LIST..nk_offset + 4 + NK_SUBKEY_LIST + 4]
            .copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        // Value count = 0
        hive[nk_offset + 4 + NK_VALUE_COUNT..nk_offset + 4 + NK_VALUE_COUNT + 4]
            .copy_from_slice(&0u32.to_le_bytes());
        // Value list = 0xFFFFFFFF (none)
        hive[nk_offset + 4 + NK_VALUE_LIST..nk_offset + 4 + NK_VALUE_LIST + 4]
            .copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        // Class name offset = 0xFFFFFFFF
        hive[nk_offset + 4 + NK_CLASS_NAME_OFFSET..nk_offset + 4 + NK_CLASS_NAME_OFFSET + 4]
            .copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        // Class name length = 0
        hive[nk_offset + 4 + NK_CLASS_NAME_LENGTH..nk_offset + 4 + NK_CLASS_NAME_LENGTH + 2]
            .copy_from_slice(&0u16.to_le_bytes());
        // Name length = 3 ("SAM")
        hive[nk_offset + 4 + NK_NAME_LENGTH..nk_offset + 4 + NK_NAME_LENGTH + 2]
            .copy_from_slice(&3u16.to_le_bytes());
        // Name = "SAM"
        hive[nk_offset + 4 + NK_NAME_START..nk_offset + 4 + NK_NAME_START + 3]
            .copy_from_slice(b"SAM");

        hive
    }

    /// Mock memory that wraps a Vec<u8>.
    struct MockMemory(Vec<u8>);

    impl MemoryAccess for MockMemory {
        fn read(
            &self,
            offset: u64,
            length: usize,
        ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
            let start = offset as usize;
            let end = start + length;
            if end > self.0.len() {
                return Err(format!("read past end: {:#x}+{} > {:#x}", offset, length, self.0.len()).into());
            }
            Ok(self.0[start..end].to_vec())
        }

        fn is_valid(&self, offset: u64, length: u64) -> bool {
            (offset + length) <= self.0.len() as u64
        }
    }

    #[test]
    fn test_parse_regf_header() {
        let hive_data = build_test_hive();
        let mem = MockMemory(hive_data);
        // Wrap in a MemoryImage-like thing — we can use parse_regf_header directly
        // but it expects MemoryImage. Instead test via HiveReader.
        let fake_hive = RegistryHive {
            regf_offset: 0, // regf at offset 0 in our test data
            hive_length: 4096,
            root_cell_offset: 0x20,
            hive_name: "\\SAM".to_string(),
            valid_root: true,
        };

        let reader = HiveReader::new(&mem, &fake_hive);
        let root = reader.root_key(0x20).unwrap();
        assert_eq!(root.name, "SAM");
        assert!(root.flags & KEY_HIVE_ENTRY != 0);
        assert_eq!(root.subkey_count, 0);
        assert_eq!(root.value_count, 0);
    }

    #[test]
    fn test_hive_reader_open_key_empty_path() {
        let hive_data = build_test_hive();
        let mem = MockMemory(hive_data);
        let fake_hive = RegistryHive {
            regf_offset: 0,
            hive_length: 4096,
            root_cell_offset: 0x20,
            hive_name: "\\SAM".to_string(),
            valid_root: true,
        };
        let reader = HiveReader::new(&mem, &fake_hive);
        let root = reader.open_key(0x20, "").unwrap();
        assert_eq!(root.name, "SAM");
    }

    #[test]
    fn test_hive_reader_missing_subkey() {
        let hive_data = build_test_hive();
        let mem = MockMemory(hive_data);
        let fake_hive = RegistryHive {
            regf_offset: 0,
            hive_length: 4096,
            root_cell_offset: 0x20,
            hive_name: "\\SAM".to_string(),
            valid_root: true,
        };
        let reader = HiveReader::new(&mem, &fake_hive);
        let err = reader.open_key(0x20, "Domains\\Account").unwrap_err();
        assert!(err.contains("not found"));
    }
}
