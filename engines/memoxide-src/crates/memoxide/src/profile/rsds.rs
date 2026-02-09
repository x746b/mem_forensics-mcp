//! RSDS debug directory scanner — extract PDB GUID from kernel PE images in physical memory.
//!
//! The RSDS signature (CodeView NB10 successor) is embedded in the PE debug directory
//! of Windows kernel images. The GUID + age uniquely identifies the exact kernel build
//! and maps 1:1 to a Volatility3 ISF filename: `{GUID}-{age}.json.xz`.
//!
//! This is the most reliable way to auto-detect the correct ISF for Win10+ where
//! KDBG is encoded and psscan probing is ambiguous across similar builds.

use crate::memory::image::MemoryImage;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// Known kernel PDB filenames.
const KERNEL_PDB_NAMES: &[&str] = &[
    "ntkrnlmp.pdb",
    "ntoskrnl.pdb",
    "ntkrpamp.pdb",
    "ntkrnlpa.pdb",
];

/// RSDS signature bytes.
const RSDS_SIGNATURE: &[u8; 4] = b"RSDS";

/// Minimum size of an RSDS entry: 4 (sig) + 16 (GUID) + 4 (age) + 5 (min pdb name "x.pdb\0").
const RSDS_MIN_SIZE: usize = 29;

/// Parsed RSDS debug directory entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RsdsInfo {
    /// Physical offset of the RSDS signature in the memory image.
    pub offset: u64,
    /// GUID string in Volatility3 format (uppercase hex, no dashes, mixed-endian).
    pub guid: String,
    /// Age field from the RSDS entry.
    pub age: u32,
    /// PDB filename (e.g., "ntkrnlmp.pdb").
    pub pdb_name: String,
}

/// Check if a PDB name belongs to a Windows kernel image.
pub fn is_kernel_pdb(name: &str) -> bool {
    KERNEL_PDB_NAMES.iter().any(|k| k.eq_ignore_ascii_case(name))
}

/// Construct the ISF filename from an RSDS entry: `{GUID}-{age}.json.xz`.
pub fn isf_filename(info: &RsdsInfo) -> String {
    format!("{}-{}.json.xz", info.guid, info.age)
}

/// Format a 16-byte GUID in Volatility3's mixed-endian uppercase hex format.
///
/// The GUID is stored as:
///   - Data1: u32 LE (bytes 0..4)
///   - Data2: u16 LE (bytes 4..6)
///   - Data3: u16 LE (bytes 6..8)
///   - Data4: 8 bytes as-is (bytes 8..16)
///
/// Output: `{Data1:08X}{Data2:04X}{Data3:04X}{Data4[0]:02X}..{Data4[7]:02X}`
pub fn format_guid(guid_bytes: &[u8; 16]) -> String {
    let data1 = u32::from_le_bytes([guid_bytes[0], guid_bytes[1], guid_bytes[2], guid_bytes[3]]);
    let data2 = u16::from_le_bytes([guid_bytes[4], guid_bytes[5]]);
    let data3 = u16::from_le_bytes([guid_bytes[6], guid_bytes[7]]);

    format!(
        "{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        data1,
        data2,
        data3,
        guid_bytes[8],
        guid_bytes[9],
        guid_bytes[10],
        guid_bytes[11],
        guid_bytes[12],
        guid_bytes[13],
        guid_bytes[14],
        guid_bytes[15],
    )
}

/// Scan the entire physical memory image for RSDS entries.
#[allow(dead_code)]
pub fn scan_rsds(
    image: &MemoryImage,
    chunk_size: usize,
    max_results: usize,
) -> Result<Vec<RsdsInfo>, String> {
    scan_rsds_limited(image, chunk_size, image.size(), max_results)
}

/// Scan up to `max_scan_bytes` of physical memory for RSDS entries.
pub fn scan_rsds_limited(
    image: &MemoryImage,
    chunk_size: usize,
    max_scan_bytes: u64,
    max_results: usize,
) -> Result<Vec<RsdsInfo>, String> {
    let image_size = image.size().min(max_scan_bytes);
    let overlap = 256usize; // RSDS entry is ~60 bytes max; 256 is plenty of overlap
    let mut results = Vec::new();
    let mut offset: u64 = 0;

    while offset < image_size && results.len() < max_results {
        let remaining = image_size - offset;
        let read_len = std::cmp::min(chunk_size + overlap, remaining as usize);
        let chunk = match image.read(offset, read_len) {
            Ok(c) => c,
            Err(_) => {
                offset += chunk_size as u64;
                continue;
            }
        };

        // Only scan the non-overlap portion to avoid duplicate matches,
        // except for the last chunk where we scan everything.
        let max_scan_offset = if offset + read_len as u64 >= image_size {
            chunk.len()
        } else {
            chunk_size
        };

        scan_chunk_for_rsds(&chunk, offset, max_scan_offset, &mut results, max_results);
        offset += chunk_size as u64;
    }

    // Deduplicate by GUID+age (same kernel image can appear multiple times).
    results.dedup_by(|a, b| a.guid == b.guid && a.age == b.age && a.pdb_name == b.pdb_name);

    debug!("RSDS scan found {} unique entries", results.len());
    Ok(results)
}

/// Scan a single chunk for RSDS signatures.
fn scan_chunk_for_rsds(
    chunk: &[u8],
    chunk_base: u64,
    max_scan_offset: usize,
    results: &mut Vec<RsdsInfo>,
    max_results: usize,
) {
    let mut pos = 0;
    while pos + RSDS_MIN_SIZE <= chunk.len() && pos < max_scan_offset && results.len() < max_results
    {
        // Fast first-byte search using memchr.
        let rel = match memchr::memchr(b'R', &chunk[pos..]) {
            Some(r) => r,
            None => break,
        };
        let abs = pos + rel;

        if abs + RSDS_MIN_SIZE > chunk.len() {
            break;
        }

        if &chunk[abs..abs + 4] == RSDS_SIGNATURE {
            if let Some(info) = parse_rsds_entry(chunk, abs, chunk_base) {
                results.push(info);
            }
        }

        pos = abs + 1;
    }
}

/// Parse a single RSDS entry starting at `pos` in `chunk`.
fn parse_rsds_entry(chunk: &[u8], pos: usize, chunk_base: u64) -> Option<RsdsInfo> {
    // Need at least: 4 (RSDS) + 16 (GUID) + 4 (age) + 1 (min pdb name) = 25 bytes
    if pos + 24 >= chunk.len() {
        return None;
    }

    // GUID: 16 bytes starting at offset 4
    let guid_start = pos + 4;
    let mut guid_bytes = [0u8; 16];
    guid_bytes.copy_from_slice(&chunk[guid_start..guid_start + 16]);

    // Age: u32 LE at offset 20
    let age_start = pos + 20;
    let age = u32::from_le_bytes([
        chunk[age_start],
        chunk[age_start + 1],
        chunk[age_start + 2],
        chunk[age_start + 3],
    ]);

    // Validate age: must be > 0 and < 100
    if age == 0 || age >= 100 {
        return None;
    }

    // PDB name: null-terminated ASCII starting at offset 24
    let name_start = pos + 24;
    let max_name_len = (chunk.len() - name_start).min(128);
    let name_end = chunk[name_start..name_start + max_name_len]
        .iter()
        .position(|&b| b == 0)?;

    if name_end < 5 {
        // Too short (min "x.pdb")
        return None;
    }

    let pdb_name = std::str::from_utf8(&chunk[name_start..name_start + name_end]).ok()?;

    // Validate: must end with ".pdb" and contain only printable ASCII
    if !pdb_name.to_ascii_lowercase().ends_with(".pdb") {
        return None;
    }
    if !pdb_name.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
        return None;
    }

    let guid = format_guid(&guid_bytes);

    Some(RsdsInfo {
        offset: chunk_base + pos as u64,
        guid,
        age,
        pdb_name: pdb_name.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_guid() {
        // Example GUID bytes (mixed-endian):
        // Data1 = 0x1D842705 stored as LE: [05, 27, 84, 1D]
        // Data2 = 0x9458 stored as LE: [58, 94]
        // Data3 = 0x4672 stored as LE: [72, 46]
        // Data4 = [A4, 48, D0, 4E, 4C, 42, 56, 88] (as-is)
        let guid_bytes: [u8; 16] = [
            0x05, 0x27, 0x84, 0x1D, // Data1 LE
            0x58, 0x94, // Data2 LE
            0x72, 0x46, // Data3 LE
            0xA4, 0x48, 0xD0, 0x4E, 0x4C, 0x42, 0x56, 0x88, // Data4
        ];
        let guid = format_guid(&guid_bytes);
        assert_eq!(guid, "1D84270594584672A448D04E4C425688");
    }

    #[test]
    fn test_format_guid_zeros() {
        let guid_bytes = [0u8; 16];
        let guid = format_guid(&guid_bytes);
        assert_eq!(guid, "00000000000000000000000000000000");
    }

    #[test]
    fn test_parse_rsds_entry() {
        // Build a synthetic RSDS entry
        let mut buf = vec![0u8; 64];
        // Signature
        buf[0..4].copy_from_slice(b"RSDS");
        // GUID (16 bytes)
        buf[4..20].copy_from_slice(&[
            0x05, 0x27, 0x84, 0x1D, 0x58, 0x94, 0x72, 0x46, 0xA4, 0x48, 0xD0, 0x4E, 0x4C, 0x42,
            0x56, 0x88,
        ]);
        // Age = 2
        buf[20..24].copy_from_slice(&2u32.to_le_bytes());
        // PDB name: "ntkrnlmp.pdb\0"
        let pdb = b"ntkrnlmp.pdb\0";
        buf[24..24 + pdb.len()].copy_from_slice(pdb);

        let info = parse_rsds_entry(&buf, 0, 0x1000).unwrap();
        assert_eq!(info.offset, 0x1000);
        assert_eq!(info.guid, "1D84270594584672A448D04E4C425688");
        assert_eq!(info.age, 2);
        assert_eq!(info.pdb_name, "ntkrnlmp.pdb");
    }

    #[test]
    fn test_isf_filename() {
        let info = RsdsInfo {
            offset: 0,
            guid: "1D84270594584672A448D04E4C425688".into(),
            age: 2,
            pdb_name: "ntkrnlmp.pdb".into(),
        };
        assert_eq!(
            isf_filename(&info),
            "1D84270594584672A448D04E4C425688-2.json.xz"
        );
    }

    #[test]
    fn test_pdb_name_validation() {
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(b"RSDS");
        buf[4..20].copy_from_slice(&[1u8; 16]);
        buf[20..24].copy_from_slice(&1u32.to_le_bytes());

        // Non-.pdb name should be rejected
        let name = b"notapdb.dll\0";
        buf[24..24 + name.len()].copy_from_slice(name);
        assert!(parse_rsds_entry(&buf, 0, 0).is_none());

        // Too short name (4 chars < 5 minimum)
        let name = b".pdb\0";
        buf[24..24 + name.len()].copy_from_slice(name);
        assert!(parse_rsds_entry(&buf, 0, 0).is_none());

        // Name with non-printable chars
        let name = b"ntk\x01rnl.pdb\0";
        buf[24..24 + name.len()].copy_from_slice(name);
        assert!(parse_rsds_entry(&buf, 0, 0).is_none());

        // Valid name should work
        let name = b"ntkrnlmp.pdb\0";
        buf[24..24 + name.len()].copy_from_slice(name);
        assert!(parse_rsds_entry(&buf, 0, 0).is_some());
    }

    #[test]
    fn test_age_validation() {
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(b"RSDS");
        buf[4..20].copy_from_slice(&[1u8; 16]);
        let pdb = b"ntkrnlmp.pdb\0";

        // Age = 0 should be rejected
        buf[20..24].copy_from_slice(&0u32.to_le_bytes());
        buf[24..24 + pdb.len()].copy_from_slice(pdb);
        assert!(parse_rsds_entry(&buf, 0, 0).is_none());

        // Age = 100 should be rejected
        buf[20..24].copy_from_slice(&100u32.to_le_bytes());
        assert!(parse_rsds_entry(&buf, 0, 0).is_none());

        // Age = 99 should be accepted
        buf[20..24].copy_from_slice(&99u32.to_le_bytes());
        assert!(parse_rsds_entry(&buf, 0, 0).is_some());
    }

    #[test]
    fn test_scan_synthetic_memory() {
        // Create a fake memory buffer with an embedded RSDS entry.
        let mut mem = vec![0u8; 4096];

        // Place RSDS at offset 0x100
        let entry_offset = 0x100;
        mem[entry_offset..entry_offset + 4].copy_from_slice(b"RSDS");
        mem[entry_offset + 4..entry_offset + 20].copy_from_slice(&[
            0x05, 0x27, 0x84, 0x1D, 0x58, 0x94, 0x72, 0x46, 0xA4, 0x48, 0xD0, 0x4E, 0x4C, 0x42,
            0x56, 0x88,
        ]);
        mem[entry_offset + 20..entry_offset + 24].copy_from_slice(&1u32.to_le_bytes());
        let pdb = b"ntkrnlmp.pdb\0";
        mem[entry_offset + 24..entry_offset + 24 + pdb.len()].copy_from_slice(pdb);

        // Write to temp file and open as MemoryImage.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &mem).unwrap();
        let image = MemoryImage::open(tmp.path().to_str().unwrap()).unwrap();

        let results = scan_rsds(&image, 2048, 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 0x100);
        assert_eq!(results[0].guid, "1D84270594584672A448D04E4C425688");
        assert_eq!(results[0].age, 1);
        assert_eq!(results[0].pdb_name, "ntkrnlmp.pdb");
    }

    #[test]
    fn test_is_kernel_pdb() {
        assert!(is_kernel_pdb("ntkrnlmp.pdb"));
        assert!(is_kernel_pdb("NTKRNLMP.PDB"));
        assert!(is_kernel_pdb("ntoskrnl.pdb"));
        assert!(!is_kernel_pdb("clr.pdb"));
        assert!(!is_kernel_pdb("notepad.pdb"));
    }

    #[test]
    fn test_deduplication() {
        // Create a buffer with the same RSDS entry twice.
        let mut mem = vec![0u8; 4096];

        for &entry_offset in &[0x100usize, 0x200] {
            mem[entry_offset..entry_offset + 4].copy_from_slice(b"RSDS");
            mem[entry_offset + 4..entry_offset + 20].copy_from_slice(&[0xAA; 16]);
            mem[entry_offset + 20..entry_offset + 24].copy_from_slice(&1u32.to_le_bytes());
            let pdb = b"ntkrnlmp.pdb\0";
            mem[entry_offset + 24..entry_offset + 24 + pdb.len()].copy_from_slice(pdb);
        }

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &mem).unwrap();
        let image = MemoryImage::open(tmp.path().to_str().unwrap()).unwrap();

        let results = scan_rsds(&image, 4096, 10).unwrap();
        // Should be deduplicated to 1
        assert_eq!(results.len(), 1);
    }
}
