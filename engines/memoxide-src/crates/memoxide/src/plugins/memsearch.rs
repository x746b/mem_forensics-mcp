//! MemSearch — scan physical memory for arbitrary byte patterns.
//!
//! Searches the entire physical address space for a given byte pattern,
//! returning matching offsets with hex/ASCII context.  Useful for finding
//! deleted files, flag strings, MFT resident data, etc.

use crate::memory::image::MemoryImage;
use serde::{Deserialize, Serialize};

/// A single pattern match in physical memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    /// Physical offset of the match.
    pub offset: u64,
    /// Hex dump of surrounding bytes.
    pub context_hex: String,
    /// ASCII representation of surrounding bytes.
    pub context_ascii: String,
}

/// Results of a memory search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub pattern_len: usize,
    pub total_matches: usize,
    pub matches: Vec<SearchHit>,
}

/// Scan physical memory for `pattern`, returning up to `max_results` hits.
///
/// Each hit includes `context_bytes` of surrounding data (before and after).
pub fn run(
    image: &MemoryImage,
    pattern: &[u8],
    chunk_size: usize,
    max_results: usize,
    context_bytes: usize,
) -> Result<SearchResult, String> {
    if pattern.is_empty() {
        return Err("Empty search pattern".into());
    }

    let image_size = image.size();
    // Overlap between chunks must be at least pattern.len() - 1 to avoid
    // missing matches that straddle a chunk boundary.
    let overlap = pattern.len().max(256);

    let mut hits = Vec::new();
    let mut offset: u64 = 0;

    while offset < image_size && hits.len() < max_results {
        let remaining = image_size - offset;
        let read_len = std::cmp::min(chunk_size + overlap, remaining as usize);
        let chunk = match image.read(offset, read_len) {
            Ok(c) => c,
            Err(_) => {
                offset += chunk_size as u64;
                continue;
            }
        };

        // Find all occurrences of pattern in this chunk.
        let first_byte = pattern[0];
        let mut pos = 0;
        while pos + pattern.len() <= chunk.len() && hits.len() < max_results {
            // Use memchr to quickly locate the first byte.
            let rel = match memchr::memchr(first_byte, &chunk[pos..]) {
                Some(r) => r,
                None => break,
            };
            let abs = pos + rel;
            if abs + pattern.len() > chunk.len() {
                break;
            }

            if chunk[abs..abs + pattern.len()] == *pattern {
                let phys_offset = offset + abs as u64;

                // Gather context from the image (may span chunk boundaries).
                let ctx_start = phys_offset.saturating_sub(context_bytes as u64);
                let ctx_len = std::cmp::min(
                    (context_bytes * 2 + pattern.len()) as u64,
                    image_size.saturating_sub(ctx_start),
                ) as usize;
                let ctx_data = image.read_padded(ctx_start, ctx_len);

                hits.push(SearchHit {
                    offset: phys_offset,
                    context_hex: hex_dump_inline(&ctx_data),
                    context_ascii: printable_ascii(&ctx_data),
                });
            }

            pos = abs + 1;
        }

        offset += chunk_size as u64;
    }

    Ok(SearchResult {
        pattern_len: pattern.len(),
        total_matches: hits.len(),
        matches: hits,
    })
}

/// One-line hex string (space-separated bytes).
fn hex_dump_inline(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
}

/// Convert bytes to printable ASCII (non-printable → '.').
fn printable_ascii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Helper: create a MemoryImage backed by a temp file with known content.
    fn image_from_bytes(data: &[u8]) -> (NamedTempFile, MemoryImage) {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(data).unwrap();
        tmp.flush().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let img = MemoryImage::open(&path).unwrap();
        (tmp, img)
    }

    #[test]
    fn test_hex_dump_inline() {
        assert_eq!(hex_dump_inline(&[0x41, 0x42, 0x00, 0xff]), "41 42 00 ff");
    }

    #[test]
    fn test_printable_ascii() {
        assert_eq!(printable_ascii(b"Hi\x00\x01Z"), "Hi..Z");
    }

    #[test]
    fn test_empty_pattern_returns_error() {
        let (_tmp, img) = image_from_bytes(b"hello world");
        let res = run(&img, b"", 4096, 10, 16);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Empty"));
    }

    #[test]
    fn test_single_match_ascii() {
        let (_tmp, img) = image_from_bytes(b"xxxx FLAG{found_it} yyyy");
        let res = run(&img, b"FLAG{found_it}", 4096, 10, 4).unwrap();
        assert_eq!(res.total_matches, 1);
        assert_eq!(res.pattern_len, 14);
        assert_eq!(res.matches[0].offset, 5);
        // context_ascii should contain the flag
        assert!(res.matches[0].context_ascii.contains("FLAG"));
    }

    #[test]
    fn test_multiple_matches() {
        // Three occurrences of "AB"
        let data = b"..AB..AB..AB..";
        let (_tmp, img) = image_from_bytes(data);
        let res = run(&img, b"AB", 4096, 10, 2).unwrap();
        assert_eq!(res.total_matches, 3);
        assert_eq!(res.matches[0].offset, 2);
        assert_eq!(res.matches[1].offset, 6);
        assert_eq!(res.matches[2].offset, 10);
    }

    #[test]
    fn test_max_results_limits_output() {
        let data = b"AAAAAAAAA"; // 9 overlapping single-byte matches
        let (_tmp, img) = image_from_bytes(data);
        let res = run(&img, b"A", 4096, 3, 0).unwrap();
        assert_eq!(res.total_matches, 3);
    }

    #[test]
    fn test_no_match() {
        let (_tmp, img) = image_from_bytes(b"hello world");
        let res = run(&img, b"ZZZZZ", 4096, 10, 4).unwrap();
        assert_eq!(res.total_matches, 0);
        assert!(res.matches.is_empty());
    }

    #[test]
    fn test_utf16le_pattern() {
        // "Hi" in UTF-16LE = [0x48, 0x00, 0x69, 0x00]
        let mut data = vec![0u8; 10];
        data.extend_from_slice(&[0x48, 0x00, 0x69, 0x00]);
        data.extend_from_slice(&[0u8; 10]);
        let (_tmp, img) = image_from_bytes(&data);
        let pattern: Vec<u8> = "Hi".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let res = run(&img, &pattern, 4096, 10, 4).unwrap();
        assert_eq!(res.total_matches, 1);
        assert_eq!(res.matches[0].offset, 10);
    }

    #[test]
    fn test_hex_pattern() {
        let data = vec![0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF, 0x02, 0x03];
        let (_tmp, img) = image_from_bytes(&data);
        let res = run(&img, &[0xDE, 0xAD, 0xBE, 0xEF], 4096, 10, 2).unwrap();
        assert_eq!(res.total_matches, 1);
        assert_eq!(res.matches[0].offset, 2);
    }

    #[test]
    fn test_chunk_boundary_match() {
        // Place a pattern exactly at a chunk boundary to test overlap handling.
        // Use a small chunk_size so we can test boundary behavior.
        let chunk_size = 32;
        let mut data = vec![0u8; chunk_size]; // first chunk: all zeros
        // Place "XYZW" straddling the boundary: starts at offset 30 (inside chunk 0's overlap)
        data[30] = b'X';
        data[31] = b'Y';
        data.push(b'Z');
        data.push(b'W');
        data.extend_from_slice(&[0u8; 28]); // pad to fill second chunk
        let (_tmp, img) = image_from_bytes(&data);
        let res = run(&img, b"XYZW", chunk_size, 10, 2).unwrap();
        assert_eq!(res.total_matches, 1);
        assert_eq!(res.matches[0].offset, 30);
    }

    #[test]
    fn test_context_bytes_in_output() {
        let mut data = vec![0x41u8; 100]; // 'A' x 100
        data[50] = b'Z'; // single different byte
        let (_tmp, img) = image_from_bytes(&data);
        let res = run(&img, b"Z", 4096, 10, 8).unwrap();
        assert_eq!(res.total_matches, 1);
        // context should be 8 bytes before + 1 match + 8 bytes after = 17 bytes
        // (pattern_len=1, context_bytes=8, so total = 8+8+1 = 17 hex pairs)
        let hex_parts: Vec<&str> = res.matches[0].context_hex.split(' ').collect();
        assert_eq!(hex_parts.len(), 17);
        // The 9th byte (index 8) should be "5a" (Z)
        assert_eq!(hex_parts[8], "5a");
    }

    #[test]
    fn test_search_result_serialize() {
        let result = SearchResult {
            pattern_len: 4,
            total_matches: 1,
            matches: vec![SearchHit {
                offset: 0x1000,
                context_hex: "41 42".into(),
                context_ascii: "AB".into(),
            }],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"offset\":4096"));
        assert!(json.contains("\"total_matches\":1"));
    }
}
