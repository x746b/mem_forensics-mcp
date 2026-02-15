//! CmdScan (lite) — best-effort recovery of suspicious command strings.
//!
//! This is not a full Volatility-style console structure parser yet.
//! Instead, it scans physical memory for suspicious command substrings in
//! both ASCII and UTF-16LE, and returns hits with offsets + small context.
//!
//! Uses Aho-Corasick for multi-pattern matching in a single pass per encoding,
//! rather than per-pattern memchr scans.

use crate::memory::image::MemoryImage;
use crate::rules::command_patterns::{self, CommandPattern, CommandSeverity};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Encoding of the hit.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HitEncoding {
    Ascii,
    Utf16le,
}

/// A single suspicious command-pattern match in memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandHit {
    pub offset: u64,
    pub encoding: HitEncoding,
    pub category: String,
    pub severity: String,
    pub needle: String,
    pub description: String,
    /// Printable context around the hit (best-effort).
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmdscanResult {
    pub total_hits: usize,
    pub hits: Vec<CommandHit>,
}

struct AcScanner {
    automaton: AhoCorasick,
    /// Map from AC pattern index → index into COMMAND_PATTERNS.
    pattern_map: Vec<usize>,
}

fn build_ascii_scanner() -> AcScanner {
    let patterns = command_patterns::COMMAND_PATTERNS;
    let needles: Vec<&[u8]> = patterns.iter().map(|p| p.needle.as_bytes()).collect();
    let pattern_map: Vec<usize> = (0..patterns.len()).collect();

    let automaton = AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::Standard)
        .build(&needles)
        .expect("failed to build ASCII Aho-Corasick");

    AcScanner { automaton, pattern_map }
}

fn build_utf16le_scanner() -> AcScanner {
    let patterns = command_patterns::COMMAND_PATTERNS;
    let mut needles: Vec<Vec<u8>> = Vec::with_capacity(patterns.len());
    let mut pattern_map: Vec<usize> = Vec::with_capacity(patterns.len());

    for (i, pat) in patterns.iter().enumerate() {
        let lower = pat.needle.to_ascii_lowercase();
        let utf16 = to_utf16le_bytes(&lower);
        needles.push(utf16);
        pattern_map.push(i);
    }

    let automaton = AhoCorasickBuilder::new()
        .match_kind(MatchKind::Standard)
        .build(&needles)
        .expect("failed to build UTF-16LE Aho-Corasick");

    AcScanner { automaton, pattern_map }
}

static ASCII_SCANNER: OnceLock<AcScanner> = OnceLock::new();
static UTF16LE_SCANNER: OnceLock<AcScanner> = OnceLock::new();

fn get_ascii_scanner() -> &'static AcScanner {
    ASCII_SCANNER.get_or_init(build_ascii_scanner)
}

fn get_utf16le_scanner() -> &'static AcScanner {
    UTF16LE_SCANNER.get_or_init(build_utf16le_scanner)
}

pub fn run(image: &MemoryImage, chunk_size: usize, max_hits: usize) -> Result<CmdscanResult, String> {
    let mut hits = Vec::with_capacity(max_hits.min(512));
    let overlap = 4096;
    let image_size = image.size();
    let patterns = command_patterns::COMMAND_PATTERNS;

    let ascii_ac = get_ascii_scanner();
    let utf16le_ac = get_utf16le_scanner();

    let mut offset: u64 = 0;
    while offset < image_size && hits.len() < max_hits {
        let read_len = std::cmp::min(chunk_size + overlap, (image_size - offset) as usize);
        let chunk = match image.read(offset, read_len) {
            Ok(c) => c,
            Err(_) => {
                offset += chunk_size as u64;
                continue;
            }
        };

        // Single-pass ASCII scan
        scan_with_ac(&chunk, offset, ascii_ac, patterns, HitEncoding::Ascii, &mut hits, max_hits);

        // Single-pass UTF-16LE scan
        if hits.len() < max_hits {
            scan_with_ac(&chunk, offset, utf16le_ac, patterns, HitEncoding::Utf16le, &mut hits, max_hits);
        }

        offset += chunk_size as u64;
    }

    // Prefer higher severity first.
    hits.sort_by(|a, b| severity_rank_str(&b.severity).cmp(&severity_rank_str(&a.severity)));

    Ok(CmdscanResult {
        total_hits: hits.len(),
        hits,
    })
}

fn scan_with_ac(
    chunk: &[u8],
    chunk_base: u64,
    scanner: &AcScanner,
    patterns: &[CommandPattern],
    encoding: HitEncoding,
    hits: &mut Vec<CommandHit>,
    max_hits: usize,
) {
    for mat in scanner.automaton.find_iter(chunk) {
        if hits.len() >= max_hits {
            break;
        }

        let pat_idx = scanner.pattern_map[mat.pattern().as_usize()];
        let pat = &patterns[pat_idx];
        let abs = mat.start();

        // For short needles, require a word boundary before the match to avoid
        // false positives like "content-encoding" matching "-enc".
        if pat.needle.len() < 6 && !has_word_boundary_before(chunk, abs, encoding) {
            continue;
        }

        let hit_off = chunk_base + abs as u64;
        hits.push(CommandHit {
            offset: hit_off,
            encoding,
            category: pat.category.to_string(),
            severity: severity_to_str(pat.severity).to_string(),
            needle: pat.needle.to_string(),
            description: pat.description.to_string(),
            context: extract_context(chunk, abs, encoding),
        });
    }
}

/// Check if there is a word boundary before the match position.
/// For short needles (< 6 chars), this prevents matching inside larger words
/// like "content-encoding" for the needle "-enc".
fn has_word_boundary_before(chunk: &[u8], match_pos: usize, encoding: HitEncoding) -> bool {
    if match_pos == 0 {
        return true;
    }
    let check_pos = match encoding {
        HitEncoding::Ascii => match_pos - 1,
        HitEncoding::Utf16le => {
            // In UTF-16LE, each char is 2 bytes. Check the byte 2 positions before.
            if match_pos >= 2 { match_pos - 2 } else { return true; }
        }
    };
    if check_pos >= chunk.len() {
        return true;
    }
    let b = chunk[check_pos];
    // Word boundary: whitespace, null, pipe, semicolon, quotes, parens, start-of-line chars
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0 | b'|' | b';' | b'"' | b'\'' | b'(' | b')')
}

fn to_utf16le_bytes(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for b in s.as_bytes() {
        out.push(*b);
        out.push(0);
    }
    out
}

fn extract_context(chunk: &[u8], abs_pos: usize, encoding: HitEncoding) -> String {
    let ctx_before = 64usize;
    let ctx_after = 128usize;
    let start = abs_pos.saturating_sub(ctx_before);
    let end = std::cmp::min(chunk.len(), abs_pos + ctx_after);
    let slice = &chunk[start..end];

    match encoding {
        HitEncoding::Ascii => printable_ascii(slice),
        HitEncoding::Utf16le => printable_utf16le(slice),
    }
}

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

fn printable_utf16le(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let lo = bytes[i];
        let hi = bytes[i + 1];
        if hi == 0 {
            if lo.is_ascii_graphic() || lo == b' ' {
                out.push(lo as char);
            } else {
                out.push('.');
            }
        }
        i += 2;
    }
    out
}

fn severity_to_str(s: CommandSeverity) -> &'static str {
    match s {
        CommandSeverity::Critical => "critical",
        CommandSeverity::High => "high",
        CommandSeverity::Medium => "medium",
        CommandSeverity::Low => "low",
    }
}

fn severity_rank_str(s: &str) -> u8 {
    match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utf16le_bytes() {
        assert_eq!(to_utf16le_bytes("ab"), vec![b'a', 0, b'b', 0]);
    }

    #[test]
    fn test_ascii_case_insensitive_match() {
        let chunk = b"xxPoWeRsHeLl -Enc AAA";
        let pat = CommandPattern {
            category: "t",
            severity: CommandSeverity::High,
            needle: "powershell",
            description: "d",
        };
        // Test via the AC scanner path
        let needles: Vec<&[u8]> = vec![pat.needle.as_bytes()];
        let ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(&needles)
            .unwrap();
        let matches: Vec<_> = ac.find_iter(chunk.as_ref()).collect();
        assert!(!matches.is_empty(), "AC should find case-insensitive match");
        assert_eq!(matches[0].start(), 2);
    }

    #[test]
    fn test_word_boundary_rejects_encoding_header() {
        // "content-encoding" should NOT match "-enc" because 't' precedes it
        let chunk = b"content-encoding: gzip";
        let abs = 7; // position of "-enc" in "content-encoding"
        assert!(
            !has_word_boundary_before(chunk, abs, HitEncoding::Ascii),
            "should not have word boundary before -enc inside content-encoding"
        );
    }

    #[test]
    fn test_word_boundary_allows_powershell_enc() {
        // "powershell -enc ABC" SHOULD match because ' ' precedes "-enc"
        let chunk = b"powershell -enc ABC123==";
        let abs = 11; // position of "-enc"
        assert!(
            has_word_boundary_before(chunk, abs, HitEncoding::Ascii),
            "should have word boundary before -enc after a space"
        );
    }

    #[test]
    fn test_utf16le_match() {
        let mut chunk = Vec::new();
        // "xxmimikatz yy" in UTF-16LE
        for b in b"xxmimikatz yy" {
            chunk.push(*b);
            chunk.push(0);
        }
        let needle = to_utf16le_bytes("mimikatz");
        let ac = AhoCorasickBuilder::new()
            .match_kind(MatchKind::Standard)
            .build(&[&needle])
            .unwrap();
        let matches: Vec<_> = ac.find_iter(&chunk).collect();
        assert!(!matches.is_empty(), "AC should find UTF-16LE match");
    }
}
