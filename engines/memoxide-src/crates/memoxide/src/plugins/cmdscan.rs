//! CmdScan (lite) — best-effort recovery of suspicious command strings.
//!
//! This is not a full Volatility-style console structure parser yet.
//! Instead, it scans physical memory for suspicious command substrings in
//! both ASCII and UTF-16LE, and returns hits with offsets + small context.

use crate::memory::image::MemoryImage;
use crate::rules::command_patterns::{self, CommandPattern, CommandSeverity};
use serde::{Deserialize, Serialize};

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

pub fn run(image: &MemoryImage, chunk_size: usize, max_hits: usize) -> Result<CmdscanResult, String> {
    let mut hits = Vec::new();
    let overlap = 4096;
    let image_size = image.size();

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

        // Scan ASCII and UTF-16LE in the same raw chunk.
        for pat in command_patterns::COMMAND_PATTERNS {
            if hits.len() >= max_hits {
                break;
            }
            scan_for_pattern(
                &chunk,
                offset,
                pat,
                &mut hits,
                max_hits,
                HitEncoding::Ascii,
            );
            if hits.len() >= max_hits {
                break;
            }
            scan_for_pattern(
                &chunk,
                offset,
                pat,
                &mut hits,
                max_hits,
                HitEncoding::Utf16le,
            );
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

fn scan_for_pattern(
    chunk: &[u8],
    chunk_base: u64,
    pat: &CommandPattern,
    hits: &mut Vec<CommandHit>,
    max_hits: usize,
    encoding: HitEncoding,
) {
    let needle_lower = pat.needle.to_ascii_lowercase();
    let needle_bytes = match encoding {
        HitEncoding::Ascii => needle_lower.as_bytes().to_vec(),
        HitEncoding::Utf16le => to_utf16le_bytes(&needle_lower),
    };
    if needle_bytes.is_empty() || chunk.len() < needle_bytes.len() {
        return;
    }

    // Case-insensitive match implemented by lowercasing the haystack on-the-fly for ASCII-ish ranges
    // isn't feasible for raw memory; we approximate by only matching lowercase needles and doing a
    // lowercasing compare per candidate window.
    //
    // We use memchr on the first byte to find candidates quickly.
    let first = needle_bytes[0];
    let first_alt = match encoding {
        HitEncoding::Ascii => first.to_ascii_uppercase(),
        HitEncoding::Utf16le => first,
    };
    let mut pos = 0;
    while pos + needle_bytes.len() <= chunk.len() && hits.len() < max_hits {
        let rel = match encoding {
            HitEncoding::Ascii => memchr::memchr2(first, first_alt, &chunk[pos..]),
            HitEncoding::Utf16le => memchr::memchr(first, &chunk[pos..]),
        };
        let rel = match rel {
            Some(r) => r,
            None => break,
        };
        let abs = pos + rel;
        if abs + needle_bytes.len() > chunk.len() {
            break;
        }

        if window_eq_case_insensitive(&chunk[abs..abs + needle_bytes.len()], &needle_bytes, encoding)
        {
            // For short needles, require a word boundary before the match to avoid
            // false positives like "content-encoding" matching "-enc".
            if pat.needle.len() < 6 && !has_word_boundary_before(chunk, abs, encoding) {
                pos = abs + 1;
                continue;
            }

            let hit_off = chunk_base + abs as u64;
            hits.push(CommandHit {
                offset: hit_off,
                encoding: encoding.clone(),
                category: pat.category.to_string(),
                severity: severity_to_str(pat.severity).to_string(),
                needle: pat.needle.to_string(),
                description: pat.description.to_string(),
                context: extract_context(chunk, abs, encoding),
            });
        }

        pos = abs + 1;
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

fn window_eq_case_insensitive(window: &[u8], needle_lower: &[u8], encoding: HitEncoding) -> bool {
    match encoding {
        HitEncoding::Ascii => window
            .iter()
            .zip(needle_lower.iter())
            .all(|(&w, &n)| w.to_ascii_lowercase() == n),
        HitEncoding::Utf16le => {
            // UTF-16LE lowercasing isn't attempted; we just compare bytes exactly
            // against a lowercased ASCII needle expanded to UTF-16LE. This still
            // hits in the common case where the buffer is lowercase or mixed and
            // ASCII range unaffected (e.g., flags/keywords).
            window == needle_lower
        }
    }
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
        let mut hits = Vec::new();
        scan_for_pattern(chunk, 0, &pat, &mut hits, 10, HitEncoding::Ascii);
        assert!(!hits.is_empty());
    }

    #[test]
    fn test_word_boundary_rejects_encoding_header() {
        // "content-encoding" should NOT match "-enc" because 't' precedes it
        let chunk = b"content-encoding: gzip";
        let pat = CommandPattern {
            category: "powershell_encoded",
            severity: CommandSeverity::High,
            needle: "-enc",
            description: "PowerShell encoded command flag",
        };
        let mut hits = Vec::new();
        scan_for_pattern(chunk, 0, &pat, &mut hits, 10, HitEncoding::Ascii);
        assert!(hits.is_empty(), "should not match -enc inside content-encoding");
    }

    #[test]
    fn test_word_boundary_allows_powershell_enc() {
        // "powershell -enc ABC" SHOULD match because ' ' precedes "-enc"
        let chunk = b"powershell -enc ABC123==";
        let pat = CommandPattern {
            category: "powershell_encoded",
            severity: CommandSeverity::High,
            needle: "-enc",
            description: "PowerShell encoded command flag",
        };
        let mut hits = Vec::new();
        scan_for_pattern(chunk, 0, &pat, &mut hits, 10, HitEncoding::Ascii);
        assert!(!hits.is_empty(), "should match -enc after a space");
    }

    #[test]
    fn test_utf16le_match() {
        let mut chunk = Vec::new();
        // "mimikatz" in UTF-16LE
        for b in b"xxmimikatz yy" {
            chunk.push(*b);
            chunk.push(0);
        }
        let pat = CommandPattern {
            category: "t",
            severity: CommandSeverity::Critical,
            needle: "mimikatz",
            description: "d",
        };
        let mut hits = Vec::new();
        scan_for_pattern(&chunk, 0, &pat, &mut hits, 10, HitEncoding::Utf16le);
        assert!(!hits.is_empty());
    }
}
