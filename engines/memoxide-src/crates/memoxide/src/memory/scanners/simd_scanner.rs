//! SIMD-accelerated scanner implementations.
//!
//! Provides high-performance memory scanners using the `memchr` crate for
//! SIMD-accelerated searching and `aho-corasick` for efficient multi-pattern
//! matching. Parallel scanners use Rayon to distribute work across all CPU cores.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use memchr::memmem::Finder;
use rayon::prelude::*;

// =============================================================================
// SimdScanner
// =============================================================================

/// SIMD-accelerated byte pattern scanner.
///
/// # Example (Rust)
///
/// ```rust,ignore
/// let scanner = SimdScanner::new_scanner(b"MZ".to_vec(), 0x1000000, 0x1000);
/// let offsets = scanner.scan(data, 0);
/// ```
#[derive(Clone)]
pub struct SimdScanner {
    /// The pattern to search for.
    needle: Vec<u8>,
    /// Whether this scanner is thread-safe.
    #[allow(dead_code)]
    thread_safe: bool,
    /// Chunk size for scanning (matches Volatility3 default).
    chunk_size: usize,
    /// Overlap size for scanning.
    #[allow(dead_code)]
    overlap: usize,
}

/// Pure-Rust API.
impl SimdScanner {
    /// Create a new SimdScanner.
    ///
    /// # Arguments
    ///
    /// * `needle` - The byte pattern to search for
    /// * `chunk_size` - Size of chunks to scan (typical: 0x1000000 = 16MB)
    /// * `overlap` - Overlap between chunks (typical: 0x1000 = 4KB)
    pub fn new_scanner(needle: Vec<u8>, chunk_size: usize, overlap: usize) -> Self {
        SimdScanner {
            needle,
            thread_safe: true,
            chunk_size,
            overlap,
        }
    }

    /// Scan `data` for the needle pattern, returning all matching offsets.
    ///
    /// Each returned offset is `data_offset + local_position`. Matches in the
    /// overlap region (positions >= `chunk_size`) are excluded.
    pub fn scan(&self, data: &[u8], data_offset: u64) -> Vec<u64> {
        let finder = Finder::new(&self.needle);
        let mut results = Vec::new();
        let mut pos = 0;

        while pos < data.len() {
            if let Some(local_offset) = finder.find(&data[pos..]) {
                let absolute_local = pos + local_offset;
                pos = absolute_local + 1;

                // Only include if not in overlap region
                if absolute_local < self.chunk_size {
                    results.push(data_offset + absolute_local as u64);
                }
            } else {
                break;
            }
        }

        results
    }

    /// Get the needle as a byte slice.
    pub fn needle_bytes(&self) -> &[u8] {
        &self.needle
    }
}

// =============================================================================
// SimdMultiScanner
// =============================================================================

/// SIMD-accelerated multi-pattern scanner.
///
/// Searches for multiple patterns simultaneously using sequential search
/// with SIMD acceleration per pattern.
#[derive(Clone)]
pub struct SimdMultiScanner {
    /// The patterns to search for.
    needles: Vec<Vec<u8>>,
    #[allow(dead_code)]
    thread_safe: bool,
    chunk_size: usize,
    #[allow(dead_code)]
    overlap: usize,
}

/// Pure-Rust API.
impl SimdMultiScanner {
    /// Create a new SimdMultiScanner.
    ///
    /// # Arguments
    ///
    /// * `needles` - The byte patterns to search for
    /// * `chunk_size` - Size of chunks to scan (typical: 0x1000000 = 16MB)
    /// * `overlap` - Overlap between chunks (typical: 0x1000 = 4KB)
    pub fn new_scanner(needles: Vec<Vec<u8>>, chunk_size: usize, overlap: usize) -> Self {
        SimdMultiScanner {
            needles,
            thread_safe: true,
            chunk_size,
            overlap,
        }
    }

    /// Scan `data` for all needle patterns, returning `(offset, matched_pattern)` pairs.
    ///
    /// Results are sorted by offset. Matches in the overlap region
    /// (positions >= `chunk_size`) are excluded.
    pub fn scan_multi(&self, data: &[u8], data_offset: u64) -> Vec<(u64, Vec<u8>)> {
        let mut results: Vec<(u64, Vec<u8>)> = Vec::new();

        for needle in &self.needles {
            let finder = Finder::new(needle);
            let mut pos = 0;

            while pos < data.len() {
                if let Some(local_offset) = finder.find(&data[pos..]) {
                    let absolute_local = pos + local_offset;
                    pos = absolute_local + 1;

                    // Only include if not in overlap region
                    if absolute_local < self.chunk_size {
                        results.push((data_offset + absolute_local as u64, needle.clone()));
                    }
                } else {
                    break;
                }
            }
        }

        // Sort by offset
        results.sort_by_key(|(offset, _)| *offset);
        results
    }

    /// Get the needles.
    pub fn needles(&self) -> &[Vec<u8>] {
        &self.needles
    }
}

// =============================================================================
// AhoCorasickScanner
// =============================================================================

/// Aho-Corasick multi-pattern scanner.
///
/// Uses the Aho-Corasick algorithm for true O(n) multi-pattern matching.
///
/// # Example (Rust)
///
/// ```rust,ignore
/// let scanner = AhoCorasickScanner::new_scanner(
///     vec![b"Proc".to_vec(), b"Thre".to_vec()],
///     0x1000000, 0x1000, "standard",
/// ).unwrap();
/// let results = scanner.scan_multi(data, 0);
/// ```
pub struct AhoCorasickScanner {
    /// The patterns to search for.
    needles: Vec<Vec<u8>>,
    /// Precompiled Aho-Corasick automaton.
    automaton: AhoCorasick,
    #[allow(dead_code)]
    thread_safe: bool,
    chunk_size: usize,
    #[allow(dead_code)]
    overlap: usize,
}

impl std::fmt::Debug for AhoCorasickScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AhoCorasickScanner")
            .field("needles_count", &self.needles.len())
            .field("thread_safe", &self.thread_safe)
            .field("chunk_size", &self.chunk_size)
            .field("overlap", &self.overlap)
            .finish()
    }
}

/// Pure-Rust API.
impl AhoCorasickScanner {
    /// Create a new AhoCorasickScanner.
    ///
    /// # Arguments
    ///
    /// * `needles` - The byte patterns to search for
    /// * `chunk_size` - Size of chunks to scan (typical: 0x1000000 = 16MB)
    /// * `overlap` - Overlap between chunks (typical: 0x1000 = 4KB)
    /// * `match_kind` - Match type: "standard", "leftmost_first", or "leftmost_longest"
    pub fn new_scanner(
        needles: Vec<Vec<u8>>,
        chunk_size: usize,
        overlap: usize,
        match_kind: &str,
    ) -> Result<Self, String> {
        let kind = match match_kind {
            "standard" => MatchKind::Standard,
            "leftmost_first" => MatchKind::LeftmostFirst,
            "leftmost_longest" => MatchKind::LeftmostLongest,
            _ => return Err(
                "match_kind must be 'standard', 'leftmost_first', or 'leftmost_longest'".into()
            ),
        };

        let automaton = AhoCorasickBuilder::new()
            .match_kind(kind)
            .build(&needles)
            .map_err(|e| format!("Failed to build automaton: {}", e))?;

        Ok(AhoCorasickScanner {
            needles,
            automaton,
            thread_safe: true,
            chunk_size,
            overlap,
        })
    }

    /// Scan `data` for all patterns using the Aho-Corasick automaton.
    pub fn scan_multi(&self, data: &[u8], data_offset: u64) -> Vec<(u64, Vec<u8>)> {
        let mut results: Vec<(u64, Vec<u8>)> = Vec::new();

        for mat in self.automaton.find_iter(data) {
            let local_offset = mat.start();

            // Only include if not in overlap region
            if local_offset < self.chunk_size {
                let pattern_idx = mat.pattern().as_usize();
                let pattern = self.needles[pattern_idx].clone();
                results.push((data_offset + local_offset as u64, pattern));
            }
        }

        results
    }

    /// Find all non-overlapping matches.
    pub fn find_nonoverlapping_matches(&self, data: &[u8], data_offset: u64) -> Vec<(u64, Vec<u8>)> {
        let mut results: Vec<(u64, Vec<u8>)> = Vec::new();

        for mat in self.automaton.find_iter(data) {
            let local_offset = mat.start();

            if local_offset < self.chunk_size {
                let pattern_idx = mat.pattern().as_usize();
                let pattern = self.needles[pattern_idx].clone();
                results.push((data_offset + local_offset as u64, pattern));
            }
        }

        results
    }

    /// Get the number of patterns.
    pub fn pattern_count(&self) -> usize {
        self.needles.len()
    }

    /// Get the needles.
    pub fn needles(&self) -> &[Vec<u8>] {
        &self.needles
    }
}

// =============================================================================
// Parallel Scanners (Rayon-based)
// =============================================================================

/// Parallel SIMD scanner using Rayon.
///
/// Distributes scanning work across all CPU cores for maximum throughput.
/// Best for large data buffers (>16MB).
#[derive(Clone)]
pub struct ParallelScanner {
    needle: Vec<u8>,
    #[allow(dead_code)]
    thread_safe: bool,
    chunk_size: usize,
    parallel_chunk_size: usize,
}

/// Pure-Rust API.
impl ParallelScanner {
    /// Create a new ParallelScanner.
    ///
    /// # Arguments
    ///
    /// * `needle` - The byte pattern to search for
    /// * `chunk_size` - Volatility3 chunk size (typical: 0x1000000 = 16MB)
    /// * `parallel_chunk_size` - Size of chunks per thread (typical: 0x400000 = 4MB)
    pub fn new_scanner(needle: Vec<u8>, chunk_size: usize, parallel_chunk_size: usize) -> Self {
        ParallelScanner {
            needle,
            thread_safe: true,
            chunk_size,
            parallel_chunk_size,
        }
    }

    /// Scan `data` for the needle pattern using parallel Rayon workers.
    pub fn scan(&self, data: &[u8], data_offset: u64) -> Vec<u64> {
        let needle = &self.needle;
        let chunk_size = self.chunk_size;
        let parallel_chunk_size = self.parallel_chunk_size;

        let mut results: Vec<u64> = data
            .par_chunks(parallel_chunk_size)
            .enumerate()
            .flat_map(|(chunk_idx, chunk)| {
                let chunk_offset = chunk_idx * parallel_chunk_size;
                let finder = Finder::new(needle);
                let mut local_results = Vec::new();
                let mut pos = 0;

                while pos < chunk.len() {
                    if let Some(local_offset) = finder.find(&chunk[pos..]) {
                        let absolute_local = chunk_offset + pos + local_offset;
                        pos += local_offset + 1;

                        // Only include if not in overlap region
                        if absolute_local < chunk_size {
                            local_results.push(data_offset + absolute_local as u64);
                        }
                    } else {
                        break;
                    }
                }
                local_results
            })
            .collect();

        results.sort();
        results
    }

    /// Get the needle as a byte slice.
    pub fn needle_bytes(&self) -> &[u8] {
        &self.needle
    }

    /// Get the number of CPU threads available.
    pub fn num_threads(&self) -> usize {
        rayon::current_num_threads()
    }
}

// =============================================================================
// ParallelMultiScanner
// =============================================================================

/// Parallel multi-pattern scanner using Rayon.
///
/// Combines SIMD per-pattern search with parallel chunk processing.
#[derive(Clone)]
pub struct ParallelMultiScanner {
    needles: Vec<Vec<u8>>,
    #[allow(dead_code)]
    thread_safe: bool,
    chunk_size: usize,
    parallel_chunk_size: usize,
}

/// Pure-Rust API.
impl ParallelMultiScanner {
    /// Create a new ParallelMultiScanner.
    pub fn new_scanner(needles: Vec<Vec<u8>>, chunk_size: usize, parallel_chunk_size: usize) -> Self {
        ParallelMultiScanner {
            needles,
            thread_safe: true,
            chunk_size,
            parallel_chunk_size,
        }
    }

    /// Scan `data` for all needle patterns using parallel Rayon workers.
    pub fn scan_multi(&self, data: &[u8], data_offset: u64) -> Vec<(u64, Vec<u8>)> {
        let needles = &self.needles;
        let chunk_size = self.chunk_size;
        let parallel_chunk_size = self.parallel_chunk_size;

        let mut results: Vec<(u64, Vec<u8>)> = data
            .par_chunks(parallel_chunk_size)
            .enumerate()
            .flat_map(|(chunk_idx, chunk)| {
                let chunk_offset = chunk_idx * parallel_chunk_size;
                let mut local_results: Vec<(u64, Vec<u8>)> = Vec::new();

                for needle in needles {
                    let finder = Finder::new(needle);
                    let mut pos = 0;

                    while pos < chunk.len() {
                        if let Some(local_offset) = finder.find(&chunk[pos..]) {
                            let absolute_local = chunk_offset + pos + local_offset;
                            pos += local_offset + 1;

                            if absolute_local < chunk_size {
                                local_results.push((
                                    data_offset + absolute_local as u64,
                                    needle.clone(),
                                ));
                            }
                        } else {
                            break;
                        }
                    }
                }
                local_results
            })
            .collect();

        results.sort_by_key(|(offset, _)| *offset);
        results
    }

    /// Get the needles.
    pub fn needles(&self) -> &[Vec<u8>] {
        &self.needles
    }

    /// Get the number of patterns.
    pub fn pattern_count(&self) -> usize {
        self.needles.len()
    }

    /// Get the number of CPU threads available.
    pub fn num_threads(&self) -> usize {
        rayon::current_num_threads()
    }
}

// =============================================================================
// ParallelAhoCorasick
// =============================================================================

/// Parallel Aho-Corasick scanner using Rayon.
///
/// Combines O(n) Aho-Corasick algorithm with parallel chunk processing.
/// Best for many patterns (10+) with large data buffers.
pub struct ParallelAhoCorasick {
    needles: Vec<Vec<u8>>,
    automaton: AhoCorasick,
    #[allow(dead_code)]
    thread_safe: bool,
    chunk_size: usize,
    parallel_chunk_size: usize,
}

/// Pure-Rust API.
impl ParallelAhoCorasick {
    /// Create a new ParallelAhoCorasick scanner.
    pub fn new_scanner(
        needles: Vec<Vec<u8>>,
        chunk_size: usize,
        parallel_chunk_size: usize,
        match_kind: &str,
    ) -> Result<Self, String> {
        let kind = match match_kind {
            "standard" => MatchKind::Standard,
            "leftmost_first" => MatchKind::LeftmostFirst,
            "leftmost_longest" => MatchKind::LeftmostLongest,
            _ => return Err(
                "match_kind must be 'standard', 'leftmost_first', or 'leftmost_longest'".into()
            ),
        };

        let automaton = AhoCorasickBuilder::new()
            .match_kind(kind)
            .build(&needles)
            .map_err(|e| format!("Failed to build automaton: {}", e))?;

        Ok(ParallelAhoCorasick {
            needles,
            automaton,
            thread_safe: true,
            chunk_size,
            parallel_chunk_size,
        })
    }

    /// Scan `data` for all patterns using parallel Aho-Corasick.
    pub fn scan_multi(&self, data: &[u8], data_offset: u64) -> Vec<(u64, Vec<u8>)> {
        let needles = &self.needles;
        let automaton = &self.automaton;
        let chunk_size = self.chunk_size;
        let parallel_chunk_size = self.parallel_chunk_size;

        let mut results: Vec<(u64, Vec<u8>)> = data
            .par_chunks(parallel_chunk_size)
            .enumerate()
            .flat_map(|(chunk_idx, chunk)| {
                let chunk_offset = chunk_idx * parallel_chunk_size;
                let mut local_results: Vec<(u64, Vec<u8>)> = Vec::new();

                for mat in automaton.find_iter(chunk) {
                    let absolute_local = chunk_offset + mat.start();

                    if absolute_local < chunk_size {
                        let pattern_idx = mat.pattern().as_usize();
                        let pattern = needles[pattern_idx].clone();
                        local_results.push((data_offset + absolute_local as u64, pattern));
                    }
                }
                local_results
            })
            .collect();

        results.sort_by_key(|(offset, _)| *offset);
        results
    }

    /// Get the number of patterns.
    pub fn pattern_count(&self) -> usize {
        self.needles.len()
    }

    /// Get the needles.
    pub fn needles(&self) -> &[Vec<u8>] {
        &self.needles
    }

    /// Get the number of CPU threads available.
    pub fn num_threads(&self) -> usize {
        rayon::current_num_threads()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simd_scanner_scan() {
        let scanner = SimdScanner::new_scanner(b"needle".to_vec(), 0x1000000, 0x1000);
        let data = b"hay needle hay needle hay";
        let results = scanner.scan(data, 0);
        assert_eq!(results, vec![4, 15]);
    }

    #[test]
    fn test_simd_scanner_scan_with_offset() {
        let scanner = SimdScanner::new_scanner(b"AB".to_vec(), 0x1000000, 0x1000);
        let data = b"__AB__AB__";
        let results = scanner.scan(data, 1000);
        assert_eq!(results, vec![1002, 1006]);
    }

    #[test]
    fn test_simd_scanner_overlap_filtering() {
        // Use a small chunk_size so we can test overlap filtering
        let scanner = SimdScanner::new_scanner(b"X".to_vec(), 10, 5);
        let data = b"X_X_X_X_X_X_X_X_X";
        let results = scanner.scan(data, 0);
        // Only positions 0, 2, 4, 6, 8 should be returned (< chunk_size of 10)
        assert_eq!(results, vec![0, 2, 4, 6, 8]);
    }

    #[test]
    fn test_simd_scanner_no_match() {
        let scanner = SimdScanner::new_scanner(b"ZZZZZ".to_vec(), 0x1000000, 0x1000);
        let data = b"hay hay hay";
        let results = scanner.scan(data, 0);
        assert!(results.is_empty());
    }

    #[test]
    fn test_simd_scanner_empty_data() {
        let scanner = SimdScanner::new_scanner(b"needle".to_vec(), 0x1000000, 0x1000);
        let results = scanner.scan(b"", 0);
        assert!(results.is_empty());
    }

    #[test]
    fn test_simd_multi_scanner_scan_multi() {
        let scanner = SimdMultiScanner::new_scanner(
            vec![b"foo".to_vec(), b"bar".to_vec()],
            0x1000000,
            0x1000,
        );
        let data = b"foo bar foo baz bar";
        let results = scanner.scan_multi(data, 100);

        assert_eq!(results.len(), 4);
        assert_eq!(results[0], (100, b"foo".to_vec()));
        assert_eq!(results[1], (104, b"bar".to_vec()));
        assert_eq!(results[2], (108, b"foo".to_vec()));
        assert_eq!(results[3], (116, b"bar".to_vec()));
    }

    #[test]
    fn test_simd_multi_scanner_no_match() {
        let scanner = SimdMultiScanner::new_scanner(
            vec![b"xxx".to_vec(), b"yyy".to_vec()],
            0x1000000,
            0x1000,
        );
        let data = b"foo bar baz";
        let results = scanner.scan_multi(data, 0);
        assert!(results.is_empty());
    }

    #[test]
    fn test_aho_corasick_scanner_scan_multi() {
        let scanner = AhoCorasickScanner::new_scanner(
            vec![b"Proc".to_vec(), b"Thre".to_vec(), b"File".to_vec()],
            0x1000000,
            0x1000,
            "standard",
        )
        .unwrap();

        let data = b"ProcThreFileProcFile";
        let results = scanner.scan_multi(data, 0);

        assert_eq!(results.len(), 5);
        assert_eq!(results[0], (0, b"Proc".to_vec()));
        assert_eq!(results[1], (4, b"Thre".to_vec()));
        assert_eq!(results[2], (8, b"File".to_vec()));
        assert_eq!(results[3], (12, b"Proc".to_vec()));
        assert_eq!(results[4], (16, b"File".to_vec()));
    }

    #[test]
    fn test_aho_corasick_scanner_invalid_match_kind() {
        let result = AhoCorasickScanner::new_scanner(
            vec![b"foo".to_vec()],
            0x1000000,
            0x1000,
            "invalid",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("match_kind must be"));
    }

    #[test]
    fn test_aho_corasick_scanner_pattern_count() {
        let scanner = AhoCorasickScanner::new_scanner(
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
            0x1000000,
            0x1000,
            "standard",
        )
        .unwrap();
        assert_eq!(scanner.pattern_count(), 3);
    }

    #[test]
    fn test_parallel_scanner_scan() {
        let scanner = ParallelScanner::new_scanner(b"needle".to_vec(), 0x1000000, 0x400000);
        let data = b"hay needle hay needle hay";
        let results = scanner.scan(data, 0);
        assert_eq!(results, vec![4, 15]);
    }

    #[test]
    fn test_parallel_scanner_large_data() {
        // Create data large enough to exercise multiple parallel chunks
        let mut data = vec![0u8; 2 * 1024 * 1024]; // 2MB
        // Place markers at known positions
        data[0] = b'M';
        data[1] = b'Z';
        data[1_000_000] = b'M';
        data[1_000_001] = b'Z';

        let scanner = ParallelScanner::new_scanner(b"MZ".to_vec(), 0x1000000, 0x100000);
        let results = scanner.scan(&data, 0);
        assert_eq!(results, vec![0, 1_000_000]);
    }

    #[test]
    fn test_parallel_multi_scanner_scan_multi() {
        let scanner = ParallelMultiScanner::new_scanner(
            vec![b"foo".to_vec(), b"bar".to_vec()],
            0x1000000,
            0x400000,
        );
        let data = b"foo bar foo baz bar";
        let results = scanner.scan_multi(data, 100);

        assert_eq!(results.len(), 4);
        assert_eq!(results[0], (100, b"foo".to_vec()));
        assert_eq!(results[1], (104, b"bar".to_vec()));
        assert_eq!(results[2], (108, b"foo".to_vec()));
        assert_eq!(results[3], (116, b"bar".to_vec()));
    }

    #[test]
    fn test_parallel_aho_corasick_scan_multi() {
        let scanner = ParallelAhoCorasick::new_scanner(
            vec![b"Proc".to_vec(), b"Thre".to_vec(), b"File".to_vec()],
            0x1000000,
            0x400000,
            "standard",
        )
        .unwrap();

        let data = b"ProcThreFileProcFile";
        let results = scanner.scan_multi(data, 0);

        assert_eq!(results.len(), 5);
        assert_eq!(results[0], (0, b"Proc".to_vec()));
        assert_eq!(results[1], (4, b"Thre".to_vec()));
        assert_eq!(results[2], (8, b"File".to_vec()));
        assert_eq!(results[3], (12, b"Proc".to_vec()));
        assert_eq!(results[4], (16, b"File".to_vec()));
    }

    #[test]
    fn test_parallel_aho_corasick_invalid_match_kind() {
        let result = ParallelAhoCorasick::new_scanner(
            vec![b"foo".to_vec()],
            0x1000000,
            0x400000,
            "bad",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_parallel_scanner_num_threads() {
        let scanner = ParallelScanner::new_scanner(b"x".to_vec(), 0x1000000, 0x400000);
        assert!(scanner.num_threads() >= 1);
    }
}
