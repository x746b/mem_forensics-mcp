//! Scanner implementations.
//!
//! This module provides high-performance SIMD-accelerated scanners.
//!
//! ## Scanner Types
//!
//! - `SimdScanner` - Single-pattern SIMD search (single-threaded)
//! - `SimdMultiScanner` - Multi-pattern SIMD search (single-threaded)
//! - `AhoCorasickScanner` - O(n) multi-pattern search (single-threaded)
//! - `ParallelScanner` - Single-pattern SIMD search (multi-threaded)
//! - `ParallelMultiScanner` - Multi-pattern SIMD search (multi-threaded)
//! - `ParallelAhoCorasick` - O(n) multi-pattern search (multi-threaded)

pub mod simd_scanner;

#[allow(unused_imports)]
pub use simd_scanner::{
    // Single-threaded scanners
    SimdScanner,
    SimdMultiScanner,
    AhoCorasickScanner,
    // Parallel scanners (Rayon)
    ParallelScanner,
    ParallelMultiScanner,
    ParallelAhoCorasick,
};
