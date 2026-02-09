//! Core traits for abstracting memory access.
//!
//! The [`MemoryLayer`] trait allows translators and scanners to work with
//! any memory source — mmap files, network streams, etc.

use crate::memory::error::Vol3Result;

/// Trait for reading from a memory layer.
///
/// This abstracts away the source of memory data, allowing translators
/// to work with native Rust layers (e.g. `MmapFileLayer`).
pub trait MemoryLayer: Send + Sync {
    /// Read `length` bytes starting at `offset`.
    fn read(&self, offset: u64, length: usize) -> Vol3Result<Vec<u8>>;

    /// Check if the address range `[offset, offset+length)` is valid.
    fn is_valid(&self, offset: u64, length: u64) -> bool;

    /// The name of this layer.
    fn name(&self) -> &str;

    /// Maximum valid address in this layer.
    fn maximum_address(&self) -> u64;
}
