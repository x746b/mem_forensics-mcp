//! Layer implementations.
//!
//! This module provides high-performance replacements for Volatility3's
//! data layer implementations.

pub mod mmap_file;

pub use mmap_file::MmapFileLayer;
