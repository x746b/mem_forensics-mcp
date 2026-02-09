//! Registry hive discovery and parsing from memory dumps.
//!
//! Scans physical memory for registry hive signatures (`regf` base block
//! headers) and parses the in-memory hive to navigate keys, subkeys, and values.
//!
//! This module does NOT require ISF symbols — registry hive internals use
//! well-known, stable binary formats (HBASE_BLOCK, HBIN, NK/VK cells) that
//! are consistent across Windows versions.

#[allow(dead_code)]
pub mod crypto;
#[allow(dead_code)]
pub mod hive;
