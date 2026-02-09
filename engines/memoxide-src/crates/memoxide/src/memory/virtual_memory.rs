//! Virtual memory translation — wraps Intel64Translator.
//!
//! Given a DTB (CR3 value) and a physical memory layer, creates a virtual
//! memory view that translates virtual addresses to physical using x86-64
//! page tables. Implements ISF's `MemoryAccess` trait so it can be used
//! directly with `StructReader`.

use crate::memory::traits::MemoryLayer;
use crate::memory::translators::Intel64Translator;
use isf::MemoryAccess;
use std::sync::Arc;

/// Virtual memory layer that translates virtual addresses via page tables.
pub struct VirtualMemory {
    translator: Intel64Translator,
}

impl VirtualMemory {
    /// Create a new virtual memory view.
    ///
    /// # Arguments
    /// * `physical` - The physical memory layer (e.g., MemoryImage's underlying layer)
    /// * `dtb` - Directory Table Base (CR3 register value)
    /// * `cache_size` - LRU cache size for page table entries (default: 4096)
    pub fn new(
        physical: Arc<dyn MemoryLayer>,
        dtb: u64,
        cache_size: usize,
    ) -> Result<Self, String> {
        let translator = Intel64Translator::new_with_layer(
            "kernel_virtual".to_string(),
            physical,
            dtb,
            cache_size,
        )
        .map_err(|e| format!("Failed to create translator: {}", e))?;

        Ok(VirtualMemory { translator })
    }

    /// Create with default cache size.
    pub fn with_dtb(physical: Arc<dyn MemoryLayer>, dtb: u64) -> Result<Self, String> {
        Self::new(physical, dtb, 4096)
    }

    /// Read bytes from a virtual address.
    pub fn read_virtual(&self, offset: u64, length: usize) -> Result<Vec<u8>, String> {
        self.translator
            .read(offset, length)
            .map_err(|e| format!("Virtual read error at {:#x}: {}", offset, e))
    }

    /// Check if a virtual address is valid (maps to physical memory).
    #[allow(dead_code)]
    pub fn is_valid_virtual(&self, offset: u64, length: u64) -> bool {
        self.translator.is_valid(offset, length)
    }
}

/// Implement ISF's MemoryAccess trait for use with StructReader.
impl MemoryAccess for VirtualMemory {
    fn read(
        &self,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        self.translator
            .read(offset, length)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }

    fn is_valid(&self, offset: u64, length: u64) -> bool {
        self.translator.is_valid(offset, length)
    }
}
