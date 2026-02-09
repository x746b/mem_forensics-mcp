//! Memory image abstraction — wraps MmapFileLayer.

use crate::memory::layers::MmapFileLayer;
use crate::memory::traits::MemoryLayer;
use isf::MemoryAccess;
use std::sync::Arc;

/// A memory-mapped forensic image.
pub struct MemoryImage {
    layer: Arc<MmapFileLayer>,
}

impl MemoryImage {
    /// Open a memory dump file.
    pub fn open(path: &str) -> Result<Self, String> {
        let layer = MmapFileLayer::open("physical", path, false)
            .map_err(|e| format!("Failed to open memory image: {}", e))?;
        Ok(MemoryImage {
            layer: Arc::new(layer),
        })
    }

    /// Size of the memory dump in bytes.
    pub fn size(&self) -> u64 {
        self.layer.maximum_address().unwrap_or(0) + 1
    }

    /// Read bytes from the physical memory layer.
    pub fn read(&self, offset: u64, length: usize) -> Result<Vec<u8>, String> {
        self.layer
            .read_bytes(offset, length, false)
            .map_err(|e| format!("Read error at {:#x}: {}", offset, e))
    }

    /// Read bytes with zero-padding for out-of-range reads.
    pub fn read_padded(&self, offset: u64, length: usize) -> Vec<u8> {
        self.layer
            .read_bytes(offset, length, true)
            .unwrap_or_else(|_| vec![0u8; length])
    }

    /// Check if an address range is valid.
    #[allow(dead_code)]
    pub fn is_valid(&self, offset: u64, length: u64) -> bool {
        MemoryLayer::is_valid(self.layer.as_ref(), offset, length)
    }

    /// Get a reference to the underlying MmapFileLayer.
    #[allow(dead_code)]
    pub fn layer(&self) -> &MmapFileLayer {
        &self.layer
    }

    /// Get a shared Arc reference to the physical layer for use with translators.
    pub fn physical_layer(&self) -> Arc<dyn MemoryLayer> {
        self.layer.clone() as Arc<dyn MemoryLayer>
    }
}

/// Implement ISF's MemoryAccess trait for direct use with StructReader.
impl MemoryAccess for MemoryImage {
    fn read(
        &self,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        self.layer
            .read_bytes(offset, length, false)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }

    fn is_valid(&self, offset: u64, length: u64) -> bool {
        MemoryLayer::is_valid(self.layer.as_ref(), offset, length)
    }
}
