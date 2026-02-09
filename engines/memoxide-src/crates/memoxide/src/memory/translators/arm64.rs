//! ARM64 (AArch64) address translation.
//!
//! Provides a high-performance ARM64 address translator with LRU caching.
//! Supports multiple page granule sizes (4KB, 16KB, 64KB).
//!
//! # Page Table Structure (4KB granule, 48-bit VA)
//!
//! ```text
//! Virtual Address (48-bit):
//! +----------+----------+----------+----------+------------+
//! | L0 (9b)  | L1 (9b)  | L2 (9b)  | L3 (9b)  | Offset(12b)|
//! | [47:39]  | [38:30]  | [29:21]  | [20:12]  | [11:0]     |
//! +----------+----------+----------+----------+------------+
//! ```
//!
//! # Descriptor Types
//!
//! - **Invalid** (bit 0 = 0): Entry not valid
//! - **Block** (bits [1:0] = 01): Maps a large block (1GB at L1, 2MB at L2)
//! - **Table** (bits [1:0] = 11): Points to next level table
//! - **Page** (bits [1:0] = 11 at L3): Maps a 4KB page
//!
//! # Supported Configurations
//!
//! | Granule | L0 | L1 | L2 | L3 | VA bits |
//! |---------|----|----|----|----|---------|
//! | 4KB     | 9  | 9  | 9  | 9  | 48      |
//! | 16KB    | 1  | 11 | 11 | 11 | 47      |
//! | 64KB    | -  | 6  | 13 | 13 | 52      |

use crate::memory::error::{Vol3Error, Vol3Result};
use crate::memory::traits::MemoryLayer;
use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::sync::Arc;

/// Descriptor type bits [1:0].
const DESC_TYPE_MASK: u64 = 0b11;
const DESC_BLOCK: u64 = 0b01;        // Block descriptor (L1/L2 only)
const DESC_TABLE: u64 = 0b11;        // Table descriptor (or page at L3)

/// Page/block descriptor attributes.
const DESC_VALID: u64 = 1 << 0;      // Valid bit

/// Page sizes.
const PAGE_SIZE_4K: u64 = 4 * 1024;
const PAGE_SIZE_16K: u64 = 16 * 1024;
const PAGE_SIZE_64K: u64 = 64 * 1024;

/// Entry size (always 8 bytes for ARM64).
const ENTRY_SIZE: usize = 8;

/// Page granule enumeration.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PageGranule {
    Granule4K,
    Granule16K,
    Granule64K,
}

impl PageGranule {
    /// Get page size in bytes.
    pub fn page_size(&self) -> u64 {
        match self {
            PageGranule::Granule4K => PAGE_SIZE_4K,
            PageGranule::Granule16K => PAGE_SIZE_16K,
            PageGranule::Granule64K => PAGE_SIZE_64K,
        }
    }

    /// Get page shift (log2 of page size).
    pub fn page_shift(&self) -> u32 {
        match self {
            PageGranule::Granule4K => 12,
            PageGranule::Granule16K => 14,
            PageGranule::Granule64K => 16,
        }
    }

    /// Get the page table structure for this granule.
    /// Returns (name, bit_size, can_be_block) for each level.
    pub fn structure(&self) -> &'static [(&'static str, u32, bool)] {
        match self {
            PageGranule::Granule4K => &[
                ("level 0", 9, false),   // L0: no blocks
                ("level 1", 9, true),    // L1: 1GB blocks
                ("level 2", 9, true),    // L2: 2MB blocks
                ("level 3", 9, false),   // L3: 4KB pages
            ],
            PageGranule::Granule16K => &[
                ("level 0", 1, false),   // L0: 1 bit
                ("level 1", 11, true),   // L1: 32MB blocks
                ("level 2", 11, true),   // L2: 2MB blocks
                ("level 3", 11, false),  // L3: 16KB pages
            ],
            PageGranule::Granule64K => &[
                ("level 1", 6, true),    // L1: 4TB blocks (no L0 for 64KB)
                ("level 2", 13, true),   // L2: 512MB blocks
                ("level 3", 13, false),  // L3: 64KB pages
            ],
        }
    }

    /// Get maximum virtual address bits.
    pub fn max_virt_addr_bits(&self) -> u32 {
        match self {
            PageGranule::Granule4K => 48,
            PageGranule::Granule16K => 47,
            PageGranule::Granule64K => 52,
        }
    }

    /// Get entries per table.
    pub fn entries_per_table(&self) -> usize {
        (self.page_size() as usize) / ENTRY_SIZE
    }
}

/// Granule configuration (always available, not Python-gated).
#[derive(Clone, Debug)]
pub struct GranuleConfig {
    pub granule: PageGranule,
    pub max_phys_addr: u32,
    pub max_virt_addr: u32,
}

impl GranuleConfig {
    pub fn new(granule: PageGranule, max_phys_addr: u32) -> Self {
        Self {
            granule,
            max_phys_addr,
            max_virt_addr: granule.max_virt_addr_bits(),
        }
    }
}

/// Cache entry type: maps page address to (entry, position).
type CacheEntry = (u64, u32);

/// Cached translation result.
#[derive(Clone, Debug)]
struct TranslationResult {
    physical_address: u64,
    page_size: u64,
    layer_name: String,
}

/// ARM64 address translator with LRU caching.
///
/// Supports 4KB, 16KB, and 64KB page granules with up to 4-level
/// page table walking.
///
/// # Thread Safety
///
/// This implementation is thread-safe using `parking_lot::Mutex` for the cache.
pub struct Arm64Translator {
    /// Layer name.
    name: String,
    /// Name of the base (physical) layer.
    base_layer_name: String,
    /// Translation table base (TTBR value).
    ttbr: u64,
    /// Reference to the base layer for reading.
    base_layer: Arc<dyn MemoryLayer>,
    /// LRU cache for page table entries.
    entry_cache: Arc<Mutex<LruCache<u64, CacheEntry>>>,
    /// LRU cache for valid page tables.
    table_cache: Arc<Mutex<LruCache<u64, Option<Vec<u8>>>>>,
    /// Page granule size.
    granule: PageGranule,
    /// Maximum physical address bits.
    max_phys_addr: u32,
    /// Maximum virtual address bits.
    max_virt_addr: u32,
    /// Initial entry value (from TTBR).
    initial_entry: u64,
    /// Initial position (highest VA bit).
    initial_position: u32,
}

impl Arm64Translator {
    /// Create a mask for bits between high_bit and low_bit (inclusive).
    #[inline]
    fn mask(value: u64, high_bit: u32, low_bit: u32) -> u64 {
        let high_mask = if high_bit >= 63 {
            u64::MAX
        } else {
            (1u64 << (high_bit + 1)).wrapping_sub(1)
        };
        let low_mask = if low_bit >= 64 {
            u64::MAX
        } else {
            (1u64 << low_bit).wrapping_sub(1)
        };
        value & (high_mask ^ low_mask)
    }

    /// Check if a descriptor is valid.
    #[inline]
    fn desc_is_valid(entry: u64) -> bool {
        entry & DESC_VALID != 0
    }

    /// Check if a descriptor is a block (large page).
    #[inline]
    fn is_block(entry: u64) -> bool {
        (entry & DESC_TYPE_MASK) == DESC_BLOCK
    }

    /// Check if a descriptor is a table pointer.
    #[inline]
    fn is_table(entry: u64) -> bool {
        (entry & DESC_TYPE_MASK) == DESC_TABLE
    }

    /// Extract output address from a descriptor.
    /// For 4KB granule: bits [47:12] contain the address
    /// For 16KB granule: bits [47:14] contain the address
    /// For 64KB granule: bits [47:16] contain the address
    #[inline]
    fn extract_address(&self, entry: u64, _level_bits: u32) -> u64 {
        let page_shift = self.granule.page_shift();
        let addr_mask = ((1u64 << self.max_phys_addr) - 1) & !((1u64 << page_shift) - 1);
        entry & addr_mask
    }

    /// Extract block address with proper alignment.
    #[inline]
    fn extract_block_address(&self, entry: u64, position: u32) -> u64 {
        let block_shift = position + 1;
        let addr_mask = ((1u64 << self.max_phys_addr) - 1) & !((1u64 << block_shift) - 1);
        entry & addr_mask
    }

    /// Get the address mask for virtual addresses.
    #[inline]
    fn address_mask(&self) -> u64 {
        (1u64 << self.max_virt_addr) - 1
    }

    /// Read from the base layer.
    fn read_base_layer(&self, offset: u64, length: usize) -> Vol3Result<Vec<u8>> {
        self.base_layer.read(offset, length)
    }

    /// Get a valid page table, checking for duplicate entries.
    fn get_valid_table(&self, base_address: u64) -> Vol3Result<Option<Vec<u8>>> {
        // Check cache first
        {
            let mut cache = self.table_cache.lock();
            if let Some(cached) = cache.get(&base_address) {
                return Ok(cached.clone());
            }
        }

        // Read the table
        let table_size = self.granule.page_size() as usize;
        let table = match self.read_base_layer(base_address, table_size) {
            Ok(t) => t,
            Err(_) => {
                let mut cache = self.table_cache.lock();
                cache.put(base_address, None);
                return Ok(None);
            }
        };

        // Check for duplicate entries (optimization for unmapped regions)
        if table.len() >= ENTRY_SIZE {
            let first_entry = &table[..ENTRY_SIZE];
            let is_duplicate = table.chunks_exact(ENTRY_SIZE).all(|chunk| chunk == first_entry);
            if is_duplicate {
                let mut cache = self.table_cache.lock();
                cache.put(base_address, None);
                return Ok(None);
            }
        }

        // Cache and return
        let mut cache = self.table_cache.lock();
        cache.put(base_address, Some(table.clone()));
        Ok(Some(table))
    }

    /// Translate a page address through the page tables.
    fn translate_entry(&self, page_address: u64) -> Vol3Result<CacheEntry> {
        // Check cache first
        {
            let mut cache = self.entry_cache.lock();
            if let Some(cached) = cache.get(&page_address) {
                return Ok(*cached);
            }
        }

        // Validate address range
        if page_address & self.address_mask() > self.maximum_address_static() {
            return Err(Vol3Error::paged_invalid_address(
                &self.name,
                page_address,
                self.initial_position + 1,
                self.initial_entry,
                "Entry outside virtual address range",
            ));
        }

        let structure = self.granule.structure();
        let mut position = self.initial_position;
        let mut entry = self.initial_entry;

        // Walk through each level of the page table structure
        for (level_idx, (name, size, can_be_block)) in structure.iter().enumerate() {
            // Check if entry is valid
            if !Self::desc_is_valid(entry) {
                return Err(Vol3Error::paged_invalid_address(
                    &self.name,
                    page_address,
                    position + 1,
                    entry,
                    format!("Invalid descriptor at {} (entry={:#x})", name, entry),
                ));
            }

            // For non-last levels, check descriptor type
            let is_last_level = level_idx == structure.len() - 1;

            if !is_last_level {
                // Check for block descriptor (large page)
                if *can_be_block && Self::is_block(entry) {
                    // This is a block (large page) - stop here
                    break;
                }

                // Must be a table descriptor
                if !Self::is_table(entry) {
                    return Err(Vol3Error::paged_invalid_address(
                        &self.name,
                        page_address,
                        position + 1,
                        entry,
                        format!("Invalid descriptor type at {} (entry={:#x})", name, entry),
                    ));
                }
            }

            // Calculate base address of next table
            let base_address = self.extract_address(entry, *size);

            // Get the table
            let table = match self.get_valid_table(base_address)? {
                Some(t) => t,
                None => {
                    return Err(Vol3Error::paged_invalid_address(
                        &self.name,
                        page_address,
                        position + 1,
                        entry,
                        format!("Invalid table at {} (base={:#x})", name, base_address),
                    ));
                }
            };

            // Calculate index into the table
            let start = position;
            position -= size;
            let index = (Self::mask(page_address, start, position + 1) >> (position + 1)) as usize;

            // Read the entry
            let entry_offset = index * ENTRY_SIZE;
            if entry_offset + ENTRY_SIZE > table.len() {
                return Err(Vol3Error::paged_invalid_address(
                    &self.name,
                    page_address,
                    position + 1,
                    entry,
                    "Entry offset out of bounds",
                ));
            }

            entry = u64::from_le_bytes(
                table[entry_offset..entry_offset + ENTRY_SIZE]
                    .try_into()
                    .unwrap(),
            );
        }

        // Cache the result
        let result = (entry, position);
        {
            let mut cache = self.entry_cache.lock();
            cache.put(page_address, result);
        }

        Ok(result)
    }

    /// Perform full address translation.
    fn translate_impl(&self, offset: u64) -> Vol3Result<TranslationResult> {
        let page_shift = self.granule.page_shift();
        let page_address = offset & !((1u64 << page_shift) - 1);
        let (entry, position) = self.translate_entry(page_address)?;

        if !Self::desc_is_valid(entry) {
            return Err(Vol3Error::paged_invalid_address(
                &self.name,
                offset,
                position + 1,
                entry,
                format!("Invalid final descriptor (entry={:#x})", entry),
            ));
        }

        // Determine if this is a block or page descriptor
        let (physical_base, page_size) = if Self::is_block(entry) {
            // Block descriptor - extract aligned block address
            let block_address = self.extract_block_address(entry, position);
            let block_size = 1u64 << (position + 1);
            (block_address, block_size)
        } else {
            // Page descriptor (L3) - extract page address
            let page_address = self.extract_address(entry, 0);
            (page_address, self.granule.page_size())
        };

        // Calculate final physical address
        let offset_mask = page_size - 1;
        let page_offset = offset & offset_mask;
        let physical_address = physical_base | page_offset;

        Ok(TranslationResult {
            physical_address,
            page_size,
            layer_name: self.base_layer_name.clone(),
        })
    }

    /// Static maximum address.
    fn maximum_address_static(&self) -> u64 {
        (1u64 << self.max_virt_addr) - 1
    }

    // ------------------------------------------------------------------
    // Pure-Rust public API
    // ------------------------------------------------------------------

    /// Create a new ARM64 translator (pure Rust).
    ///
    /// # Arguments
    ///
    /// * `name` - The name of this translation layer
    /// * `base_layer` - The base (physical) layer
    /// * `ttbr` - Translation Table Base Register value
    /// * `granule` - Page granule size
    /// * `cache_size` - Size of the LRU cache
    /// * `max_phys_addr` - Maximum physical address bits
    pub fn new_with_layer(
        name: String,
        base_layer: Arc<dyn MemoryLayer>,
        ttbr: u64,
        granule: PageGranule,
        cache_size: usize,
        max_phys_addr: u32,
    ) -> Self {
        let base_layer_name = base_layer.name().to_string();
        let max_virt_addr = granule.max_virt_addr_bits();
        let initial_position = max_virt_addr - 1;

        let page_shift = granule.page_shift();
        let addr_mask = ((1u64 << max_phys_addr) - 1) & !((1u64 << page_shift) - 1);
        let initial_entry = (ttbr & addr_mask) | DESC_TABLE;

        let cache_size_nz = NonZeroUsize::new(cache_size).unwrap_or(NonZeroUsize::new(1024).unwrap());
        let table_cache_size = NonZeroUsize::new(cache_size + 1).unwrap_or(NonZeroUsize::new(1025).unwrap());

        Arm64Translator {
            name,
            base_layer_name,
            ttbr,
            base_layer,
            entry_cache: Arc::new(Mutex::new(LruCache::new(cache_size_nz))),
            table_cache: Arc::new(Mutex::new(LruCache::new(table_cache_size))),
            granule,
            max_phys_addr,
            max_virt_addr,
            initial_entry,
            initial_position,
        }
    }

    /// Translate a virtual address to physical (pure Rust).
    ///
    /// Returns (physical_address, page_size, layer_name).
    pub fn translate_address(&self, offset: u64) -> Vol3Result<(u64, u64, String)> {
        let result = self.translate_impl(offset)?;
        Ok((result.physical_address, result.page_size, result.layer_name))
    }

    /// Get address mapping for a range (pure Rust).
    ///
    /// Returns a list of (offset, sublength, mapped_offset, mapped_length, layer_name) tuples.
    pub fn mapping_ranges(
        &self,
        offset: u64,
        length: u64,
        ignore_errors: bool,
    ) -> Vol3Result<Vec<(u64, u64, u64, u64, String)>> {
        let mut results = Vec::new();
        let mut remaining = length;
        let mut current_offset = offset;

        while remaining > 0 {
            match self.translate_impl(current_offset) {
                Ok(result) => {
                    let page_offset = current_offset % result.page_size;
                    let chunk_size = (result.page_size - page_offset).min(remaining);

                    results.push((
                        current_offset,
                        chunk_size,
                        result.physical_address,
                        chunk_size,
                        result.layer_name,
                    ));

                    current_offset += chunk_size;
                    remaining -= chunk_size;
                }
                Err(e) => {
                    if !ignore_errors {
                        return Err(e);
                    }
                    let skip = match &e {
                        Vol3Error::PagedInvalidAddress { invalid_bits, .. } => {
                            let skip_mask = (1u64 << invalid_bits) - 1;
                            skip_mask + 1 - (current_offset & skip_mask)
                        }
                        _ => self.granule.page_size() - (current_offset % self.granule.page_size()),
                    };
                    let skip = skip.min(remaining);
                    current_offset += skip;
                    remaining -= skip;
                }
            }
        }

        Ok(results)
    }

    /// Read data from the translated layer (pure Rust).
    pub fn read_virtual(&self, offset: u64, length: usize, pad: bool) -> Vol3Result<Vec<u8>> {
        let mut output = Vec::with_capacity(length);
        let mut current_offset = offset;
        let remaining = length as u64;

        for (layer_offset, sublength, mapped_offset, _, _layer_name) in
            self.mapping_ranges(offset, remaining, pad)?
        {
            if layer_offset > current_offset {
                if !pad {
                    return Err(Vol3Error::invalid_address(
                        &self.name,
                        current_offset,
                        format!("Layer {} cannot map offset: {:#x}", self.name, current_offset),
                    ));
                }
                let gap = (layer_offset - current_offset) as usize;
                output.extend(std::iter::repeat(0u8).take(gap));
                current_offset = layer_offset;
            }

            let chunk = self.read_base_layer(mapped_offset, sublength as usize)?;
            output.extend_from_slice(&chunk);
            current_offset += sublength;
        }

        if pad && output.len() < length {
            output.resize(length, 0);
        }

        Ok(output)
    }

    /// Check if an address range is valid (pure Rust).
    pub fn check_valid(&self, offset: u64, length: u64) -> bool {
        self.mapping_ranges(offset, length, false).is_ok()
    }

    /// Clear the translation cache.
    pub fn clear_cache(&self) {
        self.entry_cache.lock().clear();
        self.table_cache.lock().clear();
    }

    /// Layer name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Minimum valid address (always 0).
    pub fn get_minimum_address(&self) -> u64 {
        0
    }

    /// Maximum valid address.
    pub fn get_maximum_address(&self) -> u64 {
        self.maximum_address_static()
    }

    /// Page size (base granule size).
    pub fn get_page_size(&self) -> u64 {
        self.granule.page_size()
    }

    /// Page granule as string.
    pub fn get_granule_size(&self) -> &'static str {
        match self.granule {
            PageGranule::Granule4K => "4KB",
            PageGranule::Granule16K => "16KB",
            PageGranule::Granule64K => "64KB",
        }
    }
}

// ------------------------------------------------------------------
// MemoryLayer trait implementation
// ------------------------------------------------------------------

impl MemoryLayer for Arm64Translator {
    fn read(&self, offset: u64, length: usize) -> Vol3Result<Vec<u8>> {
        self.read_virtual(offset, length, false)
    }

    fn is_valid(&self, offset: u64, length: u64) -> bool {
        self.check_valid(offset, length)
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn maximum_address(&self) -> u64 {
        self.maximum_address_static()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask() {
        assert_eq!(Arm64Translator::mask(0xFF, 7, 0), 0xFF);
        assert_eq!(Arm64Translator::mask(0xFF, 7, 4), 0xF0);
        assert_eq!(Arm64Translator::mask(0x12345678, 15, 8), 0x5600);
    }

    #[test]
    fn test_descriptor_types() {
        assert!(Arm64Translator::desc_is_valid(0x1));
        assert!(!Arm64Translator::desc_is_valid(0x0));

        assert!(Arm64Translator::is_block(0b01));
        assert!(!Arm64Translator::is_block(0b11));

        assert!(Arm64Translator::is_table(0b11));
        assert!(!Arm64Translator::is_table(0b01));
    }

    #[test]
    fn test_granule_properties() {
        let g4k = PageGranule::Granule4K;
        assert_eq!(g4k.page_size(), 4096);
        assert_eq!(g4k.page_shift(), 12);
        assert_eq!(g4k.max_virt_addr_bits(), 48);
        assert_eq!(g4k.structure().len(), 4);

        let g16k = PageGranule::Granule16K;
        assert_eq!(g16k.page_size(), 16384);
        assert_eq!(g16k.page_shift(), 14);
        assert_eq!(g16k.max_virt_addr_bits(), 47);

        let g64k = PageGranule::Granule64K;
        assert_eq!(g64k.page_size(), 65536);
        assert_eq!(g64k.page_shift(), 16);
        assert_eq!(g64k.max_virt_addr_bits(), 52);
    }
}
