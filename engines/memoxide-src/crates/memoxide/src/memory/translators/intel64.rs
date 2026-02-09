//! Intel 64-bit (x86-64) address translation.
//!
//! Provides a high-performance replacement for `volatility3.framework.layers.intel.Intel32e`
//! with LRU caching and optimized page table walking.

use crate::memory::error::{Vol3Error, Vol3Result};
use crate::memory::traits::MemoryLayer;
use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::sync::Arc;

/// Page table entry flags.
const PAGE_PRESENT: u64 = 1 << 0;
const PAGE_PSE: u64 = 1 << 7; // Page Size Extension (large page)
const PAGE_PAT_LARGE: u64 = 1 << 12; // PAT bit for large pages

/// Page sizes.
const PAGE_SIZE_4K: u64 = 4096;

/// Intel 64-bit page table structure.
/// Structure: PML4 (9 bits) -> PDPT (9 bits) -> PD (9 bits) -> PT (9 bits) -> Offset (12 bits)
const STRUCTURE: [(& str, u32, bool); 4] = [
    ("page map layer 4", 9, false),  // PML4
    ("page directory pointer", 9, true),  // PDPT - can have 1GB pages
    ("page directory", 9, true),  // PD - can have 2MB pages
    ("page table", 9, false),  // PT
];

/// Maximum physical address bits (Intel spec).
const MAXPHYADDR: u32 = 52;

/// Maximum virtual address bits for 4-level paging.
const MAXVIRTADDR: u32 = 48;

/// Bits per register.
const BITS_PER_REGISTER: u32 = 64;

/// Page shift (log2 of page size).
const PAGE_SHIFT: u32 = 12;

/// Entry size (8 bytes for 64-bit).
const ENTRY_SIZE: usize = 8;

/// Cache entry type: maps page address to (entry, position).
type CacheEntry = (u64, u32);

/// Cached translation result.
#[derive(Clone, Debug)]
struct TranslationResult {
    physical_address: u64,
    page_size: u64,
    layer_name: String,
}

/// Intel 64-bit address translator with LRU caching.
///
/// This is a high-performance replacement for `volatility3.framework.layers.intel.Intel32e`
/// that uses an LRU cache to speed up repeated address translations.
///
/// # Thread Safety
///
/// This implementation is thread-safe using `parking_lot::Mutex` for the cache.
pub struct Intel64Translator {
    /// Layer name.
    name: String,
    /// Name of the base (physical) layer.
    base_layer_name: String,
    /// Page map offset (CR3 value).
    page_map_offset: u64,
    /// Reference to the base layer for reading.
    base_layer: Arc<dyn MemoryLayer>,
    /// LRU cache for page table entries.
    entry_cache: Arc<Mutex<LruCache<u64, CacheEntry>>>,
    /// LRU cache for valid page tables (to detect duplicate tables).
    table_cache: Arc<Mutex<LruCache<u64, Option<Vec<u8>>>>>,
    /// Initial entry value.
    initial_entry: u64,
    /// Initial position.
    initial_position: u32,
}

impl Intel64Translator {
    /// Create a mask for bits between high_bit and low_bit (inclusive).
    #[inline]
    fn mask(value: u64, high_bit: u32, low_bit: u32) -> u64 {
        // Handle overflow when high_bit >= 63
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

    /// Check if a page entry is valid (present).
    #[inline]
    fn page_is_valid(entry: u64) -> bool {
        entry & PAGE_PRESENT != 0
    }

    /// Extract PFN from a page table entry.
    #[inline]
    fn pte_pfn(entry: u64) -> u64 {
        Self::mask(entry, MAXPHYADDR - 1, 0) >> PAGE_SHIFT
    }

    /// Get the address mask.
    #[inline]
    fn address_mask(&self) -> u64 {
        (1u64 << MAXVIRTADDR) - 1
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
        let table = match self.read_base_layer(base_address, PAGE_SIZE_4K as usize) {
            Ok(t) => t,
            Err(_) => {
                let mut cache = self.table_cache.lock();
                cache.put(base_address, None);
                return Ok(None);
            }
        };

        // Check for duplicate entries (Windows optimization).
        // If all entries are the same, treat the table as invalid.
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
        if page_address & self.address_mask() > Self::maximum_address_static() {
            return Err(Vol3Error::paged_invalid_address(
                &self.name,
                page_address,
                self.initial_position + 1,
                self.initial_entry,
                "Entry outside virtual address range",
            ));
        }

        let mut position = self.initial_position;
        let mut entry = self.initial_entry;

        // Walk through each level of the page table structure
        for (name, size, large_page) in STRUCTURE.iter() {
            // Check if entry is valid
            if !Self::page_is_valid(entry) {
                return Err(Vol3Error::paged_invalid_address(
                    &self.name,
                    page_address,
                    position + 1,
                    entry,
                    format!("Page Fault at entry {:#x} in table {}", entry, name),
                ));
            }

            // Calculate base address of next table
            // Use index_shift of 3 (log2(8) for 8-byte entries)
            let base_address = Self::mask(entry, MAXPHYADDR - 1, *size + 3);

            // Get the table
            let table = match self.get_valid_table(base_address)? {
                Some(t) => t,
                None => {
                    return Err(Vol3Error::paged_invalid_address(
                        &self.name,
                        page_address,
                        position + 1,
                        entry,
                        format!("Page Fault at entry {:#x} in table {}", entry, name),
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

            // Check for large page
            if *large_page && (entry & PAGE_PSE) != 0 {
                // Mask off the PAT bit for large pages
                if entry & PAGE_PAT_LARGE != 0 {
                    entry -= PAGE_PAT_LARGE;
                }
                break;
            }
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
        let page_address = offset & !((1u64 << PAGE_SHIFT) - 1); // PAGE_MASK
        let (entry, position) = self.translate_entry(page_address)?;

        if !Self::page_is_valid(entry) {
            return Err(Vol3Error::paged_invalid_address(
                &self.name,
                offset,
                position + 1,
                entry,
                format!("Page Fault at entry {:#x} in page entry", entry),
            ));
        }

        let pfn = Self::pte_pfn(entry);
        let page_offset = Self::mask(offset, position, 0);
        let physical_address = (pfn << PAGE_SHIFT) | page_offset;
        let page_size = 1u64 << (position + 1);

        Ok(TranslationResult {
            physical_address,
            page_size,
            layer_name: self.base_layer_name.clone(),
        })
    }

    /// Static maximum address (doesn't require self).
    fn maximum_address_static() -> u64 {
        (1u64 << MAXVIRTADDR) - 1
    }

    // -- Public API --

    /// Create a new Intel64Translator from a `MemoryLayer`.
    pub fn new_with_layer(
        name: String,
        base_layer: Arc<dyn MemoryLayer>,
        page_map_offset: u64,
        cache_size: usize,
    ) -> Vol3Result<Self> {
        let base_layer_name = base_layer.name().to_owned();

        let initial_position = MAXVIRTADDR.min(BITS_PER_REGISTER) - 1;
        let initial_entry = Self::mask(page_map_offset, initial_position, 0) | 0x1;

        let cache_size_nz = NonZeroUsize::new(cache_size).unwrap_or(NonZeroUsize::new(1024).unwrap());
        let table_cache_size = NonZeroUsize::new(cache_size + 1).unwrap_or(NonZeroUsize::new(1025).unwrap());

        Ok(Intel64Translator {
            name,
            base_layer_name,
            page_map_offset,
            base_layer,
            entry_cache: Arc::new(Mutex::new(LruCache::new(cache_size_nz))),
            table_cache: Arc::new(Mutex::new(LruCache::new(table_cache_size))),
            initial_entry,
            initial_position,
        })
    }

    /// Translate a virtual address to physical.
    ///
    /// Returns (physical_address, page_size, layer_name).
    pub fn translate_address(&self, offset: u64) -> Vol3Result<(u64, u64, String)> {
        let result = self.translate_impl(offset)?;
        Ok((result.physical_address, result.page_size, result.layer_name))
    }

    /// Get address mapping for a range.
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
                    // Calculate chunk size (page-aligned)
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
                    // Skip to next page boundary
                    let skip = match &e {
                        Vol3Error::PagedInvalidAddress { invalid_bits, .. } => {
                            let skip_mask = (1u64 << invalid_bits) - 1;
                            skip_mask + 1 - (current_offset & skip_mask)
                        }
                        _ => PAGE_SIZE_4K - (current_offset % PAGE_SIZE_4K),
                    };
                    let skip = skip.min(remaining);
                    current_offset += skip;
                    remaining -= skip;
                }
            }
        }

        Ok(results)
    }

    /// Read data from the translated layer.
    pub fn read_virtual(&self, offset: u64, length: usize, pad: bool) -> Vol3Result<Vec<u8>> {
        let mut output = Vec::with_capacity(length);
        let mut current_offset = offset;
        let remaining = length as u64;

        for (layer_offset, sublength, mapped_offset, _, _layer_name) in
            self.mapping_ranges(offset, remaining, pad)?
        {
            // Handle gaps (unmapped regions)
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

            // Read from the base layer
            let chunk = self.read_base_layer(mapped_offset, sublength as usize)?;
            output.extend_from_slice(&chunk);
            current_offset += sublength;
        }

        // Pad remaining if needed
        if pad && output.len() < length {
            output.resize(length, 0);
        }

        Ok(output)
    }

    /// Check if an address range is valid.
    pub fn check_valid(&self, offset: u64, length: u64) -> bool {
        self.mapping_ranges(offset, length, false).is_ok()
    }
}

impl MemoryLayer for Intel64Translator {
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
        Self::maximum_address_static()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask() {
        assert_eq!(Intel64Translator::mask(0xFF, 7, 0), 0xFF);
        assert_eq!(Intel64Translator::mask(0xFF, 7, 4), 0xF0);
        assert_eq!(Intel64Translator::mask(0x12345678, 15, 8), 0x5600);
    }

    #[test]
    fn test_page_is_valid() {
        assert!(Intel64Translator::page_is_valid(0x1));
        assert!(Intel64Translator::page_is_valid(0x1001));
        assert!(!Intel64Translator::page_is_valid(0x0));
        assert!(!Intel64Translator::page_is_valid(0x1000));
    }

    #[test]
    fn test_pte_pfn() {
        // PFN is bits 12-51 of the entry, shifted right by 12
        let entry = 0x123456000u64 | PAGE_PRESENT;
        let pfn = Intel64Translator::pte_pfn(entry);
        assert_eq!(pfn, 0x123456);
    }
}
