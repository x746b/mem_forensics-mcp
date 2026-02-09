//! Windows-specific Intel address translators with swap file support.
//!
//! These translators extend the base Intel translators with Windows-specific
//! page validity checks and swap file detection.
//!
//! Windows uses additional bits in page table entries:
//! - Bit 10 (P-bit): Prototype flag
//! - Bit 11 (T-bit): Transition flag
//!
//! A page is considered valid if:
//! - V-bit (bit 0) is set, OR
//! - T-bit (bit 11) is set AND P-bit (bit 10) is NOT set
//!
//! A page is swapped when:
//! - V-bit = 0, T-bit = 0, P-bit = 0, and bit 7 is set
//! - Bits 1-4 contain the swap file index (0-15)
//! - Remaining bits contain the swap file offset

use crate::memory::error::{Vol3Error, Vol3Result};
use crate::memory::traits::MemoryLayer;
use lru::LruCache;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;

/// Page table entry flags.
const PAGE_PRESENT: u64 = 1 << 0;      // V-bit (Valid)
const PAGE_PSE: u64 = 1 << 7;          // Page Size Extension (also unknown bit for swap)
const PAGE_PROTOTYPE: u64 = 1 << 10;   // P-bit (Prototype)
const PAGE_TRANSITION: u64 = 1 << 11;  // T-bit (Transition)
const PAGE_PAT_LARGE: u64 = 1 << 12;   // PAT bit for large pages

/// Page sizes.
const PAGE_SIZE_4K: u64 = 4096;

/// Swap file index mask (bits 1-4).
const SWAP_INDEX_MASK: u64 = 0x1E;  // bits 1-4
const SWAP_INDEX_SHIFT: u32 = 1;

// ============================================================================
// Windows Intel 32-bit Translator
// ============================================================================

/// Intel 32-bit page table structure.
const INTEL32_STRUCTURE: [(&str, u32, bool); 2] = [
    ("page directory", 10, true),
    ("page table", 10, false),
];

const INTEL32_MAXPHYADDR: u32 = 32;
const INTEL32_MAXVIRTADDR: u32 = 32;
const INTEL32_BITS_PER_REGISTER: u32 = 32;
const INTEL32_PAGE_SHIFT: u32 = 12;
const INTEL32_ENTRY_SIZE: usize = 4;

type CacheEntry32 = (u32, u32);

/// Windows Intel 32-bit address translator with swap file support.
pub struct WindowsIntel32Translator {
    name: String,
    base_layer_name: String,
    page_map_offset: u32,
    base_layer: Arc<dyn MemoryLayer>,
    entry_cache: Arc<Mutex<LruCache<u32, CacheEntry32>>>,
    table_cache: Arc<Mutex<LruCache<u32, Option<Vec<u8>>>>>,
    initial_entry: u32,
    initial_position: u32,
    swap_layers: Arc<Mutex<HashMap<u8, Arc<dyn MemoryLayer>>>>,
}

impl WindowsIntel32Translator {
    #[inline]
    fn mask(value: u32, high_bit: u32, low_bit: u32) -> u32 {
        let high_mask = if high_bit >= 31 {
            u32::MAX
        } else {
            (1u32 << (high_bit + 1)).wrapping_sub(1)
        };
        let low_mask = if low_bit >= 32 {
            u32::MAX
        } else {
            (1u32 << low_bit).wrapping_sub(1)
        };
        value & (high_mask ^ low_mask)
    }

    #[inline]
    fn page_is_valid(entry: u32) -> bool {
        let v_bit = entry & (PAGE_PRESENT as u32) != 0;
        let t_bit = entry & (PAGE_TRANSITION as u32) != 0;
        let p_bit = entry & (PAGE_PROTOTYPE as u32) != 0;
        v_bit || (t_bit && !p_bit)
    }

    #[inline]
    fn is_swapped(entry: u32) -> bool {
        let v_bit = entry & (PAGE_PRESENT as u32) != 0;
        let t_bit = entry & (PAGE_TRANSITION as u32) != 0;
        let p_bit = entry & (PAGE_PROTOTYPE as u32) != 0;
        let bit7 = entry & (PAGE_PSE as u32) != 0;
        !v_bit && !t_bit && !p_bit && bit7
    }

    #[inline]
    fn get_swap_index(entry: u32) -> u8 {
        ((entry & (SWAP_INDEX_MASK as u32)) >> SWAP_INDEX_SHIFT) as u8
    }

    #[inline]
    fn get_swap_offset(entry: u32, invalid_bits: u32) -> u64 {
        let bit_offset = INTEL32_PAGE_SHIFT;
        ((entry >> bit_offset) as u64) << invalid_bits
    }

    #[inline]
    fn pte_pfn(entry: u32) -> u32 {
        Self::mask(entry, INTEL32_MAXPHYADDR - 1, 0) >> INTEL32_PAGE_SHIFT
    }

    fn read_base_layer(&self, offset: u64, length: usize) -> Vol3Result<Vec<u8>> {
        self.base_layer.read(offset, length)
    }

    fn read_swap_layer(&self, swap_index: u8, offset: u64, length: usize) -> Vol3Result<Vec<u8>> {
        let swap_layers = self.swap_layers.lock();
        let swap_layer = swap_layers.get(&swap_index).ok_or_else(|| {
            Vol3Error::InvalidParameter(format!("Swap layer {} not configured", swap_index))
        })?;
        swap_layer.read(offset, length)
    }

    fn get_valid_table(&self, base_address: u32) -> Vol3Result<Option<Vec<u8>>> {
        {
            let mut cache = self.table_cache.lock();
            if let Some(cached) = cache.get(&base_address) {
                return Ok(cached.clone());
            }
        }

        let table = match self.read_base_layer(base_address as u64, PAGE_SIZE_4K as usize) {
            Ok(t) => t,
            Err(_) => {
                let mut cache = self.table_cache.lock();
                cache.put(base_address, None);
                return Ok(None);
            }
        };

        if table.len() >= INTEL32_ENTRY_SIZE {
            let first_entry = &table[..INTEL32_ENTRY_SIZE];
            let is_duplicate = table.chunks_exact(INTEL32_ENTRY_SIZE).all(|chunk| chunk == first_entry);
            if is_duplicate {
                let mut cache = self.table_cache.lock();
                cache.put(base_address, None);
                return Ok(None);
            }
        }

        let mut cache = self.table_cache.lock();
        cache.put(base_address, Some(table.clone()));
        Ok(Some(table))
    }

    fn translate_entry(&self, page_address: u32) -> Vol3Result<CacheEntry32> {
        {
            let mut cache = self.entry_cache.lock();
            if let Some(cached) = cache.get(&page_address) {
                return Ok(*cached);
            }
        }

        if page_address > Self::maximum_address_static() {
            return Err(Vol3Error::paged_invalid_address(
                &self.name,
                page_address as u64,
                self.initial_position + 1,
                self.initial_entry as u64,
                "Entry outside virtual address range",
            ));
        }

        let mut position = self.initial_position;
        let mut entry = self.initial_entry;

        for (name, size, large_page) in INTEL32_STRUCTURE.iter() {
            if !Self::page_is_valid(entry) {
                if Self::is_swapped(entry) {
                    let swap_index = Self::get_swap_index(entry);
                    let swap_offset = Self::get_swap_offset(entry, position + 1);

                    let has_swap = self.swap_layers.lock().contains_key(&swap_index);
                    if !has_swap {
                        return Err(Vol3Error::swapped_invalid_address(
                            &self.name,
                            page_address as u64,
                            position + 1,
                            entry as u64,
                            swap_offset,
                            swap_index,
                            format!("Page swapped to file {} at offset {:#x}", swap_index, swap_offset),
                        ));
                    }
                }
                return Err(Vol3Error::paged_invalid_address(
                    &self.name,
                    page_address as u64,
                    position + 1,
                    entry as u64,
                    format!("Page Fault at entry {:#x} in table {}", entry, name),
                ));
            }

            let base_address = Self::mask(entry, INTEL32_MAXPHYADDR - 1, *size + 2);

            let table = match self.get_valid_table(base_address)? {
                Some(t) => t,
                None => {
                    return Err(Vol3Error::paged_invalid_address(
                        &self.name,
                        page_address as u64,
                        position + 1,
                        entry as u64,
                        format!("Page Fault at entry {:#x} in table {}", entry, name),
                    ));
                }
            };

            let start = position;
            position -= size;
            let index = (Self::mask(page_address, start, position + 1) >> (position + 1)) as usize;

            let entry_offset = index * INTEL32_ENTRY_SIZE;
            if entry_offset + INTEL32_ENTRY_SIZE > table.len() {
                return Err(Vol3Error::paged_invalid_address(
                    &self.name,
                    page_address as u64,
                    position + 1,
                    entry as u64,
                    "Entry offset out of bounds",
                ));
            }

            entry = u32::from_le_bytes(
                table[entry_offset..entry_offset + INTEL32_ENTRY_SIZE]
                    .try_into()
                    .unwrap(),
            );

            if *large_page && (entry & (PAGE_PSE as u32)) != 0 {
                if entry & (PAGE_PAT_LARGE as u32) != 0 {
                    entry -= PAGE_PAT_LARGE as u32;
                }
                break;
            }
        }

        let result = (entry, position);
        {
            let mut cache = self.entry_cache.lock();
            cache.put(page_address, result);
        }

        Ok(result)
    }

    fn translate_impl(&self, offset: u32) -> Vol3Result<(u64, u64, String, Option<u8>)> {
        let page_address = offset & !((1u32 << INTEL32_PAGE_SHIFT) - 1);
        let (entry, position) = self.translate_entry(page_address)?;

        if Self::is_swapped(entry) {
            let swap_index = Self::get_swap_index(entry);
            let swap_offset = Self::get_swap_offset(entry, position + 1);
            let page_offset = offset & ((1u32 << (position + 1)) - 1);
            let final_swap_offset = swap_offset | (page_offset as u64);

            let has_swap = self.swap_layers.lock().contains_key(&swap_index);
            if has_swap {
                let page_size = 1u64 << (position + 1);
                return Ok((final_swap_offset, page_size, format!("swap_layer_{}", swap_index), Some(swap_index)));
            }

            return Err(Vol3Error::swapped_invalid_address(
                &self.name,
                offset as u64,
                position + 1,
                entry as u64,
                swap_offset,
                swap_index,
                format!("Page swapped to file {} at offset {:#x}", swap_index, swap_offset),
            ));
        }

        if !Self::page_is_valid(entry) {
            return Err(Vol3Error::paged_invalid_address(
                &self.name,
                offset as u64,
                position + 1,
                entry as u64,
                format!("Page Fault at entry {:#x} in page entry", entry),
            ));
        }

        let pfn = Self::pte_pfn(entry);
        let page_offset = Self::mask(offset, position, 0);
        let physical_address = ((pfn as u64) << INTEL32_PAGE_SHIFT) | (page_offset as u64);
        let page_size = 1u64 << (position + 1);

        Ok((physical_address, page_size, self.base_layer_name.clone(), None))
    }

    fn maximum_address_static() -> u32 {
        u32::MAX
    }

    pub fn new_with_layer(
        name: String,
        base_layer: Arc<dyn MemoryLayer>,
        page_map_offset: u32,
        cache_size: usize,
    ) -> Self {
        let base_layer_name = base_layer.name().to_string();
        let initial_position = INTEL32_MAXVIRTADDR.min(INTEL32_BITS_PER_REGISTER) - 1;
        let initial_entry = (page_map_offset & Self::mask(u32::MAX, initial_position, 0)) | 0x1;

        let cache_size_nz = NonZeroUsize::new(cache_size).unwrap_or(NonZeroUsize::new(1024).unwrap());
        let table_cache_size = NonZeroUsize::new(cache_size + 1).unwrap_or(NonZeroUsize::new(1025).unwrap());

        WindowsIntel32Translator {
            name,
            base_layer_name,
            page_map_offset,
            base_layer,
            entry_cache: Arc::new(Mutex::new(LruCache::new(cache_size_nz))),
            table_cache: Arc::new(Mutex::new(LruCache::new(table_cache_size))),
            initial_entry,
            initial_position,
            swap_layers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn add_swap_layer_native(&self, index: u8, layer: Arc<dyn MemoryLayer>) -> Vol3Result<()> {
        if index > 15 {
            return Err(Vol3Error::InvalidParameter("Swap index must be 0-15".to_string()));
        }
        self.swap_layers.lock().insert(index, layer);
        Ok(())
    }

    pub fn remove_swap_layer_native(&self, index: u8) {
        self.swap_layers.lock().remove(&index);
    }

    pub fn swap_layer_indices(&self) -> Vec<u8> {
        self.swap_layers.lock().keys().copied().collect()
    }

    pub fn translate_address(&self, offset: u32) -> Vol3Result<(u64, u64, String)> {
        let (phys, page_size, layer_name, _) = self.translate_impl(offset)?;
        Ok((phys, page_size, layer_name))
    }

    pub fn mapping_ranges(
        &self,
        offset: u32,
        length: u64,
        ignore_errors: bool,
    ) -> Vol3Result<Vec<(u64, u64, u64, u64, String)>> {
        let mut results = Vec::new();
        let mut remaining = length;
        let mut current_offset = offset;

        while remaining > 0 {
            match self.translate_impl(current_offset) {
                Ok((phys_addr, page_size, layer_name, _)) => {
                    let page_offset = (current_offset as u64) % page_size;
                    let chunk_size = (page_size - page_offset).min(remaining);

                    results.push((
                        current_offset as u64,
                        chunk_size,
                        phys_addr,
                        chunk_size,
                        layer_name,
                    ));

                    current_offset = current_offset.wrapping_add(chunk_size as u32);
                    remaining -= chunk_size;
                }
                Err(e) => {
                    if !ignore_errors {
                        return Err(e);
                    }
                    let skip = match &e {
                        Vol3Error::PagedInvalidAddress { invalid_bits, .. } |
                        Vol3Error::SwappedInvalidAddress { invalid_bits, .. } => {
                            let skip_mask = (1u64 << invalid_bits) - 1;
                            skip_mask + 1 - ((current_offset as u64) & skip_mask)
                        }
                        _ => PAGE_SIZE_4K - ((current_offset as u64) % PAGE_SIZE_4K),
                    };
                    let skip = skip.min(remaining);
                    current_offset = current_offset.wrapping_add(skip as u32);
                    remaining -= skip;
                }
            }
        }

        Ok(results)
    }

    pub fn read_virtual(&self, offset: u32, length: usize, pad: bool) -> Vol3Result<Vec<u8>> {
        let mut output = Vec::with_capacity(length);
        let mut current_offset = offset;
        let remaining = length as u64;

        for (layer_offset, sublength, mapped_offset, _, layer_name) in
            self.mapping_ranges(offset, remaining, pad)?
        {
            if layer_offset > current_offset as u64 {
                if !pad {
                    return Err(Vol3Error::invalid_address(
                        &self.name,
                        current_offset as u64,
                        format!("Layer {} cannot map offset: {:#x}", self.name, current_offset),
                    ));
                }
                let gap = (layer_offset - current_offset as u64) as usize;
                output.extend(std::iter::repeat(0u8).take(gap));
                current_offset = layer_offset as u32;
            }

            let chunk = if layer_name.starts_with("swap_layer_") {
                let swap_index: u8 = layer_name[11..].parse().map_err(|_| {
                    Vol3Error::InvalidParameter("Invalid swap layer name".to_string())
                })?;
                self.read_swap_layer(swap_index, mapped_offset, sublength as usize)?
            } else {
                self.read_base_layer(mapped_offset, sublength as usize)?
            };

            output.extend_from_slice(&chunk);
            current_offset = current_offset.wrapping_add(sublength as u32);
        }

        if pad && output.len() < length {
            output.resize(length, 0);
        }

        Ok(output)
    }

    pub fn check_valid(&self, offset: u32, length: u64) -> bool {
        self.mapping_ranges(offset, length, false).is_ok()
    }

    pub fn clear_cache(&self) {
        self.entry_cache.lock().clear();
        self.table_cache.lock().clear();
    }
}

impl MemoryLayer for WindowsIntel32Translator {
    fn read(&self, offset: u64, length: usize) -> Vol3Result<Vec<u8>> {
        self.read_virtual(offset as u32, length, false)
    }

    fn is_valid(&self, offset: u64, length: u64) -> bool {
        self.check_valid(offset as u32, length)
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn maximum_address(&self) -> u64 {
        Self::maximum_address_static() as u64
    }
}

// ============================================================================
// Windows Intel PAE Translator
// ============================================================================

const PAE_STRUCTURE: [(&str, u32, bool); 3] = [
    ("page directory pointer", 2, false),
    ("page directory", 9, true),
    ("page table", 9, false),
];

const PAE_MAXPHYADDR: u32 = 36;
const PAE_MAXVIRTADDR: u32 = 32;
const PAE_BITS_PER_REGISTER: u32 = 32;
const PAE_PAGE_SHIFT: u32 = 12;
const PAE_ENTRY_SIZE: usize = 8;
const PAE_PDPT_SIZE: usize = 4 * PAE_ENTRY_SIZE;

type CacheEntry64 = (u64, u32);

/// Windows Intel PAE address translator with swap file support.
pub struct WindowsIntelPAETranslator {
    name: String,
    base_layer_name: String,
    page_map_offset: u64,
    base_layer: Arc<dyn MemoryLayer>,
    entry_cache: Arc<Mutex<LruCache<u64, CacheEntry64>>>,
    table_cache: Arc<Mutex<LruCache<u64, Option<Vec<u8>>>>>,
    initial_entry: u64,
    initial_position: u32,
    swap_layers: Arc<Mutex<HashMap<u8, Arc<dyn MemoryLayer>>>>,
}

impl WindowsIntelPAETranslator {
    #[inline]
    fn mask(value: u64, high_bit: u32, low_bit: u32) -> u64 {
        let high_mask = if high_bit >= 63 { u64::MAX } else { (1u64 << (high_bit + 1)).wrapping_sub(1) };
        let low_mask = if low_bit >= 64 { u64::MAX } else { (1u64 << low_bit).wrapping_sub(1) };
        value & (high_mask ^ low_mask)
    }

    #[inline]
    fn page_is_valid(entry: u64) -> bool {
        let v_bit = entry & PAGE_PRESENT != 0;
        let t_bit = entry & PAGE_TRANSITION != 0;
        let p_bit = entry & PAGE_PROTOTYPE != 0;
        v_bit || (t_bit && !p_bit)
    }

    #[inline]
    fn is_swapped(entry: u64) -> bool {
        let v_bit = entry & PAGE_PRESENT != 0;
        let t_bit = entry & PAGE_TRANSITION != 0;
        let p_bit = entry & PAGE_PROTOTYPE != 0;
        let bit7 = entry & PAGE_PSE != 0;
        !v_bit && !t_bit && !p_bit && bit7
    }

    #[inline]
    fn get_swap_index(entry: u64) -> u8 {
        ((entry & SWAP_INDEX_MASK) >> SWAP_INDEX_SHIFT) as u8
    }

    #[inline]
    fn get_swap_offset(entry: u64, invalid_bits: u32) -> u64 {
        let bit_offset = PAE_BITS_PER_REGISTER;
        (entry >> bit_offset) << invalid_bits
    }

    #[inline]
    fn pte_pfn(entry: u64) -> u64 {
        Self::mask(entry, PAE_MAXPHYADDR - 1, 0) >> PAE_PAGE_SHIFT
    }

    fn read_base_layer(&self, offset: u64, length: usize) -> Vol3Result<Vec<u8>> {
        self.base_layer.read(offset, length)
    }

    fn read_swap_layer(&self, swap_index: u8, offset: u64, length: usize) -> Vol3Result<Vec<u8>> {
        let swap_layers = self.swap_layers.lock();
        let swap_layer = swap_layers.get(&swap_index).ok_or_else(|| {
            Vol3Error::InvalidParameter(format!("Swap layer {} not configured", swap_index))
        })?;
        swap_layer.read(offset, length)
    }

    fn get_valid_table(&self, base_address: u64, table_size: usize) -> Vol3Result<Option<Vec<u8>>> {
        {
            let mut cache = self.table_cache.lock();
            if let Some(cached) = cache.get(&base_address) {
                return Ok(cached.clone());
            }
        }

        let table = match self.read_base_layer(base_address, table_size) {
            Ok(t) => t,
            Err(_) => {
                let mut cache = self.table_cache.lock();
                cache.put(base_address, None);
                return Ok(None);
            }
        };

        if table.len() >= PAE_ENTRY_SIZE {
            let first_entry = &table[..PAE_ENTRY_SIZE];
            let is_duplicate = table.chunks_exact(PAE_ENTRY_SIZE).all(|chunk| chunk == first_entry);
            if is_duplicate {
                let mut cache = self.table_cache.lock();
                cache.put(base_address, None);
                return Ok(None);
            }
        }

        let mut cache = self.table_cache.lock();
        cache.put(base_address, Some(table.clone()));
        Ok(Some(table))
    }

    fn translate_entry(&self, page_address: u64) -> Vol3Result<CacheEntry64> {
        {
            let mut cache = self.entry_cache.lock();
            if let Some(cached) = cache.get(&page_address) {
                return Ok(*cached);
            }
        }

        if page_address > Self::maximum_address_static() as u64 {
            return Err(Vol3Error::paged_invalid_address(
                &self.name, page_address, self.initial_position + 1, self.initial_entry,
                "Entry outside virtual address range",
            ));
        }

        let mut position = self.initial_position;
        let mut entry = self.initial_entry;
        let mut is_first = true;

        for (name, size, large_page) in PAE_STRUCTURE.iter() {
            if !Self::page_is_valid(entry) {
                if Self::is_swapped(entry) {
                    let swap_index = Self::get_swap_index(entry);
                    let swap_offset = Self::get_swap_offset(entry, position + 1);
                    let has_swap = self.swap_layers.lock().contains_key(&swap_index);
                    if !has_swap {
                        return Err(Vol3Error::swapped_invalid_address(
                            &self.name, page_address, position + 1, entry, swap_offset, swap_index,
                            format!("Page swapped to file {} at offset {:#x}", swap_index, swap_offset),
                        ));
                    }
                }
                return Err(Vol3Error::paged_invalid_address(
                    &self.name, page_address, position + 1, entry,
                    format!("Page Fault at entry {:#x} in table {}", entry, name),
                ));
            }

            let table_size = if is_first { PAE_PDPT_SIZE } else { PAGE_SIZE_4K as usize };
            is_first = false;

            let base_address = Self::mask(entry, PAE_MAXPHYADDR - 1, *size + 3);

            let table = match self.get_valid_table(base_address, table_size)? {
                Some(t) => t,
                None => {
                    return Err(Vol3Error::paged_invalid_address(
                        &self.name, page_address, position + 1, entry,
                        format!("Page Fault at entry {:#x} in table {}", entry, name),
                    ));
                }
            };

            let start = position;
            position -= size;
            let index = (Self::mask(page_address, start, position + 1) >> (position + 1)) as usize;

            let entry_offset = index * PAE_ENTRY_SIZE;
            if entry_offset + PAE_ENTRY_SIZE > table.len() {
                return Err(Vol3Error::paged_invalid_address(
                    &self.name, page_address, position + 1, entry, "Entry offset out of bounds",
                ));
            }

            entry = u64::from_le_bytes(
                table[entry_offset..entry_offset + PAE_ENTRY_SIZE].try_into().unwrap(),
            );

            if *large_page && (entry & PAGE_PSE) != 0 {
                if entry & PAGE_PAT_LARGE != 0 {
                    entry -= PAGE_PAT_LARGE;
                }
                break;
            }
        }

        let result = (entry, position);
        { let mut cache = self.entry_cache.lock(); cache.put(page_address, result); }
        Ok(result)
    }

    fn translate_impl(&self, offset: u64) -> Vol3Result<(u64, u64, String, Option<u8>)> {
        let page_address = offset & !((1u64 << PAE_PAGE_SHIFT) - 1);
        let (entry, position) = self.translate_entry(page_address)?;

        if Self::is_swapped(entry) {
            let swap_index = Self::get_swap_index(entry);
            let swap_offset = Self::get_swap_offset(entry, position + 1);
            let page_offset = offset & ((1u64 << (position + 1)) - 1);
            let final_swap_offset = swap_offset | page_offset;

            let has_swap = self.swap_layers.lock().contains_key(&swap_index);
            if has_swap {
                let page_size = 1u64 << (position + 1);
                return Ok((final_swap_offset, page_size, format!("swap_layer_{}", swap_index), Some(swap_index)));
            }

            return Err(Vol3Error::swapped_invalid_address(
                &self.name, offset, position + 1, entry, swap_offset, swap_index,
                format!("Page swapped to file {} at offset {:#x}", swap_index, swap_offset),
            ));
        }

        if !Self::page_is_valid(entry) {
            return Err(Vol3Error::paged_invalid_address(
                &self.name, offset, position + 1, entry,
                format!("Page Fault at entry {:#x} in page entry", entry),
            ));
        }

        let pfn = Self::pte_pfn(entry);
        let page_offset = Self::mask(offset, position, 0);
        let physical_address = (pfn << PAE_PAGE_SHIFT) | page_offset;
        let page_size = 1u64 << (position + 1);

        Ok((physical_address, page_size, self.base_layer_name.clone(), None))
    }

    fn maximum_address_static() -> u32 {
        u32::MAX
    }

    pub fn new_with_layer(
        name: String, base_layer: Arc<dyn MemoryLayer>, page_map_offset: u64, cache_size: usize,
    ) -> Self {
        let base_layer_name = base_layer.name().to_string();
        let initial_position = PAE_MAXVIRTADDR.min(PAE_BITS_PER_REGISTER) - 1;
        let initial_entry = (page_map_offset & Self::mask(u64::MAX, initial_position, 0)) | 0x1;
        let cache_size_nz = NonZeroUsize::new(cache_size).unwrap_or(NonZeroUsize::new(1024).unwrap());
        let table_cache_size = NonZeroUsize::new(cache_size + 1).unwrap_or(NonZeroUsize::new(1025).unwrap());

        WindowsIntelPAETranslator {
            name, base_layer_name, page_map_offset, base_layer,
            entry_cache: Arc::new(Mutex::new(LruCache::new(cache_size_nz))),
            table_cache: Arc::new(Mutex::new(LruCache::new(table_cache_size))),
            initial_entry, initial_position,
            swap_layers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn add_swap_layer_native(&self, index: u8, layer: Arc<dyn MemoryLayer>) -> Vol3Result<()> {
        if index > 15 { return Err(Vol3Error::InvalidParameter("Swap index must be 0-15".to_string())); }
        self.swap_layers.lock().insert(index, layer);
        Ok(())
    }

    pub fn remove_swap_layer_native(&self, index: u8) { self.swap_layers.lock().remove(&index); }

    pub fn swap_layer_indices(&self) -> Vec<u8> { self.swap_layers.lock().keys().copied().collect() }

    pub fn translate_address(&self, offset: u64) -> Vol3Result<(u64, u64, String)> {
        let (phys, page_size, layer_name, _) = self.translate_impl(offset)?;
        Ok((phys, page_size, layer_name))
    }

    pub fn mapping_ranges(&self, offset: u64, length: u64, ignore_errors: bool) -> Vol3Result<Vec<(u64, u64, u64, u64, String)>> {
        let mut results = Vec::new();
        let mut remaining = length;
        let mut current_offset = offset;
        while remaining > 0 {
            match self.translate_impl(current_offset) {
                Ok((phys_addr, page_size, layer_name, _)) => {
                    let page_offset = current_offset % page_size;
                    let chunk_size = (page_size - page_offset).min(remaining);
                    results.push((current_offset, chunk_size, phys_addr, chunk_size, layer_name));
                    current_offset += chunk_size;
                    remaining -= chunk_size;
                }
                Err(e) => {
                    if !ignore_errors { return Err(e); }
                    let skip = match &e {
                        Vol3Error::PagedInvalidAddress { invalid_bits, .. } |
                        Vol3Error::SwappedInvalidAddress { invalid_bits, .. } => {
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

    pub fn read_virtual(&self, offset: u64, length: usize, pad: bool) -> Vol3Result<Vec<u8>> {
        let mut output = Vec::with_capacity(length);
        let mut current_offset = offset;
        let remaining = length as u64;
        for (layer_offset, sublength, mapped_offset, _, layer_name) in self.mapping_ranges(offset, remaining, pad)? {
            if layer_offset > current_offset {
                if !pad {
                    return Err(Vol3Error::invalid_address(&self.name, current_offset,
                        format!("Layer {} cannot map offset: {:#x}", self.name, current_offset)));
                }
                let gap = (layer_offset - current_offset) as usize;
                output.extend(std::iter::repeat(0u8).take(gap));
                current_offset = layer_offset;
            }
            let chunk = if layer_name.starts_with("swap_layer_") {
                let swap_index: u8 = layer_name[11..].parse().map_err(|_| Vol3Error::InvalidParameter("Invalid swap layer name".to_string()))?;
                self.read_swap_layer(swap_index, mapped_offset, sublength as usize)?
            } else {
                self.read_base_layer(mapped_offset, sublength as usize)?
            };
            output.extend_from_slice(&chunk);
            current_offset += sublength;
        }
        if pad && output.len() < length { output.resize(length, 0); }
        Ok(output)
    }

    pub fn check_valid(&self, offset: u64, length: u64) -> bool { self.mapping_ranges(offset, length, false).is_ok() }

    pub fn clear_cache(&self) {
        self.entry_cache.lock().clear();
        self.table_cache.lock().clear();
    }
}

impl MemoryLayer for WindowsIntelPAETranslator {
    fn read(&self, offset: u64, length: usize) -> Vol3Result<Vec<u8>> { self.read_virtual(offset, length, false) }
    fn is_valid(&self, offset: u64, length: u64) -> bool { self.check_valid(offset, length) }
    fn name(&self) -> &str { &self.name }
    fn maximum_address(&self) -> u64 { Self::maximum_address_static() as u64 }
}

// ============================================================================
// Windows Intel 64-bit Translator
// ============================================================================

const INTEL64_STRUCTURE: [(&str, u32, bool); 4] = [
    ("page map layer 4", 9, false),
    ("page directory pointer", 9, true),
    ("page directory", 9, true),
    ("page table", 9, false),
];

const INTEL64_MAXPHYADDR: u32 = 45;
const INTEL64_MAXVIRTADDR: u32 = 48;
const INTEL64_BITS_PER_REGISTER: u32 = 64;
const INTEL64_PAGE_SHIFT: u32 = 12;
const INTEL64_ENTRY_SIZE: usize = 8;

/// Windows Intel 64-bit address translator with swap file support.
pub struct WindowsIntel64Translator {
    name: String,
    base_layer_name: String,
    page_map_offset: u64,
    base_layer: Arc<dyn MemoryLayer>,
    entry_cache: Arc<Mutex<LruCache<u64, CacheEntry64>>>,
    table_cache: Arc<Mutex<LruCache<u64, Option<Vec<u8>>>>>,
    initial_entry: u64,
    initial_position: u32,
    swap_layers: Arc<Mutex<HashMap<u8, Arc<dyn MemoryLayer>>>>,
}

impl WindowsIntel64Translator {
    #[inline]
    fn mask(value: u64, high_bit: u32, low_bit: u32) -> u64 {
        let high_mask = if high_bit >= 63 { u64::MAX } else { (1u64 << (high_bit + 1)).wrapping_sub(1) };
        let low_mask = if low_bit >= 64 { u64::MAX } else { (1u64 << low_bit).wrapping_sub(1) };
        value & (high_mask ^ low_mask)
    }

    #[inline]
    fn page_is_valid(entry: u64) -> bool {
        let v_bit = entry & PAGE_PRESENT != 0;
        let t_bit = entry & PAGE_TRANSITION != 0;
        let p_bit = entry & PAGE_PROTOTYPE != 0;
        v_bit || (t_bit && !p_bit)
    }

    #[inline]
    fn is_swapped(entry: u64) -> bool {
        let v_bit = entry & PAGE_PRESENT != 0;
        let t_bit = entry & PAGE_TRANSITION != 0;
        let p_bit = entry & PAGE_PROTOTYPE != 0;
        let bit7 = entry & PAGE_PSE != 0;
        !v_bit && !t_bit && !p_bit && bit7
    }

    #[inline]
    fn get_swap_index(entry: u64) -> u8 { ((entry & SWAP_INDEX_MASK) >> SWAP_INDEX_SHIFT) as u8 }

    #[inline]
    fn get_swap_offset(entry: u64, invalid_bits: u32) -> u64 {
        let bit_offset = INTEL64_BITS_PER_REGISTER / 2;
        (entry >> bit_offset) << invalid_bits
    }

    #[inline]
    fn pte_pfn(entry: u64) -> u64 { Self::mask(entry, INTEL64_MAXPHYADDR - 1, 0) >> INTEL64_PAGE_SHIFT }

    #[inline]
    fn address_mask(&self) -> u64 { (1u64 << INTEL64_MAXVIRTADDR) - 1 }

    fn read_base_layer(&self, offset: u64, length: usize) -> Vol3Result<Vec<u8>> { self.base_layer.read(offset, length) }

    fn read_swap_layer(&self, swap_index: u8, offset: u64, length: usize) -> Vol3Result<Vec<u8>> {
        let swap_layers = self.swap_layers.lock();
        let swap_layer = swap_layers.get(&swap_index).ok_or_else(|| Vol3Error::InvalidParameter(format!("Swap layer {} not configured", swap_index)))?;
        swap_layer.read(offset, length)
    }

    fn get_valid_table(&self, base_address: u64) -> Vol3Result<Option<Vec<u8>>> {
        {
            let mut cache = self.table_cache.lock();
            if let Some(cached) = cache.get(&base_address) { return Ok(cached.clone()); }
        }
        let table = match self.read_base_layer(base_address, PAGE_SIZE_4K as usize) {
            Ok(t) => t,
            Err(_) => { let mut cache = self.table_cache.lock(); cache.put(base_address, None); return Ok(None); }
        };
        if table.len() >= INTEL64_ENTRY_SIZE {
            let first_entry = &table[..INTEL64_ENTRY_SIZE];
            let is_duplicate = table.chunks_exact(INTEL64_ENTRY_SIZE).all(|chunk| chunk == first_entry);
            if is_duplicate { let mut cache = self.table_cache.lock(); cache.put(base_address, None); return Ok(None); }
        }
        let mut cache = self.table_cache.lock();
        cache.put(base_address, Some(table.clone()));
        Ok(Some(table))
    }

    fn translate_entry(&self, page_address: u64) -> Vol3Result<CacheEntry64> {
        {
            let mut cache = self.entry_cache.lock();
            if let Some(cached) = cache.get(&page_address) { return Ok(*cached); }
        }
        if page_address & self.address_mask() > Self::maximum_address_static() {
            return Err(Vol3Error::paged_invalid_address(&self.name, page_address, self.initial_position + 1, self.initial_entry, "Entry outside virtual address range"));
        }
        let mut position = self.initial_position;
        let mut entry = self.initial_entry;
        for (name, size, large_page) in INTEL64_STRUCTURE.iter() {
            if !Self::page_is_valid(entry) {
                if Self::is_swapped(entry) {
                    let swap_index = Self::get_swap_index(entry);
                    let swap_offset = Self::get_swap_offset(entry, position + 1);
                    let has_swap = self.swap_layers.lock().contains_key(&swap_index);
                    if !has_swap {
                        return Err(Vol3Error::swapped_invalid_address(&self.name, page_address, position + 1, entry, swap_offset, swap_index,
                            format!("Page swapped to file {} at offset {:#x}", swap_index, swap_offset)));
                    }
                }
                return Err(Vol3Error::paged_invalid_address(&self.name, page_address, position + 1, entry,
                    format!("Page Fault at entry {:#x} in table {}", entry, name)));
            }
            let base_address = Self::mask(entry, INTEL64_MAXPHYADDR - 1, *size + 3);
            let table = match self.get_valid_table(base_address)? {
                Some(t) => t,
                None => {
                    return Err(Vol3Error::paged_invalid_address(&self.name, page_address, position + 1, entry,
                        format!("Page Fault at entry {:#x} in table {}", entry, name)));
                }
            };
            let start = position;
            position -= size;
            let index = (Self::mask(page_address, start, position + 1) >> (position + 1)) as usize;
            let entry_offset = index * INTEL64_ENTRY_SIZE;
            if entry_offset + INTEL64_ENTRY_SIZE > table.len() {
                return Err(Vol3Error::paged_invalid_address(&self.name, page_address, position + 1, entry, "Entry offset out of bounds"));
            }
            entry = u64::from_le_bytes(table[entry_offset..entry_offset + INTEL64_ENTRY_SIZE].try_into().unwrap());
            if *large_page && (entry & PAGE_PSE) != 0 {
                if entry & PAGE_PAT_LARGE != 0 { entry -= PAGE_PAT_LARGE; }
                break;
            }
        }
        let result = (entry, position);
        { let mut cache = self.entry_cache.lock(); cache.put(page_address, result); }
        Ok(result)
    }

    fn translate_impl(&self, offset: u64) -> Vol3Result<(u64, u64, String, Option<u8>)> {
        let page_address = offset & !((1u64 << INTEL64_PAGE_SHIFT) - 1);
        let (entry, position) = self.translate_entry(page_address)?;
        if Self::is_swapped(entry) {
            let swap_index = Self::get_swap_index(entry);
            let swap_offset = Self::get_swap_offset(entry, position + 1);
            let page_offset = offset & ((1u64 << (position + 1)) - 1);
            let final_swap_offset = swap_offset | page_offset;
            let has_swap = self.swap_layers.lock().contains_key(&swap_index);
            if has_swap {
                let page_size = 1u64 << (position + 1);
                return Ok((final_swap_offset, page_size, format!("swap_layer_{}", swap_index), Some(swap_index)));
            }
            return Err(Vol3Error::swapped_invalid_address(&self.name, offset, position + 1, entry, swap_offset, swap_index,
                format!("Page swapped to file {} at offset {:#x}", swap_index, swap_offset)));
        }
        if !Self::page_is_valid(entry) {
            return Err(Vol3Error::paged_invalid_address(&self.name, offset, position + 1, entry,
                format!("Page Fault at entry {:#x} in page entry", entry)));
        }
        let pfn = Self::pte_pfn(entry);
        let page_offset = Self::mask(offset, position, 0);
        let physical_address = (pfn << INTEL64_PAGE_SHIFT) | page_offset;
        let page_size = 1u64 << (position + 1);
        Ok((physical_address, page_size, self.base_layer_name.clone(), None))
    }

    fn maximum_address_static() -> u64 { (1u64 << INTEL64_MAXVIRTADDR) - 1 }

    pub fn new_with_layer(name: String, base_layer: Arc<dyn MemoryLayer>, page_map_offset: u64, cache_size: usize) -> Self {
        let base_layer_name = base_layer.name().to_string();
        let initial_position = INTEL64_MAXVIRTADDR.min(INTEL64_BITS_PER_REGISTER) - 1;
        let initial_entry = Self::mask(page_map_offset, initial_position, 0) | 0x1;
        let cache_size_nz = NonZeroUsize::new(cache_size).unwrap_or(NonZeroUsize::new(1024).unwrap());
        let table_cache_size = NonZeroUsize::new(cache_size + 1).unwrap_or(NonZeroUsize::new(1025).unwrap());
        WindowsIntel64Translator {
            name, base_layer_name, page_map_offset, base_layer,
            entry_cache: Arc::new(Mutex::new(LruCache::new(cache_size_nz))),
            table_cache: Arc::new(Mutex::new(LruCache::new(table_cache_size))),
            initial_entry, initial_position,
            swap_layers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn add_swap_layer_native(&self, index: u8, layer: Arc<dyn MemoryLayer>) -> Vol3Result<()> {
        if index > 15 { return Err(Vol3Error::InvalidParameter("Swap index must be 0-15".to_string())); }
        self.swap_layers.lock().insert(index, layer);
        Ok(())
    }

    pub fn remove_swap_layer_native(&self, index: u8) { self.swap_layers.lock().remove(&index); }
    pub fn swap_layer_indices(&self) -> Vec<u8> { self.swap_layers.lock().keys().copied().collect() }

    pub fn translate_address(&self, offset: u64) -> Vol3Result<(u64, u64, String)> {
        let (phys, page_size, layer_name, _) = self.translate_impl(offset)?;
        Ok((phys, page_size, layer_name))
    }

    pub fn mapping_ranges(&self, offset: u64, length: u64, ignore_errors: bool) -> Vol3Result<Vec<(u64, u64, u64, u64, String)>> {
        let mut results = Vec::new();
        let mut remaining = length;
        let mut current_offset = offset;
        while remaining > 0 {
            match self.translate_impl(current_offset) {
                Ok((phys_addr, page_size, layer_name, _)) => {
                    let page_offset = current_offset % page_size;
                    let chunk_size = (page_size - page_offset).min(remaining);
                    results.push((current_offset, chunk_size, phys_addr, chunk_size, layer_name));
                    current_offset += chunk_size;
                    remaining -= chunk_size;
                }
                Err(e) => {
                    if !ignore_errors { return Err(e); }
                    let skip = match &e {
                        Vol3Error::PagedInvalidAddress { invalid_bits, .. } |
                        Vol3Error::SwappedInvalidAddress { invalid_bits, .. } => {
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

    pub fn read_virtual(&self, offset: u64, length: usize, pad: bool) -> Vol3Result<Vec<u8>> {
        let mut output = Vec::with_capacity(length);
        let mut current_offset = offset;
        let remaining = length as u64;
        for (layer_offset, sublength, mapped_offset, _, layer_name) in self.mapping_ranges(offset, remaining, pad)? {
            if layer_offset > current_offset {
                if !pad {
                    return Err(Vol3Error::invalid_address(&self.name, current_offset,
                        format!("Layer {} cannot map offset: {:#x}", self.name, current_offset)));
                }
                let gap = (layer_offset - current_offset) as usize;
                output.extend(std::iter::repeat(0u8).take(gap));
                current_offset = layer_offset;
            }
            let chunk = if layer_name.starts_with("swap_layer_") {
                let swap_index: u8 = layer_name[11..].parse().map_err(|_| Vol3Error::InvalidParameter("Invalid swap layer name".to_string()))?;
                self.read_swap_layer(swap_index, mapped_offset, sublength as usize)?
            } else {
                self.read_base_layer(mapped_offset, sublength as usize)?
            };
            output.extend_from_slice(&chunk);
            current_offset += sublength;
        }
        if pad && output.len() < length { output.resize(length, 0); }
        Ok(output)
    }

    pub fn check_valid(&self, offset: u64, length: u64) -> bool { self.mapping_ranges(offset, length, false).is_ok() }

    pub fn clear_cache(&self) {
        self.entry_cache.lock().clear();
        self.table_cache.lock().clear();
    }
}

impl MemoryLayer for WindowsIntel64Translator {
    fn read(&self, offset: u64, length: usize) -> Vol3Result<Vec<u8>> { self.read_virtual(offset, length, false) }
    fn is_valid(&self, offset: u64, length: u64) -> bool { self.check_valid(offset, length) }
    fn name(&self) -> &str { &self.name }
    fn maximum_address(&self) -> u64 { Self::maximum_address_static() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_page_validity() {
        assert!(WindowsIntel64Translator::page_is_valid(0x1));
        assert!(WindowsIntel64Translator::page_is_valid(PAGE_TRANSITION));
        assert!(!WindowsIntel64Translator::page_is_valid(PAGE_TRANSITION | PAGE_PROTOTYPE));
        assert!(!WindowsIntel64Translator::page_is_valid(0x0));
    }

    #[test]
    fn test_swap_detection() {
        let swapped_entry = PAGE_PSE;
        assert!(WindowsIntel64Translator::is_swapped(swapped_entry));
        assert!(!WindowsIntel64Translator::is_swapped(PAGE_PRESENT | PAGE_PSE));
        assert!(!WindowsIntel64Translator::is_swapped(PAGE_TRANSITION | PAGE_PSE));
        assert!(!WindowsIntel64Translator::is_swapped(PAGE_PROTOTYPE | PAGE_PSE));
        assert!(!WindowsIntel64Translator::is_swapped(0x0));
    }

    #[test]
    fn test_swap_index() {
        let entry = 0b11110_u64;
        assert_eq!(WindowsIntel64Translator::get_swap_index(entry), 15);
        let entry = 0b00010_u64;
        assert_eq!(WindowsIntel64Translator::get_swap_index(entry), 1);
        let entry = 0b00000_u64;
        assert_eq!(WindowsIntel64Translator::get_swap_index(entry), 0);
    }
}
