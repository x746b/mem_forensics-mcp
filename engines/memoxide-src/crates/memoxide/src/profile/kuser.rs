//! KUSER_SHARED_DATA helpers.
//!
//! KUSER_SHARED_DATA is mapped at a fixed virtual address on Windows x64:
//! `0xFFFFF78000000000`. It contains basic OS version/build information.
//!
//! This is useful for Win10+ where KDBG is often encoded.

use isf::MemoryAccess;

/// Fixed VA of KUSER_SHARED_DATA on x64 Windows.
pub const KUSER_SHARED_DATA_VA_X64: u64 = 0xFFFF_F780_0000_0000;

// KUSER_SHARED_DATA.NtBuildNumber offset (stable across many versions).
const NT_BUILD_NUMBER_OFFSET: u64 = 0x26c;

pub fn read_nt_build_number(vm: &dyn MemoryAccess) -> Option<u32> {
    let bytes = vm.read(KUSER_SHARED_DATA_VA_X64 + NT_BUILD_NUMBER_OFFSET, 2).ok()?;
    let raw = u16::from_le_bytes([bytes[0], bytes[1]]);
    // High bit sometimes marks checked build; keep the numeric build.
    Some((raw & 0x7fff) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::RwLock;

    struct MockVm {
        data: RwLock<std::collections::HashMap<u64, Vec<u8>>>,
    }

    impl MockVm {
        fn new() -> Self {
            Self {
                data: RwLock::new(std::collections::HashMap::new()),
            }
        }

        fn set_u16(&self, addr: u64, v: u16) {
            self.data
                .write()
                .unwrap()
                .insert(addr, v.to_le_bytes().to_vec());
        }
    }

    impl MemoryAccess for MockVm {
        fn read(
            &self,
            offset: u64,
            length: usize,
        ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
            let map = self.data.read().unwrap();
            let v = map.get(&offset).cloned().unwrap_or_default();
            if v.len() < length {
                return Err("short read".into());
            }
            Ok(v[..length].to_vec())
        }

        fn is_valid(&self, _offset: u64, _length: u64) -> bool {
            true
        }
    }

    #[test]
    fn test_read_nt_build_number_masks_checked_bit() {
        let vm = MockVm::new();
        vm.set_u16(KUSER_SHARED_DATA_VA_X64 + NT_BUILD_NUMBER_OFFSET, 0x8000 | 19045);
        assert_eq!(read_nt_build_number(&vm), Some(19045));
    }
}

