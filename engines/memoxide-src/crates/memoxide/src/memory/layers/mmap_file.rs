//! Memory-mapped file layer implementation.
//!
//! Provides a high-performance memory layer using memory-mapped files
//! for efficient random access.

use crate::memory::error::{Vol3Error, Vol3Result};
use crate::memory::traits::MemoryLayer;
use memmap2::{Mmap, MmapMut, MmapOptions};
use parking_lot::RwLock;
use std::fs::{File, OpenOptions};
use std::path::PathBuf;
use std::sync::Arc;

/// Internal state for the memory-mapped layer.
struct MmapState {
    /// Read-only memory map (used when not writable).
    mmap_ro: Option<Mmap>,
    /// Writable memory map (used when writable).
    mmap_rw: Option<MmapMut>,
    /// File size.
    size: u64,
}

impl MmapState {
    fn as_slice(&self) -> &[u8] {
        if let Some(ref mmap) = self.mmap_ro {
            mmap.as_ref()
        } else if let Some(ref mmap) = self.mmap_rw {
            mmap.as_ref()
        } else {
            &[]
        }
    }

    #[allow(dead_code)]
    fn as_mut_slice(&mut self) -> Option<&mut [u8]> {
        self.mmap_rw.as_mut().map(|m| m.as_mut())
    }
}

/// A high-performance memory-mapped file layer.
///
/// # Thread Safety
///
/// This implementation is thread-safe using `parking_lot::RwLock` for
/// concurrent read access while maintaining exclusive write access.
///
/// # Example
///
/// ```rust,ignore
/// use memoxide::memory::layers::MmapFileLayer;
/// use memoxide::memory::traits::MemoryLayer;
///
/// let layer = MmapFileLayer::open("physical", "/path/to/dump.raw", false)?;
/// let data = layer.read_bytes(0, 4096, false)?;
/// ```
pub struct MmapFileLayer {
    /// Layer name.
    name: String,
    /// File location (file:// URL or path).
    location: String,
    /// Resolved file path.
    #[allow(dead_code)]
    path: PathBuf,
    /// Whether the layer is writable.
    #[allow(dead_code)]
    writable: bool,
    /// The memory-mapped state, wrapped in Arc<RwLock> for thread safety.
    /// None if the layer has been destroyed.
    state: Option<Arc<RwLock<MmapState>>>,
}

// ---------------------------------------------------------------------------
// Always-available helpers
// ---------------------------------------------------------------------------
impl MmapFileLayer {
    /// Parse a file:// URL to a path.
    fn parse_location(location: &str) -> Vol3Result<PathBuf> {
        let path_str = if location.starts_with("file://") {
            // Handle file:// URLs
            let url_path = &location[7..];
            // On Windows, handle file:///C:/path format
            if url_path.starts_with('/')
                && url_path.len() > 2
                && url_path.chars().nth(2) == Some(':')
            {
                // Windows absolute path: file:///C:/path -> C:/path
                &url_path[1..]
            } else {
                url_path
            }
        } else {
            location
        };

        // URL decode the path (handle %20 etc.)
        let decoded = urlencoding_decode(path_str);
        Ok(PathBuf::from(decoded))
    }

    /// Create the memory map for the file.
    fn create_mmap(path: &PathBuf, writable: bool) -> Vol3Result<MmapState> {
        let file = if writable {
            OpenOptions::new().read(true).write(true).open(path)?
        } else {
            File::open(path)?
        };

        let size = file.metadata()?.len();

        if size == 0 {
            return Ok(MmapState {
                mmap_ro: None,
                mmap_rw: None,
                size: 0,
            });
        }

        if writable {
            let mmap = unsafe { MmapOptions::new().map_mut(&file)? };
            Ok(MmapState {
                mmap_ro: None,
                mmap_rw: Some(mmap),
                size,
            })
        } else {
            let mmap = unsafe { MmapOptions::new().map(&file)? };
            Ok(MmapState {
                mmap_ro: Some(mmap),
                mmap_rw: None,
                size,
            })
        }
    }

    /// Get the state, returning an error if destroyed.
    fn get_state(&self) -> Vol3Result<&Arc<RwLock<MmapState>>> {
        self.state
            .as_ref()
            .ok_or_else(|| Vol3Error::layer_destroyed(&self.name))
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
impl MmapFileLayer {
    /// Open a memory-mapped file layer.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the layer
    /// * `path` - File location (file:// URL or plain filesystem path)
    /// * `writable` - Whether to open the file for writing
    pub fn open(
        name: impl Into<String>,
        path: impl Into<String>,
        writable: bool,
    ) -> Vol3Result<Self> {
        let name = name.into();
        let location = path.into();
        let resolved = Self::parse_location(&location)?;
        let state = Self::create_mmap(&resolved, writable)?;

        Ok(MmapFileLayer {
            name,
            location,
            path: resolved,
            writable,
            state: Some(Arc::new(RwLock::new(state))),
        })
    }

    /// Read bytes from the layer.
    ///
    /// # Arguments
    ///
    /// * `offset` - Starting offset to read from
    /// * `length` - Number of bytes to read
    /// * `pad` - If true, pad with zeros for out-of-range reads; otherwise return an error
    pub fn read_bytes(&self, offset: u64, length: usize, pad: bool) -> Vol3Result<Vec<u8>> {
        let state = self.get_state()?;
        let state_guard = state.read();

        let data = state_guard.as_slice();
        let size = state_guard.size;

        // Check if the read is valid
        if offset > size || (offset == size && length > 0) {
            if pad {
                return Ok(vec![0u8; length]);
            }
            return Err(Vol3Error::invalid_address(
                &self.name,
                offset,
                "Offset outside of the buffer boundaries",
            ));
        }

        let start = offset as usize;
        let available = (size - offset) as usize;

        if length <= available {
            // Full read available
            Ok(data[start..start + length].to_vec())
        } else if pad {
            // Partial read with padding
            let mut result = Vec::with_capacity(length);
            result.extend_from_slice(&data[start..]);
            result.resize(length, 0);
            Ok(result)
        } else {
            // Partial read without padding - error
            Err(Vol3Error::invalid_address(
                &self.name,
                offset + available as u64,
                "Could not read sufficient bytes from the file",
            ))
        }
    }

    /// Check if an address range is valid.
    pub fn is_valid(&self, offset: u64, length: u64) -> bool {
        if length == 0 {
            return false;
        }

        let state = match self.get_state() {
            Ok(s) => s,
            Err(_) => return false,
        };
        let state_guard = state.read();
        let size = state_guard.size;

        // Check bounds
        let max_addr = if size > 0 {
            size - 1
        } else {
            return false;
        };
        let end_offset = offset.saturating_add(length).saturating_sub(1);

        offset <= max_addr && end_offset <= max_addr
    }

    /// Destroy the layer, releasing resources.
    pub fn destroy(&mut self) {
        self.state = None;
    }

    /// Maximum valid address (file_size - 1).
    pub fn maximum_address(&self) -> Vol3Result<u64> {
        let state = self.get_state()?;
        let state_guard = state.read();
        Ok(state_guard.size.saturating_sub(1))
    }

    /// Minimum valid address (always 0).
    pub fn minimum_address(&self) -> u64 {
        0
    }

    /// The file location.
    pub fn location(&self) -> &str {
        &self.location
    }

    /// The layer name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

// ---------------------------------------------------------------------------
// MemoryLayer trait implementation
// ---------------------------------------------------------------------------
impl MemoryLayer for MmapFileLayer {
    fn read(&self, offset: u64, length: usize) -> Vol3Result<Vec<u8>> {
        self.read_bytes(offset, length, false)
    }

    fn is_valid(&self, offset: u64, length: u64) -> bool {
        // Delegate to the inherent method
        MmapFileLayer::is_valid(self, offset, length)
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn maximum_address(&self) -> u64 {
        let state = match self.get_state() {
            Ok(s) => s,
            Err(_) => return 0,
        };
        let state_guard = state.read();
        state_guard.size.saturating_sub(1)
    }
}

/// Simple URL decoding for file paths.
fn urlencoding_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            result.push('%');
            result.push_str(&hex);
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_file_url() {
        let path = MmapFileLayer::parse_location("file:///tmp/test.raw").unwrap();
        assert_eq!(path, PathBuf::from("/tmp/test.raw"));
    }

    #[test]
    fn test_parse_plain_path() {
        let path = MmapFileLayer::parse_location("/tmp/test.raw").unwrap();
        assert_eq!(path, PathBuf::from("/tmp/test.raw"));
    }

    #[test]
    fn test_url_decode() {
        let path = MmapFileLayer::parse_location("file:///tmp/test%20file.raw").unwrap();
        assert_eq!(path, PathBuf::from("/tmp/test file.raw"));
    }

    #[test]
    fn test_open_and_read_bytes() {
        let mut tmpfile = NamedTempFile::new().unwrap();
        tmpfile.write_all(b"Hello, World!").unwrap();
        tmpfile.flush().unwrap();

        let layer = MmapFileLayer::open(
            "test",
            tmpfile.path().to_str().unwrap(),
            false,
        )
        .unwrap();

        let data = layer.read_bytes(0, 5, false).unwrap();
        assert_eq!(&data, b"Hello");

        let data = layer.read_bytes(7, 5, false).unwrap();
        assert_eq!(&data, b"World");
    }

    #[test]
    fn test_read_bytes_with_padding() {
        let mut tmpfile = NamedTempFile::new().unwrap();
        tmpfile.write_all(b"Hello").unwrap();
        tmpfile.flush().unwrap();

        let layer = MmapFileLayer::open(
            "test",
            tmpfile.path().to_str().unwrap(),
            false,
        )
        .unwrap();

        // Read with padding beyond file end
        let data = layer.read_bytes(3, 5, true).unwrap();
        assert_eq!(&data, b"lo\0\0\0");

        // Read entirely beyond file end with padding
        let data = layer.read_bytes(100, 3, true).unwrap();
        assert_eq!(&data, b"\0\0\0");
    }

    #[test]
    fn test_read_bytes_out_of_bounds_no_pad() {
        let mut tmpfile = NamedTempFile::new().unwrap();
        tmpfile.write_all(b"Hello").unwrap();
        tmpfile.flush().unwrap();

        let layer = MmapFileLayer::open(
            "test",
            tmpfile.path().to_str().unwrap(),
            false,
        )
        .unwrap();

        // Should fail without padding
        assert!(layer.read_bytes(100, 3, false).is_err());
    }

    #[test]
    fn test_is_valid() {
        let mut tmpfile = NamedTempFile::new().unwrap();
        tmpfile.write_all(b"0123456789").unwrap();
        tmpfile.flush().unwrap();

        let layer = MmapFileLayer::open(
            "test",
            tmpfile.path().to_str().unwrap(),
            false,
        )
        .unwrap();

        assert!(layer.is_valid(0, 1));
        assert!(layer.is_valid(0, 10));
        assert!(layer.is_valid(9, 1));
        assert!(!layer.is_valid(10, 1));
        assert!(!layer.is_valid(0, 11));
    }

    #[test]
    fn test_memory_layer_trait() {
        let mut tmpfile = NamedTempFile::new().unwrap();
        tmpfile.write_all(b"Hello, World!").unwrap();
        tmpfile.flush().unwrap();

        let layer = MmapFileLayer::open(
            "test",
            tmpfile.path().to_str().unwrap(),
            false,
        )
        .unwrap();

        // Use through trait
        let layer_ref: &dyn MemoryLayer = &layer;
        assert_eq!(layer_ref.name(), "test");
        assert_eq!(layer_ref.maximum_address(), 12); // 13 bytes, max addr = 12

        let data = layer_ref.read(0, 5).unwrap();
        assert_eq!(&data, b"Hello");

        assert!(layer_ref.is_valid(0, 13));
        assert!(!layer_ref.is_valid(0, 14));
    }

    #[test]
    fn test_destroy() {
        let mut tmpfile = NamedTempFile::new().unwrap();
        tmpfile.write_all(b"data").unwrap();
        tmpfile.flush().unwrap();

        let mut layer = MmapFileLayer::open(
            "test",
            tmpfile.path().to_str().unwrap(),
            false,
        )
        .unwrap();

        assert!(layer.read_bytes(0, 4, false).is_ok());
        layer.destroy();
        assert!(layer.read_bytes(0, 4, false).is_err());
    }
}
