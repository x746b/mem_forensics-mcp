//! Error types for memory operations.

use thiserror::Error;

/// Errors that can occur in memory operations.
#[derive(Error, Debug)]
pub enum Vol3Error {
    /// An address is not valid in the layer.
    #[error("Invalid address {invalid_address:#x} in layer '{layer_name}': {message}")]
    InvalidAddress {
        layer_name: String,
        invalid_address: u64,
        message: String,
    },

    /// A paged address is not valid (with page table entry information).
    #[error("Paged invalid address {invalid_address:#x} in layer '{layer_name}' (entry={entry:#x}, invalid_bits={invalid_bits}): {message}")]
    PagedInvalidAddress {
        layer_name: String,
        invalid_address: u64,
        invalid_bits: u32,
        entry: u64,
        message: String,
    },

    /// A swapped address - page is in a swap file.
    #[error("Swapped address {invalid_address:#x} in layer '{layer_name}' (swap_offset={swap_offset:#x}, swap_index={swap_index}): {message}")]
    SwappedInvalidAddress {
        layer_name: String,
        invalid_address: u64,
        invalid_bits: u32,
        entry: u64,
        swap_offset: u64,
        swap_index: u8,
        message: String,
    },

    /// I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The layer has been destroyed and cannot be used.
    #[error("Layer '{0}' has been destroyed")]
    LayerDestroyed(String),

    /// Invalid parameter provided.
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    /// Memory mapping error.
    #[error("Memory mapping error: {0}")]
    MmapError(String),

    /// Cache error.
    #[error("Cache error: {0}")]
    CacheError(String),
}

impl Vol3Error {
    /// Create an InvalidAddress error.
    pub fn invalid_address(layer_name: impl Into<String>, addr: u64, msg: impl Into<String>) -> Self {
        Vol3Error::InvalidAddress {
            layer_name: layer_name.into(),
            invalid_address: addr,
            message: msg.into(),
        }
    }

    /// Create a PagedInvalidAddress error.
    pub fn paged_invalid_address(
        layer_name: impl Into<String>,
        addr: u64,
        invalid_bits: u32,
        entry: u64,
        msg: impl Into<String>,
    ) -> Self {
        Vol3Error::PagedInvalidAddress {
            layer_name: layer_name.into(),
            invalid_address: addr,
            invalid_bits,
            entry,
            message: msg.into(),
        }
    }

    /// Create a SwappedInvalidAddress error.
    pub fn swapped_invalid_address(
        layer_name: impl Into<String>,
        addr: u64,
        invalid_bits: u32,
        entry: u64,
        swap_offset: u64,
        swap_index: u8,
        msg: impl Into<String>,
    ) -> Self {
        Vol3Error::SwappedInvalidAddress {
            layer_name: layer_name.into(),
            invalid_address: addr,
            invalid_bits,
            entry,
            swap_offset,
            swap_index,
            message: msg.into(),
        }
    }

    /// Create a LayerDestroyed error.
    pub fn layer_destroyed(name: impl Into<String>) -> Self {
        Vol3Error::LayerDestroyed(name.into())
    }
}

/// Result type for memory operations.
pub type Vol3Result<T> = Result<T, Vol3Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_address_error() {
        let err = Vol3Error::invalid_address("test_layer", 0x1000, "test message");
        assert!(err.to_string().contains("test_layer"));
        assert!(err.to_string().contains("0x1000"));
    }

    #[test]
    fn test_paged_invalid_address_error() {
        let err = Vol3Error::paged_invalid_address("test_layer", 0x1000, 12, 0xDEAD, "page fault");
        assert!(err.to_string().contains("test_layer"));
        assert!(err.to_string().contains("0x1000"));
        assert!(err.to_string().contains("invalid_bits=12"));
    }
}
