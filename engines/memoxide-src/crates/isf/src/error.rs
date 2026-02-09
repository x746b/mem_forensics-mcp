//! Error types for the ISF crate.

use thiserror::Error;

/// ISF parsing/reading errors.
#[derive(Debug, Error)]
pub enum IsfError {
    #[error("ISF file not found: {0}")]
    FileNotFound(String),

    #[error("I/O error: {0}")]
    Io(String),

    #[error("XZ/LZMA decompression error: {0}")]
    Decompression(String),

    #[error("JSON parse error: {0}")]
    JsonParse(String),

    #[error("Type not found: {0}")]
    TypeNotFound(String),

    #[error("Field not found: {field} in type {type_name}")]
    FieldNotFound { type_name: String, field: String },

    #[error("Memory read error at offset {offset:#x}: {msg}")]
    MemoryRead { offset: u64, msg: String },

    #[error("Invalid pointer: {0:#x}")]
    InvalidPointer(u64),
}

pub type IsfResult<T> = Result<T, IsfError>;
