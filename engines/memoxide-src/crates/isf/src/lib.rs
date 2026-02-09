//! ISF (Intermediate Symbol Format) parser for Volatility3 symbol files.
//!
//! This crate parses the JSON-based ISF files used by Volatility3 to describe
//! Windows kernel structures, symbols, and types. It provides:
//!
//! - Parsing of `.json` and `.json.xz` (LZMA-compressed) ISF files
//! - Type definitions for all ISF constructs (structs, base types, enums, symbols)
//! - `StructReader` for reading kernel structures from memory using ISF offsets
//! - `ListIterator` for walking Windows kernel doubly-linked lists (`_LIST_ENTRY`)
//!
//! # Example
//!
//! ```rust,ignore
//! use isf::{parse_isf_file, StructReader, MemoryAccess};
//!
//! let symbols = parse_isf_file("ntkrnlmp.pdb/GUID/ntkrnlmp.json.xz")?;
//! let eprocess_size = symbols.type_size("_EPROCESS");
//! let pid_offset = symbols.field_offset("_EPROCESS", "UniqueProcessId");
//! ```

pub mod error;
pub mod parser;
pub mod reader;
pub mod types;

// Re-export key types at crate root.
pub use error::{IsfError, IsfResult};
pub use parser::{parse_isf_bytes, parse_isf_file, parse_isf_str};
pub use reader::{ListIterator, MemoryAccess, StructReader};
pub use types::{IsfSymbols, BaseType, EnumType, FieldDef, Symbol, TypeInfo, UserType};
