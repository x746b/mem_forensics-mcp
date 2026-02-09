//! Type definitions for parsed ISF (Intermediate Symbol Format) data.

use serde::Deserialize;
use std::collections::HashMap;

/// Top-level ISF file structure.
#[derive(Debug, Deserialize)]
pub struct IsfFile {
    pub metadata: Metadata,
    #[serde(default)]
    pub base_types: HashMap<String, BaseType>,
    #[serde(default)]
    pub user_types: HashMap<String, UserType>,
    #[serde(default)]
    pub symbols: HashMap<String, Symbol>,
    #[serde(default)]
    pub enums: HashMap<String, EnumType>,
}

/// ISF metadata block.
#[derive(Debug, Deserialize)]
pub struct Metadata {
    pub format: String,
    #[serde(default)]
    pub producer: Option<Producer>,
    #[serde(default)]
    pub windows: Option<WindowsMetadata>,
    #[serde(default)]
    pub linux: Option<LinuxMetadata>,
    #[serde(default)]
    pub mac: Option<MacMetadata>,
}

#[derive(Debug, Deserialize)]
pub struct Producer {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub datetime: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct WindowsMetadata {
    #[serde(default)]
    pub major: Option<u32>,
    #[serde(default)]
    pub minor: Option<u32>,
    #[serde(default)]
    pub revision: Option<u32>,
    #[serde(default)]
    pub build: Option<u32>,
    #[serde(default)]
    pub pe_file: Option<String>,
    #[serde(default)]
    pub pdb_file: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LinuxMetadata {
    #[serde(default)]
    pub banner: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MacMetadata {
    #[serde(default)]
    pub banner: Option<String>,
}

/// A base (primitive) type definition.
#[derive(Debug, Clone, Deserialize)]
pub struct BaseType {
    pub size: usize,
    pub signed: bool,
    pub kind: String,
    #[serde(default = "default_endian")]
    pub endian: String,
}

fn default_endian() -> String {
    "little".to_string()
}

/// A user-defined (struct) type.
#[derive(Debug, Clone, Deserialize)]
pub struct UserType {
    pub size: usize,
    #[serde(default)]
    pub fields: HashMap<String, FieldDef>,
    /// Some ISF files have a "kind" field at the user_type level.
    #[serde(default)]
    pub kind: Option<String>,
}

/// A field within a user type.
#[derive(Debug, Clone, Deserialize)]
pub struct FieldDef {
    pub offset: usize,
    #[serde(rename = "type")]
    pub type_info: TypeInfo,
}

/// Type information for a field — recursive to handle nested types.
#[derive(Debug, Clone, Deserialize)]
pub struct TypeInfo {
    pub kind: String,

    /// For kind="struct" or kind="base": the type name.
    #[serde(default)]
    pub name: Option<String>,

    /// For kind="pointer": the subtype being pointed to.
    #[serde(default)]
    pub subtype: Option<Box<TypeInfo>>,

    /// For kind="array": element count.
    #[serde(default)]
    pub count: Option<usize>,

    /// For kind="bitfield": bit position and bit length.
    #[serde(default)]
    pub bit_position: Option<usize>,
    #[serde(default)]
    pub bit_length: Option<usize>,

    /// For kind="enum": the enum name.
    #[serde(default, rename = "enum")]
    pub enum_name: Option<String>,

    /// For kind="pointer" or "array": the element type.
    #[serde(default, rename = "type")]
    pub element_type: Option<Box<TypeInfo>>,

    /// Size override (some ISF files specify size at the type level).
    #[serde(default)]
    pub size: Option<usize>,
}

/// A symbol (named address).
#[derive(Debug, Clone, Deserialize)]
pub struct Symbol {
    pub address: u64,
    /// Some symbols have associated type information.
    #[serde(default, rename = "type")]
    pub type_info: Option<TypeInfo>,
    /// Base64-encoded constant data (rare).
    #[serde(default)]
    pub constant_data: Option<String>,
}

/// An enumeration type.
#[derive(Debug, Clone, Deserialize)]
pub struct EnumType {
    /// The size of the underlying integer type.
    pub size: usize,
    /// The base type name.
    pub base: String,
    /// Mapping from enum constant name to value.
    pub constants: HashMap<String, i64>,
}

// ============================================================================
// Resolved/processed types for runtime use
// ============================================================================

/// Fully resolved symbol table ready for use.
#[derive(Debug)]
pub struct IsfSymbols {
    /// Base (primitive) types.
    pub base_types: HashMap<String, BaseType>,
    /// User-defined struct types.
    pub user_types: HashMap<String, UserType>,
    /// Named symbols (addresses).
    pub symbols: HashMap<String, Symbol>,
    /// Enumerations.
    pub enums: HashMap<String, EnumType>,
    /// Metadata.
    pub metadata: Metadata,
    /// Pointer size in bytes (4 or 8).
    pub pointer_size: usize,
}

impl IsfSymbols {
    /// Look up a struct definition by name.
    pub fn get_type(&self, name: &str) -> Option<&UserType> {
        self.user_types.get(name)
    }

    /// Look up a symbol address by name.
    pub fn get_symbol(&self, name: &str) -> Option<u64> {
        self.symbols.get(name).map(|s| s.address)
    }

    /// Look up a field offset within a struct.
    pub fn field_offset(&self, type_name: &str, field_name: &str) -> Option<usize> {
        self.user_types
            .get(type_name)
            .and_then(|t| t.fields.get(field_name))
            .map(|f| f.offset)
    }

    /// Get the size of a type (user type or base type).
    pub fn type_size(&self, type_name: &str) -> Option<usize> {
        if let Some(ut) = self.user_types.get(type_name) {
            Some(ut.size)
        } else if let Some(bt) = self.base_types.get(type_name) {
            Some(bt.size)
        } else {
            None
        }
    }

    /// Resolve the size of a TypeInfo in bytes.
    pub fn resolve_type_size(&self, type_info: &TypeInfo) -> Option<usize> {
        if let Some(size) = type_info.size {
            return Some(size);
        }
        match type_info.kind.as_str() {
            "pointer" => Some(self.pointer_size),
            "struct" | "base" => type_info
                .name
                .as_ref()
                .and_then(|n| self.type_size(n)),
            "array" => {
                let count = type_info.count.unwrap_or(0);
                let elem_size = type_info
                    .subtype
                    .as_ref()
                    .and_then(|st| self.resolve_type_size(st))
                    .or_else(|| {
                        type_info
                            .element_type
                            .as_ref()
                            .and_then(|et| self.resolve_type_size(et))
                    })?;
                Some(count * elem_size)
            }
            "bitfield" => type_info
                .name
                .as_ref()
                .and_then(|n| self.type_size(n)),
            "enum" => type_info
                .enum_name
                .as_ref()
                .and_then(|n| self.enums.get(n))
                .map(|e| e.size),
            _ => None,
        }
    }

    /// Look up an enum value by name.
    pub fn enum_value(&self, enum_name: &str, constant_name: &str) -> Option<i64> {
        self.enums
            .get(enum_name)
            .and_then(|e| e.constants.get(constant_name))
            .copied()
    }

    /// Reverse-lookup an enum constant name by value.
    pub fn enum_name(&self, enum_name: &str, value: i64) -> Option<&str> {
        self.enums.get(enum_name).and_then(|e| {
            e.constants.iter().find_map(|(name, &v)| {
                if v == value {
                    Some(name.as_str())
                } else {
                    None
                }
            })
        })
    }
}
