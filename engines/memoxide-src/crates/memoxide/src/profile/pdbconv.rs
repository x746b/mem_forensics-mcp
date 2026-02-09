//! PDB → ISF conversion.
//!
//! Converts a Microsoft PDB (Program Database) file into the Volatility3 ISF JSON format.
//! This allows auto-detection of Windows kernel symbols by downloading PDBs from the
//! Microsoft Symbol Server and converting them on-the-fly.

use pdb::{
    ArrayType, ClassKind, FallibleIterator, PrimitiveKind, PrimitiveType, TypeData, TypeFinder,
    TypeIndex, Variant,
};
use serde_json::{json, Map, Value};
use std::io::Cursor;
use tracing::debug;

/// Convert raw PDB bytes into an ISF JSON string.
///
/// The output is compatible with `isf::parse_isf_str()` and contains:
/// - metadata (format, producer, windows PDB info)
/// - base_types (standard Windows kernel primitives)
/// - user_types (all structs/unions from the PDB type stream)
/// - enums (all enumerations from the PDB type stream)
/// - symbols (all public symbols with RVAs from the PDB symbol stream)
pub fn convert_pdb_to_isf(
    pdb_bytes: &[u8],
    pdb_name: &str,
    guid: &str,
    age: u32,
) -> Result<String, String> {
    let cursor = Cursor::new(pdb_bytes);
    let mut pdb = pdb::PDB::open(cursor).map_err(|e| format!("Failed to open PDB: {}", e))?;

    // Determine pointer size from DBI machine type.
    let pointer_size: usize = match pdb.debug_information() {
        Ok(dbi) => match dbi.machine_type() {
            Ok(pdb::MachineType::Amd64) | Ok(pdb::MachineType::Ia64) => 8,
            _ => 4,
        },
        Err(_) => 8, // Default to x64 for kernel PDBs
    };

    // Build the TypeFinder for random-access type lookups.
    let type_info = pdb
        .type_information()
        .map_err(|e| format!("Failed to read type info: {}", e))?;
    let mut type_finder = type_info.finder();
    {
        let mut iter = type_info.iter();
        while iter.next().map_err(|e| format!("type iter: {}", e))?.is_some() {
            type_finder.update(&iter);
        }
    }

    // Collect all types: structs, unions, enums.
    let mut user_types: Map<String, Value> = Map::new();
    let mut enums: Map<String, Value> = Map::new();

    {
        let mut iter = type_info.iter();
        while let Some(item) = iter.next().map_err(|e| format!("type iter: {}", e))? {
            let type_data = match item.parse() {
                Ok(d) => d,
                Err(_) => continue,
            };

            match type_data {
                TypeData::Class(c) => {
                    if c.properties.forward_reference() {
                        continue;
                    }
                    let name = c.name.to_string().to_string();
                    if name.is_empty() {
                        continue;
                    }
                    let kind_str = match c.kind {
                        ClassKind::Class | ClassKind::Struct | ClassKind::Interface => "struct",
                    };
                    let fields_json =
                        convert_fields(c.fields, &type_finder, &type_info, pointer_size);
                    user_types.insert(
                        name,
                        json!({
                            "size": c.size,
                            "fields": fields_json,
                            "kind": kind_str,
                        }),
                    );
                }
                TypeData::Union(u) => {
                    if u.properties.forward_reference() {
                        continue;
                    }
                    let name = u.name.to_string().to_string();
                    if name.is_empty() {
                        continue;
                    }
                    let fields_json = convert_fields(
                        Some(u.fields),
                        &type_finder,
                        &type_info,
                        pointer_size,
                    );
                    user_types.insert(
                        name,
                        json!({
                            "size": u.size,
                            "fields": fields_json,
                            "kind": "union",
                        }),
                    );
                }
                TypeData::Enumeration(e) => {
                    if e.properties.forward_reference() {
                        continue;
                    }
                    let name = e.name.to_string().to_string();
                    if name.is_empty() {
                        continue;
                    }
                    let underlying_size =
                        resolve_type_size(e.underlying_type, &type_finder, pointer_size);
                    let underlying_name =
                        resolve_base_type_name(e.underlying_type, &type_finder);
                    let constants = convert_enum_constants(e.fields, &type_finder, &type_info);
                    enums.insert(
                        name,
                        json!({
                            "size": underlying_size,
                            "base": underlying_name,
                            "constants": constants,
                        }),
                    );
                }
                _ => {}
            }
        }
    }

    // Extract global symbols (public symbols with RVAs).
    let mut symbols: Map<String, Value> = Map::new();
    let global_symbols = pdb
        .global_symbols()
        .map_err(|e| format!("Failed to read global symbols: {}", e))?;
    let address_map = pdb
        .address_map()
        .map_err(|e| format!("Failed to read address map: {}", e))?;

    {
        let mut iter = global_symbols.iter();
        while let Some(sym) = iter.next().map_err(|e| format!("symbol iter: {}", e))? {
            if let Ok(pdb::SymbolData::Public(pub_sym)) = sym.parse() {
                if let Some(rva) = pub_sym.offset.to_rva(&address_map) {
                    let name = pub_sym.name.to_string().to_string();
                    if !name.is_empty() {
                        symbols.insert(name, json!({ "address": rva.0 }));
                    }
                }
            }
        }
    }

    // Build base_types (standard set for the target architecture).
    let base_types = build_base_types(pointer_size);

    // Build metadata.
    let metadata = json!({
        "format": "6.2.0",
        "producer": {
            "name": "memoxide-pdbconv",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "windows": {
            "pdb_file": pdb_name,
        },
    });

    // Assemble the complete ISF JSON.
    let isf = json!({
        "metadata": metadata,
        "base_types": base_types,
        "user_types": Value::Object(user_types),
        "enums": Value::Object(enums),
        "symbols": Value::Object(symbols),
    });

    let json_str = serde_json::to_string_pretty(&isf)
        .map_err(|e| format!("Failed to serialize ISF JSON: {}", e))?;

    // Validate: parse back through the ISF parser.
    isf::parse_isf_str(&json_str).map_err(|e| format!("Generated ISF failed validation: {}", e))?;

    debug!(
        "PDB→ISF conversion complete: {} user_types, {} enums, {} symbols (guid={}-{})",
        isf["user_types"].as_object().map_or(0, |m| m.len()),
        isf["enums"].as_object().map_or(0, |m| m.len()),
        isf["symbols"].as_object().map_or(0, |m| m.len()),
        guid,
        age,
    );

    Ok(json_str)
}

/// Convert PDB fields (from a FieldList type index) into ISF-format field map.
fn convert_fields(
    fields_idx: Option<TypeIndex>,
    type_finder: &TypeFinder,
    type_info: &pdb::TypeInformation,
    pointer_size: usize,
) -> Map<String, Value> {
    let mut result = Map::new();
    let Some(idx) = fields_idx else {
        return result;
    };

    collect_fields_recursive(idx, type_finder, type_info, pointer_size, &mut result);
    result
}

/// Recursively collect fields following FieldList continuation chains.
fn collect_fields_recursive(
    field_list_idx: TypeIndex,
    type_finder: &TypeFinder,
    type_info: &pdb::TypeInformation,
    pointer_size: usize,
    out: &mut Map<String, Value>,
) {
    let item = match type_finder.find(field_list_idx) {
        Ok(item) => item,
        Err(_) => return,
    };

    let type_data = match item.parse() {
        Ok(d) => d,
        Err(_) => return,
    };

    let TypeData::FieldList(fl) = type_data else {
        return;
    };

    for field in &fl.fields {
        match field {
            TypeData::Member(m) => {
                let name = m.name.to_string().to_string();
                if name.is_empty() {
                    continue;
                }
                let type_json = resolve_type(m.field_type, type_finder, pointer_size);
                out.insert(
                    name,
                    json!({
                        "offset": m.offset,
                        "type": type_json,
                    }),
                );
            }
            TypeData::StaticMember(_) => {
                // Static members don't have offsets — skip.
            }
            TypeData::Nested(_) => {
                // Nested type definitions — skip (referenced transitively).
            }
            TypeData::BaseClass(bc) => {
                // Base class as a field at the given offset.
                let type_json = resolve_type(bc.base_class, type_finder, pointer_size);
                let name = format!("__base_{}", bc.base_class.0);
                out.insert(
                    name,
                    json!({
                        "offset": bc.offset,
                        "type": type_json,
                    }),
                );
            }
            TypeData::VirtualBaseClass(_) | TypeData::VirtualFunctionTablePointer(_) => {
                // Virtual base classes and vtable pointers — skip for ISF.
            }
            _ => {}
        }
    }

    // Follow continuation chain for large structs.
    if let Some(cont) = fl.continuation {
        collect_fields_recursive(cont, type_finder, type_info, pointer_size, out);
    }
}

/// Resolve a PDB TypeIndex to an ISF type JSON value.
fn resolve_type(idx: TypeIndex, type_finder: &TypeFinder, pointer_size: usize) -> Value {
    // Check if it's a primitive type index (< 0x1000).
    if idx.0 < 0x1000 {
        return resolve_primitive_type_index(idx, pointer_size);
    }

    let item = match type_finder.find(idx) {
        Ok(item) => item,
        Err(_) => return json!({ "kind": "base", "name": "void" }),
    };

    let type_data = match item.parse() {
        Ok(d) => d,
        Err(_) => return json!({ "kind": "base", "name": "void" }),
    };

    match type_data {
        TypeData::Primitive(p) => resolve_primitive(&p, pointer_size),
        TypeData::Class(c) => {
            let name = c.name.to_string().to_string();
            json!({ "kind": "struct", "name": name })
        }
        TypeData::Union(u) => {
            let name = u.name.to_string().to_string();
            json!({ "kind": "union", "name": name })
        }
        TypeData::Pointer(p) => {
            let sub = resolve_type(p.underlying_type, type_finder, pointer_size);
            json!({ "kind": "pointer", "subtype": sub })
        }
        TypeData::Array(a) => resolve_array(&a, type_finder, pointer_size),
        TypeData::Bitfield(b) => {
            let underlying = resolve_type(b.underlying_type, type_finder, pointer_size);
            json!({
                "kind": "bitfield",
                "bit_position": b.position,
                "bit_length": b.length,
                "type": underlying,
            })
        }
        TypeData::Modifier(m) => {
            // const/volatile don't affect ISF layout — pass through.
            resolve_type(m.underlying_type, type_finder, pointer_size)
        }
        TypeData::Enumeration(e) => {
            let name = e.name.to_string().to_string();
            json!({ "kind": "enum", "name": name })
        }
        TypeData::Procedure(_) | TypeData::MemberFunction(_) => {
            // Function pointer → treat as void pointer.
            json!({ "kind": "pointer", "subtype": { "kind": "base", "name": "void" } })
        }
        _ => json!({ "kind": "base", "name": "void" }),
    }
}

/// Resolve a PDB primitive TypeIndex (< 0x1000) to ISF type JSON.
///
/// Primitive type indices encode both the kind and indirection in a single u32:
/// - Bits 0-7: kind
/// - Bits 8-11: indirection mode
fn resolve_primitive_type_index(idx: TypeIndex, _pointer_size: usize) -> Value {
    let raw = idx.0;
    let has_indirection = (raw & 0xf00) != 0;
    let base_name = primitive_kind_name(raw & 0xff);

    if has_indirection {
        json!({
            "kind": "pointer",
            "subtype": { "kind": "base", "name": base_name },
        })
    } else {
        json!({ "kind": "base", "name": base_name })
    }
}

/// Map a raw primitive kind value (low byte of TypeIndex) to an ISF base type name.
fn primitive_kind_name(kind_val: u32) -> &'static str {
    match kind_val {
        0x00 => "void",       // NoType / special
        0x03 => "void",       // Void
        0x10 => "char",       // Char (signed 8-bit)
        0x20 => "unsigned char", // UChar
        0x68 => "char",       // RChar (narrow char)
        0x69 => "char",       // I8
        0x6a => "unsigned char", // U8
        0x71 => "wchar",      // WChar (wide char)
        0x7a => "wchar",      // RChar16
        0x7b => "unsigned long", // RChar32
        0x11 => "short",      // Short
        0x21 => "unsigned short", // UShort
        0x72 => "short",      // I16
        0x73 => "unsigned short", // U16
        0x12 => "long",       // Long
        0x22 => "unsigned long", // ULong
        0x74 => "long",       // I32
        0x75 => "unsigned long", // U32
        0x13 => "long long",  // Quad
        0x23 => "unsigned long long", // UQuad
        0x76 => "long long",  // I64
        0x77 => "unsigned long long", // U64
        0x14 => "long long",  // Octa (128-bit — approximate as 64-bit for ISF)
        0x24 => "unsigned long long", // UOcta
        0x78 => "long long",  // I128
        0x79 => "unsigned long long", // U128
        0x40 => "float",      // F32
        0x41 => "double",     // F64
        0x42 => "double",     // F80 (80-bit float → approximate)
        0x46 => "float",      // F16
        0x44 => "double",     // F128
        0x30 => "unsigned char", // Bool8
        0x31 => "unsigned short", // Bool16
        0x32 => "unsigned long", // Bool32
        0x33 => "unsigned long long", // Bool64
        0x08 => "long",       // HRESULT
        _ => "void",
    }
}

/// Resolve a parsed PrimitiveType to ISF JSON.
fn resolve_primitive(p: &PrimitiveType, _pointer_size: usize) -> Value {
    let base_name = map_primitive_kind(&p.kind);

    if p.indirection.is_some() {
        json!({
            "kind": "pointer",
            "subtype": { "kind": "base", "name": base_name },
        })
    } else {
        json!({ "kind": "base", "name": base_name })
    }
}

/// Map PrimitiveKind enum to ISF base type name.
pub fn map_primitive_kind(kind: &PrimitiveKind) -> &'static str {
    match kind {
        PrimitiveKind::NoType => "void",
        PrimitiveKind::Void => "void",
        PrimitiveKind::Char | PrimitiveKind::RChar | PrimitiveKind::I8 => "char",
        PrimitiveKind::UChar | PrimitiveKind::U8 => "unsigned char",
        PrimitiveKind::WChar | PrimitiveKind::RChar16 => "wchar",
        PrimitiveKind::RChar32 => "unsigned long",
        PrimitiveKind::Short | PrimitiveKind::I16 => "short",
        PrimitiveKind::UShort | PrimitiveKind::U16 => "unsigned short",
        PrimitiveKind::Long | PrimitiveKind::I32 => "long",
        PrimitiveKind::ULong | PrimitiveKind::U32 => "unsigned long",
        PrimitiveKind::Quad | PrimitiveKind::I64 => "long long",
        PrimitiveKind::UQuad | PrimitiveKind::U64 => "unsigned long long",
        PrimitiveKind::Octa | PrimitiveKind::I128 => "long long",
        PrimitiveKind::UOcta | PrimitiveKind::U128 => "unsigned long long",
        PrimitiveKind::F16 | PrimitiveKind::F32 | PrimitiveKind::F32PP => "float",
        PrimitiveKind::F48 | PrimitiveKind::F64 => "double",
        PrimitiveKind::F80 | PrimitiveKind::F128 => "double",
        PrimitiveKind::Complex32 => "float",
        PrimitiveKind::Complex64 | PrimitiveKind::Complex80 | PrimitiveKind::Complex128 => {
            "double"
        }
        PrimitiveKind::Bool8 => "unsigned char",
        PrimitiveKind::Bool16 => "unsigned short",
        PrimitiveKind::Bool32 => "unsigned long",
        PrimitiveKind::Bool64 => "unsigned long long",
        PrimitiveKind::HRESULT => "long",
        _ => "void",
    }
}

/// Resolve an ArrayType to ISF JSON.
fn resolve_array(a: &ArrayType, type_finder: &TypeFinder, pointer_size: usize) -> Value {
    let elem_type = resolve_type(a.element_type, type_finder, pointer_size);
    let elem_size = resolve_type_size(a.element_type, type_finder, pointer_size);

    // PDB dimensions are total byte counts.  We need element count.
    let total_bytes: u64 = a.dimensions.iter().map(|&d| d as u64).product();
    let count = if elem_size > 0 {
        (total_bytes / elem_size as u64) as usize
    } else if !a.dimensions.is_empty() {
        a.dimensions[0] as usize
    } else {
        0
    };

    json!({
        "kind": "array",
        "count": count,
        "subtype": elem_type,
    })
}

/// Resolve the byte size of a type index.
fn resolve_type_size(idx: TypeIndex, type_finder: &TypeFinder, pointer_size: usize) -> usize {
    if idx.0 < 0x1000 {
        let has_indirection = (idx.0 & 0xf00) != 0;
        if has_indirection {
            return pointer_size;
        }
        return primitive_kind_byte_size(idx.0 & 0xff, pointer_size);
    }

    let item = match type_finder.find(idx) {
        Ok(item) => item,
        Err(_) => return 0,
    };
    let type_data = match item.parse() {
        Ok(d) => d,
        Err(_) => return 0,
    };

    match type_data {
        TypeData::Primitive(p) => {
            if p.indirection.is_some() {
                pointer_size
            } else {
                primitive_kind_byte_size_enum(&p.kind, pointer_size)
            }
        }
        TypeData::Class(c) => c.size as usize,
        TypeData::Union(u) => u.size as usize,
        TypeData::Pointer(_) => pointer_size,
        TypeData::Modifier(m) => resolve_type_size(m.underlying_type, type_finder, pointer_size),
        TypeData::Enumeration(e) => {
            resolve_type_size(e.underlying_type, type_finder, pointer_size)
        }
        TypeData::Array(a) => a.dimensions.iter().map(|&d| d as usize).product::<usize>().max(1),
        TypeData::Bitfield(b) => resolve_type_size(b.underlying_type, type_finder, pointer_size),
        _ => 0,
    }
}

/// Byte size of a raw primitive kind value.
fn primitive_kind_byte_size(kind_val: u32, _pointer_size: usize) -> usize {
    match kind_val {
        0x00 | 0x03 => 0,                          // void
        0x10 | 0x20 | 0x68 | 0x69 | 0x30 => 1,    // char/uchar/i8/u8/bool8
        0x11 | 0x21 | 0x72 | 0x73 | 0x31 | 0x71 | 0x7a => 2, // short/ushort/i16/u16/bool16/wchar
        0x12 | 0x22 | 0x74 | 0x75 | 0x32 | 0x08 | 0x7b => 4, // long/ulong/i32/u32/bool32/hresult
        0x13 | 0x23 | 0x76 | 0x77 | 0x33 => 8,    // quad/uquad/i64/u64/bool64
        0x14 | 0x24 | 0x78 | 0x79 => 16,           // octa/uocta/i128/u128
        0x46 => 2,                                   // f16
        0x40 => 4,                                   // f32
        0x41 => 8,                                   // f64
        0x42 => 10,                                  // f80
        0x44 => 16,                                  // f128
        _ => 0,
    }
}

/// Byte size from a PrimitiveKind enum.
fn primitive_kind_byte_size_enum(kind: &PrimitiveKind, _pointer_size: usize) -> usize {
    match kind {
        PrimitiveKind::NoType | PrimitiveKind::Void => 0,
        PrimitiveKind::Char
        | PrimitiveKind::UChar
        | PrimitiveKind::RChar
        | PrimitiveKind::I8
        | PrimitiveKind::U8
        | PrimitiveKind::Bool8 => 1,
        PrimitiveKind::Short
        | PrimitiveKind::UShort
        | PrimitiveKind::I16
        | PrimitiveKind::U16
        | PrimitiveKind::Bool16
        | PrimitiveKind::WChar
        | PrimitiveKind::RChar16
        | PrimitiveKind::F16 => 2,
        PrimitiveKind::Long
        | PrimitiveKind::ULong
        | PrimitiveKind::I32
        | PrimitiveKind::U32
        | PrimitiveKind::Bool32
        | PrimitiveKind::HRESULT
        | PrimitiveKind::RChar32
        | PrimitiveKind::F32
        | PrimitiveKind::F32PP
        | PrimitiveKind::Complex32 => 4,
        PrimitiveKind::Quad
        | PrimitiveKind::UQuad
        | PrimitiveKind::I64
        | PrimitiveKind::U64
        | PrimitiveKind::Bool64
        | PrimitiveKind::F64
        | PrimitiveKind::Complex64 => 8,
        PrimitiveKind::F80 | PrimitiveKind::Complex80 => 10,
        PrimitiveKind::Octa
        | PrimitiveKind::UOcta
        | PrimitiveKind::I128
        | PrimitiveKind::U128
        | PrimitiveKind::F128
        | PrimitiveKind::Complex128 => 16,
        PrimitiveKind::F48 => 6,
        _ => 0,
    }
}

/// Convert enum constants from a FieldList.
fn convert_enum_constants(
    fields_idx: TypeIndex,
    type_finder: &TypeFinder,
    type_info: &pdb::TypeInformation,
) -> Map<String, Value> {
    let mut result = Map::new();
    collect_enum_constants_recursive(fields_idx, type_finder, type_info, &mut result);
    result
}

fn collect_enum_constants_recursive(
    field_list_idx: TypeIndex,
    type_finder: &TypeFinder,
    type_info: &pdb::TypeInformation,
    out: &mut Map<String, Value>,
) {
    let item = match type_finder.find(field_list_idx) {
        Ok(item) => item,
        Err(_) => return,
    };
    let type_data = match item.parse() {
        Ok(d) => d,
        Err(_) => return,
    };

    let TypeData::FieldList(fl) = type_data else {
        return;
    };

    for field in &fl.fields {
        if let TypeData::Enumerate(e) = field {
            let name = e.name.to_string().to_string();
            let value = variant_to_i64(&e.value);
            out.insert(name, json!(value));
        }
    }

    if let Some(cont) = fl.continuation {
        collect_enum_constants_recursive(cont, type_finder, type_info, out);
    }
}

/// Convert a PDB Variant to i64.
pub fn variant_to_i64(v: &Variant) -> i64 {
    match *v {
        Variant::U8(x) => x as i64,
        Variant::U16(x) => x as i64,
        Variant::U32(x) => x as i64,
        Variant::U64(x) => x as i64,
        Variant::I8(x) => x as i64,
        Variant::I16(x) => x as i64,
        Variant::I32(x) => x as i64,
        Variant::I64(x) => x,
    }
}

/// Resolve a type index to an ISF base type name string (for enum "base" field).
fn resolve_base_type_name(idx: TypeIndex, type_finder: &TypeFinder) -> String {
    if idx.0 < 0x1000 {
        return primitive_kind_name(idx.0 & 0xff).to_string();
    }
    let item = match type_finder.find(idx) {
        Ok(item) => item,
        Err(_) => return "unsigned long".to_string(),
    };
    let type_data = match item.parse() {
        Ok(d) => d,
        Err(_) => return "unsigned long".to_string(),
    };
    match type_data {
        TypeData::Primitive(p) => map_primitive_kind(&p.kind).to_string(),
        _ => "unsigned long".to_string(),
    }
}

/// Build the standard set of base types for ISF.
fn build_base_types(pointer_size: usize) -> Value {
    json!({
        "pointer": { "size": pointer_size, "signed": false, "kind": "int", "endian": "little" },
        "unsigned long": { "size": 4, "signed": false, "kind": "int", "endian": "little" },
        "unsigned long long": { "size": 8, "signed": false, "kind": "int", "endian": "little" },
        "unsigned short": { "size": 2, "signed": false, "kind": "int", "endian": "little" },
        "unsigned char": { "size": 1, "signed": false, "kind": "int", "endian": "little" },
        "long": { "size": 4, "signed": true, "kind": "int", "endian": "little" },
        "long long": { "size": 8, "signed": true, "kind": "int", "endian": "little" },
        "short": { "size": 2, "signed": true, "kind": "int", "endian": "little" },
        "char": { "size": 1, "signed": true, "kind": "int", "endian": "little" },
        "wchar": { "size": 2, "signed": false, "kind": "int", "endian": "little" },
        "void": { "size": 0, "signed": false, "kind": "void", "endian": "little" },
        "float": { "size": 4, "signed": false, "kind": "float", "endian": "little" },
        "double": { "size": 8, "signed": false, "kind": "float", "endian": "little" },
        "_Bool": { "size": 1, "signed": false, "kind": "bool", "endian": "little" },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_primitive_mapping() {
        assert_eq!(map_primitive_kind(&PrimitiveKind::Void), "void");
        assert_eq!(map_primitive_kind(&PrimitiveKind::Char), "char");
        assert_eq!(map_primitive_kind(&PrimitiveKind::UChar), "unsigned char");
        assert_eq!(map_primitive_kind(&PrimitiveKind::Short), "short");
        assert_eq!(map_primitive_kind(&PrimitiveKind::UShort), "unsigned short");
        assert_eq!(map_primitive_kind(&PrimitiveKind::Long), "long");
        assert_eq!(map_primitive_kind(&PrimitiveKind::ULong), "unsigned long");
        assert_eq!(map_primitive_kind(&PrimitiveKind::Quad), "long long");
        assert_eq!(
            map_primitive_kind(&PrimitiveKind::UQuad),
            "unsigned long long"
        );
        assert_eq!(map_primitive_kind(&PrimitiveKind::WChar), "wchar");
        assert_eq!(map_primitive_kind(&PrimitiveKind::Bool8), "unsigned char");
        assert_eq!(map_primitive_kind(&PrimitiveKind::F32), "float");
        assert_eq!(map_primitive_kind(&PrimitiveKind::F64), "double");
        assert_eq!(map_primitive_kind(&PrimitiveKind::HRESULT), "long");
        assert_eq!(map_primitive_kind(&PrimitiveKind::I8), "char");
        assert_eq!(map_primitive_kind(&PrimitiveKind::U8), "unsigned char");
        assert_eq!(map_primitive_kind(&PrimitiveKind::I16), "short");
        assert_eq!(map_primitive_kind(&PrimitiveKind::U16), "unsigned short");
        assert_eq!(map_primitive_kind(&PrimitiveKind::I32), "long");
        assert_eq!(map_primitive_kind(&PrimitiveKind::U32), "unsigned long");
        assert_eq!(map_primitive_kind(&PrimitiveKind::I64), "long long");
        assert_eq!(
            map_primitive_kind(&PrimitiveKind::U64),
            "unsigned long long"
        );
    }

    #[test]
    fn test_base_types_emitted() {
        let bt = build_base_types(8);
        let obj = bt.as_object().unwrap();
        assert!(obj.contains_key("pointer"));
        assert!(obj.contains_key("unsigned long"));
        assert!(obj.contains_key("unsigned long long"));
        assert!(obj.contains_key("unsigned short"));
        assert!(obj.contains_key("unsigned char"));
        assert!(obj.contains_key("long"));
        assert!(obj.contains_key("long long"));
        assert!(obj.contains_key("short"));
        assert!(obj.contains_key("char"));
        assert!(obj.contains_key("wchar"));
        assert!(obj.contains_key("void"));
        assert!(obj.contains_key("float"));
        assert!(obj.contains_key("double"));
        assert!(obj.contains_key("_Bool"));

        // Verify pointer size
        let ptr = obj["pointer"].as_object().unwrap();
        assert_eq!(ptr["size"], 8);

        // Verify 32-bit base types
        let bt32 = build_base_types(4);
        let obj32 = bt32.as_object().unwrap();
        assert_eq!(obj32["pointer"].as_object().unwrap()["size"], 4);
    }

    #[test]
    fn test_variant_to_i64() {
        assert_eq!(variant_to_i64(&Variant::U8(42)), 42);
        assert_eq!(variant_to_i64(&Variant::U16(1000)), 1000);
        assert_eq!(variant_to_i64(&Variant::U32(0xDEAD)), 0xDEAD);
        assert_eq!(variant_to_i64(&Variant::U64(0xCAFEBABE)), 0xCAFEBABE);
        assert_eq!(variant_to_i64(&Variant::I8(-1)), -1);
        assert_eq!(variant_to_i64(&Variant::I16(-100)), -100);
        assert_eq!(variant_to_i64(&Variant::I32(-50000)), -50000);
        assert_eq!(variant_to_i64(&Variant::I64(i64::MIN)), i64::MIN);
    }

    /// Integration test: download a real kernel PDB and convert it.
    /// Requires network access — run with `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn test_convert_real_pdb() {
        // Windows 10 21H2 (build 19044) kernel PDB — commonly available.
        let pdb_name = "ntkrnlmp.pdb";
        let guid = "1C2B4DF7EEE94F2F856C5A6CB3948E31";
        let age = 2u32;

        let pdb_bytes = super::super::symserver::download_pdb(pdb_name, guid, age)
            .expect("Failed to download PDB");

        let isf_json = convert_pdb_to_isf(&pdb_bytes, pdb_name, guid, age)
            .expect("Failed to convert PDB to ISF");

        // Parse the generated ISF.
        let symbols =
            isf::parse_isf_str(&isf_json).expect("Generated ISF failed to parse");

        // Verify critical kernel types exist.
        assert!(
            symbols.get_type("_EPROCESS").is_some(),
            "_EPROCESS missing from converted ISF"
        );
        assert!(
            symbols.get_type("_KPROCESS").is_some(),
            "_KPROCESS missing from converted ISF"
        );
        assert!(
            symbols.get_type("_LIST_ENTRY").is_some(),
            "_LIST_ENTRY missing from converted ISF"
        );
        assert!(
            symbols.get_type("_POOL_HEADER").is_some(),
            "_POOL_HEADER missing from converted ISF"
        );

        // Verify critical kernel symbols exist.
        assert!(
            symbols.get_symbol("PsActiveProcessHead").is_some(),
            "PsActiveProcessHead missing from converted ISF"
        );

        // Verify pointer size.
        assert_eq!(symbols.pointer_size, 8);

        // Verify _EPROCESS has expected fields.
        assert!(
            symbols
                .field_offset("_EPROCESS", "UniqueProcessId")
                .is_some(),
            "UniqueProcessId field missing from _EPROCESS"
        );
        assert!(
            symbols
                .field_offset("_EPROCESS", "ActiveProcessLinks")
                .is_some(),
            "ActiveProcessLinks field missing from _EPROCESS"
        );
        assert!(
            symbols
                .field_offset("_EPROCESS", "ImageFileName")
                .is_some(),
            "ImageFileName field missing from _EPROCESS"
        );
    }
}
