//! ISF file parser — handles both plain JSON and .json.xz compressed files.

use crate::error::{IsfError, IsfResult};
use crate::types::{IsfFile, IsfSymbols};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use xz2::read::XzDecoder;

/// Parse an ISF file from a filesystem path.
///
/// Automatically detects compression:
/// - `.json.xz` or `.xz` → LZMA decompression then JSON parse
/// - `.json` or anything else → direct JSON parse
pub fn parse_isf_file(path: impl AsRef<Path>) -> IsfResult<IsfSymbols> {
    let path = path.as_ref();

    if !path.exists() {
        return Err(IsfError::FileNotFound(path.display().to_string()));
    }

    let path_str = path.to_string_lossy().to_lowercase();
    let json_bytes = if path_str.ends_with(".xz") {
        // Decompress XZ/LZMA first
        let file = File::open(path)
            .map_err(|e| IsfError::Io(format!("opening {}: {}", path.display(), e)))?;
        let reader = BufReader::new(file);
        let mut decoder = XzDecoder::new(reader);
        let mut buf = Vec::new();
        decoder
            .read_to_end(&mut buf)
            .map_err(|e| IsfError::Decompression(format!("{}: {}", path.display(), e)))?;
        buf
    } else {
        // Plain JSON
        let file = File::open(path)
            .map_err(|e| IsfError::Io(format!("opening {}: {}", path.display(), e)))?;
        let mut reader = BufReader::new(file);
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .map_err(|e| IsfError::Io(format!("reading {}: {}", path.display(), e)))?;
        buf
    };

    parse_isf_bytes(&json_bytes)
}

/// Parse ISF from raw JSON bytes (already decompressed).
pub fn parse_isf_bytes(json_bytes: &[u8]) -> IsfResult<IsfSymbols> {
    let isf_file: IsfFile = serde_json::from_slice(json_bytes)
        .map_err(|e| IsfError::JsonParse(format!("{}", e)))?;

    convert_to_symbols(isf_file)
}

/// Parse ISF from a JSON string.
pub fn parse_isf_str(json_str: &str) -> IsfResult<IsfSymbols> {
    let isf_file: IsfFile = serde_json::from_str(json_str)
        .map_err(|e| IsfError::JsonParse(format!("{}", e)))?;

    convert_to_symbols(isf_file)
}

/// Convert a parsed IsfFile into a resolved IsfSymbols.
fn convert_to_symbols(isf_file: IsfFile) -> IsfResult<IsfSymbols> {
    // Determine pointer size from base_types
    let pointer_size = isf_file
        .base_types
        .get("pointer")
        .map(|bt| bt.size)
        .unwrap_or(8); // default to 64-bit

    Ok(IsfSymbols {
        base_types: isf_file.base_types,
        user_types: isf_file.user_types,
        symbols: isf_file.symbols,
        enums: isf_file.enums,
        metadata: isf_file.metadata,
        pointer_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_ISF: &str = r#"{
        "metadata": { "format": "6.2.0" },
        "base_types": {
            "pointer": { "size": 8, "signed": false, "kind": "int", "endian": "little" },
            "unsigned long": { "size": 4, "signed": false, "kind": "int", "endian": "little" },
            "unsigned long long": { "size": 8, "signed": false, "kind": "int", "endian": "little" },
            "unsigned short": { "size": 2, "signed": false, "kind": "int", "endian": "little" }
        },
        "user_types": {
            "_LIST_ENTRY": {
                "size": 16,
                "fields": {
                    "Flink": { "offset": 0, "type": { "kind": "pointer", "subtype": { "kind": "struct", "name": "_LIST_ENTRY" } } },
                    "Blink": { "offset": 8, "type": { "kind": "pointer", "subtype": { "kind": "struct", "name": "_LIST_ENTRY" } } }
                }
            },
            "_EPROCESS": {
                "size": 2096,
                "fields": {
                    "UniqueProcessId": { "offset": 440, "type": { "kind": "pointer" } },
                    "ActiveProcessLinks": { "offset": 448, "type": { "kind": "struct", "name": "_LIST_ENTRY" } },
                    "ImageFileName": { "offset": 736, "type": { "kind": "array", "count": 15, "subtype": { "kind": "base", "name": "unsigned char" } } }
                }
            }
        },
        "symbols": {
            "PsActiveProcessHead": { "address": 11501904 },
            "KiInitialProcess": { "address": 11530400 }
        },
        "enums": {}
    }"#;

    #[test]
    fn test_parse_minimal_isf() {
        let symbols = parse_isf_str(MINIMAL_ISF).unwrap();

        assert_eq!(symbols.pointer_size, 8);
        assert_eq!(symbols.metadata.format, "6.2.0");

        // Check _EPROCESS
        let eprocess = symbols.get_type("_EPROCESS").unwrap();
        assert_eq!(eprocess.size, 2096);

        let pid_field = eprocess.fields.get("UniqueProcessId").unwrap();
        assert_eq!(pid_field.offset, 440);
        assert_eq!(pid_field.type_info.kind, "pointer");

        let links_field = eprocess.fields.get("ActiveProcessLinks").unwrap();
        assert_eq!(links_field.offset, 448);
        assert_eq!(links_field.type_info.kind, "struct");
        assert_eq!(links_field.type_info.name.as_deref(), Some("_LIST_ENTRY"));

        // Check symbols
        assert_eq!(symbols.get_symbol("PsActiveProcessHead"), Some(11501904));
        assert_eq!(symbols.get_symbol("KiInitialProcess"), Some(11530400));
        assert_eq!(symbols.get_symbol("NonExistent"), None);

        // Check field_offset helper
        assert_eq!(symbols.field_offset("_EPROCESS", "UniqueProcessId"), Some(440));
        assert_eq!(symbols.field_offset("_EPROCESS", "ActiveProcessLinks"), Some(448));
        assert_eq!(symbols.field_offset("_EPROCESS", "NonExistent"), None);

        // Check type_size
        assert_eq!(symbols.type_size("_EPROCESS"), Some(2096));
        assert_eq!(symbols.type_size("_LIST_ENTRY"), Some(16));
        assert_eq!(symbols.type_size("unsigned long"), Some(4));
    }

    #[test]
    fn test_parse_with_enums() {
        let json = r#"{
            "metadata": { "format": "6.2.0" },
            "base_types": {
                "pointer": { "size": 4, "signed": false, "kind": "int" }
            },
            "user_types": {},
            "symbols": {},
            "enums": {
                "_POOL_TYPE": {
                    "size": 4,
                    "base": "unsigned int",
                    "constants": {
                        "NonPagedPool": 0,
                        "PagedPool": 1,
                        "NonPagedPoolMustSucceed": 2
                    }
                }
            }
        }"#;

        let symbols = parse_isf_str(json).unwrap();
        assert_eq!(symbols.pointer_size, 4); // 32-bit
        assert_eq!(symbols.enum_value("_POOL_TYPE", "NonPagedPool"), Some(0));
        assert_eq!(symbols.enum_value("_POOL_TYPE", "PagedPool"), Some(1));
        assert_eq!(symbols.enum_name("_POOL_TYPE", 2), Some("NonPagedPoolMustSucceed"));
    }

    #[test]
    fn test_resolve_type_size() {
        let symbols = parse_isf_str(MINIMAL_ISF).unwrap();

        // Pointer type
        let ptr_info = crate::types::TypeInfo {
            kind: "pointer".to_string(),
            name: None,
            subtype: None,
            count: None,
            bit_position: None,
            bit_length: None,
            enum_name: None,
            element_type: None,
            size: None,
        };
        assert_eq!(symbols.resolve_type_size(&ptr_info), Some(8));

        // Struct type
        let struct_info = crate::types::TypeInfo {
            kind: "struct".to_string(),
            name: Some("_LIST_ENTRY".to_string()),
            subtype: None,
            count: None,
            bit_position: None,
            bit_length: None,
            enum_name: None,
            element_type: None,
            size: None,
        };
        assert_eq!(symbols.resolve_type_size(&struct_info), Some(16));
    }

    #[test]
    fn test_parse_real_kdbg_file() {
        let path = "/opt/volatility3/volatility3/framework/symbols/windows/kdbg.json";
        if !std::path::Path::new(path).exists() {
            eprintln!("Skipping test: kdbg.json not found at {}", path);
            return;
        }

        let symbols = parse_isf_file(path).unwrap();
        assert_eq!(symbols.metadata.format, "4.1.0");

        // Check known KDBG types exist
        let kdbg = symbols.get_type("_KDDEBUGGER_DATA64").unwrap();
        assert!(kdbg.size > 0);
        assert!(kdbg.fields.contains_key("PsActiveProcessHead"));

        let header = symbols.get_type("_DBGKD_DEBUG_DATA_HEADER64").unwrap();
        assert_eq!(header.size, 24);
        assert!(header.fields.contains_key("OwnerTag"));
    }

    #[test]
    fn test_parse_real_netscan_file() {
        let path = "/opt/volatility3/volatility3/framework/symbols/windows/netscan/netscan-win10-19041-x64.json";
        if !std::path::Path::new(path).exists() {
            eprintln!("Skipping test: netscan file not found");
            return;
        }

        let symbols = parse_isf_file(path).unwrap();
        assert_eq!(symbols.pointer_size, 8); // x64

        // Check known network types
        let tcp_endpoint = symbols.get_type("_TCP_ENDPOINT");
        assert!(tcp_endpoint.is_some());

        let udp_endpoint = symbols.get_type("_UDP_ENDPOINT").unwrap();
        assert!(udp_endpoint.fields.contains_key("Owner"));
        assert!(udp_endpoint.fields.contains_key("Port"));
    }

    #[test]
    fn test_parse_file_not_found() {
        let result = parse_isf_file("/nonexistent/path.json");
        assert!(result.is_err());
        match result.unwrap_err() {
            IsfError::FileNotFound(path) => assert!(path.contains("nonexistent")),
            other => panic!("Expected FileNotFound, got: {:?}", other),
        }
    }
}
