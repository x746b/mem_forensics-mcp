//! Request/response types for MCP tools.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Deserialize an optional u64 that accepts decimal numbers, hex strings ("0x1ad000"),
/// or plain decimal strings ("1234").
fn deserialize_optional_u64_hex<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    let val: Option<serde_json::Value> = Option::deserialize(deserializer)?;
    match val {
        None => Ok(None),
        Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(n)) => n
            .as_u64()
            .map(Some)
            .ok_or_else(|| de::Error::custom("expected unsigned 64-bit integer")),
        Some(serde_json::Value::String(s)) => {
            let s = s.trim();
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u64::from_str_radix(hex, 16)
                    .map(Some)
                    .map_err(de::Error::custom)
            } else {
                s.parse::<u64>().map(Some).map_err(de::Error::custom)
            }
        }
        _ => Err(de::Error::custom("expected number or hex string")),
    }
}

/// Request to analyze a memory image.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeImageRequest {
    /// Path to the memory dump file.
    pub image_path: String,
    /// Optional ISF symbol file path. If not provided, auto-detection is attempted.
    pub isf_path: Option<String>,
    /// Optional DTB (Directory Table Base) override. Accepts decimal or hex ("0x1ad000").
    #[serde(default, deserialize_with = "deserialize_optional_u64_hex")]
    pub dtb: Option<u64>,
    /// Optional kernel base address for symbol relocation. Accepts decimal or hex ("0xf80437a00000").
    #[serde(default, deserialize_with = "deserialize_optional_u64_hex")]
    pub kernel_base: Option<u64>,
}

/// Request to run a plugin.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RunPluginRequest {
    /// Session ID from a previous analyze_image call.
    pub session_id: String,
    /// Plugin name (e.g., "pslist", "psscan", "malfind", "netscan").
    pub plugin: String,
    /// Optional plugin-specific parameters as JSON.
    pub params: Option<serde_json::Value>,
}

/// Request requiring only a session ID.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SessionRequest {
    /// Session ID from a previous analyze_image call.
    pub session_id: String,
}

/// Process information from pslist/psscan.
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct ProcessInfo {
    pub pid: u64,
    pub ppid: u64,
    pub name: String,
    pub offset: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threads: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handles: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wow64: Option<bool>,
}

/// Session info for listing.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct SessionInfo {
    pub session_id: String,
    pub image_path: String,
    pub image_size: u64,
    pub profile: Option<String>,
    pub created_at: String,
}

/// Server status information.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ServerStatus {
    pub version: String,
    pub active_sessions: usize,
    pub available_plugins: Vec<String>,
    pub engine: String,
}

/// An injected code region found by malfind (RWX VAD with content).
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct InjectedRegion {
    /// Process ID owning this region.
    pub pid: u64,
    /// Process name.
    pub process_name: String,
    /// Start virtual address of the VAD region.
    pub vad_start: u64,
    /// End virtual address (inclusive).
    pub vad_end: u64,
    /// Region size in bytes.
    pub region_size: u64,
    /// Protection string (e.g. "PAGE_EXECUTE_READWRITE").
    pub protection: String,
    /// Raw 5-bit protection index.
    pub protection_value: u8,
    /// Whether this is private (committed) memory.
    pub private_memory: bool,
    /// Whether a PE header (MZ) was found at the region start.
    pub has_pe_header: bool,
    /// First 64 bytes as hex string.
    pub hex_preview: String,
    /// Classification tag.
    pub tag: String,
}

/// Plugin info.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct PluginInfo {
    pub name: String,
    pub description: String,
    pub category: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_dtb_string() {
        let json = r#"{"image_path": "/tmp/mem.raw", "dtb": "0x1ad000"}"#;
        let req: AnalyzeImageRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.dtb, Some(0x1ad000));
    }

    #[test]
    fn test_hex_kernel_base_uppercase_prefix() {
        let json = r#"{"image_path": "/tmp/mem.raw", "kernel_base": "0Xf80437a00000"}"#;
        let req: AnalyzeImageRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.kernel_base, Some(0xf80437a00000));
    }

    #[test]
    fn test_decimal_number_dtb() {
        let json = r#"{"image_path": "/tmp/mem.raw", "dtb": 1757184}"#;
        let req: AnalyzeImageRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.dtb, Some(1757184)); // 0x1ad000
    }

    #[test]
    fn test_decimal_string_dtb() {
        let json = r#"{"image_path": "/tmp/mem.raw", "dtb": "1757184"}"#;
        let req: AnalyzeImageRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.dtb, Some(1757184));
    }

    #[test]
    fn test_null_dtb() {
        let json = r#"{"image_path": "/tmp/mem.raw", "dtb": null}"#;
        let req: AnalyzeImageRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.dtb, None);
    }

    #[test]
    fn test_missing_dtb() {
        let json = r#"{"image_path": "/tmp/mem.raw"}"#;
        let req: AnalyzeImageRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.dtb, None);
        assert_eq!(req.kernel_base, None);
    }
}
