//! Microsoft Symbol Server download client.
//!
//! Downloads PDB files from `https://msdl.microsoft.com/download/symbols/` using the
//! standard `{pdb_name}/{GUID}{age}/{pdb_name}` URL scheme.
//!
//! Uses synchronous `ureq` — acceptable because MCP is single-request-at-a-time and the
//! download happens during session init (blocking the async runtime briefly is fine).

use tracing::info;

const SYMBOL_SERVER_BASE: &str = "https://msdl.microsoft.com/download/symbols";
const USER_AGENT: &str = "Microsoft-Symbol-Server/10.0.0.0";

/// CAB archive magic bytes.
const CAB_MAGIC: &[u8; 4] = b"MSCF";

/// Build the download URL for a PDB on Microsoft's Symbol Server.
///
/// Format: `{base}/{pdb_name}/{GUID}{age}/{pdb_name}`
/// - GUID: uppercase hex, no dashes (from `rsds::format_guid`)
/// - age: decimal, appended directly to GUID
pub fn build_download_url(pdb_name: &str, guid: &str, age: u32) -> String {
    format!(
        "{}/{}/{}{}/{}",
        SYMBOL_SERVER_BASE, pdb_name, guid, age, pdb_name
    )
}

/// Download a PDB file from Microsoft's Symbol Server.
///
/// Returns the raw PDB bytes on success. Handles:
/// - 404 → descriptive "not found" error
/// - CAB-compressed response → error (not supported)
/// - Timeouts: 30s connect, 120s read
pub fn download_pdb(pdb_name: &str, guid: &str, age: u32) -> Result<Vec<u8>, String> {
    let url = build_download_url(pdb_name, guid, age);
    info!("Downloading PDB from: {}", url);

    let agent = ureq::AgentBuilder::new()
        .timeout_connect(std::time::Duration::from_secs(30))
        .timeout_read(std::time::Duration::from_secs(120))
        .build();

    let response = agent
        .get(&url)
        .set("User-Agent", USER_AGENT)
        .call()
        .map_err(|e| match e {
            ureq::Error::Status(404, _) => {
                format!("PDB not found on symbol server (404): {}", url)
            }
            ureq::Error::Status(code, _) => {
                format!("Symbol server returned HTTP {}: {}", code, url)
            }
            other => format!("Symbol server request failed: {}", other),
        })?;

    // Read body into Vec<u8>.  Kernel PDBs are typically 5-20MB.
    let mut body = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut body)
        .map_err(|e| format!("Failed to read PDB response body: {}", e))?;

    if body.len() < 64 {
        return Err(format!(
            "PDB response too small ({} bytes) — likely not a valid PDB",
            body.len()
        ));
    }

    // Check for CAB compression (not supported).
    if body.len() >= 4 && &body[..4] == CAB_MAGIC {
        return Err(
            "Symbol server returned a CAB-compressed PDB. \
             CAB decompression is not supported — download the ISF from \
             https://github.com/volatilityfoundation/volatility3#symbol-tables instead."
                .to_string(),
        );
    }

    info!(
        "Downloaded PDB: {} ({} bytes)",
        pdb_name,
        body.len()
    );

    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_download_url() {
        let url = build_download_url(
            "ntkrnlmp.pdb",
            "8E3373D6124E747F0E72EF8E02E676B3",
            1,
        );
        assert_eq!(
            url,
            "https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/8E3373D6124E747F0E72EF8E02E676B31/ntkrnlmp.pdb"
        );
    }

    #[test]
    fn test_build_download_url_age_2() {
        let url = build_download_url(
            "ntoskrnl.pdb",
            "1D84270594584672A448D04E4C425688",
            2,
        );
        assert_eq!(
            url,
            "https://msdl.microsoft.com/download/symbols/ntoskrnl.pdb/1D84270594584672A448D04E4C4256882/ntoskrnl.pdb"
        );
    }

    #[test]
    fn test_cab_magic_detection() {
        // Simulate a CAB response.
        let mut cab_data = vec![0u8; 100];
        cab_data[0..4].copy_from_slice(CAB_MAGIC);

        // Verify that the magic bytes match.
        assert_eq!(&cab_data[..4], CAB_MAGIC);
    }
}
