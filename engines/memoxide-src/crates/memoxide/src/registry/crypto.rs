//! SAM hash extraction cryptography.
//!
//! Implements the boot key (SysKey) extraction from the SYSTEM hive and
//! the SAM hash decryption pipeline:
//!
//! 1. **Boot key** — derived from 4 class names under `\ControlSet00N\Control\Lsa`
//!    (JD, Skew1, GBG, Data), scrambled with a fixed permutation.
//!
//! 2. **SAM key** — derived from the boot key + the "F" value of
//!    `\SAM\Domains\Account`. Pre-Win10 uses RC4(MD5(...)), Win10+ uses AES-CBC.
//!
//! 3. **User hashes** — each user's "V" value contains encrypted LM/NT hashes.
//!    Decrypted using the SAM key + user RID. Pre-Vista uses DES, Vista+ uses
//!    AES-CBC for the outer layer + DES for the per-RID inner layer.

use super::hive::{HiveReader, RegistryHive};
use isf::MemoryAccess;
use serde::{Deserialize, Serialize};
use tracing::debug;

// ── Boot key extraction ──────────────────────────────────────────────

/// The fixed permutation applied to the raw class-name bytes to produce the boot key.
const BOOT_KEY_PERMUTATION: [usize; 16] = [
    0x08, 0x05, 0x04, 0x02, 0x0B, 0x09, 0x0D, 0x03,
    0x00, 0x06, 0x01, 0x0C, 0x0E, 0x0A, 0x0F, 0x07,
];

/// Lsa subkey names whose class names form the raw boot key material.
const LSA_KEY_NAMES: [&str; 4] = ["JD", "Skew1", "GBG", "Data"];

/// Extract the boot key (SysKey) from the SYSTEM hive.
///
/// The boot key is 16 bytes derived from the class names of four registry keys
/// under `\ControlSet00N\Control\Lsa` (JD, Skew1, GBG, Data).
pub fn extract_boot_key(
    memory: &dyn MemoryAccess,
    system_hive: &RegistryHive,
) -> Result<[u8; 16], String> {
    let reader = HiveReader::new(memory, system_hive);

    // Determine current control set from \Select\Current
    let control_set = get_current_control_set(&reader, system_hive.root_cell_offset)?;
    let lsa_path = format!("ControlSet{:03}\\Control\\Lsa", control_set);

    debug!("boot_key: using {}", lsa_path);

    let lsa_key = reader.open_key(system_hive.root_cell_offset, &lsa_path)?;

    // Read class names from JD, Skew1, GBG, Data subkeys
    let mut raw_key = Vec::with_capacity(16);
    for name in &LSA_KEY_NAMES {
        let subkeys = reader.subkeys(&lsa_key)?;
        let subkey = subkeys
            .iter()
            .find(|k| k.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| format!("Lsa subkey '{}' not found", name))?;

        let class_name = subkey
            .class_name
            .as_ref()
            .ok_or_else(|| format!("Lsa subkey '{}' has no class name", name))?;

        // Class name is hex-encoded bytes (e.g., "a3b4c5d6")
        let decoded = hex_decode(class_name)?;
        raw_key.extend_from_slice(&decoded);
    }

    if raw_key.len() < 16 {
        return Err(format!(
            "boot key material too short: {} bytes (need 16)",
            raw_key.len()
        ));
    }

    // Apply the fixed permutation
    let mut boot_key = [0u8; 16];
    for (i, &perm_idx) in BOOT_KEY_PERMUTATION.iter().enumerate() {
        if perm_idx >= raw_key.len() {
            return Err(format!("permutation index {} out of range", perm_idx));
        }
        boot_key[i] = raw_key[perm_idx];
    }

    debug!("boot_key: extracted successfully");
    Ok(boot_key)
}

/// Determine the current control set from `\Select\Current`.
fn get_current_control_set(
    reader: &HiveReader,
    root_cell_offset: u32,
) -> Result<u32, String> {
    let select_key = reader.open_key(root_cell_offset, "Select")?;
    let current_value = reader.get_value(&select_key, "Current")?;

    if current_value.data.len() < 4 {
        return Err("Select\\Current value too short".into());
    }

    let cs = u32::from_le_bytes(current_value.data[0..4].try_into().unwrap());
    if cs == 0 || cs > 3 {
        return Err(format!("invalid control set number: {}", cs));
    }
    Ok(cs)
}

// ── SAM hash extraction ─────────────────────────────────────────────

/// A user account with extracted hashes.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SamUser {
    pub rid: u32,
    pub username: String,
    /// LM hash as hex string, or "aad3b435b51404eeaad3b435b51404ee" (empty).
    pub lm_hash: String,
    /// NT hash as hex string, or "31d6cfe0d16ae931b73c59d7e0c089c0" (empty).
    pub nt_hash: String,
}

/// Empty LM hash (= no LM hash stored).
const EMPTY_LM: &str = "aad3b435b51404eeaad3b435b51404ee";
/// Empty NT hash (= blank password).
const EMPTY_NT: &str = "31d6cfe0d16ae931b73c59d7e0c089c0";

/// Extract user hashes from the SAM hive using the boot key.
pub fn extract_sam_hashes(
    memory: &dyn MemoryAccess,
    sam_hive: &RegistryHive,
    boot_key: &[u8; 16],
) -> Result<Vec<SamUser>, String> {
    let reader = HiveReader::new(memory, sam_hive);

    // Navigate to SAM\Domains\Account
    let account_key = reader.open_key(sam_hive.root_cell_offset, "SAM\\Domains\\Account")?;

    // Get the "F" value — contains the SAM key material
    let f_value = reader.get_value(&account_key, "F")?;
    if f_value.data.len() < 0x70 {
        return Err(format!("Account\\F value too short: {} bytes", f_value.data.len()));
    }

    // Determine SAM revision and derive the hashed boot key
    let revision = u32::from_le_bytes(f_value.data[0x68..0x6C].try_into().unwrap());
    debug!("sam: F value revision = {}", revision);

    let hashed_boot_key = if revision >= 3 {
        // Win10+ (AES-CBC based)
        derive_hashed_boot_key_aes(&f_value.data, boot_key)?
    } else {
        // Pre-Win10 (RC4+MD5 based)
        derive_hashed_boot_key_rc4(&f_value.data, boot_key)?
    };

    // Navigate to SAM\Domains\Account\Users
    let users_key = reader.open_key(sam_hive.root_cell_offset, "SAM\\Domains\\Account\\Users")?;
    let user_subkeys = reader.subkeys(&users_key)?;

    let mut users = Vec::new();

    for subkey in &user_subkeys {
        // Skip the "Names" subkey
        if subkey.name.eq_ignore_ascii_case("Names") {
            continue;
        }

        // Subkey name is the RID in hex (e.g., "000001F4" for RID 500)
        let rid = match u32::from_str_radix(&subkey.name, 16) {
            Ok(r) => r,
            Err(_) => {
                debug!("sam: skipping non-RID subkey '{}'", subkey.name);
                continue;
            }
        };

        // Read the "V" value
        let v_value = match reader.get_value(subkey, "V") {
            Ok(v) => v,
            Err(e) => {
                debug!("sam: skipping RID {}: {}", rid, e);
                continue;
            }
        };

        match parse_v_value(&v_value.data, rid, &hashed_boot_key, revision) {
            Ok(user) => {
                debug!("sam: extracted user '{}' (RID {})", user.username, rid);
                users.push(user);
            }
            Err(e) => {
                debug!("sam: failed to parse V for RID {}: {}", rid, e);
            }
        }
    }

    // Sort by RID
    users.sort_by_key(|u| u.rid);
    Ok(users)
}

// ── SAM key derivation ──────────────────────────────────────────────

/// Derive the hashed boot key using RC4+MD5 (pre-Win10).
fn derive_hashed_boot_key_rc4(f_data: &[u8], boot_key: &[u8; 16]) -> Result<Vec<u8>, String> {
    use md5::Digest;

    // RC4 key = MD5(F[0x70..0x80] + AQWERTY + boot_key + ANUM)
    let salt = &f_data[0x70..0x80];
    let aqwerty = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0";
    let anum = b"0123456789012345678901234567890123456789\0";

    let mut md5_hasher = md5::Md5::new();
    md5_hasher.update(salt);
    md5_hasher.update(aqwerty);
    md5_hasher.update(boot_key);
    md5_hasher.update(anum);
    let rc4_key = md5_hasher.finalize();

    // Decrypt F[0x80..0xA0] with RC4
    let encrypted = &f_data[0x80..0xA0];
    let decrypted = rc4_crypt(&rc4_key, encrypted);

    Ok(decrypted)
}

/// Derive the hashed boot key using AES-CBC (Win10+).
fn derive_hashed_boot_key_aes(f_data: &[u8], boot_key: &[u8; 16]) -> Result<Vec<u8>, String> {
    // F[0x70..0x80] = IV (16 bytes)
    // F[0x80..0xA0] = encrypted hashed boot key (32 bytes, but we need first 16)
    if f_data.len() < 0xA0 {
        return Err("F value too short for AES decryption".into());
    }

    let iv = &f_data[0x70..0x80];
    let encrypted = &f_data[0x80..0xA0];

    let decrypted = aes_cbc_decrypt(boot_key, iv, encrypted)?;
    // Take first 16 bytes
    Ok(decrypted[..16.min(decrypted.len())].to_vec())
}

// ── V value parsing ─────────────────────────────────────────────────

/// Parse the SAM "V" value to extract username and hashes.
///
/// The V value has a structured header with offset/length pairs for various
/// fields, followed by the actual data.
fn parse_v_value(
    v_data: &[u8],
    rid: u32,
    hashed_boot_key: &[u8],
    sam_revision: u32,
) -> Result<SamUser, String> {
    if v_data.len() < 0xCC + 4 {
        return Err(format!("V value too short: {} bytes", v_data.len()));
    }

    // V value header: series of offset+length+unknown triples (each 12 bytes)
    // Username is at index 0: offset at V[0x0C], length at V[0x10]
    // LM hash is at index 6: offset at V[0x9C], length at V[0xA0]
    // NT hash is at index 7: offset at V[0xA8], length at V[0xAC]
    // All offsets are relative to 0xCC

    let user_offset = u32::from_le_bytes(v_data[0x0C..0x10].try_into().unwrap()) as usize + 0xCC;
    let user_length = u32::from_le_bytes(v_data[0x10..0x14].try_into().unwrap()) as usize;

    let username = if user_offset + user_length <= v_data.len() && user_length > 0 {
        let name_bytes = &v_data[user_offset..user_offset + user_length];
        read_utf16le_string(name_bytes)
    } else {
        format!("User_{}", rid)
    };

    // LM hash
    let lm_offset = u32::from_le_bytes(v_data[0x9C..0xA0].try_into().unwrap()) as usize + 0xCC;
    let lm_length = u32::from_le_bytes(v_data[0xA0..0xA4].try_into().unwrap()) as usize;

    let lm_hash = if lm_length >= 20 && lm_offset + lm_length <= v_data.len() {
        let enc_lm = &v_data[lm_offset..lm_offset + lm_length];
        decrypt_hash(enc_lm, hashed_boot_key, rid, sam_revision, false)
            .unwrap_or_else(|_| EMPTY_LM.to_string())
    } else {
        EMPTY_LM.to_string()
    };

    // NT hash
    let nt_offset = u32::from_le_bytes(v_data[0xA8..0xAC].try_into().unwrap()) as usize + 0xCC;
    let nt_length = u32::from_le_bytes(v_data[0xAC..0xB0].try_into().unwrap()) as usize;

    let nt_hash = if nt_length >= 20 && nt_offset + nt_length <= v_data.len() {
        let enc_nt = &v_data[nt_offset..nt_offset + nt_length];
        decrypt_hash(enc_nt, hashed_boot_key, rid, sam_revision, true)
            .unwrap_or_else(|_| EMPTY_NT.to_string())
    } else {
        EMPTY_NT.to_string()
    };

    Ok(SamUser {
        rid,
        username,
        lm_hash,
        nt_hash,
    })
}

// ── Hash decryption ─────────────────────────────────────────────────

/// Decrypt a single LM or NT hash from the encrypted blob.
fn decrypt_hash(
    encrypted: &[u8],
    hashed_boot_key: &[u8],
    rid: u32,
    sam_revision: u32,
    is_nt: bool,
) -> Result<String, String> {
    if sam_revision >= 3 {
        decrypt_hash_aes(encrypted, hashed_boot_key, rid, is_nt)
    } else {
        decrypt_hash_rc4(encrypted, hashed_boot_key, rid, is_nt)
    }
}

/// Pre-Win10 hash decryption (RC4 outer + DES inner).
fn decrypt_hash_rc4(
    encrypted: &[u8],
    hashed_boot_key: &[u8],
    rid: u32,
    is_nt: bool,
) -> Result<String, String> {
    use md5::Digest;

    // encrypted layout: 4 bytes PEK_ID + 16 bytes = 20 bytes minimum
    if encrypted.len() < 20 {
        return Err("encrypted hash too short for RC4".into());
    }

    let enc_hash = &encrypted[4..20]; // 16 bytes of RC4-encrypted hash

    // RC4 key = MD5(hashed_boot_key + RID_bytes + constant)
    let nt_constant = b"NTPASSWORD\0";
    let lm_constant = b"LMPASSWORD\0";
    let constant = if is_nt { &nt_constant[..] } else { &lm_constant[..] };

    let rid_bytes = rid.to_le_bytes();

    let mut md5_hasher = md5::Md5::new();
    md5_hasher.update(hashed_boot_key);
    md5_hasher.update(&rid_bytes);
    md5_hasher.update(constant);
    let rc4_key = md5_hasher.finalize();

    let des_encrypted = rc4_crypt(&rc4_key, enc_hash);

    // DES inner decryption with RID-derived keys
    let hash = des_decrypt_with_rid(&des_encrypted, rid)?;
    Ok(hex_encode(&hash))
}

/// Win10+ hash decryption (AES-CBC outer + DES inner).
fn decrypt_hash_aes(
    encrypted: &[u8],
    hashed_boot_key: &[u8],
    rid: u32,
    _is_nt: bool,
) -> Result<String, String> {
    // encrypted layout for AES:
    //   [0..2]  = revision (u16)
    //   [2..4]  = unknown
    //   [4..8]  = PEK ID (u32)
    //   [8..24] = IV (16 bytes)
    //   [24..]  = AES-CBC encrypted data (16 bytes of hash, padded to 32)

    if encrypted.len() < 40 {
        return Err("encrypted hash too short for AES".into());
    }

    let iv = &encrypted[8..24];
    let enc_data = &encrypted[24..];

    if hashed_boot_key.len() < 16 {
        return Err("hashed boot key too short".into());
    }

    let decrypted = aes_cbc_decrypt(&hashed_boot_key[..16], iv, enc_data)?;

    if decrypted.len() < 16 {
        return Err("AES decrypted data too short".into());
    }

    // The first 16 bytes are the DES-encrypted hash
    let des_encrypted = &decrypted[..16];

    // DES inner decryption with RID-derived keys
    let hash = des_decrypt_with_rid(des_encrypted, rid)?;
    Ok(hex_encode(&hash))
}

/// DES decrypt with two RID-derived 7-byte keys (the "SID-to-key" transform).
///
/// The 16-byte hash is split into two 8-byte halves, each decrypted with
/// a DES key derived from the RID.
fn des_decrypt_with_rid(encrypted: &[u8], rid: u32) -> Result<Vec<u8>, String> {
    if encrypted.len() < 16 {
        return Err("need 16 bytes for DES decryption".into());
    }

    let (key1, key2) = sid_to_des_keys(rid);

    let mut result = Vec::with_capacity(16);
    result.extend_from_slice(&des_ecb_decrypt(&key1, &encrypted[0..8])?);
    result.extend_from_slice(&des_ecb_decrypt(&key2, &encrypted[8..16])?);

    Ok(result)
}

/// Convert a RID to two DES keys using the standard SID-to-key algorithm.
///
/// Takes the 4 bytes of the RID and derives two 7-byte values that are then
/// expanded to 8-byte DES keys with parity bits.
fn sid_to_des_keys(rid: u32) -> ([u8; 8], [u8; 8]) {
    let s = rid.to_le_bytes();

    let key1_7 = [s[0], s[1], s[2], s[3], s[0], s[1], s[2]];
    let key2_7 = [s[3], s[0], s[1], s[2], s[3], s[0], s[1]];

    (expand_des_key(&key1_7), expand_des_key(&key2_7))
}

/// Expand a 7-byte value to an 8-byte DES key by inserting parity bits.
fn expand_des_key(input: &[u8; 7]) -> [u8; 8] {
    [
        input[0] >> 1,
        ((input[0] & 0x01) << 6) | (input[1] >> 2),
        ((input[1] & 0x03) << 5) | (input[2] >> 3),
        ((input[2] & 0x07) << 4) | (input[3] >> 4),
        ((input[3] & 0x0F) << 3) | (input[4] >> 5),
        ((input[4] & 0x1F) << 2) | (input[5] >> 6),
        ((input[5] & 0x3F) << 1) | (input[6] >> 7),
        (input[6] & 0x7F) << 1,
    ]
}

// ── Crypto primitives ────────────────────────────────────────────────

/// RC4 encrypt/decrypt (symmetric).
fn rc4_crypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    // Manual RC4 implementation (the `rc4` crate API is awkward)
    let mut s: Vec<u8> = (0..=255u8).collect();
    let mut j: u8 = 0;

    // KSA (Key Scheduling Algorithm)
    for i in 0..256usize {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }

    // PRGA (Pseudo-Random Generation Algorithm)
    let mut i: u8 = 0;
    j = 0;
    let mut output = vec![0u8; data.len()];
    for (idx, &byte) in data.iter().enumerate() {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
        output[idx] = byte ^ k;
    }

    output
}

/// AES-128-CBC decrypt with no padding removal (caller handles).
fn aes_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    use aes::cipher::{BlockDecryptMut, KeyIvInit};

    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

    if key.len() != 16 {
        return Err(format!("AES key must be 16 bytes, got {}", key.len()));
    }
    if iv.len() != 16 {
        return Err(format!("AES IV must be 16 bytes, got {}", iv.len()));
    }
    if data.is_empty() || data.len() % 16 != 0 {
        return Err(format!(
            "AES data must be non-empty and multiple of 16, got {}",
            data.len()
        ));
    }

    let mut buf = data.to_vec();
    let decryptor = Aes128CbcDec::new_from_slices(key, iv)
        .map_err(|e| format!("AES init error: {}", e))?;
    decryptor
        .decrypt_padded_mut::<aes::cipher::block_padding::NoPadding>(&mut buf)
        .map_err(|e| format!("AES decrypt error: {}", e))?;

    Ok(buf)
}

/// Single-block DES-ECB decrypt.
fn des_ecb_decrypt(key: &[u8; 8], block: &[u8]) -> Result<Vec<u8>, String> {
    use des::cipher::{BlockDecrypt, KeyInit};

    if block.len() != 8 {
        return Err(format!("DES block must be 8 bytes, got {}", block.len()));
    }

    let cipher = des::Des::new_from_slice(key)
        .map_err(|e| format!("DES key error: {}", e))?;

    let mut out = des::cipher::generic_array::GenericArray::clone_from_slice(block);
    cipher.decrypt_block(&mut out);

    Ok(out.to_vec())
}

// ── Hex helpers ──────────────────────────────────────────────────────

/// Decode a hex string to bytes.
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(format!("hex string has odd length: {}", s.len()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("hex decode error at {}: {}", i, e))
        })
        .collect()
}

/// Encode bytes as lowercase hex string.
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decode a UTF-16LE string (shared with hive.rs).
fn read_utf16le_string(data: &[u8]) -> String {
    let chars: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&c| c != 0)
        .collect();
    String::from_utf16_lossy(&chars)
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_des_key() {
        let input: [u8; 7] = [0xF4, 0x01, 0x00, 0x00, 0xF4, 0x01, 0x00];
        let expanded = expand_des_key(&input);
        // Just verify it produces 8 bytes and doesn't panic
        assert_eq!(expanded.len(), 8);
    }

    #[test]
    fn test_sid_to_des_keys() {
        // RID 500 = 0x000001F4
        let (k1, k2) = sid_to_des_keys(500);
        assert_eq!(k1.len(), 8);
        assert_eq!(k2.len(), 8);
        // Keys should be different
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_rc4_roundtrip() {
        let key = b"test_key_12345";
        let plaintext = b"Hello, World!";
        let encrypted = rc4_crypt(key, plaintext);
        let decrypted = rc4_crypt(key, &encrypted);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_hex_encode_decode() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let hex = hex_encode(&data);
        assert_eq!(hex, "deadbeef");
        let decoded = hex_decode(&hex).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_hex_decode_error() {
        assert!(hex_decode("xyz").is_err());
        assert!(hex_decode("0").is_err()); // odd length
    }

    #[test]
    fn test_aes_cbc_decrypt() {
        // Test with known values: encrypt then decrypt should roundtrip
        use aes::cipher::{BlockEncryptMut, KeyIvInit};
        type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

        let key = [0u8; 16];
        let iv = [0u8; 16];
        let plaintext = [0x41u8; 16]; // "AAAA..."

        let mut buf = plaintext.to_vec();
        let encryptor = Aes128CbcEnc::new_from_slices(&key, &iv).unwrap();
        encryptor
            .encrypt_padded_mut::<aes::cipher::block_padding::NoPadding>(&mut buf, 16)
            .unwrap();

        let decrypted = aes_cbc_decrypt(&key, &iv, &buf).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_des_ecb_decrypt() {
        // Just verify it doesn't panic with a valid key/block
        let key = [0u8; 8];
        let block = [0u8; 8];
        let result = des_ecb_decrypt(&key, &block);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 8);
    }

    #[test]
    fn test_boot_key_permutation_valid() {
        // Verify all indices in the permutation are valid (0..15)
        for &idx in &BOOT_KEY_PERMUTATION {
            assert!(idx < 16, "permutation index {} out of range", idx);
        }
        // Verify it's a real permutation (all indices 0..15 present)
        let mut seen = [false; 16];
        for &idx in &BOOT_KEY_PERMUTATION {
            seen[idx] = true;
        }
        assert!(seen.iter().all(|&s| s), "permutation is not a complete bijection");
    }
}
