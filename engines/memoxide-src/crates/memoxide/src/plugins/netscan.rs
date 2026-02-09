//! NetScan plugin — scan physical memory for network connections.
//!
//! Scans for pool tags `TcpL` (_TCP_LISTENER), `TcpE` (_TCP_ENDPOINT),
//! and `UdpA` (_UDP_ENDPOINT) in physical memory, then parses the
//! surrounding structures to extract connection details.
//!
//! Requires kernel virtual memory for full results (PID, IP addresses).
//! Without kernel VM, only ports, state, and protocol are available.

use crate::memory::image::MemoryImage;
use isf::{IsfSymbols, MemoryAccess};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use tracing::debug;

// ── Pool tags ──────────────────────────────────────────────────────

const POOL_TAG_TCPL: &[u8] = b"TcpL";
const POOL_TAG_TCPE: &[u8] = b"TcpE";
const POOL_TAG_UDPA: &[u8] = b"UdpA";

/// Tag offset within _POOL_HEADER (PoolTag field is at offset 4).
const TAG_OFFSET_IN_HEADER: usize = 4;

// ── TCP state enum ─────────────────────────────────────────────────

fn tcp_state_name(state: u32) -> &'static str {
    match state {
        0 => "CLOSED",
        1 => "LISTENING",
        2 => "SYN_SENT",
        3 => "SYN_RCVD",
        4 => "ESTABLISHED",
        5 => "FIN_WAIT1",
        6 => "FIN_WAIT2",
        7 => "CLOSE_WAIT",
        8 => "CLOSING",
        9 => "LAST_ACK",
        12 => "TIME_WAIT",
        13 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

// ── Hardcoded offsets for common Windows versions ──────────────────

/// Field offsets for network structures.
/// Populated from ISF or hardcoded for known Windows versions.
#[derive(Debug, Clone)]
pub struct NetscanOffsets {
    pub pointer_size: usize,
    pub pool_header_size: usize,

    // _TCP_LISTENER
    pub tcpl_inetaf: usize,
    pub tcpl_owner: usize,
    pub tcpl_create_time: usize,
    #[allow(dead_code)]
    pub tcpl_local_addr: usize,
    pub tcpl_port: usize,

    // _TCP_ENDPOINT
    pub tcpe_inetaf: usize,
    pub tcpe_addr_info: usize,
    pub tcpe_state: usize,
    pub tcpe_local_port: usize,
    pub tcpe_remote_port: usize,
    pub tcpe_owner: usize,
    pub tcpe_create_time: usize,

    // _UDP_ENDPOINT
    pub udpa_inetaf: usize,
    pub udpa_owner: usize,
    pub udpa_create_time: usize,
    pub udpa_port: usize,

    // _INETAF
    pub inetaf_address_family: usize,

    // _ADDRINFO
    pub addrinfo_local: usize,
    pub addrinfo_remote: usize,

    // _LOCAL_ADDRESS
    pub local_addr_pdata: usize,
}

impl NetscanOffsets {
    /// Default offsets for Windows 10 build 19041 (x64).
    pub fn win10_19041_x64() -> Self {
        NetscanOffsets {
            pointer_size: 8,
            pool_header_size: 16,
            tcpl_inetaf: 40,
            tcpl_owner: 48,
            tcpl_create_time: 64,
            tcpl_local_addr: 96,
            tcpl_port: 114,
            tcpe_inetaf: 16,
            tcpe_addr_info: 24,
            tcpe_state: 108,
            tcpe_local_port: 112,
            tcpe_remote_port: 114,
            tcpe_owner: 728,
            tcpe_create_time: 744,
            udpa_inetaf: 32,
            udpa_owner: 40,
            udpa_create_time: 88,
            udpa_port: 160,
            inetaf_address_family: 24,
            addrinfo_local: 0,
            addrinfo_remote: 16,
            local_addr_pdata: 16,
        }
    }

    /// Default offsets for Windows 7 (x64).
    pub fn win7_x64() -> Self {
        NetscanOffsets {
            pointer_size: 8,
            pool_header_size: 16,
            tcpl_inetaf: 34,
            tcpl_owner: 40,
            tcpl_create_time: 56,
            tcpl_local_addr: 88,
            tcpl_port: 106,
            tcpe_inetaf: 16,
            tcpe_addr_info: 24,
            tcpe_state: 104,
            tcpe_local_port: 108,
            tcpe_remote_port: 110,
            tcpe_owner: 368,
            tcpe_create_time: 384,
            udpa_inetaf: 24,
            udpa_owner: 32,
            udpa_create_time: 80,
            udpa_port: 128,
            inetaf_address_family: 20,
            addrinfo_local: 0,
            addrinfo_remote: 16,
            local_addr_pdata: 16,
        }
    }

    /// Try to construct offsets from a netscan ISF symbol file.
    pub fn from_isf(symbols: &IsfSymbols) -> Option<Self> {
        Some(NetscanOffsets {
            pointer_size: symbols.pointer_size,
            pool_header_size: symbols
                .type_size("_POOL_HEADER")
                .unwrap_or(if symbols.pointer_size == 8 { 16 } else { 8 }),
            tcpl_inetaf: symbols.field_offset("_TCP_LISTENER", "InetAF")?,
            tcpl_owner: symbols.field_offset("_TCP_LISTENER", "Owner")?,
            tcpl_create_time: symbols.field_offset("_TCP_LISTENER", "CreateTime")?,
            tcpl_local_addr: symbols.field_offset("_TCP_LISTENER", "LocalAddr")?,
            tcpl_port: symbols.field_offset("_TCP_LISTENER", "Port")?,
            tcpe_inetaf: symbols.field_offset("_TCP_ENDPOINT", "InetAF")?,
            tcpe_addr_info: symbols.field_offset("_TCP_ENDPOINT", "AddrInfo")?,
            tcpe_state: symbols.field_offset("_TCP_ENDPOINT", "State")?,
            tcpe_local_port: symbols.field_offset("_TCP_ENDPOINT", "LocalPort")?,
            tcpe_remote_port: symbols.field_offset("_TCP_ENDPOINT", "RemotePort")?,
            tcpe_owner: symbols.field_offset("_TCP_ENDPOINT", "Owner")?,
            tcpe_create_time: symbols.field_offset("_TCP_ENDPOINT", "CreateTime")?,
            udpa_inetaf: symbols.field_offset("_UDP_ENDPOINT", "InetAF")?,
            udpa_owner: symbols.field_offset("_UDP_ENDPOINT", "Owner")?,
            udpa_create_time: symbols.field_offset("_UDP_ENDPOINT", "CreateTime")?,
            udpa_port: symbols.field_offset("_UDP_ENDPOINT", "Port")?,
            inetaf_address_family: symbols.field_offset("_INETAF", "AddressFamily")?,
            addrinfo_local: symbols.field_offset("_ADDRINFO", "Local")?,
            addrinfo_remote: symbols.field_offset("_ADDRINFO", "Remote")?,
            local_addr_pdata: symbols.field_offset("_LOCAL_ADDRESS", "pData")?,
        })
    }
}

// ── Output types ───────────────────────────────────────────────────

/// A single network connection found in memory.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkConnection {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    pub pid: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    pub offset: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_family: Option<String>,
}

/// Full netscan results.
#[derive(Debug, Serialize, Deserialize)]
pub struct NetscanResult {
    pub tcp_listeners: usize,
    pub tcp_endpoints: usize,
    pub udp_endpoints: usize,
    pub total: usize,
    pub connections: Vec<NetworkConnection>,
}

// ── Main scan function ─────────────────────────────────────────────

/// Scan physical memory for network connections.
///
/// # Arguments
/// * `kernel_symbols` - Kernel ISF symbols (for reading _EPROCESS PID)
/// * `image` - Physical memory image
/// * `kernel_vm` - Optional kernel virtual memory (for PID + IP resolution)
/// * `offsets` - Struct offsets (from ISF or hardcoded)
/// * `chunk_size` - Scan chunk size
pub fn run(
    kernel_symbols: &IsfSymbols,
    image: &MemoryImage,
    kernel_vm: Option<&dyn MemoryAccess>,
    offsets: &NetscanOffsets,
    chunk_size: usize,
) -> Result<NetscanResult, String> {
    let image_size = image.size();
    let ptr_size = offsets.pointer_size;

    debug!(
        "netscan: scanning {} bytes, pool_header={}, ptr_size={}",
        image_size, offsets.pool_header_size, ptr_size
    );

    let mut connections = Vec::new();
    let mut seen_offsets = HashSet::new();
    let overlap = 256;

    let mut offset: u64 = 0;
    while offset < image_size {
        let read_len = std::cmp::min(chunk_size + overlap, (image_size - offset) as usize);
        let chunk = match image.read(offset, read_len) {
            Ok(c) => c,
            Err(_) => {
                offset += chunk_size as u64;
                continue;
            }
        };

        // Scan for all three pool tags
        for (tag, conn_type) in &[
            (POOL_TAG_TCPL, ConnectionType::TcpListener),
            (POOL_TAG_TCPE, ConnectionType::TcpEndpoint),
            (POOL_TAG_UDPA, ConnectionType::UdpEndpoint),
        ] {
            scan_chunk(
                &chunk,
                offset,
                tag,
                *conn_type,
                offsets,
                kernel_symbols,
                image,
                kernel_vm,
                &mut connections,
                &mut seen_offsets,
                chunk_size,
            );
        }

        offset += chunk_size as u64;
    }

    let tcp_listeners = connections
        .iter()
        .filter(|c| c.state.as_deref() == Some("LISTENING"))
        .count();
    let tcp_endpoints = connections
        .iter()
        .filter(|c| {
            (c.protocol == "TCPv4" || c.protocol == "TCPv6")
                && c.state.as_deref() != Some("LISTENING")
        })
        .count();
    let udp_endpoints = connections
        .iter()
        .filter(|c| c.protocol == "UDPv4" || c.protocol == "UDPv6")
        .count();

    debug!(
        "netscan: found {} connections ({} listeners, {} TCP endpoints, {} UDP)",
        connections.len(),
        tcp_listeners,
        tcp_endpoints,
        udp_endpoints
    );

    Ok(NetscanResult {
        tcp_listeners,
        tcp_endpoints,
        udp_endpoints,
        total: connections.len(),
        connections,
    })
}

// ── Internal types ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum ConnectionType {
    TcpListener,
    TcpEndpoint,
    UdpEndpoint,
}

// ── Chunk scanning ─────────────────────────────────────────────────

fn scan_chunk(
    chunk: &[u8],
    chunk_offset: u64,
    tag: &[u8],
    conn_type: ConnectionType,
    offsets: &NetscanOffsets,
    kernel_symbols: &IsfSymbols,
    image: &MemoryImage,
    kernel_vm: Option<&dyn MemoryAccess>,
    connections: &mut Vec<NetworkConnection>,
    seen_offsets: &mut HashSet<u64>,
    max_scan_offset: usize,
) {
    let mut pos = 0;
    while pos + tag.len() <= chunk.len() {
        if let Some(found) = memchr_find(tag, &chunk[pos..]) {
            let abs_pos = pos + found;
            pos = abs_pos + 1;

            if abs_pos >= max_scan_offset {
                continue;
            }

            if abs_pos < TAG_OFFSET_IN_HEADER {
                continue;
            }

            let pool_header_addr = chunk_offset + (abs_pos - TAG_OFFSET_IN_HEADER) as u64;
            let struct_addr = pool_header_addr + offsets.pool_header_size as u64;

            if !seen_offsets.insert(struct_addr) {
                continue;
            }

            match parse_connection(
                conn_type,
                struct_addr,
                offsets,
                kernel_symbols,
                image,
                kernel_vm,
            ) {
                Ok(Some(conn)) => {
                    debug!(
                        "netscan: {} PID {} {}:{} at {:#x}",
                        conn.protocol, conn.pid, conn.local_addr, conn.local_port, struct_addr
                    );
                    connections.push(conn);
                }
                Ok(None) => {}
                Err(e) => {
                    debug!("netscan: parse error at {:#x}: {}", struct_addr, e);
                }
            }
        } else {
            break;
        }
    }
}

// ── Connection parsing ─────────────────────────────────────────────

fn parse_connection(
    conn_type: ConnectionType,
    struct_addr: u64,
    offsets: &NetscanOffsets,
    kernel_symbols: &IsfSymbols,
    image: &MemoryImage,
    kernel_vm: Option<&dyn MemoryAccess>,
) -> Result<Option<NetworkConnection>, String> {
    match conn_type {
        ConnectionType::TcpListener => {
            parse_tcp_listener(struct_addr, offsets, kernel_symbols, image, kernel_vm)
        }
        ConnectionType::TcpEndpoint => {
            parse_tcp_endpoint(struct_addr, offsets, kernel_symbols, image, kernel_vm)
        }
        ConnectionType::UdpEndpoint => {
            parse_udp_endpoint(struct_addr, offsets, kernel_symbols, image, kernel_vm)
        }
    }
}

fn parse_tcp_listener(
    addr: u64,
    offsets: &NetscanOffsets,
    kernel_symbols: &IsfSymbols,
    image: &MemoryImage,
    kernel_vm: Option<&dyn MemoryAccess>,
) -> Result<Option<NetworkConnection>, String> {
    let ptr_size = offsets.pointer_size;

    // Read port (big-endian u16)
    let port = read_u16_be(image, addr + offsets.tcpl_port as u64)?;
    if port == 0 {
        return Ok(None);
    }

    // Read Owner pointer (kernel VA)
    let owner_va = read_ptr(image, addr + offsets.tcpl_owner as u64, ptr_size)?;
    if !is_kernel_address(owner_va, ptr_size) {
        return Ok(None);
    }

    // Resolve PID from Owner via kernel VM
    let (pid, process_name) = resolve_owner(owner_va, kernel_symbols, kernel_vm);

    // Resolve address family via InetAF pointer
    let inetaf_va = read_ptr(image, addr + offsets.tcpl_inetaf as u64, ptr_size)?;
    let af_name = resolve_address_family(inetaf_va, offsets, kernel_vm);

    // Create time
    let create_time = read_filetime(image, addr + offsets.tcpl_create_time as u64);

    let protocol = match af_name.as_deref() {
        Some("IPv6") => "TCPv6",
        _ => "TCPv4",
    };

    Ok(Some(NetworkConnection {
        protocol: protocol.to_string(),
        local_addr: "0.0.0.0".to_string(),
        local_port: port,
        remote_addr: "*".to_string(),
        remote_port: 0,
        state: Some("LISTENING".to_string()),
        pid,
        process_name,
        offset: addr,
        create_time,
        address_family: af_name,
    }))
}

fn parse_tcp_endpoint(
    addr: u64,
    offsets: &NetscanOffsets,
    kernel_symbols: &IsfSymbols,
    image: &MemoryImage,
    kernel_vm: Option<&dyn MemoryAccess>,
) -> Result<Option<NetworkConnection>, String> {
    let ptr_size = offsets.pointer_size;

    // Read state
    let state_val = read_u32_le(image, addr + offsets.tcpe_state as u64)?;
    let state_name = tcp_state_name(state_val);
    if state_name == "UNKNOWN" && state_val > 13 {
        return Ok(None);
    }

    // Read ports (big-endian u16)
    let local_port = read_u16_be(image, addr + offsets.tcpe_local_port as u64)?;
    let remote_port = read_u16_be(image, addr + offsets.tcpe_remote_port as u64)?;

    if local_port == 0 && remote_port == 0 {
        return Ok(None);
    }

    // Read Owner pointer
    let owner_va = read_ptr(image, addr + offsets.tcpe_owner as u64, ptr_size)?;
    if !is_kernel_address(owner_va, ptr_size) {
        return Ok(None);
    }

    let (pid, process_name) = resolve_owner(owner_va, kernel_symbols, kernel_vm);

    // Resolve addresses via kernel VM
    let inetaf_va = read_ptr(image, addr + offsets.tcpe_inetaf as u64, ptr_size)?;
    let af_name = resolve_address_family(inetaf_va, offsets, kernel_vm);
    let addr_info_va = read_ptr(image, addr + offsets.tcpe_addr_info as u64, ptr_size)?;
    let (local_addr, remote_addr) =
        resolve_tcp_endpoint_ips(addr_info_va, &af_name, offsets, kernel_vm);

    let create_time = read_filetime(image, addr + offsets.tcpe_create_time as u64);

    let protocol = match af_name.as_deref() {
        Some("IPv6") => "TCPv6",
        _ => "TCPv4",
    };

    Ok(Some(NetworkConnection {
        protocol: protocol.to_string(),
        local_addr: local_addr.unwrap_or_else(|| "0.0.0.0".to_string()),
        local_port,
        remote_addr: remote_addr.unwrap_or_else(|| "0.0.0.0".to_string()),
        remote_port,
        state: Some(state_name.to_string()),
        pid,
        process_name,
        offset: addr,
        create_time,
        address_family: af_name,
    }))
}

fn parse_udp_endpoint(
    addr: u64,
    offsets: &NetscanOffsets,
    kernel_symbols: &IsfSymbols,
    image: &MemoryImage,
    kernel_vm: Option<&dyn MemoryAccess>,
) -> Result<Option<NetworkConnection>, String> {
    let ptr_size = offsets.pointer_size;

    // Read port (big-endian u16)
    let port = read_u16_be(image, addr + offsets.udpa_port as u64)?;
    if port == 0 {
        return Ok(None);
    }

    // Read Owner pointer
    let owner_va = read_ptr(image, addr + offsets.udpa_owner as u64, ptr_size)?;
    if !is_kernel_address(owner_va, ptr_size) {
        return Ok(None);
    }

    let (pid, process_name) = resolve_owner(owner_va, kernel_symbols, kernel_vm);

    // Resolve address family
    let inetaf_va = read_ptr(image, addr + offsets.udpa_inetaf as u64, ptr_size)?;
    let af_name = resolve_address_family(inetaf_va, offsets, kernel_vm);

    let create_time = read_filetime(image, addr + offsets.udpa_create_time as u64);

    let protocol = match af_name.as_deref() {
        Some("IPv6") => "UDPv6",
        _ => "UDPv4",
    };

    Ok(Some(NetworkConnection {
        protocol: protocol.to_string(),
        local_addr: "0.0.0.0".to_string(),
        local_port: port,
        remote_addr: "*".to_string(),
        remote_port: 0,
        state: None,
        pid,
        process_name,
        offset: addr,
        create_time,
        address_family: af_name,
    }))
}

// ── Pointer / address resolution helpers ───────────────────────────

/// Resolve PID and process name from an Owner pointer (_EPROCESS VA).
fn resolve_owner(
    owner_va: u64,
    kernel_symbols: &IsfSymbols,
    kernel_vm: Option<&dyn MemoryAccess>,
) -> (u64, Option<String>) {
    let vm = match kernel_vm {
        Some(vm) => vm,
        None => return (0, None),
    };

    let pid_offset = kernel_symbols
        .field_offset("_EPROCESS", "UniqueProcessId")
        .unwrap_or(0x440);

    let pid = match read_ptr_from(vm, owner_va + pid_offset as u64, kernel_symbols.pointer_size) {
        Ok(p) if p < 0x10000 => p,
        _ => return (0, None),
    };

    let name_offset = kernel_symbols
        .field_offset("_EPROCESS", "ImageFileName")
        .unwrap_or(0x5a8);

    let name = read_string_from(vm, owner_va + name_offset as u64, 15).ok();

    (pid, name)
}

/// Resolve address family from _INETAF pointer via kernel VM.
fn resolve_address_family(
    inetaf_va: u64,
    offsets: &NetscanOffsets,
    kernel_vm: Option<&dyn MemoryAccess>,
) -> Option<String> {
    let vm = kernel_vm?;
    if inetaf_va == 0 || !is_kernel_address(inetaf_va, offsets.pointer_size) {
        return None;
    }
    let af = read_u16_le_from(vm, inetaf_va + offsets.inetaf_address_family as u64).ok()?;
    match af {
        2 => Some("IPv4".to_string()),
        0x17 => Some("IPv6".to_string()),
        _ => None,
    }
}

/// Resolve TCP endpoint local and remote IPs via kernel VM.
///
/// Local IP chain:  AddrInfo → Local → _LOCAL_ADDRESS.pData → ptr → _IN_ADDR
/// Remote IP chain: AddrInfo → Remote → _IN_ADDR
fn resolve_tcp_endpoint_ips(
    addr_info_va: u64,
    af_name: &Option<String>,
    offsets: &NetscanOffsets,
    kernel_vm: Option<&dyn MemoryAccess>,
) -> (Option<String>, Option<String>) {
    let vm = match kernel_vm {
        Some(vm) => vm,
        None => return (None, None),
    };

    if addr_info_va == 0 || !is_kernel_address(addr_info_va, offsets.pointer_size) {
        return (None, None);
    }

    let is_ipv6 = af_name.as_deref() == Some("IPv6");
    let ps = offsets.pointer_size;

    // Remote IP: AddrInfo.Remote → _IN_ADDR
    let remote_ip = (|| -> Option<String> {
        let remote_ptr = read_ptr_from(vm, addr_info_va + offsets.addrinfo_remote as u64, ps).ok()?;
        if remote_ptr == 0 || !is_kernel_address(remote_ptr, ps) {
            return None;
        }
        read_ip_addr(vm, remote_ptr, is_ipv6)
    })();

    // Local IP: AddrInfo.Local → _LOCAL_ADDRESS.pData → ptr → _IN_ADDR
    let local_ip = (|| -> Option<String> {
        let local_ptr = read_ptr_from(vm, addr_info_va + offsets.addrinfo_local as u64, ps).ok()?;
        if local_ptr == 0 || !is_kernel_address(local_ptr, ps) {
            return None;
        }
        let pdata_ptr = read_ptr_from(vm, local_ptr + offsets.local_addr_pdata as u64, ps).ok()?;
        if pdata_ptr == 0 || !is_kernel_address(pdata_ptr, ps) {
            return None;
        }
        // Double pointer: pData → ptr → _IN_ADDR
        let in_addr_ptr = read_ptr_from(vm, pdata_ptr, ps).ok()?;
        if in_addr_ptr == 0 || !is_kernel_address(in_addr_ptr, ps) {
            return None;
        }
        read_ip_addr(vm, in_addr_ptr, is_ipv6)
    })();

    (local_ip, remote_ip)
}

/// Read an IPv4 or IPv6 address from memory.
fn read_ip_addr(memory: &dyn MemoryAccess, addr: u64, is_ipv6: bool) -> Option<String> {
    if is_ipv6 {
        let bytes = memory.read(addr, 16).ok()?;
        let octets: [u8; 16] = bytes.try_into().ok()?;
        Some(Ipv6Addr::from(octets).to_string())
    } else {
        let bytes = memory.read(addr, 4).ok()?;
        Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string())
    }
}

// ── Low-level memory read helpers ──────────────────────────────────

fn read_ptr(image: &MemoryImage, addr: u64, ptr_size: usize) -> Result<u64, String> {
    let bytes = image
        .read(addr, ptr_size)
        .map_err(|e| format!("read_ptr at {:#x}: {}", addr, e))?;
    match ptr_size {
        4 => Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64),
        8 => Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])),
        _ => Err(format!("unsupported pointer size: {}", ptr_size)),
    }
}

fn read_ptr_from(
    memory: &dyn MemoryAccess,
    addr: u64,
    ptr_size: usize,
) -> Result<u64, String> {
    let bytes = memory
        .read(addr, ptr_size)
        .map_err(|e| format!("read_ptr_from at {:#x}: {}", addr, e))?;
    match ptr_size {
        4 => Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64),
        8 => Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])),
        _ => Err(format!("unsupported pointer size: {}", ptr_size)),
    }
}

fn read_u16_be(image: &MemoryImage, addr: u64) -> Result<u16, String> {
    let bytes = image
        .read(addr, 2)
        .map_err(|e| format!("read_u16_be at {:#x}: {}", addr, e))?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32_le(image: &MemoryImage, addr: u64) -> Result<u32, String> {
    let bytes = image
        .read(addr, 4)
        .map_err(|e| format!("read_u32_le at {:#x}: {}", addr, e))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u16_le_from(memory: &dyn MemoryAccess, addr: u64) -> Result<u16, String> {
    let bytes = memory
        .read(addr, 2)
        .map_err(|e| format!("read_u16_le at {:#x}: {}", addr, e))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_string_from(memory: &dyn MemoryAccess, addr: u64, max_len: usize) -> Result<String, String> {
    let bytes = memory
        .read(addr, max_len)
        .map_err(|e| format!("read_string at {:#x}: {}", addr, e))?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

fn read_filetime(image: &MemoryImage, addr: u64) -> Option<String> {
    let bytes = image.read(addr, 8).ok()?;
    let ft = u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    super::pslist::filetime_to_iso(ft)
}

/// Check if an address looks like a kernel-mode virtual address.
fn is_kernel_address(addr: u64, ptr_size: usize) -> bool {
    if addr == 0 {
        return false;
    }
    match ptr_size {
        8 => addr > 0xFFFF_0000_0000_0000,
        4 => addr > 0x8000_0000,
        _ => false,
    }
}

/// Simple byte pattern search (same as psscan).
fn memchr_find(needle: &[u8], haystack: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let first = needle[0];
    let mut pos = 0;
    while pos + needle.len() <= haystack.len() {
        if let Some(idx) = memchr::memchr(first, &haystack[pos..]) {
            let abs = pos + idx;
            if abs + needle.len() > haystack.len() {
                return None;
            }
            if haystack[abs..abs + needle.len()] == *needle {
                return Some(abs);
            }
            pos = abs + 1;
        } else {
            return None;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_state_names() {
        assert_eq!(tcp_state_name(0), "CLOSED");
        assert_eq!(tcp_state_name(1), "LISTENING");
        assert_eq!(tcp_state_name(4), "ESTABLISHED");
        assert_eq!(tcp_state_name(7), "CLOSE_WAIT");
        assert_eq!(tcp_state_name(12), "TIME_WAIT");
        assert_eq!(tcp_state_name(99), "UNKNOWN");
    }

    #[test]
    fn test_is_kernel_address() {
        assert!(is_kernel_address(0xFFFF_F800_0000_0000, 8));
        assert!(!is_kernel_address(0x0000_7FFF_0000_0000, 8));
        assert!(!is_kernel_address(0, 8));

        assert!(is_kernel_address(0x8000_0001, 4));
        assert!(!is_kernel_address(0x7FFF_FFFF, 4));
    }

    #[test]
    fn test_offsets_win10_19041() {
        let o = NetscanOffsets::win10_19041_x64();
        assert_eq!(o.pointer_size, 8);
        assert_eq!(o.tcpl_port, 114);
        assert_eq!(o.tcpe_owner, 728);
        assert_eq!(o.tcpe_state, 108);
        assert_eq!(o.udpa_port, 160);
    }

    #[test]
    fn test_offsets_win7() {
        let o = NetscanOffsets::win7_x64();
        assert_eq!(o.pointer_size, 8);
        assert_eq!(o.tcpl_port, 106);
        assert_eq!(o.tcpe_owner, 368);
    }

    #[test]
    fn test_netscan_result_serialize() {
        let result = NetscanResult {
            tcp_listeners: 2,
            tcp_endpoints: 5,
            udp_endpoints: 3,
            total: 10,
            connections: vec![NetworkConnection {
                protocol: "TCPv4".to_string(),
                local_addr: "0.0.0.0".to_string(),
                local_port: 80,
                remote_addr: "*".to_string(),
                remote_port: 0,
                state: Some("LISTENING".to_string()),
                pid: 4,
                process_name: Some("System".to_string()),
                offset: 0x1234,
                create_time: None,
                address_family: Some("IPv4".to_string()),
            }],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("TCPv4"));
        assert!(json.contains("LISTENING"));
    }

    #[test]
    fn test_connection_skips_none_fields() {
        let conn = NetworkConnection {
            protocol: "UDPv4".to_string(),
            local_addr: "0.0.0.0".to_string(),
            local_port: 53,
            remote_addr: "*".to_string(),
            remote_port: 0,
            state: None,
            pid: 1234,
            process_name: None,
            offset: 0x5678,
            create_time: None,
            address_family: None,
        };
        let json = serde_json::to_string(&conn).unwrap();
        assert!(!json.contains("state"));
        assert!(!json.contains("process_name"));
        assert!(!json.contains("create_time"));
        assert!(!json.contains("address_family"));
    }

    #[test]
    fn test_memchr_find() {
        assert_eq!(memchr_find(b"TcpL", b"xxTcpLyy"), Some(2));
        assert_eq!(memchr_find(b"TcpE", b"TcpE"), Some(0));
        assert_eq!(memchr_find(b"UdpA", b"nope"), None);
    }
}
