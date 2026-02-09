//! Translation layer implementations.
//!
//! This module provides high-performance replacements for Volatility3's
//! address translation layers.
//!
//! ## Supported Architectures
//!
//! ### Intel x86
//! - `Intel32Translator` - 32-bit x86 paging (2-level, 4GB address space)
//! - `IntelPAETranslator` - PAE paging (3-level, 64GB physical)
//! - `Intel64Translator` - x86-64 paging (4-level, 256TB virtual)
//!
//! ### ARM
//! - `Arm64Translator` - ARM64/AArch64 paging (4KB/16KB/64KB granules)
//!
//! ## Windows Swap File Support
//!
//! - `WindowsIntel32Translator` - Windows 32-bit with swap file support
//! - `WindowsIntelPAETranslator` - Windows PAE with swap file support
//! - `WindowsIntel64Translator` - Windows 64-bit with swap file support

pub mod arm64;
pub mod intel32;
pub mod intel64;
pub mod intel_pae;
pub mod windows;

#[allow(unused_imports)]
pub use arm64::Arm64Translator;
pub use intel64::Intel64Translator;
#[allow(unused_imports)]
pub use intel32::Intel32Translator;
#[allow(unused_imports)]
pub use intel_pae::IntelPAETranslator;
#[allow(unused_imports)]
pub use windows::{WindowsIntel32Translator, WindowsIntelPAETranslator, WindowsIntel64Translator};
