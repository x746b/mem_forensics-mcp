//! Static rule data for process anomaly detection.
//!
//! These rules encode known-good Windows process behaviors:
//! expected parent-child relationships, singleton processes,
//! LOLBins, and suspicious indicators.

pub mod lolbins;
pub mod parent_child;
pub mod command_patterns;
pub mod suspicious_ports;
