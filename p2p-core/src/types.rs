/// Additional type definitions and utilities for the P2P core

use serde::{Deserialize, Serialize};
use std::fmt;

/// Reputation score for peers
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReputationScore(pub i32);

impl ReputationScore {
    pub const MIN: i32 = -1000;
    pub const MAX: i32 = 1000;
    pub const DEFAULT: i32 = 100;
    
    pub fn new(score: i32) -> Self {
        Self(score.clamp(Self::MIN, Self::MAX))
    }
    
    pub fn adjust(&mut self, delta: i32) {
        self.0 = (self.0 + delta).clamp(Self::MIN, Self::MAX);
    }
    
    pub fn is_trusted(&self) -> bool {
        self.0 >= 50
    }
    
    pub fn is_banned(&self) -> bool {
        self.0 <= -100
    }
}

impl Default for ReputationScore {
    fn default() -> Self {
        Self(Self::DEFAULT)
    }
}

impl fmt::Display for ReputationScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Bandwidth measurement in bytes per second
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Bandwidth(pub u64);

impl Bandwidth {
    pub fn new(bytes_per_second: u64) -> Self {
        Self(bytes_per_second)
    }
    
    pub fn kbps(kbps: u64) -> Self {
        Self(kbps * 1024)
    }
    
    pub fn mbps(mbps: u64) -> Self {
        Self(mbps * 1024 * 1024)
    }
    
    pub fn as_bytes_per_second(&self) -> u64 {
        self.0
    }
    
    pub fn as_kbps(&self) -> f64 {
        self.0 as f64 / 1024.0
    }
    
    pub fn as_mbps(&self) -> f64 {
        self.0 as f64 / (1024.0 * 1024.0)
    }
}

impl fmt::Display for Bandwidth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 >= 1024 * 1024 {
            write!(f, "{:.2} MB/s", self.as_mbps())
        } else if self.0 >= 1024 {
            write!(f, "{:.2} KB/s", self.as_kbps())
        } else {
            write!(f, "{} B/s", self.0)
        }
    }
}

/// File size representation
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileSize(pub u64);

impl FileSize {
    pub fn new(bytes: u64) -> Self {
        Self(bytes)
    }
    
    pub fn kb(kb: u64) -> Self {
        Self(kb * 1024)
    }
    
    pub fn mb(mb: u64) -> Self {
        Self(mb * 1024 * 1024)
    }
    
    pub fn gb(gb: u64) -> Self {
        Self(gb * 1024 * 1024 * 1024)
    }
    
    pub fn as_bytes(&self) -> u64 {
        self.0
    }
    
    pub fn as_kb(&self) -> f64 {
        self.0 as f64 / 1024.0
    }
    
    pub fn as_mb(&self) -> f64 {
        self.0 as f64 / (1024.0 * 1024.0)
    }
    
    pub fn as_gb(&self) -> f64 {
        self.0 as f64 / (1024.0 * 1024.0 * 1024.0)
    }
}

impl fmt::Display for FileSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 >= 1024 * 1024 * 1024 {
            write!(f, "{:.2} GB", self.as_gb())
        } else if self.0 >= 1024 * 1024 {
            write!(f, "{:.2} MB", self.as_mb())
        } else if self.0 >= 1024 {
            write!(f, "{:.2} KB", self.as_kb())
        } else {
            write!(f, "{} B", self.0)
        }
    }
}

/// Protocol version for compatibility checking
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl ProtocolVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }
    
    pub fn is_compatible(&self, other: &Self) -> bool {
        self.major == other.major && self.minor <= other.minor
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self::new(1, 0, 0)
    }
}

/// Network statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    pub total_peers: u32,
    pub active_peers: u32,
    pub total_bandwidth: Bandwidth,
    pub total_storage: FileSize,
    pub active_transfers: u32,
    pub uptime: u64, // seconds
}

impl Default for NetworkStats {
    fn default() -> Self {
        Self {
            total_peers: 0,
            active_peers: 0,
            total_bandwidth: Bandwidth::new(0),
            total_storage: FileSize::new(0),
            active_transfers: 0,
            uptime: 0,
        }
    }
}

