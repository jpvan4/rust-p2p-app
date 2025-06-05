use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;
use sha2::{Sha256, Digest};

pub mod types;
pub mod config;
pub mod error;
pub mod crypto;

pub use types::*;
pub use config::*;
pub use error::*;

/// Core peer identity structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PeerId {
    pub public_key: Vec<u8>, // Ed25519 public key bytes
    pub network_id: NetworkId,
    pub capabilities: PeerCapabilities,
}

impl PeerId {
    pub fn new(public_key: Vec<u8>, network_id: NetworkId) -> Self {
        Self {
            public_key,
            network_id,
            capabilities: PeerCapabilities::default(),
        }
    }

    pub fn to_string(&self) -> String {
        format!("{}:{}", hex::encode(&self.public_key), self.network_id.0)
    }
}

/// Network identifier for multi-network support
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct NetworkId(pub String);

impl Default for NetworkId {
    fn default() -> Self {
        Self("default".to_string())
    }
}

/// Peer capabilities and supported features
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PeerCapabilities {
    pub supports_file_transfer: bool,
    pub supports_tor: bool,
    pub supports_relay: bool,
    pub max_bandwidth: Option<u64>,
    pub storage_capacity: Option<u64>,
    pub protocol_version: String,
}

impl Default for PeerCapabilities {
    fn default() -> Self {
        Self {
            supports_file_transfer: true,
            supports_tor: false,
            supports_relay: false,
            max_bandwidth: None,
            storage_capacity: None,
            protocol_version: "1.0.0".to_string(),
        }
    }
}

/// Unique message identifier
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct MessageId(pub Uuid);

impl MessageId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for MessageId {
    fn default() -> Self {
        Self::new()
    }
}

/// Main message envelope for all network communications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Control(ControlMessage),
    Data(DataMessage),
    File(FileMessage),
    Update(UpdateMessage),
}

/// Message header with authentication and routing information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageHeader {
    pub message_id: MessageId,
    pub sender: PeerId,
    pub recipient: Option<PeerId>, // None for broadcast messages
    pub timestamp: SystemTime,
    pub signature: Vec<u8>, // Ed25519 signature bytes
    pub message_type: String,
}

/// Control messages for network management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlMessage {
    PeerDiscovery {
        requesting_peer: PeerId,
        known_peers: Vec<PeerId>,
    },
    PeerAnnouncement {
        peer: PeerId,
        addresses: Vec<PeerAddress>,
    },
    ConnectionRequest {
        requester: PeerId,
        target: PeerId,
        connection_type: ConnectionType,
    },
    ConnectionResponse {
        accepted: bool,
        reason: Option<String>,
    },
    Heartbeat {
        peer: PeerId,
        status: PeerStatus,
    },
    NetworkStatus {
        active_peers: u32,
        total_bandwidth: u64,
        network_health: f32,
    },
}

/// Data messages for user content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataMessage {
    Chat {
        sender: PeerId,
        content: String,
        channel: Option<String>,
    },
    Custom {
        data_type: String,
        payload: Vec<u8>,
    },
}

/// File transfer messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileMessage {
    TransferRequest {
        transfer_id: TransferId,
        file_info: FileInfo,
        requester: PeerId,
    },
    TransferResponse {
        transfer_id: TransferId,
        accepted: bool,
        available_chunks: Option<Vec<u32>>,
    },
    ChunkRequest {
        transfer_id: TransferId,
        chunk_indices: Vec<u32>,
    },
    ChunkData {
        transfer_id: TransferId,
        chunk: FileChunk,
    },
    TransferComplete {
        transfer_id: TransferId,
        success: bool,
        error: Option<String>,
    },
}

/// Update messages for software updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UpdateMessage {
    UpdateAvailable {
        version: String,
        download_url: String,
        signature: Vec<u8>,
        changelog: String,
    },
    UpdateRequest {
        current_version: String,
    },
    UpdateData {
        version: String,
        chunk_index: u32,
        total_chunks: u32,
        data: Vec<u8>,
        checksum: Vec<u8>,
    },
}

/// Peer network address information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerAddress {
    pub address: String,
    pub port: u16,
    pub address_type: AddressType,
    pub last_successful: Option<SystemTime>,
    pub success_count: u32,
    pub failure_count: u32,
}

/// Address types for different network protocols
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AddressType {
    IPv4,
    IPv6,
    Onion, // Tor hidden service
    Domain,
}

/// Connection types for different transport protocols
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConnectionType {
    Direct,
    Relay,
    Tor,
}

/// Peer status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStatus {
    pub online: bool,
    pub bandwidth_usage: u64,
    pub active_transfers: u32,
    pub uptime: u64, // seconds
    pub last_activity: SystemTime,
}

/// File transfer identifier
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TransferId(pub Uuid);

impl TransferId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for TransferId {
    fn default() -> Self {
        Self::new()
    }
}

/// File information for transfers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub name: String,
    pub size: u64,
    pub hash: Vec<u8>, // SHA-256 hash
    pub mime_type: Option<String>,
    pub created: Option<SystemTime>,
    pub modified: Option<SystemTime>,
}

/// File chunk for transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChunk {
    pub transfer_id: TransferId,
    pub chunk_index: u32,
    pub data: Vec<u8>,
    pub checksum: Vec<u8>, // SHA-256 hash of chunk data
}

impl FileChunk {
    pub fn verify_checksum(&self) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(&self.data);
        let computed_hash = hasher.finalize().to_vec();
        computed_hash == self.checksum
    }
}

/// File transfer tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTransfer {
    pub transfer_id: TransferId,
    pub file_info: FileInfo,
    pub chunk_size: u32,
    pub total_chunks: u32,
    pub completed_chunks: std::collections::HashSet<u32>,
    pub peers: Vec<PeerId>,
    pub status: TransferStatus,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
}

/// Transfer status enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransferStatus {
    Pending,
    Active,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub network_id: NetworkId,
    pub listen_addresses: Vec<String>,
    pub bootstrap_peers: Vec<PeerAddress>,
    pub max_connections: u32,
    pub connection_timeout: u64,
    pub enable_tor: bool,
    pub enable_upnp: bool,
    pub bandwidth_limit: Option<u64>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            network_id: NetworkId::default(),
            listen_addresses: vec!["0.0.0.0:0".to_string()],
            bootstrap_peers: Vec::new(),
            max_connections: 100,
            connection_timeout: 30,
            enable_tor: false,
            enable_upnp: true,
            bandwidth_limit: None,
        }
    }
}

