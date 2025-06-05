use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, RwLock};
use p2p_core::{PeerId, PeerAddress, NetworkConfig, P2PResult, P2PError};

pub mod discovery;
pub mod connection;
pub mod messaging;
pub mod nat_traversal;

pub use discovery::*;
pub use connection::*;
pub use messaging::*;
pub use nat_traversal::*;

/// Main network manager for P2P operations
pub struct NetworkManager {
    connection_manager: connection::ConnectionManager,
    discovery_service: discovery::DiscoveryService,
    message_router: messaging::MessageRouter,
    peers: Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
    config: NetworkConfig,
    event_sender: mpsc::UnboundedSender<NetworkEvent>,
    event_receiver: mpsc::UnboundedReceiver<NetworkEvent>,
}

/// Information about a connected peer
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub addresses: Vec<PeerAddress>,
    pub connection_time: SystemTime,
    pub last_seen: SystemTime,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub is_connected: bool,
}

/// Network events that can occur
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    PeerConnected(PeerId),
    PeerDisconnected(PeerId),
    MessageReceived {
        from: PeerId,
        message: Vec<u8>,
    },
    PeerDiscovered {
        peer_id: PeerId,
        addresses: Vec<PeerAddress>,
    },
    ConnectionFailed {
        peer_id: PeerId,
        error: String,
    },
    NetworkError(String),
}

impl NetworkManager {
    /// Create a new network manager
    pub async fn new(config: NetworkConfig) -> P2PResult<Self> {
        // Create event channel
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        
        // Create local peer ID (simplified for now)
        let local_peer_id = PeerId::new(
            b"local_peer".to_vec(),
            config.network_id.clone(),
        );
        
        // Create connection manager
        let (connection_manager, _connection_events) = connection::ConnectionManager::new(
            config.max_connections as usize,
            Duration::from_secs(config.connection_timeout),
        );
        
        // Create discovery service
        let discovery_service = discovery::DiscoveryService::new(
            config.network_id.clone(),
            local_peer_id,
            config.bootstrap_peers.clone(),
        );
        
        // Create message router
        let message_router = messaging::MessageRouter::new();
        
        Ok(Self {
            connection_manager,
            discovery_service,
            message_router,
            peers: Arc::new(RwLock::new(HashMap::new())),
            config,
            event_sender,
            event_receiver,
        })
    }
    
    /// Start the network manager
    pub async fn start(&mut self) -> P2PResult<()> {
        // Start discovery service
        self.discovery_service.start().await?;
        
        // Start connection listener
        for addr_str in &self.config.listen_addresses {
            self.connection_manager.start_listener(addr_str).await?;
        }
        
        // Connect to bootstrap peers
        for bootstrap_peer in &self.config.bootstrap_peers {
            let peer_id = PeerId::new(
                format!("bootstrap_{}", bootstrap_peer.address).into_bytes(),
                self.config.network_id.clone(),
            );
            if let Err(e) = self.connection_manager.connect_to_peer(peer_id, bootstrap_peer).await {
                log::warn!("Failed to connect to bootstrap peer: {}", e);
            }
        }
        
        // Start the main event loop
        self.run_event_loop().await
    }
    
    /// Connect to a specific peer
    pub async fn connect_to_peer(&mut self, peer_address: &PeerAddress) -> P2PResult<()> {
        let peer_id = PeerId::new(
            format!("peer_{}", peer_address.address).into_bytes(),
            self.config.network_id.clone(),
        );
        
        self.connection_manager.connect_to_peer(peer_id, peer_address).await
    }
    
    /// Send a message to a specific peer
    pub async fn send_message(&mut self, peer_id: &PeerId, message: Vec<u8>) -> P2PResult<()> {
        self.connection_manager.send_message(peer_id, message).await
    }
    
    /// Broadcast a message to all connected peers
    pub async fn broadcast_message(&mut self, message: Vec<u8>) -> P2PResult<()> {
        let peer_ids = self.connection_manager.get_connected_peers().await;
        
        for peer_id in peer_ids {
            if let Err(e) = self.send_message(&peer_id, message.clone()).await {
                log::warn!("Failed to send message to peer {:?}: {}", peer_id, e);
            }
        }
        Ok(())
    }
    
    /// Get information about all known peers
    pub async fn get_peers(&self) -> HashMap<PeerId, PeerInfo> {
        self.peers.read().await.clone()
    }
    
    /// Get information about a specific peer
    pub async fn get_peer(&self, peer_id: &PeerId) -> Option<PeerInfo> {
        self.peers.read().await.get(peer_id).cloned()
    }
    
    /// Main event loop for handling network events
    async fn run_event_loop(&mut self) -> P2PResult<()> {
        loop {
            tokio::select! {
                // Handle periodic maintenance
                _ = tokio::time::sleep(Duration::from_secs(1)) => {
                    self.perform_maintenance().await?;
                }
            }
        }
    }
    
    /// Perform periodic maintenance tasks
    async fn perform_maintenance(&mut self) -> P2PResult<()> {
        // Clean up disconnected peers
        let mut peers = self.peers.write().await;
        let now = SystemTime::now();
        
        peers.retain(|_, peer_info| {
            if !peer_info.is_connected {
                // Remove peers that have been disconnected for more than 5 minutes
                if let Ok(duration) = now.duration_since(peer_info.last_seen) {
                    duration.as_secs() < 300
                } else {
                    false
                }
            } else {
                true
            }
        });
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2p_core::NetworkId;
    
    #[tokio::test]
    async fn test_network_manager_creation() {
        let config = NetworkConfig {
            network_id: NetworkId("test".to_string()),
            listen_addresses: vec!["127.0.0.1:0".to_string()],
            bootstrap_peers: Vec::new(),
            max_connections: 10,
            connection_timeout: 30,
            enable_tor: false,
            enable_upnp: false,
            bandwidth_limit: None,
        };
        
        let result = NetworkManager::new(config).await;
        assert!(result.is_ok());
    }
}

