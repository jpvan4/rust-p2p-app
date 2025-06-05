/// Connection management for P2P networking

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, RwLock};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Deserialize, Serialize};
use p2p_core::{PeerId, PeerAddress, P2PResult, P2PError};

/// Connection manager for handling peer connections
pub struct ConnectionManager {
    connections: Arc<RwLock<HashMap<PeerId, Connection>>>,
    connection_events: mpsc::UnboundedSender<ConnectionEvent>,
    max_connections: usize,
    connection_timeout: Duration,
}

/// Represents a connection to a peer
#[derive(Debug)]
pub struct Connection {
    pub peer_id: PeerId,
    pub stream: Arc<RwLock<TcpStream>>,
    pub established_at: SystemTime,
    pub last_activity: SystemTime,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub is_outbound: bool,
}

/// Connection events
#[derive(Debug, Clone)]
pub enum ConnectionEvent {
    Connected {
        peer_id: PeerId,
        is_outbound: bool,
    },
    Disconnected {
        peer_id: PeerId,
        reason: DisconnectReason,
    },
    MessageReceived {
        peer_id: PeerId,
        message: Vec<u8>,
    },
    ConnectionFailed {
        peer_id: PeerId,
        error: String,
    },
}

/// Reasons for disconnection
#[derive(Debug, Clone)]
pub enum DisconnectReason {
    PeerDisconnected,
    Timeout,
    Error(String),
    MaxConnectionsReached,
    Shutdown,
}

/// Connection handshake message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeMessage {
    pub peer_id: PeerId,
    pub protocol_version: String,
    pub capabilities: Vec<String>,
    pub timestamp: u64,
}

impl ConnectionManager {
    /// Create a new connection manager
    pub fn new(max_connections: usize, connection_timeout: Duration) -> (Self, mpsc::UnboundedReceiver<ConnectionEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        
        let manager = Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            connection_events: tx,
            max_connections,
            connection_timeout,
        };
        
        (manager, rx)
    }
    
    /// Start listening for incoming connections
    pub async fn start_listener(&self, bind_address: &str) -> P2PResult<()> {
        let listener = TcpListener::bind(bind_address).await
            .map_err(|e| P2PError::Network(format!("Failed to bind to {}: {}", bind_address, e)))?;
        
        log::info!("Listening for connections on {}", bind_address);
        
        let connections = Arc::clone(&self.connections);
        let event_sender = self.connection_events.clone();
        let max_connections = self.max_connections;
        
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        log::debug!("Incoming connection from {}", addr);
                        
                        // Check connection limit
                        if connections.read().await.len() >= max_connections {
                            log::warn!("Max connections reached, rejecting connection from {}", addr);
                            continue;
                        }
                        
                        // Handle the connection
                        let connections_clone = Arc::clone(&connections);
                        let event_sender_clone = event_sender.clone();
                        
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_incoming_connection(
                                stream,
                                connections_clone,
                                event_sender_clone,
                            ).await {
                                log::warn!("Failed to handle incoming connection: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        log::error!("Failed to accept connection: {}", e);
                    }
                }
            }
        });
        
        Ok(())
    }
    
    /// Connect to a peer
    pub async fn connect_to_peer(&self, peer_id: PeerId, address: &PeerAddress) -> P2PResult<()> {
        // Check if already connected
        if self.connections.read().await.contains_key(&peer_id) {
            return Ok(());
        }
        
        // Check connection limit
        if self.connections.read().await.len() >= self.max_connections {
            return Err(P2PError::Network("Max connections reached".to_string()));
        }
        
        let addr = format!("{}:{}", address.address, address.port);
        
        log::debug!("Connecting to peer {:?} at {}", peer_id, addr);
        
        let stream = tokio::time::timeout(
            self.connection_timeout,
            TcpStream::connect(&addr)
        ).await
        .map_err(|_| P2PError::Timeout("Connection timeout".to_string()))?
        .map_err(|e| P2PError::Network(format!("Failed to connect to {}: {}", addr, e)))?;
        
        // Perform handshake
        let connection = self.perform_outbound_handshake(peer_id.clone(), stream).await?;
        
        // Store connection
        self.connections.write().await.insert(peer_id.clone(), connection);
        
        // Send connection event
        let _ = self.connection_events.send(ConnectionEvent::Connected {
            peer_id,
            is_outbound: true,
        });
        
        Ok(())
    }
    
    /// Send a message to a peer
    pub async fn send_message(&self, peer_id: &PeerId, message: Vec<u8>) -> P2PResult<()> {
        let connections = self.connections.read().await;
        
        if let Some(connection) = connections.get(peer_id) {
            let mut stream = connection.stream.write().await;
            
            // Send message length first
            let len = message.len() as u32;
            stream.write_all(&len.to_be_bytes()).await
                .map_err(|e| P2PError::Network(format!("Failed to send message length: {}", e)))?;
            
            // Send message data
            stream.write_all(&message).await
                .map_err(|e| P2PError::Network(format!("Failed to send message: {}", e)))?;
            
            log::debug!("Sent {} bytes to peer {:?}", message.len(), peer_id);
            Ok(())
        } else {
            Err(P2PError::PeerNotFound(format!("Peer {:?} not connected", peer_id)))
        }
    }
    
    /// Disconnect from a peer
    pub async fn disconnect_peer(&self, peer_id: &PeerId, reason: DisconnectReason) {
        if let Some(_connection) = self.connections.write().await.remove(peer_id) {
            log::debug!("Disconnected from peer {:?}: {:?}", peer_id, reason);
            
            let _ = self.connection_events.send(ConnectionEvent::Disconnected {
                peer_id: peer_id.clone(),
                reason,
            });
        }
    }
    
    /// Get all connected peers
    pub async fn get_connected_peers(&self) -> Vec<PeerId> {
        self.connections.read().await.keys().cloned().collect()
    }
    
    /// Get connection info for a peer
    pub async fn get_connection_info(&self, peer_id: &PeerId) -> Option<ConnectionInfo> {
        let connections = self.connections.read().await;
        connections.get(peer_id).map(|conn| ConnectionInfo {
            peer_id: conn.peer_id.clone(),
            established_at: conn.established_at,
            last_activity: conn.last_activity,
            bytes_sent: conn.bytes_sent,
            bytes_received: conn.bytes_received,
            is_outbound: conn.is_outbound,
        })
    }
    
    /// Handle incoming connection
    async fn handle_incoming_connection(
        stream: TcpStream,
        connections: Arc<RwLock<HashMap<PeerId, Connection>>>,
        event_sender: mpsc::UnboundedSender<ConnectionEvent>,
    ) -> P2PResult<()> {
        // Perform handshake to identify the peer
        let (peer_id, connection) = Self::perform_inbound_handshake(stream).await?;
        
        // Store connection
        connections.write().await.insert(peer_id.clone(), connection);
        
        // Send connection event
        let _ = event_sender.send(ConnectionEvent::Connected {
            peer_id: peer_id.clone(),
            is_outbound: false,
        });
        
        // Start message handling loop
        Self::handle_connection_messages(peer_id, connections, event_sender).await;
        
        Ok(())
    }
    
    /// Perform outbound handshake
    async fn perform_outbound_handshake(&self, peer_id: PeerId, mut stream: TcpStream) -> P2PResult<Connection> {
        // Send handshake message
        let handshake = HandshakeMessage {
            peer_id: peer_id.clone(), // Our peer ID
            protocol_version: "1.0.0".to_string(),
            capabilities: vec!["file_transfer".to_string(), "messaging".to_string()],
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        let handshake_data = serde_json::to_vec(&handshake)?;
        let len = handshake_data.len() as u32;
        
        stream.write_all(&len.to_be_bytes()).await
            .map_err(|e| P2PError::Network(format!("Failed to send handshake length: {}", e)))?;
        stream.write_all(&handshake_data).await
            .map_err(|e| P2PError::Network(format!("Failed to send handshake: {}", e)))?;
        
        // Receive handshake response
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await
            .map_err(|e| P2PError::Network(format!("Failed to read handshake response length: {}", e)))?;
        
        let len = u32::from_be_bytes(len_bytes) as usize;
        if len > 1024 * 1024 { // 1MB limit
            return Err(P2PError::Network("Handshake response too large".to_string()));
        }
        
        let mut response_data = vec![0u8; len];
        stream.read_exact(&mut response_data).await
            .map_err(|e| P2PError::Network(format!("Failed to read handshake response: {}", e)))?;
        
        let _response: HandshakeMessage = serde_json::from_slice(&response_data)?;
        
        // Create connection
        let connection = Connection {
            peer_id: peer_id.clone(),
            stream: Arc::new(RwLock::new(stream)),
            established_at: SystemTime::now(),
            last_activity: SystemTime::now(),
            bytes_sent: handshake_data.len() as u64,
            bytes_received: response_data.len() as u64,
            is_outbound: true,
        };
        
        Ok(connection)
    }
    
    /// Perform inbound handshake
    async fn perform_inbound_handshake(mut stream: TcpStream) -> P2PResult<(PeerId, Connection)> {
        // Receive handshake message
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await
            .map_err(|e| P2PError::Network(format!("Failed to read handshake length: {}", e)))?;
        
        let len = u32::from_be_bytes(len_bytes) as usize;
        if len > 1024 * 1024 { // 1MB limit
            return Err(P2PError::Network("Handshake message too large".to_string()));
        }
        
        let mut handshake_data = vec![0u8; len];
        stream.read_exact(&mut handshake_data).await
            .map_err(|e| P2PError::Network(format!("Failed to read handshake: {}", e)))?;
        
        let handshake: HandshakeMessage = serde_json::from_slice(&handshake_data)?;
        let peer_id = handshake.peer_id.clone();
        
        // Send handshake response
        let response = HandshakeMessage {
            peer_id: peer_id.clone(), // Echo back their peer ID for now
            protocol_version: "1.0.0".to_string(),
            capabilities: vec!["file_transfer".to_string(), "messaging".to_string()],
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        let response_data = serde_json::to_vec(&response)?;
        let response_len = response_data.len() as u32;
        
        stream.write_all(&response_len.to_be_bytes()).await
            .map_err(|e| P2PError::Network(format!("Failed to send handshake response length: {}", e)))?;
        stream.write_all(&response_data).await
            .map_err(|e| P2PError::Network(format!("Failed to send handshake response: {}", e)))?;
        
        // Create connection
        let connection = Connection {
            peer_id: peer_id.clone(),
            stream: Arc::new(RwLock::new(stream)),
            established_at: SystemTime::now(),
            last_activity: SystemTime::now(),
            bytes_sent: response_data.len() as u64,
            bytes_received: handshake_data.len() as u64,
            is_outbound: false,
        };
        
        Ok((peer_id, connection))
    }
    
    /// Handle messages from a connection
    async fn handle_connection_messages(
        peer_id: PeerId,
        connections: Arc<RwLock<HashMap<PeerId, Connection>>>,
        event_sender: mpsc::UnboundedSender<ConnectionEvent>,
    ) {
        loop {
            // Read message from connection
            let message_result = {
                let connections_guard = connections.read().await;
                if let Some(connection) = connections_guard.get(&peer_id) {
                    let mut stream = connection.stream.write().await;
                    Self::read_message(&mut *stream).await
                } else {
                    break; // Connection no longer exists
                }
            };
            
            match message_result {
                Ok(message) => {
                    // Send message event
                    let _ = event_sender.send(ConnectionEvent::MessageReceived {
                        peer_id: peer_id.clone(),
                        message,
                    });
                }
                Err(e) => {
                    log::warn!("Failed to read message from peer {:?}: {}", peer_id, e);
                    
                    // Remove connection
                    connections.write().await.remove(&peer_id);
                    
                    // Send disconnect event
                    let _ = event_sender.send(ConnectionEvent::Disconnected {
                        peer_id: peer_id.clone(),
                        reason: DisconnectReason::Error(e.to_string()),
                    });
                    
                    break;
                }
            }
        }
    }
    
    /// Read a message from a stream
    async fn read_message(stream: &mut TcpStream) -> P2PResult<Vec<u8>> {
        // Read message length
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await
            .map_err(|e| P2PError::Network(format!("Failed to read message length: {}", e)))?;
        
        let len = u32::from_be_bytes(len_bytes) as usize;
        if len > 10 * 1024 * 1024 { // 10MB limit
            return Err(P2PError::Network("Message too large".to_string()));
        }
        
        // Read message data
        let mut message = vec![0u8; len];
        stream.read_exact(&mut message).await
            .map_err(|e| P2PError::Network(format!("Failed to read message: {}", e)))?;
        
        Ok(message)
    }
}

/// Connection information for external use
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub peer_id: PeerId,
    pub established_at: SystemTime,
    pub last_activity: SystemTime,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub is_outbound: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2p_core::NetworkId;
    
    #[tokio::test]
    async fn test_connection_manager_creation() {
        let (manager, _rx) = ConnectionManager::new(10, Duration::from_secs(30));
        assert_eq!(manager.connections.read().await.len(), 0);
    }
}

