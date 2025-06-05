/// Messaging protocols for P2P communication

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use p2p_core::{PeerId, Message, P2PResult, P2PError};

/// Message router for handling different message types
pub struct MessageRouter {
    handlers: HashMap<String, Box<dyn MessageHandler + Send + Sync>>,
}

/// Trait for handling specific message types
pub trait MessageHandler {
    fn handle_message(&self, from: &PeerId, message: &[u8]) -> P2PResult<Option<Vec<u8>>>;
    fn message_type(&self) -> &str;
}

/// Message envelope for network transmission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMessage {
    pub message_type: String,
    pub sender: PeerId,
    pub recipient: Option<PeerId>,
    pub payload: Vec<u8>,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

impl MessageRouter {
    /// Create a new message router
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }
    
    /// Register a message handler
    pub fn register_handler(&mut self, handler: Box<dyn MessageHandler + Send + Sync>) {
        let message_type = handler.message_type().to_string();
        self.handlers.insert(message_type, handler);
    }
    
    /// Route an incoming message to the appropriate handler
    pub fn route_message(&self, from: &PeerId, message: NetworkMessage) -> P2PResult<Option<Vec<u8>>> {
        if let Some(handler) = self.handlers.get(&message.message_type) {
            handler.handle_message(from, &message.payload)
        } else {
            log::warn!("No handler for message type: {}", message.message_type);
            Ok(None)
        }
    }
    
    /// Create a network message from a core message
    pub fn create_network_message(
        &self,
        sender: PeerId,
        recipient: Option<PeerId>,
        message: Message,
    ) -> P2PResult<NetworkMessage> {
        let message_type = match &message {
            Message::Control(_) => "control",
            Message::Data(_) => "data",
            Message::File(_) => "file",
            Message::Update(_) => "update",
        }.to_string();
        
        let payload = serde_json::to_vec(&message)?;
        
        Ok(NetworkMessage {
            message_type,
            sender,
            recipient,
            payload,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            signature: Vec::new(), // Would be filled by crypto layer
        })
    }
}

impl Default for MessageRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// Default message handler for control messages
pub struct ControlMessageHandler;

impl MessageHandler for ControlMessageHandler {
    fn handle_message(&self, from: &PeerId, message: &[u8]) -> P2PResult<Option<Vec<u8>>> {
        log::debug!("Handling control message from {:?}: {} bytes", from, message.len());
        // Implementation would handle specific control message types
        Ok(None)
    }
    
    fn message_type(&self) -> &str {
        "control"
    }
}

/// Default message handler for data messages
pub struct DataMessageHandler;

impl MessageHandler for DataMessageHandler {
    fn handle_message(&self, from: &PeerId, message: &[u8]) -> P2PResult<Option<Vec<u8>>> {
        log::debug!("Handling data message from {:?}: {} bytes", from, message.len());
        // Implementation would handle specific data message types
        Ok(None)
    }
    
    fn message_type(&self) -> &str {
        "data"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2p_core::NetworkId;
    
    #[test]
    fn test_message_router_creation() {
        let router = MessageRouter::new();
        assert_eq!(router.handlers.len(), 0);
    }
    
    #[test]
    fn test_register_handler() {
        let mut router = MessageRouter::new();
        router.register_handler(Box::new(ControlMessageHandler));
        assert_eq!(router.handlers.len(), 1);
    }
}

