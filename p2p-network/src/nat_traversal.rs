/// NAT traversal mechanisms for P2P connectivity

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use serde::{Deserialize, Serialize};
use p2p_core::{PeerId, PeerAddress, AddressType, P2PResult, P2PError};
use stunclient::StunClient;
use igd::aio::search_gateway;
use igd::PortMappingProtocol;

/// NAT traversal service
pub struct NatTraversalService {
    local_addr: SocketAddr,
    stun_servers: Vec<String>,
    upnp_enabled: bool,
}

// Legacy STUN message type retained for backward compatibility (unused)
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StunMessage {
    BindingRequest { transaction_id: [u8; 12] },
    BindingResponse { transaction_id: [u8; 12], mapped_address: SocketAddr },
    BindingError { transaction_id: [u8; 12], error_code: u16, reason: String },
}

/// UPnP port mapping request
#[derive(Debug, Clone)]
pub struct PortMapping {
    pub external_port: u16,
    pub internal_port: u16,
    pub protocol: Protocol,
    pub description: String,
    pub duration: Duration,
}

/// Network protocol types
#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    TCP,
    UDP,
}

/// NAT traversal result
#[derive(Debug, Clone)]
pub struct TraversalResult {
    pub method: TraversalMethod,
    pub external_address: Option<SocketAddr>,
    pub success: bool,
    pub error: Option<String>,
}

/// NAT traversal methods
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraversalMethod {
    Direct,
    UPnP,
    STUN,
    TURN,
    HolePunching,
}

impl NatTraversalService {
    /// Create a new NAT traversal service
    pub fn new(local_addr: SocketAddr, upnp_enabled: bool) -> Self {
        Self {
            local_addr,
            stun_servers: vec![
                "stun.l.google.com:19302".to_string(),
                "stun1.l.google.com:19302".to_string(),
                "stun2.l.google.com:19302".to_string(),
            ],
            upnp_enabled,
        }
    }
    
    /// Attempt to establish connectivity using various methods
    pub async fn establish_connectivity(&self) -> P2PResult<Vec<TraversalResult>> {
        let mut results = Vec::new();
        
        // Try direct connection first
        results.push(self.test_direct_connectivity().await);
        
        // Try UPnP if enabled
        if self.upnp_enabled {
            results.push(self.try_upnp_mapping().await);
        }
        
        // Try STUN for external address discovery
        results.push(self.discover_external_address().await);
        
        // Try hole punching (placeholder)
        results.push(self.attempt_hole_punching().await);
        
        Ok(results)
    }
    
    /// Test direct connectivity
    async fn test_direct_connectivity(&self) -> TraversalResult {
        // Test if we can bind to the local address
        match UdpSocket::bind(self.local_addr).await {
            Ok(_) => TraversalResult {
                method: TraversalMethod::Direct,
                external_address: Some(self.local_addr),
                success: true,
                error: None,
            },
            Err(e) => TraversalResult {
                method: TraversalMethod::Direct,
                external_address: None,
                success: false,
                error: Some(e.to_string()),
            },
        }
    }
    
    /// Try UPnP port mapping
    async fn try_upnp_mapping(&self) -> TraversalResult {
        log::debug!("Attempting UPnP port mapping");

        let mapping = PortMapping {
            external_port: self.local_addr.port(),
            internal_port: self.local_addr.port(),
            protocol: Protocol::TCP,
            description: "P2P Application".to_string(),
            duration: Duration::from_secs(3600), // 1 hour
        };

        match search_gateway(Default::default()).await {
            Ok(gateway) => match gateway.get_external_ip().await {
                Ok(ip) => {
                    let protocol = match mapping.protocol {
                        Protocol::TCP => PortMappingProtocol::TCP,
                        Protocol::UDP => PortMappingProtocol::UDP,
                    };

                    let internal_v4 = match self.local_addr {
                        SocketAddr::V4(v4) => v4,
                        SocketAddr::V6(_) => {
                            return TraversalResult {
                                method: TraversalMethod::UPnP,
                                external_address: None,
                                success: false,
                                error: Some("UPnP only supports IPv4 addresses".to_string()),
                            };
                        }
                    };

                    match gateway
                        .add_port(
                            protocol,
                            mapping.external_port,
                            internal_v4,
                            mapping.duration.as_secs() as u32,
                            &mapping.description,
                        )
                        .await
                    {
                        Ok(()) => TraversalResult {
                            method: TraversalMethod::UPnP,
                            external_address: Some(SocketAddr::new(IpAddr::V4(ip), mapping.external_port)),
                            success: true,
                            error: None,
                        },
                        Err(e) => TraversalResult {
                            method: TraversalMethod::UPnP,
                            external_address: None,
                            success: false,
                            error: Some(e.to_string()),
                        },
                    }
                }
                Err(e) => TraversalResult {
                    method: TraversalMethod::UPnP,
                    external_address: None,
                    success: false,
                    error: Some(e.to_string()),
                },
            },
            Err(e) => TraversalResult {
                method: TraversalMethod::UPnP,
                external_address: None,
                success: false,
                error: Some(e.to_string()),
            },
        }
    }
    
    /// Discover external address using STUN
    async fn discover_external_address(&self) -> TraversalResult {
        for stun_server in &self.stun_servers {
            match self.stun_request(stun_server).await {
                Ok(external_addr) => {
                    return TraversalResult {
                        method: TraversalMethod::STUN,
                        external_address: Some(external_addr),
                        success: true,
                        error: None,
                    };
                }
                Err(e) => {
                    log::debug!("STUN request to {} failed: {}", stun_server, e);
                    continue;
                }
            }
        }
        
        TraversalResult {
            method: TraversalMethod::STUN,
            external_address: None,
            success: false,
            error: Some("All STUN servers failed".to_string()),
        }
    }
    
    /// Perform STUN request
    async fn stun_request(&self, stun_server: &str) -> P2PResult<SocketAddr> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| P2PError::Network(format!("Failed to bind UDP socket: {}", e)))?;

        let server_addr: SocketAddr = stun_server
            .parse()
            .map_err(|e| P2PError::Network(format!("Invalid STUN server address: {}", e)))?;

        let client = StunClient::new(server_addr);
        client
            .query_external_address_async(&socket)
            .await
            .map_err(|e| P2PError::Network(format!("STUN request failed: {}", e)))
    }
    
    /// Attempt UDP hole punching
    async fn attempt_hole_punching(&self) -> TraversalResult {
        log::debug!("Attempting UDP hole punching");

        if let Some(server) = self.stun_servers.first() {
            match self.stun_request(server).await {
                Ok(addr) => TraversalResult {
                    method: TraversalMethod::HolePunching,
                    external_address: Some(addr),
                    success: true,
                    error: None,
                },
                Err(e) => TraversalResult {
                    method: TraversalMethod::HolePunching,
                    external_address: None,
                    success: false,
                    error: Some(e.to_string()),
                },
            }
        } else {
            TraversalResult {
                method: TraversalMethod::HolePunching,
                external_address: None,
                success: false,
                error: Some("No STUN servers configured".to_string()),
            }
        }
    }
    
    /// Coordinate hole punching with a peer
    pub async fn coordinate_hole_punch(&self, peer_id: &PeerId, peer_addr: &PeerAddress) -> P2PResult<SocketAddr> {
        log::debug!("Coordinating hole punch with peer {:?} at {}", peer_id, peer_addr.address);
        let target: SocketAddr = format!("{}:{}", peer_addr.address, peer_addr.port)
            .parse()
            .map_err(|e| P2PError::Network(format!("Invalid peer address: {}", e)))?;

        let socket = UdpSocket::bind(self.local_addr)
            .await
            .map_err(|e| P2PError::Network(format!("Failed to bind UDP socket: {}", e)))?;

        socket
            .send_to(b"punch", target)
            .await
            .map_err(|e| P2PError::Network(format!("Failed to send punch packet: {}", e)))?;

        let mut buf = [0u8; 16];
        let (_len, addr) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
            .await
            .map_err(|_| P2PError::Timeout("Hole punch timeout".to_string()))?
            .map_err(|e| P2PError::Network(format!("Failed to receive punch response: {}", e)))?;

        Ok(addr)
    }
    
    /// Get recommended connection addresses
    pub async fn get_connection_addresses(&self) -> Vec<PeerAddress> {
        let mut addresses = Vec::new();
        
        // Add local address
        addresses.push(PeerAddress {
            address: self.local_addr.ip().to_string(),
            port: self.local_addr.port(),
            address_type: match self.local_addr.ip() {
                IpAddr::V4(_) => AddressType::IPv4,
                IpAddr::V6(_) => AddressType::IPv6,
            },
            last_successful: None,
            success_count: 0,
            failure_count: 0,
        });
        
        // Try to discover external address
        if let Ok(results) = self.establish_connectivity().await {
            for result in results {
                if result.success {
                    if let Some(external_addr) = result.external_address {
                        addresses.push(PeerAddress {
                            address: external_addr.ip().to_string(),
                            port: external_addr.port(),
                            address_type: match external_addr.ip() {
                                IpAddr::V4(_) => AddressType::IPv4,
                                IpAddr::V6(_) => AddressType::IPv6,
                            },
                            last_successful: None,
                            success_count: 0,
                            failure_count: 0,
                        });
                    }
                }
            }
        }
        
        addresses
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::TCP => write!(f, "TCP"),
            Protocol::UDP => write!(f, "UDP"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    
    #[tokio::test]
    async fn test_nat_traversal_service_creation() {
        let local_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080));
        let service = NatTraversalService::new(local_addr, true);
        assert_eq!(service.local_addr, local_addr);
        assert!(service.upnp_enabled);
    }
    
    #[tokio::test]
    async fn test_get_connection_addresses() {
        let local_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080));
        let service = NatTraversalService::new(local_addr, false);
        
        let addresses = service.get_connection_addresses().await;
        assert!(!addresses.is_empty());
        assert_eq!(addresses[0].port, 8080);
    }
}

