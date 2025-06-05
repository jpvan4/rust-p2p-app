use p2p_core::{AppConfig, P2PResult, PeerAddress};
use p2p_network::NetworkManager;

/// High level client for interacting with the P2P network
pub struct P2PClient {
    network: NetworkManager,
    config: AppConfig,
}

impl P2PClient {
    /// Create a new client from configuration
    pub async fn new(config: AppConfig) -> P2PResult<Self> {
        let network = NetworkManager::new(config.network.clone()).await?;
        Ok(Self { network, config })
    }

    /// Start networking services
    pub async fn start(&mut self) -> P2PResult<()> {
        self.network.start().await
    }

    /// Connect to a peer using a textual address in the form host:port
    pub async fn connect(&mut self, addr: &str) -> P2PResult<()> {
        let parts: Vec<_> = addr.split(':').collect();
        if parts.len() != 2 {
            return Err(p2p_core::P2PError::Network("invalid address".into()));
        }
        let peer_addr = PeerAddress {
            address: parts[0].to_string(),
            port: parts[1].parse().unwrap_or(0),
            address_type: p2p_core::AddressType::Domain,
            last_successful: None,
            success_count: 0,
            failure_count: 0,
        };
        self.network.connect_to_peer(&peer_addr).await
    }

    /// Get list of known peers
    pub async fn peers(&self) -> std::collections::HashMap<p2p_core::PeerId, p2p_network::PeerInfo> {
        self.network.get_peers().await
    }
}

