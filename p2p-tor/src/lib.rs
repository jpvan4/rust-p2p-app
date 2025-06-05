use arti_client::{TorClient, TorClientConfig, DataStream};
use tor_rtcompat::PreferredRuntime;
use p2p_core::{P2PResult, P2PError};

/// Manage Tor connectivity for the P2P application
pub struct TorManager {
    client: TorClient<PreferredRuntime>,
}

impl TorManager {
    /// Bootstrap a new Tor client
    pub async fn new() -> P2PResult<Self> {
        let config = TorClientConfig::default();
        let client = TorClient::create_bootstrapped(config)
            .await
            .map_err(|e| P2PError::Network(format!("Tor bootstrap failed: {e}")))?;
        Ok(Self { client })
    }

    /// Connect to a remote address through Tor
    pub async fn connect(&self, addr: (&str, u16)) -> P2PResult<DataStream> {
        self.client
            .connect((addr.0, addr.1))
            .await
            .map_err(|e| P2PError::Network(format!("Tor connect failed: {e}")))
    }

    /// Access underlying Tor client
    pub fn client(&self) -> &TorClient<PreferredRuntime> {
        &self.client
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create() {
        // Tor bootstrap may fail without network access, but creation should
        // still return an error rather than panic
        let _ = TorManager::new().await.err();
    }
}
