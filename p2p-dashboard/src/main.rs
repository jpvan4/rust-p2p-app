use std::sync::Arc;
use p2p_core::NetworkConfig;
use p2p_network::NetworkManager;
use p2p_dashboard::DashboardServer;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let network = NetworkManager::new(NetworkConfig::default())
        .await
        .expect("network init failed");
    let server = DashboardServer::new("127.0.0.1:8080".into(), Arc::new(network));
    server.run().await
}
