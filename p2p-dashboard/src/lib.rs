use actix_web::{web, App, HttpServer, Responder, HttpResponse};

use p2p_network::NetworkManager;
use std::sync::Arc;

/// Simple dashboard HTTP server
pub struct DashboardServer {
    address: String,
    network: Arc<NetworkManager>,
}

impl DashboardServer {
    pub fn new(address: String, network: Arc<NetworkManager>) -> Self {
        Self { address, network }
    }

    /// Run the dashboard server
    pub async fn run(self) -> std::io::Result<()> {
        let data = self.network.clone();
        HttpServer::new(move || {
            App::new()
                .app_data(web::Data::new(data.clone()))
                .route("/", web::get().to(index))

                .route("/peers", web::get().to(get_peers))
        })
        .bind(&self.address)?
        .run()
        .await
    }
}

async fn get_peers(network: web::Data<Arc<NetworkManager>>) -> impl Responder {
    let peers = network.get_peers().await;
    let list: Vec<String> = peers.keys().map(|p| p.to_string()).collect();
    web::Json(list)
}


async fn index() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html")
        .body("<h1>P2P Dashboard</h1>")
}


