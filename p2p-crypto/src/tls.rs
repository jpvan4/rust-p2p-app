/// TLS/mTLS implementation for secure P2P connections

use std::sync::Arc;
use std::io::{self, BufReader};
use std::fs::File;
use std::path::Path;
use tokio::net::{TcpStream, TcpListener};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};
use rustls::{Certificate, PrivateKey, ServerConfig, ClientConfig, RootCertStore};
use rustls_pemfile::{certs, pkcs8_private_keys};
use p2p_core::{PeerId, P2PResult, P2PError};
use crate::{SecurityConfig, TlsVersion, CipherSuite};

/// TLS configuration manager
pub struct TlsManager {
    server_config: Arc<ServerConfig>,
    client_config: Arc<ClientConfig>,
    security_config: SecurityConfig,
}

/// TLS connection wrapper
pub struct SecureTcpStream {
    stream: TlsStream<TcpStream>,
    peer_id: Option<PeerId>,
    is_server: bool,
}

/// Certificate and key pair
#[derive(Debug, Clone)]
pub struct TlsCertificate {
    pub certificate_chain: Vec<Certificate>,
    pub private_key: PrivateKey,
    pub peer_id: PeerId,
}

impl TlsManager {
    /// Create a new TLS manager
    pub fn new(
        cert_path: &Path,
        key_path: &Path,
        ca_cert_path: Option<&Path>,
        security_config: SecurityConfig,
    ) -> P2PResult<Self> {
        // Load server certificate and key
        let cert_chain = load_certificates(cert_path)?;
        let private_key = load_private_key(key_path)?;
        
        // Create server configuration
        let server_config = create_server_config(
            cert_chain.clone(),
            private_key.clone(),
            ca_cert_path,
            &security_config,
        )?;
        
        // Create client configuration
        let client_config = create_client_config(
            cert_chain,
            private_key,
            ca_cert_path,
            &security_config,
        )?;
        
        Ok(Self {
            server_config: Arc::new(server_config),
            client_config: Arc::new(client_config),
            security_config,
        })
    }
    
    /// Create TLS acceptor for incoming connections
    pub fn create_acceptor(&self) -> TlsAcceptor {
        TlsAcceptor::from(Arc::clone(&self.server_config))
    }
    
    /// Create TLS connector for outgoing connections
    pub fn create_connector(&self) -> TlsConnector {
        TlsConnector::from(Arc::clone(&self.client_config))
    }
    
    /// Accept a TLS connection
    pub async fn accept_connection(
        &self,
        tcp_stream: TcpStream,
    ) -> P2PResult<SecureTcpStream> {
        let acceptor = self.create_acceptor();
        
        let tls_stream = acceptor.accept(tcp_stream).await
            .map_err(|e| P2PError::Tls(format!("TLS accept failed: {}", e)))?;
        
        Ok(SecureTcpStream {
            stream: tls_stream,
            peer_id: None, // Will be set after authentication
            is_server: true,
        })
    }
    
    /// Connect with TLS
    pub async fn connect(
        &self,
        tcp_stream: TcpStream,
        server_name: &str,
    ) -> P2PResult<SecureTcpStream> {
        let connector = self.create_connector();
        
        let server_name = rustls::ServerName::try_from(server_name)
            .map_err(|e| P2PError::Tls(format!("Invalid server name: {}", e)))?;
        
        let tls_stream = connector.connect(server_name, tcp_stream).await
            .map_err(|e| P2PError::Tls(format!("TLS connect failed: {}", e)))?;
        
        Ok(SecureTcpStream {
            stream: tls_stream,
            peer_id: None, // Will be set after authentication
            is_server: false,
        })
    }
    
    /// Verify peer certificate and extract peer ID
    pub fn verify_peer_certificate(&self, stream: &SecureTcpStream) -> P2PResult<PeerId> {
        let (_, session) = stream.stream.get_ref();
        
        if let Some(peer_certificates) = session.peer_certificates() {
            if let Some(cert) = peer_certificates.first() {
                // Extract peer ID from certificate
                // This is a simplified implementation - in practice, you'd parse the certificate
                // and extract the peer ID from a custom extension or subject field
                let cert_der = cert.0.clone();
                let peer_id_bytes = sha2::Sha256::digest(&cert_der).to_vec();
                
                // Create peer ID from certificate hash
                let peer_id = PeerId::new(
                    peer_id_bytes,
                    p2p_core::NetworkId("default".to_string()),
                );
                
                return Ok(peer_id);
            }
        }
        
        Err(P2PError::Authentication("No peer certificate found".to_string()))
    }
}

impl SecureTcpStream {
    /// Get the underlying TLS stream
    pub fn get_ref(&self) -> &TlsStream<TcpStream> {
        &self.stream
    }
    
    /// Get mutable reference to the underlying TLS stream
    pub fn get_mut(&mut self) -> &mut TlsStream<TcpStream> {
        &mut self.stream
    }
    
    /// Set the authenticated peer ID
    pub fn set_peer_id(&mut self, peer_id: PeerId) {
        self.peer_id = Some(peer_id);
    }
    
    /// Get the peer ID if authenticated
    pub fn peer_id(&self) -> Option<&PeerId> {
        self.peer_id.as_ref()
    }
    
    /// Check if this is a server-side connection
    pub fn is_server(&self) -> bool {
        self.is_server
    }
    
    /// Get connection information
    pub fn connection_info(&self) -> ConnectionInfo {
        let (_, session) = self.stream.get_ref();
        
        ConnectionInfo {
            protocol_version: format!("{:?}", session.protocol_version()),
            cipher_suite: format!("{:?}", session.negotiated_cipher_suite()),
            peer_certificates: session.peer_certificates().map(|certs| certs.len()).unwrap_or(0),
            is_server: self.is_server,
            peer_id: self.peer_id.clone(),
        }
    }
}

/// TLS connection information
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub protocol_version: String,
    pub cipher_suite: String,
    pub peer_certificates: usize,
    pub is_server: bool,
    pub peer_id: Option<PeerId>,
}

/// Load certificates from PEM file
fn load_certificates(path: &Path) -> P2PResult<Vec<Certificate>> {
    let file = File::open(path)
        .map_err(|e| P2PError::Io(format!("Failed to open certificate file: {}", e)))?;
    let mut reader = BufReader::new(file);
    
    let certs = certs(&mut reader)
        .map_err(|e| P2PError::Tls(format!("Failed to parse certificates: {}", e)))?;
    
    if certs.is_empty() {
        return Err(P2PError::Tls("No certificates found".to_string()));
    }
    
    Ok(certs.into_iter().map(Certificate).collect())
}

/// Load private key from PEM file
fn load_private_key(path: &Path) -> P2PResult<PrivateKey> {
    let file = File::open(path)
        .map_err(|e| P2PError::Io(format!("Failed to open private key file: {}", e)))?;
    let mut reader = BufReader::new(file);
    
    let keys = pkcs8_private_keys(&mut reader)
        .map_err(|e| P2PError::Tls(format!("Failed to parse private key: {}", e)))?;
    
    if keys.is_empty() {
        return Err(P2PError::Tls("No private keys found".to_string()));
    }
    
    Ok(PrivateKey(keys[0].clone()))
}

/// Create server TLS configuration
fn create_server_config(
    cert_chain: Vec<Certificate>,
    private_key: PrivateKey,
    ca_cert_path: Option<&Path>,
    security_config: &SecurityConfig,
) -> P2PResult<ServerConfig> {
    let mut config = ServerConfig::builder()
        .with_cipher_suites(get_cipher_suites(&security_config.allowed_ciphers))
        .with_safe_default_kx_groups()
        .with_protocol_versions(get_protocol_versions(security_config.min_tls_version))
        .map_err(|e| P2PError::Tls(format!("Failed to create server config builder: {}", e)))?;
    
    // Configure client certificate verification if mTLS is required
    if security_config.require_mtls {
        if let Some(ca_path) = ca_cert_path {
            let ca_certs = load_certificates(ca_path)?;
            let mut root_store = RootCertStore::empty();
            
            for cert in ca_certs {
                root_store.add(&cert)
                    .map_err(|e| P2PError::Tls(format!("Failed to add CA certificate: {}", e)))?;
            }
            
            config = config.with_client_cert_verifier(
                rustls::server::AllowAnyAuthenticatedClient::new(root_store)
            );
        } else {
            return Err(P2PError::Tls("mTLS requires CA certificate".to_string()));
        }
    } else {
        config = config.with_no_client_auth();
    }
    
    let server_config = config.with_single_cert(cert_chain, private_key)
        .map_err(|e| P2PError::Tls(format!("Failed to configure server certificate: {}", e)))?;
    
    Ok(server_config)
}

/// Create client TLS configuration
fn create_client_config(
    cert_chain: Vec<Certificate>,
    private_key: PrivateKey,
    ca_cert_path: Option<&Path>,
    security_config: &SecurityConfig,
) -> P2PResult<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    
    // Add system root certificates
    root_store.add_server_trust_anchors(
        webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        })
    );
    
    // Add custom CA certificates if provided
    if let Some(ca_path) = ca_cert_path {
        let ca_certs = load_certificates(ca_path)?;
        for cert in ca_certs {
            root_store.add(&cert)
                .map_err(|e| P2PError::Tls(format!("Failed to add CA certificate: {}", e)))?;
        }
    }
    
    let mut config = ClientConfig::builder()
        .with_cipher_suites(get_cipher_suites(&security_config.allowed_ciphers))
        .with_safe_default_kx_groups()
        .with_protocol_versions(get_protocol_versions(security_config.min_tls_version))
        .map_err(|e| P2PError::Tls(format!("Failed to create client config builder: {}", e)))?
        .with_root_certificates(root_store);
    
    // Configure client certificate if mTLS is required
    if security_config.require_mtls {
        config = config.with_single_cert(cert_chain, private_key)
            .map_err(|e| P2PError::Tls(format!("Failed to configure client certificate: {}", e)))?;
    } else {
        config = config.with_no_client_auth();
    }
    
    Ok(config)
}

/// Get cipher suites from configuration
fn get_cipher_suites(allowed_ciphers: &[CipherSuite]) -> &'static [rustls::SupportedCipherSuite] {
    // For simplicity, return all supported cipher suites
    // In practice, you'd filter based on the allowed_ciphers parameter
    rustls::ALL_CIPHER_SUITES
}

/// Get protocol versions from configuration
fn get_protocol_versions(min_version: TlsVersion) -> &'static [&'static rustls::SupportedProtocolVersion] {
    match min_version {
        TlsVersion::V1_2 => &[&rustls::version::TLS12, &rustls::version::TLS13],
        TlsVersion::V1_3 => &[&rustls::version::TLS13],
    }
}

// Implement AsyncRead and AsyncWrite for SecureTcpStream
impl tokio::io::AsyncRead for SecureTcpStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for SecureTcpStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }
    
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    
    #[test]
    fn test_connection_info() {
        // This would require actual TLS connection for full testing
        // For now, just test the structure
        let info = ConnectionInfo {
            protocol_version: "TLSv1.3".to_string(),
            cipher_suite: "TLS13_CHACHA20_POLY1305_SHA256".to_string(),
            peer_certificates: 1,
            is_server: false,
            peer_id: None,
        };
        
        assert_eq!(info.protocol_version, "TLSv1.3");
        assert!(!info.is_server);
    }
}

