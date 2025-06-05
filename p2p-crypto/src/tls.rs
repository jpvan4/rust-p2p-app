/// TLS/mTLS implementation for secure P2P connections

use std::sync::Arc;
use std::io::{self, BufReader};
use std::fs::File;
use std::path::Path;
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};
use rustls::{Certificate, PrivateKey, ServerConfig, ClientConfig, RootCertStore};
use sha2::Digest;
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
            .map_err(|e| P2PError::Tls(format!("TLS accept failed: {}", e)))?
            .into();
        
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
            .map_err(|e| P2PError::Tls(format!("TLS connect failed: {}", e)))?
            .into();
        
        Ok(SecureTcpStream {
            stream: tls_stream,
            peer_id: None, // Will be set after authentication
            is_server: false,
        })
    }
    
    /// Verify peer certificate and extract peer ID
/// Verify peer certificate and extract peer ID
    pub fn verify_peer_certificate(&self, stream: &SecureTcpStream) -> P2PResult<PeerId> {
        let (_, session) = stream.stream.get_ref();
        if let Some(peer_certificates) = session.peer_certificates() {
            if let Some(cert) = peer_certificates.first() {
                // Extract peer ID from certificate
                let cert_der = &cert.0;
                // Try to parse the certificate
                if let Ok(x509) = x509_parser::parse_x509_certificate(cert_der) {
                    let x509 = x509.1;
                    // Check Subject Alternative Names
                    if let Some(san_ext) = x509.extensions().iter().find(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME) {
                        if let Ok(san) = x509_parser::extensions::GeneralNames::try_from(san_ext) {
                            for name in san.general_names.iter() {
                                if let x509_parser::extensions::GeneralName::URI(uri) = name {
                                    if uri.starts_with("peerId:") {
                                        let id_str = &uri[7..]; // Skip "peerId:"
                                        if let Ok(decoded) = hex::decode(id_str) {
                                            let network_id = p2p_core::NetworkId::new("default".to_string());
                                            return Ok(PeerId::new(decoded, network_id));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // Try custom extension with OID 1.3.6.1.4.1.53594.1.1 (example OID)
                    let peer_id_oid = x509_parser::oid_registry::Oid::from(vec![1, 3, 6, 1, 4, 1, 53594, 1, 1]);
                    if let Some(peer_id_ext) = x509.extensions().iter().find(|e| e.oid == peer_id_oid) {
                        if let Ok(peer_id_bytes) = hex::decode(peer_id_ext.value.as_slice()) {
                            let network_id = p2p_core::NetworkId::new("default".to_string());
                            return Ok(PeerId::new(peer_id_bytes, network_id));
                        }
                    }
                    
                    // Try Common Name in subject
                    if let Some(cn) = x509.subject().iter_common_name().next() {
                        if let Ok(cn_str) = cn.as_str() {
                            if cn_str.starts_with("peerId:") {
                                let id_str = &cn_str[7..]; // Skip "peerId:"
                                if let Ok(decoded) = hex::decode(id_str) {
                                    let network_id = p2p_core::NetworkId::new("default".to_string());
                                    return Ok(PeerId::new(decoded, network_id));
                                }
                            }
                        }
                    }
                }
                
                // Fallback: derive peer ID from certificate hash
                let peer_id_bytes = sha2::Sha256::digest(cert_der).to_vec();
                let network_id = p2p_core::NetworkId::new("default".to_string());
                let cert_der = cert.0.clone();
                let peer_id_bytes = sha2::Sha256::digest(&cert_der).to_vec();
                
                // Create peer ID from certificate hash
                let network_id = p2p_core::NetworkId::new("default".to_string());
                let peer_id = PeerId::new(
                    peer_id_bytes,
                    network_id,
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
    let builder = ServerConfig::builder().with_safe_defaults();
    let builder = if security_config.require_mtls {
        let ca_path = ca_cert_path.ok_or_else(|| P2PError::Tls("mTLS requires CA certificate".into()))?;
        let ca_certs = load_certificates(ca_path)?;
        let mut root_store = RootCertStore::empty();
        for cert in ca_certs {
            root_store.add(&cert)
                .map_err(|e| P2PError::Tls(format!("Failed to add CA certificate: {}", e)))?;
        }
        builder.with_client_cert_verifier(
            Arc::new(rustls::server::AllowAnyAuthenticatedClient::new(root_store))
        )
    } else {
        builder.with_no_client_auth()
    };
    let server_config = builder.with_single_cert(cert_chain, private_key)
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
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    // Add custom CA certificates if provided
    if let Some(ca_path) = ca_cert_path {
        let ca_certs = load_certificates(ca_path)?;
        for cert in ca_certs {
            root_store.add(&cert)
                .map_err(|e| P2PError::Tls(format!("Failed to add CA certificate: {}", e)))?;
        }
    }
    let builder = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store);
    let config = if security_config.require_mtls {
        builder.with_client_auth_cert(cert_chain, private_key)
            .map_err(|e| P2PError::Tls(format!("Failed to configure client certificate: {}", e)))?
    } else {
        builder.with_no_client_auth()
    };
    Ok(config)
}
/// Get cipher suites from configuration
fn get_cipher_suites(_allowed_ciphers: &[CipherSuite]) -> &'static [rustls::SupportedCipherSuite] {
    // In a production environment, we want to use only the most secure cipher suites
    // TLS 1.3 cipher suites are preferred as they're more secure
    rustls::DEFAULT_CIPHER_SUITES
}

/// Get protocol versions from configuration
static PROTO_ALL: [&'static rustls::SupportedProtocolVersion; 2] = [
    &rustls::version::TLS12,
    &rustls::version::TLS13,
];
static PROTO_13: [&'static rustls::SupportedProtocolVersion; 1] = [
    &rustls::version::TLS13,
];
fn get_protocol_versions(min_version: TlsVersion) -> &'static [&'static rustls::SupportedProtocolVersion] {
    match min_version {
        TlsVersion::V1_2 => &PROTO_ALL,
        TlsVersion::V1_3 => &PROTO_13,
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

