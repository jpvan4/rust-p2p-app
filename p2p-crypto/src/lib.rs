/// Comprehensive cryptographic library for P2P security

use std::sync::Arc;
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use p2p_core::{PeerId, P2PResult, P2PError};

pub mod tls;
pub mod encryption;
pub mod key_exchange;
pub mod authentication;
pub mod certificates;

pub use tls::*;
pub use encryption::*;
pub use key_exchange::*;
pub use authentication::*;
pub use certificates::*;

/// Security configuration for the P2P network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable TLS for all connections
    pub enable_tls: bool,
    
    /// Require mutual TLS authentication
    pub require_mtls: bool,
    
    /// Enable end-to-end encryption
    pub enable_e2e_encryption: bool,
    
    /// Key rotation interval in seconds
    pub key_rotation_interval: u64,
    
    /// Certificate validity period in days
    pub cert_validity_days: u32,
    
    /// Minimum TLS version
    pub min_tls_version: TlsVersion,
    
    /// Allowed cipher suites
    pub allowed_ciphers: Vec<CipherSuite>,
    
    /// Enable perfect forward secrecy
    pub enable_pfs: bool,
    
    /// Authentication timeout in seconds
    pub auth_timeout: u64,
}

/// TLS version enumeration
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TlsVersion {
    V1_2,
    V1_3,
}

/// Supported cipher suites
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CipherSuite {
    ChaCha20Poly1305,
    Aes256Gcm,
    Aes128Gcm,
}

/// Cryptographic key material (zeroized on drop)
#[derive(Clone, ZeroizeOnDrop)]
pub struct KeyMaterial {
    #[zeroize(skip)]
    pub key_type: KeyType,
    pub key_data: Vec<u8>,
    pub created_at: SystemTime,
    pub expires_at: Option<SystemTime>,
}

/// Types of cryptographic keys
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Ed25519Signing,
    X25519KeyExchange,
    ChaCha20Poly1305,
    Aes256Gcm,
    TlsPrivateKey,
}

/// Secure session for peer communication
#[derive(Debug)]
pub struct SecureSession {
    pub peer_id: PeerId,
    pub session_id: String,
    pub encryption_key: Arc<KeyMaterial>,
    pub mac_key: Arc<KeyMaterial>,
    pub created_at: SystemTime,
    pub last_activity: SystemTime,
    pub is_authenticated: bool,
}

/// Encrypted message envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub session_id: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub mac: Vec<u8>,
    pub timestamp: u64,
}

/// Authentication challenge for peer verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallenge {
    pub challenge_id: String,
    pub challenge_data: Vec<u8>,
    pub timestamp: u64,
    pub expires_at: u64,
}

/// Authentication response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub challenge_id: String,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
    pub peer_id: PeerId,
    pub timestamp: u64,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_tls: true,
            require_mtls: true,
            enable_e2e_encryption: true,
            key_rotation_interval: 3600, // 1 hour
            cert_validity_days: 365,
            min_tls_version: TlsVersion::V1_3,
            allowed_ciphers: vec![
                CipherSuite::ChaCha20Poly1305,
                CipherSuite::Aes256Gcm,
            ],
            enable_pfs: true,
            auth_timeout: 30,
        }
    }
}

impl KeyMaterial {
    /// Create new key material
    pub fn new(key_type: KeyType, key_data: Vec<u8>) -> Self {
        Self {
            key_type,
            key_data,
            created_at: SystemTime::now(),
            expires_at: None,
        }
    }
    
    /// Create key material with expiration
    pub fn new_with_expiry(key_type: KeyType, key_data: Vec<u8>, expires_in: Duration) -> Self {
        Self {
            key_type,
            key_data,
            created_at: SystemTime::now(),
            expires_at: Some(SystemTime::now() + expires_in),
        }
    }
    
    /// Check if the key has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            SystemTime::now() > expires_at
        } else {
            false
        }
    }
    
    /// Get key age in seconds
    pub fn age_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(self.created_at)
            .unwrap_or_default()
            .as_secs()
    }
}

impl SecureSession {
    /// Create a new secure session
    pub fn new(
        peer_id: PeerId,
        encryption_key: Arc<KeyMaterial>,
        mac_key: Arc<KeyMaterial>,
    ) -> Self {
        Self {
            peer_id,
            session_id: uuid::Uuid::new_v4().to_string(),
            encryption_key,
            mac_key,
            created_at: SystemTime::now(),
            last_activity: SystemTime::now(),
            is_authenticated: false,
        }
    }
    
    /// Update last activity timestamp
    pub fn update_activity(&mut self) {
        self.last_activity = SystemTime::now();
    }
    
    /// Check if session has expired
    pub fn is_expired(&self, timeout: Duration) -> bool {
        SystemTime::now()
            .duration_since(self.last_activity)
            .unwrap_or_default() > timeout
    }
    
    /// Mark session as authenticated
    pub fn authenticate(&mut self) {
        self.is_authenticated = true;
        self.update_activity();
    }
}

impl AuthChallenge {
    /// Create a new authentication challenge
    pub fn new() -> Self {
        let challenge_data = generate_random_bytes(32);
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            challenge_id: uuid::Uuid::new_v4().to_string(),
            challenge_data,
            timestamp: now,
            expires_at: now + 300, // 5 minutes
        }
    }
    
    /// Check if challenge has expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.expires_at
    }
}

impl AuthResponse {
    /// Create a new authentication response
    pub fn new(
        challenge: &AuthChallenge,
        signing_key: &ed25519_dalek::SigningKey,
        peer_id: PeerId,
    ) -> P2PResult<Self> {
        let mut message = Vec::new();
        message.extend_from_slice(&challenge.challenge_data);
        message.extend_from_slice(peer_id.id().as_bytes());
        message.extend_from_slice(&challenge.timestamp.to_be_bytes());
        
        let signature = signing_key.sign(&message).to_bytes().to_vec();
        let public_key = signing_key.verifying_key().to_bytes().to_vec();
        
        Ok(Self {
            challenge_id: challenge.challenge_id.clone(),
            signature,
            public_key,
            peer_id,
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }
    
    /// Verify the authentication response
    pub fn verify(&self, challenge: &AuthChallenge) -> P2PResult<bool> {
        if self.challenge_id != challenge.challenge_id {
            return Ok(false);
        }
        
        if challenge.is_expired() {
            return Ok(false);
        }
        
        // Reconstruct the signed message
        let mut message = Vec::new();
        message.extend_from_slice(&challenge.challenge_data);
        message.extend_from_slice(self.peer_id.id().as_bytes());
        message.extend_from_slice(&challenge.timestamp.to_be_bytes());
        
        // Verify signature
        if self.public_key.len() != 32 || self.signature.len() != 64 {
            return Ok(false);
        }
        
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&self.public_key);
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&self.signature);
        
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|e| P2PError::Crypto(format!("Invalid public key: {}", e)))?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        
        Ok(verifying_key.verify(&message, &signature).is_ok())
    }
}

/// Generate cryptographically secure random bytes
pub fn generate_random_bytes(length: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut bytes = vec![0u8; length];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Derive key from password using Argon2
pub fn derive_key_from_password(password: &str, salt: &[u8]) -> P2PResult<Vec<u8>> {
    use argon2::{Argon2, PasswordHasher};
    use argon2::password_hash::{PasswordHasher as _, SaltString};
    
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| P2PError::Crypto(format!("Invalid salt: {}", e)))?;
    
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| P2PError::Crypto(format!("Key derivation failed: {}", e)))?;
    
    Ok(hash.hash.unwrap().as_bytes().to_vec())
}

/// Constant-time comparison of byte arrays
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use ring::constant_time;
    if a.len() != b.len() {
        return false;
    }
    constant_time::verify_slices_are_equal(a, b).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_security_config_default() {
        let config = SecurityConfig::default();
        assert!(config.enable_tls);
        assert!(config.require_mtls);
        assert!(config.enable_e2e_encryption);
        assert_eq!(config.min_tls_version, TlsVersion::V1_3);
    }
    
    #[test]
    fn test_key_material_creation() {
        let key_data = generate_random_bytes(32);
        let key = KeyMaterial::new(KeyType::ChaCha20Poly1305, key_data.clone());
        
        assert_eq!(key.key_type, KeyType::ChaCha20Poly1305);
        assert_eq!(key.key_data, key_data);
        assert!(!key.is_expired());
    }
    
    #[test]
    fn test_key_material_expiry() {
        let key_data = generate_random_bytes(32);
        let key = KeyMaterial::new_with_expiry(
            KeyType::ChaCha20Poly1305,
            key_data,
            Duration::from_millis(1),
        );
        
        std::thread::sleep(Duration::from_millis(10));
        assert!(key.is_expired());
    }
    
    #[test]
    fn test_auth_challenge_creation() {
        let challenge = AuthChallenge::new();
        assert_eq!(challenge.challenge_data.len(), 32);
        assert!(!challenge.is_expired());
    }
    
    #[test]
    fn test_random_bytes_generation() {
        let bytes1 = generate_random_bytes(32);
        let bytes2 = generate_random_bytes(32);
        
        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2); // Should be different
    }
    
    #[test]
    fn test_constant_time_eq() {
        let a = b"hello world";
        let b = b"hello world";
        let c = b"hello rust!";
        
        assert!(constant_time_eq(a, b));
        assert!(!constant_time_eq(a, c));
        assert!(!constant_time_eq(a, &b"short"));
    }
}

