/// Cryptographic utilities and key management

use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};
use crate::{P2PResult, P2PError};
use std::path::Path;
use rand::rngs::OsRng;

/// Ed25519 key pair for peer identity
#[derive(Debug)]
pub struct IdentityKeyPair {
    signing_key: SigningKey,
}

impl IdentityKeyPair {
    /// Generate a new random key pair
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }
    
    /// Load key pair from file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> P2PResult<Self> {
        let data = std::fs::read(path)?;
        if data.len() != 32 {
            return Err(P2PError::Crypto("Invalid key file length".to_string()));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&data);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        Ok(Self { signing_key })
    }
    
    /// Save key pair to file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> P2PResult<()> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, self.signing_key.to_bytes())?;
        Ok(())
    }
    
    /// Get verifying key (public key)
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
    
    /// Get public key bytes
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_bytes().to_vec()
    }
    
    /// Sign data
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.signing_key.sign(data).to_bytes().to_vec()
    }
    
    /// Verify signature
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        if signature.len() != 64 {
            return false;
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);
        let sig = Signature::from_bytes(&sig_bytes);
        self.signing_key.verifying_key().verify(data, &sig).is_ok()
    }
}

/// Verify signature with public key
pub fn verify_signature(public_key: &[u8], data: &[u8], signature: &[u8]) -> bool {
    if public_key.len() != 32 || signature.len() != 64 {
        return false;
    }
    
    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(public_key);
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(signature);
    
    if let Ok(vk) = VerifyingKey::from_bytes(&pk_bytes) {
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify(data, &sig).is_ok()
    } else {
        false
    }
}

/// Hash data using SHA-256
pub fn hash_data(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Hash file contents
pub fn hash_file<P: AsRef<Path>>(path: P) -> P2PResult<Vec<u8>> {
    let data = std::fs::read(path)?;
    Ok(hash_data(&data))
}

/// Secure random bytes generation
pub fn generate_random_bytes(length: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut bytes = vec![0u8; length];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Message authentication code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageAuth {
    pub sender_public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

impl MessageAuth {
    pub fn new(keypair: &IdentityKeyPair, data: &[u8]) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut message = Vec::new();
        message.extend_from_slice(data);
        message.extend_from_slice(&timestamp.to_be_bytes());
        
        let signature = keypair.sign(&message);
        
        Self {
            sender_public_key: keypair.public_key_bytes(),
            signature,
            timestamp,
        }
    }
    
    pub fn verify(&self, data: &[u8]) -> bool {
        let mut message = Vec::new();
        message.extend_from_slice(data);
        message.extend_from_slice(&self.timestamp.to_be_bytes());
        
        verify_signature(&self.sender_public_key, &message, &self.signature)
    }
    
    pub fn is_fresh(&self, max_age_seconds: u64) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        now.saturating_sub(self.timestamp) <= max_age_seconds
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_key_generation() {
        let keypair = IdentityKeyPair::generate();
        let data = b"test message";
        let signature = keypair.sign(data);
        assert!(keypair.verify(data, &signature));
    }
    
    #[test]
    fn test_message_auth() {
        let keypair = IdentityKeyPair::generate();
        let data = b"test message";
        let auth = MessageAuth::new(&keypair, data);
        assert!(auth.verify(data));
        assert!(auth.is_fresh(60)); // 60 seconds
    }
    
    #[test]
    fn test_hash_data() {
        let data = b"test data";
        let hash1 = hash_data(data);
        let hash2 = hash_data(data);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32); // SHA-256 produces 32 bytes
    }
}

