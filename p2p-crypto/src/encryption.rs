use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead, OsRng, rand_core::RngCore};
use crate::{KeyMaterial, KeyType, P2PResult, P2PError};

/// Encrypt a plaintext message using AES-256-GCM
pub fn encrypt(key: &KeyMaterial, plaintext: &[u8]) -> P2PResult<(Vec<u8>, Vec<u8>)> {
    if key.key_type != KeyType::Aes256Gcm {
        return Err(P2PError::Crypto("Invalid key type for encryption".into()));
    }
    let cipher = Aes256Gcm::new_from_slice(&key.key_data)
        .map_err(|e| P2PError::Crypto(format!("Invalid key: {e}")))?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| P2PError::Crypto(format!("Encryption failed: {e}")))?;
    Ok((nonce_bytes.to_vec(), ciphertext))
}

/// Decrypt a ciphertext message using AES-256-GCM
pub fn decrypt(key: &KeyMaterial, nonce: &[u8], ciphertext: &[u8]) -> P2PResult<Vec<u8>> {
    if key.key_type != KeyType::Aes256Gcm {
        return Err(P2PError::Crypto("Invalid key type for decryption".into()));
    }
    let cipher = Aes256Gcm::new_from_slice(&key.key_data)
        .map_err(|e| P2PError::Crypto(format!("Invalid key: {e}")))?;
    let nonce = Nonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| P2PError::Crypto(format!("Decryption failed: {e}")))?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_random_bytes;

    #[test]
    fn test_encrypt_decrypt() {
        let key_data = generate_random_bytes(32);
        let key = KeyMaterial::new(KeyType::Aes256Gcm, key_data);
        let msg = b"secret";
        let (nonce, ct) = encrypt(&key, msg).unwrap();
        let pt = decrypt(&key, &nonce, &ct).unwrap();
        assert_eq!(pt, msg);
    }
}
