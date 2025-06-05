use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use crate::{KeyMaterial, KeyType};

/// Sign a message with an Ed25519 signing key
pub fn sign_message(key: &SigningKey, message: &[u8]) -> Vec<u8> {
    key.sign(message).to_bytes().to_vec()
}

/// Verify a signature with an Ed25519 verifying key
pub fn verify_message(key: &VerifyingKey, message: &[u8], signature: &[u8]) -> bool {
    if signature.len() != 64 { return false; }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(signature);
    let sig = Signature::from_bytes(&sig_bytes);
    key.verify(message, &sig).is_ok()
}

/// Convert signing key to key material
pub fn signing_key_to_material(key: &SigningKey) -> KeyMaterial {
    KeyMaterial::new(KeyType::Ed25519Signing, key.to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let msg = b"test";
        let sig = sign_message(&key, msg);
        assert!(verify_message(&key.verifying_key(), msg, &sig));
    }
}
