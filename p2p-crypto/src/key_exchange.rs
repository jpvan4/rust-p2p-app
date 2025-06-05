use x25519_dalek::{EphemeralSecret, PublicKey};
use crate::{KeyMaterial, KeyType, P2PError, P2PResult};

/// Generate an ephemeral X25519 key pair
pub fn generate_keypair() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Derive a shared secret from our secret key and the peer's public key
pub fn derive_shared_secret(secret: EphemeralSecret, peer_public: &PublicKey) -> KeyMaterial {
    let shared = secret.diffie_hellman(peer_public);
    KeyMaterial::new(KeyType::X25519KeyExchange, shared.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange() {
        let (s1, p1) = generate_keypair();
        let (s2, p2) = generate_keypair();
        let k1 = derive_shared_secret(s1, &p2);
        let k2 = derive_shared_secret(s2, &p1);
        assert_eq!(k1.key_data, k2.key_data);
    }
}
