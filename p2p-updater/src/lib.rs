use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use semver::Version;
use serde::Deserialize;
use reqwest::Client;
use p2p_core::{P2PResult, P2PError};

/// Information about an available update
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateManifest {
    pub version: String,
    pub download_url: String,
    pub signature: String,
    pub changelog: String,
}

/// Simple software updater
pub struct Updater {
    client: Client,
    current: Version,
    manifest_url: String,
    verifying_key: VerifyingKey,
}

impl Updater {
    /// Create a new updater instance
    pub fn new(current_version: &str, manifest_url: String, public_key: &[u8]) -> P2PResult<Self> {
        let current = Version::parse(current_version)
            .map_err(|e| P2PError::InvalidData(format!("invalid version: {e}")))?;
        let key_arr: [u8; 32] = public_key
            .try_into()
            .map_err(|_| P2PError::Crypto("invalid public key length".into()))?;
        let verifying_key = VerifyingKey::from_bytes(&key_arr)
            .map_err(|e| P2PError::Crypto(format!("invalid public key: {e}")))?;
        Ok(Self {
            client: Client::new(),
            current,
            manifest_url,
            verifying_key,
        })
    }

    /// Check the manifest endpoint for updates
    pub async fn check_for_update(&self) -> P2PResult<Option<UpdateManifest>> {
        let resp = self
            .client
            .get(&self.manifest_url)
            .send()
            .await
            .map_err(|e| P2PError::Network(format!("manifest fetch failed: {e}")))?;
        let manifest: UpdateManifest = resp
            .json()
            .await
            .map_err(|e| P2PError::Serialization(format!("manifest decode failed: {e}")))?;
        let new_version = Version::parse(&manifest.version)
            .map_err(|e| P2PError::InvalidData(format!("invalid version in manifest: {e}")))?;
        if new_version > self.current {
            Ok(Some(manifest))
        } else {
            Ok(None)
        }
    }

    /// Download an update file
    pub async fn download_update(&self, url: &str) -> P2PResult<Vec<u8>> {
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| P2PError::Network(format!("download failed: {e}")))?;
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| P2PError::Network(format!("download error: {e}")))?;
        Ok(bytes.to_vec())
    }

    /// Verify update data against the provided base64 signature
    pub fn verify_update(&self, data: &[u8], signature_b64: &str) -> P2PResult<bool> {
        let sig_bytes = base64::decode(signature_b64)
            .map_err(|e| P2PError::InvalidData(format!("invalid signature: {e}")))?;
        if sig_bytes.len() != 64 {
            return Ok(false);
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = Signature::from_bytes(&sig_arr);
        Ok(self.verifying_key.verify(data, &sig).is_ok())
    }

    /// Apply an update (placeholder implementation)
    pub async fn apply_update(&self, _data: &[u8]) -> P2PResult<()> {
        // In a real implementation this would replace binaries safely
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[tokio::test]
    async fn test_verify() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let data = b"test";
        let sig = key.sign(data).to_bytes();
        let up = Updater::new("0.1.0", "http://localhost".into(), &key.verifying_key().to_bytes()).unwrap();
        let sig_b64 = base64::encode(sig);
        assert!(up.verify_update(data, &sig_b64).unwrap());
    }
}
