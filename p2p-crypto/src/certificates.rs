use rcgen::{Certificate, CertificateParams, DistinguishedName};
use crate::{KeyMaterial, KeyType, P2PResult, P2PError};

/// Generate a self-signed certificate for the given domain name
pub fn generate_self_signed(domain: &str) -> P2PResult<(Certificate, KeyMaterial)> {
    let mut params = CertificateParams::new(vec![domain.to_string()]);
    params.distinguished_name = DistinguishedName::new();
    let cert = Certificate::from_params(params)
        .map_err(|e| P2PError::Crypto(format!("Certificate generation failed: {e}")))?;
    let key = KeyMaterial::new(KeyType::TlsPrivateKey, cert.serialize_private_key_der());
    Ok((cert, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate() {
        let (cert, _key) = generate_self_signed("example.com").unwrap();
        assert!(cert.serialize_der().is_ok());
    }
}
