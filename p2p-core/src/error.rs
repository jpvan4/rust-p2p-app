use thiserror::Error;

/// Core error types for the P2P application
#[derive(Error, Debug)]
pub enum P2PError {
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("Cryptographic error: {0}")]
    Crypto(String),
    
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("File system error: {0}")]
    FileSystem(String),
    
    #[error("Authentication failed: {0}")]
    Authentication(String),
    
    #[error("Authorization failed: {0}")]
    Authorization(String),
    
    #[error("Peer not found: {0}")]
    PeerNotFound(String),
    
    #[error("Transfer error: {0}")]
    Transfer(String),
    
    #[error("Timeout error: {0}")]
    Timeout(String),
    
    #[error("Invalid data: {0}")]
    InvalidData(String),
    
    #[error("Internal error: {0}")]
    Internal(String),
}

pub type P2PResult<T> = Result<T, P2PError>;

impl From<std::io::Error> for P2PError {
    fn from(err: std::io::Error) -> Self {
        P2PError::FileSystem(err.to_string())
    }
}

impl From<serde_json::Error> for P2PError {
    fn from(err: serde_json::Error) -> Self {
        P2PError::Serialization(err.to_string())
    }
}

impl From<bincode::Error> for P2PError {
    fn from(err: bincode::Error) -> Self {
        P2PError::Serialization(err.to_string())
    }
}

