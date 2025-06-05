use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use crate::{NetworkConfig, P2PResult, P2PError};

/// Application configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub network: NetworkConfig,
    pub storage: StorageConfig,
    pub security: SecurityConfig,
    pub dashboard: DashboardConfig,
    pub tor: TorConfig,
    pub logging: LoggingConfig,
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub data_dir: PathBuf,
    pub max_storage: Option<u64>, // bytes
    pub cleanup_interval: u64, // seconds
    pub retention_days: u32,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub key_file: PathBuf,
    pub cert_file: Option<PathBuf>,
    pub require_authentication: bool,
    pub max_failed_attempts: u32,
    pub session_timeout: u64, // seconds
}

/// Dashboard configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    pub enabled: bool,
    pub bind_address: String,
    pub port: u16,
    pub admin_password: Option<String>,
    pub tls_enabled: bool,
}

/// Tor configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorConfig {
    pub enabled: bool,
    pub socks_port: u16,
    pub control_port: u16,
    pub data_dir: PathBuf,
    pub hidden_service: bool,
    pub bridge_mode: bool,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file: Option<PathBuf>,
    pub max_size: u64, // bytes
    pub max_files: u32,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(),
            storage: StorageConfig::default(),
            security: SecurityConfig::default(),
            dashboard: DashboardConfig::default(),
            tor: TorConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
            max_storage: Some(10 * 1024 * 1024 * 1024), // 10GB
            cleanup_interval: 3600, // 1 hour
            retention_days: 30,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            key_file: PathBuf::from("./keys/identity.key"),
            cert_file: None,
            require_authentication: true,
            max_failed_attempts: 5,
            session_timeout: 3600, // 1 hour
        }
    }
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port: 8080,
            admin_password: None,
            tls_enabled: false,
        }
    }
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            socks_port: 9050,
            control_port: 9051,
            data_dir: PathBuf::from("./tor"),
            hidden_service: false,
            bridge_mode: false,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file: Some(PathBuf::from("./logs/p2p.log")),
            max_size: 100 * 1024 * 1024, // 100MB
            max_files: 10,
        }
    }
}

impl AppConfig {
    /// Load configuration from file
    pub fn load_from_file(path: &PathBuf) -> P2PResult<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| P2PError::Config(format!("Failed to read config file: {}", e)))?;
        
        let config: AppConfig = toml::from_str(&content)
            .map_err(|e| P2PError::Config(format!("Failed to parse config: {}", e)))?;
        
        Ok(config)
    }
    
    /// Save configuration to file
    pub fn save_to_file(&self, path: &PathBuf) -> P2PResult<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| P2PError::Config(format!("Failed to serialize config: {}", e)))?;
        
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        std::fs::write(path, content)
            .map_err(|e| P2PError::Config(format!("Failed to write config file: {}", e)))?;
        
        Ok(())
    }
    
    /// Validate configuration
    pub fn validate(&self) -> P2PResult<()> {
        // Validate network configuration
        if self.network.max_connections == 0 {
            return Err(P2PError::Config("max_connections must be greater than 0".to_string()));
        }
        
        // Validate storage configuration
        if !self.storage.data_dir.is_absolute() {
            return Err(P2PError::Config("data_dir must be an absolute path".to_string()));
        }
        
        // Validate dashboard configuration
        if self.dashboard.enabled && self.dashboard.port == 0 {
            return Err(P2PError::Config("dashboard port must be specified when enabled".to_string()));
        }
        
        Ok(())
    }
}

