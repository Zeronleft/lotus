use crate::lua::model::LuaRunTime;
use mlua::UserData;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

macro_rules! set_global_function {
    ($lua:expr, $name:expr, $func:expr) => {
        $lua.globals().set($name, $func).unwrap();
    };
}

// ============================================================================
// SecretsManager - Centralized API key and secrets management
// ============================================================================

#[derive(Clone, Debug)]
pub struct SecretsManager {
    secrets: HashMap<String, String>,
    config_path: Option<PathBuf>,
}

impl Default for SecretsManager {
    fn default() -> Self {
        let mut manager = Self {
            secrets: HashMap::new(),
            config_path: None,
        };
        
        // Auto-load from default locations
        manager.load_from_env();
        manager.load_from_default_config();
        
        manager
    }
}

impl SecretsManager {
    /// Load secrets from environment variables with common prefixes
    fn load_from_env(&mut self) {
        let env_mappings = vec![
            // Shodan
            ("SHODAN_API_KEY", "shodan"),
            ("SHODAN_KEY", "shodan"),
            
            // VirusTotal
            ("VIRUSTOTAL_API_KEY", "virustotal"),
            ("VT_API_KEY", "virustotal"),
            
            // SecurityTrails
            ("SECURITYTRAILS_API_KEY", "securitytrails"),
            ("ST_API_KEY", "securitytrails"),
            
            // Censys
            ("CENSYS_API_ID", "censys_id"),
            ("CENSYS_API_SECRET", "censys_secret"),
            
            // Hunter.io
            ("HUNTER_API_KEY", "hunter"),
            ("HUNTERIO_API_KEY", "hunter"),
            
            // GitHub
            ("GITHUB_TOKEN", "github"),
            ("GH_TOKEN", "github"),
            
            // GitLab
            ("GITLAB_TOKEN", "gitlab"),
            
            // AbuseIPDB
            ("ABUSEIPDB_API_KEY", "abuseipdb"),
            
            // AlienVault OTX
            ("OTX_API_KEY", "otx"),
            ("ALIENVAULT_API_KEY", "otx"),
            
            // BinaryEdge
            ("BINARYEDGE_API_KEY", "binaryedge"),
            
            // Chaos (ProjectDiscovery)
            ("CHAOS_API_KEY", "chaos"),
            ("PDCP_API_KEY", "chaos"),
            
            // Cloudflare
            ("CLOUDFLARE_API_KEY", "cloudflare"),
            ("CF_API_KEY", "cloudflare"),
            
            // PassiveTotal/RiskIQ
            ("PASSIVETOTAL_API_KEY", "passivetotal"),
            ("RISKIQ_API_KEY", "passivetotal"),
            
            // URLScan
            ("URLSCAN_API_KEY", "urlscan"),
            
            // WhoisXML
            ("WHOISXML_API_KEY", "whoisxml"),
            
            // ZoomEye
            ("ZOOMEYE_API_KEY", "zoomeye"),
            
            // Fofa
            ("FOFA_API_KEY", "fofa"),
            ("FOFA_EMAIL", "fofa_email"),
            
            // Netlas
            ("NETLAS_API_KEY", "netlas"),
            
            // FullHunt
            ("FULLHUNT_API_KEY", "fullhunt"),
            
            // Onyphe
            ("ONYPHE_API_KEY", "onyphe"),
            
            // Intelx
            ("INTELX_API_KEY", "intelx"),
            
            // LeakIX
            ("LEAKIX_API_KEY", "leakix"),
            
            // SpiderFoot HX
            ("SPIDERFOOT_API_KEY", "spiderfoot"),
            
            // OpenAI (for LLM tools)
            ("OPENAI_API_KEY", "openai"),
            
            // Anthropic
            ("ANTHROPIC_API_KEY", "anthropic"),
            
            // HuggingFace
            ("HF_TOKEN", "huggingface"),
            ("HUGGINGFACE_TOKEN", "huggingface"),
        ];
        
        for (env_var, key) in env_mappings {
            if let Ok(value) = std::env::var(env_var) {
                if !value.is_empty() {
                    self.secrets.insert(key.to_string(), value);
                }
            }
        }
    }
    
    /// Load from default config locations
    fn load_from_default_config(&mut self) {
        let mut config_paths: Vec<PathBuf> = vec![
            // Current directory
            PathBuf::from(".lotus_secrets"),
            PathBuf::from(".lotus_secrets.json"),
            PathBuf::from("lotus_secrets.json"),
        ];
        
        // Home directory paths
        if let Some(home) = dirs_next::home_dir() {
            config_paths.push(home.join(".lotus_secrets"));
            config_paths.push(home.join(".lotus_secrets.json"));
            config_paths.push(home.join(".config/lotus/secrets.json"));
        }
        
        // XDG config
        if let Some(config) = dirs_next::config_dir() {
            config_paths.push(config.join("lotus/secrets.json"));
        }
        
        for path in config_paths {
            if path.exists() {
                if let Ok(content) = fs::read_to_string(&path) {
                    self.parse_config(&content);
                    self.config_path = Some(path);
                    break;
                }
            }
        }
    }
    
    /// Parse config content (JSON or KEY=VALUE format)
    fn parse_config(&mut self, content: &str) {
        // Try JSON first
        if let Ok(json) = serde_json::from_str::<HashMap<String, String>>(content) {
            for (k, v) in json {
                self.secrets.insert(k.to_lowercase(), v);
            }
            return;
        }
        
        // Try KEY=VALUE format
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim().to_lowercase();
                let value = value.trim().trim_matches('"').trim_matches('\'');
                self.secrets.insert(key, value.to_string());
            }
        }
    }
}

impl UserData for SecretsManager {
    fn add_methods<'lua, M: mlua::UserDataMethods<'lua, Self>>(methods: &mut M) {
        // Get a secret by key
        methods.add_method("get", |_, this, key: String| {
            Ok(this.secrets.get(&key.to_lowercase()).cloned())
        });
        
        // Set a secret (runtime only, not persisted)
        methods.add_method_mut("set", |_, this, (key, value): (String, String)| {
            this.secrets.insert(key.to_lowercase(), value);
            Ok(())
        });
        
        // Check if secret exists
        methods.add_method("has", |_, this, key: String| {
            Ok(this.secrets.contains_key(&key.to_lowercase()))
        });
        
        // Get all secret keys (not values for security)
        methods.add_method("keys", |lua, this, ()| {
            let table = lua.create_table()?;
            for (i, key) in this.secrets.keys().enumerate() {
                table.set(i + 1, key.clone())?;
            }
            Ok(table)
        });
        
        // Load from a specific file
        methods.add_method_mut("load_file", |_, this, path: String| {
            match fs::read_to_string(&path) {
                Ok(content) => {
                    this.parse_config(&content);
                    this.config_path = Some(PathBuf::from(path));
                    Ok(true)
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("Failed to load secrets: {}", e))),
            }
        });
        
        // Save current secrets to file
        methods.add_method("save", |_, this, path: Option<String>| {
            let save_path = path.map(PathBuf::from)
                .or_else(|| this.config_path.clone())
                .unwrap_or_else(|| PathBuf::from(".lotus_secrets.json"));
            
            let json = serde_json::to_string_pretty(&this.secrets)
                .map_err(|e| mlua::Error::RuntimeError(format!("JSON error: {}", e)))?;
            
            fs::write(&save_path, json)
                .map_err(|e| mlua::Error::RuntimeError(format!("Write error: {}", e)))?;
            
            Ok(save_path.to_string_lossy().to_string())
        });
        
        // Reload from environment and config
        methods.add_method_mut("reload", |_, this, ()| {
            this.secrets.clear();
            this.load_from_env();
            this.load_from_default_config();
            Ok(())
        });
        
        // Get multiple secrets as a table
        methods.add_method("get_all", |lua, this, keys: Vec<String>| {
            let table = lua.create_table()?;
            for key in keys {
                if let Some(value) = this.secrets.get(&key.to_lowercase()) {
                    table.set(key.as_str(), value.clone())?;
                }
            }
            Ok(table)
        });
        
        // Require a secret (error if missing)
        methods.add_method("require", |_, this, key: String| {
            match this.secrets.get(&key.to_lowercase()) {
                Some(value) => Ok(value.clone()),
                None => Err(mlua::Error::RuntimeError(format!(
                    "Required secret '{}' not found. Set via environment variable or config file.", 
                    key
                ))),
            }
        });
        
        // Get with default value
        methods.add_method("get_or", |_, this, (key, default): (String, String)| {
            Ok(this.secrets.get(&key.to_lowercase()).cloned().unwrap_or(default))
        });
        
        // Get Shodan API key specifically (common use case)
        methods.add_method("shodan_key", |_, this, ()| {
            Ok(this.secrets.get("shodan").cloned())
        });
        
        // Get VirusTotal API key
        methods.add_method("virustotal_key", |_, this, ()| {
            Ok(this.secrets.get("virustotal").cloned())
        });
        
        // Get GitHub token
        methods.add_method("github_token", |_, this, ()| {
            Ok(this.secrets.get("github").cloned())
        });
        
        // Check what secrets are configured (returns list of available services)
        methods.add_method("configured_services", |lua, this, ()| {
            let table = lua.create_table()?;
            let services = vec![
                "shodan", "virustotal", "securitytrails", "censys_id", "hunter",
                "github", "gitlab", "abuseipdb", "otx", "binaryedge", "chaos",
                "cloudflare", "passivetotal", "urlscan", "whoisxml", "zoomeye",
                "fofa", "netlas", "fullhunt", "onyphe", "intelx", "leakix",
                "spiderfoot", "openai", "anthropic", "huggingface"
            ];
            
            let mut idx = 1;
            for service in services {
                if this.secrets.contains_key(service) {
                    table.set(idx, service)?;
                    idx += 1;
                }
            }
            Ok(table)
        });
    }
}

// ============================================================================
// APIConfig - Pre-configured API endpoints and settings
// ============================================================================

#[derive(Clone, Debug)]
pub struct APIConfig {
    pub endpoints: HashMap<String, String>,
    pub headers: HashMap<String, HashMap<String, String>>,
}

impl Default for APIConfig {
    fn default() -> Self {
        let mut endpoints = HashMap::new();
        let headers = HashMap::new();
        
        // Common API endpoints
        endpoints.insert("shodan".to_string(), "https://api.shodan.io".to_string());
        endpoints.insert("virustotal".to_string(), "https://www.virustotal.com/api/v3".to_string());
        endpoints.insert("abuseipdb".to_string(), "https://api.abuseipdb.com/api/v2".to_string());
        endpoints.insert("urlscan".to_string(), "https://urlscan.io/api/v1".to_string());
        endpoints.insert("securitytrails".to_string(), "https://api.securitytrails.com/v1".to_string());
        endpoints.insert("hunter".to_string(), "https://api.hunter.io/v2".to_string());
        endpoints.insert("censys".to_string(), "https://search.censys.io/api".to_string());
        endpoints.insert("otx".to_string(), "https://otx.alienvault.com/api/v1".to_string());
        endpoints.insert("greynoise".to_string(), "https://api.greynoise.io/v3".to_string());
        endpoints.insert("ipinfo".to_string(), "https://ipinfo.io".to_string());
        endpoints.insert("hackertarget".to_string(), "https://api.hackertarget.com".to_string());
        endpoints.insert("crtsh".to_string(), "https://crt.sh".to_string());
        
        Self { endpoints, headers }
    }
}

impl UserData for APIConfig {
    fn add_methods<'lua, M: mlua::UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method("endpoint", |_, this, service: String| {
            Ok(this.endpoints.get(&service.to_lowercase()).cloned())
        });
        
        methods.add_method_mut("set_endpoint", |_, this, (service, url): (String, String)| {
            this.endpoints.insert(service.to_lowercase(), url);
            Ok(())
        });
        
        methods.add_method("all_endpoints", |lua, this, ()| {
            let table = lua.create_table()?;
            for (k, v) in &this.endpoints {
                table.set(k.as_str(), v.as_str())?;
            }
            Ok(table)
        });
    }
}

// ============================================================================
// SecretsEXT trait implementation
// ============================================================================

pub trait SecretsEXT {
    fn add_secrets_funcs(&self);
}

impl SecretsEXT for LuaRunTime<'_> {
    fn add_secrets_funcs(&self) {
        // Global Secrets manager instance
        set_global_function!(
            self.lua,
            "Secrets",
            SecretsManager::default()
        );
        
        // API configuration
        set_global_function!(
            self.lua,
            "APIConfig",
            APIConfig::default()
        );
        
        // Convenience function: get_secret(key)
        set_global_function!(
            self.lua,
            "get_secret",
            self.lua.create_function(|lua, key: String| {
                let secrets: SecretsManager = lua.globals().get("Secrets")?;
                Ok(secrets.secrets.get(&key.to_lowercase()).cloned())
            }).unwrap()
        );
        
        // Convenience function: require_secret(key) - errors if missing
        set_global_function!(
            self.lua,
            "require_secret",
            self.lua.create_function(|lua, key: String| {
                let secrets: SecretsManager = lua.globals().get("Secrets")?;
                match secrets.secrets.get(&key.to_lowercase()) {
                    Some(value) => Ok(value.clone()),
                    None => Err(mlua::Error::RuntimeError(format!(
                        "Required secret '{}' not found", key
                    ))),
                }
            }).unwrap()
        );
        
        // Convenience function: has_secret(key)
        set_global_function!(
            self.lua,
            "has_secret",
            self.lua.create_function(|lua, key: String| {
                let secrets: SecretsManager = lua.globals().get("Secrets")?;
                Ok(secrets.secrets.contains_key(&key.to_lowercase()))
            }).unwrap()
        );
    }
}

// Add dirs_next for cross-platform directory resolution
// Note: This requires adding dirs-next to Cargo.toml
