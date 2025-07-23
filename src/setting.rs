use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Settings {
    pub client_key: String,
    pub task: TaskConfig,
    pub proxy: ProxyConfig,
    pub country: String,
    pub funcaptcha_task_proxy: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            client_key: String::new(),
            task: TaskConfig {
                count: 0,
                thread: 5,
            },
            proxy: ProxyConfig {
                mode: String::new(),
                config: ProxyServerConfig {
                    address: String::new(),
                    username: String::new(),
                    password: String::new(),
                },
                china: false,
            },
            country: "US".to_string(),
            funcaptcha_task_proxy: false,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TaskConfig {
    pub count: u32,
    pub thread: u32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EmailSettings {
    pub mode: String,
    pub prefix: PrefixSettings,
    pub suffix: String,
    pub mkt: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PrefixSettings {
    pub letters: String,
    pub numbers: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RegionConfig {
    pub country: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProxyConfig {
    pub mode: String,
    pub config: ProxyServerConfig,
    pub china: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProxyServerConfig {
    pub address: String,
    pub username: String,
    pub password: String,
}
