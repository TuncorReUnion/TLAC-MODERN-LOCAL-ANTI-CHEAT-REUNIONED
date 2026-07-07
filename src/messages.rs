use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiCheatMessage {
    pub pid: u32,
    pub event_type: String,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanCommand {
    pub hwid: String,
    pub reason: String,
    pub timestamp: u64,
}
