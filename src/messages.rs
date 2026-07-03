use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum AntiCheatMessage {
    Heartbeat {
        hwid: String,
        pid: u32,
        timestamp: String,
    },
    SuspiciousActivity {
        pid: u32,
        reason: String,
        memory_address: Option<usize>,
        signature_found: Option<String>,
    },
}

#[derive(Deserialize, Debug)]
pub enum BanCommand {
    Ban { hwid: String },
}
