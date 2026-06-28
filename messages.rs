use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AntiCheatMessage
{
    Heartbeat
    {
        pid: u32,
        timestamp: u64,
    },
    SuspiciousActivity
    {
        pid: u32,
        reason: String,
        memory_address: Option<u64>,
        signature_found: Option<Vec<u8>>,
    },
    BanCommand
    {
        pid: u32,
        ban_type: BanType,
        reason: String,
    },
    Ack
    {
        message: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum BanType
{
    Temporary { duration_seconds: u64 },
    Permanent,
    HardwareId,
    IpAddress,
}
