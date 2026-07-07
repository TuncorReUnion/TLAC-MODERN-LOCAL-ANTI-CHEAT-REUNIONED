use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::net::UnixListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use log::{info, warn, error};

use crate::messages::{AntiCheatMessage, BanCommand};

pub struct ServerState {
    pub banned_hwids: Arc<Mutex<HashMap<String, String>>>,
}

impl ServerState {
    pub fn new() -> Self {
        ServerState {
            banned_hwids: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

pub async fn run_server(socket_path: &str, state: Arc<ServerState>) -> Result<(), Box<dyn std::error::Error>> {
    if std::path::Path::new(socket_path).exists() {
        std::fs::remove_file(socket_path)?;
    }

    let listener = UnixListener::bind(socket_path)?;
    info!("🚀 Anti-Cheat Server listening on {}", socket_path);

    loop {
        match listener.accept().await {
            Ok((mut stream, _addr)) => {
                let state_clone = state.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if let Ok(msg) = serde_json::from_slice::<AntiCheatMessage>(&buf[..n]) {
                                    match msg {
                                        AntiCheatMessage::Heartbeat { hwid, pid, timestamp } => {
                                            info!("💓 Heartbeat from HWID: {} (PID: {}) at {}", hwid, pid, timestamp);
                                            
                                            let ban_reason = {
                                                let bans = state_clone.banned_hwids.lock().unwrap();
                                                bans.get(&hwid).cloned()
                                            }; // ← MutexGuard burada drop edildi

                                            if let Some(reason) = ban_reason {
                                                let ban_cmd = BanCommand::Ban { hwid: hwid.clone() };
                                                if let Ok(json) = serde_json::to_vec(&ban_cmd) {
                                                    if let Err(e) = stream.write_all(&json).await {
                                                        error!("Failed to send BanCommand: {}", e);
                                                    } else {
                                                        warn!("🚨 Sent BanCommand to HWID: {} (Reason: {})", hwid, reason);
                                                    }
                                                }
                                            }
                                        }
                                        AntiCheatMessage::SuspiciousActivity { pid, reason, memory_address, signature_found } => {
                                            warn!("⚠️ Suspicious Activity reported for PID {}: {} (Addr: {:?}, Sig: {:?})", 
                                                  pid, reason, memory_address, signature_found);
                                        }
                                    }
                                } else {
                                    warn!("Received invalid JSON message");
                                }
                            }
                            Err(e) => {
                                error!("Socket read error: {}", e);
                                break;
                            }
                        }
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}
