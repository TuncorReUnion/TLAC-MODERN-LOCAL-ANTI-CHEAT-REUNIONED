use tokio::net::{UnixListener, UnixStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde_json;
use crate::messages::{AntiCheatMessage, BanType};
use std::collections::HashSet;

pub struct AntiCheatServer {
    socket_path: String,
    #[allow(dead_code)]
    banned_pids: HashSet<u32>,
}

impl AntiCheatServer {
    pub fn new(socket_path: &str) -> Self {
        Self {
            socket_path: socket_path.to_string(),
            banned_pids: HashSet::new(),
        }
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let _ = std::fs::remove_file(&self.socket_path);

        let listener = UnixListener::bind(&self.socket_path)?;
        println!("🔌 Server listening on {}", self.socket_path);

        loop {
            let (stream, _) = listener.accept().await?;
            tokio::spawn(Self::handle_client(stream));
        }
    }

    async fn handle_client(mut stream: UnixStream) {
        let mut buf = [0u8; 4096];
        
        loop {
            let n = match stream.read(&mut buf).await {
                Ok(0) => break,  
                Ok(n) => n,
                Err(e) => {
                    eprintln!("❌ Read error: {}", e);
                    break;
                }
            };

            if let Ok(msg) = serde_json::from_slice::<AntiCheatMessage>(&buf[..n]) {
                match msg {
                    AntiCheatMessage::Heartbeat { pid, timestamp } => {
                        println!("💓 Heartbeat from PID {} at {}", pid, timestamp);
                        let ack = AntiCheatMessage::Ack { message: "OK".to_string() };
                        let _ = stream.write_all(&serde_json::to_vec(&ack).unwrap()).await;
                    }
                    AntiCheatMessage::SuspiciousActivity { pid, reason, .. } => {
                        println!("⚠️ Suspicious activity from PID {}: {}", pid, reason);
                        let ban_cmd = AntiCheatMessage::BanCommand {
                            pid,
                            ban_type: BanType::Permanent,
                            reason: format!("Cheat detected: {}", reason),
                        };
                        let _ = stream.write_all(&serde_json::to_vec(&ban_cmd).unwrap()).await;
                    }
                    AntiCheatMessage::BanCommand { pid, ban_type, reason } => {
                        println!("🚫 Banning PID {} ({:?}): {}", pid, ban_type, reason);
                    }
                    AntiCheatMessage::Ack { message } => {
                        println!("✅ Ack: {}", message);
                    }
                }
            }
        }
    }
}
