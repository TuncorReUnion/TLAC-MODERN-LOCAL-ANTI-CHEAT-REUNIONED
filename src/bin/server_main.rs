use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::Mutex;
use tokio::net::{UnixListener, UnixStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Deserialize, Serialize};
use serde_json;
use log::{info, error, warn};
use rusqlite::Connection;

type SharedState = Arc<Mutex<ServerState>>;

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

pub struct ServerState {
    pub banned_hwids: HashMap<String, String>,
    pub connections: Vec<UnixStream>,
}

impl ServerState {
    pub fn new() -> Self {
        Self {
            banned_hwids: HashMap::new(),
            connections: Vec::new(),
        }
    }

    pub fn add_ban(&mut self, hwid: &str, reason: &str) {
        self.banned_hwids.insert(hwid.to_string(), reason.to_string());
        info!("HWID banned: {} ({})", hwid, reason);
    }

    pub fn is_banned(&self, hwid: &str) -> bool {
        self.banned_hwids.contains_key(hwid)
    }
}

fn init_db() -> Result<Connection, Box<dyn std::error::Error>> {
    let db_path = "/var/lib/tlac/anti_cheat.db";
    if let Some(parent) = std::path::Path::new(db_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(db_path)?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS hwid_bans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hwid TEXT NOT NULL UNIQUE,
            reason TEXT DEFAULT 'Cheating detected',
            banned_at TEXT DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;
    Ok(conn)
}

fn load_bans_from_db(conn: &Connection) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut stmt = conn.prepare("SELECT hwid, reason FROM hwid_bans")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get(0)?, row.get(1)?))
    })?;
    
    let mut bans = HashMap::new();
    for row in rows {
        let (hwid, reason) = row?;
        bans.insert(hwid, reason);
    }
    Ok(bans)
}

fn save_ban_to_db(conn: &Connection, hwid: &str, reason: &str) -> Result<(), Box<dyn std::error::Error>> {
    conn.execute(
        "INSERT OR IGNORE INTO hwid_bans (hwid, reason) VALUES (?1, ?2)",
        [hwid, reason],
    )?;
    Ok(())
}

async fn handle_client(mut stream: UnixStream, state: SharedState, conn: Connection) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = vec![0u8; 4096];
    
    loop {
        let n = match stream.read(&mut buf).await {
            Ok(n) if n == 0 => {
                info!("Client disconnected");
                break;
            }
            Ok(n) => n,
            Err(e) => {
                error!("Read error: {}", e);
                break;
            }
        };

        let data = &buf[..n];
        if let Ok(msg) = serde_json::from_slice::<AntiCheatMessage>(data) {
            info!("Received message: {:?}", msg);
            
            match msg.event_type.as_str() {
                "SuspiciousActivity" => {
                    if let Some(hwid) = msg.data.get("hwid").and_then(|v| v.as_str()) {
                        let mut state_lock = state.lock().await;
                        state_lock.add_ban(hwid, &format!("Suspicious activity from PID: {}", msg.pid));
                        if let Err(e) = save_ban_to_db(&conn, hwid, &format!("Suspicious activity from PID: {}", msg.pid)) {
                            error!("Failed to save ban to DB: {}", e);
                        }
                    }
                }
                "CheckBan" => {
                    if let Some(hwid) = msg.data.get("hwid").and_then(|v| v.as_str()) {
                        let state_lock = state.lock().await;
                        let is_banned = state_lock.is_banned(hwid);
                        let response = serde_json::json!({
                            "type": "BanStatus",
                            "hwid": hwid,
                            "banned": is_banned,
                            "reason": if is_banned { state_lock.banned_hwids.get(hwid) } else { None }
                        });
                        let response_data = serde_json::to_vec(&response)?;
                        if let Err(e) = stream.write_all(&response_data).await {
                            error!("Failed to send response: {}", e);
                        }
                    }
                }
                "SyncBans" => {
                    let state_lock = state.lock().await;
                    let bans: Vec<serde_json::Value> = state_lock.banned_hwids
                        .iter()
                        .map(|(hwid, reason)| {
                            serde_json::json!({
                                "hwid": hwid,
                                "reason": reason,
                                "banned_at": chrono::Utc::now().to_rfc3339()
                            })
                        })
                        .collect();
                    let response = serde_json::json!({
                        "type": "BanList",
                        "bans": bans
                    });
                    let response_data = serde_json::to_vec(&response)?;
                    if let Err(e) = stream.write_all(&response_data).await {
                        error!("Failed to send response: {}", e);
                    }
                }
                _ => {
                    warn!("Unknown event type: {}", msg.event_type);
                }
            }
        } else {
            error!("Failed to parse message");
        }
    }
    
    Ok(())
}

pub async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    let socket_path = "/tmp/anti-cheat.sock";
    
    if std::path::Path::new(socket_path).exists() {
        std::fs::remove_file(socket_path)?;
    }
    
    let listener = UnixListener::bind(socket_path)?;
    info!("Server listening on {}", socket_path);
    
    let state = Arc::new(Mutex::new(ServerState::new()));
    let conn = init_db()?;
    
    if let Ok(bans) = load_bans_from_db(&conn) {
        let mut state_lock = state.lock().await;
        for (hwid, reason) in bans {
            state_lock.banned_hwids.insert(hwid, reason);
        }
        info!("Loaded {} bans from database", state_lock.banned_hwids.len());
    }
    
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                info!("New client connected");
                let state_clone = state.clone();
                let conn_clone = init_db()?;
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, state_clone, conn_clone).await {
                        error!("Client handler error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Accept error: {}", e);
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    run_server().await
}
