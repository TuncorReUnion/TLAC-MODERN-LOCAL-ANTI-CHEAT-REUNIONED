use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Duration as StdDuration;
use tokio::net::UnixStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, Duration};
use rusqlite::Connection;
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};
use nix::sys::ptrace;
use nix::unistd::Pid;
use procfs::process::Process;
use hex;
use log::{warn, error};

use anti_cheat::messages::{AntiCheatMessage, BanCommand};
use anti_cheat::sync_client::SyncClient;

use aya::Ebpf;
use aya::util::online_cpus;
use aya::maps::perf::PerfEventArray;

mod proc_status;
use proc_status::{read_kernel_status, KernelStatus};

mod messages;
mod sync_client;

#[derive(Deserialize, Serialize, Debug, Default)]
struct AntiCheatConfig {
    expected_binary_hash: String,
    version: String,
    #[serde(default = "default_interval")]
    scan_interval_ms: u64,
    log_path: String,
}

fn default_interval() -> u64 { 5000 }

fn get_config_path() -> PathBuf {
    if let Ok(path) = env::var("TLAC_CONFIG") {
        return PathBuf::from(path);
    }

    let home_dir = if let Ok(user) = env::var("SUDO_USER") {
        PathBuf::from("/home").join(user)
    } else {
        env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/root"))
    };

    home_dir.join(".config").join("tlac").join("config.json")
}

fn load_config() -> Result<AntiCheatConfig, Box<dyn std::error::Error>> {
    let path = get_config_path();

    if !path.exists() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let default = AntiCheatConfig::default();
        std::fs::write(&path, serde_json::to_string_pretty(&default)?)?;
        eprintln!("⚠️ Config dosyası bulunamadı, varsayılan oluşturuldu: {:?}", path);
    }

    let content = std::fs::read_to_string(&path)?;
    let config: AntiCheatConfig = serde_json::from_str(&content)?;
    Ok(config)
}

fn calculate_binary_hash() -> Result<String, Box<dyn std::error::Error>> {
    let exe_path = env::current_exe()?;
    let content = fs::read(exe_path)?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let result = hasher.finalize();
    Ok(hex::encode(result))
}

fn verify_binary_integrity(expected_hash: &str) -> Result<(), Box<dyn std::error::Error>> {
    if expected_hash.is_empty() {
        eprintln!("⚠️ Binary hash kontrolü atlandı (expected_hash boş)");
        return Ok(());
    }

    let current_hash = calculate_binary_hash()?;
    if current_hash != expected_hash {
        return Err(format!(
            "!!! BINARY TAMPERING DETECTED!\nExpected: {}\nGot: {}",
            expected_hash, current_hash
        ).into());
    }
    println!("✅ Binary integrity verified.");
    Ok(())
}

fn generate_hwid() -> String {
    let mut hasher = Sha256::new();

    if let Ok(uuid) = fs::read_to_string("/sys/class/dmi/id/product_uuid") {
        hasher.update(uuid.trim());
    }

    if let Ok(mac) = fs::read_to_string("/sys/class/net/eth0/address") {
        hasher.update(mac.trim());
    } else if let Ok(mac) = fs::read_to_string("/sys/class/net/wlan0/address") {
        hasher.update(mac.trim());
    }

    if let Ok(serial) = fs::read_to_string("/sys/block/sda/device/serial") {
        hasher.update(serial.trim());
    }

    format!("{:x}", hasher.finalize())
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

fn ban_hwid(conn: &Connection, hwid: &str, reason: &str) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT OR IGNORE INTO hwid_bans (hwid, reason) VALUES (?1, ?2)",
        [hwid, reason],
    )?;
    Ok(())
}

fn is_hwid_banned(conn: &Connection, hwid: &str) -> std::result::Result<bool, Box<dyn std::error::Error>> {
    let count: u32 = conn.query_row(
        "SELECT COUNT(*) FROM hwid_bans WHERE hwid = ?1",
        [hwid],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

#[derive(Debug, Clone)]
struct FoundCheat {
    name: String,
    address: usize,
    severity: String,
}

#[derive(Deserialize, Debug, Clone)]
struct SignatureFile {
    signatures: Vec<CheatSignature>,
}

#[derive(Deserialize, Debug, Clone)]
struct CheatSignature {
    id: String,
    name: String,
    pattern: String,
    severity: String,
    memory_regions: Vec<String>,
}

fn parse_pattern(pattern_str: &str) -> Vec<Option<u8>> {
    if pattern_str.trim().is_empty() {
        return Vec::new();
    }

    pattern_str.split_whitespace()
        .filter_map(|byte| {
            if byte == "?" || byte == "*" {
                Some(None)
            } else {
                u8::from_str_radix(byte, 16).ok().map(Some)
            }
        })
        .collect()
}

fn load_signatures() -> Result<Vec<CheatSignature>, Box<dyn std::error::Error>> {
    let sig_path = PathBuf::from("/etc/tlac/signatures.json");
    let content = fs::read_to_string(&sig_path)?;
    let file: SignatureFile = serde_json::from_str(&content)?;
    Ok(file.signatures)
}

const MAX_REGION_SIZE: usize = 256 * 1024 * 1024;

fn read_memory_range(pid: u32, start: usize, len: usize) -> nix::Result<Vec<u8>> {
    if len == 0 || len > MAX_REGION_SIZE {
        eprintln!("⚠️ Bölge atlandı: start={:#x}, len={} (max: {})", start, len, MAX_REGION_SIZE);
        return Ok(Vec::new());
    }

    let mut data = Vec::with_capacity(len.min(MAX_REGION_SIZE));
    let pid = Pid::from_raw(pid as i32);

    for offset in (0..len).step_by(4) {
        if offset >= MAX_REGION_SIZE { break; }

        let addr = (start + offset) as *mut std::ffi::c_void;
        match ptrace::read(pid, addr) {
            Ok(word) => data.extend_from_slice(&word.to_ne_bytes()),
            Err(_) => break,
        }
    }
    Ok(data)
}

fn search_pattern_in_bytes(bytes: &[u8], pattern: &[u8]) -> Option<usize> {
    bytes.windows(pattern.len()).position(|window| window == pattern)
}

fn search_wildcard_pattern_in_bytes(bytes: &[u8], pattern: &[Option<u8>]) -> Option<usize> {
    if pattern.is_empty() || bytes.is_empty() {
        return None;
    }

    let pat_len = pattern.len();
    let bytes_len = bytes.len();

    if pat_len > bytes_len {
        return None;
    }

    let max_start_index = bytes_len - pat_len;

    for i in 0..=max_start_index {
        let mut matched = true;

        for j in 0..pat_len {
            if i + j >= bytes_len {
                matched = false;
                break;
            }

            if let Some(expected_byte) = pattern[j] {
                if bytes[i + j] != expected_byte {
                    matched = false;
                    break;
                }
            }
        }

        if matched {
            return Some(i);
        }
    }
    None
}

fn search_wildcard_pattern_in_memory(pid: u32, start: usize,
                                     
