use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::UnixStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use rusqlite::Connection;
use sha2::{Sha256, Digest};
use serde::Deserialize;
use nix::sys::ptrace;
use nix::unistd::Pid;
use procfs::process::Process;
use hex;
use log::{warn, error, info};

use anti_cheat::messages::{AntiCheatMessage, BanCommand};
use anti_cheat::sync_client::SyncClient;

mod proc_status;
use proc_status::{read_kernel_status, KernelStatus};

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

#[derive(Debug, Clone)]
struct FoundCheat {
    name: String,
    address: usize,
    severity: String,
}

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

fn calculate_binary_hash() -> Result<String, Box<dyn std::error::Error>> {
    let exe_path = env::current_exe()?;
    let content = fs::read(exe_path)?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    Ok(hex::encode(hasher.finalize()))
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

fn is_hwid_banned(conn: &Connection, hwid: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let count: u32 = conn.query_row(
        "SELECT COUNT(*) FROM hwid_bans WHERE hwid = ?1",
        [hwid],
        |row| row.get(0),
    )?;
    Ok(count > 0)
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
        return Ok(Vec::new());
    }
    let mut data = Vec::with_capacity(len.min(MAX_REGION_SIZE));
    let pid_nix = Pid::from_raw(pid as i32);
    for offset in (0..len).step_by(4) {
        if offset >= MAX_REGION_SIZE { break; }
        let addr = (start + offset) as *mut std::ffi::c_void;
        match ptrace::read(pid_nix, addr) {
            Ok(word) => data.extend_from_slice(&word.to_ne_bytes()),
            Err(_) => break,
        }
    }
    Ok(data)
}

fn search_wildcard_pattern_in_bytes(bytes: &[u8], pattern: &[Option<u8>]) -> Option<usize> {
    if pattern.is_empty() || bytes.is_empty() || pattern.len() > bytes.len() {
        return None;
    }
    let max_start_index = bytes.len() - pattern.len();
    for i in 0..=max_start_index {
        let mut matched = true;
        for j in 0..pattern.len() {
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

fn search_wildcard_pattern_in_memory(pid: u32, start: usize, len: usize, pattern: &[Option<u8>]) -> Option<usize> {
    if let Ok(memory) = read_memory_range(pid, start, len) {
        if let Some(pos) = search_wildcard_pattern_in_bytes(&memory, pattern) {
            return Some(start + pos);
        }
    }
    None
}

async fn scan_all_signatures(pid: u32) -> Result<Vec<FoundCheat>, Box<dyn std::error::Error>> {
    let sigs = match load_signatures() {
        Ok(s) => s,
        Err(e) => {
            warn!("⚠️ Signature dosyası yüklenemedi: {}. Tarama atlanıyor.", e);
            return Ok(Vec::new());
        }
    };
    let mut found = Vec::new();
    let proc = Process::new(pid as i32)?;
    let pid_nix = Pid::from_raw(pid as i32);
    match ptrace::attach(pid_nix) {
        Ok(_) => {}
        Err(e) => {
            error!("❌ ptrace attach failed for PID {}: {}. Bu işlem temiz kabul edilemez!", pid, e);
            return Err(format!("ptrace_attach_failed: {}", e).into());
        }
    }
    for map in proc.maps()? {
        let region_size = map.address.1 - map.address.0;
        if region_size == 0 || region_size > MAX_REGION_SIZE as u64 {
            continue;
        }
        let is_exec = map.perms.contains(procfs::process::MMPermissions::EXECUTE);
        let is_writable = map.perms.contains(procfs::process::MMPermissions::WRITE);
        for sig in &sigs {
            let should_scan = sig.memory_regions.iter().any(|r| match r.to_lowercase().as_str() {
                "executable" => is_exec,
                "writable" => is_writable,
                _ => true,
            });
            if !should_scan { continue; }
            let pattern = parse_pattern(&sig.pattern);
            if pattern.is_empty() { continue; }
            let start = map.address.0 as usize;
            let len = region_size as usize;
            if let Some(offset) = search_wildcard_pattern_in_memory(pid, start, len, &pattern) {
                found.push(FoundCheat {
                    name: sig.name.clone(),
                    address: offset,
                    severity: sig.severity.clone(),
                });
            }
        }
    }
    let _ = ptrace::detach(pid_nix, None);
    Ok(found)
}

async fn send_to_server(socket_path: &str, msg: &AntiCheatMessage) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = UnixStream::connect(socket_path).await?;
    let data = serde_json::to_vec(msg)?;
    stream.write_all(&data).await?;
    Ok(())
}

async fn report_suspicious_activity(pid: u32, reason: String, socket_path: &str) {
    let msg = AntiCheatMessage::SuspiciousActivity {
        pid,
        reason,
        memory_address: None,
        signature_found: None,
    };
    if let Err(e) = send_to_server(socket_path, &msg).await {
        error!("❌ Failed to report to server: {}", e);
    }
}

fn get_embedded_hash() -> &'static str {
    include_str!("../bin_hash.txt")
}

fn verify_binary_integrity() -> Result<(), Box<dyn std::error::Error>> {
    let expected = get_embedded_hash().trim();
    
    if expected.is_empty() {
        warn!("⚠️ Binary hash embed edilmemiş (ilk derleme). Integrity check atlanıyor.");
        return Ok(());
    }

    let current_hash = calculate_binary_hash()?;
    if current_hash != expected {
        return Err(format!(
            "!!! BINARY TAMPERING DETECTED!\nExpected: {}\nGot: {}",
            expected, current_hash
        ).into());
    }
    info!("✅ Binary integrity verified.");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    if let Err(e) = verify_binary_integrity() {
        error!("🚨 KRİTİK: Binary değiştirilmiş! Sistem kapatılıyor. ({})", e);
        std::process::exit(1);
    }

    let pid: u32 = std::env::args()
        .nth(1)
        .expect("❌ Hata: PID belirtilmedi! Kullanım: ./Anti-Cheat <pid>")
        .parse()
        .expect("❌ Hata: PID geçerli bir sayı olmalı!");

    let hwid = generate_hwid();
    let conn = init_db().expect("Veritabanı açılamadı");

    if is_hwid_banned(&conn, &hwid)? {
        error!("🚫 DONANIM BANLI! Sistem başlatılamıyor.");
        std::process::exit(1);
    }

    match read_kernel_status() {
        KernelStatus::Clean => info!("🛡️ Sistem temiz."),
        KernelStatus::Suspicious => {
            warn!("⚠️ UYARI: Sistemde şüpheli aktivite tespit edildi!");
            let _ = ban_hwid(&conn, &hwid, "Kernel modülü şüpheli aktivite tespit etti");
            error!("🚫 Sistem kapatılıyor.");
            std::process::exit(1);
        }
        KernelStatus::Error(e) => warn!("🛡️ Kernel modül hatası: {}", e),
    }

    let local_count: u32 = conn.query_row(
        "SELECT COUNT(*) FROM hwid_bans", [], |row| row.get(0)
    ).unwrap_or(0);

    let sync_client = SyncClient::new("http://127.0.0.1:5000");
    match sync_client.sync_bans(&hwid, local_count).await {
        Ok(sync_data) => {
            info!("📥 Sunucudan {} ban alındı.", sync_data.bans.len());
            for ban in &sync_data.bans {
                let _ = conn.execute(
                    "INSERT OR IGNORE INTO hwid_bans (hwid, reason, banned_at) VALUES (?1, ?2, ?3)",
                    [&ban.hwid, &ban.reason, &ban.banned_at],
                );
            }
        }
        Err(e) => warn!("⚠️ Sync başarısız, yerel veritabanı kullanılıyor: {}", e),
    }

    if is_hwid_banned(&conn, &hwid)? {
        error!("🚫 DONANIM BANLI! Sistem başlatılamıyor.");
        std::process::exit(1);
    }

    info!("✅ HWID temiz: {}", hwid);

    // Ban komutlarını dinleyen arka plan görevi
    tokio::spawn(async move {
        let mut stream = match UnixStream::connect("/tmp/anti-cheat.sock").await {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to connect to /tmp/anti-cheat.sock: {}", e);
                return;
            }
        };
        let mut buf = [0u8; 1024];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Ok(cmd) = serde_json::from_slice::<BanCommand>(&buf[..n]) {
                        match cmd {
                            BanCommand::Ban { hwid } => {
                                warn!("🚨 BAN RECEIVED for HWID: {}", hwid);
                                let conn = match Connection::open("/var/lib/tlac/anti_cheat.db") {
                                    Ok(c) => c,
                                    Err(e) => {
                                        error!("Failed to open DB for ban: {}", e);
                                        continue;
                                    }
                                };
                                if let Err(e) = ban_hwid(&conn, &hwid, "Received ban command from server") {
                                    error!("Failed to ban HWID {}: {}", hwid, e);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Socket read error: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });

    info!("🎯 Process {} izlenmeye başlandı...", pid);

    loop {
        match scan_all_signatures(pid).await {
            Ok(found) if !found.is_empty() => {
                for cheat in found {
                    error!("🚨 {} detected at {:#x}!", cheat.name, cheat.address);
                    if let Err(e) = ban_hwid(&conn, &hwid, &cheat.name) {
                        error!("⚠️ Ban kaydı eklenemedi: {}", e);
                    }
                    // Şüpheli aktiviteyi sunucuya bildir
                    report_suspicious_activity(pid, format!("{} detected", cheat.name), "/tmp/anti-cheat.sock").await;
                }
            }
            Ok(_) => {}
            Err(e) => error!("❌ Tarama hatası: {}", e),
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
