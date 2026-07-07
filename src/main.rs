use std::time::Duration;
use tokio::net::UnixStream;
use tokio::io::{AsyncWriteExt};
use rusqlite::Connection;
use sha2::{Sha256, Digest};
use serde::Deserialize;
use nix::sys::ptrace;
use nix::unistd::Pid;
use procfs::process::Process;
use log::{warn, error, info};
use std::sync::Arc;
use tokio::sync::Mutex; // tokio'nun Mutex'ini kullan

mod proc_status;
use proc_status::{read_kernel_status, KernelStatus};

fn generate_hwid() -> String {
    let mut hasher = Sha256::new();
    if let Ok(uuid) = std::fs::read_to_string("/sys/class/dmi/id/product_uuid") {
        hasher.update(uuid.trim());
    }
    if let Ok(machine_id) = std::fs::read_to_string("/etc/machine-id") {
        hasher.update(machine_id.trim());
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

const MAX_REGION_SIZE: usize = 256 * 1024 * 1024;

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
    let sig_path = std::path::PathBuf::from("/etc/tlac/signatures.json");
    let content = std::fs::read_to_string(&sig_path)?;
    let file: SignatureFile = serde_json::from_str(&content)?;
    Ok(file.signatures)
}

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

async fn scan_all_signatures(pid: u32) -> Result<Vec<FoundCheat>, Box<dyn std::error::Error + Send + Sync>> {
    let sigs = match load_signatures() {
        Ok(s) => s,
        Err(e) => {
            warn!("Signature dosyası yüklenemedi: {}. Tarama atlanıyor.", e);
            return Ok(Vec::new());
        }
    };

    let mut found = Vec::new();
    let proc = Process::new(pid as i32)?;
    let pid_nix = Pid::from_raw(pid as i32);

    match ptrace::attach(pid_nix) {
        Ok(_) => {}
        Err(e) => {
            error!("ptrace attach failed for PID {}: {}", pid, e);
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

async fn report_suspicious_activity(pid: u32, reason: String, socket_path: &str) {
    let msg = serde_json::json!({
        "type": "SuspiciousActivity",
        "pid": pid,
        "reason": reason,
        "memory_address": null,
        "signature_found": null
    });
    let mut stream = match UnixStream::connect(socket_path).await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to connect to server: {}", e);
            return;
        }
    };
    if let Err(e) = stream.write_all(&serde_json::to_vec(&msg).unwrap()).await {
        error!("Failed to report to server: {}", e);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let pid: u32 = std::env::args()
    .nth(1)
    .expect("PID belirtilmedi! Kullanım: ./tlac <pid>")
    .parse()
    .expect("PID geçerli bir sayı olmalı!");

    let hwid = generate_hwid();
    let conn = Arc::new(Mutex::new(init_db()?));

    {
        let conn_guard = conn.lock().await;
        if is_hwid_banned(&conn_guard, &hwid)? {
            error!("DONANIM BANLI! Sistem başlatılamıyor.");
            std::process::exit(1);
        }
    }

    info!("HWID temiz: {}", hwid);

    match read_kernel_status() {
        KernelStatus::Clean => info!("Sistem temiz."),
        KernelStatus::Suspicious(msg) => {
            warn!("Sistemde şüpheli aktivite tespit edildi: {}", msg);
            let conn_guard = conn.lock().await;
            let _ = ban_hwid(&conn_guard, &hwid, &format!("Kernel modülü şüpheli aktivite: {}", msg));
            error!("Sistem kapatılıyor.");
            std::process::exit(1);
        }
        KernelStatus::Error(e) => warn!("Kernel modül hatası: {}", e),
    }

    info!("Process {} izlenmeye başlandı...", pid);

    let conn_clone = conn.clone();
    let scan_handle = tokio::spawn(async move {
        loop {
            match scan_all_signatures(pid).await {
                Ok(found) if !found.is_empty() => {
                    let hwid = generate_hwid();
                    let mut conn_guard = conn_clone.lock().await;
                    for cheat in found {
                        error!("{} detected at {:#x}!", cheat.name, cheat.address);
                        if let Err(e) = ban_hwid(&mut conn_guard, &hwid, &cheat.name) {
                            error!("Ban kaydı eklenemedi: {}", e);
                        }
                        report_suspicious_activity(pid, format!("{} detected", cheat.name), "/tmp/anti-cheat.sock").await;
                    }
                }
                Ok(_) => {}
                Err(e) => error!("Tarama hatası: {}", e),
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    scan_handle.await?;

    Ok(())
}
