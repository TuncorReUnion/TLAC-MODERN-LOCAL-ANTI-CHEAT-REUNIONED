use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::UnixStream;
use tokio::io::AsyncWriteExt;
use rusqlite::Connection;
use sha2::{Sha256, Digest};
use serde::Deserialize;
use nix::sys::ptrace;
use nix::unistd::Pid;
use procfs::process::Process;
use hex;
use libudev::Context;
use log::{warn, error, info};
use aya::{include_bytes_aligned, Ebpf, programs::TracePoint};
use tokio::sync::mpsc;
use aya::maps::perf::PerfEventArray;
use aya::util::online_cpus;
use bytes::BytesMut;

mod ai;
mod ebpf;

const INFERENCE_INTERVAL: Duration = Duration::from_millis(100);
const DEFAULT_AI_THRESHOLD: f32 = 0.75;

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

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SuspiciousEvent {
    pub pid: u32,
    pub syscall_type: u32,
    pub timestamp_ns: u64,
    pub filename: [u8; 256],
    pub comm: [u8; 16],
}

impl SuspiciousEvent {
    pub fn filename_str(&self) -> String {
        let len = self.filename.iter().position(|&b| b == 0).unwrap_or(256);
        String::from_utf8_lossy(&self.filename[..len]).to_string()
    }

    pub fn comm_str(&self) -> String {
        let len = self.comm.iter().position(|&b| b == 0).unwrap_or(16);
        String::from_utf8_lossy(&self.comm[..len]).to_string()
    }

    pub fn syscall_name(&self) -> &'static str {
        match self.syscall_type {
            1 => "openat",
            2 => "execve",
            3 => "ptrace",
            4 => "clone",
            _ => "unknown",
        }
    }
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

fn get_embedded_hash() -> &'static str {
    include_str!("../bin_hash.txt")
}

fn verify_binary_integrity() -> Result<(), Box<dyn std::error::Error>> {
    let expected = get_embedded_hash().trim();
    if expected.is_empty() {
        warn!("Binary hash embed edilmemiş (ilk derleme). Integrity check atlanıyor.");
        return Ok(());
    }
    let current_hash = calculate_binary_hash()?;
    if current_hash != expected {
        return Err(format!(
            "Binary tampering detected!\nExpected: {}\nGot: {}",
            expected, current_hash
        ).into());
    }
    info!("Binary integrity verified.");
    Ok(())
}

fn generate_hwid() -> String {
    let mut hasher = Sha256::new();
    if let Ok(uuid) = fs::read_to_string("/sys/class/dmi/id/product_uuid") {
        hasher.update(uuid.trim());
    } else if let Ok(machine_id) = fs::read_to_string("/etc/machine-id") {
        hasher.update(machine_id.trim());
    }

    if let Ok(context) = Context::new() {
        let mut enumerator = libudev::Enumerator::new(&context).unwrap();
        enumerator.match_subsystem("net").unwrap();
        enumerator.match_is_initialized().unwrap();
        for device in enumerator.scan_devices().unwrap() {
            if let Some(sys_path) = device.syspath().to_str() {
                let mac_path = format!("{}/address", sys_path);
                if let Ok(mac) = fs::read_to_string(&mac_path) {
                    let mac_trimmed = mac.trim();
                    if !mac_trimmed.is_empty() && mac_trimmed != "00:00:00:00:00:00" {
                        hasher.update(mac_trimmed);
                    }
                }
            }
        }
    }

    if let Ok(entries) = fs::read_dir("/sys/block") {
        for entry in entries.flatten() {
            let path = entry.path();
            let dev_name = path.file_name().unwrap().to_str().unwrap();
            if dev_name.starts_with("nvme") || dev_name.starts_with("sd") || dev_name.starts_with("vd") {
                let serial_path = path.join("device").join("serial");
                if let Ok(serial) = fs::read_to_string(&serial_path) {
                    hasher.update(serial.trim());
                }
            }
        }
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
    if !sig_path.exists() {
        return Ok(Vec::new());
    }
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

async fn scan_all_signatures(pid: u32, conn: &Connection) -> Result<Vec<FoundCheat>, Box<dyn std::error::Error>> {
    let sigs = load_signatures()?;
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

async fn send_to_server(socket_path: &str, msg: &serde_json::Value) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = UnixStream::connect(socket_path).await?;
    let data = serde_json::to_vec(msg)?;
    stream.write_all(&data).await?;
    Ok(())
}

async fn report_suspicious_activity(pid: u32, reason: String, socket_path: &str) {
    let msg = serde_json::json!({
        "type": "SuspiciousActivity",
        "pid": pid,
        "reason": reason,
        "memory_address": null,
        "signature_found": null
    });
    if let Err(e) = send_to_server(socket_path, &msg).await {
        error!("Failed to report to server: {}", e);
    }
}

pub async fn start_ebpf_event_loop(
    bpf: &mut Ebpf,
    tx: mpsc::Sender<SuspiciousEvent>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut perf_array: PerfEventArray<_> = bpf
        .take_map("suspicious_events")
        .ok_or("Map 'suspicious_events' not found!")?
        .try_into()?;

    info!("Opening perf buffers for all online CPUs...");

    let cpu_ids = online_cpus().map_err(|(_, e)| e)?;

    for cpu_id in cpu_ids {
        let mut buf = perf_array.open(cpu_id, None).map_err(|(_, e)| e)?;
        let tx_clone = tx.clone();

        tokio::spawn(async move {
            let mut buffers = vec![BytesMut::with_capacity(4096)];

            loop {
                let events = match buf.read_events(&mut buffers) {
                    Ok(events) => events,
                    Err(e) => {
                        error!("Perf buffer read error on CPU {}: {}", cpu_id, e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };

                if events.lost > 0 {
                    error!("Lost {} events on CPU {} (buffer overflow!)", events.lost, cpu_id);
                }

                for buf_data in &buffers[..events.read] {
                    if buf_data.len() < std::mem::size_of::<SuspiciousEvent>() {
                        continue;
                    }

                    let evt = unsafe {
                        std::ptr::read_unaligned(buf_data.as_ptr() as *const SuspiciousEvent)
                    };

                    if tx_clone.send(evt).await.is_err() {
                        error!("Channel closed, stopping perf buffer on CPU {}", cpu_id);
                        break;
                    }
                }

                buffers[0].clear();
            }
        });
    }

    info!("eBPF event loop started on {} CPUs", cpu_ids.len());
    Ok(())
}

async fn process_events(event_buffer: &mut Vec<SuspiciousEvent>, threshold: f32, conn: &Connection) {
    for event in event_buffer.iter() {
        let score = event.syscall_type as f32 / 4.0;
        if score > threshold {
            let hwid = generate_hwid();
            error!("Anomaly detected! Score: {:.3} | Syscall: {} | PID: {}",
                   score, event.syscall_name(), event.pid);
            let _ = ban_hwid(conn, &hwid, &format!("AI anomaly score: {:.3}", score));
            error!("HWID banned: {}", hwid);
            std::process::exit(1);
        }
    }
    event_buffer.clear();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    if let Err(e) = verify_binary_integrity() {
        error!("Critical: Binary tampering detected! System shutting down. ({})", e);
        std::process::exit(1);
    }

    let pid: u32 = std::env::args()
        .nth(1)
        .expect("Error: PID not specified! Usage: ./tlac <pid>")
        .parse()
        .expect("Error: PID must be a valid number!");

    let hwid = generate_hwid();
    let conn = init_db().expect("Database cannot be opened");

    if is_hwid_banned(&conn, &hwid)? {
        error!("Hardware banned! System cannot start.");
        std::process::exit(1);
    }

    info!("HWID clean: {}", hwid);

    let mut bpf = Ebpf::load(include_bytes_aligned!("../bpf/program.bpf.o"))?;

    let (ebpf_tx, mut ebpf_rx) = mpsc::channel::<SuspiciousEvent>(1024);

    start_ebpf_event_loop(&mut bpf, ebpf_tx).await?;

    let tracepoint_openat: TracePoint = bpf.program_mut("trace_openat").unwrap().try_into()?;
    tracepoint_openat.load()?;
    tracepoint_openat.attach("syscalls", "sys_enter_openat")?;
    info!("Attached trace_openat");

    let tracepoint_execve: TracePoint = bpf.program_mut("trace_execve").unwrap().try_into()?;
    tracepoint_execve.load()?;
    tracepoint_execve.attach("syscalls", "sys_enter_execve")?;
    info!("Attached trace_execve");

    let tracepoint_ptrace: TracePoint = bpf.program_mut("trace_ptrace").unwrap().try_into()?;
    tracepoint_ptrace.load()?;
    tracepoint_ptrace.attach("syscalls", "sys_enter_ptrace")?;
    info!("Attached trace_ptrace");

    let tracepoint_clone: TracePoint = bpf.program_mut("trace_clone").unwrap().try_into()?;
    tracepoint_clone.load()?;
    tracepoint_clone.attach("syscalls", "sys_enter_clone")?;
    info!("Attached trace_clone");

    let threshold: f32 = std::env::var("TLAC_AI_THRESHOLD")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_AI_THRESHOLD);

    let mut event_buffer = Vec::with_capacity(64);
    let mut interval = tokio::time::interval(INFERENCE_INTERVAL);

    let ai_handle = tokio::spawn(async move {
        let conn = init_db().expect("Database cannot be opened");
        loop {
            tokio::select! {
                Some(event) = ebpf_rx.recv() => {
                    event_buffer.push(event);
                    if event_buffer.len() >= 32 {
                        process_events(&mut event_buffer, threshold, &conn).await;
                    }
                }
                _ = interval.tick() => {
                    if !event_buffer.is_empty() {
                        process_events(&mut event_buffer, threshold, &conn).await;
                    }
                }
            }
        }
    });

    let scan_handle = tokio::spawn(async move {
        let conn = init_db().expect("Database cannot be opened");
        loop {
            match scan_all_signatures(pid, &conn).await {
                Ok(found) if !found.is_empty() => {
                    for cheat in found {
                        error!("{} detected at {:#x}!", cheat.name, cheat.address);
                        let hwid = generate_hwid();
                        if let Err(e) = ban_hwid(&conn, &hwid, &cheat.name) {
                            error!("Ban record could not be added: {}", e);
                        }
                        report_suspicious_activity(pid, format!("{} detected", cheat.name), "/tmp/anti-cheat.sock").await;
                        error!("System shutting down due to cheat detection");
                        std::process::exit(1);
                    }
                }
                Ok(_) => {}
                Err(e) => error!("Scan error: {}", e),
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    tokio::try_join!(ai_handle, scan_handle)?;

    Ok(())
}
