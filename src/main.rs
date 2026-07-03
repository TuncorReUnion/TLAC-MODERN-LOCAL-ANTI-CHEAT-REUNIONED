use std::env;
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
use anti_cheat::messages::AntiCheatMessage;
use anti_cheat::sync_client::SyncClient;
use aya::Bpf;
use aya::util::online_cpus;
use aya::maps::perf::PerfEventArray;
use aya::programs::TracePoint;
mod proc_status;
use proc_status::{read_kernel_status, KernelStatus};
mod messages;
mod sync_client;

#[derive(Deserialize, Serialize, Debug, Default)]
struct AntiCheatConfig
{
    expected_binary_hash: String,
    version: String,
    #[serde(default = "default_interval")]
    scan_interval_ms: u64,
    log_path: String,
}

fn load_config() -> Result<AntiCheatConfig, Box<dyn std::error::Error>>
{
    let path = get_config_path();

    if !path.exists()
    {
        if let Some(parent) = path.parent()
        {
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

let status = proc_status::read_kernel_status();
println!("{:?}", status);

fn default_interval() -> u64 { 5000 }

fn get_config_path() -> PathBuf
{
    if let Ok(path) = env::var("TLAC_CONFIG")
    {
        return PathBuf::from(path);
    }

    let home_dir = if let Ok(user) = env::var("SUDO_USER")
    {
        PathBuf::from("/home").join(user)
    }
    else
    {
        env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/root"))
    };

    home_dir.join(".config").join("tlac").join("config.json")
}

fn attach_to_process(pid: u32) -> nix::Result<()>
{
    let pid = Pid::from_raw(pid as i32);
    ptrace::attach(pid)?;
    println!("Process {} attached!", pid);
    Ok(())
}

fn detach_from_process(pid: u32) -> nix::Result<()>
{
    let pid = Pid::from_raw(pid as i32);
    ptrace::detach(pid, None)?;
    println!("Process {} detached.", pid);
    Ok(())
}

fn read_process_maps(pid: u32) -> procfs::ProcResult<()>
{
    let proc = Process::new(pid as i32)?;
    for map in proc.maps()?
    {
        let pathname_str = match &map.pathname
        {
            procfs::process::MMapPath::Path(path) => path.display().to_string(),
            procfs::process::MMapPath::Heap => "[heap]".to_string(),
            procfs::process::MMapPath::Stack => "[stack]".to_string(),
            procfs::process::MMapPath::Vvar => "[vvar]".to_string(),
            procfs::process::MMapPath::Vdso => "[vdso]".to_string(),
            procfs::process::MMapPath::Vsyscall => "[vsyscall]".to_string(),
            procfs::process::MMapPath::Other(s) => format!("[{}]", s),
            _ => "[unknown]".to_string(),
        };
        println!("{:x}-{:x} {:?} {:x} {:?} {}", map.address.0, map.address.1, map.perms, map.offset, map.dev, pathname_str);
    }
    Ok(())
}

fn read_memory_at_address(pid: u32, address: usize) -> nix::Result<i32>
{
    let pid = Pid::from_raw(pid as i32);
    let data = ptrace::read(pid, address as *mut std::ffi::c_void)?;
    Ok(data as i32)
}

const MAX_REGION_SIZE: usize = 256 * 1024 * 1024;

fn read_memory_range(pid: u32, start: usize, len: usize) -> nix::Result<Vec<u8>>
{
    if len == 0 || len > MAX_REGION_SIZE
    {
        eprintln!("⚠️ Bölge atlandı: start={:#x}, len={} (max: {})", start, len, MAX_REGION_SIZE);
        return Ok(Vec::new());
    }

    let mut data = Vec::with_capacity(len.min(MAX_REGION_SIZE));
    let pid = Pid::from_raw(pid as i32);

    for offset in (0..len).step_by(4)
    {
        if offset >= MAX_REGION_SIZE { break; }

        let addr = (start + offset) as *mut std::ffi::c_void;
        match ptrace::read(pid, addr)
        {
            Ok(word) => data.extend_from_slice(&word.to_ne_bytes()),
            Err(_) => break,
        }
    }
    Ok(data)
}

fn search_pattern_in_memory(pid: u32, start: usize, len: usize, pattern: &[u8]) -> Option<usize>
{
    if let Ok(memory) = read_memory_range(pid, start, len)
    {
        if let Some(pos) = search_pattern_in_bytes(&memory, pattern)
        {
            return Some(start + pos);
        }
    }
    None
}

fn search_pattern_in_bytes(bytes: &[u8], pattern: &[u8]) -> Option<usize>
{
    bytes.windows(pattern.len()).position(|window| window == pattern)
}

fn search_wildcard_pattern_in_bytes(bytes: &[u8], pattern: &[Option<u8>]) -> Option<usize>
{
    if pattern.is_empty() || bytes.is_empty()
    {
        return None;
    }

    let pat_len = pattern.len();
    let bytes_len = bytes.len();

    if pat_len > bytes_len
    {
        return None;
    }

    let max_start_index = bytes_len - pat_len;

    for i in 0..=max_start_index
    {
        let mut matched = true;

        for j in 0..pat_len
        {
            if i + j >= bytes_len
            {
                matched = false;
                break;
            }

            if let Some(expected_byte) = pattern[j]
            {
                if bytes[i + j] != expected_byte
                {
                    matched = false;
                    break;
                }
            }
        }

        if matched
        {
            return Some(i);
        }
    }
    None
}

fn search_wildcard_pattern_in_memory(pid: u32, start: usize, len: usize, pattern: &[Option<u8>]) -> Option<usize> {
    if let Ok(memory) = read_memory_range(pid, start, len)
    {
        if let Some(pos) = search_wildcard_pattern_in_bytes(&memory, pattern)
        {
            return Some(start + pos);
        }
    }
    None
}

fn scan_process_for_cheat_signatures(pid: u32, signatures: &[Vec<Option<u8>>]) -> procfs::ProcResult<()>
{
    let proc = Process::new(pid as i32)?;
    let pid_struct = Pid::from_raw(pid as i32);
    match ptrace::attach(pid_struct)
    {
        Ok(_) => {},
        Err(e) => return Err(procfs::ProcError::Other(e.to_string())),
    }
    println!("Attached to process {}", pid);
    for map in proc.maps()?
    {
        if map.perms.contains(procfs::process::MMPermissions::READ) && map.perms.contains(procfs::process::MMPermissions::PRIVATE)
        {
            if let procfs::process::MMapPath::Path(_) = &map.pathname
            {
                let start = map.address.0 as usize;
                let len = (map.address.1 - map.address.0) as usize;
                for sig in signatures
                {
                    if let Some(found_at) = search_wildcard_pattern_in_memory(pid, start, len, sig)
                    {
                        println!("!!! CHEAT SIGNATURE FOUND at {:#x} in range {:#x}-{:#x}", found_at, start, map.address.1);
                    }
                }
            }
        }
    }
    match ptrace::detach(pid_struct, None)
    {
        Ok(_) => {},
        Err(e) => return Err(procfs::ProcError::Other(e.to_string())),
    }
    println!("Detached from process {}", pid);
    Ok(())
}

fn calculate_binary_hash() -> Result<String, Box<dyn std::error::Error>>
{
    let exe_path = env::current_exe()?;
    let content = fs::read(exe_path)?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let result = hasher.finalize();
    Ok(hex::encode(result))
}

fn verify_binary_integrity(expected_hash: &str) -> Result<(), Box<dyn std::error::Error>>
{
    if expected_hash.is_empty()
    {
        eprintln!("⚠️ Binary hash kontrolü atlandı (expected_hash boş)");
        return Ok(());
    }

    let current_hash = calculate_binary_hash()?;
    if current_hash != expected_hash
    {
        return Err(format!(
            "!!! BINARY TAMPERING DETECTED!\nExpected: {}\nGot: {}",
            expected_hash, current_hash
        ).into());
    }
    println!("✅ Binary integrity verified.");
    Ok(())
}

async fn send_to_server(socket_path: &str, msg: &AntiCheatMessage) -> Result<(), Box<dyn std::error::Error>>
{
    let mut stream = UnixStream::connect(socket_path).await?;

    let data = serde_json::to_vec(msg)?;
    stream.write_all(&data).await?;

    let mut buf = [0u8; 1024];
    let _ = stream.read(&mut buf).await;

    Ok(())
}

async fn report_suspicious_activity(pid: u32, reason: String, socket_path: &str)
{
    let msg = AntiCheatMessage::SuspiciousActivity
    {
        pid,
        reason,
        memory_address: None,
        signature_found: None,
    };
    if let Err(e) = send_to_server(socket_path, &msg).await
    {
        eprintln!("❌ Failed to report to server: {}", e);
    }
}

fn init_db() -> Result<Connection, Box<dyn std::error::Error>>
{
    let conn = Connection::open("anti_cheat.db")?;

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

fn generate_hwid() -> String
{
    let mut hasher = Sha256::new();

    if let Ok(uuid) = fs::read_to_string("/sys/class/dmi/id/product_uuid")
    {
        hasher.update(uuid.trim());
    }

    if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo")
    {
        if let Some(serial) = cpuinfo.lines().find(|l| l.starts_with("serial"))
        {
            hasher.update(serial);
        }
    }

    if let Ok(mac) = fs::read_to_string("/sys/class/net/eth0/address")
    {
        hasher.update(mac.trim());
    }
    else if let Ok(mac) = fs::read_to_string("/sys/class/net/wlan0/address")
    {
        hasher.update(mac.trim());
    }

    if let Ok(serial) = fs::read_to_string("/sys/block/sda/device/serial")
    {
        hasher.update(serial.trim());
    }

    format!("{:x}", hasher.finalize())
}

fn ban_hwid(conn: &Connection, hwid: &str, reason: &str) -> Result<(), rusqlite::Error>
{
    conn.execute(
        "INSERT OR IGNORE INTO hwid_bans (hwid, reason) VALUES (?1, ?2)",
                 [hwid, reason],
    )?;
    Ok(())
}

fn is_hwid_banned(conn: &Connection, hwid: &str) -> std::result::Result<bool, Box<dyn std::error::Error>>
{
    let count: u32 = conn.query_row
    (
        "SELECT COUNT(*) FROM hwid_bans WHERE hwid = ?1",
     [hwid],
     |row| row.get(0),
    )?;
    Ok(count > 0)
}

#[tokio::main]
async fn main()
{
    tokio::spawn(async move {
    match online_cpus() 
        {
        Ok(cpus) => 
            {
            for cpu in cpus 
                {
                if let Ok(mut events) = perf.open(cpu, None) 
                {
                    loop 
                        {
                        match events.read_events(10, tokio::time::Duration::from_millis(100)) 
                            {
                            Ok(batch) => 
                                {
                                for event in batch 
                                    {
                                    if let Ok(evt) = serde_json::from_slice::<SuspiciousEvent>(&event.data) 
                                    {
                                        warn!("⚠️ Suspicious file opened by PID {}: {}", evt.pid, evt.filename);
                                        if let Ok(cmd) = serde_json::from_slice::<BanCommand>(&buf[..n]) 
                                        {
                                             match cmd {
                        BanCommand::Ban { hwid } => 
                            {
                            warn!("🚨 BAN RECEIVED for HWID: {}", hwid);
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("BPF event read error: {}", e);
                                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                            }
                        }
                    }
                } else {
                    warn!("Failed to open perf event for CPU {}", cpu);
                }
            }
        }
        Err(e) => {
            error!("Failed to get online CPUs: {}", e);
        }
    }
    }
    }
                 }
    let mut bpf = Bpf::load(include_bytes!("../bpf/program.bpf.o"))?;
    let perf = bpf.take_table::<PerfEventArray<_>>("suspicious_events")?;
    let hwid = generate_hwid();
    let conn = init_db().expect("Veritabanı açılamadı");

    match read_kernel_status()
    {
        KernelStatus::Clean => println!("🛡️ Sistem temiz."),
        KernelStatus::Suspicious =>
        {
            println!("⚠️ UYARI: Sistemde şüpheli aktivite tespit edildi!");
            if let Err(e) = ban_hwid(&conn, &hwid, "Kernel modülü şüpheli aktivite tespit etti")
            {
                eprintln!("⚠️ Ban kaydı eklenemedi: {}", e);
            }
            println!("🚫 Sistem kapatılıyor.");
            std::process::exit(1);
        }
        KernelStatus::Error(e) => println!("🛡️ Kernel modül hatası: {}", e),
    }

    let local_count: u32 = conn.query_row
    (
        "SELECT COUNT(*) FROM hwid_bans", [], |row| row.get(0)
    ).unwrap_or(0);
    let sync_client = SyncClient::new("http://127.0.0.1:5000");
    match sync_client.sync_bans(&hwid, local_count).await
    {
        Ok(sync_data) => {
            println!("📥 Sunucudan {} ban alındı.", sync_data.bans.len());
            for ban in &sync_data.bans
            {
                conn.execute(
                    "INSERT OR IGNORE INTO hwid_bans (hwid, reason, banned_at) VALUES (?1, ?2, ?3)",
                             [&ban.hwid, &ban.reason, &ban.banned_at],
                ).ok();
            }
        }
        Err(e) =>
        {
            eprintln!("⚠️ Sync başarısız, yerel veritabanı kullanılıyor: {}", e);
        }
    }

    let is_banned: bool = conn.query_row
    (
        "SELECT COUNT(*) > 0 FROM hwid_bans WHERE hwid = ?1", [&hwid], |row| row.get(0)
    ).unwrap_or(false);

    if is_banned
    {
        eprintln!("🚫 HWID banlı! Sistem başlatılamıyor.");
        std::process::exit(1);
    }

    match is_hwid_banned(&conn, &hwid)
    {
        Ok(true) =>
        {
            eprintln!("🚫 DONANIM BANLI! Sistem başlatılamıyor.");
            std::process::exit(1);
        }
        Ok(false) => println!("✅ HWID temiz: {}", hwid),
        Err(e) => eprintln!("⚠️ Ban kontrolü hatası: {}", e),
    }

    let config = load_config().unwrap_or_else(|e| {
        eprintln!("⚠️ Config hatası: {}, varsayılan kullanılıyor", e);
        AntiCheatConfig::default()
    });

    println!("🔧 Anti-Cheat v{} başlatılıyor...", config.version);

    if let Err(e) = verify_binary_integrity(&config.expected_binary_hash)
    {
        eprintln!("🚨 KRİTİK: Binary değiştirilmiş! Sistem kapatılıyor. ({})", e);
        std::process::exit(1);
    }

    println!("✅ Binary bütünlüğü doğrulandı.");

    let pid: u32 = std::env::args()
    .nth(1)
    .expect("❌ Hata: PID belirtilmedi! Kullanım: ./Anti-Cheat <pid>")
    .parse()
    .expect("❌ Hata: PID geçerli bir sayı olmalı!");

    println!("🎯 Process {} izlenmeye başlandı...", pid);

    loop
    {
        match scan_all_signatures(pid).await
        {
            Ok(found) if !found.is_empty() =>
            {
                for cheat in found
                {
                    eprintln!("🚨 {} detected at {:#x}!", cheat.name, cheat.address);

                    if let Err(e) = ban_hwid(&conn, &hwid, &cheat.name)
                    {
                        eprintln!("⚠️ Ban kaydı eklenemedi: {}", e);
                    }
                }
            }

            Ok(_) =>
            {
            }

            Err(e) => eprintln!("❌ Tarama hatası: {}", e),
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

#[derive(Deserialize, Debug, Clone)]
struct SignatureFile
{
    signatures: Vec<CheatSignature>,
}

#[derive(Deserialize, Debug, Clone)]
struct CheatSignature
{
    id: String,
    name: String,
    pattern: String,
    severity: String,
    memory_regions: Vec<String>,
}

#[derive(Debug, Clone)]
struct FoundCheat
{
    name: String,
    address: usize,
    severity: String,
}

fn parse_pattern(pattern_str: &str) -> Vec<Option<u8>>
{
    if pattern_str.trim().is_empty()
    {
        return Vec::new();
    }

    pattern_str.split_whitespace()
    .filter_map(|byte|
    {
        if byte == "?" || byte == "*"
        {
            Some(None)
        }
        else
        {
            u8::from_str_radix(byte, 16).ok().map(Some)
        }
    })
    .collect()
}

fn load_signatures() -> Result<Vec<CheatSignature>, Box<dyn std::error::Error>>
{
    let sig_path = PathBuf::from("/etc/tlac/signatures.json");
    let content = fs::read_to_string(&sig_path)?;
    let file: SignatureFile = serde_json::from_str(&content)?;
    Ok(file.signatures)
}

async fn scan_all_signatures(pid: u32) -> Result<Vec<FoundCheat>, Box<dyn std::error::Error>>
{
    const MAX_REGION_SIZE: usize = 256 * 1024 * 1024;

    let sigs = match load_signatures()
    {
        Ok(s) => s,
        Err(e) =>
        {
            eprintln!("⚠️ Signature dosyası yüklenemedi: {}. Tarama atlanıyor.", e);
            return Ok(Vec::new());
        }
    };

    let mut found = Vec::new();
    let proc = Process::new(pid as i32)?;
    let pid_nix = Pid::from_raw(pid as i32);

    ptrace::attach(pid_nix).ok();

    for map in proc.maps()?
    {
        let region_size = map.address.1 - map.address.0;

        if region_size == 0 || region_size > MAX_REGION_SIZE as u64
        {
            eprintln!("⚠️ Büyük bölge atlandı: {:#x}-{:#x}", map.address.0, map.address.1);
            continue;
        }

        let is_exec = map.perms.contains(procfs::process::MMPermissions::EXECUTE);
        let is_writable = map.perms.contains(procfs::process::MMPermissions::WRITE);

        for sig in &sigs
        {
            let should_scan = sig.memory_regions.iter().any(|r| match r.to_lowercase().as_str()
            {
                "executable" => is_exec,
                "writable" => is_writable,
                _ => true,
            });
            if !should_scan { continue; }

            let pattern = parse_pattern(&sig.pattern);
            if pattern.is_empty()
            {
                eprintln!("⚠️ Boş pattern atlandı: {}", sig.name);
                continue;
            }

            let start = map.address.0 as usize;
            let len = region_size as usize;

            if let Some(offset) = search_wildcard_pattern_in_memory(pid, start, len, &pattern)
            {
                found.push(FoundCheat
                {
                    name: sig.name.clone(),
                           address: offset,
                           severity: sig.severity.clone(),
                });
            }
        }
    }

    ptrace::detach(pid_nix, None).ok();
    Ok(found)
}
