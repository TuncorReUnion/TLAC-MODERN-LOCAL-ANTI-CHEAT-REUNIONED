use std::time::Duration;
use aya::maps::perf::{AsyncPerfEventArray, PerfBuffer};
use aya::util::online_cpus;
use tokio::sync::mpsc;
use bytes::BytesMut;
use log::{error, info};

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

pub async fn start_ebpf_event_loop(
    bpf: &mut aya::Ebpf,
    tx: mpsc::Sender<SuspiciousEvent>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut perf_array: AsyncPerfEventArray<_> = bpf
    .take_map("suspicious_events")
    .ok_or("Map 'suspicious_events' not found!")?
    .try_into()?;

    info!("🔌 Opening perf buffers for all online CPUs...");

    let mut buffers = Vec::new();
    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        let tx_clone = tx.clone();
        tokio::spawn(async move {
            let mut buffers = vec![BytesMut::with_capacity(4096)];

            loop {
                let events = match buf.read_events(&mut buffers).await {
                    Ok(events) => events,
                     Err(e) => {
                         error!("❌ Perf buffer read error on CPU {}: {}", cpu_id, e);
                         tokio::time::sleep(Duration::from_millis(100)).await;
                         continue;
                     }
                };

                if events.lost > 0 {
                    error!("⚠️ Lost {} events on CPU {} (buffer overflow!)", events.lost, cpu_id);
                }

                for buf_data in &buffers[..events.read] {
                    if buf_data.len() < std::mem::size_of::<SuspiciousEvent>() {
                        continue;
                    }

                    let evt = unsafe {
                        std::ptr::read_unaligned(buf_data.as_ptr() as *const SuspiciousEvent)
                    };

                    info!(
                        "🚨 [{}] PID={} | {} | {}",
                        evt.comm_str(),
                          evt.pid,
                          evt.syscall_name(),
                          evt.filename_str()
                    );

                    if tx_clone.send(evt).await.is_err() {
                        error!("Channel closed, stopping perf buffer on CPU {}", cpu_id);
                        break;
                    }
                }

                buffers[0].clear();
            }
        });

        buffers.push(buf);
    }

    info!("✅ eBPF event loop started on {} CPUs", buffers.len());

    Ok(())
}
