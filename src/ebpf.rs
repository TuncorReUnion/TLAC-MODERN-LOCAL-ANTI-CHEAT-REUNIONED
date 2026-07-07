use aya::maps::perf::PerfEventArray;
use aya::Bpf;
use std::time::Duration;
use tokio::sync::mpsc;
use crate::SuspiciousEvent;

pub async fn start_ebpf_event_loop(
    bpf: &mut Ebpf,
    tx: mpsc::Sender<SuspiciousEvent>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut perf_array: PerfEventArray<_> = bpf
        .take_map("suspicious_events")
        .ok_or("Map 'suspicious_events' not found!")?
        .try_into()?;

    let cpu_ids = aya::util::online_cpus().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    for cpu_id in cpu_ids {
        let mut buf = perf_array.open(cpu_id, None).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let tx_clone = tx.clone();

        tokio::spawn(async move {
            let mut buffers = vec![bytes::BytesMut::with_capacity(4096)];

            loop {
                let events = match buf.read_events(&mut buffers) {
                    Ok(events) => events,
                    Err(e) => {
                        eprintln!("Perf buffer read error on CPU {}: {}", cpu_id, e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };

                if events.lost > 0 {
                    eprintln!("Lost {} events on CPU {} (buffer overflow!)", events.lost, cpu_id);
                }

                for buf_data in &buffers[..events.read] {
                    if buf_data.len() < std::mem::size_of::<SuspiciousEvent>() {
                        continue;
                    }

                    let evt = unsafe {
                        std::ptr::read_unaligned(buf_data.as_ptr() as *const SuspiciousEvent)
                    };

                    if tx_clone.send(evt).await.is_err() {
                        eprintln!("Channel closed, stopping perf buffer on CPU {}", cpu_id);
                        break;
                    }
                }

                buffers[0].clear();
            }
        });
    }

    Ok(())
}
