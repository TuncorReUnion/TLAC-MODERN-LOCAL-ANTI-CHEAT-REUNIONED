#[derive(Debug)]
pub enum KernelStatus {
    Clean,
    Suspicious,
    Error(String),
}

pub fn read_kernel_status() -> KernelStatus {
    match std::fs::read_to_string("/proc/modules") {
        Ok(content) => {
            if content.contains("rootkit") || content.contains("suspicious") {
                KernelStatus::Suspicious
            } else {
                KernelStatus::Clean
            }
        }
        Err(e) => KernelStatus::Error(format!("Failed to read /proc/modules: {}", e)),
    }
}
