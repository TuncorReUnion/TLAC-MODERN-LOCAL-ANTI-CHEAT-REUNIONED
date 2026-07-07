pub mod ai;
pub mod ebpf;
pub mod sync_client;

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
