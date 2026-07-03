use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Debug)]
pub struct KernelStatus {
    pub modules: String,
}

pub fn read_kernel_status() -> KernelStatus {
    let modules = std::fs::read_to_string("/proc/modules")
        .unwrap_or_default();
    KernelStatus { modules }
}

pub fn read_kernel_status() -> KernelStatus {
    let path = Path::new("/proc/tlac_status");
    if !path.exists() {
        return KernelStatus::Error("TLAC kernel module not loaded".to_string());
    }

    match File::open(path) {
        Ok(file) => {
            let reader = BufReader::new(file);
            for line in reader.lines() {
                if let Ok(content) = line {
                    if content.contains("ŞÜPHELİ") {
                        return KernelStatus::Suspicious;
                    } else if content.contains("TEMİZ") {
                        return KernelStatus::Clean;
                    }
                }
            }
            KernelStatus::Error("Unknown status".to_string())
        }
        Err(e) => KernelStatus::Error(format!("Failed to read: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_status() {
        let status = read_kernel_status();
        println!("Kernel Status: {:?}", status);
    }
}
