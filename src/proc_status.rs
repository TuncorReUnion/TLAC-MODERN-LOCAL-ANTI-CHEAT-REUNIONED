use std::fs;
use std::path::Path;
use log::{info, warn};

#[derive(Debug)]
pub enum KernelStatus {
    Clean,
    Suspicious(String),
    Error(String),
}

const KNOWN_MODULES: &[&str] = &[
    "ext4", "xfs", "btrfs", "nvidia", "amdgpu", "i915",
"usbcore", "bluetooth", "cfg80211", "mac80211",
"snd_hda_intel", "intel_rapl", "kvm", "kvm_intel"
];

pub fn read_kernel_status() -> KernelStatus {
    let content = match fs::read_to_string("/proc/modules") {
        Ok(c) => c,
        Err(e) => return KernelStatus::Error(format!("Failed to read /proc/modules: {}", e)),
    };

    let mut suspicious_found = Vec::new();

    for line in content.lines() {
        if line.is_empty() { continue; }

        let module_name = match line.split_whitespace().next() {
            Some(name) => name,
            None => continue,
        };

        if !KNOWN_MODULES.contains(&module_name) {
            let sys_path = format!("/sys/module/{}/sections/.text", module_name);

            if !Path::new(&sys_path).exists() {
                suspicious_found.push(module_name.to_string());
            }
        }
    }

    if suspicious_found.is_empty() {
        KernelStatus::Clean
    } else {
        KernelStatus::Suspicious(
            format!("Detected {} unsigned/hidden module(s): {:?}", suspicious_found.len(), suspicious_found)
        )
    }
}
