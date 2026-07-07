use crate::ebpf::SuspiciousEvent;
use std::collections::VecDeque;

const WINDOW_SIZE: usize = 100;

pub struct FeatureExtractor {
    events: VecDeque<SuspiciousEvent>,
}

impl FeatureExtractor {
    pub fn new() -> Self {
        Self {
            events: VecDeque::with_capacity(WINDOW_SIZE),
        }
    }

    pub fn add_event(&mut self, evt: SuspiciousEvent) {
        if self.events.len() >= WINDOW_SIZE {
            self.events.pop_front();
        }
        self.events.push_back(evt);
    }

    pub fn extract_features(&self) -> [f32; 5] {
        let total = self.events.len() as f32;
        if total == 0.0 { return [0.0; 5]; }

        let mut openat = 0u32;
        let mut execve = 0u32;
        let mut ptrace = 0u32;
        let mut clone = 0u32;
        let mut pids = std::collections::HashSet::new();

        for evt in &self.events {
            match evt.syscall_type {
                1 => openat += 1,
                2 => execve += 1,
                3 => ptrace += 1,
                4 => clone += 1,
                _ => {}
            }
            pids.insert(evt.pid);
        }

        [
            openat as f32 / total,
            execve as f32 / total,
            ptrace as f32 / total,
            clone as f32 / total,
            pids.len() as f32 / total,
        ]
    }
}
