# 🛡️ TLAC (Tuncor's Local Anti-Cheat)

**User-space + eBPF + AI powered anti-cheat for Linux**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-1.80+-orange.svg)](https://www.rust-lang.org/)
[![Stars](https://img.shields.io/github/stars/TuncorReUnion/TLAC-MODERN-LOCAL-ANTI-CHEAT-REUNIONED?style=social)](https://github.com/TuncorReUnion/TLAC-MODERN-LOCAL-ANTI-CHEAT-REUNIONED/stargazers)

---

**TLAC** is a lightweight, open-source anti-cheat solution built for Linux. It protects your games by scanning memory, detecting cheat signatures, and analyzing player behavior — all while staying in user-space and respecting your system.

## 🚀 Why TLAC?

| Feature | TLAC |
|---|---|
| **User-Space** | Runs without kernel-level access – safe and non-intrusive. |
| **Local Server** | No cloud latency, no third-party data collection. |
| **eBPF Support** | Kernel verification without the risk. |
| **AI Behavioral Analysis** | Detects unknown cheats via anomaly detection. |
| **HWID Ban** | Hardware-based bans to keep cheaters out. |
| **Lightweight** | Only ~6 MB – minimal system impact. |
| **Open Source** | Fully transparent, MIT licensed. |

---

## 📦 Features

- 🔍 **Memory Scanning** – Wildcard pattern support for cheat signatures.
- 🛡️ **Self-Integrity** – SHA256 binary verification.
- 🖥️ **HWID Ban** – Hardware-based banning.
- 🔌 **IPC Server** – Local server communication via Tokio.
- 📦 **Config-Driven** – JSON-based configuration.
- 🧠 **AI Anomaly Detection** – Behavioral analysis for unknown cheats.
- 🐧 **Linux Native** – Runs on any Linux distribution, including Steam Deck.

---

## 📥 Installation

### From Source (Recommended)

```bash
git clone https://github.com/TuncorReUnion/TLAC-MODERN-LOCAL-ANTI-CHEAT-REUNIONED.git
cd TLAC-MODERN-LOCAL-ANTI-CHEAT-REUNIONED
cargo build --release
sudo ./target/release/anti-cheat <PID>
