# 🛡️ TLAC (Tuncor's Local Anti-Cheat)

An open-source, user-level anti-cheat tool developed for Linux systems. It scans process memory using `ptrace` and `procfs`, detects cheat signatures (patterns), and supports HWID-based banning.

## ✨ Features

- 🔍 **Memory Scanning:** Wildcard pattern support for flexible signature detection.
- 🛡️ **Self-Integrity:** Binary integrity verification using SHA256 hashing.
- 🖥️ **HWID Ban:** Hardware-based banning system to prevent cheaters from returning.
- 🔌 **IPC Server:** Local client-server communication via Tokio async runtime.
- 📦 **Config-Driven:** JSON-based configuration for easy customization.
- 🔒 **Secure:** Database and configuration file protection.

## 📥 Installation

1. Download the latest release from the [Releases](https://github.com/YOUR_USERNAME/TLAC/releases) page.
2. Extract the archive:
   ```bash
   tar -xvf TLAC-v0.1.0-x86_64-linux.tar.gz
   3. Run the install.sh:
   cd TLAC-v0.1.0-x86_64-linux/
   ./install.sh

   if want sudo. work with sudo.
