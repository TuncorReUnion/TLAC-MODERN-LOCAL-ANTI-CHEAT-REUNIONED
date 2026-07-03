#!/bin/bash

# ==============================================================================
# TLAC (Tuncor's Local Anti-Cheat) v4.0 Installer
# Description: Installs the anti-cheat binary, server, configuration files, and kernel module.
# License: MIT
# ==============================================================================

set -e

# --- Configuration ---
INSTALL_BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/tlac"
DB_PATH="/var/lib/tlac/anti_cheat.db"
SERVICE_NAME="tlac.service"
KERNEL_MODULE="tlac_kernel.ko"
BPF_PROGRAM="program.bpf.o"
BIN_NAME="anti-cheat"
SERVER_NAME="server_main"

# --- Colors for Output ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# --- Root Check ---
if [ "$(id -u)" -ne 0 ]; then
    log_error "This script must be run as root. Please use 'sudo ./install.sh'"
fi

# --- 1. Install System Dependencies ---
log_info "Installing system dependencies..."
if command -v apt-get &> /dev/null; then
    apt-get update -qq
    apt-get install -y -qq build-essential libssl-dev pkg-config linux-headers-$(uname -r) > /dev/null
elif command -v dnf &> /dev/null; then
    dnf install -y make gcc openssl-devel pkg-config kernel-devel-$(uname -r) > /dev/null
else
    log_warn "Package manager not detected. Please ensure 'build-essential', 'libssl-dev', and kernel headers are installed manually."
fi

# --- 2. Create Directory Structure ---
log_info "Creating directory structure..."
mkdir -p "$INSTALL_BIN_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$(dirname "$DB_PATH")"

# --- 3. Install Binaries ---
log_info "Installing binaries to $INSTALL_BIN_DIR..."
if [ ! -f "$BIN_NAME" ]; then
    log_error "Binary '$BIN_NAME' not found in current directory. Please run this script from the release folder."
fi
cp "$BIN_NAME" "$INSTALL_BIN_DIR/"
chmod +x "$INSTALL_BIN_DIR/$BIN_NAME"

if [ -f "$SERVER_NAME" ]; then
    cp "$SERVER_NAME" "$INSTALL_BIN_DIR/"
    chmod +x "$INSTALL_BIN_DIR/$SERVER_NAME"
    log_info "Server binary installed: $INSTALL_BIN_DIR/$SERVER_NAME"
else
    log_warn "Server binary '$SERVER_NAME' not found. Skipping server installation."
fi

# --- 4. Install Configuration ---
log_info "Installing configuration files..."
if [ ! -f "$CONFIG_DIR/signatures.json" ]; then
    if [ -f "signatures.json" ]; then
        cp "signatures.json" "$CONFIG_DIR/"
        log_info "signatures.json installed to $CONFIG_DIR/"
    else
        log_warn "signatures.json not found. You will need to create one manually at $CONFIG_DIR/signatures.json"
    fi
else
    log_info "signatures.json already exists at $CONFIG_DIR/ (skipping)"
fi

# --- 5. Kernel Module (Optional) ---
if [ -f "$KERNEL_MODULE" ]; then
    log_info "Installing kernel module..."
    mkdir -p "/lib/modules/$(uname -r)/extra/"
    cp "$KERNEL_MODULE" "/lib/modules/$(uname -r)/extra/"
    depmod -a
    if modprobe tlac_kernel 2>/dev/null; then
        log_info "Kernel module loaded successfully."
    else
        log_warn "Failed to load kernel module. It may require a reboot or specific kernel config."
    fi
else
    log_warn "Kernel module ($KERNEL_MODULE) not found. Skipping kernel-level protection."
fi

# --- 6. eBPF Program (Optional) ---
if [ -f "$BPF_PROGRAM" ]; then
    log_info "Installing eBPF program..."
    mkdir -p "/usr/lib/tlac/bpf/"
    cp "$BPF_PROGRAM" "/usr/lib/tlac/bpf/"
    log_info "eBPF program installed to /usr/lib/tlac/bpf/"
else
    log_warn "eBPF program ($BPF_PROGRAM) not found. Skipping eBPF support."
fi

# --- 7. Systemd Service Setup ---
log_info "Setting up systemd service..."
cat > /etc/systemd/system/$SERVICE_NAME <<EOF
[Unit]
Description=TLAC Local Anti-Cheat Daemon
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_BIN_DIR/$BIN_NAME --daemon
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable $SERVICE_NAME

# --- Completion ---
echo ""
log_info "============================================"
log_info " TLAC v4.0 Installation Complete!"
log_info "============================================"
log_info " Binary Location   : $INSTALL_BIN_DIR/$BIN_NAME"
log_info " Server Location   : $INSTALL_BIN_DIR/$SERVER_NAME"
log_info " Config Dir        : $CONFIG_DIR"
log_info " Database Path     : $DB_PATH"
log_info ""
log_info "To start the service:"
echo "  sudo systemctl start $SERVICE_NAME"
log_info "To check logs:"
echo "  journalctl -u $SERVICE_NAME -f"
log_info "============================================"
