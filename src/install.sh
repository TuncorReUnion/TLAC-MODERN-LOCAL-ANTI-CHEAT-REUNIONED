#!/bin/bash

# ==============================================================================
# TLAC (Tuncor's Local Anti-Cheat) v4.0 Installer
# Description: Installs the anti-cheat binary, configuration files, and kernel module.
# License: MIT
# ==============================================================================

set -e # Exit immediately if a command exits with a non-zero status.

# --- Configuration ---
INSTALL_DIR="/opt/tlac"
BIN_NAME="anti-cheat"
CONFIG_DIR="/etc/tlac"
DB_PATH="/var/lib/tlac/anti_cheat.db"
SERVICE_NAME="tlac.service"
KERNEL_MODULE="tlac_kernel.ko"

# --- Colors for Output ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$(dirname "$DB_PATH")"

# --- 3. Install Binary & Configs ---
log_info "Installing binary to $INSTALL_DIR..."
if [ ! -f "$BIN_NAME" ]; then
    log_error "Binary '$BIN_NAME' not found in current directory. Please run this script from the release folder."
fi
cp "$BIN_NAME" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/$BIN_NAME"

# Install default signatures if not present
if [ ! -f "$CONFIG_DIR/signatures.json" ]; then
    log_info "Installing default signature database..."
    if [ -f "signatures.json" ]; then
        cp "signatures.json" "$CONFIG_DIR/"
    else
        log_warn "signatures.json not found. You will need to create one manually at $CONFIG_DIR/signatures.json"
    fi
fi

# --- 4. Kernel Module (Optional) ---
if [ -f "$KERNEL_MODULE" ]; then
    log_info "Installing kernel module..."
    cp "$KERNEL_MODULE" "/lib/modules/$(uname -r)/extra/"
    depmod -a
    modprobe tlac_kernel || log_warn "Failed to load kernel module. It may require a reboot or specific kernel config."
else
    log_warn "Kernel module ($KERNEL_MODULE) not found. Skipping kernel-level protection."
fi

# --- 5. Systemd Service Setup ---
log_info "Setting up systemd service..."
cat > /etc/systemd/system/$SERVICE_NAME <<EOF
[Unit]
Description=TLAC Local Anti-Cheat Daemon
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/$BIN_NAME --daemon
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
log_info " Binary Location : $INSTALL_DIR/$BIN_NAME"
log_info " Config Dir      : $CONFIG_DIR"
log_info " Database Path   : $DB_PATH"
log_info ""
log_info "To start the service:"
echo "  sudo systemctl start $SERVICE_NAME"
log_info "To check logs:"
echo "  journalctl -u $SERVICE_NAME -f"
log_info "============================================"
