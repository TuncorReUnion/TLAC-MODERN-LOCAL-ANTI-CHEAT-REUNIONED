#!/bin/bash
#
# TLAC v6.0 Uninstaller
# TuncorReUnion - 2026
# License: MIT
#

set -e

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_error() { echo -e "${RED}[!]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[⚠]${NC} $1"; }

# --- Root Check ---
if [ "$EUID" -ne 0 ]; then
    print_error "This script must be run with root privileges!"
    echo "Usage: sudo ./uninstall.sh"
    exit 1
fi

# --- Variables ---
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/tlac"
BPF_DIR="/usr/lib/tlac"
MODEL_DIR="$BIN_DIR/models"

print_status "TLAC v6.0 Uninstallation started..."

# ============================================
# 1. KERNEL MODÜLÜNÜ KALDIR
# ============================================
if lsmod | grep -q "^tlac_kernel"; then
    print_status "Removing kernel module..."
    rmmod tlac_kernel 2>/dev/null
    if lsmod | grep -q "^tlac_kernel"; then
        print_error "Failed to remove kernel module!"
    else
        print_success "Kernel module removed successfully!"
    fi
else
    print_warning "Kernel module not loaded"
fi

# ============================================
# 2. BINARY'LERİ KALDIR
# ============================================
print_status "Removing binaries..."
for binary in anti-cheat server_main; do
    if [ -f "$BIN_DIR/$binary" ]; then
        rm -f "$BIN_DIR/$binary"
        print_success "Removed $binary"
    else
        print_warning "$binary not found in $BIN_DIR"
    fi
done

# ============================================
# 3. AI MODELİNİ KALDIR
# ============================================
if [ -f "$MODEL_DIR/anomaly_model.onnx" ]; then
    rm -f "$MODEL_DIR/anomaly_model.onnx"
    print_success "Removed anomaly_model.onnx"
else
    print_warning "anomaly_model.onnx not found"
fi

# ============================================
# 4. MODELS KLASÖRÜNÜ KALDIR (Eğer boşsa)
# ============================================
if [ -d "$MODEL_DIR" ]; then
    rmdir "$MODEL_DIR" 2>/dev/null
    if [ $? -eq 0 ]; then
        print_success "Removed models directory"
    else
        print_warning "models directory not empty or not found"
    fi
fi

# ============================================
# 5. KONFİGÜRASYON DOSYALARINI KALDIR
# ============================================
if [ -d "$CONFIG_DIR" ]; then
    print_status "Removing configuration directory..."
    rm -rf "$CONFIG_DIR"
    print_success "Removed $CONFIG_DIR"
else
    print_warning "$CONFIG_DIR not found"
fi

# ============================================
# 6. BPF DİZİNİNİ KALDIR
# ============================================
if [ -d "$BPF_DIR" ]; then
    print_status "Removing BPF directory..."
    rm -rf "$BPF_DIR"
    print_success "Removed $BPF_DIR"
else
    print_warning "$BPF_DIR not found"
fi

# ============================================
# 7. SYSTEMD SERVİSİNİ KALDIR (Eğer varsa)
# ============================================
if [ -f "/etc/systemd/system/tlac.service" ]; then
    print_status "Removing systemd service..."
    systemctl stop tlac.service 2>/dev/null
    systemctl disable tlac.service 2>/dev/null
    rm -f "/etc/systemd/system/tlac.service"
    systemctl daemon-reload
    print_success "Removed tlac.service"
else
    print_warning "tlac.service not found"
fi

# ============================================
# 8. VERİTABANINI KALDIR (Opsiyonel)
# ============================================
if [ -f "/var/lib/tlac/anti_cheat.db" ]; then
    read -p "Do you want to remove the ban database? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -f "/var/lib/tlac/anti_cheat.db"
        rmdir "/var/lib/tlac" 2>/dev/null
        print_success "Removed ban database"
    else
        print_warning "Ban database kept at /var/lib/tlac/anti_cheat.db"
    fi
fi

# ============================================
# 9. KERNEL MODÜLÜNÜN DOSYASINI KALDIR
# ============================================
KERNEL_VERSION=$(uname -r)
MODULE_FILE="/lib/modules/${KERNEL_VERSION}/extra/tlac_kernel.ko"
if [ -f "$MODULE_FILE" ]; then
    rm -f "$MODULE_FILE"
    print_success "Removed kernel module file"
else
    print_warning "Kernel module file not found"
fi

# ============================================
# 10. KURULUM SONRASI BİLGİ
# ============================================
print_success "TLAC v6.0 uninstallation completed!"
echo ""
echo "📁 Removed directories:"
echo "  $CONFIG_DIR"
echo "  $BPF_DIR"
echo "  $MODEL_DIR"
echo ""
echo "📁 Removed files:"
echo "  $BIN_DIR/anti-cheat"
echo "  $BIN_DIR/server_main"
echo "  $BIN_DIR/models/anomaly_model.onnx"
echo "  /etc/systemd/system/tlac.service"
echo "  $MODULE_FILE"
echo ""
echo "💡 Note: The ban database may still exist at /var/lib/tlac/anti_cheat.db"
echo "   To remove it, run: sudo rm -f /var/lib/tlac/anti_cheat.db"
