#!/bin/bash
#
# TLAC v6.0 Installer
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
    echo "Usage: sudo ./install.sh"
    exit 1
fi

# --- Variables ---
KERNEL_VERSION=$(uname -r)
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/tlac"
MODULE_DIR="/lib/modules/${KERNEL_VERSION}/extra"
BPF_DIR="/usr/lib/tlac/bpf"

print_status "TLAC v6.0 Installation started..."
print_status "Kernel: ${KERNEL_VERSION}"

# --- Create Directories ---
print_status "Creating directories..."
mkdir -p "$BIN_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$MODULE_DIR"
mkdir -p "$BPF_DIR"

# ============================================
# 1. MAIN BINARY (anti-cheat)
# ============================================
if [ -f "anti-cheat" ]; then
    cp anti-cheat "$BIN_DIR/"
    chmod +x "$BIN_DIR/anti-cheat"
    print_success "anti-cheat -> $BIN_DIR/"
else
    print_error "anti-cheat binary not found!"
    exit 1
fi

# ============================================
# 2. SERVER BINARY (server_main)
# ============================================
if [ -f "server_main" ]; then
    cp server_main "$BIN_DIR/"
    chmod +x "$BIN_DIR/server_main"
    print_success "server_main -> $BIN_DIR/"
else
    print_warning "server_main not found (optional)"
fi

# ============================================
# 3. CONFIGURATION (signatures.json)
# ============================================
if [ -f "signatures.json" ]; then
    cp signatures.json "$CONFIG_DIR/"
    print_success "signatures.json -> $CONFIG_DIR/"
else
    print_warning "signatures.json not found"
fi

# ============================================
# 4. KERNEL MODULE (tlac_kernel.ko)
# ============================================
if [ -f "tlac_kernel.ko" ]; then
    cp tlac_kernel.ko "$MODULE_DIR/"
    print_success "tlac_kernel.ko -> $MODULE_DIR/"

    print_status "Loading kernel module..."
    if lsmod | grep -q "^tlac_kernel"; then
        rmmod tlac_kernel 2>/dev/null
    fi
    insmod "$MODULE_DIR/tlac_kernel.ko" 2>/dev/null
    if lsmod | grep -q "^tlac_kernel"; then
        print_success "Kernel module loaded successfully!"
    else
        print_warning "Failed to load kernel module (check dmesg)"
    fi
else
    print_warning "tlac_kernel.ko not found (module skipped)"
fi

# ============================================
# 5. eBPF PROGRAM (program.bpf.o)
# ============================================
if [ -f "program.bpf.o" ]; then
    cp program.bpf.o "$BPF_DIR/"
    print_success "program.bpf.o -> $BPF_DIR/"
else
    print_warning "program.bpf.o not found (eBPF skipped)"
fi

# ============================================
# 6. AI MODEL (anomaly_model.onnx) -> Binary ile aynı dizine
# ============================================
if [ -f "anomaly_model.onnx" ]; then
    cp anomaly_model.onnx "$BIN_DIR/"
    print_success "anomaly_model.onnx -> $BIN_DIR/"
else
    print_warning "anomaly_model.onnx not found (AI skipped)"
fi

# ============================================
# 7. POST-INSTALLATION CHECK
# ============================================
if [ -f "/proc/tlac_status" ]; then
    print_success "/proc/tlac_status is active!"
    cat /proc/tlac_status
fi

print_success "TLAC v6.0 installation completed!"
echo ""
echo "📦 Usage:"
echo "  sudo anti-cheat <PID>"
echo "  sudo server_main"
echo "  cat /proc/tlac_status"
echo ""
echo "📁 File locations:"
echo "  Main Binary:    $BIN_DIR/anti-cheat"
echo "  Server:         $BIN_DIR/server_main"
echo "  Config:         $CONFIG_DIR/signatures.json"
echo "  Kernel Module:  $MODULE_DIR/tlac_kernel.ko"
echo "  eBPF:           $BPF_DIR/program.bpf.o"
echo "  AI Model:       $BIN_DIR/anomaly_model.onnx"
echo ""
echo "📌 To test eBPF logs:"
echo "  sudo cat /sys/kernel/debug/tracing/trace_pipe"
