#!/bin/bash
#
# TLAC v3.0 - Installer
# TuncorReUnion - 2026
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_error() { echo -e "${RED}[!]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[⚠]${NC} $1"; }

if [ "$EUID" -ne 0 ]; then 
    print_error "This script must be run with root privileges!"
    echo "Usage: sudo ./install.sh"
    exit 1
fi

KERNEL_VERSION=$(uname -r)
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/tlac"
MODULE_DIR="/lib/modules/${KERNEL_VERSION}/extra"
BPF_DIR="/usr/lib/tlac/bpf"

print_status "TLAC v3.0 Installation started..."
print_status "Kernel: ${KERNEL_VERSION}"

mkdir -p "$BIN_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$MODULE_DIR"
mkdir -p "$BPF_DIR"

# ============================================
# 1. MAIN BINARY
# ============================================
if [ -f "Anti-Cheat" ]; then
    cp Anti-Cheat "$BIN_DIR/tlac"
    chmod +x "$BIN_DIR/tlac"
    print_success "Anti-Cheat -> $BIN_DIR/tlac"
else
    print_error "Anti-Cheat binary not found!"
    exit 1
fi

# ============================================
# 2. SERVER BINARY
# ============================================
if [ -f "ac-server" ]; then
    cp ac-server "$BIN_DIR/ac-server"
    chmod +x "$BIN_DIR/ac-server"
    print_success "ac-server -> $BIN_DIR/ac-server"
else
    print_warning "ac-server not found (optional)"
fi

# ============================================
# 3. CONFIGURATION
# ============================================
if [ -f "signatures.json" ]; then
    cp signatures.json "$CONFIG_DIR/"
    print_success "signatures.json -> $CONFIG_DIR/"
else
    print_warning "signatures.json not found"
fi

# ============================================
# 4. KERNEL MODULE (from kernel/ folder)
# ============================================
if [ -f "kernel/tlac_kernel.ko" ]; then
    cp kernel/tlac_kernel.ko "$MODULE_DIR/"
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
    print_warning "kernel/tlac_kernel.ko not found (module skipped)"
fi

# ============================================
# 5. eBPF PROGRAM (from bpf/ folder)
# ============================================
if [ -f "bpf/program.bpf.o" ]; then
    cp bpf/program.bpf.o "$BPF_DIR/"
    print_success "program.bpf.o -> $BPF_DIR/"
else
    print_warning "bpf/program.bpf.o not found (eBPF skipped)"
fi

# ============================================
# 6. POST-INSTALLATION CHECK
# ============================================
if [ -f "/proc/tlac_status" ]; then
    print_success "/proc/tlac_status is active!"
    cat /proc/tlac_status
fi

print_success "TLAC v3.0 installation completed!"
echo ""
echo "📦 Usage:"
echo "  sudo tlac <PID>"
echo "  sudo ac-server"
echo "  cat /proc/tlac_status"
echo ""
echo "📁 File locations:"
echo "  Main Binary:   $BIN_DIR/tlac"
echo "  Server:        $BIN_DIR/ac-server"
echo "  Config:        $CONFIG_DIR/signatures.json"
echo "  Kernel Module: $MODULE_DIR/tlac_kernel.ko"
echo "  eBPF:          $BPF_DIR/program.bpf.o"
