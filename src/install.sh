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
    print_error "Bu betik root yetkileriyle çalıştırılmalıdır!"
    echo "Kullanım: sudo ./install.sh"
    exit 1
fi

KERNEL_VERSION=$(uname -r)
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/tlac"
MODULE_DIR="/lib/modules/${KERNEL_VERSION}/extra"
BPF_DIR="/usr/lib/tlac/bpf"

print_status "TLAC v3.0 Kurulumu başlatılıyor..."
print_status "Kernel: ${KERNEL_VERSION}"

mkdir -p "$BIN_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$MODULE_DIR"
mkdir -p "$BPF_DIR"

# ============================================
# 1. ANA BINARY
# ============================================
if [ -f "Anti-Cheat" ]; then
    cp Anti-Cheat "$BIN_DIR/tlac"
    chmod +x "$BIN_DIR/tlac"
    print_success "Anti-Cheat -> $BIN_DIR/tlac"
else
    print_error "Anti-Cheat binary'si bulunamadı!"
    exit 1
fi

# ============================================
# 2. SUNUCU BINARY
# ============================================
if [ -f "ac-server" ]; then
    cp ac-server "$BIN_DIR/ac-server"
    chmod +x "$BIN_DIR/ac-server"
    print_success "ac-server -> $BIN_DIR/ac-server"
else
    print_warning "ac-server bulunamadı (opsiyonel)"
fi

# ============================================
# 3. KONFİGÜRASYON
# ============================================
if [ -f "signatures.json" ]; then
    cp signatures.json "$CONFIG_DIR/"
    print_success "signatures.json -> $CONFIG_DIR/"
else
    print_warning "signatures.json bulunamadı"
fi

# ============================================
# 4. KERNEL MODÜLÜ (kernel/ klasöründen)
# ============================================
if [ -f "kernel/tlac_kernel.ko" ]; then
    cp kernel/tlac_kernel.ko "$MODULE_DIR/"
    print_success "tlac_kernel.ko -> $MODULE_DIR/"

    print_status "Kernel modülü yükleniyor..."
    if lsmod | grep -q "^tlac_kernel"; then
        rmmod tlac_kernel 2>/dev/null
    fi
    insmod "$MODULE_DIR/tlac_kernel.ko" 2>/dev/null
    if lsmod | grep -q "^tlac_kernel"; then
        print_success "Kernel modülü yüklendi!"
    else
        print_warning "Kernel modülü yüklenemedi (dmesg kontrol et)"
    fi
else
    print_warning "kernel/tlac_kernel.ko bulunamadı (modül atlandı)"
fi

# ============================================
# 5. eBPF PROGRAMI (bpf/ klasöründen)
# ============================================
if [ -f "bpf/program.bpf.o" ]; then
    cp bpf/program.bpf.o "$BPF_DIR/"
    print_success "program.bpf.o -> $BPF_DIR/"
else
    print_warning "bpf/program.bpf.o bulunamadı (eBPF atlandı)"
fi

# ============================================
# 6. KURULUM SONRASI
# ============================================
if [ -f "/proc/tlac_status" ]; then
    print_success "/proc/tlac_status aktif!"
    cat /proc/tlac_status
fi

print_success "TLAC v3.0 kurulumu tamamlandı!"
echo ""
echo "📦 Kullanım:"
echo "  sudo tlac <PID>"
echo "  sudo ac-server"
echo "  cat /proc/tlac_status"
echo ""
echo "📁 Dosya konumları:"
echo "  Ana Binary:   $BIN_DIR/tlac"
echo "  Sunucu:       $BIN_DIR/ac-server"
echo "  Config:       $CONFIG_DIR/signatures.json"
echo "  Kernel Modülü: $MODULE_DIR/tlac_kernel.ko"
echo "  eBPF:         $BPF_DIR/program.bpf.o"
