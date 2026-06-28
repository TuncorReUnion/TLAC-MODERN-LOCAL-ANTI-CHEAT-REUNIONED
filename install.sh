#!/bin/bash
#
# TLAC v2.0 - Hybrid Anti-Cheat Installer
# TuncorReUnion - 2026
#

set -e  # Hata durumunda durdur
set -u  # Tanımsız değişken kullanımına izin verme

# Renkli çıktı için
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_error() { echo -e "${RED}[!]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[⚠]${NC} $1"; }

# Kullanıcı root mu kontrol et
if [ "$EUID" -ne 0 ]; then
    print_error "Bu betik root yetkileriyle çalıştırılmalıdır!"
    echo "Kullanım: sudo ./install.sh"
    exit 1
fi

# Sistem bilgilerini al
KERNEL_VERSION=$(uname -r)
USER_HOME=$(eval echo ~${SUDO_USER:-$USER})
INSTALL_DIR="/opt/tlac"
CONFIG_DIR="/etc/tlac"
BIN_DIR="/usr/local/bin"
MODULE_DIR="/lib/modules/${KERNEL_VERSION}/extra"

print_status "TLAC v2.0 Kurulumu başlatılıyor..."
print_status "Kernel versiyonu: ${KERNEL_VERSION}"

# 1. Bağımlılıkları kontrol et ve kur
print_status "Bağımlılıklar kontrol ediliyor..."

# Paket yöneticisini belirle
PKG_MANAGER=""
if command -v pacman &> /dev/null; then
    PKG_MANAGER="pacman"
    INSTALL_CMD="pacman -S --noconfirm"
elif command -v apt &> /dev/null; then
    PKG_MANAGER="apt"
    INSTALL_CMD="apt install -y"
elif command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
    INSTALL_CMD="dnf install -y"
elif command -v zypper &> /dev/null; then
    PKG_MANAGER="zypper"
    INSTALL_CMD="zypper install -y"
else
    print_warning "Paket yöneticisi tespit edilemedi. Bağımlılıkları manuel kurun."
fi

# Bağımlılıkları kontrol et
NEEDED_PKGS=""
if ! command -v make &> /dev/null; then
    NEEDED_PKGS="$NEEDED_PKGS make"
fi
if ! command -v gcc &> /dev/null && ! command -v clang &> /dev/null; then
    NEEDED_PKGS="$NEEDED_PKGS gcc"
fi
if ! command -v rustc &> /dev/null; then
    NEEDED_PKGS="$NEEDED_PKGS rust cargo"
fi
if ! command -v bear &> /dev/null && [ -f "/usr/lib/modules/${KERNEL_VERSION}/build" ]; then
    # Bear sadece kernel modülü derlemek için gerekiyor
    NEEDED_PKGS="$NEEDED_PKGS bear"
fi

if [ -n "$NEEDED_PKGS" ] && [ -n "$PKG_MANAGER" ]; then
    print_warning "Gerekli paketler kuruluyor: $NEEDED_PKGS"
    eval "$INSTALL_CMD $NEEDED_PKGS"
fi

# 2. Kernel headers kontrolü
print_status "Kernel headers kontrol ediliyor..."
HEADER_PATH="/usr/lib/modules/${KERNEL_VERSION}/build"
if [ ! -d "$HEADER_PATH" ]; then
    print_warning "Kernel headers bulunamadı! (${HEADER_PATH})"
    if [ "$PKG_MANAGER" = "pacman" ]; then
        eval "$INSTALL_CMD linux-cachyos-headers"
    else
        print_error "Lütfen kernel headers paketini manuel kurun:"
        echo "  - Arch:   pacman -S linux-cachyos-headers"
        echo "  - Ubuntu: apt install linux-headers-$(uname -r)"
        echo "  - Fedora: dnf install kernel-devel-$(uname -r)"
        exit 1
    fi
fi

# 3. Klasörleri oluştur
print_status "Klasörler oluşturuluyor..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$MODULE_DIR"

# 4. Kernel modülünü derle
print_status "Kernel modülü derleniyor..."
if [ -f "kernel/tlac_kernel.c" ]; then
    cd kernel
    # Derleyici kontrolü
    if grep -q "clang version" /usr/lib/modules/${KERNEL_VERSION}/build/Makefile 2>/dev/null; then
        make CC=clang LD=ld.lld
    else
        make
    fi
    cd ..
else
    print_error "tlac_kernel.c bulunamadı! kernel/ klasörünü kontrol edin."
    exit 1
fi

# 5. Rust projesini derle
print_status "Rust projesi derleniyor..."
if [ -f "Cargo.toml" ]; then
    cargo build --release
else
    print_error "Cargo.toml bulunamadı!"
    exit 1
fi

# 6. Dosyaları kopyala
print_status "Dosyalar kopyalanıyor..."
cp -r kernel/*.ko "$MODULE_DIR/" 2>/dev/null || print_warning "Modül dosyası kopyalanamadı"
cp target/release/Anti-Cheat "$BIN_DIR/tlac"
cp config/signatures.json "$CONFIG_DIR/"
cp ac-server "$BIN_DIR/ac-server" 2>/dev/null || print_warning "ac-server bulunamadı"

# 7. Kernel modülünü yükle
print_status "Kernel modülü yükleniyor..."
MODULE_NAME="tlac_kernel"
if lsmod | grep -q "^${MODULE_NAME}"; then
    print_warning "Modül zaten yüklü, kaldırılıyor..."
    rmmod "${MODULE_NAME}" 2>/dev/null
fi
insmod "$MODULE_DIR/${MODULE_NAME}.ko" 2>/dev/null || {
    print_error "Modül yüklenemedi! dmesg çıktısını kontrol edin."
    dmesg | tail -20
    exit 1
}

# 8. Modülün çalıştığını doğrula
if lsmod | grep -q "^${MODULE_NAME}"; then
    print_success "Kernel modülü başarıyla yüklendi!"
else
    print_error "Kernel modülü yüklenemedi!"
    exit 1
fi

# 9. /proc/tlac_status kontrol et
if [ -f "/proc/tlac_status" ]; then
    print_success "/proc/tlac_status oluşturuldu!"
    cat /proc/tlac_status
else
    print_warning "/proc/tlac_status bulunamadı. Modül çalışıyor olabilir."
fi

# 10. Kurulum bilgilerini göster
print_success "TLAC v2.0 başarıyla kuruldu!"
echo ""
echo "📦 Kullanım:"
echo "  1. PID ile çalıştır:  sudo tlac <PID>"
echo "  2. Kernel durumunu kontrol et: cat /proc/tlac_status"
echo "  3. Modülü kaldır: sudo rmmod tlac_kernel"
echo ""
echo "📁 Dosya konumları:"
echo "  Binary:     $BIN_DIR/tlac"
echo "  Config:     $CONFIG_DIR/signatures.json"
echo "  Modül:      $MODULE_DIR/tlac_kernel.ko"
echo "  Sunucu:     $BIN_DIR/ac-server"
echo ""

# 11. Otomatik modül yükleme için systemd servisi (opsiyonel)
read -p "Otomatik modül yükleme için systemd servisi kurulsun mu? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    cat > /etc/systemd/system/tlac-module.service << EOF
[Unit]
Description=TLAC Kernel Module
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/insmod $MODULE_DIR/tlac_kernel.ko
ExecStop=/usr/sbin/rmmod tlac_kernel
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable tlac-module.service
    print_success "Systemd servisi oluşturuldu!"
fi

print_success "Kurulum tamamlandı! 🚀"
