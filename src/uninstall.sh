#!/bin/bash
# TLAC - Tuncor's Local Anti-Cheat
# Uninstallation script for TLAC 9.0

set -e

echo "🗑️  TLAC 9.0 Uninstallation Starting..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}❌ Please run as root (sudo ./uninstall.sh)${NC}"
    exit 1
fi

echo -e "${YELLOW}⚠️  This will remove TLAC completely from your system.${NC}"
read -p "Are you sure? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${GREEN}Uninstallation cancelled.${NC}"
    exit 0
fi

# Remove binaries
echo -e "${YELLOW}📦 Removing binaries...${NC}"
rm -f /usr/local/bin/tlac
rm -f /usr/local/bin/tlac-server
echo -e "${GREEN}✅ Binaries removed${NC}"

# Remove kernel module
echo -e "${YELLOW}🔧 Removing kernel module...${NC}"
if lsmod | grep -q tlac_kernel; then
    rmmod tlac_kernel 2>/dev/null || true
    echo -e "${GREEN}✅ Kernel module unloaded${NC}"
fi
rm -f /lib/modules/$(uname -r)/tlac_kernel.ko
echo -e "${GREEN}✅ Kernel module removed${NC}"

# Remove eBPF program
echo -e "${YELLOW}📡 Removing eBPF program...${NC}"
rm -f /usr/lib/tlac/program.bpf.o
echo -e "${GREEN}✅ eBPF program removed${NC}"

# Remove configuration files
echo -e "${YELLOW}⚙️  Removing configuration files...${NC}"
rm -rf /etc/tlac
echo -e "${GREEN}✅ Configuration files removed${NC}"

# Remove logs
echo -e "${YELLOW}📋 Removing log files...${NC}"
rm -rf /var/log/tlac
rm -f /etc/logrotate.d/tlac
echo -e "${GREEN}✅ Log files removed${NC}"

# Remove service
echo -e "${YELLOW}🔄 Removing service...${NC}"
if command -v systemctl &>/dev/null; then
    if systemctl is-active --quiet tlac.service 2>/dev/null; then
        systemctl stop tlac.service
    fi
    systemctl disable tlac.service 2>/dev/null || true
    rm -f /etc/systemd/system/tlac.service
    systemctl daemon-reload
    echo -e "${GREEN}✅ Systemd service removed${NC}"
elif [ -d "/etc/sv" ]; then
    sv down tlac 2>/dev/null || true
    rm -f /var/service/tlac
    rm -rf /etc/sv/tlac
    echo -e "${GREEN}✅ Runit service removed${NC}"
fi

# Remove empty directories
echo -e "${YELLOW}🧹 Cleaning up directories...${NC}"
rmdir /usr/lib/tlac 2>/dev/null || true

echo -e "${GREEN}✅ TLAC $VERSION uninstallation completed!${NC}"
