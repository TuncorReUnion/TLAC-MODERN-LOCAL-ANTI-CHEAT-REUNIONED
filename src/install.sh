#!/bin/bash
# TLAC - Tuncor's Local Anti-Cheat
# Installation script for TLAC 9.0

set -e

echo "🚀 TLAC 9.0 Installation Starting..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}❌ Please run as root (sudo ./install.sh)${NC}"
    exit 1
fi

# Define paths
TLAC_BIN="/usr/local/bin/tlac"
TLAC_SERVER="/usr/local/bin/tlac-server"
TLAC_KERNEL_MODULE="/lib/modules/$(uname -r)/tlac_kernel.ko"
TLAC_CONFIG_DIR="/etc/tlac"
BPF_PROG="/usr/lib/tlac/program.bpf.o"
VERSION="9.0"

echo -e "${YELLOW}📁 Creating directories...${NC}"
mkdir -p "$TLAC_CONFIG_DIR"
mkdir -p "/usr/lib/tlac"
mkdir -p "/var/log/tlac"

# Copy binaries
echo -e "${YELLOW}📦 Installing binaries...${NC}"
if [ -f "./tlac" ]; then
    cp "./tlac" "$TLAC_BIN"
    chmod 755 "$TLAC_BIN"
    echo -e "${GREEN}✅ tlac installed to $TLAC_BIN${NC}"
else
    echo -e "${RED}❌ tlac binary not found.${NC}"
    exit 1
fi

if [ -f "./server_main" ]; then
    cp "./server_main" "$TLAC_SERVER"
    chmod 755 "$TLAC_SERVER"
    echo -e "${GREEN}✅ tlac-server installed to $TLAC_SERVER${NC}"
fi

# Install kernel module
echo -e "${YELLOW}🔧 Installing kernel module...${NC}"
if [ -f "./tlac_kernel.ko" ]; then
    cp "./tlac_kernel.ko" "$TLAC_KERNEL_MODULE"
    
    # Remove old module if loaded
    if lsmod | grep -q tlac_kernel; then
        rmmod tlac_kernel 2>/dev/null || true
        echo -e "${YELLOW}⚠️  Old kernel module unloaded${NC}"
    fi
    
    # Load new module
    insmod "$TLAC_KERNEL_MODULE" 2>/dev/null || {
        echo -e "${RED}❌ Failed to load kernel module. Check dmesg for details.${NC}"
        exit 1
    }
    echo -e "${GREEN}✅ Kernel module installed and loaded${NC}"
else
    echo -e "${RED}❌ tlac_kernel.ko not found.${NC}"
    exit 1
fi

# Install eBPF program
echo -e "${YELLOW}📡 Installing eBPF program...${NC}"
if [ -f "./program.bpf.o" ]; then
    cp "./program.bpf.o" "$BPF_PROG"
    echo -e "${GREEN}✅ eBPF program installed to $BPF_PROG${NC}"
else
    echo -e "${YELLOW}⚠️  eBPF program not found, skipping...${NC}"
fi

# Copy configuration files
echo -e "${YELLOW}⚙️  Installing configuration files...${NC}"
if [ -f "./signatures.json" ]; then
    cp "./signatures.json" "$TLAC_CONFIG_DIR/"
    echo -e "${GREEN}✅ signatures.json copied${NC}"
fi

if [ -f "./anomaly_model.onnx" ]; then
    cp "./anomaly_model.onnx" "$TLAC_CONFIG_DIR/"
    echo -e "${GREEN}✅ AI model (ONNX) copied${NC}"
fi

# Create config file
echo -e "${YELLOW}📝 Creating default configuration...${NC}"
cat > "$TLAC_CONFIG_DIR/config.toml" << 'EOF'
[general]
log_level = "info"
log_file = "/var/log/tlac/tlac.log"

[server]
listen_addr = "127.0.0.1:8080"

[anti_cheat]
signature_file = "/etc/tlac/signatures.json"
model_file = "/etc/tlac/anomaly_model.onnx"
eBPF_program = "/usr/lib/tlac/program.bpf.o"
kernel_module = "/lib/modules/$(uname -r)/tlac_kernel.ko"

[protection]
enabled = true
mode = "active"
ban_threshold = 5
EOF

# Set up service (runit for Void, systemd for others)
echo -e "${YELLOW}🔄 Setting up service...${NC}"
if command -v systemctl &>/dev/null; then
    cat > /etc/systemd/system/tlac.service << 'EOF'
[Unit]
Description=TLAC - Tuncor's Local Anti-Cheat
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/tlac
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable tlac.service
    echo -e "${GREEN}✅ Systemd service installed${NC}"
elif [ -d "/etc/sv" ]; then
    mkdir -p /etc/sv/tlac
    cat > /etc/sv/tlac/run << 'EOF'
#!/bin/sh
exec /usr/local/bin/tlac
EOF
    chmod +x /etc/sv/tlac/run
    ln -sf /etc/sv/tlac /var/service/
    echo -e "${GREEN}✅ Runit service installed${NC}"
else
    echo -e "${YELLOW}⚠️  No service manager detected. Run manually: sudo /usr/local/bin/tlac${NC}"
fi

# Create log rotation
echo -e "${YELLOW}📋 Setting up log rotation...${NC}"
if command -v logrotate &>/dev/null; then
    cat > /etc/logrotate.d/tlac << 'EOF'
/var/log/tlac/tlac.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 0640 root root
}
EOF
    echo -e "${GREEN}✅ Log rotation configured${NC}"
fi

# Add user to required groups
echo -e "${YELLOW}👤 Adding current user to required groups...${NC}"
if [ -n "$SUDO_USER" ]; then
    usermod -aG input,video,audio "$SUDO_USER" 2>/dev/null || true
    echo -e "${GREEN}✅ User $SUDO_USER added to input,video,audio groups${NC}"
fi

echo -e "${GREEN}✅ TLAC $VERSION installation completed!${NC}"
echo -e "${YELLOW}🚀 Start TLAC: sudo tlac${NC}"
echo -e "${YELLOW}📖 Check logs: sudo journalctl -u tlac${NC}"
