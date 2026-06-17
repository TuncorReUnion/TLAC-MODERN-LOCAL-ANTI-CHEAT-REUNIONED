#!/bin/bash
# TLAC - Basit Kurulum Scripti (signatures.json dahil)
# Binary'leri ve signatures.json'u /usr/local/bin/ içine kopyalar

set -e

# Renkli çıktı
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}🚀 TLAC Kurulum Başlatılıyor...${NC}"

# Scriptin çalıştığı dizin
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Hedef sistem dizini
TARGET_DIR="/usr/local/bin"

# Config dizini
CONFIG_DIR="$HOME/.config/tlac"

# ============================================================================
# 1. BINARY'LERİ KOPYALA
# ============================================================================

# Anti-Cheat binary
if [ -f "$SCRIPT_DIR/Anti-Cheat" ]; then
    echo -e "${GREEN}✅ Anti-Cheat binary bulundu.${NC}"
    sudo cp "$SCRIPT_DIR/Anti-Cheat" "$TARGET_DIR/Anti-Cheat"
    sudo chmod +x "$TARGET_DIR/Anti-Cheat"
    echo -e "${GREEN}✅ Kuruldu: $TARGET_DIR/Anti-Cheat${NC}"
else
    echo -e "${RED}❌ Anti-Cheat binary bulunamadı: $SCRIPT_DIR/Anti-Cheat${NC}"
    exit 1
fi

# ac-server binary (opsiyonel)
if [ -f "$SCRIPT_DIR/ac-server" ]; then
    echo -e "${GREEN}✅ ac-server binary bulundu.${NC}"
    sudo cp "$SCRIPT_DIR/ac-server" "$TARGET_DIR/ac-server"
    sudo chmod +x "$TARGET_DIR/ac-server"
    echo -e "${GREEN}✅ Kuruldu: $TARGET_DIR/ac-server${NC}"
else
    echo -e "${YELLOW}⚠️  ac-server binary bulunamadı (opsiyonel, atlanıyor)${NC}"
fi

# ============================================================================
# 2. SIGNATURES.JSON KOPYALA
# ============================================================================

if [ -f "$SCRIPT_DIR/signatures.json" ]; then
    echo -e "${GREEN}✅ signatures.json bulundu.${NC}"
    sudo cp "$SCRIPT_DIR/signatures.json" "$TARGET_DIR/signatures.json"
    echo -e "${GREEN}✅ Kuruldu: $TARGET_DIR/signatures.json${NC}"
else
    echo -e "${YELLOW}⚠️  signatures.json bulunamadı. Tarama çalışmayacak!${NC}"
    echo -e "${YELLOW}   Proje kökünden signatures.json dosyasını bu klasöre kopyalayın.${NC}"
fi

# ============================================================================
# 3. CONFIG DİZİNİ HAZIRLA
# ============================================================================

if [ ! -d "$CONFIG_DIR" ]; then
    mkdir -p "$CONFIG_DIR"
    echo -e "${GREEN}✅ Config dizini oluşturuldu: $CONFIG_DIR${NC}"
fi

# ============================================================================
# 4. SON MESAJ
# ============================================================================

echo
echo -e "${GREEN}╔════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ✅ Kurulum Tamamlandı!            ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════╝${NC}"
echo
echo "📦 Kurulan Dosyalar:"
echo "  • $TARGET_DIR/Anti-Cheat"
[ -f "$TARGET_DIR/ac-server" ] && echo "  • $TARGET_DIR/ac-server"
[ -f "$TARGET_DIR/signatures.json" ] && echo "  • $TARGET_DIR/signatures.json"
echo
echo "🚀 Kullanım:"
echo "  sudo Anti-Cheat <PID>          # Ana anti-cheat'i çalıştır"
echo "  sudo ac-server                 # Server modu (varsa)"
echo
echo "⚙️  Config için:"
echo "  ~/.config/tlac/config.json"
echo
echo "🔍 Signature'ları güncellemek için:"
echo "  sudo nano /usr/local/bin/signatures.json"
echo
