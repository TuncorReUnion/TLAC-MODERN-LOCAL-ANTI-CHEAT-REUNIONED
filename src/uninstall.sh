#!/bin/bash
set -e

echo "🗑️ TLAC v8.0 Sistemden Temizleniyor..."

if [ "$(id -u)" -ne 0 ]; then
    echo "❌ Hata: Bu işlem root yetkisi gerektirir."
    exit 1
fi

echo "⏹️ Çalışan Process'ler Durduruluyor..."
pkill -f "tlac" 2>/dev/null || true
pkill -f "server_main" 2>/dev/null || true
sleep 1

echo " Kernel Modülü Güvenli Şekilde Kaldırılıyor..."
rmmod tlac_kernel 2>/dev/null || echo "⚠️ Kernel modülü zaten yüklü değil."

echo "🗑️ Binary Dosyaları Siliniyor..."
rm -f /usr/local/bin/tlac
rm -f /usr/local/bin/server_main

echo "🗑️ Yapılandırma ve Kernel Dosyaları Temizleniyor..."
rm -rf /lib/tlac
rm -rf /etc/tlac
rm -f /tmp/anti-cheat.sock

echo "💾 Veritabanı Yedekleniyor ve Temizleniyor..."
if [ -d "/var/lib/tlac" ]; then
    cp -r /var/lib/tlac /var/lib/tlac_backup_$(date +%s)
    rm -rf /var/lib/tlac
fi

echo "✅ TLAC v8.0 Tamamen Kaldırıldı."
echo "   Yedek klasör: /var/lib/tlac_backup_*"
