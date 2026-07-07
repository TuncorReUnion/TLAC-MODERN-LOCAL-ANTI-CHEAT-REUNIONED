#!/bin/bash
set -e

echo "🔧 TLAC v8.0 Sistem Entegrasyonu Başlatılıyor..."

if [ "$(id -u)" -ne 0 ]; then
    echo "❌ Hata: Bu işlem root yetkisi gerektirir."
    exit 1
fi

REQUIRED_FILES=("tlac" "server_main" "tlac_kernel.ko" "program.bpf.o" "anomaly_model.onnx" "signatures.json")
for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "./$file" ]; then
        echo "❌ Hata: Gerekli dosya bulunamadı: $file"
        exit 1
    fi
done

echo " Dizin Yapısı Oluşturuluyor..."
mkdir -p /etc/tlac
mkdir -p /lib/tlac
mkdir -p /var/lib/tlac

echo "🛡️ Binary Dosyaları Yükleniyor..."
cp ./tlac /usr/local/bin/tlac
cp ./server_main /usr/local/bin/server_main
chmod +x /usr/local/bin/tlac
chmod +x /usr/local/bin/server_main

echo " Kernel ve eBPF Bileşenleri Yerleştiriliyor..."
cp ./tlac_kernel.ko /lib/tlac/tlac_kernel.ko
cp ./program.bpf.o /lib/tlac/program.bpf.o

echo "🧠 AI Modeli ve İmzalar Yapılandırılıyor..."
cp ./anomaly_model.onnx /etc/tlac/anomaly_model.onnx
cp ./signatures.json /etc/tlac/signatures.json

echo "💾 Veritabanı Başlatılıyor..."
touch /var/lib/tlac/anti_cheat.db

echo "✅ TLAC v8.0 Başarıyla Sisteme Entegre Edildi!"
echo "   Anti-Cheat: sudo tlac <hedef_pid>"
echo "   Sunucu:     sudo server_main"
