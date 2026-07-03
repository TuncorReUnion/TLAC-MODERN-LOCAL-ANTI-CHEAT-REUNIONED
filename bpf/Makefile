# bpf/Makefile

# Derleyici ve araçlar
CLANG ?= clang
LLVM_STRIP ?= llvm-strip

# Hedef dosya
TARGET := program.bpf.o

# Mimariyi belirt (x86_64 varsayılır)
ARCH ?= x86_64

# Kernel başlık yolları (opsiyonel ama önerilir)
VMLINUX_H := /sys/kernel/btf/vmlinux
ifeq ($(wildcard $(VMLINUX_H)),)
    $(error vmlinux BTF file not found at $(VMLINUX_H). Is CONFIG_DEBUG_INFO_BTF enabled?)
endif

# CFLAGS
CFLAGS := -g -O2 -target bpf
CFLAGS += -D__TARGET_ARCH_$(ARCH)
CFLAGS += -I/usr/include/x86_64-linux-gnu

# Kurallar
.PHONY: all clean

all: $(TARGET)

$(TARGET): program.bpf.c
	$(CLANG) $(CFLAGS) -c $< -o $(TARGET)
	$(LLVM_STRIP) --strip-debug $(TARGET)
	@echo "✅ eBPF bytecode compiled: $@"

clean:
	rm -f $(TARGET)
