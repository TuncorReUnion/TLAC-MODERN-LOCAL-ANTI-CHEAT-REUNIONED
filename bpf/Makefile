# TLAC v8.0 Universal Makefile (eBPF + Kernel Module) - Clang + LLVM Linker
# Assumes kernel was built with Clang (like Cachyos)

CLANG ?= clang
BPFTOOL ?= bpftool
KVER := $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build

VMLINUX_H := vmlinux.h

.PHONY: all clean bpf kmod

all: bpf kmod

# === eBPF Section ===
$(VMLINUX_H):
	@test -f /sys/kernel/btf/vmlinux || { echo "ERROR: BTF not found. Install linux-headers."; exit 1; }
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

bpf: $(VMLINUX_H)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86_64 \
		-mllvm -bpf-stack-size=1024 \
		-c program.bpf.c -o program.bpf.o

# === Kernel Module Section (Force Clang + LLVM Linker) ===
obj-m += tlac_kernel.o

kmod: $(VMLINUX_H)
	@test -d $(KDIR) || { echo "ERROR: Kernel headers not found at $(KDIR)."; exit 1; }
	$(MAKE) -C $(KDIR) M=$(PWD) CC=$(CLANG) LLVM=1 modules

clean:
	rm -f $(VMLINUX_H) program.bpf.o *.o *.ko .*.cmd Module.symvers modules.order
	$(MAKE) -C $(KDIR) M=$(PWD) clean 2>/dev/null || true

