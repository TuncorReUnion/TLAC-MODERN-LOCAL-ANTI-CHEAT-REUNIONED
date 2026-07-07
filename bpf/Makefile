<<<<<<< HEAD
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

=======
BPF_PROG = program.bpf.o
BPF_SRC = program.bpf.c
CLANG = clang

$(BPF_PROG): $(BPF_SRC)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86_64 \
		-mllvm -bpf-stack-size=1024 \
		-I/usr/include \
		-I/usr/include/x86_64-linux-gnu \
		-I/usr/include/bpf \
		-c $(BPF_SRC) -o $(BPF_PROG)

obj-m += tlac_kernel.o

KERNEL_MODULE = tlac_kernel.ko

kmod: $(BPF_PROG)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) CC=clang LLVM=1 modules
	@if [ -f $(PWD)/tlac_kernel.ko ]; then \
		echo "✅ Modül başarıyla oluşturuldu: $(PWD)/tlac_kernel.ko"; \
	else \
		echo "⚠️  tlac_kernel.ko bulunamadı, taşınıyor..."; \
		find $(PWD) -name "tlac_kernel.ko" -exec mv -v {} $(PWD)/tlac_kernel.ko \;; \
	fi

all: $(BPF_PROG) kmod

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f $(BPF_PROG) tlac_kernel.ko

.PHONY: all clean kmod
>>>>>>> 744efd6 (TLAC 9.0: eBPF, kernel modülü ve AI entegrasyonu)
