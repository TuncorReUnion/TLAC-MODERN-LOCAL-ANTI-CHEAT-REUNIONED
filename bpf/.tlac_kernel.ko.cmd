<<<<<<< HEAD
savedcmd_tlac_kernel.ko := ld.lld -r -m elf_x86_64 -mllvm -import-instr-limit=5 --mllvm=-enable-fs-discriminator=true --mllvm=-improved-fs-discriminator=true -plugin-opt=thinlto -plugin-opt=-split-machine-functions -z noexecstack --build-id=sha1  -T /usr/lib/modules/7.1.3-1-cachyos/build/scripts/module.lds -o tlac_kernel.ko tlac_kernel.o tlac_kernel.mod.o .module-common.o
=======
savedcmd_tlac_kernel.ko := ld.lld -r -m elf_x86_64 -mllvm -import-instr-limit=5 --mllvm=-enable-fs-discriminator=true --mllvm=-improved-fs-discriminator=true -plugin-opt=thinlto -plugin-opt=-split-machine-functions -z noexecstack --build-id=sha1  -T /usr/lib/modules/7.1.3-2-cachyos/build/scripts/module.lds -o tlac_kernel.ko tlac_kernel.o tlac_kernel.mod.o .module-common.o
>>>>>>> 744efd6 (TLAC 9.0: eBPF, kernel modülü ve AI entegrasyonu)
