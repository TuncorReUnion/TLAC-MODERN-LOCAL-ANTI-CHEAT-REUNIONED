savedcmd_tlac_kernel.mod := printf '%s\n'   tlac_kernel.o | awk '!x[$$0]++ { print("./"$$0) }' > tlac_kernel.mod
