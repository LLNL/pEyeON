risc-v test binary thing

test object file for riscv to help pEyeON with detection + disassembly testing.

goal
create a basic riscv ELF object file for use in structural or feature extraction tests.

tools i used

    riscv64-unknown-elf-as

    file (to verify)

    readelf (optional, for header checking)

how i did it

    made a 1-instruction asm file (nop.s)

    used the assembler to build nop.o

    confirmed it was riscv relocatable with file

    moved it into tests/binaries/ELF_object_riscv/

result
nop.o is a tiny but valid ELF object for riscv — good for lightweight tests.

sudo apt install gcc-riscv64-unknown-elf

cat <<EOF > nop.s
.section .text
.global _start
_start:
nop
EOF

riscv64-unknown-elf-as -o nop.o nop.s

file nop.o

mkdir -p ~/pEyeON/tests/binaries/ELF_object_riscv

mv nop.o ~/pEyeON/tests/binaries/ELF_object_riscv/

readelf -h ~/pEyeON/tests/binaries/ELF_object_riscv/nop.o