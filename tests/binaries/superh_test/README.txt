superH test binary thing

a tiny object file for superH (sh4) — made for testing pEyeON’s parser.

goal
make a simple relocatable ELF for SH-4 that we can throw into tests.

tools i used

    sh4-linux-gnu-gcc

    file (to confirm format)

    readelf (optional)

how i did it

    wrote a simple return-zero main in C (sh_test.c)

    compiled it with the sh4 gcc toolchain

    confirmed output ELF + arch with file

    moved it into tests/binaries/superh_test/

result
sh_test.o is clean, relocatable, and SH-4 — useful for parser logic and arch detection.

sudo apt install gcc-sh4-linux-gnu

cat <<EOF > sh_test.c
int main() { return 0; }
EOF

sh4-linux-gnu-gcc -c -o sh_test.o sh_test.c

file sh_test.o

mkdir -p ~/pEyeON/tests/binaries/superh_test

mv sh_test.o ~/pEyeON/tests/binaries/superh_test/