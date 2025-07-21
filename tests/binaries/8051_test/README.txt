8051 test binary thing

quick setup for making a super minimal 8051 binary for pEyeON testing.

goal
build a tiny intel hex file for 8051 that pEyeON can detect and extract structure/features from.

tools i used

    sdcc (Small Device C Compiler)

    file (optional, for checking output)

how i did it

    wrote a basic infinite loop in C (blink.c)

    compiled it with sdcc targeting 8051

    renamed the .ihx output to minimal_8051.hex

    moved it into tests/binaries/8051_test/

result
a valid intel hex file with 8051 layout — compact and useful for detection and analysis testing.

sudo apt install sdcc

cat <<EOF > blink.c
void main() {
while (1);
}
EOF

sdcc -mmcs51 blink.c

mkdir -p ~/pEyeON/tests/binaries/8051_test

mv blink.ihx ~/pEyeON/tests/binaries/8051_test/minimal_8051.hex