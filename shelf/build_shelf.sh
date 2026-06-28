#!/bin/bash	

read -p "Enter the Architecture (aarch64 [1] or x86_64 [2]): " ARCH
read -p "Enter the desired file output name: " NAME
read -p "Enter the PID of the target process: " PID

if [[ $ARCH == 1 ]]; then
    ARCH="aarch64"
elif [[ $ARCH == 2 ]]; then
    ARCH="x64"
else
    echo "Error: Unknown or unset architecture: $ARCH"
    exit 1
fi


gcc -O3 -fPIE -pie -nostdlib -nostartfiles -fno-stack-protector -fno-builtin -Wl,-e,_start -I ../include -o agent ./$ARCH/payload-example-"$ARCH".c
    
# Compile for ptrace reg process injection + shelf
sed -i "s/^\(#define PID \).*/\1$PID/" ../process_injection/$ARCH/"$ARCH"_reg.c
sed -i '17i #include "loader.h"' ../process_injection/$ARCH/"$ARCH"_reg.c
sed -i "3i #include \"param_struct_${ARCH}.h\"" loader.h

xxd -n "agent" -i "agent" | sed 's/unsigned char/static const unsigned char/g' | sed 's/unsigned int/static const unsigned int/g' > ./$ARCH/agent.h
gcc -static -pie -s -fPIE -Wall -O3 -I../include -I./$ARCH -I. -I../process_injection/$ARCH -o "$NAME" ../process_injection/$ARCH/"$ARCH"_reg.c ./$ARCH/shelf-"$ARCH".c

# Cleanup
rm ./$ARCH/agent.h
sed -i "3d" loader.h
sed -i '17d' ../process_injection/$ARCH/"$ARCH"_reg.c
sed -i "s/^\(#define PID \).*/\11234/" ../process_injection/$ARCH/"$ARCH"_reg.c


# rm loader.o loader.elf loader.bin
echo "============== Build complete for $NAME ($ARCH) =============="