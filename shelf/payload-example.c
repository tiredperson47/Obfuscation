#include <unistd.h>
#include <stdio.h>

int main() {
    for (int i = 0; i < 3; i++) {
        if (i != 2) {
            printf("[+] Payload is running...\n");
        } else {
            printf("[+] Payload is quitting... Process will be restored and continue normally\n");
            #if defined(__aarch64__)
                __asm__ volatile("brk #0");
            #elif defined(__x86_64__)
                __asm__ volatile("int3");
            #endif
        }
        sleep(5);
    }

    while(1);
    return 0;
}