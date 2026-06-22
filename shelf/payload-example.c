#include <unistd.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <time.h>
#include <stdint.h>

static long syscall_api(long n, long a0, long a1, long a2) {
    register long x0 asm("x0") = a0;
    register long x1 asm("x1") = a1;
    register long x2 asm("x2") = a2;
    register long x8 asm("x8") = n;

    asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
}

struct cleanup {
    uint64_t x[31];       // x0-x30 from saved user_pt_regs.regs[]
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;

    uint64_t tpidr_el0;

    uint8_t  sigmask[128];

    uint64_t a_addr;
    uint64_t a_size;
    uint64_t b_addr;
    uint64_t b_size;

    uint64_t stub_dst;    // executable, 16-byte aligned
    uint64_t page_size;
} cleanup;

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

__attribute__((noreturn, noinline, used))
void clean_memory(struct cleanup *params)
{
    uintptr_t target = params->b_addr;

    __asm__ volatile(
        "mov x0, %x[ctx]\n"
        "br  %x[target]\n"
        :
        : [ctx] "r"(params),
          [target] "r"(target)
        : "x0", "memory"
    );

    __builtin_unreachable();
}

int go(struct cleanup *params) {
    int uid = syscall_api(SYS_getuid, 0, 0, 0);
    print("[+] Payload running with UID: ");
    print_int(uid);
    print("\n");

    for (int i = 0; i < 3; i++) {
        if (i != 2) {
            print("[+] Payload is running...\n");
        } else {
            print("[+] Payload quitting -- restoring process\n");
            clean_memory(params);
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
"    bl go\n"
"    brk #0\n"
);