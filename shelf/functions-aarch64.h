#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <elf.h>

// shelf-arm.c
static void *sys_memset(void *s, int c, size_t n) {
    unsigned char *p = s;
    while (n--) *p++ = (unsigned char)c;
    return s;
}

static void *sys_memcpy(void *dest, const void *src, size_t n) {
    unsigned char *d = dest;
    const unsigned char *s = src;
    while (n--) *d++ = *s++;
    return dest;
}

static size_t sys_strlen(const char *s) {
    size_t i = 0;
    while (s && s[i]) i++;
    return i;
}

static inline void *sys_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    register long x0 __asm__("x0") = (long)addr;
    register long x1 __asm__("x1") = length;
    register long x2 __asm__("x2") = prot;
    register long x3 __asm__("x3") = flags;
    register long x4 __asm__("x4") = fd;
    register long x5 __asm__("x5") = offset;
    register long x8 __asm__("x8") = 222; // __NR_mmap on AArch64

    __asm__ volatile (
        "svc #0"
        : "+r" (x0)
        : "r" (x1), "r" (x2), "r" (x3), "r" (x4), "r" (x5), "r" (x8)
        : "memory", "cc"
    );

    if (x0 < 0)
        return (void *)-1;

    return (void *)x0;
}

static inline int sys_mprotect(void *addr, unsigned long length, int prot) {
    register long x0 __asm__("x0") = (long)addr;
    register long x1 __asm__("x1") = length;
    register long x2 __asm__("x2") = prot;
    register long x8 __asm__("x8") = 226;
    __asm__ volatile (
            "svc #0"
            : "+r" (x0)
            : "r" (x1), "r" (x2), "r" (x8)
            : "memory", "cc"
    );
    return (int)x0;
}

static inline long sys_getrandom(void *buf, size_t len, unsigned int flags) {
    register long x0 __asm__("x0") = (long)buf;
    register long x1 __asm__("x1") = len;
    register long x2 __asm__("x2") = flags;
    register long x8 __asm__("x8") = 278;

    __asm__ volatile (
        "svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x8)
        : "memory", "cc"
    );

    return x0;
}

static inline int sys_munmap(void *addr, size_t length) {
    register long x0 __asm__("x0") = (long)addr;
    register long x1 __asm__("x1") = length;
    register long x8 __asm__("x8") = 215;

    __asm__ volatile (
        "svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x8)
        : "memory", "cc"
    );

    return (int)x0;
}

static int sys_memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *a = s1, *b = s2;
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return a[i] - b[i];
    }
    return 0;
}