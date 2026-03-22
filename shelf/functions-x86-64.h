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
    long ret;
    register long x10 __asm__("x10") = flags;
    register long x8 __asm__("x8") = fd;
    register long x9 __asm__("x9") = offset;

    __asm__ volatile (
        "syscall"
        : "=a" (ret)
        : "a" (9), "D" (addr), "S" (length), "d" (x4), "r" (x10), "r" (x8), "r" (x9)
        : "rcx", "r11", "memory"
    );

    if (ret < 0)
        return (void *)-1;

    return (void *)ret;
}

static inline void *sys_mprotect(void *addr, unsigned long length, int prot) {
		long ret;
		__asm__ volatile (
				"syscall"
				: "=a" (ret)
				: "a" (10), "D" (addr), "S" (length), "d" (prot)
				: "rcx", "r11", "memory"
		);
		return (ret < 0) ? -1 : 0;
}

static inline long sys_getrandom(void *buf, size_t len, unsigned int flags) {
    long ret;
    register long x10 __asm__("x10") = flags;

    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(318), "D"(buf), "S"(len), "d"(x10)
        : "rcx", "r11", "memory"
    );

    return ret;
}

static inline int sys_munmap(void *addr, size_t length) {
    long ret;

    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(11), "D"(addr), "S"(length)
        : "rcx", "r11", "memory"
    );

    return (int)ret;
}

static int sys_memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *a = s1, *b = s2;
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return a[i] - b[i];
    }
    return 0;
}