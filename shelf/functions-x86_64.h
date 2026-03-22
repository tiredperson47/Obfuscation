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

static inline void *sys_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    long ret;
    register long r10 __asm__("r10") = flags;
    register long r8 __asm__("r8") = fd;
    register long r9 __asm__("r9") = offset;

    __asm__ volatile (
        "syscall"
        : "=a" (ret)
        : "a" (9), "D" (addr), "S" (length), "d" (prot), "r" (r10), "r" (r8), "r" (r9)
        : "rcx", "r11", "memory"
    );

    if (ret < 0)
        return (void *)-1;

    return (void *)ret;
}

static inline int sys_mprotect(void *addr, unsigned long length, int prot) {
		long ret;
		__asm__ volatile (
				"syscall"
				: "=a" (ret)
				: "a" (10), "D" (addr), "S" (length), "d" (prot)
				: "rcx", "r11", "memory"
		);
		return (ret < 0) ? -1 : 0;
}

static int sys_memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *a = s1, *b = s2;
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return a[i] - b[i];
    }
    return 0;
}