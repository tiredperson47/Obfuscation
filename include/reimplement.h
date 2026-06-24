#ifndef REIMPLEMENT_H
#define REIMPLEMENT_H

#include <stddef.h>

static inline void *sys_memcpy(void *dest, const void *src, size_t n) {
    unsigned char *d = dest;
    const unsigned char *s = src;

    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }

    return dest;
}

static inline int sys_memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *a = s1;
    const unsigned char *b = s2;

    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            return a[i] - b[i];
        }
    }

    return 0;
}

static inline void *sys_memset(void *dest, int c, size_t n) {
    unsigned char *d = dest;

    for (size_t i = 0; i < n; i++) {
        d[i] = (unsigned char)c;
    }

    return dest;
}

static inline int sys_strcmp(const char *s1, const char *s2) {
    const unsigned char *a = (const unsigned char *)s1;
    const unsigned char *b = (const unsigned char *)s2;

    while (*a && (*a == *b)) {
        a++;
        b++;
    }
    return *a - *b;
}

#endif