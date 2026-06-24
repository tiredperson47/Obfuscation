
#define _GNU_SOURCE
#ifndef PTRACE_x64_REG_H
#define PTRACE_x64_REG_H

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <signal.h>
#include <errno.h>
#include <elf.h>
#include <sys/uio.h>
#include "reimplement.h"

static inline int wait_for_tracee(pid_t pid, int *status) {
    pid_t waited;

    do {
        waited = waitpid(pid, status, 0);
    } while (waited == -1 && errno == EINTR);

    if (waited == -1) {
        // perror("waitpid");
        return -1;
    }
    return 0;
}

static inline int remote_syscall(pid_t pid, struct user_regs_struct *regs, unsigned long syscall_rip,
                          unsigned long ssn, unsigned long arg0, unsigned long arg1,
                          unsigned long arg2, unsigned long arg3, unsigned long arg4,
                          unsigned long arg5, unsigned long *result) {
    struct iovec iov;
    int status;
    int restored = 0;
    unsigned long trampoline_rip = syscall_rip - sizeof(uint32_t);

    errno = 0;
    long original0 = ptrace(PTRACE_PEEKTEXT, pid, (void *)trampoline_rip, NULL);
    // if (original0 == -1 && errno != 0) {
    //     perror("ptrace(PTRACE_PEEKTEXT, trampoline word 0)");
    //     return -1;
    // }

    errno = 0;
    long original1 = ptrace(PTRACE_PEEKTEXT, pid, (void *)(trampoline_rip + sizeof(long)), NULL);
    // if (original1 == -1 && errno != 0) {
    //     perror("ptrace(PTRACE_PEEKTEXT, trampoline word 1)");
    //     return -1;
    // }

    unsigned long patched0 = (unsigned long)original0;
    // unsigned long patched1 = (unsigned long)original1;

    unsigned char tramp[] = {0x0f, 0x05, 0xcc}; // syscall; int3

    sys_memcpy(&patched0, tramp, sizeof(tramp));

    if (ptrace(PTRACE_POKETEXT, pid, (void *)trampoline_rip, (void *)patched0) == -1) {
        // perror("ptrace(PTRACE_POKETEXT, trampoline word 0)");
        return -1;
    }

    // if (ptrace(PTRACE_POKETEXT, pid, (void *)(trampoline_rip + sizeof(long)), (void *)patched1) == -1) {
    //     // perror("ptrace(PTRACE_POKETEXT, trampoline word 1)");
    //     // ptrace(PTRACE_POKETEXT, pid, (void *)trampoline_rip, (void *)original0);
    //     return -1;
    // }

    regs->rax = ssn;
    regs->rdi = arg0;
    regs->rsi = arg1;
    regs->rdx = arg2;
    regs->r10 = arg3;
    regs->r8 = arg4;
    regs->r9 = arg5;
    regs->rip = trampoline_rip;

    iov.iov_base = regs;
    iov.iov_len = sizeof(*regs);
    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
        // perror("ptrace(PTRACE_SETREGSET, remote syscall)");
        goto restore_original;
    }

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        // perror("ptrace(PTRACE_CONT, remote syscall)");
        goto restore_original;
    }

    while (1) {
        if (wait_for_tracee(pid, &status) == -1) {
            goto restore_original;
        }

        if (!WIFSTOPPED(status)) {
            // fprintf(stderr, "tracee did not stop after remote syscall\n");
            goto restore_original;
        }

        if (WSTOPSIG(status) != SIGTRAP) {
            // fprintf(stderr, "[*] remote syscall interrupted by signal %d; suppressing until trampoline finishes\n", WSTOPSIG(status));
            if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
                // perror("ptrace(PTRACE_CONT, suppress signal)");
                goto restore_original;
            }
            continue;
        }

        iov.iov_base = regs;
        iov.iov_len = sizeof(*regs);
        if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
            // perror("ptrace(PTRACE_GETREGSET, trampoline stop)");
            goto restore_original;
        }

        if (regs->rip == trampoline_rip + 3) {
            break;
        }

        // fprintf(stderr, "SIGTRAP at unexpected rip 0x%llx, expected trampoline near 0x%lx\n", (unsigned long long)regs->rip, trampoline_rip);
        goto restore_original;
    }

    if (ptrace(PTRACE_POKETEXT, pid, (void *)(trampoline_rip + sizeof(long)), (void *)original1) == -1) {
        // perror("ptrace(PTRACE_POKETEXT, restore trampoline word 1)");
        return -1;
    }

    if (ptrace(PTRACE_POKETEXT, pid, (void *)trampoline_rip, (void *)original0) == -1) {
        // perror("ptrace(PTRACE_POKETEXT, restore trampoline word 0)");
        return -1;
    }

    restored = 1;

    *result = regs->rax;
    return 0;

restore_original:
    if (!restored) {
        int saved_errno = errno;
        if (ptrace(PTRACE_POKETEXT, pid, (void *)(trampoline_rip + sizeof(long)), (void *)original1) == -1) {
            // perror("ptrace(PTRACE_POKETEXT, restore word 1 after failed syscall)");
        }
        if (ptrace(PTRACE_POKETEXT, pid, (void *)trampoline_rip, (void *)original0) == -1) {
            // perror("ptrace(PTRACE_POKETEXT, restore word 0 after failed syscall)");
        }
        errno = saved_errno;
    }
    return -1;
}



static inline int write_payload(long pid, long address, const unsigned char *payload, size_t payload_size) {
    for (size_t i = 0; i < payload_size; i += sizeof(long)) {
        long chunk = 0;

        size_t remaining = payload_size - i;
        size_t copy_size = remaining < sizeof(long) ? remaining : sizeof(long);

        if (copy_size != sizeof(long)) {
            // read existing memory to avoid clobbering
            errno = 0;
            chunk = ptrace(PTRACE_PEEKTEXT, pid, address + i, NULL);
            if (chunk == -1 && errno != 0) {
                // perror("ptrace(PTRACE_PEEKTEXT, partial write)");
                return -1;
            }
        }

        sys_memcpy(&chunk, payload + i, copy_size);

        if (ptrace(PTRACE_POKETEXT, pid, address + i, chunk) == -1) {
            // perror("ptrace(PTRACE_POKETEXT, payload)");
            return -1;
        }
    }
    return 0;
}

static inline uint64_t align_down(uint64_t x, uint64_t a) {
    return x & ~(a - 1);
}

static inline uint64_t align_up(uint64_t x, uint64_t a) {
    return (x + a - 1) & ~(a - 1);
}

#endif // PTRACE_x64_REG_H