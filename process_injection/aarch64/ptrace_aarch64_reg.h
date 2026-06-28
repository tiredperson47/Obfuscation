#ifndef PTRACE_AARCH64_REG_H
#define PTRACE_AARCH64_REG_H

#include <asm/ptrace.h>
#include <elf.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include "reimplement.h"
#define AARCH64_NOP 0xd503201fu
#define AARCH64_SVC_0 0xd4000001u
#define AARCH64_BRK_0 0xd4200000u

static inline int wait_for_tracee(pid_t pid, int *status) {
    pid_t waited;

    do {
        waited = waitpid(pid, status, 0);
    } while (waited == -1 && errno == EINTR);

    if (waited == -1) {
        return -1;
    }
    return 0;
}

static inline int remote_syscall(pid_t pid, struct user_pt_regs *regs, unsigned long syscall_pc,
                          unsigned long ssn, unsigned long arg0, unsigned long arg1,
                          unsigned long arg2, unsigned long arg3, unsigned long arg4,
                          unsigned long arg5, unsigned long *result) {
    struct iovec iov;
    int status;
    int restored = 0;
    unsigned long trampoline_pc = syscall_pc - sizeof(uint32_t);

    errno = 0;
    long original0 = ptrace(PTRACE_PEEKTEXT, pid, (void *)trampoline_pc, NULL);

    errno = 0;
    long original1 = ptrace(PTRACE_PEEKTEXT, pid, (void *)(trampoline_pc + sizeof(long)), NULL);

    unsigned long patched0 = (unsigned long)original0;
    unsigned long patched1 = (unsigned long)original1;
    uint32_t nop = AARCH64_NOP;
    uint32_t svc = AARCH64_SVC_0;
    uint32_t brk = AARCH64_BRK_0;

    sys_memcpy(&patched0, &nop, sizeof(nop));
    sys_memcpy((char *)&patched0 + sizeof(nop), &svc, sizeof(svc));
    sys_memcpy(&patched1, &brk, sizeof(brk));

    if (ptrace(PTRACE_POKETEXT, pid, (void *)trampoline_pc, (void *)patched0) == -1) {
        return -1;
    }

    if (ptrace(PTRACE_POKETEXT, pid, (void *)(trampoline_pc + sizeof(long)), (void *)patched1) == -1) {
        return -1;
    }

    regs->regs[0] = arg0;
    regs->regs[1] = arg1;
    regs->regs[2] = arg2;
    regs->regs[3] = arg3;
    regs->regs[4] = arg4;
    regs->regs[5] = arg5;
    regs->regs[8] = ssn;
    regs->pc = trampoline_pc;

    iov.iov_base = regs;
    iov.iov_len = sizeof(*regs);
    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
        goto restore_original;
    }

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        goto restore_original;
    }

    while (1) {
        if (wait_for_tracee(pid, &status) == -1) {
            goto restore_original;
        }

        if (!WIFSTOPPED(status)) {
            goto restore_original;
        }

        if (WSTOPSIG(status) != SIGTRAP) {
            if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
                goto restore_original;
            }
            continue;
        }

        iov.iov_base = regs;
        iov.iov_len = sizeof(*regs);
        if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
            goto restore_original;
        }

        if (regs->pc == trampoline_pc + (2 * sizeof(uint32_t)) ||
            regs->pc == trampoline_pc + (3 * sizeof(uint32_t))) {
            break;
        }

        goto restore_original;
    }

    if (ptrace(PTRACE_POKETEXT, pid, (void *)(trampoline_pc + sizeof(long)), (void *)original1) == -1) {
        return -1;
    }

    if (ptrace(PTRACE_POKETEXT, pid, (void *)trampoline_pc, (void *)original0) == -1) {
        return -1;
    }

    restored = 1;

    *result = regs->regs[0];
    return 0;

restore_original:
    if (!restored) {
        int saved_errno = errno;
        if (ptrace(PTRACE_POKETEXT, pid, (void *)(trampoline_pc + sizeof(long)), (void *)original1) == -1) {
        }
        if (ptrace(PTRACE_POKETEXT, pid, (void *)trampoline_pc, (void *)original0) == -1) {
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
                return -1;
            }
        }

        sys_memcpy(&chunk, payload + i, copy_size);

        if (ptrace(PTRACE_POKETEXT, pid, address + i, chunk) == -1) {
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

#endif // PTRACE_AARCH64_REG_H