#define _GNU_SOURCE
#include <asm/ptrace.h>
#include <elf.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define PID 1234
#define CHECK(x) if ((x) == -1) { perror(#x); exit(1); }
#define NT_ARM_TLS 0x401 // Ptrace flag for AArch64 TLS register

static int wait_for_tracee(pid_t pid, int *status) {
    pid_t waited;

    do {
        waited = waitpid(pid, status, 0);
    } while (waited == -1 && errno == EINTR);

    if (waited == -1) {
        perror("waitpid");
        return -1;
    }

    return 0;
}

int main() {
    pid_t pid = PID;
    int status;

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        return EXIT_FAILURE;
    }

    if (wait_for_tracee(pid, &status) == -1) {
        return EXIT_FAILURE;
    }

    struct user_pt_regs regs, backup = {0};

    struct iovec iov = {
        .iov_base = &backup,
        .iov_len = sizeof(backup),
    };

    CHECK(ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov));
    regs = backup;

    // backup TLS registers
    uint64_t tls_backup = 0;
    struct iovec tls_iov;
    tls_iov.iov_base = &tls_backup;
    tls_iov.iov_len = sizeof(tls_backup);
    ptrace(PTRACE_GETREGSET, pid, NT_ARM_TLS, &tls_iov);


    unsigned long syscall_pc = backup.pc;

    struct loader_params params;
    params.pid = pid;
    params.regs = &regs;
    params.syscall_pc = syscall_pc;
    params.backup = backup;
    params.tls_backup = tls_backup;
    load_image(&params);
    
    regs = backup;
    regs.pc = (unsigned long)params.entry_point;
    regs.regs[0] = params.cleanup_ctx_addr;

    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);

    // Tell process to continue at payload address and detatch
    CHECK(ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov));
    memset(&params, 0, sizeof(params));
    __asm__ __volatile__("" ::: "memory");
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    exit(0);
    return 0;
}