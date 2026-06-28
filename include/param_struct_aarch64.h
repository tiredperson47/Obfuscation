#ifndef PARAM_STRUCT_AARCH64_H
#define PARAM_STRUCT_AARCH64_H

#include <asm/ptrace.h>
#include <sys/uio.h>
#include <stdint.h>

struct cleanup {
    uint64_t x[31];       // x0-x30 from saved user_pt_regs.regs[]
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
    uint64_t tpidr_el0;
    uint8_t  sigmask[128];
    uint64_t a_addr;
    uint64_t a_size;
};

// Modify the struct as needed or add multiple structs for different functions
struct loader_params {
    pid_t pid;
    void *regs;
    unsigned long syscall_pc;
    void *entry_point;
    unsigned long cleanup_ctx_addr;
    struct user_pt_regs backup;
    uint64_t tls_backup;
};

#endif // PARAM_STRUCT_AARCH64_H