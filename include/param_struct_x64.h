#ifndef PARAM_STRUCT_X64_H
#define PARAM_STRUCT_X64_H

#include <sys/ptrace.h>
#include <sys/uio.h>
#include <stdint.h>
#include <sys/user.h>

struct cleanup {
    uint64_t x[15];       // x0-x30 from saved user_pt_regs.regs[]
    uint64_t rsp;
    uint64_t rip;
    uint64_t eflags;
    uint64_t fs_backup;
    uint64_t cs;
    uint64_t ss;
    uint64_t original_rax;

    uint8_t  sigmask[128];

    uint64_t a_addr;
    uint64_t a_size;
};

// Modify the struct as needed or add multiple structs for different functions
struct loader_params {
    pid_t pid;
    void *regs;
    unsigned long syscall_rip;
    void *entry_point;
    unsigned long cleanup_ctx_addr;
    struct user_regs_struct backup;
    uint64_t fs_backup;
};

#endif // PARAM_STRUCT_X64_H