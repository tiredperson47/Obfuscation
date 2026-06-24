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
    uint64_t b_addr;
    uint64_t b_size;

    uint64_t stub_dst;    // executable, 16-byte aligned
    uint64_t page_size;
};

// Modify the struct as needed or add multiple structs for different functions
struct loader_params {
    // const unsigned char *agent;
    // size_t agent_len;
    pid_t pid;
    void *regs;
    unsigned long syscall_pc;
    void *entry_point;
    unsigned long cleanup_ctx_addr;
    struct user_regs_struct backup;
    uint64_t tls_backup;
};