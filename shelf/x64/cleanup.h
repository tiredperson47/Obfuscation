#ifndef CLEANUP_H
#define CLEANUP_H

#include <stdint.h>
#include <elf.h>
#include <sys/syscall.h>
#include "param_struct_x64.h"
#include "reimplement.h"
#define MAX_GADGETS 512
#define FRAME_UC        0x08
#define UC_FLAGS        (FRAME_UC + 0x00)
#define UC_STACK        (FRAME_UC + 0x10)
#define FRAME_SC        (FRAME_UC + 0x28)
#define FRAME_SIGMASK   (FRAME_SC + 0x100)
#define SC_R8           (FRAME_SC + 0x00)
#define SC_R9           (FRAME_SC + 0x08)
#define SC_R10          (FRAME_SC + 0x10)
#define SC_R11          (FRAME_SC + 0x18)
#define SC_R12          (FRAME_SC + 0x20)
#define SC_R13          (FRAME_SC + 0x28)
#define SC_R14          (FRAME_SC + 0x30)
#define SC_R15          (FRAME_SC + 0x38)
#define SC_RDI          (FRAME_SC + 0x40)
#define SC_RSI          (FRAME_SC + 0x48)
#define SC_RBP          (FRAME_SC + 0x50)
#define SC_RBX          (FRAME_SC + 0x58)
#define SC_RDX          (FRAME_SC + 0x60)
#define SC_RAX          (FRAME_SC + 0x68)
#define SC_RCX          (FRAME_SC + 0x70)
#define SC_RSP          (FRAME_SC + 0x78)
#define SC_RIP          (FRAME_SC + 0x80)
#define SC_EFLAGS       (FRAME_SC + 0x88)
#define SC_CS           (FRAME_SC + 0x90)
#define SC_SS           (FRAME_SC + 0x96)
#define SC_FPSTATE      (FRAME_SC + 0xb8)
#define SS_DISABLE      2
#define N_PATTERNS (sizeof(PATTERNS) / sizeof(PATTERNS[0]))

static inline uint64_t find_libc_base(uint64_t seed) {
    uint64_t page = seed & ~0xfffULL;
    for (size_t i = 0; i < 0x10000; i++, page -= 0x1000) {
        Elf64_Ehdr *eh = (Elf64_Ehdr *)page;
        // In-process: just dereference directly, no remote read needed
        if (sys_memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) continue;
        if (eh->e_type   != ET_DYN)     continue;
        if (eh->e_machine != EM_X86_64) continue;
        return page;
    }
    return 0;
}

typedef struct {
    uint64_t start;
    uint64_t size;
} ExecRegion;

// Find executable region so we don't scan the entire libc for gadgets
// Note that this region geenrally doesn't find gadgets for r10, r8, r9, so we may need to scan more for those
static inline ExecRegion get_exec_region(uint64_t elf_base) {
    Elf64_Ehdr *eh = (Elf64_Ehdr *)elf_base;
    Elf64_Phdr *ph = (Elf64_Phdr *)(elf_base + eh->e_phoff);

    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_LOAD && (ph[i].p_flags & PF_X)) {
            return (ExecRegion){
                .start = elf_base + ph[i].p_vaddr,
                .size  = ph[i].p_filesz
            };
        }
    }
    return (ExecRegion){0, 0};
}

typedef struct {
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rdx;
    uint64_t r10;
    uint64_t r8;
    uint64_t r9;
    uint64_t rax;
    uint64_t syscall;
    uint64_t rsp;
} Registers;

enum GadgetId {
    G_POP_RDI,
    G_POP_RSI,
    G_POP_RDX,
    G_POP_RAX,
    G_POP_R8,
    G_POP_R9,
    G_POP_R10,
    G_SYSCALL_RET,
    G_POP_RSP,
};

typedef struct {
    uint8_t bytes[4];
    uint8_t len;
    uint8_t id;
} GadgetPattern;

// Byte patterns for common gadgets
static const GadgetPattern PATTERNS[] = {
    { {0x5f, 0xc3},        2, G_POP_RDI },
    { {0x5e, 0xc3},        2, G_POP_RSI },
    { {0x5a, 0xc3},        2, G_POP_RDX },
    { {0x58, 0xc3},        2, G_POP_RAX },
    { {0x41, 0x58, 0xc3}, 3, G_POP_R8 },
    { {0x41, 0x59, 0xc3}, 3, G_POP_R9 },
    { {0x41, 0x5a, 0xc3}, 3, G_POP_R10 },
    { {0x0f, 0x05, 0xc3}, 3, G_SYSCALL_RET },
    { {0x5c, 0xc3},        2, G_POP_RSP },
};

static inline int find_gadgets(uint64_t scan_start, uint64_t scan_size, Registers *regs) {
    uint8_t *mem = (uint8_t *)scan_start;
    int found = 0;

    for (uint64_t i = 0; i < scan_size; i++) {
        for (size_t p = 0; p < N_PATTERNS; p++) {
            size_t plen = PATTERNS[p].len;

            if (i + plen > scan_size)
                continue;

            if (sys_memcmp(&mem[i], PATTERNS[p].bytes, plen) != 0)
                continue;

            switch (PATTERNS[p].id) {
            case G_POP_RDI:
                if (!regs->rdi) regs->rdi = scan_start + i;
                break;
            case G_POP_RSI:
                if (!regs->rsi) regs->rsi = scan_start + i;
                break;
            case G_POP_RDX:
                if (!regs->rdx) regs->rdx = scan_start + i;
                break;
            case G_POP_RAX:
                if (!regs->rax) regs->rax = scan_start + i;
                break;
            case G_POP_R8:
                if (!regs->r8) regs->r8 = scan_start + i;
                break;
            case G_POP_R9:
                if (!regs->r9) regs->r9 = scan_start + i;
                break;
            case G_POP_R10:
                if (!regs->r10) regs->r10 = scan_start + i;
                break;
            case G_SYSCALL_RET:
                if (!regs->syscall) regs->syscall = scan_start + i;
                break;
            case G_POP_RSP:
                if (!regs->rsp) regs->rsp = scan_start + i;
                break;
            }

            found++;

            if (regs->rdi &&
                regs->rsi &&
                regs->rax &&
                regs->syscall &&
                regs->rsp) {
                return found;
            }

            break;
        }
    }

    return found;
}

static inline uint64_t current_rsp(void) {
    uint64_t rsp;
    __asm__ volatile("mov %%rsp, %0" : "=r"(rsp));
    return rsp;
}

__attribute__((naked, noreturn, noinline, used))
static void pivot_to_rop(uint64_t chain_addr) {
    __asm__ volatile(
        "mov %rdi, %rsp\n"
        "ret\n"
    );
}

static inline void *rop_chain(struct cleanup *params) {
    uint64_t libc_base = find_libc_base(params->rip);
    ExecRegion region = get_exec_region(libc_base);
    Registers regs = {0};

    find_gadgets(region.start, region.size, &regs);

    uint64_t cur_rsp = current_rsp();

    uint64_t frame_addr = (cur_rsp - 0x1000) & ~0xfULL;
    uint64_t chain_addr = frame_addr - 0x100;

    uint64_t *chain = (uint64_t *)chain_addr;

    // munmap(params->a_addr, params->a_size)
    *chain++ = regs.rdi;
    *chain++ = params->a_addr;

    *chain++ = regs.rsi;
    *chain++ = params->a_size;

    *chain++ = regs.rax;
    *chain++ = 11; // SYS_munmap

    *chain++ = regs.syscall;

    /* rt_sigreturn */
    *chain++ = regs.rax;
    *chain++ = 15; // SYS_rt_sigreturn

    *chain++ = regs.rsp;        // pop rsp; ret
    *chain++ = frame_addr;      // ret lands at *(frame_addr)

    // build frame for rt_sigreturn
    uint8_t *f = (uint8_t *)frame_addr;
    sys_memset(f, 0, 0x400);

    /* ret from pop rsp jumps here */
    *(uint64_t *)(f + 0x00) = regs.syscall;

    /* ucontext setup */
    *(uint64_t *)(f + UC_FLAGS) = 6;
    *(uint64_t *)(f + UC_STACK + 0) = 0;
    *(uint32_t *)(f + UC_STACK + 8) = SS_DISABLE;
    *(uint64_t *)(f + UC_STACK + 16) = 0;

    /* saved registers */
    *(uint64_t *)(f + SC_R8)  = params->x[0];
    *(uint64_t *)(f + SC_R9)  = params->x[1];
    *(uint64_t *)(f + SC_R10) = params->x[2];
    *(uint64_t *)(f + SC_R11) = params->x[3];
    *(uint64_t *)(f + SC_R12) = params->x[4];
    *(uint64_t *)(f + SC_R13) = params->x[5];
    *(uint64_t *)(f + SC_R14) = params->x[6];
    *(uint64_t *)(f + SC_R15) = params->x[7];

    *(uint64_t *)(f + SC_RDI) = params->x[8];
    *(uint64_t *)(f + SC_RSI) = params->x[9];
    *(uint64_t *)(f + SC_RBP) = params->x[10];
    *(uint64_t *)(f + SC_RBX) = params->x[11];
    *(uint64_t *)(f + SC_RDX) = params->x[12];
    *(uint64_t *)(f + SC_RAX) = params->original_rax;
    *(uint64_t *)(f + SC_RCX) = params->x[14];

    *(uint64_t *)(f + SC_RSP) = params->rsp;
    *(uint64_t *)(f + SC_RIP) = params->rip - 2;
    *(uint64_t *)(f + SC_EFLAGS) = params->eflags;

    *(uint16_t *)(f + SC_CS) = params->cs;
    *(uint16_t *)(f + SC_SS) = params->ss;
    *(uint64_t *)(f + SC_FPSTATE) = 0;

    pivot_to_rop(chain_addr);
}

#endif