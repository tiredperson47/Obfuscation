#ifndef CLEANUP_H
#define CLEANUP_H

#include <stdint.h>
#include <elf.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include "param_struct_aarch64.h"
#include "reimplement.h"
#define RT_SIGINFO_SIZE 0x80
#define FRAME_UC       RT_SIGINFO_SIZE
#define UC_FLAGS       (FRAME_UC + 0x00)
#define UC_LINK        (FRAME_UC + 0x08)
#define UC_STACK       (FRAME_UC + 0x10)
#define UC_SIGMASK     (FRAME_UC + 0x28)
#define UC_MCONTEXT    (FRAME_UC + 0xb0)

#define SC_FAULT_ADDR  (UC_MCONTEXT + 0x00)
#define SC_REGS        (UC_MCONTEXT + 0x08)
#define SC_SP          (UC_MCONTEXT + 0x100)
#define SC_PC          (UC_MCONTEXT + 0x108)
#define SC_PSTATE      (UC_MCONTEXT + 0x110)
#define SC_RESERVED    (UC_MCONTEXT + 0x120)
#define FPSIMD_MAGIC        0x46508001u
#define FPSIMD_CONTEXT_SIZE 0x210u
#define TERMINATOR_SIZE     0x10u
#define RT_FRAME_SIZE       SC_RESERVED + FPSIMD_CONTEXT_SIZE + TERMINATOR_SIZE

#define N_PATTERNS (sizeof(PATTERNS) / sizeof(PATTERNS[0]))
#define AT_SYSINFO_EHDR 33

typedef struct {
    uint64_t start;
    uint64_t size;
} ExecRegion;

typedef struct {
    uint64_t syscall_trampoline;
    uint64_t rt_sigreturn;
} CleanupTargets;

static inline unsigned long sys_prctl(unsigned long a0, unsigned long a1, unsigned long a2) {
    register long x0 asm("x0") = a0;
    register long x1 asm("x1") = a1;
    register long x2 asm("x2") = a2;
    register long x3 asm("x3") = 0;
    register long x4 asm("x4") = 0;
    register long x8 asm("x8") = SYS_prctl;

    asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8) : "memory");
    return x0;
}

// Walks page by page and checks to see if the page is a valid ELF header for libc.
static inline uint64_t find_libc_base(uint64_t seed) {
    uint64_t page = seed & ~0xfffULL;
    for (size_t i = 0; i < 0x10000; i++, page -= 0x1000) {
        Elf64_Ehdr *eh = (Elf64_Ehdr *)page;
        if (sys_memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) continue;
        if (eh->e_type   != ET_DYN)     continue;
        if (eh->e_machine != EM_AARCH64) continue;
        return page;
    }
    return 0;
}

// uses prctl to get the vdso base address
// Base address is needed because libc doesn't have rop gadgets to chain rt_sigreturn. 
static inline uint64_t find_vdso_base() {
    Elf64_auxv_t auxv[1024];
    unsigned long result = sys_prctl(PR_GET_AUXV, (long)auxv, sizeof(auxv));

    int n = result / sizeof(auxv[0]);
    for (size_t i = 0; i < n; i++) {
        if (auxv[i].a_type == AT_SYSINFO_EHDR) {
            return auxv[i].a_un.a_val;
            break;
        }
    }
    return 0;
}

// Find executable region so we don't scan the entire libc for gadgets
// Also, we want to find memory addresses where we can execute code.
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

static inline uint64_t scan_bytes(uint64_t scan_start, uint64_t scan_size, const uint8_t *pattern, size_t len) {
    uint8_t *mem = (uint8_t *)scan_start;

    for (uint64_t i = 0; i < scan_size; i++) {
        if (i + len > scan_size)
            break;
        if (sys_memcmp(&mem[i], pattern, len) == 0)
            return scan_start + i;
    }

    return 0;
}

static inline uint64_t current_sp(void) {
    uint64_t sp;
    __asm__ volatile("mov %0, sp" : "=r"(sp));
    return sp;
}


static inline void *rop_chain(struct cleanup *params) {
    CleanupTargets targets = {0};
    uint64_t libc_base = find_libc_base(params->pc);
    uint64_t vdso_base = find_vdso_base();

    // rop gadget in libc to perform munmap. Gadget found through ROPGadget tool.
    // Finding rop chain gadgets of aarch64 is difficult because of the limited number of useful gadgets.
    static const uint8_t syscall_trampoline[] = {
        0xe8, 0x03, 0x01, 0xaa, /* mov x8, x1 */
        0xe0, 0x03, 0x02, 0xaa, /* mov x0, x2 */
        0xe1, 0x03, 0x03, 0xaa, /* mov x1, x3 */
        0xe2, 0x03, 0x04, 0xaa, /* mov x2, x4 */
        0xe3, 0x03, 0x05, 0xaa, /* mov x3, x5 */
        0xe4, 0x03, 0x06, 0xaa, /* mov x4, x6 */
        0xe5, 0x03, 0x07, 0xaa, /* mov x5, x7 */
        0x01, 0x00, 0x00, 0xd4, /* svc #0 */
        0xc0, 0x03, 0x5f, 0xd6, /* ret */
    };

    // vdso patterns for call rt_sigreturn
    static const uint8_t mov_x8_rt_sigreturn_svc[] = {
        0x68, 0x11, 0x80, 0xd2, /* mov x8, #139 */
        0x01, 0x00, 0x00, 0xd4, /* svc #0 */
    };
    static const uint8_t bti_c[] = {
        0x5f, 0x24, 0x03, 0xd5, /* bti c */
    };

    ExecRegion region = get_exec_region(libc_base);
    targets.syscall_trampoline = scan_bytes(region.start, region.size, syscall_trampoline, sizeof(syscall_trampoline));
    
    ExecRegion vdso = get_exec_region(vdso_base);

    uint64_t frame_addr = (current_sp() - 0x4000) & ~0xfULL;

    uint64_t mov_addr = scan_bytes(vdso.start, vdso.size, mov_x8_rt_sigreturn_svc, sizeof(mov_x8_rt_sigreturn_svc));

    if (mov_addr >= vdso.start + sizeof(bti_c) && sys_memcmp((void *)(mov_addr - sizeof(bti_c)), bti_c, sizeof(bti_c)) == 0) {
        targets.rt_sigreturn = mov_addr - sizeof(bti_c);
    } else {
        targets.rt_sigreturn = mov_addr;
    }

    // build frame for rt_sigreturn
    uint8_t *f = (uint8_t *)frame_addr;
    sys_memset(f, 0, RT_FRAME_SIZE);

    *(uint64_t *)(f + UC_FLAGS) = 0;
    *(uint64_t *)(f + UC_LINK) = 0;
    *(uint64_t *)(f + UC_STACK + 0) = 0;
    *(uint32_t *)(f + UC_STACK + 8) = 2; // SS_DISABLE
    *(uint64_t *)(f + UC_STACK + 16) = 0;
    *(uint64_t *)(f + SC_FAULT_ADDR) = 0;

    for (size_t i = 0; i < 31; i++) {
        *(uint64_t *)(f + SC_REGS + i * 8) = params->x[i];
    }

    *(uint64_t *)(f + SC_SP) = params->sp;
    *(uint64_t *)(f + SC_PC) = params->pc;
    *(uint64_t *)(f + SC_PSTATE) = params->pstate;

    *(uint32_t *)(f + SC_RESERVED + 0x00) = FPSIMD_MAGIC;
    *(uint32_t *)(f + SC_RESERVED + 0x04) = FPSIMD_CONTEXT_SIZE;
    *(uint32_t *)(f + SC_RESERVED + 0x08) = 0;
    *(uint32_t *)(f + SC_RESERVED + 0x0c) = 0;

    *(uint32_t *)(f + SC_RESERVED + FPSIMD_CONTEXT_SIZE + 0x00) = 0;
    *(uint32_t *)(f + SC_RESERVED + FPSIMD_CONTEXT_SIZE + 0x04) = 0;

    register uint64_t r_frame  __asm__("x10") = frame_addr;
    register uint64_t r_tramp  __asm__("x11") = targets.syscall_trampoline;
    register uint64_t r_sigret __asm__("x12") = targets.rt_sigreturn;
    register uint64_t r_addr   __asm__("x13") = params->a_addr;
    register uint64_t r_size   __asm__("x14") = params->a_size;

    __asm__ volatile(
        "mov sp, x10\n"
        "mov x9, x11\n"
        "mov x30, x12\n"
        "mov x2, x13\n"
        "mov x3, x14\n"
        "mov x1, #215\n"
        "br x9\n"
        :
        : "r"(r_frame), "r"(r_tramp), "r"(r_sigret), "r"(r_addr), "r"(r_size)
        : "x1", "x2", "x3", "x9", "x30", "memory"
    );

    __builtin_unreachable();
}

#endif