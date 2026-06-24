#include <elf.h>
#include <sys/mman.h>
#include <stdint.h>
#include "agent.h"
#include "cleanup.h"
#include "ptrace_aarch64_reg.h"
#include "param_struct_aarch64.h"
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
    ElfN_Xword filesz;
    ElfN_Off   offset;
    ElfN_Xword  flags;
    ElfN_Xword align;
} load_segment;

int is_image_valid(ElfN_Ehdr *hdr) {
    if (sys_memcmp(hdr->e_ident, ELFMAG, SELFMAG) != 0) return 0;
    if (hdr->e_ident[EI_CLASS] != ELFCLASS64) return 0;
    if (hdr->e_machine != EM_AARCH64) return 0; 
    if (hdr->e_type != ET_DYN) return 0;
    if (hdr->e_phnum <= 0) return 0;
    return 1;
}

int *load_image(struct loader_params *params) {
    ElfN_Ehdr *hdr = (ElfN_Ehdr *)agent;
    if (!is_image_valid(hdr)) return 0;

    ElfN_Phdr *phdr = (ElfN_Phdr *)(agent + hdr->e_phoff);
    ElfN_Addr min_vaddr = UINT64_MAX;
    ElfN_Addr max_vaddr = 0;
    
    load_segment segments[MAX_SEGMENTS];
    int seg_count = 0;

    // Gather PT_LOAD segments for memory size and protection permissions
    for (int i = 0; i < hdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            if (seg_count >= MAX_SEGMENTS) return 0;
            segments[seg_count++] = (load_segment) {
                .vaddr = phdr[i].p_vaddr, .memsz = phdr[i].p_memsz,
                .filesz = phdr[i].p_filesz, .offset = phdr[i].p_offset,
                .flags = phdr[i].p_flags, .align = phdr[i].p_align
            };
            if (phdr[i].p_vaddr < min_vaddr) min_vaddr = phdr[i].p_vaddr;
            if ((phdr[i].p_vaddr + phdr[i].p_memsz) > max_vaddr) max_vaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
        }
    }

    size_t memsz = max_vaddr - min_vaddr;
    struct cleanup clean = {0};

    clean.a_size = memsz + PAGESIZE;

    // map memory region A
    unsigned long syscall_result = 0;
    remote_syscall(params->pid, params->regs, params->syscall_pc, __NR_mmap, 0, clean.a_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, (unsigned long)-1, 0, &syscall_result);
    clean.a_addr = (uint64_t)syscall_result;
    
    if ((long)clean.a_addr <= 0) return NULL;

    ElfN_Addr pie_base = (ElfN_Addr)(((uintptr_t)clean.a_addr + (PAGESIZE - 1)) & ~(uintptr_t)(PAGESIZE - 1)) - min_vaddr;

    // Write payload to region A
    write_payload(params->pid, (long)clean.a_addr, agent, agent_len);

    // apply memory protections
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
        
        remote_syscall(params->pid, params->regs, params->syscall_pc, __NR_mprotect, (unsigned long)aligned_start, aligned_end - aligned_start, prot, 0, 0, 0, &syscall_result);
    }

    params->entry_point = (void *)(pie_base + hdr->e_entry);

    size_t b_code_map_len = align_up(cleanup_len, PAGESIZE);
    size_t ctx_map_len    = align_up(sizeof(clean), PAGESIZE);
    size_t b_alloc_len    = b_code_map_len + ctx_map_len;

    unsigned long b_remote = 0;
    remote_syscall(params->pid, params->regs, params->syscall_pc, __NR_mmap, 0, b_alloc_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0, &b_remote);
    
    uintptr_t ctx_remote = b_remote + b_code_map_len;
    clean.b_addr = b_remote;
    clean.b_size = b_alloc_len;
    
    clean.x[0] = params->backup.regs[0];
    for (int i = 1; i < 31; i++) {
        clean.x[i] = params->backup.regs[i];
    }

    clean.sp = params->backup.sp;
    clean.pc = params->backup.pc;
    clean.pstate = params->backup.pstate;
    clean.tpidr_el0 = params->tls_backup;
    clean.page_size = PAGESIZE;

    clean.stub_dst = align_down(clean.sp - PAGESIZE - 256, 16);

    // cleanup code
    write_payload(params->pid, b_remote, (unsigned char *)&cleanup, cleanup_len);
    remote_syscall(params->pid, params->regs, params->syscall_pc, __NR_mprotect, b_remote, b_code_map_len, PROT_READ | PROT_EXEC, 0, 0, 0, &syscall_result);

    //struct
    write_payload(params->pid, ctx_remote, (unsigned char *)&clean, sizeof(clean));
    params->cleanup_ctx_addr = ctx_remote;

    // Wipe the cleanup struct from local memory
    memset(&clean, 0, sizeof(clean));
    __asm__ __volatile__("" ::: "memory");

    return 0;
}