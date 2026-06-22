// aarch64-linux-gnu-as cleanup.S -o cleanup.o
// aarch64-linux-gnu-objcopy -O binary -j .text cleanup.o cleanup.bin

.equ __NR_rt_sigreturn, 139
.equ __NR_rt_sigprocmask, 135
.equ __NR_munmap,       215
.equ __NR_mprotect,     226

.equ PROT_RW, 3
.equ PROT_RX, 5

// ctx layout, filled by your debugger before entering cleanup_B.
// Prefer ptrace GETREGSET for regs/sp/pc/pstate, plus TLS/sigmask.
.equ CTX_X0,        0              // x0-x30, 31 * 8 bytes
.equ CTX_SP,        248
.equ CTX_PC,        256
.equ CTX_PSTATE,    264
.equ CTX_TPIDR,     272
.equ CTX_SIGMASK,   280            // 128 bytes
.equ CTX_A_ADDR,    408
.equ CTX_A_SIZE,    416
.equ CTX_B_ADDR,    424
.equ CTX_B_SIZE,    432
.equ CTX_STUB_DST,  440            // executable stack destination
.equ CTX_PAGE_SIZE, 448

// Linux arm64 rt_sigframe offsets.
.equ RT_SIGINFO_SIZE, 0x80
.equ UC_MCONTEXT,    0xb0
.equ FRAME_SC,       RT_SIGINFO_SIZE + UC_MCONTEXT
.equ FRAME_SIGMASK,  RT_SIGINFO_SIZE + 40
.equ SC_REGS,        FRAME_SC + 0x08
.equ SC_SP,          FRAME_SC + 0x100
.equ SC_PC,          FRAME_SC + 0x108
.equ SC_PSTATE,      FRAME_SC + 0x110
.equ SC_RESERVED,    FRAME_SC + 0x120
.equ FPSIMD_MAGIC,        0x46508001
.equ FPSIMD_CONTEXT_SIZE, 0x210
.equ TERMINATOR_SIZE,     0x10
.equ RT_FRAME_SIZE,  SC_RESERVED + FPSIMD_CONTEXT_SIZE + TERMINATOR_SIZE


.equ FD_B_ADDR,      0
.equ FD_B_SIZE,      8
.equ FD_TPIDR,       16
.equ FD_RT_FRAME,    32

.section go, "ax"
.align 4
.global _start
_start:
    mov x19, x0                         // ctx = first argument
    ldr x20, [x19, #CTX_STUB_DST]        // copied S destination

    // clear ctx->sigmask[0..127]
    add x2, x19, #CTX_SIGMASK
    mov x3, #8                           // 8 * 16 = 128 bytes
    mov x4, xzr
    mov x5, xzr

.Lzero_sigmask:
    stp x4, x5, [x2], #16
    subs x3, x3, #1
    b.ne .Lzero_sigmask

    // query current thread signal mask into ctx->sigmask[0..7]
    add x2, x19, #CTX_SIGMASK            // oldset = &ctx->sigmask[0]
    mov x0, xzr                          // how ignored because set == NULL
    mov x1, xzr                          // set = NULL, query only
    mov x3, #8                           // kernel sigset size on arm64
    mov x8, #__NR_rt_sigprocmask
    svc #0
    cbnz x0, .Lbad

    // mprotect(stack pages covering S) -> RWX
    ldr x21, [x19, #CTX_PAGE_SIZE]
    sub x22, x21, #1
    bic x26, x20, x22                     // page start

    adr x23, final_stub_start
    adr x24, final_stub_end
    sub x1, x24, x23                     // blob length

    add x25, x20, x1
    add x25, x25, x22
    bic x25, x25, x22                    // page end
    sub x27, x25, x26                      // mprotect length

    mov x0, x26
    mov x1, x27
    mov x2, #PROT_RW
    mov x8, #__NR_mprotect
    svc #0
    cbnz x0, .Lbad

    // copy final stub blob from B to stack
    mov x1, x23
    mov x2, x20
    sub x3, x24, x23

.Lcopy_stub:
    cbz x3, .Lpatch
    ldrb w4, [x1], #1
    strb w4, [x2], #1
    sub x3, x3, #1
    b .Lcopy_stub

.Lpatch:
    // x5 = copied final_data
    adr x6, final_data
    sub x6, x6, x23
    add x5, x20, x6

    ldr x6, [x19, #CTX_B_ADDR]
    str x6, [x5, #FD_B_ADDR]
    ldr x6, [x19, #CTX_B_SIZE]
    str x6, [x5, #FD_B_SIZE]
    ldr x6, [x19, #CTX_TPIDR]
    str x6, [x5, #FD_TPIDR]

    // x10 = copied rt_sigframe
    add x10, x5, #FD_RT_FRAME

    // copy signal mask into fake ucontext
    add x11, x10, #FRAME_SIGMASK
    add x12, x19, #CTX_SIGMASK
    mov x13, #8                          // 8 * 16 = 128 bytes
.Lcopy_sigmask:
    ldp x14, x15, [x12], #16
    stp x14, x15, [x11], #16
    subs x13, x13, #1
    b.ne .Lcopy_sigmask

    // copy x0-x30 into sigcontext.regs[]
    add x11, x10, #SC_REGS
    add x12, x19, #CTX_X0
    mov x13, #31
.Lcopy_regs:
    ldr x14, [x12], #8
    str x14, [x11], #8
    subs x13, x13, #1
    b.ne .Lcopy_regs

    ldr x14, [x19, #CTX_SP]
    str x14, [x10, #SC_SP]
    ldr x14, [x19, #CTX_PC]
    str x14, [x10, #SC_PC]
    ldr x14, [x19, #CTX_PSTATE]
    str x14, [x10, #SC_PSTATE]

    add x11, x10, #SC_RESERVED

    movz w14, #0x8001
    movk w14, #0x4650, lsl #16
    str w14, [x11]              // FPSIMD_MAGIC

    movz w14, #0x0210
    str w14, [x11, #4]          // sizeof(struct fpsimd_context)

    mov x0, x26
    mov x1, x27
    mov x2, #PROT_RX
    mov x8, #__NR_mprotect
    svc #0
    cbnz x0, .Lbad

    // munmap(A)
    ldr x0, [x19, #CTX_A_ADDR]
    ldr x1, [x19, #CTX_A_SIZE]
    mov x8, #__NR_munmap
    svc #0

    // no more need for B state except copied S
    br x20

.Lbad:
    brk #0

.align 4
final_stub_start:
    adr x19, final_data

    // munmap(B)
    ldr x0, [x19, #FD_B_ADDR]
    ldr x1, [x19, #FD_B_SIZE]
    mov x8, #__NR_munmap
    svc #0

    // restore TLS, not restored by rt_sigreturn on arm64
    ldr x0, [x19, #FD_TPIDR]
    msr tpidr_el0, x0

    // kernel restores regs/sp/pc/pstate from copied fake frame
    add x0, x19, #FD_RT_FRAME
    mov sp, x0
    mov x8, #__NR_rt_sigreturn
    svc #0

    brk #1                               // should never return

.align 4
final_data:
    .quad 0                              // B addr
    .quad 0                              // B size
    .quad 0                              // TPIDR_EL0
    .quad 0                              // padding/alignment
    .zero RT_FRAME_SIZE                  // fake rt_sigframe
final_stub_end:
