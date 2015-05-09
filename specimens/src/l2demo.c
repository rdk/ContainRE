/* l2demo - freestanding, static, no-PIE specimen for L2 instruction tracing.
 *
 * With no dynamic loader, the ELF entry point IS our _start, so single-stepping
 * from exec sees a short, deterministic instruction stream: register arithmetic
 * (reg_deltas), an explicit stack memory write (mem_writes), then exit(38).
 *
 * Build: cc -O0 -no-pie -static -nostdlib -ffreestanding -fno-stack-protector
 */

static long compute(long a, long b) {
    long c = a * b;   /* 5 * 7 = 35 */
    c = c + 3;        /* 38 */
    return c;
}

void _start(void) {
    volatile long slot = 0;    /* stack slot -> memory write below */
    long c = compute(5, 7);    /* 38, via register arithmetic */
    slot = c;                  /* mov [rbp-x], rax : an explicit memory write */
    long code = slot & 0x3f;   /* 38 */
    asm volatile(
        "mov $60, %%rax\n\t"   /* SYS_exit */
        "syscall\n\t"
        :: "D"(code) : "rax", "memory");
    __builtin_unreachable();
}
