/* antidebug - calls ptrace(PTRACE_TRACEME), a classic anti-analysis check.
 * Under the harness this fails (already traced) but the syscall is recorded and
 * flagged by the anti-debug detector. */
#include <stdio.h>
#include <sys/ptrace.h>

int main(void) {
    long r = ptrace(PTRACE_TRACEME, 0, 0, 0);
    printf("ptrace(PTRACE_TRACEME) returned %ld\n", r);
    return 0;
}
