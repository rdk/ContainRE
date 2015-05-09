/* unpacker - writes code into an anonymous buffer, makes it executable with
 * mprotect(+X), and runs it. Mimics a runtime unpacker / self-modifying stub, and
 * trips the executable-memory (injection) detector and an mmap+x memory snapshot. */
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
    size_t n = 4096;
    unsigned char *m = mmap(NULL, n, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    memset(m, 0x90, 64); /* NOP sled */
    m[64] = 0xc3;        /* ret */

    if (mprotect(m, n, PROT_READ | PROT_EXEC) != 0) {
        perror("mprotect");
        return 1;
    }
    printf("unpacked stub at %p, executing\n", (void *)m);
    ((void (*)(void))m)();
    printf("stub executed\n");
    return 0;
}
