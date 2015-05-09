/* yaratarget - exercises YARA scanning of both memory and dropped files.
 *
 *  - places a distinctive marker string on the heap (scanned via a snapshot),
 *  - drops a payload file with another marker (scanned as an artifact),
 *  - touches a decoy to trigger a memory snapshot while the heap marker is live.
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char *buf = malloc(1024);
    memset(buf, 0, 1024);
    strcpy(buf, "YARA_MEM_MARKER_containre_heap_C0FFEE");

    int fd = open("payload.bin", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        const char *p = "EVIL_FILE_MARKER_containre_payload";
        ssize_t n = write(fd, p, strlen(p));
        (void)n;
        close(fd);
    }

    /* drop a fake PE so the built-in embedded_pe rule fires (MZ at offset 0) */
    int m = open("dropped.exe", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (m >= 0) {
        ssize_t n = write(m, "MZ\x90\x00\x03 fake-pe payload", 22);
        (void)n;
        close(m);
    }

    int d = open("wallet.dat", O_WRONLY | O_APPEND);  /* decoy -> snapshot trigger */
    if (d >= 0) {
        ssize_t n = write(d, "x", 1);
        (void)n;
        close(d);
    }

    printf("yaratarget done, marker=%.8s\n", buf);
    free(buf);
    return 0;
}
