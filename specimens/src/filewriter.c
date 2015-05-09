/* filewriter - exercises file I/O and touches a decoy (canary) file.
 *
 * Runs in its working directory (the harness sets cwd to the run's work dir):
 *   - creates and writes output.txt        (normal artifact)
 *   - appends to wallet.dat                 (DECOY -> should trip decoy detector)
 *   - creates then unlinks temp.bin         (transient file)
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    int fd = open("output.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        const char *msg = "normal-data\n";
        ssize_t n = write(fd, msg, strlen(msg));
        (void)n;
        close(fd);
    }

    int d = open("wallet.dat", O_WRONLY | O_APPEND);
    if (d >= 0) {
        ssize_t n = write(d, "ENCRYPTED", 9);
        (void)n;
        close(d);
    }

    int t = open("temp.bin", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (t >= 0) {
        ssize_t n = write(t, "x", 1);
        (void)n;
        close(t);
    }
    unlink("temp.bin");

    printf("filewriter done\n");
    return 0;
}
