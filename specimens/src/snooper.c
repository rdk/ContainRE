/* snooper - attempts to read credential/secret files (like a stealer). The reads
 * may fail (e.g. /etc/shadow as non-root) but the *attempt* is recorded and flagged
 * by the sensitive-file detector. */
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    const char *targets[] = {"/etc/shadow", "/etc/passwd", "/root/.ssh/id_rsa"};
    for (int i = 0; i < 3; i++) {
        int fd = open(targets[i], O_RDONLY);
        if (fd >= 0) {
            char buf[64];
            ssize_t n = read(fd, buf, sizeof buf);
            (void)n;
            close(fd);
            printf("read %s\n", targets[i]);
        } else {
            printf("could not open %s\n", targets[i]);
        }
    }
    return 0;
}
