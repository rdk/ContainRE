/* dropper_stub - writes a harmless executable-looking payload.
 *
 * The payload is just text in the harness work directory. It is chmodded to
 * exercise dropper telemetry, but it is never executed.
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    const char *payload = "# ContainRE harmless payload fixture\nexit 0\n";
    int fd = open("payload.sh", O_WRONLY | O_CREAT | O_TRUNC, 0700);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    ssize_t n = write(fd, payload, strlen(payload));
    (void)n;
    close(fd);

    if (chmod("payload.sh", 0700) != 0) {
        perror("chmod");
        return 1;
    }

    printf("dropper stub wrote payload.sh without executing it\n");
    return 0;
}
