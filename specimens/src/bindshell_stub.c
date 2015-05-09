/* bindshell_stub - emulates bind-shell setup without accepting or spawning.
 *
 * It binds an ephemeral loopback TCP port and listens, then exits immediately.
 * No shell is executed and no external interface is exposed.
 */
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("socket");
        return 1;
    }

    int one = 1;
    int opt = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    (void)opt;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (bind(s, (struct sockaddr *)&addr, sizeof addr) != 0) {
        perror("bind");
        close(s);
        return 1;
    }
    if (listen(s, 1) != 0) {
        perror("listen");
        close(s);
        return 1;
    }

    socklen_t len = sizeof addr;
    if (getsockname(s, (struct sockaddr *)&addr, &len) == 0) {
        printf("listening on 127.0.0.1:%u without accepting\n",
               (unsigned)ntohs(addr.sin_port));
    } else {
        printf("listening on loopback without accepting\n");
    }

    close(s);
    return 0;
}
