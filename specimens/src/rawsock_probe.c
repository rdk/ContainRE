/* rawsock_probe - attempts raw-socket creation, then exits.
 *
 * It sends no packets. On ordinary unprivileged runs the syscall should fail
 * with EPERM; if a test host has CAP_NET_RAW, the socket is closed immediately.
 */
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (s < 0) {
        printf("raw socket denied: %s\n", strerror(errno));
        return 0;
    }

    printf("raw socket opened; closing without sending\n");
    close(s);
    return 0;
}
