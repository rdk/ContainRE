/* ipv6beacon - attempts an outbound IPv6 C2-style connection.
 *
 * The target is the documentation prefix 2001:db8::/32. Under ContainRE's
 * default deny policy the connect is blocked before the kernel can route it.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    const char *host = "2001:db8::42";
    int port = 443;

    int s = socket(AF_INET6, SOCK_STREAM, 0);
    if (s < 0) {
        printf("ipv6 socket unavailable: %s\n", strerror(errno));
        return 0;
    }

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof addr);
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons((uint16_t)port);
    inet_pton(AF_INET6, host, &addr.sin6_addr);

    int r = connect(s, (struct sockaddr *)&addr, sizeof addr);
    printf("connect([%s]:%d) returned %d\n", host, port, r);
    close(s);
    return 0;
}
