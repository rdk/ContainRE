/* netbeacon - attempts an outbound TCP connection (like C2 beaconing).
 *
 * With ContainRE's deny/simulate posture the connect() is blocked in-flight by
 * the tracer and returns an error; the attempt is still recorded and flagged.
 */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *host = (argc > 1) ? argv[1] : "93.184.216.34"; /* example.org */
    int port = (argc > 2) ? atoi(argv[2]) : 80;

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    int r = connect(s, (struct sockaddr *)&addr, sizeof addr);
    printf("connect(%s:%d) returned %d\n", host, port, r);
    close(s);
    return 0;
}
