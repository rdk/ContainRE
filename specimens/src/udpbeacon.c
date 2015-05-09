/* udpbeacon - sends a UDP datagram to a DNS resolver (like DNS-tunneling C2).
 * The harness blocks the sendto() to a non-allowlisted host in deny/simulate mode. */
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("socket");
        return 1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);

    ssize_t r = sendto(s, "\x12\x34", 2, 0, (struct sockaddr *)&addr, sizeof addr);
    printf("sendto(8.8.8.8:53) returned %zd\n", r);
    close(s);
    return 0;
}
