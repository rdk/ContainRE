/* httpsbeacon - beacons to C2 over HTTPS (TLS), the common real-world case.
 *
 * It verifies the server certificate against the system trust store (which the
 * harness points at its MITM CA via SSL_CERT_FILE when --mitm is set) and against
 * the SNI hostname. With MITM on, the handshake succeeds and the request is
 * decrypted by the sink; with MITM off (or against a real pinned server) the
 * handshake fails.
 *
 * Build: cc httpsbeacon.c -lssl -lcrypto
 */
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *host = (argc > 1) ? argv[1] : "93.184.216.34";
    int port = (argc > 2) ? atoi(argv[2]) : 443;
    const char *sni = (argc > 3) ? argv[3] : "secure.evil.example.com";

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_default_verify_paths(ctx);            /* honors SSL_CERT_FILE */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);
    if (connect(s, (struct sockaddr *)&addr, sizeof addr) != 0) {
        printf("connect failed\n");
        return 1;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, s);
    SSL_set_tlsext_host_name(ssl, sni);                          /* SNI */
    X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), sni, 0);    /* verify hostname */

    if (SSL_connect(ssl) != 1) {
        printf("TLS handshake failed (verify=%ld)\n", SSL_get_verify_result(ssl));
        SSL_free(ssl);
        close(s);
        SSL_CTX_free(ctx);
        return 2;
    }

    char req[256];
    snprintf(req, sizeof req, "GET /gate/beacon HTTP/1.0\r\nHost: %s\r\n\r\n", sni);
    SSL_write(ssl, req, (int)strlen(req));

    char buf[512];
    int n = SSL_read(ssl, buf, sizeof buf - 1);
    if (n > 0) {
        buf[n] = 0;
        char *eol = strchr(buf, '\r');
        if (eol) *eol = 0;
        printf("tls got %d bytes: %s\n", n, buf);
    } else {
        printf("no tls response\n");
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(s);
    SSL_CTX_free(ctx);
    return 0;
}
