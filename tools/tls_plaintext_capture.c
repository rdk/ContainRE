#define _GNU_SOURCE

#include <dlfcn.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

typedef struct ssl_st SSL;

static int guard = 0;
static int replay_loaded = 0;
static uint8_t *replay_data = NULL;
static size_t replay_len = 0;
typedef struct {
    size_t start;
    size_t len;
    char direction;
} replay_segment_t;
static replay_segment_t *replay_segments = NULL;
static size_t replay_segment_count = 0;
static size_t replay_segment_index = 0;
static size_t replay_segment_offset = 0;
static int replay_last_error = -1;

static int replay_enabled(void) {
    const char *mode = getenv("CONTAINRE_TLS_MODE");
    if (mode && strcmp(mode, "replay") == 0) {
        return 1;
    }
    const char *path = getenv("CONTAINRE_TLS_REPLAY");
    return path && *path;
}

static int fake_handshake_enabled(void) {
    const char *raw = getenv("CONTAINRE_TLS_FAKE_HANDSHAKE");
    return replay_enabled() && raw && strcmp(raw, "1") == 0;
}

static void *resolve_ssl_symbol(const char *name) {
    void *sym = dlsym(RTLD_NEXT, name);
    if (sym) {
        return sym;
    }
    const char *explicit_path = getenv("CONTAINRE_TLS_LIBSSL");
    if (explicit_path && *explicit_path) {
        void *handle = dlopen(explicit_path, RTLD_LAZY | RTLD_NOLOAD);
        if (handle) {
            sym = dlsym(handle, name);
            if (sym) {
                return sym;
            }
        }
    }
    void *handle = dlopen("libssl.so.3", RTLD_LAZY | RTLD_NOLOAD);
    return handle ? dlsym(handle, name) : NULL;
}

static size_t capture_limit(void) {
    const char *raw = getenv("CONTAINRE_TLS_CAPTURE_MAX");
    if (!raw || !*raw) {
        return 4096;
    }
    char *end = NULL;
    unsigned long value = strtoul(raw, &end, 10);
    if (end == raw || value == 0) {
        return 4096;
    }
    if (value > 65536) {
        return 65536;
    }
    return (size_t)value;
}

static int append_open(void) {
    const char *path = getenv("CONTAINRE_TLS_CAPTURE");
    if (!path || !*path) {
        path = "/work/tls_plaintext_capture.log";
    }
    return (int)syscall(SYS_openat, AT_FDCWD, path, O_WRONLY | O_CREAT | O_APPEND, 0600);
}

static char hex_digit(unsigned int value) {
    return (char)(value < 10 ? ('0' + value) : ('a' + value - 10));
}

static void append_str(int fd, const char *s) {
    syscall(SYS_write, fd, s, strlen(s));
}

static void append_uint(int fd, size_t value) {
    char buf[32];
    size_t pos = sizeof(buf);
    buf[--pos] = '\0';
    if (value == 0) {
        buf[--pos] = '0';
    } else {
        while (value && pos > 0) {
            buf[--pos] = (char)('0' + (value % 10));
            value /= 10;
        }
    }
    append_str(fd, &buf[pos]);
}

static void log_buffer(const char *direction, const char *api, const void *buf, size_t len) {
    if (guard || !buf || len == 0) {
        return;
    }
    guard = 1;
    size_t limit = capture_limit();
    size_t n = len < limit ? len : limit;
    int fd = append_open();
    if (fd >= 0) {
        append_str(fd, "{\"direction\":\"");
        append_str(fd, direction);
        append_str(fd, "\",\"api\":\"");
        append_str(fd, api);
        append_str(fd, "\",\"len\":");
        append_uint(fd, len);
        append_str(fd, ",\"captured\":");
        append_uint(fd, n);
        append_str(fd, ",\"hex\":\"");
        const uint8_t *p = (const uint8_t *)buf;
        char out[512];
        size_t out_pos = 0;
        for (size_t i = 0; i < n; i++) {
            out[out_pos++] = hex_digit((p[i] >> 4) & 0xf);
            out[out_pos++] = hex_digit(p[i] & 0xf);
            if (out_pos == sizeof(out)) {
                syscall(SYS_write, fd, out, out_pos);
                out_pos = 0;
            }
        }
        if (out_pos) {
            syscall(SYS_write, fd, out, out_pos);
        }
        append_str(fd, "\"}\n");
        syscall(SYS_close, fd);
    }
    guard = 0;
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static char *find_substr(char *haystack, size_t hay_len, const char *needle) {
    size_t needle_len = strlen(needle);
    if (needle_len == 0 || hay_len < needle_len) {
        return NULL;
    }
    for (size_t i = 0; i + needle_len <= hay_len; i++) {
        if (memcmp(haystack + i, needle, needle_len) == 0) {
            return haystack + i;
        }
    }
    return NULL;
}

static void append_hex_bytes(uint8_t *out, size_t *out_len, const char *start, const char *end) {
    int high = -1;
    for (const char *p = start; p < end; p++) {
        int value = hex_value(*p);
        if (value < 0) {
            continue;
        }
        if (high < 0) {
            high = value;
        } else {
            out[(*out_len)++] = (uint8_t)((high << 4) | value);
            high = -1;
        }
    }
}

static void load_replay(void) {
    if (replay_loaded) {
        return;
    }
    replay_loaded = 1;
    const char *path = getenv("CONTAINRE_TLS_REPLAY");
    if (!path || !*path) {
        return;
    }
    int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY, 0);
    if (fd < 0) {
        return;
    }
    size_t cap = 65536;
    size_t used = 0;
    char *raw = (char *)malloc(cap);
    if (!raw) {
        syscall(SYS_close, fd);
        return;
    }
    for (;;) {
        if (used == cap) {
            size_t next = cap * 2;
            char *grown = (char *)realloc(raw, next);
            if (!grown) {
                free(raw);
                syscall(SYS_close, fd);
                return;
            }
            raw = grown;
            cap = next;
        }
        ssize_t n = (ssize_t)syscall(SYS_read, fd, raw + used, cap - used);
        if (n <= 0) {
            break;
        }
        used += (size_t)n;
    }
    syscall(SYS_close, fd);
    if (used == 0) {
        free(raw);
        return;
    }

    replay_data = (uint8_t *)malloc(used / 2 + 1);
    if (!replay_data) {
        free(raw);
        return;
    }
    replay_segments = (replay_segment_t *)malloc((used + 1) * sizeof(replay_segment_t));
    if (!replay_segments) {
        free(replay_data);
        replay_data = NULL;
        free(raw);
        return;
    }
    replay_len = 0;
    replay_segment_count = 0;
    char *line = raw;
    char *end = raw + used;
    while (line < end) {
        char *line_end = line;
        while (line_end < end && *line_end != '\n' && *line_end != '\r') {
            line_end++;
        }
        int include = 1;
        char segment_direction = 'i';
        char *direction = find_substr(line, (size_t)(line_end - line), "\"direction\"");
        if (direction) {
            if (find_substr(line, (size_t)(line_end - line), "\"out\"")) {
                segment_direction = 'o';
            } else if (find_substr(line, (size_t)(line_end - line), "\"in\"")) {
                segment_direction = 'i';
            } else {
                include = 0;
            }
        }
        char *hex = find_substr(line, (size_t)(line_end - line), "\"hex\"");
        size_t before = replay_len;
        if (include && hex) {
            char *colon = hex;
            while (colon < line_end && *colon != ':') {
                colon++;
            }
            char *quote = colon;
            while (quote < line_end && *quote != '"') {
                quote++;
            }
            if (quote < line_end) {
                char *value = quote + 1;
                char *value_end = value;
                while (value_end < line_end && *value_end != '"') {
                    value_end++;
                }
                append_hex_bytes(replay_data, &replay_len, value, value_end);
            }
        } else if (include && !direction) {
            append_hex_bytes(replay_data, &replay_len, line, line_end);
        }
        if (replay_len > before) {
            replay_segments[replay_segment_count].start = before;
            replay_segments[replay_segment_count].len = replay_len - before;
            replay_segments[replay_segment_count].direction = segment_direction;
            replay_segment_count++;
        }
        line = line_end;
        while (line < end && (*line == '\n' || *line == '\r')) {
            line++;
        }
    }
    free(raw);
}

static int replay_current_is(char direction) {
    load_replay();
    while (replay_segment_index < replay_segment_count
           && replay_segment_offset >= replay_segments[replay_segment_index].len) {
        replay_segment_index++;
        replay_segment_offset = 0;
    }
    return replay_segment_index < replay_segment_count
        && replay_segments[replay_segment_index].direction == direction;
}

static void replay_consume_expected_out(void) {
    load_replay();
    if (replay_current_is('o')) {
        replay_segment_index++;
        replay_segment_offset = 0;
    }
}

static ssize_t replay_read_bytes(void *buf, size_t max_len) {
    load_replay();
    if (!buf || max_len == 0 || replay_len == 0) {
        replay_last_error = 6; /* SSL_ERROR_ZERO_RETURN */
        return 0;
    }
    if (replay_segment_count == 0) {
        replay_segments = (replay_segment_t *)malloc(sizeof(replay_segment_t));
        if (!replay_segments) {
            return 0;
        }
        replay_segments[0].start = 0;
        replay_segments[0].len = replay_len;
        replay_segments[0].direction = 'i';
        replay_segment_count = 1;
    }
    if (replay_segment_index >= replay_segment_count) {
        replay_last_error = 6; /* SSL_ERROR_ZERO_RETURN */
        return 0;
    }
    replay_segment_t *segment = &replay_segments[replay_segment_index];
    if (replay_segment_offset >= segment->len) {
        replay_segment_index++;
        replay_segment_offset = 0;
        if (replay_segment_index >= replay_segment_count) {
            replay_last_error = 6; /* SSL_ERROR_ZERO_RETURN */
            return 0;
        }
        segment = &replay_segments[replay_segment_index];
    }
    if (segment->direction != 'i') {
        replay_last_error = 2; /* SSL_ERROR_WANT_READ */
        return -1;
    }
    size_t n = segment->len - replay_segment_offset;
    if (n > max_len) {
        n = max_len;
    }
    memcpy(buf, replay_data + segment->start + replay_segment_offset, n);
    replay_segment_offset += n;
    if (replay_segment_offset >= segment->len) {
        replay_segment_index++;
        replay_segment_offset = 0;
    }
    replay_last_error = 0; /* SSL_ERROR_NONE */
    return (ssize_t)n;
}

int SSL_connect(SSL *ssl) {
    if (fake_handshake_enabled()) {
        (void)ssl;
        return 1;
    }
    typedef int (*fn_t)(SSL *);
    static fn_t real_fn = NULL;
    if (!real_fn) {
        real_fn = (fn_t)resolve_ssl_symbol("SSL_connect");
    }
    return real_fn ? real_fn(ssl) : -1;
}

int SSL_do_handshake(SSL *ssl) {
    if (fake_handshake_enabled()) {
        (void)ssl;
        return 1;
    }
    typedef int (*fn_t)(SSL *);
    static fn_t real_fn = NULL;
    if (!real_fn) {
        real_fn = (fn_t)resolve_ssl_symbol("SSL_do_handshake");
    }
    return real_fn ? real_fn(ssl) : -1;
}

int SSL_shutdown(SSL *ssl) {
    if (fake_handshake_enabled()) {
        (void)ssl;
        return 1;
    }
    typedef int (*fn_t)(SSL *);
    static fn_t real_fn = NULL;
    if (!real_fn) {
        real_fn = (fn_t)resolve_ssl_symbol("SSL_shutdown");
    }
    return real_fn ? real_fn(ssl) : -1;
}

int SSL_get_error(SSL *ssl, int ret) {
    if (replay_enabled() && replay_last_error >= 0) {
        (void)ssl;
        int out = replay_last_error;
        replay_last_error = -1;
        return out;
    }
    if (fake_handshake_enabled()) {
        (void)ssl;
        if (ret > 0) {
            return 0; /* SSL_ERROR_NONE */
        }
        if (ret == 0) {
            return 6; /* SSL_ERROR_ZERO_RETURN */
        }
        return 1; /* SSL_ERROR_SSL */
    }
    typedef int (*fn_t)(SSL *, int);
    static fn_t real_fn = NULL;
    if (!real_fn) {
        real_fn = (fn_t)resolve_ssl_symbol("SSL_get_error");
    }
    return real_fn ? real_fn(ssl, ret) : 1;
}

void SSL_get0_alpn_selected(const SSL *ssl, const unsigned char **data, unsigned int *len) {
    if (replay_enabled()) {
        static const unsigned char h2[] = "h2";
        (void)ssl;
        if (data) {
            *data = h2;
        }
        if (len) {
            *len = 2;
        }
        return;
    }
    typedef void (*fn_t)(const SSL *, const unsigned char **, unsigned int *);
    static fn_t real_fn = NULL;
    if (!real_fn) {
        real_fn = (fn_t)resolve_ssl_symbol("SSL_get0_alpn_selected");
    }
    if (real_fn) {
        real_fn(ssl, data, len);
        return;
    }
    if (data) {
        *data = NULL;
    }
    if (len) {
        *len = 0;
    }
}

int SSL_write(SSL *ssl, const void *buf, int num) {
    if (replay_enabled()) {
        (void)ssl;
        if (num > 0) {
            log_buffer("out", "SSL_write", buf, (size_t)num);
        }
        replay_consume_expected_out();
        replay_last_error = 0;
        return num;
    }
    typedef int (*fn_t)(SSL *, const void *, int);
    static fn_t real_fn = NULL;
    if (!real_fn) {
        real_fn = (fn_t)resolve_ssl_symbol("SSL_write");
    }
    int ret = real_fn ? real_fn(ssl, buf, num) : -1;
    if (ret > 0) {
        log_buffer("out", "SSL_write", buf, (size_t)ret);
    }
    return ret;
}

int SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written) {
    if (replay_enabled()) {
        (void)ssl;
        if (written) {
            *written = num;
        }
        if (num > 0) {
            log_buffer("out", "SSL_write_ex", buf, num);
        }
        replay_consume_expected_out();
        replay_last_error = 0;
        return 1;
    }
    typedef int (*fn_t)(SSL *, const void *, size_t, size_t *);
    static fn_t real_fn = NULL;
    if (!real_fn) {
        real_fn = (fn_t)resolve_ssl_symbol("SSL_write_ex");
    }
    int ret = real_fn ? real_fn(ssl, buf, num, written) : 0;
    if (ret == 1 && written && *written > 0) {
        log_buffer("out", "SSL_write_ex", buf, *written);
    }
    return ret;
}

int SSL_read(SSL *ssl, void *buf, int num) {
    if (replay_enabled()) {
        (void)ssl;
        if (num <= 0) {
            return 0;
        }
        ssize_t n = replay_read_bytes(buf, (size_t)num);
        if (n > 0) {
            log_buffer("in", "SSL_read", buf, (size_t)n);
        }
        return (int)n;
    }
    typedef int (*fn_t)(SSL *, void *, int);
    static fn_t real_fn = NULL;
    if (!real_fn) {
        real_fn = (fn_t)resolve_ssl_symbol("SSL_read");
    }
    int ret = real_fn ? real_fn(ssl, buf, num) : -1;
    if (ret > 0) {
        log_buffer("in", "SSL_read", buf, (size_t)ret);
    }
    return ret;
}

int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes) {
    if (replay_enabled()) {
        (void)ssl;
        ssize_t n = replay_read_bytes(buf, num);
        if (readbytes) {
            *readbytes = n > 0 ? (size_t)n : 0;
        }
        if (n > 0) {
            log_buffer("in", "SSL_read_ex", buf, (size_t)n);
        }
        return n > 0 ? 1 : 0;
    }
    typedef int (*fn_t)(SSL *, void *, size_t, size_t *);
    static fn_t real_fn = NULL;
    if (!real_fn) {
        real_fn = (fn_t)resolve_ssl_symbol("SSL_read_ex");
    }
    int ret = real_fn ? real_fn(ssl, buf, num, readbytes) : 0;
    if (ret == 1 && readbytes && *readbytes > 0) {
        log_buffer("in", "SSL_read_ex", buf, *readbytes);
    }
    return ret;
}
