#include "ws.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_MAX_MESSAGE (16u * 1024u * 1024u)

struct ws_conn {
    int fd;
    // Bytes read past the HTTP response / previous frame.
    uint8_t* buf;
    size_t buf_len;
    size_t buf_cap;
};

static int read_more(ws_conn_t* ws) {
    if (ws->buf_cap - ws->buf_len < 4096) {
        size_t ncap = ws->buf_cap ? ws->buf_cap * 2 : 8192;
        uint8_t* nb = realloc(ws->buf, ncap);
        if (!nb) return -1;
        ws->buf = nb;
        ws->buf_cap = ncap;
    }
    ssize_t r = recv(ws->fd, ws->buf + ws->buf_len, ws->buf_cap - ws->buf_len, 0);
    if (r <= 0) return -1;
    ws->buf_len += (size_t)r;
    return 0;
}

static int take_exact(ws_conn_t* ws, uint8_t* out, size_t n) {
    while (ws->buf_len < n) {
        if (read_more(ws) != 0) return -1;
    }
    memcpy(out, ws->buf, n);
    memmove(ws->buf, ws->buf + n, ws->buf_len - n);
    ws->buf_len -= n;
    return 0;
}

static int send_all(int fd, const uint8_t* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, data + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int send_frame(ws_conn_t* ws, uint8_t opcode, const uint8_t* payload, size_t len) {
    uint8_t header[14];
    size_t hlen = 0;
    header[hlen++] = 0x80 | opcode; // FIN + opcode

    if (len < 126) {
        header[hlen++] = 0x80 | (uint8_t)len; // MASK + len
    } else if (len < 65536) {
        header[hlen++] = 0x80 | 126;
        header[hlen++] = (uint8_t)(len >> 8);
        header[hlen++] = (uint8_t)(len & 0xFF);
    } else {
        header[hlen++] = 0x80 | 127;
        for (int i = 7; i >= 0; i--) header[hlen++] = (uint8_t)((uint64_t)len >> (i * 8));
    }

    uint8_t mask[4];
    if (RAND_bytes(mask, 4) != 1) return -1;
    memcpy(header + hlen, mask, 4);
    hlen += 4;

    if (send_all(ws->fd, header, hlen) != 0) return -1;

    if (len > 0) {
        uint8_t* masked = malloc(len);
        if (!masked) return -1;
        for (size_t i = 0; i < len; i++) masked[i] = payload[i] ^ mask[i % 4];
        int rc = send_all(ws->fd, masked, len);
        free(masked);
        return rc;
    }
    return 0;
}

// Reads one frame. Returns 0 on success; *payload is malloc'd (or NULL when
// empty), caller frees.
static int read_frame(ws_conn_t* ws, uint8_t* opcode, int* fin, uint8_t** payload, size_t* plen) {
    uint8_t head[2];
    if (take_exact(ws, head, 2) != 0) return -1;

    *fin = (head[0] & 0x80) != 0;
    *opcode = head[0] & 0x0F;
    int masked = (head[1] & 0x80) != 0;
    uint64_t len = head[1] & 0x7F;

    if (len == 126) {
        uint8_t ext[2];
        if (take_exact(ws, ext, 2) != 0) return -1;
        len = ((uint64_t)ext[0] << 8) | ext[1];
    } else if (len == 127) {
        uint8_t ext[8];
        if (take_exact(ws, ext, 8) != 0) return -1;
        len = 0;
        for (int i = 0; i < 8; i++) len = (len << 8) | ext[i];
    }
    if (len > WS_MAX_MESSAGE) return -1;

    uint8_t mask[4] = {0};
    if (masked && take_exact(ws, mask, 4) != 0) return -1;

    uint8_t* data = NULL;
    if (len > 0) {
        data = malloc(len);
        if (!data) return -1;
        if (take_exact(ws, data, len) != 0) { free(data); return -1; }
        if (masked) {
            for (uint64_t i = 0; i < len; i++) data[i] ^= mask[i % 4];
        }
    }
    *payload = data;
    *plen = (size_t)len;
    return 0;
}

ws_conn_t* ws_connect(const char* host, int port, const char* path) {
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* res = NULL;
    if (getaddrinfo(host, port_str, &hints, &res) != 0) return NULL;

    int fd = -1;
    for (struct addrinfo* ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) return NULL;

    // --- HTTP Upgrade ---
    uint8_t key_raw[16];
    if (RAND_bytes(key_raw, 16) != 1) { close(fd); return NULL; }
    char key_b64[32];
    int b64len = EVP_EncodeBlock((unsigned char*)key_b64, key_raw, 16);
    key_b64[b64len] = 0;

    char request[512];
    int rlen = snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n",
        (path && path[0]) ? path : "/ws", host, port, key_b64);
    if (send_all(fd, (uint8_t*)request, (size_t)rlen) != 0) { close(fd); return NULL; }

    // Read response headers
    char response[4096];
    size_t rcvd = 0;
    char* body = NULL;
    while (rcvd < sizeof(response) - 1) {
        ssize_t n = recv(fd, response + rcvd, sizeof(response) - 1 - rcvd, 0);
        if (n <= 0) { close(fd); return NULL; }
        rcvd += (size_t)n;
        response[rcvd] = 0;
        body = strstr(response, "\r\n\r\n");
        if (body) break;
    }
    if (!body || !strstr(response, " 101 ")) { close(fd); return NULL; }

    // Verify Sec-WebSocket-Accept
    char expect_src[64];
    snprintf(expect_src, sizeof(expect_src), "%s%s", key_b64, WS_GUID);
    uint8_t sha[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char*)expect_src, strlen(expect_src), sha);
    char expect_b64[64];
    int elen = EVP_EncodeBlock((unsigned char*)expect_b64, sha, SHA_DIGEST_LENGTH);
    expect_b64[elen] = 0;
    if (!strstr(response, expect_b64)) { close(fd); return NULL; }

    ws_conn_t* ws = calloc(1, sizeof(ws_conn_t));
    if (!ws) { close(fd); return NULL; }
    ws->fd = fd;

    // Keep any bytes that followed the HTTP headers (first frames).
    size_t consumed = (size_t)(body - response) + 4;
    if (rcvd > consumed) {
        size_t extra = rcvd - consumed;
        ws->buf = malloc(extra < 8192 ? 8192 : extra);
        if (!ws->buf) { close(fd); free(ws); return NULL; }
        memcpy(ws->buf, response + consumed, extra);
        ws->buf_len = extra;
        ws->buf_cap = extra < 8192 ? 8192 : extra;
    }
    return ws;
}

int ws_send_binary(ws_conn_t* ws, const uint8_t* data, size_t len) {
    if (!ws) return -1;
    return send_frame(ws, 0x2, data, len);
}

int ws_recv_binary(ws_conn_t* ws, uint8_t** out, size_t* out_len) {
    if (!ws) return -1;
    uint8_t* message = NULL;
    size_t message_len = 0;
    int in_binary = 0;

    for (;;) {
        uint8_t opcode;
        int fin;
        uint8_t* payload = NULL;
        size_t plen = 0;
        if (read_frame(ws, &opcode, &fin, &payload, &plen) != 0) {
            free(message);
            return -1;
        }

        switch (opcode) {
            case 0x2: // binary
                free(message);
                message = payload;
                message_len = plen;
                in_binary = 1;
                if (fin) { *out = message; *out_len = message_len; return 0; }
                break;
            case 0x0: // continuation
                if (in_binary) {
                    if (message_len + plen > WS_MAX_MESSAGE) { free(payload); free(message); return -1; }
                    uint8_t* nb = realloc(message, message_len + plen);
                    if (!nb) { free(payload); free(message); return -1; }
                    message = nb;
                    if (plen) memcpy(message + message_len, payload, plen);
                    message_len += plen;
                    free(payload);
                    if (fin) { *out = message; *out_len = message_len; return 0; }
                } else {
                    free(payload);
                }
                break;
            case 0x9: // ping → pong
                send_frame(ws, 0xA, payload, plen);
                free(payload);
                break;
            case 0xA: // pong
            case 0x1: // text — AdaTP is binary-only
                free(payload);
                break;
            case 0x8: // close
                send_frame(ws, 0x8, NULL, 0);
                free(payload);
                free(message);
                return -1;
            default:
                free(payload);
                break;
        }
    }
}

void ws_close(ws_conn_t* ws) {
    if (!ws) return;
    if (ws->fd >= 0) {
        send_frame(ws, 0x8, NULL, 0);
        close(ws->fd);
    }
    free(ws->buf);
    free(ws);
}

int ws_get_fd(ws_conn_t* ws) {
    return ws ? ws->fd : -1;
}
