/*
 * v2 end-to-end client: connects to a live AdaTP server with a pinned key,
 * runs the authenticated handshake, then an encrypted auth + join + text
 * round-trip (which only works if the AAD-bound v2 session agrees end to end).
 * Exit 0 on success. Driven by test/run_e2e_v2.sh.
 *
 * usage: e2e_v2 <host> <port> <server_key_hex(64) | "v1">
 *   - a 64-hex key pins the server and runs the authenticated v2 handshake;
 *   - the literal "v1" runs the unauthenticated v1 handshake (regression check).
 */
#include "adatp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int unhex(const char *h, uint8_t *out, size_t n) {
    if (strlen(h) != n * 2) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(h + i * 2, "%2x", &v) != 1) return 0;
        out[i] = (uint8_t)v;
    }
    return 1;
}

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    int port = argc > 2 ? atoi(argv[2]) : 3199;
    const char *keyhex = argc > 3 ? argv[3] : getenv("ADATP_SERVER_KEY");
    int v1_mode = (keyhex && strcmp(keyhex, "v1") == 0);
    uint8_t key[32];
    if (!v1_mode && (!keyhex || strlen(keyhex) != 64 || !unhex(keyhex, key, 32))) {
        fprintf(stderr, "usage: e2e_v2 <host> <port> <server_key_hex(64) | v1>\n");
        return 2;
    }

    adatp_client_t *c = adatp_client_create(host, port);
    if (!c) { fprintf(stderr, "create failed\n"); return 1; }

    if (!v1_mode) adatp_client_set_server_key(c, key); /* pin -> v2 */

    int rc = 1;
    if (adatp_client_connect(c) != 0) { fprintf(stderr, "FAIL: handshake\n"); goto done; }
    if (adatp_client_authenticate(c, "guest", "") != 0) { fprintf(stderr, "FAIL: auth round-trip\n"); goto done; }
    if (adatp_client_join_room(c, "lobby") != 0) { fprintf(stderr, "FAIL: join round-trip\n"); goto done; }
    if (adatp_client_send_text(c, "hello from C v2") != 0) { fprintf(stderr, "FAIL: send text\n"); goto done; }
    adatp_client_disconnect(c);
    printf("C E2E %s PASSED: handshake + round-trip (auth + join + text)%s.\n",
           v1_mode ? "v1" : "v2", v1_mode ? "" : " with header-AAD");
    rc = 0;
done:
    adatp_client_destroy(c);
    return rc;
}
