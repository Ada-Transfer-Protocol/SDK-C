#include "adatp.h"
#include "internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/rand.h>

struct adatp_client {
    int socket;
    char* host;
    int port;
    int connected;
    secure_session_t session;
    uint8_t session_id[16];
};

adatp_client_t* adatp_client_create(const char* host, int port) {
    adatp_client_t* client = malloc(sizeof(adatp_client_t));
    client->host = strdup(host);
    client->port = port;
    client->socket = -1;
    client->connected = 0;
    // Generate Session ID
    RAND_bytes(client->session_id, 16);
    return client;
}

void adatp_client_destroy(adatp_client_t* client) {
    if (client) {
        if (client->connected) adatp_client_disconnect(client);
        free(client->host);
        free(client);
    }
}

static int recv_all(int sock, uint8_t* buf, int len) {
    int total = 0;
    while(total < len) {
        int r = recv(sock, buf + total, len - total, 0);
        if (r <= 0) return -1;
        total += r;
    }
    return 0;
}

int adatp_client_read_packet(adatp_client_t* client, adatp_packet_t* packet) {
    uint8_t header_buf[ADATP_HEADER_SIZE];
    if (recv_all(client->socket, header_buf, ADATP_HEADER_SIZE) != 0) return -1;
    
    // Decode Header manually to get length and flags
    // Magic (4), Ver(1), Flags(2), Len(4)...
    // Offsets: Magic:0, Ver:4, Flags:5, Len:7, Seq:11, Type:19, Time:21, Sid:29
    
    // We need Little Endian check.
    // For simplicity assuming Host is LE (x86/ARM).
    memcpy(&packet->header.magic, header_buf, 4);
    packet->header.version = header_buf[4];
    memcpy(&packet->header.flags, header_buf + 5, 2);
    memcpy(&packet->header.length, header_buf + 7, 4);
    memcpy(&packet->header.sequence, header_buf + 11, 8);
    memcpy(&packet->header.msg_type, header_buf + 19, 2);
    memcpy(&packet->header.timestamp, header_buf + 21, 8);
    memcpy(packet->header.session_id, header_buf + 29, 16);
    
    // Allocate payload
    packet->payload = malloc(packet->header.length);
    if(packet->header.length > 0) {
        if (recv_all(client->socket, packet->payload, packet->header.length) != 0) {
            free(packet->payload);
            return -1;
        }
    }
    
    if(packet->header.flags & ADATP_FLAG_ENCRYPTED) {
        if (recv_all(client->socket, packet->auth_tag, 16) != 0) {
            free(packet->payload);
            return -1;
        }
    }
    
    return 0;
}

static int send_raw_packet(adatp_client_t* client, adatp_packet_t* packet) {
    uint8_t buf[4096]; // Max packet size suitable for demo
    size_t len = 0; // Filled by encode?
    
    // Manual serialization based on packet.c Logic needed here or call serialize
    adatp_packet_serialize(packet, buf);
    size_t size = adatp_packet_serialized_size(packet);
    
    if (send(client->socket, buf, size, 0) != size) return -1;
    return 0;
}

int adatp_client_connect(adatp_client_t* client) {
    client->socket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(client->port);
    inet_pton(AF_INET, client->host, &serv_addr.sin_addr);
    
    if (connect(client->socket, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) return -1;
    client->connected = 1;
    
    // Handshake
    printf("C Client: Connected, starting handshake...\n");
    
    // 1. Generate Keypair
    EVP_PKEY *my_key = NULL;
    uint8_t my_pub[32];
    if (!crypto_generate_x25519(&my_key, my_pub)) {
        printf("Keygen failed\n");
        return -2;
    }
    
    // 2. Send INIT
    adatp_packet_t init_pkt;
    memset(&init_pkt, 0, sizeof(init_pkt));
    init_pkt.header.magic = ADATP_MAGIC_NUMBER;
    init_pkt.header.version = 1;
    init_pkt.header.msg_type = ADATP_MSG_HANDSHAKE_INIT;
    init_pkt.header.length = 32;
    memcpy(init_pkt.header.session_id, client->session_id, 16);
    init_pkt.payload = my_pub;
    
    send_raw_packet(client, &init_pkt);
    
    // 3. Recv RESPONSE
    adatp_packet_t resp_pkt;
    if(adatp_client_read_packet(client, &resp_pkt) != 0) return -3;
    
    if(resp_pkt.header.msg_type != ADATP_MSG_HANDSHAKE_RESPONSE) {
        printf("Expected Handshake Response\n");
        return -3;
    }
    
    // 4. Compute Shared
    uint8_t shared_secret[32];
    if(!crypto_compute_shared(my_key, resp_pkt.payload, shared_secret)) {
        printf("Shared secret failed\n");
        return -4;
    }
    EVP_PKEY_free(my_key);
    free(resp_pkt.payload);
    
    // 5. Init Session
    memset(&client->session, 0, sizeof(secure_session_t));
    client->session.role = 0; // Client
    client->session.my_sequence = 1;
    client->session.peer_sequence = 1;
    crypto_hkdf_derive(shared_secret, &client->session);
    
    // 6. Send COMPLETE (Encrypted)
    uint8_t verify_plain[] = "Verification OK";
    uint8_t ciphertext[64];
    uint8_t tag[16];
    uint64_t seq;
    
    int clen = crypto_encrypt_gcm(&client->session, verify_plain, strlen((char*)verify_plain), ciphertext, tag, &seq);
    
    adatp_packet_t cur;
    memset(&cur, 0, sizeof(cur));
    cur.header.magic = ADATP_MAGIC_NUMBER;
    cur.header.version = 1;
    cur.header.msg_type = ADATP_MSG_HANDSHAKE_COMPLETE;
    cur.header.flags = ADATP_FLAG_ENCRYPTED;
    cur.header.length = clen;
    cur.header.sequence = seq;
    memcpy(cur.header.session_id, client->session_id, 16);
    cur.payload = ciphertext;
    memcpy(cur.auth_tag, tag, 16);
    
    send_raw_packet(client, &cur);
    printf("C Client: Handshake Complete!\n");
    
    return 0;
}

void adatp_client_disconnect(adatp_client_t* client) {
    if (client->socket >= 0) {
        // Send DISCONNECT
        adatp_packet_t pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.header.magic = ADATP_MAGIC_NUMBER;
        pkt.header.version = 1;
        pkt.header.msg_type = ADATP_MSG_DISCONNECT;
        pkt.header.length = 0;
        memcpy(pkt.header.session_id, client->session_id, 16);
        pkt.payload = NULL;
        send_raw_packet(client, &pkt);
        
        close(client->socket);
        client->socket = -1;
    }
    client->connected = 0;
}

int adatp_client_join_room(adatp_client_t* client, const char* room) {
    uint8_t ciphertext[1024];
    uint8_t tag[16];
    uint64_t seq;
    
    int clen = crypto_encrypt_gcm(&client->session, (uint8_t*)room, strlen(room), ciphertext, tag, &seq);
    if(clen < 0) return -1;
    
    adatp_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.header.magic = ADATP_MAGIC_NUMBER;
    pkt.header.version = 1;
    pkt.header.msg_type = ADATP_MSG_JOIN_ROOM;
    pkt.header.flags = ADATP_FLAG_ENCRYPTED;
    pkt.header.length = clen;
    pkt.header.sequence = seq;
    memcpy(pkt.header.session_id, client->session_id, 16);
    pkt.payload = ciphertext;
    memcpy(pkt.auth_tag, tag, 16);
    
    send_raw_packet(client, &pkt);
    // printf("Joined room: %s\n", room);
    return 0;
}

int adatp_client_authenticate(adatp_client_t* client, const char* username, const char* password) {
    char json[512];
    snprintf(json, sizeof(json), "{\"username\": \"%s\", \"password\": \"%s\"}", username, password);
    
    uint8_t ciphertext[1024];
    uint8_t tag[16];
    uint64_t seq;
    
    int clen = crypto_encrypt_gcm(&client->session, (uint8_t*)json, strlen(json), ciphertext, tag, &seq);
    if(clen < 0) return -1;
    
    adatp_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.header.magic = ADATP_MAGIC_NUMBER;
    pkt.header.version = 1;
    pkt.header.msg_type = ADATP_MSG_AUTH_REQUEST;
    pkt.header.flags = ADATP_FLAG_ENCRYPTED;
    pkt.header.length = clen;
    pkt.header.sequence = seq;
    memcpy(pkt.header.session_id, client->session_id, 16);
    pkt.payload = ciphertext;
    memcpy(pkt.auth_tag, tag, 16);
    
    if (send_raw_packet(client, &pkt) != 0) return -1;
    
    // Read Response
    adatp_packet_t resp;
    if (adatp_client_read_packet(client, &resp) != 0) return -2;
    
    if (resp.header.flags & ADATP_FLAG_ENCRYPTED) {
        uint8_t plain[1024];
        int plen = crypto_decrypt_gcm(&client->session, resp.payload, resp.header.length, resp.auth_tag, resp.header.sequence, plain);
        free(resp.payload);
        
        if (plen < 0) return -3;
        plain[plen] = 0; // Null terminate
        
        if (resp.header.msg_type == ADATP_MSG_AUTH_SUCCESS) {
            printf("Auth Success: %s\n", plain);
            return 0;
        } else if (resp.header.msg_type == ADATP_MSG_AUTH_FAILURE) {
            printf("Auth Failed: %s\n", plain);
            return -4;
        }
    } else {
        free(resp.payload);
    }
    
    return -5; // Unexpected
}

int adatp_client_send_text(adatp_client_t* client, const char* text) {
    uint8_t ciphertext[1024];
    uint8_t tag[16];
    uint64_t seq;
    
    int clen = crypto_encrypt_gcm(&client->session, (uint8_t*)text, strlen(text), ciphertext, tag, &seq);
    if(clen < 0) return -1;
    
    adatp_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.header.magic = ADATP_MAGIC_NUMBER;
    pkt.header.version = 1;
    pkt.header.msg_type = ADATP_MSG_TEXT_MESSAGE;
    pkt.header.flags = ADATP_FLAG_ENCRYPTED;
    pkt.header.length = clen;
    pkt.header.sequence = seq;
    memcpy(pkt.header.session_id, client->session_id, 16);
    pkt.payload = ciphertext;
    memcpy(pkt.auth_tag, tag, 16);
    
    send_raw_packet(client, &pkt);
    return 0;
}

int adatp_client_send(adatp_client_t* client, adatp_msg_type_t type, const uint8_t* payload, size_t len) {
    if (!client || len > 4096) return -1;
    
    uint8_t ciphertext[4128]; 
    uint8_t tag[16];
    uint64_t seq;
    
    int clen = crypto_encrypt_gcm(&client->session, payload, len, ciphertext, tag, &seq);
    if (clen < 0) return -1;
    
    adatp_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.header.magic = ADATP_MAGIC_NUMBER;
    pkt.header.version = 1;
    pkt.header.msg_type = type;
    pkt.header.flags = ADATP_FLAG_ENCRYPTED;
    pkt.header.length = clen;
    pkt.header.sequence = seq;
    memcpy(pkt.header.session_id, client->session_id, 16);
    pkt.payload = ciphertext;
    memcpy(pkt.auth_tag, tag, 16);
    
    return send_raw_packet(client, &pkt);
}

int adatp_client_get_socket(adatp_client_t* client) {
    return client->socket;
}

int adatp_client_decrypt_packet(adatp_client_t* client, const adatp_packet_t* packet, uint8_t* out_buf) {
    if (!packet->payload) return -1;
    if (!(packet->header.flags & ADATP_FLAG_ENCRYPTED)) {
        // Just copy
        memcpy(out_buf, packet->payload, packet->header.length);
        return packet->header.length;
    }
    
    int len = crypto_decrypt_gcm(
        &client->session, 
        packet->payload, 
        packet->header.length, 
        packet->auth_tag, 
        packet->header.sequence, 
        out_buf
    );
    
    return len;
}
