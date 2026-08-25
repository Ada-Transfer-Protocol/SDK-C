
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "include/adatp.h"

// Note: Ensure you build with proper include paths for OpenSSL
// E.g. -I/opt/homebrew/include -L/opt/homebrew/lib

void generate_mock_uuid_bytes(uint8_t* buf) {
    // 16 bytes dummy
    for(int i=0; i<16; i++) buf[i] = (uint8_t)i;
}

int main() {
    printf("C File Transfer Example (Sender Only)\n");
    
    // Use adatp_client_create (Heap Ptr) instead of stack allocation (Incomplete Type)
    adatp_client_t* client = adatp_client_create("127.0.0.1", 3000);
    if (!client) {
        printf("Failed to create client\n");
        return 1;
    }
    
    if (adatp_client_connect(client) != 0) {
        printf("Connect failed (Is server running?)\n");
        return 1;
    }
    
    printf("Connected. Authenticating...\n");
    if (adatp_client_authenticate(client, "cbot", "secret_password") != 0) {
        printf("Auth failed\n");
        adatp_client_disconnect(client);
        adatp_client_destroy(client);
        return 1;
    }
    
    printf("Joining 'files' room...\n");
    adatp_client_join_room(client, "files");
    
    printf("Sending file implementation in 2 seconds...\n");
    sleep(2);
    
    // Mock File Data
    const char* filename = "test_c_upload.txt";
    const char* content = "Hello from C File Transfer SDK!";
    size_t size = strlen(content);
    
    // Init Payload (JSON)
    const char* file_id = "00010203-0405-0607-0809-0a0b0c0d0e0f";
    
    char init_json[256];
    snprintf(init_json, sizeof(init_json), "{\"id\": \"%s\", \"filename\": \"%s\", \"size\": %zu}", file_id, filename, size);
    
    printf("Sending Init: %s\n", init_json);
    adatp_client_send(client, ADATP_MSG_FILE_INIT, (const uint8_t*)init_json, strlen(init_json));
    
    // Chunk Payload
    // [FileID(16)][Data]
    uint8_t chunk_payload[1024];
    uint8_t fid_bytes[16];
    generate_mock_uuid_bytes(fid_bytes); 
    
    memcpy(chunk_payload, fid_bytes, 16);
    memcpy(chunk_payload + 16, content, size);
    
    printf("Sending Chunk...\n");
    adatp_client_send(client, ADATP_MSG_FILE_CHUNK, chunk_payload, 16 + size);
    
    // Complete Payload
    // [FileID(16)]
    printf("Sending Complete...\n");
    adatp_client_send(client, ADATP_MSG_FILE_COMPLETE, fid_bytes, 16);
    
    printf("File sent successfully! Disconnecting in 1s...\n");
    sleep(1);
    
    adatp_client_disconnect(client);
    adatp_client_destroy(client);
    return 0;
}
