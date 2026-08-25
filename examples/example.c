#include "adatp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <arpa/inet.h>

// Helper to check prefix
int starts_with(const char *pre, const char *str) {
    size_t lenpre = strlen(pre),
           lenstr = strlen(str);
    return lenstr < lenpre ? 0 : strncmp(pre, str, lenpre) == 0;
}

int main(int argc, char* argv[]) {
    printf("==========================================\n");
    printf("   AdaTP C Chat Client (CLI)              \n");
    printf("==========================================\n");
    
    char username[256];
    printf("Enter your username: ");
    if (fgets(username, sizeof(username), stdin) != NULL) {
        username[strcspn(username, "\n")] = 0; // Remove newline
    }
    
    adatp_client_t* client = adatp_client_create("127.0.0.1", 3000);
    
    printf("Connecting...\n");
    if (adatp_client_connect(client) != 0) {
        printf("Failed to connect.\n");
        return 1;
    }
    
    printf("Joined chat as '%s'.\n", username);
    printf("Type '/join <room>' to switch rooms.\n");
    printf("Type '/quit' to exit.\n");
    
    int sock = adatp_client_get_socket(client);
    fd_set readfds;
    
    while(1) {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sock, &readfds);
        
        int max_fd = (sock > STDIN_FILENO) ? sock : STDIN_FILENO;
        
        if (select(max_fd + 1, &readfds, NULL, NULL, NULL) < 0) {
            perror("select");
            break;
        }
        
        // Socket Readable?
        if (FD_ISSET(sock, &readfds)) {
            adatp_packet_t pkt;
            if (adatp_client_read_packet(client, &pkt) != 0) {
                printf("Server disconnected or error.\n");
                break;
            }
            
            if (pkt.header.msg_type == ADATP_MSG_TEXT_MESSAGE) {
                uint8_t plaintext[1024];
                int len = adatp_client_decrypt_packet(client, &pkt, plaintext);
                if (len >= 0) {
                    plaintext[len] = 0; // Null terminate
                    printf("< %s\n", plaintext);
                } else {
                    printf("< Decryption Error\n");
                }
            } else if (pkt.header.msg_type == ADATP_MSG_DISCONNECT) {
                printf("Server disconnected.\n");
                break;
            }
            
            if (pkt.payload) free(pkt.payload);
        }
        
        // Stdin Readable?
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            char line[1024];
            if (fgets(line, sizeof(line), stdin) == NULL) break;
            
            line[strcspn(line, "\n")] = 0; // Remove newline
            if (strlen(line) == 0) continue;
            
            if (strcmp(line, "/quit") == 0) {
                printf("Exiting...\n");
                adatp_client_disconnect(client);
                break;
            }
            
            if (starts_with("/join ", line)) {
                char* room = line + 6;
                adatp_client_join_room(client, room);
                printf("Joined room: %s\n", room);
                continue;
            }
            
            // Send
            char msg[2048];
            snprintf(msg, sizeof(msg), "[%s] %s", username, line);
            adatp_client_send_text(client, msg);
        }
    }
    
    adatp_client_destroy(client);
    return 0;
}
