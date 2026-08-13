#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "frame.h"
#include "error.h"

#define NUM_FRAMES 11

/* MAC addresses (arbitrary, for demonstration) */
static const uint8_t SMAC[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
static const uint8_t DMAC[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

/*
 * Error plan for 11 frames:
 *   0  : clean            -> both ACCEPT
 *   1  : single-bit       -> both REJECT
 *   2  : two isolated     -> both REJECT
 *   3  : odd (3 bits)     -> both REJECT
 *   4  : burst (8 bits)   -> both REJECT
 *   5  : clean            -> both ACCEPT
 *   6  : word-swap        -> checksum ACCEPT (false +), CRC REJECT
 *   7  : single-bit       -> both REJECT
 *   8  : burst            -> both REJECT
 *   9  : clean            -> both ACCEPT
 *  10  : CRC false        -> CRC ACCEPT (false +), checksum REJECT
 */
static const int error_plan[NUM_FRAMES] = {
    ERR_NONE, ERR_SINGLE, ERR_TWO_ISOL, ERR_ODD, ERR_BURST,
    ERR_NONE, ERR_CS_FALSE, ERR_SINGLE, ERR_BURST, ERR_NONE, ERR_CRC_FALSE
};

int main(int argc, char *argv[]) {
    srand(time(NULL));

    if (argc < 3) {
        printf("Usage: %s <receiver_ip> <input_file>\n", argv[0]);
        return 1;
    }
    const char *ip       = argv[1];
    const char *filename = argv[2];

    /* ---- Read input lines ---- */

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        printf("Couldn't open %s\n", filename);
        return 1;
    }

    char lines[NUM_FRAMES][256];
    int n = 0;
    while (n < NUM_FRAMES && fgets(lines[n], sizeof(lines[0]), fp))
        n++;
    fclose(fp);

    if (n < NUM_FRAMES) {
        printf("Need %d lines, got %d\n", NUM_FRAMES, n);
        return 1;
    }

    /* ---- Create TCP socket and connect ---- */

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket failed");
        return 1;
    }

    struct sockaddr_in srv;
    srv.sin_family = AF_INET;
    srv.sin_port   = htons(PORT);
    if (inet_pton(AF_INET, ip, &srv.sin_addr) <= 0) {
        perror("Invalid IP");
        close(sock);
        return 1;
    }

    printf("Connecting to %s:%d...\n", ip, PORT);
    if (connect(sock, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        perror("Connection failed");
        close(sock);
        return 1;
    }
    printf("Connected! Sending %d frames.\n\n", NUM_FRAMES);

    /* ---- Build and send each frame ---- */

    for (int i = 0; i < NUM_FRAMES; i++) {
        frame_t f;
        memset(&f, 0, sizeof(f));

        /* header */
        memcpy(f.dest_mac, DMAC, MAC_LEN);
        memcpy(f.src_mac, SMAC, MAC_LEN);
        f.frame_no = (uint16_t)i;

        /* payload — strip newline/carriage-return */
        char *nl = strchr(lines[i], '\n');
        if (nl) *nl = '\0';
        nl = strchr(lines[i], '\r');
        if (nl) *nl = '\0';
        size_t plen = strlen(lines[i]);
        if (plen > PAYLOAD_SIZE) plen = PAYLOAD_SIZE;
        memcpy(f.payload, lines[i], plen);
        f.payload_len = (uint16_t)plen;

        /* compute checksum and CRC over header + payload */
        uint16_t csum = calc_checksum((uint8_t *)&f, HEADER_SIZE + PAYLOAD_SIZE);
        uint16_t crc  = calc_crc((uint8_t *)&f, HEADER_SIZE + PAYLOAD_SIZE);

        /* store in FCS field (big-endian) */
        f.fcs[0] = (csum >> 8) & 0xFF;
        f.fcs[1] = csum & 0xFF;
        f.fcs[2] = (crc >> 8) & 0xFF;
        f.fcs[3] = crc & 0xFF;

        /* inject planned error (switch to inject_random_error for randomised tests) */
        int etype = error_plan[i];
        inject_error(&f, etype);
        /* inject_random_error(&f, etype); */

        printf("Frame %02d | %-22s | CS=0x%04X CRC=0x%04X | \"%.30s\"\n",
               i, err_name(etype), csum, crc, lines[i]);

        send(sock, &f, sizeof(f), 0);
        usleep(200000);
    }

    close(sock);
    printf("\nDone. All %d frames sent.\n", NUM_FRAMES);
    return 0;
}
