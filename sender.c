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


#define NUM_FRAMES 11

/* error types */
#define ERR_NONE       0
#define ERR_SINGLE     1
#define ERR_TWO_ISOL   2
#define ERR_ODD        3
#define ERR_BURST      4
#define ERR_CS_FALSE   5
#define ERR_CRC_FALSE  6

static const uint8_t SMAC[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
static const uint8_t DMAC[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

/*
 * Error plan for 10 frames:
 *   0: clean           -> both ACCEPT
 *   1: single-bit      -> both REJECT
 *   2: two isolated    -> both REJECT
 *   3: odd (3 bits)    -> both REJECT
 *   4: burst (8 bits)  -> both REJECT
 *   5: clean           -> both ACCEPT
 *   6: word-swap       -> checksum ACCEPT (false +), CRC REJECT
 *   7: single-bit      -> both REJECT
 *   8: burst           -> both REJECT
 *   9: clean           -> both ACCEPT
 *   10: CRC false      -> CRC ACCEPT (false), checksum REJECT
 */

static const int error_plan[NUM_FRAMES] = {
    ERR_NONE, ERR_SINGLE, ERR_TWO_ISOL, ERR_ODD, ERR_BURST,
    ERR_NONE, ERR_CS_FALSE, ERR_SINGLE, ERR_BURST, ERR_NONE, ERR_CRC_FALSE
};

// 16-bit Internet Checksum (RFC 1071)
uint16_t calc_checksum(uint8_t *data, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < len; i += 2) {
        uint16_t word = (data[i] << 8) + (i < len - 1 ? data[i + 1] : 0);
        sum += word;
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

// CRC-16 (x^16 + x^15 + x^2 + 1)
uint16_t calc_crc(uint8_t *data, int len) {
    uint16_t crc = 0;
    for (int p = 0; p < len; p++) {
        crc ^= (uint16_t)data[p] << 8;
        for (int i = 0; i < 8; i++) {
            crc = (crc & 0x8000) ? (crc << 1) ^ 0x8005 : (crc << 1);
        }
    }
    return crc;
}

void inject_error(frame_t *f, int type) {
    uint8_t tmp;
    switch (type) {
        case ERR_SINGLE:
        f->payload[5] ^= (1 << 3);
        break;
        case ERR_TWO_ISOL:
        f->payload[3]  ^= (1 << 2);
        f->payload[25] ^= (1 << 6);
        break;
    case ERR_ODD:
        f->payload[1]  ^= (1 << 0);
        f->payload[15] ^= (1 << 4);
        f->payload[35] ^= (1 << 7);
        break;
        case ERR_BURST:
        f->payload[10] = (uint8_t)~f->payload[10];
        break;
        case ERR_CS_FALSE: // swap
        tmp = f->payload[0]; f->payload[0] = f->payload[2]; f->payload[2] = tmp;
        tmp = f->payload[1]; f->payload[1] = f->payload[3]; f->payload[3] = tmp;
        break;
        case ERR_CRC_FALSE:
        // Inject G(x) = x^16 + x^15 + x^2 + 1 (17 bits: 0xC0, 0x02, 0x80 across 3 bytes)
        // CRC remainder will remain 0 (ACCEPT), but 16-bit Checksum will fail (REJECT).
        f->payload[10] ^= 0xC0;
        f->payload[11] ^= 0x02;
        f->payload[12] ^= 0x80;
        break;
    }
}

void inject_random_error(frame_t *f, int type) {
    uint8_t tmp;
    int x, y;
    switch(type) {
        case ERR_SINGLE:
            f->payload[(rand() % 44)] ^= (rand() % 256);
            break;
        case ERR_TWO_ISOL:
            x = (rand() % 44);
            y = (rand() % 44);
            if(x == y) y = (x + 10) % 44;
            f->payload[x] ^= (rand() % 256);
            break;
            case ERR_ODD:
            // hardcoded because if random used then it might become other type of errors
            f->payload[1]  ^= (1 << 0);
            f->payload[15] ^= (1 << 4);
            f->payload[35] ^= (1 << 7);
            break;
        case ERR_BURST:
            int idx = (rand() % 44), len = (rand() % 44) + 1;
            len = (len <= 44 - idx ? len : 44 - idx); // in bound
            for(int i = 0; i < len; i++) {
                f->payload[i + idx] ^= (rand() % 256);
            }
            break;
            case ERR_CS_FALSE: // random 2 swaps
            // int x, y;
            {
                x = (rand() % 44), y = (rand() % 44);
                if(x == y) y = (x + 10) % 44;
                tmp = f->payload[x]; f->payload[y] = f->payload[y]; f->payload[y] = tmp;
            }
            {
                x = (rand() % 44), y = (rand() % 44);
                if(x == y) y = (x + 10) % 44;
                tmp = f->payload[x]; f->payload[y] = f->payload[y]; f->payload[y] = tmp;
            }
        }
}

const char *err_name(int t) {
    switch (t) {
        case ERR_NONE:     return "NONE (clean)";
        case ERR_SINGLE:   return "SINGLE-BIT";
        case ERR_TWO_ISOL: return "TWO ISOLATED";
        case ERR_ODD:      return "ODD (3 bits)";
        case ERR_BURST:    return "BURST (8 bits)";
        case ERR_CS_FALSE: return "WORD-SWAP (CS blind)";
        case ERR_CRC_FALSE: return "CRC FALSE";
        default:           return "UNKNOWN";
    }
}

int main(int argc, char *argv[]) {
    srand(time(NULL));
    if (argc < 3) {
        printf("Usage: %s <receiver_ip> <input_file>\n", argv[0]);
        return 1;
    }
    const char *ip = argv[1];
    const char *filename = argv[2];

    // reading 10 lines from the input
    FILE *fp = fopen(filename, "r");
    if (!fp) { printf("Couldn't open %s\n", filename); return 1; }

    char lines[NUM_FRAMES][256];
    int n = 0;
    while (n < NUM_FRAMES && fgets(lines[n], sizeof(lines[0]), fp))
        n++;
    fclose(fp);

    if (n < NUM_FRAMES) {
        printf("Need %d lines, got %d\n", NUM_FRAMES, n);
        return 1;
    }

    // socket creation
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("Socket failed"); return 1; }

    struct sockaddr_in srv;
    srv.sin_family = AF_INET;
    srv.sin_port = htons(PORT);
    if (inet_pton(AF_INET, ip, &srv.sin_addr) <= 0) {
        perror("Invalid IP"); close(sock); return 1;
    }

    printf("Connecting to %s:%d...\n", ip, PORT);
    if (connect(sock, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        perror("Connection failed"); close(sock); return 1;
    }
    printf("Connected! Sending %d frames.\n\n", NUM_FRAMES);

    // sending frames
    for (int i = 0; i < NUM_FRAMES; i++) {
        frame_t f;
        memset(&f, 0, sizeof(f));

        // header
        memcpy(f.dest_mac, DMAC, MAC_LEN);
        memcpy(f.src_mac, SMAC, MAC_LEN);
        f.frame_no = (uint16_t)i;

        // payload
        char *nl = strchr(lines[i], '\n');
        if (nl) *nl = '\0';
        nl = strchr(lines[i], '\r');
        if (nl) *nl = '\0';
        size_t plen = strlen(lines[i]);
        if (plen > PAYLOAD_SIZE) plen = PAYLOAD_SIZE;
        memcpy(f.payload, lines[i], plen);
        f.payload_len = (uint16_t)plen;

        // crc and checksum
        uint16_t csum = calc_checksum((uint8_t *)&f, HEADER_SIZE + PAYLOAD_SIZE);
        uint16_t crc  = calc_crc((uint8_t *)&f, HEADER_SIZE + PAYLOAD_SIZE);

        // fcs
        f.fcs[0] = (csum >> 8) & 0xFF;
        f.fcs[1] = csum & 0xFF;
        f.fcs[2] = (crc >> 8) & 0xFF;
        f.fcs[3] = crc & 0xFF;

        // error injection
        int etype = error_plan[i];
        inject_error(&f, etype);
        // inject_random_error(&f, etype);

        printf("Frame %02d | %-22s | CS=0x%04X CRC=0x%04X | \"%.30s\"\n", i, err_name(etype), csum, crc, lines[i]);

        send(sock, &f, sizeof(f), 0);
        usleep(200000);
    }

    close(sock);
    printf("\nDone. All %d frames sent.\n", NUM_FRAMES);
    return 0;
}
