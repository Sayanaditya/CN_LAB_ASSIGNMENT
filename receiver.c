#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "frame.h"

/* 16-bit Internet Checksum (RFC 1071) */
uint16_t calc_checksum(uint8_t *data, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < len; i += 2) {
        uint16_t word = (data[i] << 8) + (i < len - 1 ? data[i + 1] : 0);
        sum += word;
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

/* CRC-16 (x^16 + x^15 + x^2 + 1) */
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

int main(void) {
    // server socket creation
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("Socket failed"); return 1; }

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Bind failed"); close(srv); return 1;
    }
    if (listen(srv, 1) < 0) {
        perror("Listen failed"); close(srv); return 1;
    }

    printf("Listening on port %d...\n", PORT);

    // accept the sender 
    struct sockaddr_in caddr;
    socklen_t clen = sizeof(caddr);
    int cli = accept(srv, (struct sockaddr *)&caddr, &clen);
    if (cli < 0) { perror("Accept failed"); close(srv); return 1; }

    char sender_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &caddr.sin_addr, sender_ip, sizeof(sender_ip));
    printf("Sender connected from %s\n\n", sender_ip);

    int total = 0, cs_acc = 0, cs_rej = 0, crc_acc = 0, crc_rej = 0;

    // loop to receive frames
    for (;;) {
        frame_t f;
        int got = 0;
        while (got < (int)sizeof(f)) {
            int n = recv(cli, (char *)&f + got, sizeof(f) - got, 0);
            if (n <= 0) goto done;
            got += n;
        }
        total++;

        // fcs 
        uint16_t stored_cs  = ((uint16_t)f.fcs[0] << 8) | f.fcs[1];
        uint16_t stored_crc = ((uint16_t)f.fcs[2] << 8) | f.fcs[3];

        // zeroing out fcs to recalculate over the data without interference of fcs bits
        memset(f.fcs, 0, FCS_SIZE);

        // fcs recomputation
        uint16_t recv_cs  = calc_checksum((uint8_t *)&f, HEADER_SIZE + PAYLOAD_SIZE);
        uint16_t recv_crc = calc_crc((uint8_t *)&f, HEADER_SIZE + PAYLOAD_SIZE);

        int cs_ok  = (recv_cs == stored_cs);
        int crc_ok = (recv_crc == stored_crc);

        printf("--- Frame %02d ---\n", f.frame_no);
        printf("  Payload : \"%.40s\"\n", (char *)f.payload);
        printf("  Stored  : CS=0x%04X  CRC=0x%04X\n", stored_cs, stored_crc);
        printf("  Computed: CS=0x%04X  CRC=0x%04X\n", recv_cs, recv_crc);
        printf("  Checksum: %s\n", cs_ok  ? "ACCEPTED" : "REJECTED");
        printf("  CRC-16  : %s\n", crc_ok ? "ACCEPTED" : "REJECTED");

        if (cs_ok && !crc_ok)
            printf("  ** Checksum missed error (false accept), CRC caught it!\n");

        printf("\n");

        if (cs_ok)  cs_acc++; else cs_rej++;
        if (crc_ok) crc_acc++; else crc_rej++;
    }

done:
    printf("=== Summary ===\n");
    printf("Total frames : %d\n", total);
    printf("Checksum     : %d accepted, %d rejected\n", cs_acc, cs_rej);
    printf("CRC-16       : %d accepted, %d rejected\n", crc_acc, crc_rej);

    close(cli);
    close(srv);
    return 0;
}
