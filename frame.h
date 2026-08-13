#ifndef FRAME_H
#define FRAME_H
 
#include <stdint.h>
 
#define MAC_LEN         6
#define PAYLOAD_SIZE    44
#define HEADER_SIZE     (MAC_LEN + MAC_LEN + 2 + 2) // 16 bytes header
#define FCS_SIZE        4
#define FRAME_SIZE      (HEADER_SIZE + PAYLOAD_SIZE + FCS_SIZE) // total 64 bytes 

#define PORT            5050
 
#pragma pack(push, 1)
typedef struct {
    uint8_t  dest_mac[MAC_LEN];
    uint8_t  src_mac[MAC_LEN];
    uint16_t payload_len;   // actual data length before padding, host order in memory,//
    uint16_t frame_no;
    uint8_t  payload[PAYLOAD_SIZE];
    uint8_t  fcs[FCS_SIZE]; // checksum result stored here
} frame_t;
#pragma pack(pop)

#endif