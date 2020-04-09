// Pcap file format information obtained from (March 2020):
// https://wiki.wireshark.org/Development/LibpcapFileFormat

#ifndef __PCAP_WRITER_H__
#define __PCAP_WRITER_H__

#include <stdio.h>
#include <stdint.h>

#define PCAP_MAGIC_NUMBER  0xa1b2c3d4

// PCAP file version numbers, current as of March 2020
// const uint16_t PCAP_MAJOR_VERSION = 2;
// const uint16_t PCAP_MINOR_VERSION = 4;
#define PCAP_MAJOR_VERSION  2
#define PCAP_MINOR_VERSION  4

typedef struct _pcap_file_header {
    uint32_t    magic_number;
    uint16_t    version_major;
    uint16_t    version_minor;
    int32_t     this_timezone;      // GMT-to-local correction, in seconds
    uint32_t    sigfigs;        // Accuracy of timestamps, usually set to 0
    uint32_t    snaplen;        // Max length of captured packets, in bytes
    uint32_t    network;        // Data Link Type
} PcapFileHeader;

typedef struct _pcap_packet_header {
    uint32_t    ts_sec;         // Timestamp seconds
    uint32_t    ts_usec;        // Timestamp microseconds
    uint32_t    included_len;   // Included number of bytes for packet
    uint32_t    real_len;       // Actual length of packet
} PcapPacketHeader;

typedef struct _pcap_writer {
    FILE *      file;
    uint64_t    bytes_written;
    uint64_t    packets_written;
    uint8_t     header_written;
    char *      filename;
    PcapFileHeader *file_header;
} PcapWriter;

// 
// Function prototypes.
// 
PcapWriter *pcap_writer_new(char *filename,
                            uint32_t snaplen,
                            uint32_t dll_type);
void pcap_writer_free(PcapWriter *writer);
void pcap_writer_close(PcapWriter *writer);
uint32_t pcap_writer_write_packet(PcapWriter *writer,
                                  unsigned char *packet_data,
                                  uint32_t ll_header_len,
                                  uint32_t data_len,
                                  uint32_t real_len);
PcapPacketHeader *pcap_writer_packet_header_new();
void pcap_writer_packet_header_free(PcapPacketHeader *header);

// Data Link Type (DLT_) definitions.
// Obtained from information at: http://www.tcpdump.org/linktypes.html
// (Mar 2020).
// Only a select few have been included here
#define     DLT_NULL                0
#define     DLT_EN10MB              1
#define     DLT_AX25                3
#define     DLT_IEEE802             6
#define     DLT_ARCNET              7
#define     DLT_SLIP                8
#define     DLT_PPP                 9
#define     DLT_FDDI                10
#define     DLT_PPP_SERIAL          50

#define     DLT_IPV4                228     // Packet begins with raw IPV4
#define     DLT_IPV6                229     // Packet begins with raw IPV6

#endif  /* End __PCAP_WRITER_H__ */
