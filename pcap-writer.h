// Pcap file format information obtained from (March 2020):
// https://wiki.wireshark.org/Development/LibpcapFileFormat

#ifndef __PCAP_WRITER_H__
#define __PCAP_WRITER_H__

#include <stdio.h>
#include <stdint.h>

const uint32_t PCAP_MAGIC_NUMBER = 0xa1b2c3d4;

// PCAP file version numbers, current as of March 2020
const uint16_t PCAP_MAJOR_VERSION = 2;
const uint16_t PCAP_MINOR_VERSION = 4;

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
PcapPacketHeader *pcap_writer_packet_header_new();
void pcap_writer_packet_header_free(PcapPacketHeader *header);
#endif  /* End __PCAP_WRITER_H__ */
