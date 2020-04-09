#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <sys/time.h>

#include "pcap-writer.h"


static inline void get_packet_timestamp(PcapPacketHeader *packet_header)
{
    struct timeval tv;

    // TODO: More robust error handling? Might be overkill for our particular
    //       use-case though??
    if (gettimeofday(&tv, NULL) != 0) { return; }

    packet_header->ts_sec = tv.tv_sec;
    packet_header->ts_usec = tv.tv_usec;
}

static PcapFileHeader *pcap_file_header_new(uint32_t snaplen,
                                            uint32_t dll_type)
{
    PcapFileHeader *file_header = NULL;

    file_header = (PcapFileHeader *)calloc(1, sizeof(PcapFileHeader));
    if (file_header == NULL) {
        return NULL;
    }

    // Setup values
    file_header->magic_number = PCAP_MAGIC_NUMBER;
    file_header->version_major = PCAP_MAJOR_VERSION;
    file_header->version_minor = PCAP_MINOR_VERSION;
    file_header->this_timezone = 0;
    file_header->sigfigs = 0;
    file_header->snaplen = snaplen;
    file_header->network = dll_type;

    return file_header;
}

static void pcap_file_header_free(PcapFileHeader *file_header)
{
    if (file_header == NULL) { return; }
    free(file_header);
}

// Dynamically allocates memory for data structures,
// creates and opens the output file
// Returns NULL on failure, check errno
PcapWriter *pcap_writer_new(char *filename,
                            uint32_t snaplen,
                            uint32_t dll_type)
{
    PcapWriter *new_writer = NULL;

    new_writer = (PcapWriter *)calloc(1, sizeof(PcapWriter));
    if (new_writer == NULL) {
        return NULL;
    }

    // Create file header structure
    PcapFileHeader *file_header = pcap_file_header_new(snaplen, dll_type);
    if (file_header == NULL) {
        free(new_writer);
        return NULL;
    }
    new_writer->file_header = file_header;

    // Duplicate file name string
    new_writer->filename = strdup(filename);
    if (new_writer->filename == NULL) {
        free(file_header);
        free(new_writer);
        return NULL;
    }

    // zero integers
    new_writer->bytes_written = 0;
    new_writer->packets_written = 0;
    new_writer->header_written = false;

    // Open the output file
    FILE *out_file = NULL;
    out_file = fopen(filename, "wb");
    if (out_file == NULL) {
        pcap_file_header_free(file_header);
        free(new_writer->filename);
        free(new_writer);
        return NULL;
    }

    new_writer->file = out_file;

    // We made it!
    return new_writer;
}

static int pcap_writer_write_header(PcapWriter *writer)
{
    if (writer == NULL || writer->file == NULL) { return true; }
    if (writer->header_written == true) { return true; }

    size_t written_bytes = 0;

    written_bytes = fwrite(writer->file_header, 1, sizeof(PcapFileHeader),
                           writer->file);

    if (written_bytes < sizeof(PcapFileHeader)) {
        return false;
    }

    writer->header_written = true;
    fflush(writer->file);
    writer->bytes_written += written_bytes;

    printf("PCAP header written\n");

    return true;
}

// Write's a given block of data as a packet. Creates the appropriate
// header structure.
// NOTE: It is expected that any link-layer-specific header has been pre-pended
// and included in the packet_data and
// Return's boolean indicating success or failure
uint32_t pcap_writer_write_packet(PcapWriter *writer,
                                  unsigned char *packet_data,
                                  uint32_t ll_header_len, uint32_t data_len,
                                  uint32_t real_len)
{
    if (writer == NULL || packet_data == NULL) { return false; }
    if (writer->file == NULL) { return false; }

    // Make sure header has been written
    if (writer->header_written == false) {
        pcap_writer_write_header(writer);
    }

    // Allocate PcapPacketHeader structure on Heap
    PcapPacketHeader *packet_header = NULL;
    packet_header = pcap_writer_packet_header_new();
    if (packet_header == NULL) { return false; }

    // Note: It appears we need to include the length of the link-layer header
    //       as such, we use the passed in data_len as the included length
    packet_header->included_len = data_len;
    packet_header->real_len = real_len;

    // Write the pcap packet header
    int bytes_written = fwrite(packet_header,
                               1, sizeof(PcapPacketHeader),
                               writer->file);

    // Write packet-data, including Link-layer header
    bytes_written = fwrite(packet_data,
                           1, data_len,
                           writer->file);

    fflush(writer->file);
    writer->bytes_written += sizeof(PcapPacketHeader);
    writer->bytes_written += data_len;
    writer->packets_written++;

    pcap_writer_packet_header_free(packet_header);

    return true;
}

// Return allocated packet header structure with timestamps filled in
// Return's NULL on failure
PcapPacketHeader *pcap_writer_packet_header_new()
{
    PcapPacketHeader *new_header = NULL;

    new_header = (PcapPacketHeader *)calloc(1, sizeof(PcapPacketHeader));
    if (new_header == NULL) { return NULL; }
    get_packet_timestamp(new_header);
    return new_header;
}

void pcap_writer_close(PcapWriter *writer)
{
    if (writer == NULL || writer->file == NULL) { return; }
    fclose(writer->file);
    writer->file = NULL;
}

void pcap_writer_packet_header_free(PcapPacketHeader *header)
{
    if (header == NULL) { return; }
    free(header);
}

void pcap_writer_free(PcapWriter *writer)
{
    if (writer == NULL) { return; }
    if (writer->file_header != NULL) {
        pcap_file_header_free(writer->file_header);
    }
    if (writer->filename != NULL) {
        free(writer->filename);
    }

    //  Close the underlying file, in case it hasn't been done already
    if (writer->file != NULL) { pcap_writer_close(writer); }
    free(writer);
}
