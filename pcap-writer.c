#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "pcap-writer.h"

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

    // We made it!
    return new_writer;
}

void pcap_writer_close(PcapWriter *writer) {
    if (writer == NULL || writer->file == NULL) { return; }
    fclose(writer->file);
    writer->file = NULL;
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