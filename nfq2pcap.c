// Simple Proof-of-Concept to read packets from an NFQUEUE, write them to
// a pcap file.
// 
// The following online resources were used in developing this program:
// https://www.apriorit.com/dev-blog/598-linux-mitm-nfqueue
// https://netfilter.org/projects/libnetfilter_queue/doxygen/group__Queue.html
// https://www.tcpdump.org/linktypes.html

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>         // wanted for getopt() and others
#include <time.h>
#include <sys/time.h>
#include <sys/select.h>
#include <arpa/inet.h>        // For ntohl

#include <linux/netfilter.h>  // For NF_ACCEPT
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <pcap/pcap.h>

#include "nfq2pcap.h"

void usage(char *progname) {
    fprintf(stderr, "USAGE:\n");
    fprintf(stderr, "  %s output [-q queue]\n\n", progname);
    fprintf(stderr, "Where:\n");
    fprintf(stderr,
        "  \033[1moutput\033[0m is the name of the output Pcap file\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr,
        "  -q queue       NFQUEUE ID to read packets from. Default: %d\n",
        DEFAULT_QUEUE_ID);
}

// Prepend a custom constructed link layer header to the payload data that
// was pulled from the netlink/nfqueue stuctures for the packet.
// If there is an issue allocating memory we just exit.
// Returns a re-malloc'ed structure that needs to be free'd by the caller.
unsigned char *prepend_link_header(unsigned char *ll_hdr,
                          int ll_len,
                          unsigned char *payload,
                          int payload_len)
{
    int total_len = ll_len + payload_len;

    unsigned char *return_buffer = malloc(total_len);

    if (!return_buffer) {
        error_msg("Failed allocating buffer space for link layer manipulation!\n");
        exit(1);
    }

    memcpy(return_buffer, ll_hdr, ll_len);
    memcpy(return_buffer + ll_len, payload, payload_len);

    return return_buffer;
}

// This function does all the work to write a packet to the pcap file
int queue_callback(struct nfq_q_handle *nfq_h,
                   struct nfgenmsg *nfmsg,
                   struct nfq_data *nfad,
                   void *data)
{
    uint32_t null_header = 2;  // 2 -> IPv4 packets
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
    pcap_dumper_t *pcap_writer = ((callback_args *)data)->dumper;
    uint32_t verdict = ((callback_args *)data)->verdict;

    unsigned char *raw_data = NULL;

    int packet_len = nfq_get_payload(nfad, &raw_data);

    // 'Final', as in, we've pre-pended the fake link layer header
    unsigned char *final_payload = prepend_link_header((unsigned char *)&null_header,
                                              sizeof(null_header),
                                              raw_data,
                                              packet_len);
    int final_len = sizeof(null_header) + packet_len;

    struct pcap_pkthdr header;
    struct timeval ts;
    gettimeofday(&ts, NULL);

    header.ts = ts;
    header.caplen = header.len = final_len;

    pcap_dump((u_char *)pcap_writer, &header, final_payload);
    free(final_payload);
    pcap_dump_flush(pcap_writer);

    if (verdict == NF_QUEUE) {
        // The queue to direct to is in upper 16-bits of the verdict we set
        verdict = NF_QUEUE_NR(((callback_args *)data)->queue_num);
    }

    return nfq_set_verdict(nfq_h, ntohl(ph->packet_id), verdict, 0, NULL);
};

struct nfq_q_handle *open_queue_or_exit(struct nfq_handle *nfq_lib_ctx,
                                        uint16_t queue_num,
                                        callback_args *cb_args)
{
    // Create our queue handle
    struct nfq_q_handle *nfq_h = nfq_create_queue(nfq_lib_ctx,
                                                  queue_num,
                                                  queue_callback,
                                                  (void *)cb_args);
    if (!nfq_h) {
        error_msg("Failed opening queue %d! %s\n",
                  queue_num, strerror(errno));
        nfq_close(nfq_lib_ctx);
        exit(1);
    }

    return nfq_h;
}

int main(int argc, char *argv[])
{
    char pcap_errbuff[PCAP_ERRBUF_SIZE];

    if (argc < 2) {
        usage(argv[0]);
        exit(1);
    }
    char *output_filename = argv[1];

    // Open Pcap file and handles for writing packets out using pcap_dump()
    // We're going to use DLT_NULL, as we won't have Ethernet frame headers
    // coming off an NFQUEUE
    pcap_t *pcap_h = pcap_open_dead(DLT_NULL, 65536);
    if (!pcap_h) {
        error_msg("Failed opening '%s' as pcap output file! %s.\n",
            output_filename, pcap_errbuff);
        exit(1);
    }

    pcap_dumper_t *pcap_writer = pcap_dump_open(pcap_h, output_filename);
    if (!pcap_writer) {
        error_msg("Failed creating dumper handle for pcap! %s.\n",
            pcap_geterr(pcap_h));
        pcap_close(pcap_h);
        exit(1);
    }

    // Initialise a handle for the netfilter_queue library
    struct nfq_handle *nfq_lib_ctx = nfq_open();
    if (!nfq_lib_ctx) {
        error_msg("Failed opening library handle! %s", strerror(errno));
        exit(1);
    }

    uint32_t queue_num = DEFAULT_QUEUE_ID;

    callback_args cb_args;

    cb_args.dumper = pcap_writer;
    cb_args.queue_num = queue_num;
    cb_args.verdict = NF_ACCEPT;

    struct nfq_q_handle *queue = open_queue_or_exit(nfq_lib_ctx, queue_num, &cb_args);

    // We want to copy the entirety of the packet.
    if (nfq_set_mode(queue, NFQNL_COPY_PACKET, 65535) < 0) {
        error_msg("Failed setting copy mode! %s", strerror(errno));
        nfq_destroy_queue(queue);
        nfq_close(nfq_lib_ctx);
        exit(1);
    }

    // Get the file descriptor of the underlying netlink socket so we
    int nl_fd = nfq_fd(nfq_lib_ctx);
    char packet_buff[PACKET_BUFF_MAX];

    while (1) {
        int read_len = read(nl_fd, packet_buff, PACKET_BUFF_MAX);
        if (read_len < 0) {
            error_msg("Issue reading packet! %s", strerror(errno));
            continue;
        }

        // Actually handle the packet
        nfq_handle_packet(nfq_lib_ctx, packet_buff, read_len);
    }

    return 0;
}
