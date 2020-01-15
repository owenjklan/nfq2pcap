// Simple Proof-of-Concept to read packets from an NFQUEUE, write them to
// a pcap file.
// 
// The following online resources were used in developing this program:
// https://www.apriorit.com/dev-blog/598-linux-mitm-nfqueue
// https://netfilter.org/projects/libnetfilter_queue/doxygen/group__Queue.html


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
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
    fprintf(stderr, "  \033[1moutput\033[0m is the name of the output Pcap file\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -q queue       NFQUEUE ID to read packets from. Default: %d\n", DEFAULT_QUEUE_ID);
}

int queue_callback(struct nfq_q_handle *nfq_h,
                   struct nfgenmsg *nfmsg,
                   struct nfq_data *nfad,
                   void *data)
{
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
    pcap_dumper_t *pcap_writer = (pcap_dumper_t *)data;
    // struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);

    unsigned char *raw_data = NULL;

    int packet_len = nfq_get_payload(nfad, &raw_data);

    struct pcap_pkthdr header;
    struct timeval ts;
    gettimeofday(&ts, NULL);

    header.ts = ts;
    header.caplen = header.len = packet_len;

    pcap_dump((u_char *)pcap_writer, &header, raw_data);
    pcap_dump_flush(pcap_writer);

    return nfq_set_verdict(nfq_h, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
};

struct nfq_q_handle *open_queue_or_exit(struct nfq_handle *nfq_lib_ctx,
                                        uint16_t queue_num,
                                        pcap_dumper_t *dumper)
{
    // Create our queue handle
    struct nfq_q_handle *nfq_h = nfq_create_queue(nfq_lib_ctx,
                                                  queue_num,
                                                  queue_callback,
                                                  (void *)dumper);
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
    pcap_t *pcap_h = pcap_open_dead(DLT_EN10MB, 65536);
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

    int queue_num = DEFAULT_QUEUE_ID;

    struct nfq_q_handle *queue = open_queue_or_exit(nfq_lib_ctx, queue_num, pcap_writer);

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