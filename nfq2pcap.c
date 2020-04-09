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

#include "nfq2pcap.h"

void usage(char *progname) {
    fprintf(stderr,
        "USAGE:\n");
    fprintf(stderr,
        "  %s [-h] [-6] [-o filename] [-q queue] [-t target] [-v verdict]\n\n",
        progname);
    fprintf(stderr,
        "Options:\n");
    fprintf(stderr,
        "  -6           Capture as RAW IPv6 packets.\n\n");
    fprintf(stderr,
        "  -h           Display usage information / help.\n\n");
    fprintf(stderr,
        "  -o filename  Name of output pcap file. Default: %s\n\n",
        DEFAULT_OUT_FILENAME);
    fprintf(stderr,
        "  -q queue     NFQUEUE ID to read packets from. Default: %d\n\n",
        DEFAULT_QUEUE_ID);
    fprintf(stderr,
        "  -t target    NFQUEUE ID to write packets to. Default: %d\n"
        "               (Only relevant when a verdict of QUEUE (3) is used.\n",
        DEFAULT_TARGET_ID);
    fprintf(stderr,
        "  -v verdict   Netfilter verdict code to use for packets. Default: %d\n",
        DEFAULT_VERDICT);
    fprintf(stderr,
        "\nValid values for verdict are:\n");
    fprintf(stderr, "  DROP    0\n");
    fprintf(stderr, "  ACCEPT  1\n");
    fprintf(stderr, "  QUEUE   3\n");
    fprintf(stderr, "\n");
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
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
    PcapWriter *pcap_writer = ((callback_args *)data)->writer;
    uint32_t verdict = ((callback_args *)data)->verdict;

    unsigned char *raw_data = NULL;

    int packet_len = nfq_get_payload(nfad, &raw_data);

    pcap_writer_write_packet(pcap_writer, raw_data,
                             0,
                             packet_len, packet_len);

    if (verdict == NF_QUEUE) {
        // The queue to direct to is in upper 16-bits of the verdict we set
        verdict = NF_QUEUE_NR(((callback_args *)data)->target_queue);
    }

    return nfq_set_verdict(nfq_h, ntohl(ph->packet_id), verdict, 0, NULL);
};

struct nfq_q_handle *open_queue_or_exit(struct nfq_handle *nfq_lib_ctx,
                                        uint16_t queue_num,
                                        callback_args *cb_args)
{
#ifdef DEBUG
    fprintf(stderr, "Writing output PCAP file to: %s\n",
        cb_args->output_filename);
    fprintf(stderr, "Using verdict of %s. Listening on queue #%d\n",
        verdict_to_str(cb_args->verdict), cb_args->queue_num);
    if (cb_args->verdict == NF_QUEUE) {
        fprintf(stderr, "Target Queue: %d\n", cb_args->target_queue);
    }
#endif      // DEBUG

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


void parse_args(int argc, char *argv[], callback_args *args)
{
    int c;
    opterr = 0;
    while ((c = getopt(argc, argv, "h6o:q:t:v:")) != EOF) {
        switch (c) {
            case 'h':
                usage(argv[0]);
                exit(0);
            case 'o':
                args->output_filename = optarg;
                break;
            case 't':
                args->target_queue = atoi(optarg);
                break;
            case 'q':
                args->queue_num = atoi(optarg);
                break;
            case 'v':
                args->verdict = atoi(optarg);
                break;
            case '6':
                args->dlt = DLT_IPV6;
#ifdef DEBUG
                fprintf(stderr, "IPv6 Mode\n");
#endif
                break;
            default:
                fprintf(stderr, "Unknown option! %c\n", c);
        }
    }
}


int main(int argc, char *argv[])
{
    callback_args cb_args;

    cb_args.verdict =         DEFAULT_VERDICT;
    cb_args.queue_num =       DEFAULT_QUEUE_ID;
    cb_args.output_filename = DEFAULT_OUT_FILENAME;
    cb_args.target_queue =    DEFAULT_TARGET_ID;
    cb_args.dlt =             DEFAULT_DLT_RAWIPV4;

    parse_args(argc, argv, &cb_args);

    // Open our Pcap writer. Hard-coding (gross), for now (sure...) snaplen
    // and Data link type to be NULL.
    PcapWriter *pcap_writer = pcap_writer_new(cb_args.output_filename,
                                              DEFAULT_SNAPLEN,
                                              cb_args.dlt);
    if (!pcap_writer) {
        error_msg("Failed creating pcap file writer! %s.\n",
            strerror(errno));
        exit(1);
    }
    cb_args.writer = pcap_writer;   // Update the callback args

    // Initialise a handle for the netfilter_queue library
    struct nfq_handle *nfq_lib_ctx = nfq_open();
    if (!nfq_lib_ctx) {
        error_msg("Failed opening library handle! %s", strerror(errno));
        pcap_writer_close(pcap_writer);
        exit(1);
    }

    struct nfq_q_handle *queue = open_queue_or_exit(
        nfq_lib_ctx, cb_args.queue_num, &cb_args);

    // We want to copy the entirety of the packet.
    if (nfq_set_mode(queue, NFQNL_COPY_PACKET, 65535) < 0) {
        error_msg("Failed setting copy mode! %s", strerror(errno));
        nfq_destroy_queue(queue);
        nfq_close(nfq_lib_ctx);
        pcap_writer_close(pcap_writer);
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
