#ifndef __NFQ_2_PCAP_H__
#define __NFQ_2_PCAP_H__

#include <stdint.h>
#include <linux/netfilter.h>  // For NF_ACCEPT

#include "pcap-writer.h"

#define DEFAULT_OUT_FILENAME "output.pcap"

#define DEFAULT_QUEUE_ID    0

#define DEFAULT_TARGET_ID   1

#define PACKET_BUFF_MAX 65535

#define DEFAULT_SNAPLEN 65535

#define DEFAULT_VERDICT     NF_ACCEPT

#define DEFAULT_DLT_RAWIPV4 DLT_IPV4

// Helper macro to display error messages in bold red text
#define error_msg(fmt, args...) \
    fprintf(stderr, "\033[1;31m"); \
    fprintf(stderr, fmt, ##args); \
    fprintf(stderr, "\033[0m");

// Arguments passed into the callback as user-supplied args
typedef struct _callback_args {
    PcapWriter      *writer;
    uint32_t        verdict;
    uint32_t        queue_num;
    uint32_t        target_queue;   // Only relevant if verdict == NF_QUEUE
    char *          output_filename;
    uint32_t        dlt;            // Here so we can send to parse_args()
} callback_args;

static inline char *verdict_to_str(uint32_t verdict)
{
    switch (verdict) {
        case NF_DROP:
            return "NF_DROP";
        case NF_ACCEPT:
            return "NF_ACCEPT";
        // TODO: Add appropriate code to free/dispose of packets when done
        // case NF_STOLEN:
        //     return "NF_STOLEN";
        case NF_QUEUE:
            return "NF_QUEUE";
    }
    return "Unknown or Unsupported";
};

extern char *describe_nfqueue_verdict(uint32_t verdict);
extern uint32_t verdict_from_str(char *verdict_str);

#endif  /* __NFQ_2_PCAP_H__ */