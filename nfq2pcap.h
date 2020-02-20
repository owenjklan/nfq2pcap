#ifndef __NFQ_2_PCAP_H__
#define __NFQ_2_PCAP_H__

#include <stdint.h>
#include <linux/netfilter.h>  // For NF_ACCEPT
#include <pcap/pcap.h>


#define DEFAULT_QUEUE_ID    0

#define PACKET_BUFF_MAX 65535

#define DEFAULT_VERDICT     NF_ACCEPT

// Helper macro to display error messages in bold red text
#define error_msg(fmt, args...) \
    fprintf(stderr, "\033[1;31m"); \
    fprintf(stderr, fmt, ##args); \
    fprintf(stderr, "\033[0m");

// Arguments passed into the callback as user-supplied args
typedef struct _callback_args {
	pcap_dumper_t 	*dumper;
	uint32_t		verdict;
	uint32_t		queue_num;		// Only relevant if verdict == NF_QUEUE
} callback_args;

#endif  /* __NFQ_2_PCAP_H__ */