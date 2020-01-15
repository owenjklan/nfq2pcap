#ifndef __NFQ_2_PCAP_H__
#define __NFQ_2_PCAP_H__

#define DEFAULT_QUEUE_ID    0

#define PACKET_BUFF_MAX 65535

// Helper macro to display error messages in bold red text
#define error_msg(fmt, args...) \
    fprintf(stderr, "\033[1;31m"); \
    fprintf(stderr, fmt, ##args); \
    fprintf(stderr, "\033[0m");

#endif  /* __NFQ_2_PCAP_H__ */