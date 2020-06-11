#include <string.h>
#include <stdint.h>

#include "nfq2pcap.h"

char *describe_nfqueue_verdict(uint32_t verdict)
{
    switch (verdict) {
        case NF_DROP:
            return strdup("NF_DROP");
        case NF_ACCEPT:
            return strdup("NF_ACCEPT");
        case NF_STOLEN:
            return strdup("NF_STOLEN");
        case NF_QUEUE:
            return strdup("NF_QUEUE");
        case NF_REPEAT:
            return strdup("NF_REPEAT");
        case NF_STOP:
            return strdup("NF_STOP");
        default:
            return strdup("Unknown verdict!");
    }
}

uint32_t verdict_from_str(char *verdict_str)
{
    // Check for NF_ prefix
    char *prefix = NULL;
    char *compare_str = verdict_str;
    if ((prefix = strstr(verdict_str, "NF_")) != NULL)
    {
        compare_str = prefix;
    }

    if (strncmp(compare_str, "DROP", 4) == 0) {
        return NF_DROP;
    }
    if (strncmp(compare_str, "ACCEPT", 6) == 0) {
        return NF_ACCEPT;
    }
    if (strncmp(compare_str, "STOLEN", 6) == 0) {
        return NF_STOLEN;
    }
    if (strncmp(compare_str, "QUEUE", 5) == 0) {
        return NF_QUEUE;
    }
    if (strncmp(compare_str, "REPEAT", 6) == 0) {
        return NF_REPEAT;
    }
    if (strncmp(compare_str, "STOP", 4) == 0) {
        return NF_STOP;
    }
}