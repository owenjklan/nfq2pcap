#include <string.h>
#include <stdlib.h>
#include <ctype.h>

// Take a string like NF_ACCEPT and return the matching Netfilter
// Verdict integer value
int verdict_str_to_int(char *verdict_str)
{
    char *lower_dup = NULL;
    char *dup_free_ptr = NULL;
    int return_value = -1;

    if (verdict_str == NULL) {
        return return_value;
    }

    lower_dup = strdup(verdict_str);
    dup_free_ptr = lower_dup;

    for (int i = 0; lower_dup[i]; i++) {
        lower_dup[i] = tolower(lower_dup[i]);
    };

    // Check for possible 'nf_' prefix
    if (strncmp(lower_dup, "nf_", 3) == 0) {
        lower_dup += 3;
    }

    if (strncmp(lower_dup, "accept", strlen("accept")) == 0) {
        return_value = 1;
    } else if (strncmp(lower_dup, "drop", strlen("drop")) == 0) {
        return_value = 0;
    } else if (strncmp(lower_dup, "queue", strlen("queue")) == 0) {
        return_value = 3;
    }

    // Free the duplicate we made to lower-case
    if (dup_free_ptr) {
        free(dup_free_ptr);
    }
    return return_value;
}