#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "ow-crypt.h"

/**
 * README
 *
 * to get documentation on crypt_* functions, use:
 *
 *     man ./crypt.3
 *     
 */

int c_gen_salt(unsigned char cost, const char *random16, char *result) {
#ifdef DEBAG
    printf("[C] random16: [");

    int i;
    for (i = 0; i < 16; i++) {
        printf("%d", random16[i]);
        if (i != 15) {
            printf(", ");
        }
    }

    printf("]\n");
#endif

    // NOTE: the 3rd param must be "cryptographically random bytes"
    // generate them using Rust's `rand` crate
    const char *setting = crypt_gensalt("$2b$", cost, random16, 16);

    if (!setting) {
        return errno;
    } else {
#ifdef DEBAG
        printf("[C] salt: %s\n", setting);
#endif
        memcpy(result, setting, strlen(setting) + 1);

        return 0;
    }
}

int c_hash(const char *key, const char *salt, char *result) {
    const char *outcome = crypt_rn(key, salt, result, 61);
    if (!outcome) {
        return errno;
    }

    memcpy(result, outcome, strlen(outcome) + 1);

    return 0;
}

