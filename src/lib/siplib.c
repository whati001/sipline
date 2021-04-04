//
// Created by akarner on 4/4/21.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "siplib.h"

int parseInterfaceFromParams(int argc, char *argv[], char **interface) {
    free(*interface);
    *interface = NULL;

    if (argc != 2 || NULL == argv[1]) {
        return EXIT_FAILURE;
    }

    size_t params_len = strlen(argv[1]);
    if (MAX_INTERFACE_LEN <= params_len) {
        fprintf(stderr, "Interface length longer than 100 character, are you sure?\n");
        return EXIT_FAILURE;
    }

    char *buf = (char *) calloc(params_len + 1, sizeof(char));
    if (NULL == buf) {
        fprintf(stderr, "Failed to allocated buffer for interface name\n");
        return EXIT_FAILURE;
    }

    memcpy(buf, argv[1], params_len);
    *interface = buf;
    buf = NULL;

    return EXIT_SUCCESS;
}