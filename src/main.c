//
// Created by akarner on 4/4/21.
//

#include <stdlib.h>
#include "sipline.h"

int main(int argc, char *argv[]) {
    int ret_code = EXIT_SUCCESS;
    char *parsed_nic_name = NULL;
    sipline_t *sipline = NULL;

    ret_code = parseInterfaceFromParams(argc, argv, &parsed_nic_name);
    if (EXIT_FAILURE == ret_code) {
        fprintf(stdout, "Usage: ./sipline <nic_name>\n");
        goto cleanup;
    }

    ret_code = initializeSipline(&sipline, parsed_nic_name);
    if (EXIT_FAILURE == ret_code) {
        fprintf(stderr, "Failed to initialize sipline process, shutdown started\n");
        goto cleanup;
    }
    fprintf(stdout, "Start analysing SIP traffic on interface: %s\n", sipline->nic_name);

    cleanup:
FLUSH_OUTPUT;
    destroySipline(sipline);
    return ret_code;
}