//
// Created by akarner on 4/4/21.
//

#include <stdlib.h>
#include "sipline.h"
#include "siplib.h"

int main(int argc, char *argv[]) {
    int ret_code = EXIT_SUCCESS;
    char *nic_name = NULL;
    pcap_t *pcap_handle = NULL;
    osip_t *osip_parser = NULL;
    pthread_t *notify_thread = NULL;

    ret_code = parseInterfaceFromParams(argc, argv, &nic_name);
    if (EXIT_FAILURE == ret_code) {
        fprintf(stdout, "Usage: ./sipline <nic_name>\n");
        goto cleanup;
    }
    fprintf(stdout, "Start analysing SIP traffic on interface: %s\n", nic_name);

    ret_code = initializeSipline(nic_name);
    if (EXIT_FAILURE == ret_code) {
        fprintf(stderr, "Faied to initialize sipline process, shutdown started\n");
        goto cleanup;
    }

    cleanup:
    destroySipline();
    return ret_code;
}