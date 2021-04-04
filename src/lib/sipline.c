//
// Created by akarner on 4/4/21.
//

#include "sipline.h"
#include <stdlib.h>
#include <string.h>

int initializeSipline(sipline_t **parent_sipline, char *interface) {
    int ret_code = EXIT_SUCCESS;
    sipline_t *sipline = (sipline_t *) malloc(sizeof(sipline_t));
    sipline->nic_name = interface;
    fprintf(stdout, "Start initializing new sipline instance for nic: %s\n", sipline->nic_name);

    ret_code = registerOsip(&sipline->osip_parser);
    if (EXIT_FAILURE == ret_code) {
        fprintf(stderr, "Failed to register osip watch properly");
        free(sipline);
        sipline = NULL;
        return EXIT_FAILURE;
    }

    ret_code = setupLivePcapParsing(&sipline->pcap_handle, sipline->nic_name);
//    ret_code = setupFilePcapParsing(&sipline->pcap_handle, "/run/media/akarner/5125-83A9/goForIt.pcapng");
    if (EXIT_FAILURE == ret_code) {
        fprintf(stderr, "Failed to analyze traffic on interface: %s\n", interface);
        osip_release(sipline->osip_parser);
        free(sipline);
        sipline = NULL;
        return EXIT_FAILURE;
    }

//    free((char *) interface);
    *parent_sipline = sipline;
    fprintf(stdout, "Successfully initialized sipline instance for nic: %s\n", (*parent_sipline)->nic_name);
    FLUSH_OUTPUT;
    return ret_code;
}

int destroySipline(sipline_t *sipline) {
    free(sipline->nic_name);
    if (NULL != sipline->pcap_handle) {
        pcap_close(sipline->pcap_handle);
    }
    osip_release(sipline->osip_parser);
//    pthread_join(sipline->notify_thread);
    free(sipline);
}
