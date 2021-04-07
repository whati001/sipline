//
// Created by akarner on 4/4/21.
//

#include <stdlib.h>
#include <string.h>

#include "sipline.h"
#include "siplib.h"

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
        return ret_code;
    }

    // ret_code = setupFilePcapParsing(&sipline->pcap_handle, "/run/media/akarner/5125-83A9/goForIt.pcapng");
    ret_code = setupLivePcapParsing(&sipline->pcap_handle, sipline->nic_name);
    if (EXIT_FAILURE == ret_code) {
        fprintf(stderr, "Failed to setup pcap for interface: %s\n", interface);
        osip_release(sipline->osip_parser);
        free(sipline);
        sipline = NULL;
        return ret_code;
    }

    // TODO: setup ping_service_t
    ret_code = initPingService(&sipline->ping_service);
    if (EXIT_FAILURE == ret_code) {
        fprintf(stderr, "Failed to setup ping service\n");
        osip_release(sipline->osip_parser);
        pcap_close(sipline->pcap_handle);
        free(sipline);
        sipline = NULL;
        return ret_code;
    }

    *parent_sipline = sipline;
    fprintf(stdout, "Successfully initialized sipline instance for nic: %s\n", (*parent_sipline)->nic_name);
    FLUSH_OUTPUT;
    return ret_code;
}

void destroySipline(sipline_t *sipline) {
    if (NULL == sipline) {
        return;
    }

    free(sipline->nic_name);
    if (NULL != sipline->pcap_handle) {
        pcap_close(sipline->pcap_handle);
    }
    osip_release(sipline->osip_parser);
//    pthread_join(sipline->notify_thread);
    free(sipline);
}
