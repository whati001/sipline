//
// Created by akarner on 4/4/21.
//

#ifndef SIPLINE_SIPLINE_H
#define SIPLINE_SIPLINE_H

#include <pcap/pcap.h>
#include <osip2/osip.h>
#include <pthread.h>

#include "ping/pingservice.h"
#include "siplib.h"

typedef struct {
    char *nic_name;
    pcap_t *pcap_handle;
    osip_t *osip_parser;
    ping_service_t *ping_service;
} sipline_t;

/**
 * Init sipline and set global variables listed above
 * @param sipline
 * @param interface_name
 * @return on success we return EXIT_SUCESS, otherwise EXIT_FAILURE
 */
int initializeSipline(sipline_t **sipline, char *interface_name);

/**
 * Destroy sipline instance
 * @param sipline
 * @return on success we return EXIT_SUCESS, otherwise EXIT_FAILURE
 */
void destroySipline(sipline_t *sipline);

#endif //SIPLINE_SIPLINE_H
