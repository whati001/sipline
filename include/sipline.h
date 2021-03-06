//
// Created by akarner on 4/4/21.
//

#ifndef SIPLINE_SIPLINE_H
#define SIPLINE_SIPLINE_H

#include <pcap/pcap.h>
#include <pthread.h>

#include "siplib.h"

// BPF filter expression for SIP messages -> port may vary
#define BPF_SIP_FILTER "(port 6050) and (udp)"

#define USE_CURL 1

// Backend Server connection info
#define TARGET_URL "http://localhost:2711/ringBell"

typedef struct {
    char *nic_name;
    pcap_t *pcap_handle;
} sipline_t;

/**
 * Init sipline and set global variables listed above
 * @param sipline
 * @param interface_name
 * @return on success we return EXIT_SUCESS, otherwise EXIT_FAILURE
 */
int initializeSipline(sipline_t **sipline, char *interface_name);

/**
 * Start sipline passed in argument
 * @param sipline
 */
int startSipline(sipline_t *sipline);

/**
 * Destroy sipline instance
 * @param sipline
 * @return on success we return EXIT_SUCESS, otherwise EXIT_FAILURE
 */
void destroySipline(sipline_t *sipline);

#endif //SIPLINE_SIPLINE_H
