//
// Created by akarner on 4/4/21.
//

#ifndef SIPLINE_SIPLIB_H
#define SIPLINE_SIPLIB_H

#include "stdint.h"

// enable/disable some more login -> please do not use in production
#define DEBUG 0

// maximal interface length
#define MAX_INTERFACE_LEN 100
// BPF filter expression for SIP messages -> port may vary
#define BPF_SIP_FILTER "(port 6050) and (udp)"
// define API endpoint to send SIP signals to
#define TARGET_URL "http://localhost:2711/ringBell"

// define some stuff to clean up code
#define SIP_INVITE_CODE 0
#define SIP_INVITE_LABEL "INVITE"
#define SIP_CANCEL_CODE 1
#define SIP_CANCEL_LABEL "CANCEL"
#define SIP_ANSWER_CODE 2

typedef struct {
    uint8_t type;
    char *from;
    char *to;
} sipline_call_info;

/**
 * Simple program argument parser, parse network interface name from argument with index 1
 * @param argc program argument count
 * @param argv program argument values
 * @param interface char pointer to parsed interface, on failure set to NULL
 * @return on Success return EXIT_SUCCESS, on Failure EXIT_FAILURE
 */
int parseInterfaceFromParams(int argc, char *argv[], char **interface);


#endif //SIPLINE_SIPLIB_H
