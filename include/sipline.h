//
// Created by akarner on 4/4/21.
//

#ifndef SIPLINE_SIPLINE_H
#define SIPLINE_SIPLINE_H

#include <pcap/pcap.h>
#include <osip2/osip.h>
#include <pthread.h>

#include "siplib.h"
#include "sipnet.h"
#include "sipqueue.h"

/**
 * Init sipline and set global variables listed above
 * @return on success we return EXIT_SUCESS, otherwise EXIT_FAILURE
 */
int initializeSipline(const char *interface_name);

/**
 * Destroy sipline instance
 * @return on success we return EXIT_SUCESS, otherwise EXIT_FAILURE
 */
int destroySipline();

#endif //SIPLINE_SIPLINE_H
