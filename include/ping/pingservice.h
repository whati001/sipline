//
// Created by akarner on 4/7/21.
//

#ifndef SIPLINE_PINGSERVICE_H
#define SIPLINE_PINGSERVICE_H

#include "pingqueue.h"
#include "pingworker.h"

#define SERVICE_CAPACITY UINT8_MAX

typedef struct {
    pthread_t worker_thread;
    char thread_started;
    ping_queue_t *ping_queue;
} ping_service_t;

int initPingService(ping_service_t **ping_service);

int startPingService(ping_service_t *ping_service);

void destroyPingService(ping_service_t* ping_service);

#endif //SIPLINE_PINGSERVICE_H
