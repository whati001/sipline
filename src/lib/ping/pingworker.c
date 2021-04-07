//
// Created by akarner on 4/5/21.
//

#include <stdio.h>
#include <stdlib.h>
#include "ping/pingservice.h"

void *workerRoutine(void *args) {
    ping_service_t *service = (ping_service_t *) args;
    fprintf(stdout, "Ping worker started successfully\n");
    fprintf(stdout, "Ping worker queue address: %p\n", service->ping_queue);

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    ping_task_t *task = NULL;
    while (1) {
        fprintf(stdout, "PingWorker waits for new task\n");
        if (EXIT_FAILURE == popPingTask(service->ping_queue, &task)) {
            fprintf(stdout, "PingWorker finished task successfully\n");
        } else {
            fprintf(stdout, "PingWorker failed to pop task\n");
        }
        fflush(stdout);
    }

    fprintf(stdout, "Shutdown ping worker graceful\n");
    return NULL;
}

int initPingService(ping_service_t **ping_service) {
    if (NULL == ping_service) {
        fprintf(stderr, "Failed to initialize ping service, passed NULL pointer\n");
        return EXIT_FAILURE;
    }

    ping_service_t *prepared_service = (ping_service_t *) malloc(sizeof(ping_service_t));
    if (NULL == prepared_service) {
        fprintf(stderr, "Failed to initialize ping service, memory allocation failed\n");
        return EXIT_FAILURE;
    }

    if (EXIT_FAILURE == initPingQueue(&prepared_service->ping_queue, SERVICE_CAPACITY)) {
        fprintf(stderr, "Failed to initialize ping service, queue creation failed\n");
        free(ping_service);
        return EXIT_FAILURE;
    }

    if (0 != pthread_create(&prepared_service->worker_thread, NULL, &workerRoutine, (void *) prepared_service)) {
        fprintf(stderr, "Failed to initialize ping service, worker thread creation failed\n");
        free(ping_service);
        return EXIT_FAILURE;
    }

    *ping_service = prepared_service;
    return EXIT_SUCCESS;
}

