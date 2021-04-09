//
// Created by akarner on 4/5/21.
//

#include <stdio.h>
#include <stdlib.h>
#include "ping/pingservice.h"

void *workerRoutine(void *args) {
    ping_queue_t *queue = (ping_queue_t *) args;
    fprintf(stdout, "Ping worker started successfully\n");
    fprintf(stdout, "Ping worker queue address: %p\n", queue);

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    ping_task_t *task = NULL;
    while (1) {
        fprintf(stdout, "PingWorker waits for new task\n");
        if (EXIT_FAILURE == popPingTask(queue, &task)) {
            fprintf(stdout, "PingWorker failed to pop task, wait and hope for the next one\n");
        } else {
            fprintf(stdout, "PingWorker finished task successfully\n");
            char *stringify_task = stringifyPingTask(task);
            fprintf(stdout, "%s\n", stringify_task);
            free(stringify_task);
            destroyPingTask(task);
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
        free(prepared_service);
        return EXIT_FAILURE;
    }

    prepared_service->thread_started = 0;
    *ping_service = prepared_service;
    return EXIT_SUCCESS;
}

int startPingService(ping_service_t *ping_service) {
    if (0 != pthread_create(&ping_service->worker_thread, NULL, &workerRoutine, (void *) ping_service->ping_queue)) {
        fprintf(stderr, "Failed to initialize ping service, worker thread creation failed\n");
        free(ping_service);
        return EXIT_FAILURE;
    }
    ping_service->thread_started = 1;

    return EXIT_SUCCESS;
}

void destroyPingService(ping_service_t *service) {
    if (1 == service->thread_started) {
        pthread_cancel(service->worker_thread);
        pthread_join(service->worker_thread, NULL);
    }
    destroyPingQueue(service->ping_queue);
    free(service);
}