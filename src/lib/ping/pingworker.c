//
// Created by akarner on 4/5/21.
//

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <libnet.h>
#include "ping/pingservice.h"

int doPost(int sock, ping_task_t *task) {
    size_t needed = snprintf(NULL, 0,
                             "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %ld\r\n\r\n%s\r\n\r\n",
                             task->query, task->host, strlen(task->body), task->body);
    char *buffer = (char *) calloc(sizeof(char), needed + 1);
    sprintf(buffer,
            "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %ld\r\n\r\n%s\r\n\r\n",
            task->query, task->host, strlen(task->body), task->body);

    send(sock, buffer, strlen(buffer), 0);
    fprintf(stdout, "POST request send to socket\n");

    fflush(stdout);
    free(buffer);
    return EXIT_SUCCESS;
}

int doGet(int sock, ping_task_t *task) {
    size_t needed = snprintf(NULL, 0,
                             "GET %s HTTP/1.1\r\nHost: %s\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n",
                             task->query, task->host);
    char *buffer = (char *) calloc(sizeof(char), needed + 1);
    sprintf(buffer,
            "GET %s HTTP/1.1\r\nHost: %s\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n",
            task->query, task->host);

    send(sock, buffer, strlen(buffer), 0);
    fprintf(stdout, "GET request send to socket\n");

    fflush(stdout);
    free(buffer);
    return EXIT_SUCCESS;
}


int prepareSocket(int *sock, ping_task_t *task) {
    int prepare_socket;
    struct sockaddr_in serv_addr;
    if ((prepare_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stdout, "Socket creation error \n");
        return EXIT_FAILURE;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(task->port);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, task->host, &serv_addr.sin_addr) <= 0) {
        fprintf(stdout, "Invalid address/ Address not supported \n");
        return EXIT_FAILURE;
    }

    if (connect(prepare_socket, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        fprintf(stdout, "Connection failed\n");
        return EXIT_FAILURE;
    }

    *sock = prepare_socket;
    return EXIT_SUCCESS;
}

int pingBackend(ping_task_t *task) {
    int sock;
    if (EXIT_FAILURE == prepareSocket(&sock, task)) {
        fprintf(stdout, "Failed to open socket, skip ping task\n");
        return EXIT_FAILURE;
    }

    switch (task->method) {
        case POST:
            fprintf(stdout, "Connection established, send POST request\n");
            return doPost(sock, task);
        case GET:
            fprintf(stdout, "Connection established, send GET request\n");
            return doGet(sock, task);
        default:
            return EXIT_FAILURE;
    }
}

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
            char *stringify_task = stringifyPingTask(task);
            fprintf(stdout, "%s\n", stringify_task);

            if (EXIT_FAILURE == pingBackend(task)) {
                fprintf(stdout, "PingWorker failed to ping backend\n");
            } else {
                fprintf(stdout, "PingWorker successfully pinged backend\n");
            }

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