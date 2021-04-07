//
// Created by akarner on 4/4/21.
//

#include "ping/pingqueue.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

char *stringifyPingTask(ping_task_t *task) {
    if (NULL == task) {
        return NULL;
    }
    size_t needed = snprintf(NULL, 0, "PingTask{protocol: %d,host: %s,port: %d,method: %d, query: %s, body: %s}",
                             task->protocol, task->host, task->port, task->method, task->query, task->body);
    char *buffer = (char *) calloc(sizeof(char), needed + 1);
    sprintf(buffer, "PingTask{protocol: %d,host: %s,port: %d,method: %d, query: %s, body: %s}",
            task->protocol, task->host, task->port, task->method, task->query, task->body);
    return buffer;
}

int initPingQueue(ping_queue_t **queue, uint8_t capacity) {
    ping_queue_t *tmp = (ping_queue_t *) malloc(sizeof(ping_queue_t));
    if (NULL == tmp) {
        fprintf(stderr, "Failed to allocate memory for new ping queue\n");
        return EXIT_FAILURE;
    }

    pthread_mutex_init(&tmp->mutex, NULL);
    pthread_cond_init(&tmp->cond, NULL);
    tmp->front = NULL;
    tmp->back = NULL;
    tmp->size = 0;
    tmp->capacity = capacity;

    *queue = tmp;
    return EXIT_SUCCESS;
}

void destroyPingTask(ping_task_t *task) {
    if (NULL == task) {
        return;
    }
    free(task->host);
    free(task->query);
    free(task->body);
    free(task);
}

void destroyPingQueue(ping_queue_t *queue) {
    if (NULL == queue) {
        return;
    }

    ping_task_t *tmp = NULL;
    while (queue->front != NULL) {
        if (EXIT_SUCCESS == popPingTask(queue, &tmp)) {
            fprintf(stdout, "Remove remaining task from queue: "
                            "PingTask{prot: %d, host: %s, port: %d, method: %d, query: %s, body: %s}\n",
                    tmp->protocol, tmp->host, tmp->port, tmp->method, tmp->query, tmp->body);
            destroyPingTask(tmp);
        }
    }
    fprintf(stdout, "Freed all ping tasks from queue before destroying the queue itself\n");

    pthread_mutex_destroy(&queue->mutex);
    pthread_cond_destroy(&queue->cond);
    free(queue);
}

int pushPingTask(ping_queue_t *queue, ping_task_t *task) {
    if (NULL == queue) {
        fprintf(stderr, "Failed to push task to queue, passed NULL queue instance\n");
        return EXIT_FAILURE;
    }
    if (NULL == task) {
        fprintf(stderr, "Failed to push task to queue, passed NULL task instance\n");
        return EXIT_FAILURE;
    }

    pthread_mutex_lock(&queue->mutex);

    if (queue->capacity == queue->size) {
        fprintf(stdout, "Ping queue reached max size, drop task\n");
        pthread_mutex_unlock(&queue->mutex);
        return EXIT_SUCCESS;
    }

    fprintf(stdout, "Push element: %p\n", task);
    if (NULL == queue->front) {
        fprintf(stdout, "Pushed first element\n");
        queue->front = task;
        queue->back = task;
    } else {
        fprintf(stdout, "Pushed not first element\n");
        queue->back->next = task;
        queue->back = task;
    }

    queue->size++;
    pthread_mutex_unlock(&queue->mutex);
    pthread_cond_signal(&queue->cond);

    return EXIT_SUCCESS;
}

int popPingTask(ping_queue_t *queue, ping_task_t **task) {
    if (NULL == queue) {
        fprintf(stderr, "Failed to pop task from queue, passed NULL queue instance\n");
        return EXIT_FAILURE;
    }

    pthread_mutex_lock(&queue->mutex);
    while (0 == queue->size) {
        pthread_cond_wait(&queue->cond, &queue->mutex);
    }

    ping_task_t *tmp = queue->front;
    if (NULL == tmp->next) {
        queue->front = NULL;
        queue->back = NULL;
    } else {
        queue->front = tmp->next;
        tmp->next = NULL;
    }

    queue->size--;
    *task = tmp;
    pthread_mutex_unlock(&queue->mutex);

    return EXIT_SUCCESS;
}