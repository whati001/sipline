//
// Created by akarner on 4/4/21.
//

#include "sipqueue.h"

#include <stdlib.h>
#include <stdio.h>

int initSignalQueue(signal_queue **queue) {
    signal_queue *tmp = (signal_queue *) malloc(sizeof(signal_queue));
    if (NULL == queue) {
        fprintf(stderr, "Failed to allocate memory for Signal queue\n");
        return EXIT_FAILURE;
    }
    pthread_mutex_init(&tmp->mutex, NULL);
    pthread_cond_init(&tmp->cond, NULL);

    tmp->front = NULL;
    tmp->back = NULL;
    tmp->size = 0;

    *queue = tmp;
    return EXIT_SUCCESS;
}

signal_task *_createSignalTask(sipline_call_info **call_info) {
    signal_task *tmp = (signal_task *) malloc(sizeof(signal_task));
    if (NULL == call_info) {
        fprintf(stderr, "Failed to create signal task, call info was NULL\n");
        return NULL;
    }
    if (NULL == tmp) {
        fprintf(stderr, "Failed to allocate new memory for signal task\n");
        return NULL;
    }

    tmp->item = *call_info;
    tmp->next = NULL;

    return tmp;
}

int pushSignalQueue(signal_queue *queue, sipline_call_info **call_info) {
    if (NULL == queue) {
        fprintf(stderr, "Failed to push, received NULL queue pointer\n");
        return EXIT_FAILURE;
    }
    if (NULL == call_info) {
        fprintf(stderr, "Failed to push, received NULL call info pointer\n");
        return EXIT_FAILURE;
    }

    pthread_mutex_lock(&queue->mutex);

    if (UINT32_MAX == queue->size) {
        fprintf(stdout, "Signal queue received max value, skip push\n");
        pthread_mutex_unlock(&queue->mutex);
        return EXIT_SUCCESS;
    }

    signal_task *task = _createSignalTask(call_info);
    if (NULL == task) {
        fprintf(stderr, "Failed wrap call info into signal task\n");
        pthread_mutex_unlock(&queue->mutex);
        return EXIT_FAILURE;
    }

    if (NULL == queue->front) {
        queue->front = task;
        queue->back = task;
    } else {
        queue->back->next = task;
        queue->back = task;
    }

    queue->size++;
    pthread_mutex_unlock(&queue->mutex);
    pthread_cond_signal(&queue->cond);

    return EXIT_SUCCESS;
}

int popSignalQueue(signal_queue *queue, sipline_call_info **call_info) {
    if (NULL == queue) {
        fprintf(stderr, "Failed to pop, received NULL queue pointer\n");
        return EXIT_FAILURE;
    }
    if (NULL == call_info) {
        fprintf(stderr, "Received NULL pointer, just pop without free task from queue\n");
        return EXIT_FAILURE;
    }

    pthread_mutex_lock(&queue->mutex);
    while (0 == queue->size) {
        pthread_cond_wait(&queue->cond, &queue->mutex);
    }

    signal_task *task = queue->front;
    if (NULL == task->next) {
        queue->front = NULL;
        queue->back = NULL;
    } else {
        queue->front = task->next;
    }

    queue->size--;
    *call_info = task->item;
    free(task);
    pthread_mutex_unlock(&queue->mutex);
}

void freeSignalQueue(signal_queue *queue) {
    if (NULL == queue) {
        return;
    }

    while (queue->front != NULL) {
        sipline_call_info *call_info = NULL;
        popSignalQueue(queue, &call_info);
        free(call_info->from);
        free(call_info->to);
        free(call_info);
    }

    pthread_mutex_destroy(&queue->mutex);
    pthread_cond_destroy(&queue->cond);
    free(queue);
}