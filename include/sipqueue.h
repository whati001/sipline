//
// Created by akarner on 4/4/21.
//

#ifndef SIPLINE_SIPQUEUE_H
#define SIPLINE_SIPQUEUE_H

#include <pthread.h>
#include "siplib.h"

/**
 * Signal queue item
 */
typedef struct signal_task {
    sipline_call_info *item;
    struct signal_task *next;
} signal_task;

/**
 * Signal Queue object
 */
typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;

    signal_task *front;
    signal_task *back;
    uint32_t size;
} signal_queue;

/**
 * Init Signal queue object
 * @return on Success return EXIT_SUCCESS, on Failure EXIT_FAILURE
 */
int initSignalQueue();

/**
 * Create new task from call info object, this method wrapps the call_info parameter
 * @param call_info to create task for
 * @param signal_task pointer with wrapped call_info
 */
signal_task *_createSignalTask(sipline_call_info **call_info);

/**
 * Push new signal_task struct to queue
 * @param queue to push task onto
 * @param call_info to push to queue
 * @return on Success return EXIT_SUCCESS, on Failure EXIT_FAILURE
 */
int pushSignalQueue(signal_queue *queue, sipline_call_info **call_info);

/**
 * Pop new signal_task from queue back
 * @param queue to pop from
 * @param call_info to pop from queue
 * @return on Success return EXIT_SUCCESS, on Failure EXIT_FAILURE
 */
int popSignalQueue(signal_queue *queue, sipline_call_info **call_info);

/**
 * Free and close Signal queue
 * @param queue to cleanup
 */
void freeSignalQueue(signal_queue *queue);

#endif //SIPLINE_SIPQUEUE_H
