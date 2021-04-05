//
// Created by akarner on 4/4/21.
//

#ifndef SIPLINE_PINGQUEUE_H
#define SIPLINE_PINGQUEUE_H

#include <pthread.h>
#include <stdint.h>

/**
 * Protocols supported by ping packages
 */
typedef enum {
    HTTP = 1
} ping_protocol;

typedef enum {
    GET = 1, POST
} ping_method;

/**
 * Struct holding all the relevant data for processing a ping request
 * This object will get stored to the queue and processed by the pingworker.c
 */
typedef struct ping_task {
    ping_protocol protocol;
    char *host;
    int port;
    ping_method method;
    char *query;
    char *body;
    struct ping_task *next;
} ping_task_t;

/**
 * Signal Queue object
 */
typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;

    ping_task_t *front;
    ping_task_t *back;
    uint8_t size;
    uint8_t capacity;
} ping_queue_t;

/**
 * Initialize new ping queue to publish work for pingwoker.c
 * @param queue pointer pointer to store new ping_queue_t instance to
 * @param capacity define capacity for queue
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int initPingQueue(ping_queue_t **queue, uint8_t capacity);

/**
 * Destroy and free everything properly
 * @param task pointer to object
 */
void _destroyPingTask(ping_task_t *task);

/**
 * Destroy and free everything properly. This will also free all remaining tasks
 *  within the queue
 * @param queue pointer to queue
 */
void destroyPingQueue(ping_queue_t *queue);

/**
 * Push new ping_task_t object onto queue
 * @param queue to push new element to
 * @param task to push
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int pushPingTask(ping_queue_t *queue, ping_task_t *task);

/**
 * Pop front element from queue and store it to task parameter
 * @param queue to pop task from
 * @param task where to store popped task
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int popPingTask(ping_queue_t *queue, ping_task_t **task);

#endif //SIPLINE_PINGQUEUE_H
