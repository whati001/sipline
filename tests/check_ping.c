//
// Created by akarner on 4/4/21.
//

#include "check.h"
#include "ping/pingqueue.h"
#include <stdlib.h>
#include <stdio.h>

START_TEST(test_pingqueue_create_destroy) {
    ping_queue_t *queue = NULL;
    ck_assert_int_eq(EXIT_SUCCESS, initPingQueue(&queue, UINT8_MAX));
    ck_assert_int_eq(0, queue->size);
    ck_assert_int_eq(UINT8_MAX, queue->capacity);
    ck_assert_ptr_eq(NULL, queue->front);
    ck_assert_ptr_eq(NULL, queue->back);

    destroyPingQueue(queue);
}

END_TEST

START_TEST(test_pingqueue_push_destroy) {
    ping_queue_t *queue = NULL;
    ck_assert_int_eq(EXIT_SUCCESS, initPingQueue(&queue, UINT8_MAX));

    ping_task_t *task = (ping_task_t *) malloc(sizeof(ping_task_t));
    *task = (ping_task_t) {
            HTTP,
            strdup("localhost"),
            2711,
            GET,
            strdup("/sipbell/test"),
            strdup("something"),
            NULL
    };
    ck_assert_int_eq(EXIT_SUCCESS, pushPingTask(queue, task));
    destroyPingQueue(queue);
}

END_TEST

START_TEST(test_pingqueue_push_pop) {
    ping_queue_t *queue = NULL;
    ck_assert_int_eq(EXIT_SUCCESS, initPingQueue(&queue, UINT8_MAX));

    ping_task_t *task = (ping_task_t *) malloc(sizeof(ping_task_t));
    *task = (ping_task_t) {
            HTTP,
            strdup("localhost"),
            2711,
            GET,
            strdup("/sipbell/test"),
            strdup("something"),
            NULL
    };
    ck_assert_int_eq(EXIT_SUCCESS, pushPingTask(queue, task));

    ping_task_t *pop_task = NULL;
    ck_assert_int_eq(EXIT_SUCCESS, popPingTask(queue, &pop_task));
    ck_assert_int_eq(task->protocol, pop_task->protocol);
    ck_assert_str_eq(task->host, pop_task->host);
    ck_assert_int_eq(task->port, pop_task->port);
    ck_assert_str_eq(task->query, pop_task->query);
    ck_assert_str_eq(task->body, pop_task->body);

    _destroyPingTask(pop_task);
    destroyPingQueue(queue);
}

END_TEST

START_TEST(test_pingqueue_push_limit) {
    ping_queue_t *queue = NULL;
    ck_assert_int_eq(EXIT_SUCCESS, initPingQueue(&queue, 5));

    ping_task_t *task1 = (ping_task_t *) malloc(sizeof(ping_task_t));
    *task1 = (ping_task_t) {
            HTTP,
            strdup("localhost"),
            2711,
            GET,
            strdup("/sipbell/test"),
            strdup("something"),
            NULL
    };
    ck_assert_int_eq(EXIT_SUCCESS, pushPingTask(queue, task1));

    ping_task_t *task2 = (ping_task_t *) malloc(sizeof(ping_task_t));
    *task2 = (ping_task_t) {
            HTTP,
            strdup("localhost"),
            2711,
            GET,
            strdup("/sipbell/test"),
            strdup("something"),
            NULL
    };
    ck_assert_int_eq(EXIT_SUCCESS, pushPingTask(queue, task2));

    ping_task_t *task3 = (ping_task_t *) malloc(sizeof(ping_task_t));
    *task3 = (ping_task_t) {
            HTTP,
            strdup("localhost"),
            2711,
            GET,
            strdup("/sipbell/test"),
            strdup("something"),
            NULL
    };
    ck_assert_int_eq(EXIT_SUCCESS, pushPingTask(queue, task3));

    ping_task_t *task4 = (ping_task_t *) malloc(sizeof(ping_task_t));
    *task4 = (ping_task_t) {
            HTTP,
            strdup("localhost"),
            2711,
            GET,
            strdup("/sipbell/test"),
            strdup("something"),
            NULL
    };
    ck_assert_int_eq(EXIT_SUCCESS, pushPingTask(queue, task4));

    ping_task_t *task5 = (ping_task_t *) malloc(sizeof(ping_task_t));
    *task5 = (ping_task_t) {
            HTTP,
            strdup("localhost"),
            2711,
            GET,
            strdup("/sipbell/test"),
            strdup("something"),
            NULL
    };
    ck_assert_int_eq(EXIT_SUCCESS, pushPingTask(queue, task5));
    ck_assert_int_eq(EXIT_SUCCESS, pushPingTask(queue, task5));

    ping_task_t *pop_task = NULL;
    ck_assert_int_eq(EXIT_SUCCESS, popPingTask(queue, &pop_task));
    _destroyPingTask(pop_task);

    destroyPingQueue(queue);
}

END_TEST

Suite *queue_suite() {
    Suite *s;
    TCase *tc_core;

    s = suite_create("PingQueue");
    tc_core = tcase_create("PingQueueBasic");

    tcase_add_test(tc_core, test_pingqueue_create_destroy);
    tcase_add_test(tc_core, test_pingqueue_push_destroy);
    tcase_add_test(tc_core, test_pingqueue_push_pop);
    tcase_add_test(tc_core, test_pingqueue_push_limit);
    suite_add_tcase(s, tc_core);

    return s;
}


int main() {
    int number_failed = 0;
    Suite *s;
    SRunner *sr;

    s = queue_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}