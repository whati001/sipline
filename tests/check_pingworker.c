//
// Created by akarner on 4/4/21.
//

#include "check.h"
#include <stdlib.h>
#include <sipline.h>

void wrapFuncInHttpServer(void (*func)(void)) {
    printf("Start python http server at port 2711\n");
    system("/usr/bin/tmux new-session -d -s \"pythonHttpServer\" python3 -m http.server 2711");
    printf("Start python http server started at port 2711\n");
    func();
    printf("Kill python server at port 2711\n");
    system("/usr/bin/tmux kill-session -t pythonHttpServer");
}

START_TEST(test_init_worker) {
    ck_assert_int_eq(EXIT_FAILURE, initPingService(NULL));

    ping_service_t *service = NULL;
    ck_assert_int_eq(EXIT_SUCCESS, initPingService(&service));

    destroyPingService(service);
}

END_TEST

START_TEST(test_worker_tcp_get) {
    ping_task_t *task = (ping_task_t *) malloc(sizeof(ping_task_t));
    *task = (ping_task_t) {
            HTTP,
            strdup("127.0.0.1"),
            2711,
            GET,
            strdup("/sipbell/test"),
            strdup("something"),
            NULL
    };

    ck_assert_int_eq(EXIT_SUCCESS, pingBackend(task));
    destroyPingTask(task);
}

END_TEST

START_TEST(test_worker_tcp_post) {
    ping_task_t *task = (ping_task_t *) malloc(sizeof(ping_task_t));
    *task = (ping_task_t) {
            HTTP,
            strdup("127.0.0.1"),
            2711,
            POST,
            strdup("/sipbell/test"),
            strdup("{\"type\":0, \"from\":\"whati001\",\"to\":\"L12\"}"),
            NULL
    };

    ck_assert_int_eq(EXIT_SUCCESS, pingBackend(task));
    destroyPingTask(task);
}

END_TEST

START_TEST(test_worker_tcp_fail_address) {
    ping_task_t *task = (ping_task_t *) malloc(sizeof(ping_task_t));
    *task = (ping_task_t) {
            HTTP,
            strdup("localhost"),
            2711,
            POST,
            strdup("/sipbell/test"),
            strdup("{\"type\":0, \"from\":\"whati001\",\"to\":\"L12\"}"),
            NULL
    };

    ck_assert_int_eq(EXIT_FAILURE, pingBackend(task));
    destroyPingTask(task);
}

END_TEST

Suite *queue_suite() {
    Suite *s;
    TCase *tc_core;

    // INFO: please start a http server before running those tests
    s = suite_create("PingWorker");
    tc_core = tcase_create("PingWorkerBasic");

    tcase_add_test(tc_core, test_init_worker);
    tcase_add_test(tc_core, test_worker_tcp_get);
    tcase_add_test(tc_core, test_worker_tcp_post);
    tcase_add_test(tc_core, test_worker_tcp_fail_address);
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