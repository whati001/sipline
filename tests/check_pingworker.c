//
// Created by akarner on 4/4/21.
//

#include "check.h"
#include <stdlib.h>
#include <sipline.h>

START_TEST(test_init_worker) {
    ck_assert_int_eq(EXIT_FAILURE, initPingService(NULL));

    ping_service_t *service = NULL;
    ck_assert_int_eq(EXIT_SUCCESS, initPingService(&service));

    destroyPingService(service);
}

END_TEST

Suite *queue_suite() {
    Suite *s;
    TCase *tc_core;

    s = suite_create("PingWorker");
    tc_core = tcase_create("PingWorkerBasic");

    tcase_add_test(tc_core, test_init_worker);
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