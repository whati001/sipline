//
// Created by akarner on 4/4/21.
//

#include "check.h"
#include <stdlib.h>

START_TEST(test_queue_basic) {
    ck_assert_int_eq(1, 1);
}

START_TEST(test_queue_init) {
    ck_assert_int_eq(1, 1);
}

END_TEST

Suite *queue_suite() {
    Suite *s;
    TCase *tc_core;

    s = suite_create("Queue");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_queue_basic);
    tcase_add_test(tc_core, test_queue_init);
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