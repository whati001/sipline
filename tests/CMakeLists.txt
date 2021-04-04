pkg_search_module(CHECK REQUIRED check)
include_directories(${CHECK_INCLUDE_DIRS})

set(TESTSUITE_SOURCES testsuite.c)
set(TESTSUITE_LIBS ${LIBS} ${CHECK_LIBRARIES} pthread)

add_executable(testsuite ${TESTSUITE_SOURCES})
target_link_libraries(testsuite PUBLIC ${TESTSUITE_LIBS})

add_test(NAME allTests COMMAND testsuite)