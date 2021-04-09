pkg_search_module(CHECK REQUIRED check)
include_directories(${CHECK_INCLUDE_DIRS})

set(PROJECT_INCLUDE_DIRS ${CMAKE_HOME_DIRECTORY}/include/)
set(TESTSUITE_LIBS ${LIBS} ${CHECK_LIBRARIES} pthread)
set(SIPLINE_SRC ${CMAKE_HOME_DIRECTORY}/src/lib/ping/pingqueue.c ${CMAKE_HOME_DIRECTORY}/src/lib/ping/pingworker.c)

# ping project test suite
set(CHECK_REMOTE_SOURCES check_pingqueue.c ${SIPLINE_SRC})
add_executable(check_ping ${CHECK_REMOTE_SOURCES})
target_include_directories(check_ping PRIVATE ${PROJECT_INCLUDE_DIRS})
target_link_libraries(check_ping PUBLIC ${TESTSUITE_LIBS})
add_test(NAME check_ping COMMAND check_ping)

# sipline project suite
set(CHECK_SIPLINE_SOURCES check_pingworker.c ${SIPLINE_SRC})
add_executable(check_pingworker ${CHECK_SIPLINE_SOURCES})
target_include_directories(check_pingworker PRIVATE ${PROJECT_INCLUDE_DIRS})
target_link_libraries(check_pingworker PUBLIC ${TESTSUITE_LIBS})
add_test(NAME check_pingworker COMMAND check_pingworker)