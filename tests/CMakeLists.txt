pkg_search_module(CHECK REQUIRED check)
include_directories(${CHECK_INCLUDE_DIRS})

set(PROJECT_INCLUDE_DIRS ${CMAKE_HOME_DIRECTORY}/include/)
set(TESTSUITE_LIBS ${LIBS} ${CHECK_LIBRARIES} pthread)

# ping project test suite
set(CHECK_REMOTE_SOURCES check_ping.c ${CMAKE_HOME_DIRECTORY}/src/lib/ping/pingqueue.c)
add_executable(check_ping ${CHECK_REMOTE_SOURCES})
target_include_directories(check_ping PRIVATE ${PROJECT_INCLUDE_DIRS})
target_link_libraries(check_ping PUBLIC ${TESTSUITE_LIBS})
add_test(NAME check_ping COMMAND check_ping)

# sipline project suite
set(CHECK_SIPLINE_SOURCES check_sipline.c)
add_executable(check_sipline ${CHECK_SIPLINE_SOURCES})
target_include_directories(check_sipline PRIVATE ${PROJECT_INCLUDE_DIRS})
target_link_libraries(check_sipline PUBLIC ${TESTSUITE_LIBS})
add_test(NAME check_sipline COMMAND check_sipline)