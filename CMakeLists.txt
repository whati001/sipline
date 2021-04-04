cmake_minimum_required(VERSION 3.17)
project(sipline)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "-Os -Wall -Wextra -lpcap -lcurl -losipparser2")

enable_testing()
find_package(PkgConfig REQUIRED)

add_subdirectory(src)
add_subdirectory(tests)
#add_executable(sipline main.c include/siplinenet.h include/sipline.h include/osip.h include/check_queue.h src/lib/queue.c tests/check_queue.c)
#
#target_include_directories(sipline PRIVATE ${CMAKE_HOME_DIRECTORY}/include)
