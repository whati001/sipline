cmake_minimum_required(VERSION 3.17)
project(sipline)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "-Os -Wall -Wextra -lpcap -lpthread -losipparser2")

enable_testing()
find_package(PkgConfig REQUIRED)

add_subdirectory(src)
add_subdirectory(tests)