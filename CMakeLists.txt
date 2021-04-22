cmake_minimum_required(VERSION 3.17)
project(sipline)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "-Os -Wall -Wextra -lpcap -lcurl -lpthread -losipparser2")

add_subdirectory(src)