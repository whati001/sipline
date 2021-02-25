cmake_minimum_required(VERSION 3.17)
project(sipline C)

set(CMAKE_C_STANDARD 11)
SET(CMAKE_C_FLAGS "-lpcap -lcurl -losip2 -losipparser2")

add_executable(sipline main.c siplinePackages.h)