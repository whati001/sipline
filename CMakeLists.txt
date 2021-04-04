cmake_minimum_required(VERSION 3.17)
project(sipline C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "-Os -lpcap -lcurl -losipparser2")

add_executable(sipline main.c include/siplinenet.h include/sipline.h include/osip.h include/queue.h src/queue.c)

target_include_directories(sipline PRIVATE ${CMAKE_HOME_DIRECTORY}/include)
