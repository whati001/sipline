
file(GLOB SIPLINE_SRC_SOURCES *.c)
file(GLOB SIPLINE_LIB_SOURCES lib/*.c
        SIPLINE_LIB_SOURCES lib/ping/*.c)

add_executable(sipline ${SIPLINE_SRC_SOURCES} ${SIPLINE_LIB_SOURCES})

target_include_directories(sipline PUBLIC ${CMAKE_HOME_DIRECTORY}/include/)