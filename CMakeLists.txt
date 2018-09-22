cmake_minimum_required(VERSION 2.8)
project(fastj C)

set(CMAKE_C_STANDARD 99)

#SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")

add_executable(fastj hash.c picohttpparser.c fastj.c slog.c)
#add_executable(fastj hash.c test/testconfig.c)
#add_executable(fastj test/testreg.c)


target_link_libraries (fastj pcap pthread rt)
