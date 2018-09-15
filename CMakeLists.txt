cmake_minimum_required(VERSION 3.10)
project(fastj C)

set(CMAKE_C_STANDARD 99)

add_executable(fastj hash.c picohttpparser.c fastj.c slog.c)
#add_executable(fastj hash.c test/testconfig.c)
#add_executable(fastj test/testreg.c)


target_link_libraries (fastj pcap)
