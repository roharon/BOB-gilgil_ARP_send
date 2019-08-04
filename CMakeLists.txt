cmake_minimum_required(VERSION 3.14)
project(BOB-gilgil_ARP_spoofing C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

find_package(PCAP REQUIRED)
include_directories(${PCAP_INCLUDE_DIR})

set(SOURCE_FILES main.c)
add_executable(network_homework_1 ${SOURCE_FILES})
target_link_libraries(network_homework_1 ${PCAP_LIBRARY})