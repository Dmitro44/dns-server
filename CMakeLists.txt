cmake_minimum_required(VERSION 3.20)
project(DNSServer LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(dns-server src/main.cpp src/dns_packet.cpp src/dns_record.cpp src/zone_loader.cpp)
target_link_libraries(dns-server PRIVATE Threads::Threads)
