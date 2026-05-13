cmake_minimum_required(VERSION 3.20)
project(DNSServer LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(dns-server src/main.cpp src/dns_packet.cpp src/dns_record.cpp src/zone_loader.cpp src/resolver.cpp src/udp_server.cpp src/logger.cpp src/config.cpp src/thread_pool.cpp src/cache.cpp)
target_link_libraries(dns-server PRIVATE Threads::Threads)

enable_testing()
file(COPY config.ini DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY zones DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

# Stress and Shutdown tests
add_executable(shutdown_test tests/shutdown_test.cpp)
target_link_libraries(shutdown_test PRIVATE Threads::Threads)
# Note: shutdown_test requires the path to the server binary
add_test(NAME ShutdownTest COMMAND shutdown_test ./dns-server)

# C++ Stress Test
add_executable(stress_test tests/stress_test.cpp)
target_link_libraries(stress_test PRIVATE Threads::Threads)

# Performance Wrapper
add_executable(perf_test tests/perf_wrapper.cpp)
add_test(NAME PerformanceTest COMMAND perf_test ./dns-server ./stress_test 4 5000 20)
