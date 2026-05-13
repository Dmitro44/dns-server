#include <iostream>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <string>

std::atomic<uint64_t> total_sent(0);
std::atomic<uint64_t> total_responses(0);

// Hardcoded DNS query for A record of 'example.test'
const uint8_t dns_query[] = {
    0x12, 0x34, // Transaction ID
    0x01, 0x00, // Flags: Standard query
    0x00, 0x01, // Questions: 1
    0x00, 0x00, // Answer RRs: 0
    0x00, 0x00, // Authority RRs: 0
    0x00, 0x00, // Additional RRs: 0
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x04, 't', 'e', 's', 't',
    0x00,       // End of name
    0x00, 0x01, // Type: A
    0x00, 0x01  // Class: IN
};

void worker(const char* ip, int port, uint64_t queries, uint32_t delay_us) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return;
    }

    // Set non-blocking mode to blast queries and read available responses
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &server_addr.sin_addr);

    uint8_t buffer[512];
    uint64_t local_sent = 0;
    uint64_t local_resp = 0;
    
    for (uint64_t i = 0; i < queries; ++i) {
        ssize_t sent = sendto(sock, dns_query, sizeof(dns_query), 0,
                              (struct sockaddr*)&server_addr, sizeof(server_addr));
        if (sent > 0) {
            local_sent++;
        }

        // Drain available responses
        while (true) {
            struct sockaddr_in from_addr;
            socklen_t from_len = sizeof(from_addr);
            ssize_t recvd = recvfrom(sock, buffer, sizeof(buffer), 0,
                                     (struct sockaddr*)&from_addr, &from_len);
            if (recvd > 0) {
                local_resp++;
            } else {
                break; // No more responses right now
            }
        }
        
        if (delay_us > 0) {
            usleep(delay_us);
        } else {
            // Yield occasionally if no delay is specified to prevent starving the server threads
            if (i % 100 == 0) std::this_thread::yield();
        }
    }
    
    // Drain for up to 500ms to catch late responses
    auto end_drain = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
    while (std::chrono::steady_clock::now() < end_drain) {
        while (true) {
            struct sockaddr_in from_addr;
            socklen_t from_len = sizeof(from_addr);
            ssize_t recvd = recvfrom(sock, buffer, sizeof(buffer), 0,
                                     (struct sockaddr*)&from_addr, &from_len);
            if (recvd > 0) {
                local_resp++;
            } else {
                break;
            }
        }
        usleep(1000); // 1ms
    }

    total_sent += local_sent;
    total_responses += local_resp;
    close(sock);
}

int main(int argc, char* argv[]) {
    const char* ip = "127.0.0.1";
    int port = 8053;
    int num_threads = 4;
    uint64_t target_queries = 10000;
    uint32_t delay_us = 0;

    if (argc < 4) {
        std::cout << "Usage: " << argv[0] << " <threads> <total_queries> <delay_us>\n";
        std::cout << "Using default values since arguments are missing.\n\n";
    }

    if (argc > 1) num_threads = std::stoi(argv[1]);
    if (argc > 2) target_queries = std::stoull(argv[2]);
    if (argc > 3) delay_us = std::stoul(argv[3]);

    if (num_threads <= 0) num_threads = 1;

    std::cout << "Starting DNS stress test...\n"
              << "Server: " << ip << ":" << port << "\n"
              << "Threads: " << num_threads << "\n"
              << "Total Queries: " << target_queries << "\n"
              << "Delay per query: " << delay_us << " us\n\n";

    std::vector<std::thread> threads;
    auto start_time = std::chrono::steady_clock::now();

    uint64_t queries_per_thread = target_queries / num_threads;
    uint64_t remainder = target_queries % num_threads;

    for (int i = 0; i < num_threads; ++i) {
        uint64_t qt = queries_per_thread + (i < remainder ? 1 : 0);
        threads.emplace_back(worker, ip, port, qt, delay_us);
    }

    for (auto& t : threads) {
        t.join();
    }

    auto end_time = std::chrono::steady_clock::now();
    // Subtract 500ms from elapsed time as this is the drain delay added at the end
    std::chrono::duration<double> elapsed = end_time - start_time - std::chrono::milliseconds(500);
    if (elapsed.count() <= 0) elapsed = std::chrono::duration<double>(0.001);

    uint64_t q = total_sent.load();
    uint64_t r = total_responses.load();

    std::cout << "--- Results ---\n";
    std::cout << "Time elapsed:    " << elapsed.count() << " seconds\n";
    std::cout << "Queries sent:    " << q << " (" << (uint64_t)(q / elapsed.count()) << " qps)\n";
    std::cout << "Responses rcvd:  " << r << " (" << (uint64_t)(r / elapsed.count()) << " rps)\n";
    double success_rate = (q > 0 ? (r * 100.0 / q) : 0.0);
    std::cout << "Success rate:    " << success_rate << "%\n";

    if (success_rate == 0.0 && q > 0) {
        return 1;
    }

    return 0;
}
