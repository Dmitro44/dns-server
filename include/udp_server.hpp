#pragma once

#include "resolver.hpp"
#include <atomic>
#include <cstdint>
#include <string>

struct sockaddr_in;

namespace dns {

// UDP DNS Server - binds to port, receives queries, sends responses
class UDPServer {
  public:
    explicit UDPServer(uint16_t port, Resolver &resolver);
    ~UDPServer();

    // Start server loop (blocks until stop() called)
    void start();

    // Stop server gracefully (call from signal handler)
    void stop();

  private:
    int socket_fd_;
    uint16_t port_;
    Resolver &resolver_;
    std::atomic<bool> running_;

    void handle_query(const uint8_t *data, size_t len,
                      const struct sockaddr_in &client_addr);

    static void log_query(const std::string &client_ip, uint16_t client_port,
                          const std::string &qname, uint16_t qtype);

    static std::string get_timestamp();
};

} // namespace dns
