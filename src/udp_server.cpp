#include "udp_server.hpp"
#include "dns_packet.hpp"
#include "logger.hpp"
#include <arpa/inet.h>
#include <cstring>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace dns {

UDPServer::UDPServer(uint16_t port, size_t thread_count, Resolver &resolver)
    : socket_fd_(-1), port_(port), resolver_(resolver), running_(false),
      thread_pool_(std::make_unique<ThreadPool>(thread_count)) {

    socket_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd_ < 0) {
        throw std::runtime_error("Failed to create socket");
    }

    int reuse = 1;
    if (setsockopt(socket_fd_, SOL_SOCKET, SO_REUSEADDR, &reuse,
                   sizeof(reuse)) < 0) {
        close(socket_fd_);
        throw std::runtime_error("Failed to set SO_REUSEADDR");
    }

    struct sockaddr_in server_addr;
    std::memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port_);

    if (bind(socket_fd_, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
        0) {
        close(socket_fd_);
        throw std::runtime_error("Failed to bind to port " +
                                 std::to_string(port_));
    }
}

UDPServer::~UDPServer() {
    if (socket_fd_ >= 0) {
        close(socket_fd_);
    }
}

void UDPServer::start() {
    running_ = true;
    LOG_INFO("DNS Server listening on port " << port_ << "...");

    uint8_t buffer[512];

    while (running_) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        ssize_t recv_len =
            recvfrom(socket_fd_, buffer, sizeof(buffer), 0,
                     (struct sockaddr *)&client_addr, &client_len);

        if (!running_) {
            break;
        }

        if (recv_len < 0) {
            if (errno == EINTR) {
                continue;
            }
            LOG_ERROR("Error receiving data: " << strerror(errno));
            continue;
        }

        std::vector<uint8_t> query_data(buffer, buffer + recv_len);
        thread_pool_->enqueue(
            [this, data = std::move(query_data), client_addr]() {
                this->handle_query(data.data(), data.size(), client_addr);
            });
    }

    LOG_INFO("Server shutting down...");
}

void UDPServer::stop() {
    running_ = false;
    if (socket_fd_ >= 0) {
        // Shutdown the socket to break the blocking recvfrom call
        shutdown(socket_fd_, SHUT_RD);
    }
}

void UDPServer::handle_query(const uint8_t *data, size_t len,
                             const struct sockaddr_in &client_addr) {
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    uint16_t client_port = ntohs(client_addr.sin_port);

    DNSPacket query;
    if (!query.parse(data, len)) {
        LOG_ERROR("Failed to parse query from " << client_ip << ":"
                                                << client_port);
        return;
    }

    if (query.questions.empty()) {
        LOG_ERROR("Query has no questions from " << client_ip << ":"
                                                 << client_port);
        return;
    }

    const auto &question = query.questions[0];
    log_query(client_ip, client_port, question.qname, question.qtype);

    LOG_DEBUG("Parsed qname: '" << question.qname
                                << "' (len=" << question.qname.length() << ")");

    DNSPacket response = resolver_.resolve(query);

    LOG_DEBUG("Response RCODE: " << (response.header.flags & 0x0F)
                                 << ", answers: " << response.answers.size());

    std::vector<uint8_t> response_data = response.serialize();

    ssize_t sent_len =
        sendto(socket_fd_, response_data.data(), response_data.size(), 0,
               (struct sockaddr *)&client_addr, sizeof(client_addr));

    if (sent_len < 0) {
        LOG_ERROR("Failed to send response to " << client_ip << ":"
                                                << client_port);
    }
}

void UDPServer::log_query(const std::string &client_ip, uint16_t client_port,
                          const std::string &qname, uint16_t qtype) {
    std::string type_str;
    switch (qtype) {
    case 1:
        type_str = "A";
        break;
    case 28:
        type_str = "AAAA";
        break;
    case 5:
        type_str = "CNAME";
        break;
    case 2:
        type_str = "NS";
        break;
    case 6:
        type_str = "SOA";
        break;
    default:
        type_str = "TYPE" + std::to_string(qtype);
    }

    LOG_INFO("Query from " << client_ip << ":" << client_port << " for "
                           << qname << " (" << type_str << ")");
}

} // namespace dns
