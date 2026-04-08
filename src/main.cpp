#include "resolver.hpp"
#include "udp_server.hpp"
#include "zone_loader.hpp"
#include <csignal>
#include <iostream>
#include <memory>

std::unique_ptr<dns::UDPServer> g_server;

void signal_handler(int signum) {
    if (g_server) {
        g_server->stop();
    }
}

int main() {
    std::cout << "DNS Server starting...\n";

    dns::ZoneLoader loader;
    if (!loader.load("zones/example.zone")) {
        std::cerr << "Failed to load zone file\n";
        return 1;
    }

    dns::Resolver resolver(loader);

    try {
        g_server = std::make_unique<dns::UDPServer>(5353, resolver);

        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);

        g_server->start();

    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
