#include "config.hpp"
#include "logger.hpp"
#include "resolver.hpp"
#include "udp_server.hpp"
#include "zone_loader.hpp"
#include <csignal>
#include <memory>

std::unique_ptr<dns::UDPServer> g_server;

void signal_handler(int signum) {
    if (g_server) {
        g_server->stop();
    }
}

int main(int argc, char *argv[]) {
    Logger::getInstance().setLevel(LogLevel::DEBUG);
    LOG_INFO("DNS Server starting...");

    Config config = Config::load(argc, argv);

    dns::ZoneLoader loader;
    if (!loader.load(config.zone_file)) {
        LOG_ERROR("Failed to load zone file");
        return 1;
    }

    dns::Resolver resolver(loader);

    try {
        g_server = std::make_unique<dns::UDPServer>(config.port, config.threads, resolver);

        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);

        g_server->start();

    } catch (const std::exception &e) {
        LOG_ERROR("Error: " << e.what());
        return 1;
    }

    return 0;
}
