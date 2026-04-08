#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <cstdint>
#include <string>

struct Config {
    uint16_t port = 53;
    uint32_t threads = 4;
    std::string zone_file = "zones/example.zone";

    static Config load(int argc, char **argv);
};

#endif // CONFIG_HPP
