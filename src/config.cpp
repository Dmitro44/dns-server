#include "config.hpp"
#include <fstream>
#include <getopt.h>
#include <string>

Config Config::load(int argc, char **argv) {
    Config cfg;

    std::ifstream file("config.ini");
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            auto comment_pos = line.find('#');
            if (comment_pos != std::string::npos) {
                line = line.substr(0, comment_pos);
            }
            line.erase(0, line.find_first_not_of(" \t\r\n"));
            line.erase(line.find_last_not_of(" \t\r\n") + 1);
            if (line.empty())
                continue;

            auto delim_pos = line.find('=');
            if (delim_pos != std::string::npos) {
                std::string key = line.substr(0, delim_pos);
                std::string val = line.substr(delim_pos + 1);

                key.erase(key.find_last_not_of(" \t") + 1);
                val.erase(0, val.find_first_not_of(" \t"));

                if (key == "port") {
                    cfg.port = std::stoi(val);
                } else if (key == "threads") {
                    cfg.threads = std::stoi(val);
                } else if (key == "zone") {
                    cfg.zone_file = val;
                }
            }
        }
    }

    const struct option long_options[] = {
        {"port", required_argument, 0, 'p'},
        {"threads", required_argument, 0, 't'},
        {"zone", required_argument, 0, 'z'},
        {0, 0, 0, 0}};

    int opt;
    int option_index = 0;
    // Reset optind to ensure repeated calls to getopt_long work correctly in
    // tests
    optind = 1;
    while ((opt = getopt_long(argc, argv, "p:t:z:", long_options,
                              &option_index)) != -1) {
        switch (opt) {
        case 'p':
            cfg.port = std::stoi(optarg);
            break;
        case 't':
            cfg.threads = std::stoi(optarg);
            break;
        case 'z':
            cfg.zone_file = optarg;
            break;
        default:
            break;
        }
    }

    return cfg;
}
