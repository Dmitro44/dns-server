#include "../include/config.hpp"
#include <cassert>
#include <iostream>

void test_cli_overrides() {
    const char *argv[] = {"dns-server", "--port", "10053",          "--threads",
                          "16",         "--zone", "zones/test.zone"};
    int argc = 7;

    Config cfg = Config::load(argc, const_cast<char **>(argv));

    assert(cfg.port == 10053);
    assert(cfg.threads == 16);
    assert(cfg.zone_file == "zones/test.zone");

    std::cout << "test_cli_overrides passed.\n";
}

void test_ini_loading() {
    const char *argv[] = {"dns-server"};
    int argc = 1;

    Config cfg = Config::load(argc, const_cast<char **>(argv));

    assert(cfg.port == 8053);
    assert(cfg.threads == 8);
    assert(cfg.zone_file == "zones/custom.zone");

    std::cout << "test_ini_loading passed.\n";
}

int main() {
    test_cli_overrides();
    test_ini_loading();
    std::cout << "All config tests passed successfully.\n";
    return 0;
}
