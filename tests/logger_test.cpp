#include "../include/logger.hpp"
#include <thread>
#include <vector>

void worker(int id) {
    for (int i = 0; i < 5; ++i) {
        LOG_INFO("Worker " << id << " iteration " << i);
    }
}

int main() {
    Logger::getInstance().setLevel(LogLevel::DEBUG);

    LOG_DEBUG("This is a debug message");
    LOG_INFO("This is an info message");
    LOG_WARNING("This is a warning message");
    LOG_ERROR("This is an error message");

    std::vector<std::thread> threads;
    for (int i = 0; i < 3; ++i) {
        threads.emplace_back(worker, i);
    }

    for (auto &t : threads) {
        t.join();
    }

    LOG_INFO("All workers finished. Logger test completed successfully.");
    return 0;
}
