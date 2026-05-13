#include <iostream>
#include <csignal>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <chrono>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <path_to_dns_server_executable>" << std::endl;
        return 1;
    }

    std::cout << "Starting Shutdown Test..." << std::endl;

    pid_t pid = fork();
    if (pid == 0) {
        // Child process: start the server
        execl(argv[1], argv[1], nullptr);
        perror("execl failed");
        exit(1);
    } else if (pid > 0) {
        // Parent process
        std::cout << "Server started with PID: " << pid << ". Waiting for it to initialize..." << std::endl;
        sleep(2); // Give the server time to start

        std::cout << "Sending SIGINT (Ctrl+C) to server..." << std::endl;
        kill(pid, SIGINT);

        auto start = std::chrono::high_resolution_clock::now();
        int status;
        pid_t result = waitpid(pid, &status, 0);
        auto end = std::chrono::high_resolution_clock::now();

        std::chrono::duration<double> diff = end - start;

        if (result == pid) {
            std::cout << "Server exited correctly." << std::endl;
            if (WIFEXITED(status)) {
                std::cout << "Exit code: " << WEXITSTATUS(status) << std::endl;
            }
            std::cout << "Shutdown took: " << diff.count() << " seconds" << std::endl;
            
            // Expected behavior: clean shutdown should be fast (usually < 1s)
            if (diff.count() < 2.0) {
                std::cout << "SUCCESS: Clean shutdown is fast." << std::endl;
            } else {
                std::cout << "WARNING: Shutdown took longer than expected." << std::endl;
            }
        } else {
            std::cerr << "Error waiting for server process." << std::endl;
            return 1;
        }
    } else {
        perror("fork failed");
        return 1;
    }

    return 0;
}
