#include <iostream>
#include <csignal>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string>

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <server_bin> <stress_bin> [threads] [queries]" << std::endl;
        return 1;
    }

    std::string server_bin = argv[1];
    std::string stress_bin = argv[2];
    std::string threads = (argc > 3) ? argv[3] : "4";
    std::string queries = (argc > 4) ? argv[4] : "5000";
    std::string delay = (argc > 5) ? argv[5] : "0";

    std::cout << "[PerfTest] Starting DNS server: " << server_bin << std::endl;
    pid_t server_pid = fork();
    if (server_pid == 0) {
        execl(server_bin.c_str(), server_bin.c_str(), nullptr);
        perror("execl server failed");
        exit(1);
    }

    sleep(2);

    std::cout << "[PerfTest] Starting stress test: " << stress_bin << std::endl;
    pid_t stress_pid = fork();
    if (stress_pid == 0) {
        execl(stress_bin.c_str(), stress_bin.c_str(), threads.c_str(), queries.c_str(), delay.c_str(), nullptr);
        perror("execl stress failed");
        exit(1);
    }

    int stress_status;
    waitpid(stress_pid, &stress_status, 0);
    std::cout << "[PerfTest] Stress test finished." << std::endl;

    std::cout << "[PerfTest] Shutting down server (PID " << server_pid << ")..." << std::endl;
    kill(server_pid, SIGINT);
    
    int server_status;
    waitpid(server_pid, &server_status, 0);
    std::cout << "[PerfTest] Server exited." << std::endl;

    if (WIFEXITED(stress_status) && WEXITSTATUS(stress_status) == 0) {
        std::cout << "[PerfTest] SUCCESS" << std::endl;
        return 0;
    } else {
        std::cerr << "[PerfTest] FAILURE in stress test (Exit code: " << WEXITSTATUS(stress_status) << ")" << std::endl;
        return 1;
    }
}
