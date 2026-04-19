#include "../include/logger.hpp"
#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>

static std::string escapeMessage(const std::string &msg) {
    std::string result;
    result.reserve(msg.size());
    for (char c : msg) {
        if (c == '\n') {
            result += "\\n";
        } else if (c == '\r') {
            result += "\\r";
        } else if (static_cast<unsigned char>(c) < 32 || c == 127) {
            continue;
        } else {
            result += c;
        }
    }
    return result;
}

Logger &Logger::getInstance() {
    static Logger instance;
    return instance;
}

Logger::Logger() : currentLevel_(LogLevel::INFO) {}

void Logger::setLevel(LogLevel level) { currentLevel_ = level; }

void Logger::log(LogLevel level, const std::string &message) {
    if (level < currentLevel_) {
        return;
    }

    std::string timeStr = currentDateTime();
    std::string levelStr = levelToString(level);
    std::string escapedMsg = escapeMessage(message);

    std::lock_guard<std::mutex> lock(mutex_);

    std::ostream &out = (level == LogLevel::ERROR) ? std::cerr : std::cout;
    out << "[" << timeStr << "] [" << levelStr << "] " << escapedMsg << '\n';
    if (level == LogLevel::ERROR) {
        out.flush();
    }
}

void Logger::log(LogLevel level, std::string_view file, int line,
                 const std::string &message) {
    if (level < currentLevel_) {
        return;
    }

    std::string timeStr = currentDateTime();
    std::string levelStr = levelToString(level);
    std::string escapedMsg = escapeMessage(message);

    std::string_view filename = file;
    size_t pos = filename.find_last_of("/\\");
    if (pos != std::string_view::npos) {
        filename = filename.substr(pos + 1);
    }

    std::lock_guard<std::mutex> lock(mutex_);

    std::ostream &out = (level == LogLevel::ERROR) ? std::cerr : std::cout;
    out << "[" << timeStr << "] [" << levelStr << "] " << escapedMsg << '\n';
    if (level == LogLevel::ERROR) {
        out.flush();
    }
}

std::string Logger::currentDateTime() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);

    struct tm timeinfo;
    localtime_r(&in_time_t, &timeinfo);

    std::stringstream ss;
    ss << std::put_time(&timeinfo, "%Y-%m-%d %X");
    return ss.str();
}

std::string Logger::levelToString(LogLevel level) {
    switch (level) {
    case LogLevel::DEBUG:
        return "DEBUG";
    case LogLevel::INFO:
        return "INFO";
    case LogLevel::WARNING:
        return "WARNING";
    case LogLevel::ERROR:
        return "ERROR";
    default:
        return "UNKNOWN";
    }
}
