#pragma once

#include <atomic>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>

enum class LogLevel { DEBUG, INFO, WARNING, ERROR };

class Logger {
  public:
    static Logger &getInstance();

    // Delete copy constructor and assignment operator to ensure singleton
    Logger(const Logger &) = delete;
    Logger &operator=(const Logger &) = delete;

    void setLevel(LogLevel level);
    bool shouldLog(LogLevel level) const {
        return level >= currentLevel_.load();
    }

    void log(LogLevel level, const std::string &message);
    void log(LogLevel level, std::string_view file, int line,
             const std::string &message);

  private:
    Logger();
    ~Logger() = default;

    std::string currentDateTime();
    std::string levelToString(LogLevel level);

    std::atomic<LogLevel> currentLevel_;
    std::mutex mutex_;
};

// Macros for easier usage and capturing file/line info
#define LOG_DEBUG(msg)                                                         \
    do {                                                                       \
        if (Logger::getInstance().shouldLog(LogLevel::DEBUG)) {                \
            std::ostringstream oss;                                            \
            oss << msg;                                                        \
            Logger::getInstance().log(LogLevel::DEBUG, __FILE__, __LINE__,     \
                                      oss.str());                              \
        }                                                                      \
    } while (0)
#define LOG_INFO(msg)                                                          \
    do {                                                                       \
        if (Logger::getInstance().shouldLog(LogLevel::INFO)) {                 \
            std::ostringstream oss;                                            \
            oss << msg;                                                        \
            Logger::getInstance().log(LogLevel::INFO, __FILE__, __LINE__,      \
                                      oss.str());                              \
        }                                                                      \
    } while (0)
#define LOG_WARNING(msg)                                                       \
    do {                                                                       \
        if (Logger::getInstance().shouldLog(LogLevel::WARNING)) {              \
            std::ostringstream oss;                                            \
            oss << msg;                                                        \
            Logger::getInstance().log(LogLevel::WARNING, __FILE__, __LINE__,   \
                                      oss.str());                              \
        }                                                                      \
    } while (0)
#define LOG_ERROR(msg)                                                         \
    do {                                                                       \
        if (Logger::getInstance().shouldLog(LogLevel::ERROR)) {                \
            std::ostringstream oss;                                            \
            oss << msg;                                                        \
            Logger::getInstance().log(LogLevel::ERROR, __FILE__, __LINE__,     \
                                      oss.str());                              \
        }                                                                      \
    } while (0)
