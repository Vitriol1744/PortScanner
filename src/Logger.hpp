#pragma once

#include <iostream>
#define FMT_HEADER_ONLY 1
#include <fmt/format.h>

enum class LogLevel
{
    ePlain,
    eTrace,
    eInfo,
    eWarn,
    eError
};

inline constexpr const char* FOREGROUND_COLOR_RED = "\u001b[31m";
inline constexpr const char* FOREGROUND_COLOR_GREEN = "\u001b[32m";
inline constexpr const char* FOREGROUND_COLOR_YELLOW = "\u001b[33m";
inline constexpr const char* FOREGROUND_COLOR_CYAN = "\u001b[36m";
inline constexpr const char* COLOR_RESET = "\u001b[0m";

namespace Logger
{
    inline void Log(LogLevel level, std::string_view msg)
    {
        if (level != LogLevel::ePlain) std::cout << '[';
        switch (level)
        {
            case LogLevel::eTrace:
                std::cout << FOREGROUND_COLOR_GREEN;
                std::cout << "Trace";
                break;
            case LogLevel::eInfo:
                std::cout << FOREGROUND_COLOR_CYAN;
                std::cout << "Info";
                break;
            case LogLevel::eWarn:
                std::cout << FOREGROUND_COLOR_YELLOW;
                std::cout << "Warn";
                break;
            case LogLevel::eError:
                std::cout << FOREGROUND_COLOR_RED;
                std::cout << "Error";
                break;

            default: break;
        }

        if (level != LogLevel::ePlain)
        {
            std::cout << COLOR_RESET;
            std::cout << "]: ";
        }
        std::cout << msg << "\n";
    }
}

#define LogPlain(...) Logger::Log(LogLevel::ePlain, fmt::format(__VA_ARGS__))
#define LogTrace(...) Logger::Log(LogLevel::eTrace, fmt::format(__VA_ARGS__))
#define LogInfo(...)  Logger::Log(LogLevel::eInfo, fmt::format(__VA_ARGS__))
#define LogWarn(...)  Logger::Log(LogLevel::eWarn, fmt::format(__VA_ARGS__))
#define LogError(...) Logger::Log(LogLevel::eError, fmt::format(__VA_ARGS__))
