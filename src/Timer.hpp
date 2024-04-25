#pragma once

#include "Timestep.hpp"

#include <cstdint>
#include <time.h>

inline double getCurrentTime()
{
    timespec currentTime{};
    clock_gettime(CLOCK_MONOTONIC, &currentTime);

    uint64_t time = static_cast<uint64_t>(currentTime.tv_sec) * 1000000 + currentTime.tv_nsec / 1000;

    return static_cast<double>(time / 1000000.0);
}

class Timer
{
    public:
        Timer() { Restart(); }

        inline void Restart() { start = getCurrentTime(); }
        inline Timestep Elapsed() const { return getCurrentTime() - start; }

    private:
        Timestep start;
};
