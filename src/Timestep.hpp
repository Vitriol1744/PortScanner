#pragma once

class Timestep
{
    public:
        inline Timestep() = default;
        inline Timestep(double seconds)
        {
            if (seconds < 0.0f) seconds = 0.0f;
            this->seconds = seconds;
        }

        inline double Seconds() noexcept { return seconds; }
        inline double Milliseconds() noexcept { return Seconds() * 1000; }
        inline double Microseconds() noexcept { return Milliseconds() * 1000; }
        inline double Nanoseconds() noexcept { return Microseconds() * 1000; }

        void operator=(const Timestep& timestep) { seconds = timestep.seconds; }
        void operator=(const double seconds) { this->seconds = seconds; }
        friend Timestep operator+(Timestep lhs, Timestep rhs)
        {
            return Timestep(lhs.seconds + rhs.seconds);
        }
        friend Timestep operator-(Timestep lhs, Timestep rhs)
        {
            return Timestep(lhs.seconds - rhs.seconds);
        }

    private:
        double seconds;
};
