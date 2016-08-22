#ifndef SIMPLEBENCHMARK_HPP
#define SIMPLEBENCHMARK_HPP

// std::chrono (-std=c++0x)
#include <chrono>

class simplebenchmark {
public:
    simplebenchmark( bool record_start_time = false )
    {
        // record start time as soon as object is created, if start==TRUE
        if ( record_start_time )
            start_time = std::chrono::high_resolution_clock::now();
    }

    void start()
    {
        // explicity record start_time 
        start_time = std::chrono::high_resolution_clock::now();
    }

    void stop()
    {
        // record stop_time 
        stop_time = std::chrono::high_resolution_clock::now();
    }

    long int getResult()
    {
        // return diff in milliseconds
        return std::chrono::duration_cast<std::chrono::milliseconds>
                                         (stop_time-start_time).count();
    }

private:
    // to track start time and stop time
    std::chrono::high_resolution_clock::time_point start_time, stop_time;
};

#endif
