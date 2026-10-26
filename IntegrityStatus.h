#pragma once
#include <atomic>

// Notifications published by the monitor; consumers only read these counters.
struct IntegrityStatus {
    std::atomic<unsigned> modified{0};
    std::atomic<unsigned> restored{0};
    std::atomic<unsigned> failed{0};
    std::atomic<unsigned> failureReasons{0};
};
