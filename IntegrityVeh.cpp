#include "IntegrityVeh.h"
#include <atomic>
#include <exception>
#include <stdexcept>

namespace {
// Latch detections permanently: another exception or monitor restart must not
// silently clear a failure. No allocation, logging, user callbacks or locks
// are allowed in the VEH. This EXE code remains loaded for the process lifetime.
std::atomic<unsigned> reasons{0};
std::atomic<bool> active{false};
static_assert(std::atomic<unsigned>::is_always_lock_free,
              "Exception reporting requires lock-free atomics");

LONG CALLBACK ObserveException(EXCEPTION_POINTERS* pointers) noexcept {
    const unsigned reason = DebugRegisterFailureReason(pointers ? pointers->ContextRecord : nullptr);
    if (reason) reasons.fetch_or(reason, std::memory_order_relaxed);
    // Observe only: do not change registers, swallow faults, or resume execution.
    return EXCEPTION_CONTINUE_SEARCH;
}
}

IntegrityVeh::IntegrityVeh() {
    bool expected = false;
    if (!active.compare_exchange_strong(expected, true))
        throw std::logic_error("Only one integrity session can be active");
    registration_ = AddVectoredExceptionHandler(1, ObserveException);
    if (!registration_) {
        active.store(false);
        throw std::runtime_error("Cannot register integrity exception observer");
    }
}

void IntegrityVeh::stop() noexcept {
    if (registration_) {
        if (!RemoveVectoredExceptionHandler(registration_)) std::terminate();
        registration_ = nullptr;
    }
}

IntegrityVeh::~IntegrityVeh() {
    stop();
    active.store(false);
}

unsigned IntegrityVeh::failureReasons() noexcept {
    return reasons.load(std::memory_order_relaxed);
}
