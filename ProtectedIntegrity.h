#pragma once
#include "IntegrityKernelApi.h"
#include <cstddef>

// Own this before starting the monitor, and destroy it after joining the worker.
class ProtectedIntegrity {
public:
    ProtectedIntegrity();
    ~ProtectedIntegrity();
    ProtectedIntegrity(const ProtectedIntegrity&) = delete;
    ProtectedIntegrity& operator=(const ProtectedIntegrity&) = delete;
    IntegrityChunkCheck entry() const noexcept { return entry_; }
    const void* data() const noexcept { return view_; }
    std::size_t size() const noexcept { return size_; }
    void verify() const;
private:
    void cleanup() noexcept;
    void* view_ = nullptr;
    std::size_t size_ = 0;
    IntegrityChunkCheck entry_ = nullptr;
    RUNTIME_FUNCTION unwind_{};
    bool registered_ = false;
};
