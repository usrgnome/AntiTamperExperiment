#include "CodeIntegrityMonitor.h"
#include "PayloadApi.h"
#include "IntegrityVeh.h"
#include <cstdio>
#include <memory>

namespace {
// This demo has one active monitor. Its worker forwards events to the loader.
IntegrityCallback callback = nullptr;
unsigned reportedReasons = 0; // Accessed by the worker, then after it is joined.
void PublishExceptionFailures() noexcept {
    const unsigned pending = IntegrityVeh::failureReasons() & ~reportedReasons;
    if (pending && callback) {
        reportedReasons |= pending;
        callback(nullptr, 0, 3, pending);
    }
}
void OnChange(const void* address, std::size_t size, CodeIntegrityMonitor::Event event) noexcept {
    if (callback) callback(address, size, static_cast<int>(event), 0);
}

struct IntegritySession {
    // Register before capturing the baseline. Reverse destruction keeps the
    // singleton claim until callback/state teardown has completed.
    IntegrityVeh veh;
    std::unique_ptr<CodeIntegrityMonitor> monitor;
    ~IntegritySession() {
        monitor.reset(); // Join the worker before touching reporter state.
        veh.stop();
        PublishExceptionFailures();
        callback = nullptr;
    }
};
}
extern "C" void* StartIntegrity(IntegrityCallback onChange, bool fastTest,
                               IntegrityChunkCheck check, const void* mappedCode, std::size_t mappedSize) {
    auto session = std::make_unique<IntegritySession>();
    callback = onChange;
    reportedReasons = 0;
    // Discovery/thread ownership live in the EXE. Hashing and baseline comparison
    // execute through 'check', which points into the MEM_MAPPED RX view.
    session->monitor = std::make_unique<CodeIntegrityMonitor>(check, mappedCode, mappedSize);
    std::printf("SHA-256 monitor: %zu executable bytes, %zu chunks.\n",
        session->monitor->byteCount(), session->monitor->chunkCount());
    session->monitor->start(OnChange,
        fastTest ? std::chrono::milliseconds(100) : std::chrono::seconds(20),
        std::chrono::milliseconds(10), PublishExceptionFailures);
    return session.release();
}
extern "C" void StopIntegrity(void* monitor) noexcept {
    // Stop and join the worker before the loader unmaps its checker code.
    delete static_cast<IntegritySession*>(monitor);
}
