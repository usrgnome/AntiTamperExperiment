#include "CodeIntegrityMonitor.h"
#include "PayloadApi.h"
#include <cstdio>
#include <memory>

namespace {
IntegrityCallback callback = nullptr;
void OnChange(const void* address, std::size_t size, CodeIntegrityMonitor::Event event) noexcept {
    if (callback) callback(address, size, static_cast<int>(event));
}
}
extern "C" void* StartIntegrity(IntegrityCallback onChange, bool fastTest) {
    callback = onChange;
    auto monitor = std::make_unique<CodeIntegrityMonitor>();
    std::printf("Original SHA-256 monitor: %zu executable bytes, %zu chunks; %s sweep target.\n",
        monitor->byteCount(), monitor->chunkCount(), fastTest ? "100 ms test" : "20 second");
    monitor->start(OnChange, fastTest ? std::chrono::milliseconds(100) : std::chrono::seconds(20));
    return monitor.release();
}
extern "C" void StopIntegrity(void* monitor) noexcept {
    delete static_cast<CodeIntegrityMonitor*>(monitor);
}
