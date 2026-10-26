#pragma once
#include <cstddef>
#include "IntegrityKernelApi.h"
// Keep the loader independent of the monitor implementation and its templates.
// Events 0/1/2 are modified/restored/scan-failed; event 3 is a VEH observation.
// failureReason is zero for hash events and a reason bitmask for event 3.
using IntegrityCallback = void (*)(const void*, std::size_t, int, unsigned failureReason) noexcept;
extern "C" void* StartIntegrity(IntegrityCallback callback, bool fastTest,
    IntegrityChunkCheck check, const void* mappedCode, std::size_t mappedSize);
extern "C" int CheckIntegrityChunk(const IntegrityChunkRequest* request);
extern "C" void StopIntegrity(void* monitor) noexcept;
