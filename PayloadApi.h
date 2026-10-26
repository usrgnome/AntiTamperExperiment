#pragma once
#include <cstddef>
// Keep the loader independent of the monitor implementation and its templates.
using IntegrityCallback = void (*)(const void*, std::size_t, int) noexcept;
extern "C" void* StartIntegrity(IntegrityCallback callback, bool fastTest);
extern "C" void StopIntegrity(void* monitor) noexcept;
extern "C" void ImportantGameLogic();
extern "C" int CalculateDamage(int base, int armor);
extern "C" unsigned char GameSentinel;
