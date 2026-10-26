#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

inline constexpr unsigned integrityDebugRegisterReason = 0x800;

// Match the requested policy: any nonzero address register, even if DR7 has
// disabled that slot. Missing debug-register context means "not observed".
inline unsigned DebugRegisterFailureReason(const CONTEXT* context) noexcept {
    if (!context ||
        (context->ContextFlags & CONTEXT_DEBUG_REGISTERS) != CONTEXT_DEBUG_REGISTERS)
        return 0;
    return (context->Dr0 || context->Dr1 || context->Dr2 || context->Dr3)
        ? integrityDebugRegisterReason : 0;
}

// One active integrity session. Handler state lives for the process lifetime,
// so an in-flight handler never touches a destroyed session object.
class IntegrityVeh {
public:
    IntegrityVeh();
    ~IntegrityVeh();
    IntegrityVeh(const IntegrityVeh&) = delete;
    IntegrityVeh& operator=(const IntegrityVeh&) = delete;
    void stop() noexcept;
    static unsigned failureReasons() noexcept;
private:
    void* registration_ = nullptr;
};
