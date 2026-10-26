#include "IntegrityVeh.h"
#include <cstdio>
#include <stdexcept>

namespace {
void Require(bool passed, const char* message) {
    if (!passed) throw std::runtime_error(message);
}

void CheckContexts() {
    Require(DebugRegisterFailureReason(nullptr) == 0, "Null context");
    CONTEXT context{};
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    Require(DebugRegisterFailureReason(&context) == 0, "Zero registers");
    for (unsigned slot = 0; slot < 4; ++slot) {
        context = {};
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        switch (slot) {
        case 0: context.Dr0 = 0x1234; break;
        case 1: context.Dr1 = 0x1234; break;
        case 2: context.Dr2 = 0x1234; break;
        case 3: context.Dr3 = 0x1234; break;
        }
        Require(DebugRegisterFailureReason(&context) == 0x800, "Individual DR slot");
        context.ContextFlags |= CONTEXT_CONTROL;
        Require(DebugRegisterFailureReason(&context) == 0x800, "Additional context flags");
        context.ContextFlags = CONTEXT_CONTROL;
        Require(DebugRegisterFailureReason(&context) == 0, "Debug registers not supplied");
        context.ContextFlags = 0x10; // Missing AMD64 architecture flag.
        Require(DebugRegisterFailureReason(&context) == 0, "Partial context mask");
    }
    context = {};
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    context.Dr6 = 0xffff;
    context.Dr7 = 0xffff;
    Require(DebugRegisterFailureReason(&context) == 0, "DR6/DR7 are outside this policy");
}

void CheckRegistrationLifetime() {
    {
        IntegrityVeh first;
        bool rejected = false;
        try { IntegrityVeh duplicate; }
        catch (const std::logic_error&) { rejected = true; }
        Require(rejected, "Reject concurrent integrity sessions");
        first.stop();
        first.stop(); // Explicit stop and destructor must be safe together.
    }
    IntegrityVeh next; // Destruction releases the singleton claim.
}
}

int main() {
    try {
        CheckContexts();
        CheckRegistrationLifetime();
        std::puts("PASS: debug-register policy and VEH registration lifetime.");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "VEH test failed: %s\n", error.what());
        return 1;
    }
}
