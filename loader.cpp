#define NOMINMAX
#include <Windows.h>
#include "PayloadApi.h"
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <stdexcept>

namespace {
volatile LONG stopping = 0;
std::atomic<unsigned> modified{0}, restored{0}, failed{0};
BOOL WINAPI Stop(DWORD event) {
    if (event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT) return FALSE;
    InterlockedExchange(&stopping, 1);
    return TRUE;
}
void OnChange(const void* address, std::size_t size, int event) noexcept {
    if (event == 0) ++modified;
    else if (event == 1) ++restored;
    else ++failed;
    std::printf("[CHECK] %p (%zu bytes): %s\n", address, size,
        event == 0 ? "modified" : event == 1 ? "restored" : "SCAN FAILED");
}
bool WaitFor(const std::atomic<unsigned>& counter) {
    const auto deadline = GetTickCount64() + 3000;
    while (!counter.load() && !failed.load() && GetTickCount64() < deadline) Sleep(10);
    return counter.load() != 0 && !failed.load();
}

// Windows has already mapped the EXE. Decrypt its actual code sections in place.
void DecryptSection(const char* name, DWORD finalProtection) {
    auto* base = reinterpret_cast<unsigned char*>(GetModuleHandleW(nullptr));
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    const auto* sections = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const auto& section = sections[i];
        if (std::strncmp(reinterpret_cast<const char*>(section.Name), name, 8)) continue;
        auto* code = base + section.VirtualAddress;
        const auto size = section.Misc.VirtualSize;
        const auto encryptedSize = (std::min)(size, section.SizeOfRawData);
        // Packer marks encrypted sections with a private marker in this unused PE field.
        if (section.PointerToLinenumbers != 0x584F5231 || !size)
            throw std::runtime_error("EXE is not sealed; run the packaged build output");
        DWORD previous = 0;
        if (!VirtualProtect(code, size, PAGE_READWRITE, &previous))
            throw std::runtime_error("Cannot make section writable for decryption");
        for (DWORD offset = 0; offset < encryptedSize; ++offset) code[offset] ^= 0xA7;
        if (!VirtualProtect(code, size, finalProtection, &previous) ||
            !FlushInstructionCache(GetCurrentProcess(), code, size))
            throw std::runtime_error("Cannot finalize section permissions");
        // Check all pages, not just the first page in the section.
        for (std::size_t offset = 0; offset < size;) {
            MEMORY_BASIC_INFORMATION info{};
            if (!VirtualQuery(code + offset, &info, sizeof(info)) || info.Protect != finalProtection ||
                info.Type != MEM_IMAGE || info.AllocationBase != base)
                throw std::runtime_error("Incorrect EXE page protection or mapping");
            offset = static_cast<unsigned char*>(info.BaseAddress) + info.RegionSize - code;
        }
        std::printf("%s: %p, %lu bytes, %s, EXE image pages\n", name, code,
            static_cast<unsigned long>(size), finalProtection == PAGE_EXECUTE_READ ? "RX" : "RWX");
        return;
    }
    throw std::runtime_error("Missing encrypted EXE section");
}
struct MonitorLifetime {
    void* monitor;
    ~MonitorLifetime() { StopIntegrity(monitor); }
};
}

int main(int argc, char** argv) {
    try {
        const bool test = argc == 2 && std::strcmp(argv[1], "--self-test") == 0;
        if (argc > 1 && !test) throw std::runtime_error("Usage: detour_check [--self-test]");
        DecryptSection(".integr", PAGE_EXECUTE_READ);
        DecryptSection(".game", PAGE_EXECUTE_READWRITE);
        // Baseline creation must follow decryption and precede gameplay.
        MonitorLifetime monitor{StartIntegrity(OnChange, test)};
        std::printf("ImportantGameLogic: %p; CalculateDamage: %p\n",
            reinterpret_cast<void*>(&ImportantGameLogic), reinterpret_cast<void*>(&CalculateDamage));
        if (test) {
            ImportantGameLogic();
            if (CalculateDamage(100, 25) != 75 || CalculateDamage(10, 25) != 0)
                throw std::runtime_error("Game execution test failed");
            Sleep(200);
            if (modified.load() || failed.load()) throw std::runtime_error("Unchanged code reported modified");
            GameSentinel ^= 1;
            const bool detected = WaitFor(modified);
            GameSentinel ^= 1;
            if (!detected || !WaitFor(restored)) throw std::runtime_error("SHA-256 modification/restoration test failed");
            std::puts("PASS: EXE image RX/RWX pages, original monitor, background detection/restoration, gameplay.");
            return 0;
        }
        if (!SetConsoleCtrlHandler(Stop, TRUE)) throw std::runtime_error("Cannot register Ctrl+C handler");
        std::puts("Baseline captured; background 20-second sweep target. Ctrl+C exits.");
        while (!InterlockedCompareExchange(&stopping, 0, 0)) {
            ImportantGameLogic();
            std::printf("Damage: %d\n", CalculateDamage(100, 25));
            std::fflush(stdout);
            Sleep(1000);
        }
        SetConsoleCtrlHandler(Stop, FALSE);
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "Loader error: %s\n", error.what());
        return 1;
    }
}
