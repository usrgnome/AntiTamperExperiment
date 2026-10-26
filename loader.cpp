#define NOMINMAX
#include <Windows.h>
#include "PayloadApi.h"
#include "ProtectedIntegrity.h"
#include "Game.h"
#include "IntegrityStatus.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <stdexcept>

namespace {
IntegrityStatus integrityStatus;
void OnChange(const void* address, std::size_t size, int event, unsigned failureReason) noexcept {
    if (event == 3) {
        integrityStatus.failureReasons.fetch_or(failureReason);
        ++integrityStatus.failed;
        std::printf("[CHECK] failure reason 0x%X: nonzero debug address register in exception context\n",
            failureReason);
        return;
    }
    if (event == 0) ++integrityStatus.modified;
    else if (event == 1) ++integrityStatus.restored;
    else ++integrityStatus.failed;
    std::printf("[CHECK] %p (%zu bytes): %s\n", address, size,
        event == 0 ? "modified" : event == 1 ? "restored" : "SCAN FAILED");
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
        // The protected code outlives the monitor and its worker thread.
        ProtectedIntegrity protectedIntegrity;
        std::printf("Integrity kernel: %p, %zu bytes, MEM_MAPPED RX; permission changes rejected.\n",
            protectedIntegrity.data(), protectedIntegrity.size());
        // Capture both EXE and mapped-code baselines before gameplay.
        MonitorLifetime monitor{StartIntegrity(OnChange, test, protectedIntegrity.entry(),
            protectedIntegrity.data(), protectedIntegrity.size())};
        const int result = Game::Run(test, integrityStatus);
        if (test) {
            protectedIntegrity.verify();
            std::puts("PASS: locked mapped RX integrity kernel, EXE RX/RWX pages, background detection/restoration, gameplay.");
        }
        return result;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "Loader error: %s\n", error.what());
        return 1;
    }
}
