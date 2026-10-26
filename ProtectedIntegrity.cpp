#define NOMINMAX
#include "ProtectedIntegrity.h"
#include "PayloadApi.h"
#include <cstring>
#include <exception>
#include <initializer_list>
#include <stdexcept>

// Technique reference: changeofpace/Self-Remapping-Code (remap.cpp).
// This implementation creates one isolated view; it never unmaps the EXE.
// SEC_NO_CHANGE is a native, undocumented contract, checked at startup below.
namespace {
constexpr ULONG noChange = 0x00400000;
constexpr LONG invalidProtection = static_cast<LONG>(0xC0000045u);
using CreateSection = LONG(NTAPI*)(PHANDLE, ACCESS_MASK, void*, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
using MapSection = LONG(NTAPI*)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T,
                              PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
using UnmapSection = LONG(NTAPI*)(HANDLE, PVOID);
using ProtectMemory = LONG(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

template<class T> T Native(const char* name) {
    const auto module = GetModuleHandleW(L"ntdll.dll");
    const auto address = module ? GetProcAddress(module, name) : nullptr;
    if (!address) throw std::runtime_error("Required native mapping API unavailable");
    return reinterpret_cast<T>(address);
}
struct SectionOwner {
    HANDLE handle = nullptr;
    ~SectionOwner() { if (handle) CloseHandle(handle); }
};
struct ViewOwner {
    UnmapSection unmap;
    void* address = nullptr;
    ~ViewOwner() { if (address) unmap(GetCurrentProcess(), address); }
};
}

ProtectedIntegrity::ProtectedIntegrity() {
    try {
        const auto create = Native<CreateSection>("NtCreateSection");
        const auto map = Native<MapSection>("NtMapViewOfSection");
        const auto unmap = Native<UnmapSection>("NtUnmapViewOfSection");
        const auto* image = reinterpret_cast<const unsigned char*>(GetModuleHandleW(nullptr));
        if (!image) throw std::runtime_error("Cannot locate integrity source image");
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image + dos->e_lfanew);
        const auto* sections = IMAGE_FIRST_SECTION(nt);
        const IMAGE_SECTION_HEADER* source = nullptr;
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i)
            if (!std::strncmp(reinterpret_cast<const char*>(sections[i].Name), ".integr", 8))
                source = &sections[i];
        if (!source || !source->Misc.VirtualSize ||
            source->VirtualAddress > nt->OptionalHeader.SizeOfImage ||
            source->Misc.VirtualSize > nt->OptionalHeader.SizeOfImage - source->VirtualAddress)
            throw std::runtime_error("Invalid integrity code section");

        const auto originalEntry = reinterpret_cast<DWORD64>(&CheckIntegrityChunk);
        DWORD64 unwindBase = 0;
        const auto* function = RtlLookupFunctionEntry(originalEntry, &unwindBase, nullptr);
        const DWORD start = source->VirtualAddress;
        const DWORD length = source->Misc.VirtualSize;
        if (!function || unwindBase != reinterpret_cast<DWORD64>(image) ||
            originalEntry != unwindBase + function->BeginAddress ||
            function->BeginAddress < start || function->EndAddress <= function->BeginAddress ||
            function->EndAddress > start + length)
            throw std::runtime_error("Unsupported integrity function layout");
        // Only simple unwind records are supported: no handlers or chained entries.
        // The copied function uses plain calls through the request and no C++ EH.
        const DWORD unwindRva = function->UnwindData;
        if (nt->OptionalHeader.SizeOfImage < 4 ||
            unwindRva > nt->OptionalHeader.SizeOfImage - 4)
            throw std::runtime_error("Invalid integrity unwind record");
        const auto* metadata = image + unwindRva;
        if (metadata[0] != 1)
            throw std::runtime_error("Integrity kernel needs simple version-1 unwind metadata");
        const std::size_t metadataSize = (4 + 2 * static_cast<std::size_t>(metadata[2]) + 3) & ~std::size_t(3);
        if (metadataSize > nt->OptionalHeader.SizeOfImage - unwindRva)
            throw std::runtime_error("Integrity unwind record exceeds image");
        const std::size_t metadataOffset = (static_cast<std::size_t>(length) + 3) & ~std::size_t(3);
        if (metadataOffset + metadataSize > MAXDWORD)
            throw std::runtime_error("Integrity mapping is too large");
        size_ = metadataOffset + metadataSize;

        SectionOwner section;
        LARGE_INTEGER maximum{};
        maximum.QuadPart = static_cast<LONGLONG>(size_);
        if (create(&section.handle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
                   nullptr, &maximum, PAGE_EXECUTE_READWRITE, SEC_COMMIT | noChange, nullptr) < 0)
            throw std::runtime_error("Cannot create protected integrity section");
        ViewOwner staging{unmap};
        SIZE_T stagingSize = size_;
        if (map(section.handle, GetCurrentProcess(), &staging.address, 0, 0, nullptr,
                &stagingSize, 2 /* ViewUnmap */, 0, PAGE_READWRITE) < 0)
            throw std::runtime_error("Cannot create integrity staging view");
        std::memcpy(staging.address, image + start, length);
        std::memcpy(static_cast<unsigned char*>(staging.address) + metadataOffset, metadata, metadataSize);
        // There must be no surviving writable alias of the final code.
        if (unmap(GetCurrentProcess(), staging.address) < 0)
            throw std::runtime_error("Cannot remove writable integrity staging view");
        staging.address = nullptr;
        SIZE_T mappedSize = size_;
        if (map(section.handle, GetCurrentProcess(), &view_, 0, 0, nullptr,
                &mappedSize, 2 /* ViewUnmap */, noChange, PAGE_EXECUTE_READ) < 0)
            throw std::runtime_error("Cannot map locked RX integrity code");
        if (!FlushInstructionCache(GetCurrentProcess(), view_, size_))
            throw std::runtime_error("Cannot flush integrity instruction cache");
        unwind_ = {function->BeginAddress - start, function->EndAddress - start,
                   static_cast<DWORD>(metadataOffset)};
        if (!RtlAddFunctionTable(&unwind_, 1, reinterpret_cast<DWORD64>(view_)))
            throw std::runtime_error("Cannot register integrity unwind metadata");
        registered_ = true;
        entry_ = reinterpret_cast<IntegrityChunkCheck>(
            static_cast<unsigned char*>(view_) + unwind_.BeginAddress);
        verify();
        // section's handle closes here. Only the RX view survives construction.
    } catch (...) {
        cleanup();
        throw;
    }
}

void ProtectedIntegrity::verify() const {
    const auto protect = Native<ProtectMemory>("NtProtectVirtualMemory");
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    for (std::size_t offset = 0; offset < size_; offset += system.dwPageSize) {
        auto* page = static_cast<unsigned char*>(view_) + offset;
        MEMORY_BASIC_INFORMATION info{};
        if (!VirtualQuery(page, &info, sizeof(info)) || info.State != MEM_COMMIT ||
            info.Type != MEM_MAPPED || info.Protect != PAGE_EXECUTE_READ || info.AllocationBase != view_)
            throw std::runtime_error("Integrity view is not mapped RX memory");
        // Require the specific refusal, rather than interpreting any API failure
        // as evidence of protection. Probe both writable permission variants.
        for (ULONG requested : {PAGE_READWRITE, PAGE_EXECUTE_READWRITE}) {
            void* address = page;
            SIZE_T bytes = system.dwPageSize;
            ULONG previous = 0;
            const LONG status = protect(GetCurrentProcess(), &address, &bytes, requested, &previous);
            if (status >= 0) {
                ULONG ignored = 0;
                protect(GetCurrentProcess(), &address, &bytes, previous, &ignored);
                throw std::runtime_error("Integrity page protections are not locked");
            }
            if (status != invalidProtection)
                throw std::runtime_error("Unexpected status probing integrity protection");
        }
    }
}

void ProtectedIntegrity::cleanup() noexcept {
    if (registered_) {
        // A stale function table must never outlive its backing allocation.
        if (!RtlDeleteFunctionTable(&unwind_)) std::terminate();
        registered_ = false;
    }
    if (view_) {
        const auto unmap = reinterpret_cast<UnmapSection>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtUnmapViewOfSection"));
        if (!unmap || unmap(GetCurrentProcess(), view_) < 0) std::terminate();
        view_ = nullptr;
    }
}
ProtectedIntegrity::~ProtectedIntegrity() { cleanup(); }
