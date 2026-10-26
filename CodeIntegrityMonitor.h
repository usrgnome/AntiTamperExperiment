// Include this header only once per .cpp file, even if other headers include it.
#pragma once

// Windows normally defines min/max macros. Disable those so they do not
// interfere with C++ functions such as std::min.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <bcrypt.h>
#if defined(_MSC_VER)
// Tell Microsoft's linker where the Windows hashing functions live.
// This is a build instruction; it does not hash anything itself.
#pragma comment(lib, "bcrypt.lib")
#endif
#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>
#include "IntegrityKernelApi.h"

// Hashes every executable PE section in the application's EXE at startup.
// No function registration or instrumentation is required.
//
// The overall process is:
//   1. Locate the machine instructions Windows loaded for this EXE.
//   2. Split them into chunks and remember each chunk's SHA-256 fingerprint.
//   3. On a separate thread, periodically calculate those fingerprints again.
//   4. Report a change if a new fingerprint differs from the startup value.
//
// We detect changed bytes, not the intent behind them. A detour often changes
// instructions to jump somewhere else, but a debugger breakpoint can too.
// DLL code and hooks that change only data pointers are outside this example.
class CodeIntegrityMonitor
{
public:
    // These are the three kinds of notification the caller can receive.
    enum class Event { Modified, Restored, ScanFailed };
    // A function pointer: the caller supplies a function with this signature.
    // We call it when something happens. That is what "callback" means here.
    // void* represents an address without specifying what type lives there.
    // noexcept means the callback promises not to throw C++ exceptions.
    using OnChange = void (*)(const void* address, std::size_t size, Event event) noexcept;
    using OnPoll = void (*)() noexcept;
    // KiB means 1024 bytes, so each full chunk contains 65,536 code bytes.
    // A chunk is just a range of memory; it need not match function boundaries.
    static constexpr std::size_t chunkSize = 64 * 1024;

    // Constructor: runs automatically when you write CodeIntegrityMonitor monitor;
    // Do this during startup, because reading/hashing all code takes time.
    // We trust the code at this moment. A hook already installed becomes part
    // of the baseline and will not be identified as a new change.
    CodeIntegrityMonitor(IntegrityChunkCheck check, const void* mappedCode, std::size_t mappedSize)
        : check_(check)
    {
        if (!check || !mappedCode || !mappedSize)
            throw std::runtime_error("Missing protected integrity kernel");
        // nullptr asks for this process's main EXE, not a DLL. Its "base" is
        // the address where Windows loaded it, which may change between runs.
        // Treating that address as unsigned char* lets us move through bytes.
        const auto* base = reinterpret_cast<const unsigned char*>(GetModuleHandleW(nullptr));
        if (!base) throw std::runtime_error("Cannot locate application module");
        // A Windows EXE uses the PE (Portable Executable) format. Its headers
        // are a table of contents describing the memory Windows loaded.
        // reinterpret_cast views existing memory as a particular header type;
        // it does not copy or convert that memory. We assume a valid loaded EXE.
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            throw std::runtime_error("Invalid DOS header");
        // e_lfanew is the byte offset from the base to the main PE header.
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            throw std::runtime_error("Invalid PE header");
        const auto* sections = IMAGE_FIRST_SECTION(nt);
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            // A section is a region such as code or data. The & makes this a
            // reference to the existing header rather than a separate copy.
            const auto& section = sections[i];
            // & here is bitwise AND: test the "contains executable memory" flag.
            // Skip data sections, textures, heap objects, etc. We look at all
            // executable sections, rather than relying on the name ".text".
            if (!(section.Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
            const std::size_t length = section.Misc.VirtualSize;
            // VirtualAddress is an offset relative to the loaded EXE base.
            // Check the section stays inside the loaded image before reading.
            if (section.VirtualAddress > nt->OptionalHeader.SizeOfImage ||
                length > nt->OptionalHeader.SizeOfImage - section.VirtualAddress)
                throw std::runtime_error("Executable section is outside the module");
            for (std::size_t offset = 0; offset < length; offset += chunkSize)
            {
                Chunk chunk;
                chunk.address = base + section.VirtualAddress + offset;
                // The last chunk may be shorter. Do not read past the section.
                chunk.size = (std::min)(chunkSize, length - offset);
                // SHA-256 reduces this chunk to a 32-byte fingerprint (digest).
                // We store that fingerprint, not a copy of all the code bytes.
                if (hasher_.check(check_, chunk.address, chunk.size, chunk.original, nullptr) != 0)
                    throw std::runtime_error("Cannot hash executable code");
                chunks_.push_back(chunk); // Save its address, length and fingerprint.
                bytes_ += chunk.size;
            }
        }
        if (chunks_.empty()) throw std::runtime_error("No executable sections found");
        // The active kernel is outside the EXE. Scan its code and unwind data too.
        const auto* mapped = static_cast<const unsigned char*>(mappedCode);
        for (std::size_t offset = 0; offset < mappedSize; offset += chunkSize) {
            Chunk chunk;
            chunk.address = mapped + offset;
            chunk.size = (std::min)(chunkSize, mappedSize - offset);
            if (hasher_.check(check_, chunk.address, chunk.size, chunk.original, nullptr) != 0)
                throw std::runtime_error("Cannot hash protected integrity mapping");
            chunks_.push_back(chunk);
            bytes_ += chunk.size;
        }
    }

    // Copying an object that owns a running thread and Windows handles would
    // make ownership confusing. '= delete' forbids those copies at compile time.
    CodeIntegrityMonitor(const CodeIntegrityMonitor&) = delete;
    CodeIntegrityMonitor& operator=(const CodeIntegrityMonitor&) = delete;

    ~CodeIntegrityMonitor()
    {
        // Destructor: on normal scope exit, ask the worker to stop, wake it if
        // sleeping, then wait for it to finish before releasing its resources.
        // The game handles Ctrl+C through normal scope exit. Forced process
        // termination does not guarantee C++ destructor cleanup will run.
        {
            // A mutex allows only one thread at a time into this protected
            // part. Both threads use it when accessing stopping_.
            std::lock_guard<std::mutex> lock(mutex_);
            stopping_ = true;
        }
        wake_.notify_one();
        if (worker_.joinable()) worker_.join(); // join = wait for the thread to finish.
    }

    // These totals are set during construction and never change afterward.
    std::size_t byteCount() const noexcept { return bytes_; }
    std::size_t chunkCount() const noexcept { return chunks_.size(); }

    // Distribute one full sweep across sweepTarget in small scheduled batches.
    // Callback runs only on transitions, on the worker. Keep it brief and
    // never destroy the monitor from its callback. Configure on one thread.
    // sweepTarget is the desired time to revisit all chunks, not a guaranteed
    // deadline. interval is the requested minimum spacing between scheduled wakes.
    // Defaults: aim for 20 seconds per sweep, with a 10 ms minimum interval.
    void start(OnChange onChange, std::chrono::milliseconds sweepTarget = std::chrono::seconds(20),
               std::chrono::milliseconds interval = std::chrono::milliseconds(10),
               OnPoll onPoll = nullptr)
    {
        if (worker_.joinable() || interval.count() <= 0 || sweepTarget < interval)
            throw std::logic_error("Start once with a positive interval <= sweep target");
        // A "slot" is one scheduled wake within a sweep. Do not create more
        // slots than chunks: a tiny EXE can sleep longer between its few checks.
        // Example: 4 chunks / 20 seconds => 4 slots, each 5 seconds apart.
        const auto slots = (std::min)(chunks_.size(),
            static_cast<std::size_t>(sweepTarget / interval));
        interval = sweepTarget / static_cast<std::chrono::milliseconds::rep>(slots);
        // This lambda (an unnamed function) runs on the new worker thread.
        // The capture list keeps the timing/callback values and a pointer to
        // this monitor. The monitor must stay alive until that thread finishes.
        worker_ = std::thread([this, interval, slots, onChange, onPoll] {
            if (onPoll) onPoll();
            std::size_t index = 0;
            std::size_t slot = 0;
            // steady_clock measures elapsed time; changing the wall clock
            // will not move this schedule backward or forward.
            auto next = std::chrono::steady_clock::now() + interval;
            std::unique_lock<std::mutex> lock(mutex_);
            // Sleep without busy-spinning. wait_until releases the mutex while
            // asleep and reacquires it before returning. The predicate checks
            // the stop flag and handles early/spurious wakeups safely.
            // true = stop requested; false = scheduled time reached, do a batch.
            while (!wake_.wait_until(lock, next, [this] { return stopping_; }))
            {
                // No need to hold the stop mutex during hashing or callbacks.
                // Only this worker changes chunk state after startup.
                lock.unlock();
                // Drain exception observations on a normal thread, outside the
                // VEH and outside the monitor mutex, before each hash batch.
                if (onPoll) onPoll();
                // Fractional distribution avoids rescanning small EXEs on
                // every wake. Over 'slots' wakes, each chunk is checked once.
                const auto batch = chunks_.size() / slots +
                    (slot < chunks_.size() % slots ? 1 : 0);
                // Integer / gives the base batch size; % gives the remainder.
                // For 10 chunks and 3 slots the batches are 4, 3, 3.
                for (std::size_t n = 0; n < batch; ++n)
                {
                    auto& chunk = chunks_[index];
                    std::array<unsigned char, 32> digest{}; // Fixed-size local storage.
                    const int result = hasher_.check(check_, chunk.address, chunk.size, digest,
                                                     chunk.original.data());
                    if (result != 0 && result != 1)
                    {
                        if (onChange) onChange(chunk.address, chunk.size, Event::ScanFailed);
                        return; // Leave the worker; do not silently claim code is valid.
                    }
                    const bool modified = result == 1;
                    // Report transitions, not the same warning every sweep.
                    // unchanged -> modified: alert; modified -> unchanged: restored.
                    // Another patch inside an already modified chunk is not a
                    // new transition, so it does not generate another alert.
                    if (modified != chunk.modified)
                    {
                        chunk.modified = modified;
                        if (onChange) onChange(chunk.address, chunk.size,
                                              modified ? Event::Modified : Event::Restored);
                    }
                    index = (index + 1) % chunks_.size(); // Wrap to the first chunk at the end.
                }
                slot = (slot + 1) % slots;
                next += interval;
                // Do not run catch-up bursts if scheduling/scanning falls behind.
                // Favor smooth work over meeting the deadline at any cost.
                // Heavy load can therefore push a sweep beyond 20 or 30 seconds.
                const auto now = std::chrono::steady_clock::now();
                if (next <= now) next = now + interval;
                lock.lock();
            }
        });
    }

private:
    // Private helpers and state are implementation details, not caller settings.
    // Windows owns the reusable hash object's workspace. Allocate once,
    // then reuse it serially for baseline creation and background scanning.
    class Hasher
    {
    public:
        Hasher()
        {
            // Open Windows' SHA-256 implementation. BCrypt is the Windows
            // cryptography API here, not the similarly named password hash.
            // These APIs return a negative status on failure.
            if (BCryptOpenAlgorithmProvider(&algorithm_, BCRYPT_SHA256_ALGORITHM,
                                            nullptr, 0) < 0)
                throw std::runtime_error("Cannot open SHA-256 provider");
            // Create reusable working state once. nullptr/0 asks Windows to
            // allocate its workspace; there is no secret key for this hash.
            if (BCryptCreateHash(algorithm_, &hash_, nullptr, 0, nullptr, 0,
                                 BCRYPT_HASH_REUSABLE_FLAG) < 0)
            {
                // If setup fails halfway through, release the provider we
                // already opened before throwing the exception.
                BCryptCloseAlgorithmProvider(algorithm_, 0);
                throw std::runtime_error("Cannot create reusable SHA-256 hash");
            }
        }
        ~Hasher()
        {
            // Release resources in reverse order: hash first, provider second.
            BCryptDestroyHash(hash_);
            BCryptCloseAlgorithmProvider(algorithm_, 0);
        }
        int check(IntegrityChunkCheck kernel, const unsigned char* data, std::size_t size,
                  std::array<unsigned char, 32>& output, const unsigned char* baseline) noexcept
        {
            IntegrityChunkRequest request{hash_, &BCryptHashData, &BCryptFinishHash,
                data, static_cast<ULONG>(size), output.data(), baseline};
            return kernel(&request);
        }
    private:
        BCRYPT_ALG_HANDLE algorithm_ = nullptr;
        BCRYPT_HASH_HANDLE hash_ = nullptr;
    };

    struct Chunk
    {
        const unsigned char* address = nullptr;      // Start of this code range.
        std::array<unsigned char, 32> original{};    // Trusted startup fingerprint.
        std::size_t size = 0;                        // Number of bytes to hash.
        bool modified = false;                      // Last reported comparison state.
    };
    // Members are created before the constructor body. hasher_ is therefore
    // ready when the constructor hashes the first code chunk.
    IntegrityChunkCheck check_;
    Hasher hasher_;
    std::vector<Chunk> chunks_;             // Growable list, filled only at startup.
    std::size_t bytes_ = 0;                 // Total code bytes, not process RAM usage.
    std::mutex mutex_;                     // Protects the shared shutdown flag.
    std::condition_variable wake_;         // Lets shutdown interrupt the sleep.
    bool stopping_ = false;                // Access only while holding mutex_.
    std::thread worker_;                   // Owns the background scanning thread.
};
