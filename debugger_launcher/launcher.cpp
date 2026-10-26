#define NOMINMAX
#include <Windows.h>
#include <algorithm>
#include "Pattern.h"
#include <cstdio>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>

// Source-only lab debugger for this repository's distributed x64 EXE.
// Scans the decrypted .game section for an instruction signature. No PDB,
// printed address, injected DLL, code patch, or integrity-state change is used.
static_assert(sizeof(void*) == 8, "Build this launcher for x64");

namespace {
[[noreturn]] void WinError(const char* operation) {
    const DWORD error = GetLastError();
    throw std::runtime_error(std::string(operation) + " failed (Win32 " + std::to_string(error) + ")");
}
void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

class Handle {
public:
    explicit Handle(HANDLE value = nullptr) noexcept : value_(value) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE get() const noexcept { return value_; }
    void reset(HANDLE value = nullptr) noexcept {
        if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_);
        value_ = value;
    }
private:
    HANDLE value_;
};

volatile LONG interrupted = 0;
BOOL WINAPI ConsoleControl(DWORD event) {
    if (event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT) return FALSE;
    InterlockedExchange(&interrupted, 1);
    return TRUE;
}
struct ConsoleControlLifetime {
    ConsoleControlLifetime() {
        if (!SetConsoleCtrlHandler(ConsoleControl, TRUE)) WinError("SetConsoleCtrlHandler");
    }
    ~ConsoleControlLifetime() { SetConsoleCtrlHandler(ConsoleControl, FALSE); }
};

template<class T> T ReadRemote(HANDLE process, ULONG_PTR address) {
    T value{};
    SIZE_T read = 0;
    if (!ReadProcessMemory(process, reinterpret_cast<const void*>(address), &value, sizeof(value), &read))
        WinError("ReadProcessMemory(PE headers)");
    Require(read == sizeof(value), "Incomplete PE header read");
    return value;
}

struct GameSection {
    ULONG_PTR imageBase = 0;
    ULONG_PTR begin = 0;
    ULONG_PTR end = 0;
    void discover(HANDLE process, ULONG_PTR base) {
        const auto dos = ReadRemote<IMAGE_DOS_HEADER>(process, base);
        Require(dos.e_magic == IMAGE_DOS_SIGNATURE && dos.e_lfanew > 0 && dos.e_lfanew < 0x100000,
                "Invalid DOS header");
        const auto nt = ReadRemote<IMAGE_NT_HEADERS64>(process, base + dos.e_lfanew);
        Require(nt.Signature == IMAGE_NT_SIGNATURE && nt.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 &&
                nt.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
                nt.FileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER64) &&
                nt.FileHeader.NumberOfSections <= 96, "Expected a native x64 PE image");
        const ULONG_PTR table = base + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
        bool integrityFound = false;
        for (unsigned i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
            const auto section = ReadRemote<IMAGE_SECTION_HEADER>(process, table + i * sizeof(IMAGE_SECTION_HEADER));
            const std::string_view name(reinterpret_cast<const char*>(section.Name), 8);
            if (name == std::string_view(".integr\0", 8)) integrityFound = true;
            if (name != std::string_view(".game\0\0\0", 8)) continue;
            Require(!begin && section.Misc.VirtualSize &&
                    (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                    section.VirtualAddress <= nt.OptionalHeader.SizeOfImage &&
                    section.Misc.VirtualSize <= nt.OptionalHeader.SizeOfImage - section.VirtualAddress,
                    "Invalid game section");
            begin = base + section.VirtualAddress;
            end = begin + section.Misc.VirtualSize;
        }
        Require(begin && integrityFound && end - begin <= 16 * 1024 * 1024,
                "Expected this lab's .game and .integr sections (game size <= 16 MiB)");
        imageBase = base;
    }
    void validate(HANDLE process, ULONG_PTR address) const {
        Require(address >= begin && address < end, "Matched function is outside the game section");
        MEMORY_BASIC_INFORMATION info{};
        if (!VirtualQueryEx(process, reinterpret_cast<const void*>(address), &info, sizeof(info)))
            WinError("VirtualQueryEx");
        Require(info.State == MEM_COMMIT && info.Type == MEM_IMAGE &&
                reinterpret_cast<ULONG_PTR>(info.AllocationBase) == imageBase &&
                info.Protect == PAGE_EXECUTE_READWRITE, "Game mapping does not match the lab's RWX image");
    }
    ULONG_PTR find(HANDLE process, const std::vector<int>& pattern) const {
        // Call while the main thread is suspended, so it cannot be halfway
        // through decrypting the section. Initial ciphertext simply won't match.
        MEMORY_BASIC_INFORMATION info{};
        if (!VirtualQueryEx(process, reinterpret_cast<const void*>(begin), &info, sizeof(info)))
            WinError("VirtualQueryEx(game scan)");
        if (info.State != MEM_COMMIT || info.Protect != PAGE_EXECUTE_READWRITE) return 0;
        std::vector<unsigned char> bytes(static_cast<std::size_t>(end - begin));
        SIZE_T read = 0;
        if (!ReadProcessMemory(process, reinterpret_cast<const void*>(begin), bytes.data(), bytes.size(), &read))
            WinError("ReadProcessMemory(game scan)");
        Require(read == bytes.size(), "Incomplete game section scan");
        const auto matches = FindPattern(bytes, pattern);
        Require(matches.size() < 2, "Signature is ambiguous; supply a more specific function-entry signature");
        return matches.empty() ? 0 : begin + matches.front();
    }
};

struct Output {
    std::string partial;
    bool failure = false;
    bool kernelReady = false;
    bool baselineReady = false;

    void line(std::string_view text) {
        if (text.find("[CHECK]") != std::string_view::npos ||
            text.find("Loader error:") != std::string_view::npos) failure = true;
        if (text.find("permission changes rejected.") != std::string_view::npos) kernelReady = true;
        if (text.find("Baseline captured;") != std::string_view::npos) baselineReady = true;
    }
    void drain(HANDLE pipe) {
        for (;;) {
            DWORD available = 0;
            if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr)) {
                if (GetLastError() == ERROR_BROKEN_PIPE) return;
                WinError("PeekNamedPipe");
            }
            if (!available) return;
            char bytes[4096];
            DWORD read = 0;
            if (!ReadFile(pipe, bytes, (std::min)(available, static_cast<DWORD>(sizeof(bytes))), &read, nullptr))
                WinError("ReadFile(child output)");
            Require(read != 0, "Unexpected empty pipe read");
            std::fwrite(bytes, 1, read, stdout);
            std::fflush(stdout);
            partial.append(bytes, read);
            for (;;) {
                const auto newline = partial.find('\n');
                if (newline == std::string::npos) break;
                line(std::string_view(partial.data(), newline));
                partial.erase(0, newline + 1);
            }
            Require(partial.size() <= 65536, "Child output line exceeds limit");
        }
    }
};

class SuspendedThread {
public:
    explicit SuspendedThread(HANDLE thread) : thread_(thread) {
        if (SuspendThread(thread_) == MAXDWORD) WinError("SuspendThread");
    }
    ~SuspendedThread() { if (thread_) ResumeThread(thread_); }
    void resume() {
        if (ResumeThread(thread_) == MAXDWORD) WinError("ResumeThread");
        thread_ = nullptr;
    }
private:
    HANDLE thread_;
};

struct Breakpoint {
    ULONG_PTR address = 0;
    DWORD64 savedDr0 = 0, savedSlot = 0;
    bool armed = false;
    unsigned hits = 0;
    static constexpr DWORD64 slotMask = 3ull | (15ull << 16);
    static CONTEXT context(HANDLE thread) {
        CONTEXT result{};
        result.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(thread, &result)) WinError("GetThreadContext");
        return result;
    }
    static void set(HANDLE thread, const CONTEXT& value) {
        if (!SetThreadContext(thread, &value)) WinError("SetThreadContext");
    }
    void arm(HANDLE thread, ULONG_PTR target) {
        // Caller holds a suspension across both the signature scan and arming.
        auto ctx = context(thread);
        Require(!ctx.Dr0 && !ctx.Dr1 && !ctx.Dr2 && !ctx.Dr3 && !(ctx.Dr7 & 0xff),
                "The game thread already has debug-register state; refusing to overwrite it");
        address = target;
        savedDr0 = ctx.Dr0;
        savedSlot = ctx.Dr7 & slotMask;
        ctx.Dr0 = address;
        ctx.Dr6 &= ~1ull;
        ctx.Dr7 = (ctx.Dr7 & ~slotMask) | 1ull; // L0=1, execution, length=1.
        set(thread, ctx);
        armed = true;
        const auto actual = context(thread);
        Require(actual.Dr0 == address && (actual.Dr7 & slotMask) == 1,
                "Windows did not retain the requested hardware breakpoint");
        std::printf("[launcher] Armed DR0 at %p on the game thread.\n", reinterpret_cast<void*>(address));
    }
    void restore(CONTEXT& ctx) const {
        ctx.Dr0 = savedDr0;
        ctx.Dr7 = (ctx.Dr7 & ~slotMask) | savedSlot;
        ctx.Dr6 &= ~1ull;
    }
    bool handle(HANDLE thread, const EXCEPTION_DEBUG_INFO& exception, unsigned limit) {
        if (!armed || !exception.dwFirstChance || exception.ExceptionRecord.ExceptionCode != EXCEPTION_SINGLE_STEP)
            return false;
        auto ctx = context(thread); // A debug event has stopped the process.
        if (ctx.Rip != address || ctx.Dr0 != address || !(ctx.Dr6 & 1) ||
            (ctx.Dr6 & (0xeull | (7ull << 13)))) return false;
        ++hits;
        ctx.Dr6 &= ~1ull;
        // RF permits the faulting instruction to execute once without immediately
        // retriggering this execution breakpoint. Do not set the single-step flag.
        ctx.EFlags |= 1u << 16;
        if (hits == limit) restore(ctx);
        set(thread, ctx);
        if (hits == limit) armed = false;
        std::printf("[launcher] Hardware breakpoint hit %u/%u; handled before application VEH.\n", hits, limit);
        return true;
    }
    void disarm(HANDLE thread) {
        if (!armed) return;
        SuspendedThread suspended(thread);
        auto ctx = context(thread);
        restore(ctx);
        set(thread, ctx);
        armed = false;
        suspended.resume();
    }
};

int Run(const std::filesystem::path& executable, unsigned requestedHits, unsigned observationSeconds,
        const std::vector<int>& pattern) {
    Require(GetConsoleCP() != 0, "Run this console launcher from a terminal (graceful Ctrl+Break needs a console)");
    ConsoleControlLifetime console;
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    HANDLE readEnd = nullptr, writeEnd = nullptr;
    if (!CreatePipe(&readEnd, &writeEnd, &security, 65536)) WinError("CreatePipe");
    Handle outputRead(readEnd), outputWrite(writeEnd);
    if (!SetHandleInformation(outputRead.get(), HANDLE_FLAG_INHERIT, 0)) WinError("SetHandleInformation");
    Handle input(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             &security, OPEN_EXISTING, 0, nullptr));
    if (input.get() == INVALID_HANDLE_VALUE) WinError("CreateFile(NUL)");
    Handle job(CreateJobObjectW(nullptr, nullptr));
    if (!job.get()) WinError("CreateJobObject");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
        WinError("SetInformationJobObject");

    const auto path = std::filesystem::absolute(executable);
    const auto directory = path.parent_path().wstring();
    std::wstring command = L"\"" + path.wstring() + L"\"";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = input.get();
    startup.hStdOutput = outputWrite.get();
    startup.hStdError = outputWrite.get();
    PROCESS_INFORMATION child{};
    if (!CreateProcessW(path.c_str(), command.data(), nullptr, nullptr, TRUE,
            DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP,
            nullptr, directory.c_str(), &startup, &child)) WinError("CreateProcess");
    Handle process(child.hProcess), mainThread(child.hThread);
    if (!AssignProcessToJobObject(job.get(), process.get())) {
        const DWORD error = GetLastError();
        TerminateProcess(process.get(), 1); // Only the child this launcher created.
        SetLastError(error);
        WinError("AssignProcessToJobObject");
    }
    // The job kills this owned child on any error, including a pending debug event.
    // Debug-event process/thread handles are OS-owned until their exit events;
    // PROCESS_INFORMATION handles above are separately owned by this scope.
    outputWrite.reset();
    input.reset();
    if (ResumeThread(mainThread.get()) == MAXDWORD) WinError("ResumeThread(initial)");

    GameSection game;
    Output output;
    Breakpoint breakpoint;
    bool initialBreakpointHandled = false, stopSent = false, unexpectedException = false;
    ULONGLONG observedFrom = 0, stopSentAt = 0, lastScan = 0;
    const ULONGLONG started = GetTickCount64();
    for (;;) {
        output.drain(outputRead.get());
        const auto now = GetTickCount64();
        const bool cancelled = InterlockedCompareExchange(&interrupted, 0, 0) != 0;
        if (!stopSent && !cancelled && !output.failure && !breakpoint.address &&
            initialBreakpointHandled && game.imageBase && now - lastScan >= 250 &&
            WaitForSingleObject(mainThread.get(), 0) == WAIT_TIMEOUT) {
            SuspendedThread suspended(mainThread.get());
            const auto candidate = game.find(process.get(), pattern);
            if (candidate) {
                game.validate(process.get(), candidate);
                breakpoint.arm(mainThread.get(), candidate);
            }
            suspended.resume();
            lastScan = now;
        }
        if (breakpoint.hits == requestedHits && !observedFrom) {
            observedFrom = now;
            std::printf("[launcher] Breakpoint removed; observing output for %u seconds.\n", observationSeconds);
        }
        if (!stopSent && (cancelled || output.failure || unexpectedException ||
            (observedFrom && now - observedFrom >= observationSeconds * 1000ull))) {
            breakpoint.disarm(mainThread.get());
            if (!GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, child.dwProcessId)) WinError("GenerateConsoleCtrlEvent");
            stopSent = true;
            stopSentAt = now;
        }
        Require(stopSent || observedFrom || now - started < 60000,
                "No signature match or insufficient hits within 60 seconds; confirm the signature against this Release build");
        Require(!stopSent || now - stopSentAt < 10000, "Child did not stop within 10 seconds");

        DEBUG_EVENT event{};
        if (!WaitForDebugEvent(&event, 50)) {
            if (GetLastError() == ERROR_SEM_TIMEOUT) continue;
            WinError("WaitForDebugEvent");
        }
        DWORD disposition = DBG_CONTINUE;
        bool exited = false;
        DWORD exitCode = 0;
        switch (event.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT: {
            Handle imageFile(event.u.CreateProcessInfo.hFile);
            game.discover(process.get(), reinterpret_cast<ULONG_PTR>(event.u.CreateProcessInfo.lpBaseOfImage));
            break;
        }
        case LOAD_DLL_DEBUG_EVENT: {
            Handle dllFile(event.u.LoadDll.hFile);
            break;
        }
        case EXCEPTION_DEBUG_EVENT: {
            const auto& exception = event.u.Exception;
            const DWORD code = exception.ExceptionRecord.ExceptionCode;
            disposition = DBG_EXCEPTION_NOT_HANDLED;
            if (!initialBreakpointHandled && exception.dwFirstChance && code == EXCEPTION_BREAKPOINT) {
                initialBreakpointHandled = true; // Windows' initial debugger breakpoint.
                disposition = DBG_CONTINUE;
            } else if (event.dwThreadId == child.dwThreadId &&
                       breakpoint.handle(mainThread.get(), exception, requestedHits)) {
                disposition = DBG_CONTINUE;
            } else if (code != DBG_CONTROL_C && code != DBG_CONTROL_BREAK) {
                std::printf("[launcher] Forwarding unexpected exception 0x%08lX (first chance=%lu).\n",
                    code, exception.dwFirstChance);
                unexpectedException = true;
                // Never claim success by swallowing unrelated application faults.
            }
            break;
        }
        case EXIT_PROCESS_DEBUG_EVENT:
            exited = true;
            exitCode = event.u.ExitProcess.dwExitCode;
            break;
        default:
            break;
        }
        if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, disposition)) WinError("ContinueDebugEvent");
        if (exited) {
            output.drain(outputRead.get());
            if (!output.partial.empty()) output.line(output.partial);
            const bool success = !cancelled && !output.failure && !unexpectedException &&
                output.kernelReady && output.baselineReady && initialBreakpointHandled &&
                breakpoint.hits == requestedHits && observedFrom && stopSent && exitCode == 0;
            std::printf("[launcher] %s: %u breakpoint hits, child exit %lu, integrity failure output %s.\n",
                success ? "OBSERVATION COMPLETED" : "INCOMPLETE OR FAILED", breakpoint.hits, exitCode,
                output.failure ? "seen" : "not seen");
            // This is evidence about observed output, not a proof that every
            // integrity scan ran or that arbitrary future exceptions are safe.
            return success ? 0 : 1;
        }
    }
}

unsigned Number(const wchar_t* text, unsigned maximum) {
    unsigned result = 0;
    Require(*text != L'\0', "Empty numeric argument");
    for (; *text; ++text) {
        Require(*text >= L'0' && *text <= L'9', "Expected a positive decimal number");
        result = result * 10 + static_cast<unsigned>(*text - L'0');
        Require(result <= maximum, "Numeric argument exceeds limit");
    }
    Require(result != 0, "Numeric argument must be positive");
    return result;
}
}

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc < 2 || argc > 5) {
            std::fputs("Usage: hardware_breakpoint_launcher.exe <detour_check.exe> [hits=3] [observe_seconds=30] [\"entry byte pattern\"]\n", stderr);
            return 2;
        }
        std::string signature(defaultDamagePattern);
        if (argc == 5) {
            signature.clear();
            for (const wchar_t* ch = argv[4]; *ch; ++ch) {
                Require(*ch <= 127, "The byte signature must contain ASCII characters");
                signature.push_back(static_cast<char>(*ch));
            }
        }
        return Run(argv[1], argc >= 3 ? Number(argv[2], 20) : 3,
                   argc >= 4 ? Number(argv[3], 300) : 30, ParsePattern(signature));
    } catch (const std::exception& error) {
        std::fprintf(stderr, "Launcher error: %s\n", error.what());
        return 1;
    }
}
