#define NOMINMAX
#include <Windows.h>
#include "Game.h"
#include "IntegrityStatus.h"
#include <cstdio>
#include <stdexcept>

namespace {
volatile LONG stopping = 0;

BOOL WINAPI Stop(DWORD event) {
    if (event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT) return FALSE;
    InterlockedExchange(&stopping, 1);
    return TRUE;
}

class ConsoleHandler {
public:
    ConsoleHandler() {
        InterlockedExchange(&stopping, 0);
        if (!SetConsoleCtrlHandler(Stop, TRUE))
            throw std::runtime_error("Cannot register Ctrl+C handler");
    }
    ~ConsoleHandler() { SetConsoleCtrlHandler(Stop, FALSE); }
    ConsoleHandler(const ConsoleHandler&) = delete;
    ConsoleHandler& operator=(const ConsoleHandler&) = delete;
};

bool WaitFor(const std::atomic<unsigned>& counter, const IntegrityStatus& integrity) {
    const auto deadline = GetTickCount64() + 3000;
    while (!counter.load() && !integrity.failed.load() && GetTickCount64() < deadline) Sleep(10);
    return counter.load() != 0 && !integrity.failed.load();
}

// An unexecuted byte in the game code section permits a safe detection test.
#pragma section(".game", read, write, execute)
// Volatile keeps the two writes observable after making this byte file-private.
__declspec(allocate(".game")) volatile unsigned char GameSentinel = 0x90;
}

__declspec(noinline) void Game::ImportantGameLogic() {
    static unsigned tick = 0;
    std::printf("Game logic tick: %u\n", ++tick);
}
__declspec(noinline) int Game::CalculateDamage(int base, int armor) {
    return base > armor ? base - armor : 0;
}
void Game::RunSelfTest(const IntegrityStatus& integrity) {
    ImportantGameLogic();
    if (CalculateDamage(100, 25) != 75 || CalculateDamage(10, 25) != 0)
        throw std::runtime_error("Game execution test failed");
    Sleep(200);
    if (integrity.modified.load() || integrity.failed.load())
        throw std::runtime_error("Unchanged code reported modified");
    GameSentinel ^= 1;
    const bool detected = WaitFor(integrity.modified, integrity);
    GameSentinel ^= 1;
    if (!detected || !WaitFor(integrity.restored, integrity))
        throw std::runtime_error("SHA-256 modification/restoration test failed");
}

int Game::Run(bool selfTest, const IntegrityStatus& integrity) {
    std::printf("ImportantGameLogic: %p; CalculateDamage: %p\n",
        reinterpret_cast<void*>(&ImportantGameLogic), reinterpret_cast<void*>(&CalculateDamage));
    if (selfTest) {
        RunSelfTest(integrity);
        return 0;
    }
    ConsoleHandler consoleHandler;
    std::puts("Baseline captured; background 20-second sweep target. Ctrl+C exits.");
    while (!InterlockedCompareExchange(&stopping, 0, 0)) {
        ImportantGameLogic();
        std::printf("Damage: %d\n", CalculateDamage(100, 25));
        std::fflush(stdout);
        Sleep(1000);
    }
    return 0;
}
