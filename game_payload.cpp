#include "PayloadApi.h"
#include <cstdio>
extern "C" __declspec(noinline) void ImportantGameLogic() {
    static unsigned tick = 0;
    std::printf("Game logic tick: %u\n", ++tick);
}
extern "C" __declspec(noinline) int CalculateDamage(int base, int armor) {
    return base > armor ? base - armor : 0;
}
// An unexecuted byte in the game code section permits a safe detection test.
#pragma section(".game", read, write, execute)
extern "C" { __declspec(allocate(".game")) unsigned char GameSentinel = 0x90; }
