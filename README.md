# Anti-tamper playground

A dummy Windows x64 project for me to try cracking later. Some game logic,
an integrity checker, and a loader to get them running. Nothing production-ready.

## What's in here

- `loader.cpp` decrypts the EXE's code sections in memory and starts everything.
- `game_payload.cpp` is the dummy game logic. Its pages stay read/write/execute (RWX).
- `integrity_payload.cpp` uses `CodeIntegrityMonitor.h` to watch for code changes with SHA-256. Its code pages become read/execute (RX).
- `pack_payload.py` XORs the game and integrity sections after linking. Basic obfuscation, nothing fancy.

The checker takes its baseline after decryption and scans the EXE's executable
sections in the background. It reports changes and restorations while the game
keeps ticking. Ctrl+C stops it.

## Build and run

**Builds are paused for now because this trips antivirus. Don't compile or run it
while doing source-only edits.**

When ready, use a Visual Studio developer terminal with CMake and Python 3:

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
.\build\Release\detour_check.exe
```

Everything generated goes in `build/`, which Git ignores. The final EXE is
`build/Release/detour_check.exe`; it doesn't need separate payload files.

The self-test changes an unused game byte, checks that the monitor notices,
then restores it. The standalone test repeats that with just the EXE.
