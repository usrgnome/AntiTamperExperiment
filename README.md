# Encrypted code loader lab

Windows x64 / MSVC C++17 example shipped as one EXE with two embedded XOR-encrypted payloads:

| Embedded payload | Function | Final memory protection |
| --- | --- | --- |
| Integrity checker | FNV-1a checksum, baseline initialization and comparison | Read/execute (`PAGE_EXECUTE_READ`) |
| Game logic | Increment game tick and calculate damage | Read/write/execute (`PAGE_EXECUTE_READWRITE`) |

The EXE holds encrypted byte arrays in its image. At runtime it allocates separate
read/write regions, decrypts from those arrays directly into them, applies the final protections, and flushes the
instruction cache before calling either function. Integrity code is writable
during loading only. Its baseline and game state are ordinary writable data
owned by the loader. Startup prints addresses and verified page permissions.
There are no payload file reads or temporary extracted files at runtime. Windows
still loads the EXE and system libraries normally; payload loading happens in memory.

The loader captures the game payload baseline and calls the loaded checker once
per second, reporting modified/restored transitions. Gameplay continues after a
change. Ctrl+C exits and releases allocations. This replaces the previous
background SHA-256 scanner with a small synchronous lab example. The old
`CodeIntegrityMonitor.h` remains as reference and is not compiled into this demo.

## Build and run

Use a Visual Studio developer terminal with CMake and Python 3 available:

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
.\build\Release\detour_check.exe
```

Distribute only `build/Release/detour_check.exe`; the MSVC runtime is statically linked.
Keep generated files under `build/`, which is ignored by Git. In-source builds are
not supported. To discard build output, delete `build/` and rerun the commands above.
The self-test verifies RX/RWX permissions, executes both payloads, changes a
non-executed game sentinel byte, checks detection, restores it, and checks recovery.
The standalone test copies only the EXE into a fresh directory and runs the self-test there.

## How the payloads work

Read `integrity_payload.cpp` and `game_payload.cpp` for the loaded code,
`pack_payload.py` for packaging, and `loader.cpp` for allocation and execution.

```text
integrity_payload.cpp -> .obj -> encrypt -> integrity_embedded.h
game_payload.cpp      -> .obj -> encrypt -> game_embedded.h
loader.cpp + generated headers -> compile/link -> detour_check.exe
```
The build compiles each payload to an object without linking it into the EXE.
The packer finds the entry symbol, requires it at the beginning of the sole code
section, rejects relocations, appends a test sentinel, and XORs bytes with `0xA7`.
It writes generated C++ headers under `build/generated/<configuration>`. The loader
includes these headers, embedding the encrypted arrays in the EXE. These headers
and object files are build intermediates, not runtime dependencies. Python is
needed only during the build. Rebuilding after a payload edit regenerates its
header and recompiles the loader automatically.

These are deliberately tiny position-independent leaf functions, not general DLLs.
Do not add library calls, static data, exceptions, or other functions without
redesigning the payload format and loader. COFF unwind metadata is not loaded;
these leaf functions do not adjust the stack or require unwind registration.
The packer rejects code needing relocations instead of implementing PE mapping.

## Exercise boundaries

The RX page rejects ordinary writes once loaded. A debugger or code in this process
with sufficient access can change page permissions; RX is not an anti-debugging
boundary. This program does not implement patching or a bypass. Coordinate external
code edits while execution is paused and flush the instruction cache after editing
instructions before resuming.

Only the game payload, including its sentinel, is monitored. The checker does not
monitor itself, the loader, or writable baseline data. Startup bytes are trusted;
patches between checks can be missed. 32-bit FNV-1a is a simple checksum, not a cryptographic
integrity guarantee. XOR is reversible obfuscation, not authenticated encryption.
Build objects still contain plaintext instructions; the deployed EXE contains
encrypted payload bytes. The game intentionally uses RWX for this local exercise.
