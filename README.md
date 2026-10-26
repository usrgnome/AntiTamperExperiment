# Anti-tamper playground

A dummy Windows x64 project for me to try cracking later. Some game logic,
an integrity checker, and a loader to get them running. Nothing production-ready.

## What's in here

- `loader.cpp` decrypts the EXE's code sections, starts the integrity monitor,
  and calls `Game::Run`. It owns startup and cleanup, with no game loop or rules.
- `Game.h` exposes the game class entry point. `game_payload.cpp` owns the game
  loop, damage calculation, Ctrl+C handling, and game self-test. Its code stays
  in the packed read/write/execute (RWX) game section.
- `IntegrityStatus.h` exposes atomic notification counters so the game self-test
  can observe integrity results without depending on monitor implementation.
- `integrity_payload.cpp` contains a position-independent SHA-256 hash/compare routine.
- `ProtectedIntegrity.cpp` copies that routine into a page-file-backed section,
  removes the writable staging view, and maps an RX view with `SEC_NO_CHANGE`.
  Startup checks every mapped page and requires permission-change attempts to
  return `STATUS_INVALID_PAGE_PROTECTION`; failure stops startup.
- `integrity_host.cpp` and `CodeIntegrityMonitor.h` own discovery, baselines,
  scheduling and notifications, and invoke the protected routine for each chunk.
- `IntegrityVeh.cpp` observes exception contexts during the integrity session
  and records failure reason `0x800` when valid debug-register context contains
  a nonzero DR0, DR1, DR2 or DR3.
- `pack_payload.py` XORs the game and integrity sections after linking. Basic obfuscation, nothing fancy.

The checker takes its baseline after decryption and protected mapping setup,
then scans the EXE's executable sections and the active mapped routine in the
background. It reports changes and restorations while the game keeps ticking.
Ctrl+C stops the worker before the protected mapping is released.

## Integrity mapping experiment

The mapping technique is based on
[changeofpace/Self-Remapping-Code](https://github.com/changeofpace/Self-Remapping-Code).
This is a separate implementation of the section/view technique, not a vendored
copy of that project's whole-image remapper. The original repository is GPL-3.0.
Only the hash/compare routine runs in the protected view. BCrypt itself, the host
monitor, callbacks, function pointers and writable baseline/state remain outside
this protection. The original `.integr` code remains RX in the EXE; the monitor
calls the protected copy, not that original function.

Unlike the reference, this does not unmap the executable. Windows chooses a new
view address at section offset zero, so no `/ALIGN:0x10000` change is needed.
The packer rejects any COFF relocation in integrity code, preventing copied code
from retaining references to EXE imports, globals or compiler helpers. OS calls
are passed through an explicit request structure. Simple x64 unwind metadata is
copied and registered for the mapped function; other unwind layouts fail startup.

`SEC_NO_CHANGE` is an undocumented native behavior and remains unverified here
until builds resume. The runtime check is required, with no fallback to an
ordinary RX mapping. This restricts protection changes, not reads, dumping,
unmapping, host-state changes, or kernel access. The game deliberately stays RWX
so the existing modification/restoration exercise still works.

## Exception context check

The VEH is registered before baseline capture and removed during integrity
shutdown. It checks `CONTEXT_DEBUG_REGISTERS` (AMD64's `0x100010`) rather than
embedding a numeric context mask. Any nonzero DR0-DR3 triggers this policy,
including disabled slots; it does not inspect DR7 enable bits or prove a hook
exists. It does not need comparison RVAs from another binary.

Inside the handler, a lock-free atomic operation latches the reason for the
process lifetime. It never calls the logger, allocates memory, changes the
context, or consumes the exception: it returns `EXCEPTION_CONTINUE_SEARCH`.
The normal monitor worker reports event 3 with reason `0x800` once per session,
at startup or before the next scheduled hash batch; shutdown also drains pending
reasons after joining the worker. The loader records it in `failureReasons`,
increments `failed`, and logs it. Reporting can be delayed by the scan schedule;
an unhandled exception can terminate the process before deferred logging.

This is passive observation of the faulting thread's supplied context, not a
continuous check of all threads. Debuggers receive first-chance exceptions before
vectored handlers, and another handler can precede this observer. Missing flags
mean no observation, not proof that debug registers are clear. The VEH is normal
EXE host code, covered by hashing but outside the `SEC_NO_CHANGE` mapping.
No new process-termination policy is introduced.

References: [Windows VEH registration](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
and [handler restrictions](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nc-winnt-pvectored_exception_handler).

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

The self-test checks locked integrity permissions, changes an unused game byte,
checks that the monitor notices, then restores it and rechecks permissions.
The standalone test repeats that with just the EXE. These runtime tests are
prepared but must not be run while builds are paused.
`veh_integrity_policy` covers synthetic context flag/register combinations and
handler registration lifetime. It does not install real hardware breakpoints;
live exception delivery and debugger interaction still require validation.

Source-only packer tests can run without compiling or executing the EXE:
`python -m unittest test_pack_payload.py`.
