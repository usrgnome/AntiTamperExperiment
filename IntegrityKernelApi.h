#pragma once
#include <Windows.h>
#include <bcrypt.h>

// The mapped checker cannot use the EXE's imports or writable global variables.
// Pass its OS services explicitly. No game-function registration is involved.
// State and output buffers stay in ordinary writable memory.
struct IntegrityChunkRequest {
    BCRYPT_HASH_HANDLE hash;
    decltype(&BCryptHashData) hashData;
    decltype(&BCryptFinishHash) finishHash;
    const unsigned char* bytes;
    ULONG size;
    unsigned char* digest;          // Caller provides space for 32 SHA-256 bytes.
    const unsigned char* baseline; // nullptr means capture without comparing.
};
// -1 = hashing failed, 0 = unchanged/baseline captured, 1 = modified.
using IntegrityChunkCheck = int (*)(const IntegrityChunkRequest*);
