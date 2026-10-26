#include "IntegrityKernelApi.h"

// Copied into a separate SEC_NO_CHANGE mapping. No references to imports,
// globals, literals or other EXE functions: the packer rejects code relocations.
#pragma runtime_checks("", off)
extern "C" __declspec(noinline) int CheckIntegrityChunk(const IntegrityChunkRequest* request) {
    if (!request || !request->hashData || !request->finishHash ||
        !request->hash || !request->bytes || !request->digest) return -1;
    if (request->hashData(request->hash, const_cast<unsigned char*>(request->bytes),
                          request->size, 0) < 0 ||
        request->finishHash(request->hash, request->digest, 32, 0) < 0) return -1;
    if (!request->baseline) return 0;
    // Volatile reads prevent replacement with an out-of-section memcmp call.
    const volatile unsigned char* actual = request->digest;
    const volatile unsigned char* expected = request->baseline;
    unsigned difference = 0;
    for (unsigned i = 0; i < 32; ++i) difference |= actual[i] ^ expected[i];
    return difference ? 1 : 0;
}
#pragma runtime_checks("", restore)
