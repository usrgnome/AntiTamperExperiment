#pragma once
#include <algorithm>
#include <cstddef>
#include <stdexcept>
#include <string_view>
#include <vector>

// Actual CalculateDamage instructions read from the existing Release COFF
// artifact without executing it. Despite its Release directory, that artifact
// has stack-based, unoptimized code. A new compiler/configuration may differ:
// accept a replacement signature rather than guessing at a different function.
inline constexpr std::string_view defaultDamagePattern =
    "89 54 24 10 89 4C 24 08 48 83 EC 18 8B 44 24 28 "
    "39 44 24 20 7E 11 8B 44 24 28 8B 4C 24 20 2B C8 "
    "8B C1 89 04 24 EB 07 C7 04 24 00 00 00 00 8B 04 "
    "24 48 83 C4 18 C3";

inline std::vector<int> ParsePattern(std::string_view text) {
    const auto whitespace = [](char ch) { return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n'; };
    const auto nibble = [](char ch) -> int {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
        if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
        return -1;
    };
    std::vector<int> pattern;
    unsigned concrete = 0;
    while (!text.empty()) {
        while (!text.empty() && whitespace(text.front())) text.remove_prefix(1);
        if (text.empty()) break;
        std::size_t length = 0;
        while (length < text.size() && !whitespace(text[length])) ++length;
        const auto token = text.substr(0, length);
        if (token == "?" || token == "??") pattern.push_back(-1);
        else {
            if (token.size() != 2 || nibble(token[0]) < 0 || nibble(token[1]) < 0)
                throw std::runtime_error("Signature tokens must be two hex digits or ??");
            pattern.push_back(nibble(token[0]) * 16 + nibble(token[1]));
            ++concrete;
        }
        text.remove_prefix(length);
    }
    if (pattern.size() < 8 || pattern.size() > 256 || concrete < 8 || pattern.front() < 0)
        throw std::runtime_error("Signature needs 8-256 bytes, at least 8 fixed bytes, and a fixed first byte");
    return pattern;
}

// Return at most two offsets: enough to distinguish absent, unique and ambiguous.
inline std::vector<std::size_t> FindPattern(const std::vector<unsigned char>& bytes,
                                          const std::vector<int>& pattern) {
    std::vector<std::size_t> matches;
    if (pattern.empty() || bytes.size() < pattern.size()) return matches;
    for (std::size_t offset = 0; offset <= bytes.size() - pattern.size(); ++offset) {
        if (bytes[offset] != pattern.front()) continue;
        bool match = true;
        for (std::size_t i = 1; i < pattern.size(); ++i)
            if (pattern[i] >= 0 && bytes[offset + i] != pattern[i]) { match = false; break; }
        if (match) {
            matches.push_back(offset);
            if (matches.size() == 2) break;
        }
    }
    return matches;
}
