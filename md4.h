#ifndef MD4_H
#define MD4_H

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

// MD4 (RFC 1320) & NTLM (Windows NT Hash) Implementation
namespace md4_internal {

#define MD4_R(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define MD4_F1(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define MD4_F2(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define MD4_F3(x, y, z) ((x) ^ (y) ^ (z))

#define MD4_ROUND1(a,b,c,d,k,s) a = MD4_R((a + MD4_F1(b,c,d) + w[k]), s)
#define MD4_ROUND2(a,b,c,d,k,s) a = MD4_R((a + MD4_F2(b,c,d) + w[k] + 0x5A827999), s)
#define MD4_ROUND3(a,b,c,d,k,s) a = MD4_R((a + MD4_F3(b,c,d) + w[k] + 0x6ED9EBA1), s)

inline void process_block(uint32_t state[4], const uint8_t block[64]) {
    uint32_t w[16];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4]) |
               (((uint32_t)block[i * 4 + 1]) << 8) |
               (((uint32_t)block[i * 4 + 2]) << 16) |
               (((uint32_t)block[i * 4 + 3]) << 24);
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];

    // Round 1
    MD4_ROUND1(a, b, c, d,  0,  3); MD4_ROUND1(d, a, b, c,  1,  7);
    MD4_ROUND1(c, d, a, b,  2, 11); MD4_ROUND1(b, c, d, a,  3, 19);
    MD4_ROUND1(a, b, c, d,  4,  3); MD4_ROUND1(d, a, b, c,  5,  7);
    MD4_ROUND1(c, d, a, b,  6, 11); MD4_ROUND1(b, c, d, a,  7, 19);
    MD4_ROUND1(a, b, c, d,  8,  3); MD4_ROUND1(d, a, b, c,  9,  7);
    MD4_ROUND1(c, d, a, b, 10, 11); MD4_ROUND1(b, c, d, a, 11, 19);
    MD4_ROUND1(a, b, c, d, 12,  3); MD4_ROUND1(d, a, b, c, 13,  7);
    MD4_ROUND1(c, d, a, b, 14, 11); MD4_ROUND1(b, c, d, a, 15, 19);

    // Round 2
    MD4_ROUND2(a, b, c, d,  0,  3); MD4_ROUND2(d, a, b, c,  4,  5);
    MD4_ROUND2(c, d, a, b,  8,  9); MD4_ROUND2(b, c, d, a, 12, 13);
    MD4_ROUND2(a, b, c, d,  1,  3); MD4_ROUND2(d, a, b, c,  5,  5);
    MD4_ROUND2(c, d, a, b,  9,  9); MD4_ROUND2(b, c, d, a, 13, 13);
    MD4_ROUND2(a, b, c, d,  2,  3); MD4_ROUND2(d, a, b, c,  6,  5);
    MD4_ROUND2(c, d, a, b, 10,  9); MD4_ROUND2(b, c, d, a, 14, 13);
    MD4_ROUND2(a, b, c, d,  3,  3); MD4_ROUND2(d, a, b, c,  7,  5);
    MD4_ROUND2(c, d, a, b, 11,  9); MD4_ROUND2(b, c, d, a, 15, 13);

    // Round 3
    MD4_ROUND3(a, b, c, d,  0,  3); MD4_ROUND3(d, a, b, c,  8,  9);
    MD4_ROUND3(c, d, a, b,  4, 11); MD4_ROUND3(b, c, d, a, 12, 15);
    MD4_ROUND3(a, b, c, d,  2,  3); MD4_ROUND3(d, a, b, c, 10,  9);
    MD4_ROUND3(c, d, a, b,  6, 11); MD4_ROUND3(b, c, d, a, 14, 15);
    MD4_ROUND3(a, b, c, d,  1,  3); MD4_ROUND3(d, a, b, c,  9,  9);
    MD4_ROUND3(c, d, a, b,  5, 11); MD4_ROUND3(b, c, d, a, 13, 15);
    MD4_ROUND3(a, b, c, d,  3,  3); MD4_ROUND3(d, a, b, c, 11,  9);
    MD4_ROUND3(c, d, a, b,  7, 11); MD4_ROUND3(b, c, d, a, 15, 15);

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

#undef MD4_R
#undef MD4_F1
#undef MD4_F2
#undef MD4_F3
#undef MD4_ROUND1
#undef MD4_ROUND2
#undef MD4_ROUND3

inline void md4_raw(const uint8_t *data, size_t len, uint8_t digest[16]) {
    uint32_t state[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
    size_t paddedLen = ((len + 8) / 64 + 1) * 64;
    uint8_t stackBuf[128];
    uint8_t *buffer = stackBuf;
    std::vector<uint8_t> heapBuf;
    if (paddedLen > sizeof(stackBuf)) {
        heapBuf.assign(paddedLen, 0);
        buffer = heapBuf.data();
    } else {
        std::memset(stackBuf, 0, paddedLen);
    }
    if (len > 0) std::memcpy(buffer, data, len);
    buffer[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) {
        buffer[paddedLen - 8 + i] = (bits >> (i * 8)) & 0xFF;
    }
    for (size_t off = 0; off < paddedLen; off += 64) {
        process_block(state, buffer + off);
    }
    for (int i = 0; i < 4; i++) {
        digest[i * 4 + 0] = (state[i]) & 0xFF;
        digest[i * 4 + 1] = (state[i] >> 8) & 0xFF;
        digest[i * 4 + 2] = (state[i] >> 16) & 0xFF;
        digest[i * 4 + 3] = (state[i] >> 24) & 0xFF;
    }
}

} // namespace md4_internal

inline std::string md4(const std::string &input) {
    uint8_t digest[16];
    md4_internal::md4_raw((const uint8_t*)input.data(), input.length(), digest);
    static const char hexChars[] = "0123456789abcdef";
    char out[33];
    for (int i = 0; i < 16; i++) {
        out[i * 2]     = hexChars[(digest[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hexChars[digest[i] & 0x0F];
    }
    out[32] = '\0';
    return std::string(out, 32);
}

// NTLM (Windows NT Hash): MD4 of UTF-16LE password bytes
inline std::string ntlm(const std::string &password) {
    uint8_t stackUtf16[128];
    uint8_t *utf16Ptr = stackUtf16;
    std::vector<uint8_t> heapUtf16;
    size_t utf16Len = password.length() * 2;
    if (utf16Len > sizeof(stackUtf16)) {
        heapUtf16.resize(utf16Len);
        utf16Ptr = heapUtf16.data();
    }
    for (size_t i = 0; i < password.length(); i++) {
        utf16Ptr[i * 2]     = static_cast<uint8_t>(password[i]);
        utf16Ptr[i * 2 + 1] = 0;
    }
    uint8_t digest[16];
    md4_internal::md4_raw(utf16Ptr, utf16Len, digest);
    static const char hexChars[] = "0123456789abcdef";
    char out[33];
    for (int i = 0; i < 16; i++) {
        out[i * 2]     = hexChars[(digest[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hexChars[digest[i] & 0x0F];
    }
    out[32] = '\0';
    return std::string(out, 32);
}

#endif // MD4_H
