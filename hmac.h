#ifndef HMAC_H
#define HMAC_H

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include "md5.h"
#include "sha1.h"
#include "picosha2.h"

namespace hmac_internal {

inline void sha1_bytes(const uint8_t *data, size_t len, uint8_t digest[20]) {
    SHA1 s;
    s.update(std::string((const char*)data, len));
    std::string hex = s.final();
    for (int i = 0; i < 20; i++) {
        digest[i] = static_cast<uint8_t>(std::stoul(hex.substr(i * 2, 2), nullptr, 16));
    }
}

inline void sha256_bytes(const uint8_t *data, size_t len, uint8_t digest[32]) {
    picosha2::hash256(data, data + len, digest, digest + 32);
}

inline void md5_bytes(const uint8_t *data, size_t len, uint8_t digest[16]) {
    MD5 m;
    m.update(data, static_cast<MD5::size_type>(len));
    m.finalize();
    std::memcpy(digest, m.getDigest(), 16);
}

inline void to_hex(const uint8_t *in, size_t len, std::string &out) {
    const char hexChars[] = "0123456789abcdef";
    out.clear();
    out.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        out.push_back(hexChars[(in[i] >> 4) & 0x0F]);
        out.push_back(hexChars[in[i] & 0x0F]);
    }
}

} // namespace hmac_internal

// RFC 2104 HMAC-MD5
inline void hmac_md5_raw(const uint8_t *key, size_t keyLen,
                         const uint8_t *msg, size_t msgLen,
                         uint8_t out[16]) {
    uint8_t k[64] = {0};
    if (keyLen > 64) {
        hmac_internal::md5_bytes(key, keyLen, k);
    } else {
        std::memcpy(k, key, keyLen);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5C;
    }
    std::vector<uint8_t> inner(64 + msgLen);
    std::memcpy(inner.data(), ipad, 64);
    if (msgLen > 0) std::memcpy(inner.data() + 64, msg, msgLen);
    uint8_t innerHash[16];
    hmac_internal::md5_bytes(inner.data(), inner.size(), innerHash);

    uint8_t outer[64 + 16];
    std::memcpy(outer, opad, 64);
    std::memcpy(outer + 64, innerHash, 16);
    hmac_internal::md5_bytes(outer, 80, out);
}

inline std::string hmac_md5(const std::string &key, const std::string &data) {
    uint8_t digest[16];
    hmac_md5_raw(reinterpret_cast<const uint8_t*>(key.data()), key.length(),
                 reinterpret_cast<const uint8_t*>(data.data()), data.length(),
                 digest);
    std::string hex;
    hmac_internal::to_hex(digest, 16, hex);
    return hex;
}

// RFC 2104 HMAC-SHA1
inline void hmac_sha1_raw(const uint8_t *key, size_t keyLen,
                          const uint8_t *msg, size_t msgLen,
                          uint8_t out[20]) {
    uint8_t k[64] = {0};
    if (keyLen > 64) {
        hmac_internal::sha1_bytes(key, keyLen, k);
    } else {
        std::memcpy(k, key, keyLen);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5C;
    }
    std::vector<uint8_t> inner(64 + msgLen);
    std::memcpy(inner.data(), ipad, 64);
    if (msgLen > 0) std::memcpy(inner.data() + 64, msg, msgLen);
    uint8_t innerHash[20];
    hmac_internal::sha1_bytes(inner.data(), inner.size(), innerHash);

    uint8_t outer[64 + 20];
    std::memcpy(outer, opad, 64);
    std::memcpy(outer + 64, innerHash, 20);
    hmac_internal::sha1_bytes(outer, 84, out);
}

inline std::string hmac_sha1(const std::string &key, const std::string &data) {
    uint8_t digest[20];
    hmac_sha1_raw(reinterpret_cast<const uint8_t*>(key.data()), key.length(),
                  reinterpret_cast<const uint8_t*>(data.data()), data.length(),
                  digest);
    std::string hex;
    hmac_internal::to_hex(digest, 20, hex);
    return hex;
}

// RFC 2104 HMAC-SHA256
inline void hmac_sha256_raw(const uint8_t *key, size_t keyLen,
                            const uint8_t *msg, size_t msgLen,
                            uint8_t out[32]) {
    uint8_t k[64] = {0};
    if (keyLen > 64) {
        hmac_internal::sha256_bytes(key, keyLen, k);
    } else {
        std::memcpy(k, key, keyLen);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5C;
    }
    std::vector<uint8_t> inner(64 + msgLen);
    std::memcpy(inner.data(), ipad, 64);
    if (msgLen > 0) std::memcpy(inner.data() + 64, msg, msgLen);
    uint8_t innerHash[32];
    hmac_internal::sha256_bytes(inner.data(), inner.size(), innerHash);

    uint8_t outer[64 + 32];
    std::memcpy(outer, opad, 64);
    std::memcpy(outer + 64, innerHash, 32);
    hmac_internal::sha256_bytes(outer, 96, out);
}

inline std::string hmac_sha256(const std::string &key, const std::string &data) {
    uint8_t digest[32];
    hmac_sha256_raw(reinterpret_cast<const uint8_t*>(key.data()), key.length(),
                    reinterpret_cast<const uint8_t*>(data.data()), data.length(),
                    digest);
    std::string hex;
    hmac_internal::to_hex(digest, 32, hex);
    return hex;
}

// RFC 2898 / RFC 6070 PBKDF2-HMAC-SHA1 (Used in WPA2-PSK Pairwise Master Key derivation)
inline std::string pbkdf2_hmac_sha1(const std::string &pass, const std::string &salt, int iterations = 4096, int dkLen = 32) {
    int blocks = (dkLen + 19) / 20;
    std::vector<uint8_t> dk(blocks * 20);
    for (int b = 1; b <= blocks; b++) {
        std::vector<uint8_t> saltBlock(salt.length() + 4);
        std::memcpy(saltBlock.data(), salt.data(), salt.length());
        saltBlock[salt.length()]     = static_cast<uint8_t>((b >> 24) & 0xFF);
        saltBlock[salt.length() + 1] = static_cast<uint8_t>((b >> 16) & 0xFF);
        saltBlock[salt.length() + 2] = static_cast<uint8_t>((b >> 8)  & 0xFF);
        saltBlock[salt.length() + 3] = static_cast<uint8_t>(b & 0xFF);

        uint8_t u[20], f[20];
        hmac_sha1_raw(reinterpret_cast<const uint8_t*>(pass.data()), pass.length(),
                      saltBlock.data(), saltBlock.size(), u);
        std::memcpy(f, u, 20);

        for (int i = 1; i < iterations; i++) {
            hmac_sha1_raw(reinterpret_cast<const uint8_t*>(pass.data()), pass.length(), u, 20, u);
            for (int k = 0; k < 20; k++) f[k] ^= u[k];
        }
        std::memcpy(dk.data() + (b - 1) * 20, f, 20);
    }
    std::string hex;
    hmac_internal::to_hex(dk.data(), dkLen, hex);
    return hex;
}

#endif // HMAC_H
