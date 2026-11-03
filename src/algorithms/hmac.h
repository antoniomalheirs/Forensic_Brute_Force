#ifndef HMAC_H
#define HMAC_H

#include <algorithm>
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
    s.update(reinterpret_cast<const char *>(data), len);
    s.final(digest);
}

class Sha1HmacState {
public:
    Sha1HmacState(const uint8_t *key, size_t keyLen) {
        uint8_t keyBlock[64] = {0};
        if (keyLen > sizeof(keyBlock)) {
            sha1_bytes(key, keyLen, keyBlock);
        } else if (keyLen > 0) {
            std::memcpy(keyBlock, key, keyLen);
        }

        uint8_t ipad[64], opad[64];
        for (size_t i = 0; i < sizeof(keyBlock); ++i) {
            ipad[i] = keyBlock[i] ^ 0x36;
            opad[i] = keyBlock[i] ^ 0x5C;
        }
        innerBase_.update(reinterpret_cast<const char *>(ipad), sizeof(ipad));
        outerBase_.update(reinterpret_cast<const char *>(opad), sizeof(opad));
    }

    void hash(const uint8_t *msg, size_t msgLen, uint8_t digest[20]) const {
        uint8_t innerDigest[20];
        SHA1 inner = innerBase_;
        if (msgLen > 0)
            inner.update(reinterpret_cast<const char *>(msg), msgLen);
        inner.final(innerDigest);

        SHA1 outer = outerBase_;
        outer.update(reinterpret_cast<const char *>(innerDigest),
                      sizeof(innerDigest));
        outer.final(digest);
    }

private:
    SHA1 innerBase_;
    SHA1 outerBase_;
};

inline void sha256_bytes(const uint8_t *data, size_t len, uint8_t digest[32]) {
    picosha2::hash256_one_by_one hasher;
    const size_t chunkLimit = 1024 * 1024;
    for (size_t offset = 0; offset < len;) {
        const size_t chunk = std::min(chunkLimit, len - offset);
        hasher.process(data + offset, data + offset + chunk);
        offset += chunk;
    }
    hasher.finish();
    hasher.get_hash_bytes(digest, digest + 32);
}

class Sha256HmacState {
public:
    Sha256HmacState(const uint8_t *key, size_t keyLen) {
        uint8_t keyBlock[64] = {0};
        if (keyLen > sizeof(keyBlock)) {
            sha256_bytes(key, keyLen, keyBlock);
        } else if (keyLen > 0) {
            std::memcpy(keyBlock, key, keyLen);
        }

        uint8_t ipad[64], opad[64];
        for (size_t i = 0; i < sizeof(keyBlock); ++i) {
            ipad[i] = keyBlock[i] ^ 0x36;
            opad[i] = keyBlock[i] ^ 0x5C;
        }
        innerBase_.process(ipad, ipad + sizeof(ipad));
        outerBase_.process(opad, opad + sizeof(opad));
    }

    void hash(const uint8_t *msg, size_t msgLen, uint8_t digest[32]) const {
        picosha2::hash256_one_by_one inner = innerBase_;
        if (msgLen > 0)
            inner.process(msg, msg + msgLen);
        inner.finish();
        uint8_t innerDigest[32];
        inner.get_hash_bytes(innerDigest, innerDigest + sizeof(innerDigest));

        picosha2::hash256_one_by_one outer = outerBase_;
        outer.process(innerDigest, innerDigest + sizeof(innerDigest));
        outer.finish();
        outer.get_hash_bytes(digest, digest + 32);
    }

private:
    picosha2::hash256_one_by_one innerBase_;
    picosha2::hash256_one_by_one outerBase_;
};

inline void md5_bytes(const uint8_t *data, size_t len, uint8_t digest[16]) {
    MD5 m;
    const size_t chunkLimit = 1024 * 1024;
    for (size_t offset = 0; offset < len;) {
        const size_t chunk = std::min(chunkLimit, len - offset);
        m.update(data + offset, static_cast<MD5::size_type>(chunk));
        offset += chunk;
    }
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
    } else if (keyLen > 0) {
        std::memcpy(k, key, keyLen);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5C;
    }
    MD5 innerHashState;
    innerHashState.update(ipad, sizeof(ipad));
    const size_t chunkLimit = 1024 * 1024;
    for (size_t offset = 0; offset < msgLen;) {
        const size_t chunk = std::min(chunkLimit, msgLen - offset);
        innerHashState.update(msg + offset,
                              static_cast<MD5::size_type>(chunk));
        offset += chunk;
    }
    innerHashState.finalize();
    uint8_t innerHash[16];
    std::memcpy(innerHash, innerHashState.getDigest(), sizeof(innerHash));

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
    const hmac_internal::Sha1HmacState state(key, keyLen);
    state.hash(msg, msgLen, out);
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
    const hmac_internal::Sha256HmacState state(key, keyLen);
    state.hash(msg, msgLen, out);
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
    if (iterations <= 0 || dkLen <= 0) return "";
    const hmac_internal::Sha1HmacState hmacState(
        reinterpret_cast<const uint8_t *>(pass.data()), pass.length());
    const size_t outputLength = static_cast<size_t>(dkLen);
    const size_t blocks = (outputLength - 1) / 20 + 1;
    std::vector<uint8_t> dk(blocks * 20);
    for (size_t b = 1; b <= blocks; b++) {
        std::vector<uint8_t> saltBlock(salt.length() + 4);
        std::memcpy(saltBlock.data(), salt.data(), salt.length());
        const uint32_t blockIndex = static_cast<uint32_t>(b);
        saltBlock[salt.length()]     = static_cast<uint8_t>((blockIndex >> 24) & 0xFF);
        saltBlock[salt.length() + 1] = static_cast<uint8_t>((blockIndex >> 16) & 0xFF);
        saltBlock[salt.length() + 2] = static_cast<uint8_t>((blockIndex >> 8)  & 0xFF);
        saltBlock[salt.length() + 3] = static_cast<uint8_t>(blockIndex & 0xFF);

        uint8_t u[20], f[20];
        hmacState.hash(saltBlock.data(), saltBlock.size(), u);
        std::memcpy(f, u, 20);

        for (int i = 1; i < iterations; i++) {
            hmacState.hash(u, sizeof(u), u);
            for (int k = 0; k < 20; k++) f[k] ^= u[k];
        }
        std::memcpy(dk.data() + (b - 1) * 20, f, 20);
    }
    std::string hex;
    hmac_internal::to_hex(dk.data(), outputLength, hex);
    return hex;
}

#endif // HMAC_H
