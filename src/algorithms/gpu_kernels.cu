
#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <algorithm>
#include <limits>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <string.h>
#include <vector>
#include "test_faults.h"

// Macro to silence VS IntelliSense errors on triple-bracket syntax
#ifdef __INTELLISENSE__
#define KERNEL_LAUNCH(name, grid, block, ...)
#else
#define KERNEL_LAUNCH(name, grid, block, ...) name<<<grid, block>>>(__VA_ARGS__)
#endif

using CudaProgressCallback = void (*)(void *, unsigned long long,
                                      unsigned long long, double, int, int);

#if defined(CERBERUS_TESTING)
static int g_cuda_test_fault = CERBERUS_CUDA_FAIL_NONE;
static int g_cuda_test_fault_skip = 0;

extern "C" void cerberusCudaTestFailAfter(int fault, int successfulCalls) {
  g_cuda_test_fault = fault;
  g_cuda_test_fault_skip = std::max(0, successfulCalls);
}

extern "C" void cerberusCudaTestResetFault() {
  g_cuda_test_fault = CERBERUS_CUDA_FAIL_NONE;
  g_cuda_test_fault_skip = 0;
}

static bool cudaShouldFail(int fault) {
  if (g_cuda_test_fault != fault) return false;
  if (g_cuda_test_fault_skip > 0) {
    --g_cuda_test_fault_skip;
    return false;
  }
  return true;
}
#else
static bool cudaShouldFail(int) { return false; }
#endif

static cudaError_t cerberusCudaMalloc(void **pointer, size_t size) {
  if (cudaShouldFail(CERBERUS_CUDA_FAIL_ALLOCATION)) {
    if (pointer) *pointer = nullptr;
    return cudaErrorMemoryAllocation;
  }
  return cudaMalloc(pointer, size);
}

static cudaError_t cerberusCudaMemcpy(void *destination, const void *source,
                                      size_t size, cudaMemcpyKind kind) {
  const int fault = kind == cudaMemcpyHostToDevice
                        ? CERBERUS_CUDA_FAIL_HOST_TO_DEVICE_COPY
                        : (kind == cudaMemcpyDeviceToHost
                               ? CERBERUS_CUDA_FAIL_DEVICE_TO_HOST_COPY
                               : CERBERUS_CUDA_FAIL_NONE);
  if (fault != CERBERUS_CUDA_FAIL_NONE && cudaShouldFail(fault))
    return cudaErrorInvalidValue;
  return cudaMemcpy(destination, source, size, kind);
}

static cudaError_t cerberusCudaMemset(void *destination, int value,
                                      size_t size) {
  if (cudaShouldFail(CERBERUS_CUDA_FAIL_MEMSET))
    return cudaErrorInvalidValue;
  return cudaMemset(destination, value, size);
}

// --- Device Constants & Macros ---
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

// SHA256 Macros
#define Ch(x, y, z) ((x & y) ^ (~x & z))
#define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define Sigma0_256(x) (ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define Sigma1_256(x) (ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define sigma0_256(x) (ROTR32(x, 7) ^ ROTR32(x, 18) ^ ((x) >> 3))
#define sigma1_256(x) (ROTR32(x, 17) ^ ROTR32(x, 19) ^ ((x) >> 10))

__constant__ uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

__constant__ uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
    0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
    0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
    0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
    0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
    0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
    0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

// MD5 Constants
__constant__ uint32_t KMD5[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
    0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
    0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
    0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

// --- Helper: String Copy / Length on GPU ---
__device__ int d_strlen(const char *str) {
  int len = 0;
  while (str[len] != 0)
    len++;
  return len;
}

__device__ void d_strcpy(char *dest, const char *src) {
  int i = 0;
  while (src[i] != 0) {
    dest[i] = src[i];
    i++;
  }
  dest[i] = 0;
}

__device__ void d_uint32_to_hex(uint32_t val, char *out) {
  const char hex[] = "0123456789abcdef";
  for (int i = 0; i < 4; i++) {
    uint8_t byte = (val >> (24 - 8 * i)) & 0xFF;
    out[2 * i] = hex[(byte >> 4) & 0xF];
    out[2 * i + 1] = hex[byte & 0xF];
  }
}

// Reverse-byte hex (for MD5 little-endian)
__device__ void d_uint32_to_hex_le(uint32_t val, char *out) {
  const char hex[] = "0123456789abcdef";
  for (int i = 0; i < 4; i++) {
    uint8_t byte = (val >> (i * 8)) & 0xFF;
    out[2 * i] = hex[(byte >> 4) & 0xF];
    out[2 * i + 1] = hex[byte & 0xF];
  }
}

__device__ void d_uint64_to_hex(uint64_t val, char *out) {
  const char hex[] = "0123456789abcdef";
  for (int i = 0; i < 8; i++) {
    const uint8_t byte = static_cast<uint8_t>(val >> (56 - 8 * i));
    out[2 * i] = hex[(byte >> 4) & 0xF];
    out[2 * i + 1] = hex[byte & 0xF];
  }
}

// ============================================================
// SHA-256 Multi-Block (up to 119 bytes input)
// ============================================================
__device__ void sha256_process_block(uint32_t *state, const uint8_t *block) {
  uint32_t w[64];
  for (int i = 0; i < 16; i++)
    w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
           (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
           (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
           static_cast<uint32_t>(block[i * 4 + 3]);
  for (int i = 16; i < 64; i++)
    w[i] = sigma1_256(w[i - 2]) + w[i - 7] + sigma0_256(w[i - 15]) + w[i - 16];
  uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
  uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
  for (int i = 0; i < 64; i++) {
    uint32_t t1 = h + Sigma1_256(e) + Ch(e, f, g) + K256[i] + w[i];
    uint32_t t2 = Sigma0_256(a) + Maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
}

__device__ void sha256_core(const uint8_t *data, int len, uint32_t *hash) {
  hash[0] = 0x6a09e667;
  hash[1] = 0xbb67ae85;
  hash[2] = 0x3c6ef372;
  hash[3] = 0xa54ff53a;
  hash[4] = 0x510e527f;
  hash[5] = 0x9b05688c;
  hash[6] = 0x1f83d9ab;
  hash[7] = 0x5be0cd19;
  uint8_t buffer[128];
  for (int i = 0; i < 128; i++)
    buffer[i] = 0;
  for (int i = 0; i < len && i < 120; i++)
    buffer[i] = data[i];
  buffer[len] = 0x80;
  int paddedLen = (len < 56) ? 64 : 128;
  uint64_t bits = (uint64_t)len * 8;
  for (int i = 0; i < 8; i++)
    buffer[paddedLen - 1 - i] = (bits >> (i * 8)) & 0xFF;
  for (int off = 0; off < paddedLen; off += 64)
    sha256_process_block(hash, buffer + off);
}

// ============================================================
// SHA-512 Multi-Block (up to 239 bytes input)
// ============================================================
__device__ void sha512_process_block(uint64_t *state, const uint8_t *block) {
  uint64_t w[80];
  for (int i = 0; i < 16; i++) {
    const int off = i * 8;
    w[i] = (static_cast<uint64_t>(block[off]) << 56) |
           (static_cast<uint64_t>(block[off + 1]) << 48) |
           (static_cast<uint64_t>(block[off + 2]) << 40) |
           (static_cast<uint64_t>(block[off + 3]) << 32) |
           (static_cast<uint64_t>(block[off + 4]) << 24) |
           (static_cast<uint64_t>(block[off + 5]) << 16) |
           (static_cast<uint64_t>(block[off + 6]) << 8) |
           static_cast<uint64_t>(block[off + 7]);
  }
  for (int i = 16; i < 80; i++) {
    const uint64_t sigma0 = ROTR64(w[i - 15], 1) ^ ROTR64(w[i - 15], 8) ^
                                   (w[i - 15] >> 7);
    const uint64_t sigma1 = ROTR64(w[i - 2], 19) ^ ROTR64(w[i - 2], 61) ^
                                   (w[i - 2] >> 6);
    w[i] = sigma1 + w[i - 7] + sigma0 + w[i - 16];
  }

  uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
  uint64_t e = state[4], f = state[5], g = state[6], h = state[7];
  for (int i = 0; i < 80; i++) {
    const uint64_t sum1 = ROTR64(e, 14) ^ ROTR64(e, 18) ^ ROTR64(e, 41);
    const uint64_t choose = (e & f) ^ (~e & g);
    const uint64_t t1 = h + sum1 + choose + K512[i] + w[i];
    const uint64_t sum0 = ROTR64(a, 28) ^ ROTR64(a, 34) ^ ROTR64(a, 39);
    const uint64_t majority = (a & b) ^ (a & c) ^ (b & c);
    const uint64_t t2 = sum0 + majority;
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
}

__device__ void sha512_core(const uint8_t *data, int len, uint64_t *hash) {
  hash[0] = 0x6a09e667f3bcc908ULL;
  hash[1] = 0xbb67ae8584caa73bULL;
  hash[2] = 0x3c6ef372fe94f82bULL;
  hash[3] = 0xa54ff53a5f1d36f1ULL;
  hash[4] = 0x510e527fade682d1ULL;
  hash[5] = 0x9b05688c2b3e6c1fULL;
  hash[6] = 0x1f83d9abfb41bd6bULL;
  hash[7] = 0x5be0cd19137e2179ULL;

  uint8_t buffer[256];
  for (int i = 0; i < 256; i++) buffer[i] = 0;
  for (int i = 0; i < len && i < 240; i++) buffer[i] = data[i];
  buffer[len] = 0x80;
  const int paddedLen = len < 112 ? 128 : 256;
  const uint64_t bitLength = static_cast<uint64_t>(len) * 8;
  // Inputs here are shorter than 2^64 bits, so the high half of SHA-512's
  // 128-bit message length remains zero from buffer initialization.
  for (int i = 0; i < 8; i++)
    buffer[paddedLen - 1 - i] = (bitLength >> (i * 8)) & 0xFF;
  for (int off = 0; off < paddedLen; off += 128)
    sha512_process_block(hash, buffer + off);
}

// ============================================================
// MD5 Multi-Block (up to 119 bytes input)
// ============================================================
__device__ void md5_process_block(uint32_t *state, const uint8_t *block) {
  uint32_t w[16];
  for (int i = 0; i < 16; i++)
    w[i] = ((uint32_t)block[i * 4]) | (((uint32_t)block[i * 4 + 1]) << 8) |
           (((uint32_t)block[i * 4 + 2]) << 16) |
           (((uint32_t)block[i * 4 + 3]) << 24);
  uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
  const int r[] = {7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21};
  for (int i = 0; i < 64; i++) {
    uint32_t f, g;
    if (i < 16) {
      f = (b & c) | ((~b) & d);
      g = i;
    } else if (i < 32) {
      f = (d & b) | ((~d) & c);
      g = (5 * i + 1) % 16;
    } else if (i < 48) {
      f = b ^ c ^ d;
      g = (3 * i + 5) % 16;
    } else {
      f = c ^ (b | (~d));
      g = (7 * i) % 16;
    }
    uint32_t tmp = d;
    d = c;
    c = b;
    int shift = r[(i / 16) * 4 + (i % 4)];
    b = b + ROTL32(a + f + KMD5[i] + w[g], shift);
    a = tmp;
  }
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
}

__device__ void md5_core(const uint8_t *data, int len, uint32_t *digest) {
  digest[0] = 0x67452301;
  digest[1] = 0xefcdab89;
  digest[2] = 0x98badcfe;
  digest[3] = 0x10325476;
  uint8_t buffer[128];
  for (int i = 0; i < 128; i++)
    buffer[i] = 0;
  for (int i = 0; i < len && i < 120; i++)
    buffer[i] = data[i];
  buffer[len] = 0x80;
  int paddedLen = (len < 56) ? 64 : 128;
  uint64_t bits = (uint64_t)len * 8;
  for (int i = 0; i < 8; i++)
    buffer[paddedLen - 8 + i] = (bits >> (i * 8)) & 0xFF;
  for (int off = 0; off < paddedLen; off += 64)
    md5_process_block(digest, buffer + off);
}

// ============================================================
// SHA-1 Multi-Block (up to 119 bytes input)
// ============================================================
__device__ void sha1_process_block(uint32_t *state, const uint8_t *block) {
  uint32_t w[80];
  for (int i = 0; i < 16; i++)
    w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
           (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
           (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
           static_cast<uint32_t>(block[i * 4 + 3]);
  for (int i = 16; i < 80; i++)
    w[i] = ROTL32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
  uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
  for (int i = 0; i < 80; i++) {
    uint32_t f, k;
    if (i < 20) {
      f = (b & c) | (~b & d);
      k = 0x5A827999;
    } else if (i < 40) {
      f = b ^ c ^ d;
      k = 0x6ED9EBA1;
    } else if (i < 60) {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8F1BBCDC;
    } else {
      f = b ^ c ^ d;
      k = 0xCA62C1D6;
    }
    uint32_t tmp = ROTL32(a, 5) + f + e + k + w[i];
    e = d;
    d = c;
    c = ROTL32(b, 30);
    b = a;
    a = tmp;
  }
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
}

__device__ void sha1_core(const uint8_t *data, int len, uint32_t *hash) {
  hash[0] = 0x67452301;
  hash[1] = 0xefcdab89;
  hash[2] = 0x98badcfe;
  hash[3] = 0x10325476;
  hash[4] = 0xc3d2e1f0;
  uint8_t buffer[128];
  for (int i = 0; i < 128; i++)
    buffer[i] = 0;
  for (int i = 0; i < len && i < 120; i++)
    buffer[i] = data[i];
  buffer[len] = 0x80;
  int paddedLen = (len < 56) ? 64 : 128;
  uint64_t bits = (uint64_t)len * 8;
  for (int i = 0; i < 8; i++)
    buffer[paddedLen - 1 - i] = (bits >> (i * 8)) & 0xFF;
  for (int off = 0; off < paddedLen; off += 64)
    sha1_process_block(hash, buffer + off);
}

// MD4 Implementation on GPU (RFC 1320 - for NTLM & MD4)
__device__ void md4_process_block(uint32_t *state, const uint8_t *block) {
    uint32_t w[16];
    for(int i=0; i<16; i++) {
        w[i] = ((uint32_t)block[i*4]) | (((uint32_t)block[i*4+1]) << 8) |
               (((uint32_t)block[i*4+2]) << 16) | (((uint32_t)block[i*4+3]) << 24);
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];

    #define F_4(x, y, z) (((x) & (y)) | ((~x) & (z)))
    #define G_4(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
    #define H_4(x, y, z) ((x) ^ (y) ^ (z))
    #define R1_4(a,b,c,d,k,s) a = ROTL32((a + F_4(b,c,d) + w[k]), s)
    #define R2_4(a,b,c,d,k,s) a = ROTL32((a + G_4(b,c,d) + w[k] + 0x5A827999), s)
    #define R3_4(a,b,c,d,k,s) a = ROTL32((a + H_4(b,c,d) + w[k] + 0x6ED9EBA1), s)

    R1_4(a,b,c,d, 0, 3); R1_4(d,a,b,c, 1, 7); R1_4(c,d,a,b, 2, 11); R1_4(b,c,d,a, 3, 19);
    R1_4(a,b,c,d, 4, 3); R1_4(d,a,b,c, 5, 7); R1_4(c,d,a,b, 6, 11); R1_4(b,c,d,a, 7, 19);
    R1_4(a,b,c,d, 8, 3); R1_4(d,a,b,c, 9, 7); R1_4(c,d,a,b,10, 11); R1_4(b,c,d,a,11, 19);
    R1_4(a,b,c,d,12, 3); R1_4(d,a,b,c,13, 7); R1_4(c,d,a,b,14, 11); R1_4(b,c,d,a,15, 19);

    R2_4(a,b,c,d, 0, 3); R2_4(d,a,b,c, 4, 5); R2_4(c,d,a,b, 8, 9); R2_4(b,c,d,a,12, 13);
    R2_4(a,b,c,d, 1, 3); R2_4(d,a,b,c, 5, 5); R2_4(c,d,a,b, 9, 9); R2_4(b,c,d,a,13, 13);
    R2_4(a,b,c,d, 2, 3); R2_4(d,a,b,c, 6, 5); R2_4(c,d,a,b,10, 9); R2_4(b,c,d,a,14, 13);
    R2_4(a,b,c,d, 3, 3); R2_4(d,a,b,c, 7, 5); R2_4(c,d,a,b,11, 9); R2_4(b,c,d,a,15, 13);

    R3_4(a,b,c,d, 0, 3); R3_4(d,a,b,c, 8, 9); R3_4(c,d,a,b, 4, 11); R3_4(b,c,d,a,12, 15);
    R3_4(a,b,c,d, 2, 3); R3_4(d,a,b,c,10, 9); R3_4(c,d,a,b, 6, 11); R3_4(b,c,d,a,14, 15);
    R3_4(a,b,c,d, 1, 3); R3_4(d,a,b,c, 9, 9); R3_4(c,d,a,b, 5, 11); R3_4(b,c,d,a,13, 15);
    R3_4(a,b,c,d, 3, 3); R3_4(d,a,b,c,11, 9); R3_4(c,d,a,b, 7, 11); R3_4(b,c,d,a,15, 15);

    #undef F_4
    #undef G_4
    #undef H_4
    #undef R1_4
    #undef R2_4
    #undef R3_4

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

__device__ void md4_core(const uint8_t *data, int len, uint32_t *digest) {
    digest[0] = 0x67452301; digest[1] = 0xefcdab89;
    digest[2] = 0x98badcfe; digest[3] = 0x10325476;
    uint8_t buffer[128];
    for(int i=0; i<128; i++) buffer[i] = 0;
    for(int i=0; i<len && i<120; i++) buffer[i] = data[i];
    buffer[len] = 0x80;
    int paddedLen = (len < 56) ? 64 : 128;
    uint64_t bits = (uint64_t)len * 8;
    for(int i=0; i<8; i++) buffer[paddedLen-8+i] = (bits >> (i*8)) & 0xFF;
    for(int off=0; off<paddedLen; off+=64) md4_process_block(digest, buffer+off);
}

// --- Global Kernels ---

extern "C" __global__ void verify_gpu_execution(int *d_output) {
  if (threadIdx.x == 0 && blockIdx.x == 0) {
    *d_output = 1337;
  }
}

// Hash Calculator: single-thread, compute hash for display
extern "C" __global__ void gpu_hash_calculator(const char *input,
                                                    char *output_hex) {
  int idx = threadIdx.x + blockIdx.x * blockDim.x;
  if (idx > 0)
    return;
  int len = d_strlen(input);
  uint32_t hash_res[8];
  sha256_core((const uint8_t *)input, len, hash_res);
  for (int i = 0; i < 8; i++)
    d_uint32_to_hex(hash_res[i], output_hex + (i * 8));
  output_hex[64] = 0;
}

// ============================================================
// Universal GPU Brute Force Kernel (MD5, SHA1, SHA256, SHA512 + Salt)
// ============================================================
extern "C" __global__ void
gpu_brute_force_kernel(const char *charset, int charsetLen, int length,
                       int prefixLen, const char *prefix,
                       unsigned long long offset, unsigned long long maxCombinations,
                       const char *targetHash, int hashType, const char *salt,
                       int saltLen, int *d_found, char *d_result) {
  const int maxCombinedLen = hashType == 3 ? 239 : 119;
  if (charsetLen <= 0 || length < 1 || prefixLen < 0 ||
      prefixLen >= length || !prefix || saltLen < 0 ||
      length > maxCombinedLen || saltLen > maxCombinedLen - length ||
      (hashType == 11 && length > 59))
    return;
  if (!(hashType == 0 || hashType == 1 || hashType == 2 || hashType == 3 ||
        hashType == 11 || hashType == 12))
    return;
  unsigned long long relativeIdx = (unsigned long long)threadIdx.x +
                                   (unsigned long long)blockIdx.x * blockDim.x;
  // The host checks d_found between launches; only the winning write is atomic.
  if (offset >= maxCombinations) return;
  if (relativeIdx >= maxCombinations - offset)
    return;
  unsigned long long idx = offset + relativeIdx;

  // Build candidate password
  char candidate[256];
  for (int i = 0; i < prefixLen; ++i) candidate[i] = prefix[i];
  unsigned long long temp = idx;
  const int suffixLen = length - prefixLen;
  for (int i = 0; i < suffixLen; i++) {
    candidate[length - 1 - i] = charset[temp % charsetLen];
    temp /= charsetLen;
  }

  // Append salt
  int combinedLen = length;
  if (saltLen > 0) {
    for (int i = 0; i < saltLen; i++)
      candidate[length + i] = salt[i];
    combinedLen += saltLen;
  }
  candidate[combinedLen] = '\0';

  // Hash with the correct algorithm
  uint32_t hash_res[8];
  char hex_output[129];
  int hexLen = 0;

  if (hashType == 0) { // MD5
    md5_core((const uint8_t *)candidate, combinedLen, hash_res);
    for (int i = 0; i < 4; i++)
      d_uint32_to_hex_le(hash_res[i], hex_output + i * 8);
    hexLen = 32;
  } else if (hashType == 1) { // SHA1
    sha1_core((const uint8_t *)candidate, combinedLen, hash_res);
    for (int i = 0; i < 5; i++)
      d_uint32_to_hex(hash_res[i], hex_output + i * 8);
    hexLen = 40;
  } else if (hashType == 11) { // NTLM: MD4(UTF-16LE(candidate))
    uint8_t utf16[128];
    for (int i = 0; i < length && i < 60; i++) {
      utf16[i * 2] = candidate[i];
      utf16[i * 2 + 1] = 0;
    }
    md4_core(utf16, length * 2, hash_res);
    for (int i = 0; i < 4; i++)
      d_uint32_to_hex_le(hash_res[i], hex_output + i * 8);
    hexLen = 32;
  } else if (hashType == 12) { // MD4
    md4_core((const uint8_t *)candidate, combinedLen, hash_res);
    for (int i = 0; i < 4; i++)
      d_uint32_to_hex_le(hash_res[i], hex_output + i * 8);
    hexLen = 32;
  } else if (hashType == 3) { // SHA-512
    uint64_t sha512_res[8];
    sha512_core((const uint8_t *)candidate, combinedLen, sha512_res);
    for (int i = 0; i < 8; i++)
      d_uint64_to_hex(sha512_res[i], hex_output + i * 16);
    hexLen = 128;
  } else { // SHA256 (default)
    sha256_core((const uint8_t *)candidate, combinedLen, hash_res);
    for (int i = 0; i < 8; i++)
      d_uint32_to_hex(hash_res[i], hex_output + i * 8);
    hexLen = 64;
  }
  hex_output[hexLen] = 0;

  // Compare
  bool match = true;
  for (int i = 0; i < hexLen; i++) {
    if (hex_output[i] != targetHash[i]) {
      match = false;
      break;
    }
  }

  if (match) {
    if (atomicCAS(d_found, 0, 1) == 0) {
      d_strcpy(d_result, candidate);
      d_result[length] = '\0'; // Only store the password, not salt
    }
  }
}

// ============================================================
// Host Wrappers
// ============================================================

static int launch_gpu_brute_force_impl(
    const char *charset, const char *target, int max_len, char *result,
    int hashType, const char *salt, unsigned long long *attempts_out,
    void *progress_context, CudaProgressCallback progress_callback,
    unsigned long long indexLimit) {
  if (attempts_out) *attempts_out = 0;
  if (!result) return 0;
  result[0] = '\0';
  if (!charset || !target || max_len < 1) return 0;
  int charsetLen = (int)strlen(charset);
  if (charsetLen < 1) return 0;
  const int supportedType = hashType == 0 || hashType == 1 || hashType == 2 ||
                            hashType == 3 || hashType == 11 || hashType == 12;
  const int saltLen = salt ? (int)strlen(salt) : 0;
  const size_t maxCombinedLen = hashType == 3 ? 239 : 119;
  if (!supportedType || saltLen < 0 ||
      static_cast<size_t>(max_len) + static_cast<size_t>(saltLen) >
          maxCombinedLen ||
      (hashType == 11 && max_len > 59))
    return 0;
  if (hashType == 11 &&
      std::any_of(charset, charset + charsetLen,
                  [](unsigned char c) { return c > 0x7F; }))
    return 0;
  if (cudaShouldFail(CERBERUS_CUDA_FAIL_DRIVER_INITIALIZATION)) return 0;
  char *d_charset = nullptr, *d_prefix = nullptr, *d_target = nullptr;
  char *d_result = nullptr, *d_salt = nullptr;
  int *d_found = nullptr;
  auto releaseBuffers = [&]() {
    if (d_charset) cudaFree(d_charset);
    if (d_prefix) cudaFree(d_prefix);
    if (d_target) cudaFree(d_target);
    if (d_found) cudaFree(d_found);
    if (d_result) cudaFree(d_result);
    if (d_salt) cudaFree(d_salt);
  };
  auto fail = [&]() {
    releaseBuffers();
    return 0;
  };

  if (cerberusCudaMalloc(reinterpret_cast<void **>(&d_charset),
                         charsetLen + 1) != cudaSuccess ||
      cerberusCudaMalloc(reinterpret_cast<void **>(&d_prefix),
                         static_cast<size_t>(max_len) + 1) != cudaSuccess ||
      cerberusCudaMalloc(reinterpret_cast<void **>(&d_target), 129) !=
          cudaSuccess ||
      cerberusCudaMalloc(reinterpret_cast<void **>(&d_found), sizeof(int)) !=
          cudaSuccess ||
      cerberusCudaMalloc(reinterpret_cast<void **>(&d_result), 256) !=
          cudaSuccess ||
      cerberusCudaMalloc(reinterpret_cast<void **>(&d_salt), saltLen + 1) !=
          cudaSuccess)
    return fail();

  // Normalize supported hexadecimal target hashes.
  char lowerTarget[129] = {0};
  if (target) {
    size_t tLen = strlen(target);
    if (tLen >= sizeof(lowerTarget)) tLen = sizeof(lowerTarget) - 1;
    for (size_t i = 0; i < tLen; i++) {
      char c = target[i];
      if (c >= 'A' && c <= 'Z') c = c + ('a' - 'A');
      lowerTarget[i] = c;
    }
  }

  if (cerberusCudaMemcpy(d_charset, charset, charsetLen + 1,
                         cudaMemcpyHostToDevice) != cudaSuccess ||
      cerberusCudaMemcpy(d_target, lowerTarget, strlen(lowerTarget) + 1,
                         cudaMemcpyHostToDevice) != cudaSuccess ||
      cerberusCudaMemset(d_found, 0, sizeof(int)) != cudaSuccess ||
      cerberusCudaMemcpy(d_salt, salt ? salt : "", saltLen + 1,
                         cudaMemcpyHostToDevice) != cudaSuccess)
    return fail();

  // A single CUDA launch indexes at most 64 bits. For longer passwords, keep
  // a fixed prefix on the host and enumerate only a representable suffix on
  // the GPU. The prefix odometer itself has no global numeric index.
  const unsigned long long radix = static_cast<unsigned long long>(charsetLen);
  const unsigned long long maxIndex = indexLimit;
  unsigned long long suffixCapacity = 1;
  int maxSuffixLength = 0;
  while (maxSuffixLength < max_len && suffixCapacity <= maxIndex / radix) {
    suffixCapacity *= radix;
    ++maxSuffixLength;
  }
  if (maxSuffixLength == 0) return fail();

  int blockSize = 256;
  int executionSucceeded = 1;
  unsigned long long completedAttempts = 0;

  for (int len = 1; len <= max_len; len++) {
    const int suffixLen = std::min(len, maxSuffixLength);
    const int prefixLen = len - suffixLen;
    if (progress_callback)
      progress_callback(progress_context, 0, completedAttempts, 0.0, len,
                        max_len);
    unsigned long long totalCombinations = 1;
    for (int i = 0; i < suffixLen; ++i) {
      if (totalCombinations > maxIndex / radix) return fail();
      totalCombinations *= radix;
    }

    std::vector<size_t> prefixDigits(static_cast<size_t>(prefixLen), 0);
    std::string prefix(static_cast<size_t>(prefixLen) + 1, '\0');
    bool morePrefixes = true;
    while (morePrefixes) {
      for (int i = 0; i < prefixLen; ++i)
        prefix[static_cast<size_t>(i)] = charset[prefixDigits[static_cast<size_t>(i)]];
      prefix[static_cast<size_t>(prefixLen)] = '\0';
      if (cerberusCudaMemcpy(d_prefix, prefix.c_str(), prefix.size(),
                             cudaMemcpyHostToDevice) != cudaSuccess) {
        executionSucceeded = 0;
        goto cleanup;
      }
      long double prefixFraction = 0.0L;
      long double prefixScale = 1.0L;
      for (int i = 0; i < prefixLen; ++i) {
        prefixFraction =
            (prefixFraction + static_cast<long double>(
                                  prefixDigits[static_cast<size_t>(i)])) /
            static_cast<long double>(radix);
        prefixScale /= static_cast<long double>(radix);
      }

      // Launch enough batches to cover this prefix's suffix keyspace.
      for (unsigned long long offset = 0; offset < totalCombinations;) {
        const unsigned long long remaining = totalCombinations - offset;
        const unsigned long long blocksNeeded =
            remaining / blockSize + (remaining % blockSize != 0 ? 1 : 0);
        const int numBlocks =
            (blocksNeeded > 65535) ? 65535 : static_cast<int>(blocksNeeded);
        unsigned long long launched =
            static_cast<unsigned long long>(numBlocks) * blockSize;
        if (launched > remaining) launched = remaining;

        dim3 grid(numBlocks);
        dim3 block(blockSize);
        if (cudaShouldFail(CERBERUS_CUDA_FAIL_KERNEL_LAUNCH)) {
          executionSucceeded = 0;
          goto cleanup;
        }
        KERNEL_LAUNCH(gpu_brute_force_kernel, grid, block, d_charset, charsetLen,
                      len, prefixLen, d_prefix, offset, totalCombinations,
                      d_target, hashType, d_salt, saltLen, d_found, d_result);
        const cudaError_t launchError =
            cudaShouldFail(CERBERUS_CUDA_FAIL_LAUNCH_STATUS)
                ? cudaErrorLaunchFailure
                : cudaGetLastError();
        if (launchError != cudaSuccess ||
            (cudaShouldFail(CERBERUS_CUDA_FAIL_SYNCHRONIZE)
                 ? cudaErrorLaunchFailure
                 : cudaDeviceSynchronize()) != cudaSuccess) {
          executionSucceeded = 0;
          goto cleanup;
        }

        if (attempts_out) {
          const unsigned long long attemptLimit =
              std::numeric_limits<unsigned long long>::max();
          *attempts_out = launched > attemptLimit - *attempts_out
                              ? attemptLimit
                              : *attempts_out + launched;
        }
        const unsigned long long attemptLimit =
            std::numeric_limits<unsigned long long>::max();
        completedAttempts = launched > attemptLimit - completedAttempts
                                ? attemptLimit
                                : completedAttempts + launched;

        if (progress_callback) {
          const long double suffixFraction =
              static_cast<long double>(offset + launched) /
              static_cast<long double>(totalCombinations);
          const long double lengthFraction = std::min(
              1.0L, prefixFraction + suffixFraction * prefixScale);
          const double progressPct =
              static_cast<double>(std::max(0.0L, lengthFraction) * 100.0L);
          progress_callback(progress_context, launched, completedAttempts,
                            progressPct, len, max_len);
        }

        int h_found = 0;
        if (cerberusCudaMemcpy(&h_found, d_found, sizeof(int),
                               cudaMemcpyDeviceToHost) != cudaSuccess) {
          executionSucceeded = 0;
          goto cleanup;
        }
        if (h_found) {
          if (cerberusCudaMemcpy(result, d_result, len + 1,
                                 cudaMemcpyDeviceToHost) != cudaSuccess) {
            executionSucceeded = 0;
          } else {
            result[len] = '\0';
          }
          goto cleanup;
        }
        if (launched >= remaining) break;
        offset += launched;
      }

      int digit = prefixLen - 1;
      while (digit >= 0) {
        size_t &value = prefixDigits[static_cast<size_t>(digit)];
        if (++value < static_cast<size_t>(charsetLen)) break;
        value = 0;
        --digit;
      }
      morePrefixes = digit >= 0;
    }
  }

cleanup:
  releaseBuffers();
  return executionSucceeded;
}

extern "C" int launch_gpu_brute_force_ext(
    const char *charset, const char *target, int max_len, char *result,
    int hashType, const char *salt, unsigned long long *attempts_out,
    void *progress_context, CudaProgressCallback progress_callback) {
  return launch_gpu_brute_force_impl(
      charset, target, max_len, result, hashType, salt, attempts_out,
      progress_context, progress_callback,
      std::numeric_limits<unsigned long long>::max());
}

#if defined(CERBERUS_TESTING)
extern "C" int launch_gpu_brute_force_ext_test_limit(
    const char *charset, const char *target, int max_len, char *result,
    int hashType, const char *salt, unsigned long long *attempts_out,
    unsigned long long indexLimit) {
  return launch_gpu_brute_force_impl(charset, target, max_len, result, hashType,
                                     salt, attempts_out, nullptr, nullptr,
                                     indexLimit);
}
#endif

extern "C" void launch_gpu_brute_force(const char *charset, const char *target,
                                       int max_len, char *result) {
  launch_gpu_brute_force_ext(charset, target, max_len, result,
                             2 /*SHA256*/, "", nullptr, nullptr, nullptr);
}

extern "C" void launch_cuda_test(int *h_output) {
  if (!h_output) return;
  *h_output = 0;
  int *d_output = nullptr;
  if (cudaMalloc(&d_output, sizeof(int)) != cudaSuccess) return;
  if (cudaMemset(d_output, 0, sizeof(int)) != cudaSuccess) {
    cudaFree(d_output);
    return;
  }
  dim3 grid(1);
  dim3 block(1);
  KERNEL_LAUNCH(verify_gpu_execution, grid, block, d_output);
  if (cudaGetLastError() == cudaSuccess &&
      cudaDeviceSynchronize() == cudaSuccess)
    cudaMemcpy(h_output, d_output, sizeof(int), cudaMemcpyDeviceToHost);
  cudaFree(d_output);
}

extern "C" void launch_gpu_hash_calc(const char *input, char *output_hex) {
  if (!output_hex) return;
  output_hex[0] = '\0';
  if (!input) return;
  const size_t len = strlen(input);
  // sha256_core uses a 128-byte local buffer and supports up to 119 bytes.
  if (len > 119) return;

  char *d_input = nullptr;
  char *d_output = nullptr;
  bool ok = cudaMalloc(&d_input, len + 1) == cudaSuccess;
  if (ok) ok = cudaMalloc(&d_output, 65) == cudaSuccess;
  if (ok) ok = cudaMemcpy(d_input, input, len + 1,
                          cudaMemcpyHostToDevice) == cudaSuccess;
  if (ok) ok = cudaMemset(d_output, 0, 65) == cudaSuccess;
  if (ok) {
    dim3 grid(1);
    dim3 block(1);
    KERNEL_LAUNCH(gpu_hash_calculator, grid, block, d_input, d_output);
    ok = cudaGetLastError() == cudaSuccess &&
         cudaDeviceSynchronize() == cudaSuccess;
  }
  if (ok) ok = cudaMemcpy(output_hex, d_output, 65,
                          cudaMemcpyDeviceToHost) == cudaSuccess;
  if (d_input) cudaFree(d_input);
  if (d_output) cudaFree(d_output);
  if (!ok) output_hex[0] = '\0';
}
