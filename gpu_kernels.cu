
#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// Macro to silence VS IntelliSense errors on triple-bracket syntax
#ifdef __INTELLISENSE__
#define KERNEL_LAUNCH(name, grid, block, ...)
#else
#define KERNEL_LAUNCH(name, grid, block, ...) name<<<grid, block>>>(__VA_ARGS__)
#endif

// --- Device Constants & Macros ---
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

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

// ============================================================
// SHA-256 Multi-Block (up to 119 bytes input)
// ============================================================
__device__ void sha256_process_block(uint32_t *state, const uint8_t *block) {
  uint32_t w[64];
  for (int i = 0; i < 16; i++)
    w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) |
           (block[i * 4 + 2] << 8) | block[i * 4 + 3];
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
    w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) |
           (block[i * 4 + 2] << 8) | block[i * 4 + 3];
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

// --- Global Kernels ---

extern "C" __global__ void verify_gpu_execution(int *d_output) {
  if (threadIdx.x == 0 && blockIdx.x == 0) {
    *d_output = 1337;
  }
}

// Hash Calculator: single-thread, compute hash for display
extern "C" __global__ void gpu_hash_calculator_demo(const char *input,
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
// Universal GPU Brute Force Kernel (MD5, SHA1, SHA256 + Salt)
// ============================================================
extern "C" __global__ void
gpu_brute_force_kernel(const char *charset, int charsetLen, int length,
                       const char *targetHash, int hashType, const char *salt,
                       int saltLen, int *d_found, char *d_result) {
  unsigned long long idx = (unsigned long long)threadIdx.x +
                           (unsigned long long)blockIdx.x * blockDim.x;
  if (*d_found)
    return;

  // Build candidate password
  char candidate[128];
  unsigned long long temp = idx;
  for (int i = 0; i < length; i++) {
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
    *d_found = 1;
    d_strcpy(d_result, candidate);
    d_result[length] = '\0'; // Only store the password, not salt
  }
}

// ============================================================
// Host Wrappers
// ============================================================

extern "C" void launch_gpu_brute_force(const char *charset, const char *target,
                                       int max_len, char *result) {
  int charsetLen = (int)strlen(charset);
  char *d_charset, *d_target, *d_result, *d_salt;
  int *d_found;

  cudaMalloc(&d_charset, charsetLen + 1);
  cudaMalloc(&d_target, 129);
  cudaMalloc(&d_found, sizeof(int));
  cudaMalloc(&d_result, 128);
  cudaMalloc(&d_salt, 1); // No salt in legacy API

  cudaMemcpy(d_charset, charset, charsetLen + 1, cudaMemcpyHostToDevice);
  cudaMemcpy(d_target, target, strlen(target) + 1, cudaMemcpyHostToDevice);
  cudaMemset(d_found, 0, sizeof(int));
  cudaMemset(d_salt, 0, 1);

  int blockSize = 256;

  for (int len = 1; len <= max_len; len++) {
    // Calculate total combinations for this length
    unsigned long long totalCombinations = 1;
    for (int i = 0; i < len; i++)
      totalCombinations *= charsetLen;

    // Launch enough blocks to cover the entire keyspace
    for (unsigned long long offset = 0; offset < totalCombinations;
         offset += (unsigned long long)blockSize * 4096) {
      unsigned long long remaining = totalCombinations - offset;
      int numBlocks = (int)((remaining + blockSize - 1) / blockSize);
      if (numBlocks > 65535)
        numBlocks = 65535;

      dim3 grid(numBlocks);
      dim3 block(blockSize);
      KERNEL_LAUNCH(gpu_brute_force_kernel, grid, block, d_charset, charsetLen,
                    len, d_target, 2 /*SHA256*/, d_salt, 0 /*no salt*/, d_found,
                    d_result);
      cudaDeviceSynchronize();

      int h_found = 0;
      cudaMemcpy(&h_found, d_found, sizeof(int), cudaMemcpyDeviceToHost);
      if (h_found) {
        cudaMemcpy(result, d_result, 128, cudaMemcpyDeviceToHost);
        goto cleanup;
      }
    }
  }

cleanup:
  cudaFree(d_charset);
  cudaFree(d_target);
  cudaFree(d_found);
  cudaFree(d_result);
  cudaFree(d_salt);
}

extern "C" void launch_cuda_test(int *h_output) {
  int *d_output;
  cudaError_t err;
  err = cudaMalloc(&d_output, sizeof(int));
  if (err != cudaSuccess)
    printf("[CUDA Error] Malloc: %s\n", cudaGetErrorString(err));
  err = cudaMemset(d_output, 0, sizeof(int));
  if (err != cudaSuccess)
    printf("[CUDA Error] Memset: %s\n", cudaGetErrorString(err));
  dim3 grid(1);
  dim3 block(1);
  KERNEL_LAUNCH(verify_gpu_execution, grid, block, d_output);
  err = cudaDeviceSynchronize();
  if (err != cudaSuccess)
    printf("[CUDA Error] Kernel Sync: %s\n", cudaGetErrorString(err));
  err = cudaMemcpy(h_output, d_output, sizeof(int), cudaMemcpyDeviceToHost);
  if (err != cudaSuccess)
    printf("[CUDA Error] Memcpy: %s\n", cudaGetErrorString(err));
  cudaFree(d_output);
}

extern "C" void launch_gpu_hash_calc(const char *input, char *output_hex) {
  char *d_input, *d_output;
  int len = (int)strlen(input);
  cudaError_t err;
  err = cudaMalloc(&d_input, len + 1);
  if (err != cudaSuccess)
    printf("[CUDA Error] HashCalc Malloc Input: %s\n", cudaGetErrorString(err));
  err = cudaMalloc(&d_output, 65);
  if (err != cudaSuccess)
    printf("[CUDA Error] HashCalc Malloc Output: %s\n",
           cudaGetErrorString(err));
  err = cudaMemcpy(d_input, input, len + 1, cudaMemcpyHostToDevice);
  if (err != cudaSuccess)
    printf("[CUDA Error] HashCalc Memcpy Input: %s\n", cudaGetErrorString(err));
  err = cudaMemset(d_output, 0, 65);
  dim3 grid(1);
  dim3 block(1);
  KERNEL_LAUNCH(gpu_hash_calculator_demo, grid, block, d_input, d_output);
  err = cudaDeviceSynchronize();
  if (err != cudaSuccess)
    printf("[CUDA Error] HashCalc Kernel Sync: %s\n", cudaGetErrorString(err));
  err = cudaMemcpy(output_hex, d_output, 65, cudaMemcpyDeviceToHost);
  if (err != cudaSuccess)
    printf("[CUDA Error] HashCalc Memcpy Output: %s\n",
           cudaGetErrorString(err));
  cudaFree(d_input);
  cudaFree(d_output);
}
