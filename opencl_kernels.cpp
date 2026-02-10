#define CL_TARGET_OPENCL_VERSION 300
#define CL_USE_DEPRECATED_OPENCL_1_2_APIS // For wider compatibility
#include <CL/cl.h>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

// --- Embedded OpenCL C Kernel Source ---
const char *kernelSource = R"(
// Rotate Left (for MD5/SHA1)
#define R(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
// Rotate Right (for SHA256)
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
// Rotate Right (for SHA512)
#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

// --- SHA256 K Constants ---
__constant unsigned int K256[64] = {
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
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// --- SHA512 K Constants ---
__constant unsigned long K512[80] = {
    0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
    0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
    0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
    0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
    0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
    0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
    0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
    0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
    0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
    0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
    0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
    0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
    0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
    0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
    0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
    0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
    0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
    0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
    0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
    0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL
};

// --- Common Macros ---
#define Ch(x, y, z) ((x & y) ^ (~x & z))
#define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

// --- SHA256 Macros ---
#define Sigma0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define Sigma1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define sigma1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

// --- SHA512 Macros ---
#define Sigma0_512(x) (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define Sigma1_512(x) (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define sigma0_512(x) (ROTR64(x, 1) ^ ROTR64(x, 8) ^ ((x) >> 7))
#define sigma1_512(x) (ROTR64(x, 19) ^ ROTR64(x, 61) ^ ((x) >> 6))

// ============================================================
// SHA-256 Multi-Block Implementation (supports up to 119 bytes)
// ============================================================
void sha256_process_block(unsigned int *state, const unsigned char *block) {
    unsigned int w[64];
    for(int i=0; i<16; i++) {
        w[i] = ((unsigned int)block[i*4] << 24) | ((unsigned int)block[i*4+1] << 16) |
               ((unsigned int)block[i*4+2] << 8) | (unsigned int)block[i*4+3];
    }
    for(int i=16; i<64; i++) {
        w[i] = sigma1(w[i-2]) + w[i-7] + sigma0(w[i-15]) + w[i-16];
    }
    unsigned int a=state[0], b=state[1], c=state[2], d=state[3];
    unsigned int e=state[4], f=state[5], g=state[6], h=state[7];
    for(int i=0; i<64; i++) {
        unsigned int t1 = h + Sigma1(e) + Ch(e,f,g) + K256[i] + w[i];
        unsigned int t2 = Sigma0(a) + Maj(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

void sha256_core(const unsigned char *data, int len, unsigned int *hash) {
    hash[0]=0x6a09e667; hash[1]=0xbb67ae85; hash[2]=0x3c6ef372; hash[3]=0xa54ff53a;
    hash[4]=0x510e527f; hash[5]=0x9b05688c; hash[6]=0x1f83d9ab; hash[7]=0x5be0cd19;
    unsigned char buffer[128];
    for(int i=0; i<128; i++) buffer[i] = 0;
    for(int i=0; i<len && i<120; i++) buffer[i] = data[i];
    buffer[len] = 0x80;
    int paddedLen = (len < 56) ? 64 : 128;
    unsigned long bits = (unsigned long)len * 8;
    for(int i=0; i<8; i++) buffer[paddedLen-1-i] = (bits >> (i*8)) & 0xFF;
    for(int off=0; off<paddedLen; off+=64) sha256_process_block(hash, buffer+off);
}

// ============================================================
// SHA-512 Multi-Block Implementation (supports up to 239 bytes)
// ============================================================
void sha512_process_block(unsigned long *state, const unsigned char *block) {
    unsigned long w[16];
    for (int i = 0; i < 16; i++) {
        w[i] = ((unsigned long)block[i*8] << 56) | ((unsigned long)block[i*8+1] << 48) |
               ((unsigned long)block[i*8+2] << 40) | ((unsigned long)block[i*8+3] << 32) |
               ((unsigned long)block[i*8+4] << 24) | ((unsigned long)block[i*8+5] << 16) |
               ((unsigned long)block[i*8+6] << 8) | (unsigned long)block[i*8+7];
    }
    unsigned long a=state[0], b=state[1], c=state[2], d=state[3];
    unsigned long e=state[4], f=state[5], g=state[6], h=state[7];
    for (int i = 0; i < 80; i++) {
        unsigned long W_i;
        if (i < 16) { W_i = w[i]; }
        else {
            W_i = sigma1_512(w[(i-2)&0xF]) + w[(i-7)&0xF] +
                  sigma0_512(w[(i-15)&0xF]) + w[(i-16)&0xF];
            w[i & 0xF] = W_i;
        }
        unsigned long t1 = h + Sigma1_512(e) + Ch(e,f,g) + K512[i] + W_i;
        unsigned long t2 = Sigma0_512(a) + Maj(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

void sha512_core(const unsigned char *data, int len, unsigned long *hash) {
    hash[0]=0x6a09e667f3bcc908UL; hash[1]=0xbb67ae8584caa73bUL;
    hash[2]=0x3c6ef372fe94f82bUL; hash[3]=0xa54ff53a5f1d36f1UL;
    hash[4]=0x510e527fade682d1UL; hash[5]=0x9b05688c2b3e6c1fUL;
    hash[6]=0x1f83d9abfb41bd6bUL; hash[7]=0x5be0cd19137e2179UL;
    unsigned char buffer[256];
    for(int i=0; i<256; i++) buffer[i] = 0;
    for(int i=0; i<len && i<240; i++) buffer[i] = data[i];
    buffer[len] = 0x80;
    int paddedLen = (len < 112) ? 128 : 256;
    unsigned long bits = (unsigned long)len * 8;
    for(int i=0; i<8; i++) buffer[paddedLen-1-i] = (bits >> (i*8)) & 0xFF;
    for(int off=0; off<paddedLen; off+=128) sha512_process_block(hash, buffer+off);
}

// ============================================================
// MD5 Multi-Block Implementation (supports up to 119 bytes)
// ============================================================
__constant unsigned int K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

void md5_process_block(unsigned int *state, const unsigned char *block) {
    unsigned int w[16];
    for(int i=0; i<16; i++) {
        w[i] = ((unsigned int)block[i*4]) | (((unsigned int)block[i*4+1]) << 8) |
               (((unsigned int)block[i*4+2]) << 16) | (((unsigned int)block[i*4+3]) << 24);
    }
    unsigned int a = state[0], b = state[1], c = state[2], d = state[3];
    for(int i=0; i<64; i++) {
        unsigned int f, g;
        if (i < 16) { f = (b & c) | ((~b) & d); g = i; }
        else if (i < 32) { f = (d & b) | ((~d) & c); g = (5*i + 1) % 16; }
        else if (i < 48) { f = b ^ c ^ d; g = (3*i + 5) % 16; }
        else { f = c ^ (b | (~d)); g = (7*i) % 16; }
        unsigned int temp = d; d = c; c = b;
        unsigned int r[] = {7,12,17,22, 5,9,14,20, 4,11,16,23, 6,10,15,21};
        unsigned int shift = r[(i/16)*4 + (i%4)];
        b = b + LEFTROTATE((a + f + K[i] + w[g]), shift);
        a = temp;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

void md5_core(const unsigned char *data, int len, unsigned int *digest) {
    digest[0] = 0x67452301; digest[1] = 0xefcdab89;
    digest[2] = 0x98badcfe; digest[3] = 0x10325476;
    unsigned char buffer[128];
    for(int i=0; i<128; i++) buffer[i] = 0;
    for(int i=0; i<len && i<120; i++) buffer[i] = data[i];
    buffer[len] = 0x80;
    int paddedLen = (len < 56) ? 64 : 128;
    unsigned long bits = (unsigned long)len * 8;
    for(int i=0; i<8; i++) buffer[paddedLen-8+i] = (bits >> (i*8)) & 0xFF;
    for(int off=0; off<paddedLen; off+=64) md5_process_block(digest, buffer+off);
}

// ============================================================
// SHA-1 Multi-Block Implementation (supports up to 119 bytes)
// ============================================================
void sha1_process_block(unsigned int *state, const unsigned char *block) {
    unsigned int w[80];
    for(int i=0; i<16; i++) {
        w[i] = ((unsigned int)block[i*4] << 24) | ((unsigned int)block[i*4+1] << 16) |
               ((unsigned int)block[i*4+2] << 8) | (unsigned int)block[i*4+3];
    }
    for(int i=16; i<80; i++) w[i] = R(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    unsigned int a=state[0], b=state[1], c=state[2], d=state[3], e=state[4];
    for(int i=0; i<80; i++) {
        unsigned int f, k;
        if(i<20){ f=(b&c)|(~b&d); k=0x5A827999; }
        else if(i<40){ f=b^c^d; k=0x6ED9EBA1; }
        else if(i<60){ f=(b&c)|(b&d)|(c&d); k=0x8F1BBCDC; }
        else { f=b^c^d; k=0xCA62C1D6; }
        unsigned int temp = R(a,5)+f+e+k+w[i];
        e=d; d=c; c=R(b,30); b=a; a=temp;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d; state[4]+=e;
}

void sha1_core(const unsigned char *data, int len, unsigned int *hash) {
    hash[0]=0x67452301; hash[1]=0xefcdab89; hash[2]=0x98badcfe;
    hash[3]=0x10325476; hash[4]=0xc3d2e1f0;
    unsigned char buffer[128];
    for(int i=0; i<128; i++) buffer[i] = 0;
    for(int i=0; i<len && i<120; i++) buffer[i] = data[i];
    buffer[len] = 0x80;
    int paddedLen = (len < 56) ? 64 : 128;
    unsigned long bits = (unsigned long)len * 8;
    for(int i=0; i<8; i++) buffer[paddedLen-1-i] = (bits >> (i*8)) & 0xFF;
    for(int off=0; off<paddedLen; off+=64) sha1_process_block(hash, buffer+off);
}

// ============================================================
// Hex Conversion Utility
// ============================================================
void hex_to_string(unsigned int val, char *out, bool reverseBytes) {
    const char hex[] = "0123456789abcdef";
    for(int i=0; i<4; i++) {
        int shift = reverseBytes ? (i*8) : (24-i*8);
        unsigned char byte = (val >> shift) & 0xFF;
        out[2*i] = hex[(byte >> 4) & 0xF];
        out[2*i+1] = hex[byte & 0xF];
    }
}

// ============================================================
// Universal Brute Force Kernel
// ============================================================
__kernel void brute_force_universal(
    __global const char *charset,
    int charsetLen,
    int length,
    ulong offset,
    __global const char *targetHash,
    int hashType,
    __global const char *salt,
    int saltLen,
    __global int *found,
    __global char *result,
    __global ulong *found_index
) {
    ulong gid = get_global_id(0) + offset;
    if (*found) return;

    char candidate[256]; ulong temp = gid;
    for(int i=0; i<length; i++) {
        candidate[length-1-i] = charset[temp % charsetLen];
        temp /= charsetLen;
    }
    
    int combinedLen = length;
    if (saltLen > 0) {
        for(int i=0; i<saltLen; i++) candidate[length+i] = salt[i];
        combinedLen += saltLen;
    }
    candidate[combinedLen] = '\0';
    
    unsigned int res[8]; char hex[256]; int hexLen = 0;
    
    if(hashType == 0) { // MD5
        md5_core((const unsigned char*)candidate, combinedLen, res);
        for(int i=0; i<4; i++) hex_to_string(res[i], hex+(i*8), true);
        hexLen = 32;
    } else if(hashType == 1) { // SHA1
        sha1_core((const unsigned char*)candidate, combinedLen, res);
        for(int i=0; i<5; i++) hex_to_string(res[i], hex+(i*8), false);
        hexLen = 40;
    } else if(hashType == 2) { // SHA256
        sha256_core((const unsigned char*)candidate, combinedLen, res);
        for(int i=0; i<8; i++) hex_to_string(res[i], hex+(i*8), false);
        hexLen = 64;
    } else if(hashType == 3) { // SHA512
        unsigned long res512[8];
        sha512_core((const unsigned char*)candidate, combinedLen, res512);
        for(int i=0; i<8; i++) {
            unsigned long val = res512[i];
            hex_to_string((unsigned int)(val >> 32), hex+(i*16), false);
            hex_to_string((unsigned int)(val & 0xFFFFFFFF), hex+(i*16)+8, false);
        }
        hexLen = 128;
    } else if(hashType == 4) { // WPA2-Sim: sha1(pass + salt + pass)
        for(int i=0; i<length; i++) {
            candidate[combinedLen + i] = candidate[i];
        }
        int wpaLen = combinedLen + length;
        sha1_core((const unsigned char*)candidate, wpaLen, res);
        for(int i=0; i<5; i++) hex_to_string(res[i], hex+(i*8), false);
        hexLen = 40;
)";
const char *kernelSource2 = R"(
    } else if(hashType == 5) { // WPA3-Sim: sha256(pass + salt + "SAE_Dragonfly_Commit")
        const char suffix[] = "SAE_Dragonfly_Commit";
        for(int i=0; i<20; i++) candidate[combinedLen+i] = suffix[i];
        sha256_core((const unsigned char*)candidate, combinedLen+20, res);
        for(int i=0; i<8; i++) hex_to_string(res[i], hex+(i*8), false);
        hexLen = 64;
    } else if(hashType == 6) { // BCRYPT-Sim
        md5_core((const unsigned char*)candidate, combinedLen, res);
        const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        unsigned char bytes[16];
        for(int i=0; i<4; i++) {
             bytes[i*4]   = res[i] & 0xFF;
             bytes[i*4+1] = (res[i] >> 8) & 0xFF;
             bytes[i*4+2] = (res[i] >> 16) & 0xFF;
             bytes[i*4+3] = (res[i] >> 24) & 0xFF;
        }
        const char prefix[] = "$2a$12$";
        for(int i=0; i<7; i++) hex[i] = prefix[i];
        int k = 7;
        for (int i = 0; i < 15; i += 3) {
            unsigned int n = (bytes[i] << 16) + (bytes[i+1] << 8) + bytes[i+2];
            hex[k++] = b64[(n >> 18) & 63];
            hex[k++] = b64[(n >> 12) & 63];
            hex[k++] = b64[(n >> 6) & 63];
            hex[k++] = b64[n & 63];
            if(k >= 29) break;
        }
        if (k < 29) {
             unsigned int n = (bytes[15] << 16);
             hex[k++] = b64[(n >> 18) & 63];
             hex[k++] = b64[(n >> 12) & 63];
        }
        hexLen = 29;
    } else if(hashType == 7) { // SCRYPT-Sim
         const char prefix[] = "SCRYPT:";
         for(int i=0; i<7; i++) hex[i] = prefix[i];
         const char suffix[] = "N=16384,r=8,p=1";
         int suffixLen = 15;
         for(int i=0; i<suffixLen; i++) candidate[combinedLen+i] = suffix[i];
         unsigned int r256[8];
         sha256_core((const unsigned char*)candidate, combinedLen+suffixLen, r256);
         for(int i=0; i<8; i++) hex_to_string(r256[i], hex+7+(i*8), false);
         hexLen = 7 + 64;
    } else if(hashType == 8) { // SOCIAL_FB: sha256(salt + pass)
         char tempBuf[256];
         if (saltLen > 0) {
             for(int i=0; i<saltLen; i++) tempBuf[i] = salt[i];
             for(int i=0; i<length; i++) tempBuf[saltLen+i] = candidate[i];
         } else {
             for(int i=0; i<length; i++) tempBuf[i] = candidate[i];
         }
         const char prefix[] = "FB_SHA256:";
         for(int i=0; i<10; i++) hex[i] = prefix[i];
         unsigned int r256[8];
         sha256_core((const unsigned char*)tempBuf, length+saltLen, r256);
         for(int i=0; i<8; i++) hex_to_string(r256[i], hex+10+(i*8), false);
         hexLen = 10 + 64;
    } else if(hashType == 9) { // SOCIAL_IG: sha512(pass + salt + "instagram_v1")
         const char prefix[] = "IG_ARGON2:";
         for(int i=0; i<10; i++) hex[i] = prefix[i];
         const char suffix[] = "instagram_v1";
         int suffixLen = 12;
         for(int i=0; i<suffixLen; i++) candidate[combinedLen+i] = suffix[i];
         unsigned long r512[8];
         sha512_core((const unsigned char*)candidate, combinedLen+suffixLen, r512);
         for(int i=0; i<8; i++) {
            unsigned long val = r512[i];
            hex_to_string((unsigned int)(val >> 32), hex+10+(i*16), false);
            hex_to_string((unsigned int)(val & 0xFFFFFFFF), hex+10+(i*16)+8, false);
         }
         hexLen = 10 + 128;
    } else if(hashType == 10) { // SOCIAL_TW: md5(pass + salt + "twitter_salt")
         const char prefix[] = "TW_BCRYPT:";
         for(int i=0; i<10; i++) hex[i] = prefix[i];
         const char suffix[] = "twitter_salt";
         int suffixLen = 12;
         for(int i=0; i<suffixLen; i++) candidate[combinedLen+i] = suffix[i];
         md5_core((const unsigned char*)candidate, combinedLen+suffixLen, res);
         for(int i=0; i<4; i++) hex_to_string(res[i], hex+10+(i*8), true);
         hexLen = 10 + 32;
    }
    
    hex[hexLen] = '\0';
    
    bool match = true;
    if (hexLen == 0) match = false; 
    else {
        for(int i=0; i<hexLen; i++) {
            if(hex[i] != targetHash[i]) { match=false; break; }
        }
    }

    if(match) {
        *found = 1;
        *found_index = gid;
        for(int i=0; i<length; i++) result[i] = candidate[i]; 
        result[length] = '\0';
    }
}

__kernel void hash_calculator_universal(
    __global const char *input,
    int len,
    int hashType,
    __global char *output_hex
) {
    unsigned int res[8];
    if(hashType == 0) {
        md5_core((const unsigned char*)input, len, res);
        for(int i=0; i<4; i++) hex_to_string(res[i], output_hex+(i*8), true);
        output_hex[32] = '\0';
    } else if(hashType == 1) {
        sha1_core((const unsigned char*)input, len, res);
        for(int i=0; i<5; i++) hex_to_string(res[i], output_hex+(i*8), false);
        output_hex[40] = '\0';
    } else if(hashType == 3) {
        unsigned long r512[8];
        sha512_core((const unsigned char*)input, len, r512);
        for(int i=0; i<8; i++) {
            unsigned long val = r512[i];
            hex_to_string((unsigned int)(val >> 32), output_hex+(i*16), false);
            hex_to_string((unsigned int)(val & 0xFFFFFFFF), output_hex+(i*16)+8, false);
        }
        output_hex[128] = '\0';
    } else {
        sha256_core((const unsigned char*)input, len, res);
        for(int i=0; i<8; i++) hex_to_string(res[i], output_hex+(i*8), false);
        output_hex[64] = '\0';
    }
}
)";

// --- Host Globals ---
cl_platform_id platform_id = NULL;
cl_device_id device_id = NULL;
cl_context context = NULL;
cl_command_queue command_queue = NULL;
cl_program program = NULL;
cl_kernel kernel = NULL;

void checkErr(cl_int err, const char *name) {
  if (err != CL_SUCCESS) {
    std::cerr << "[OpenCL] ERROR: " << name << " (" << err << ")" << std::endl;
  }
}

// --- Public Interface ---

extern "C" void initOpenCL() {
  cl_int err;
  cl_uint num_platforms;

  std::cout << "\n\x1b[1;36m[OpenCL] Initializing Runtime...\x1b[0m\n";

  err = clGetPlatformIDs(1, &platform_id, &num_platforms);
  checkErr(err, "clGetPlatformIDs");

  err = clGetDeviceIDs(platform_id, CL_DEVICE_TYPE_GPU, 1, &device_id, NULL);
  checkErr(err, "clGetDeviceIDs");

  char deviceName[128];
  clGetDeviceInfo(device_id, CL_DEVICE_NAME, 128, deviceName, NULL);
  std::cout << "  [+] Device: " << deviceName << " (Universal Support)\n";

  context = clCreateContext(NULL, 1, &device_id, NULL, NULL, &err);
  checkErr(err, "clCreateContext");

  command_queue = clCreateCommandQueue(context, device_id, 0, &err);
  checkErr(err, "clCreateCommandQueue");

  const char *sources[] = {kernelSource, kernelSource2};
  program = clCreateProgramWithSource(context, 2, sources, NULL, &err);
  checkErr(err, "clCreateProgramWithSource");

  std::cout << "[OpenCL] Building Kernel (JIT Compilation)...\n";
  err = clBuildProgram(program, 1, &device_id, NULL, NULL, NULL);
  if (err != CL_SUCCESS) {
    size_t len;
    clGetProgramBuildInfo(program, device_id, CL_PROGRAM_BUILD_LOG, 0, NULL,
                          &len);
    char *log = new char[len];
    clGetProgramBuildInfo(program, device_id, CL_PROGRAM_BUILD_LOG, len, log,
                          NULL);
    std::cerr << "[OpenCL] Build Log:\n" << log << std::endl;
    delete[] log;
  }
  checkErr(err, "clBuildProgram");

  kernel = clCreateKernel(program, "brute_force_universal", &err);
  checkErr(err, "clCreateKernel");

  std::cout << "\x1b[1;32m[OpenCL] ENGINE READY.\x1b[0m\n";
}

extern "C" void launch_opencl_brute_force(const char *charset,
                                          const char *target, int max_len,
                                          char *result, int *should_stop,
                                          int hashType, const char *salt,
                                          unsigned long long *attempts_out) {
  cl_int err;
  int charsetLen = (int)strlen(charset);
  int saltLen = salt ? (int)strlen(salt) : 0;
  if (attempts_out)
    *attempts_out = 0;

  cl_mem d_charset =
      clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                     charsetLen + 1, (void *)charset, &err);
  cl_mem d_target =
      clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 256,
                     (void *)target, &err);
  cl_mem d_salt =
      clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                     saltLen + 1, (void *)(salt ? salt : ""), &err);
  cl_mem d_found =
      clCreateBuffer(context, CL_MEM_READ_WRITE, sizeof(int), NULL, &err);
  cl_mem d_result = clCreateBuffer(context, CL_MEM_WRITE_ONLY, 256, NULL, &err);
  cl_mem d_index =
      clCreateBuffer(context, CL_MEM_WRITE_ONLY, sizeof(cl_ulong), NULL, &err);

  int initialFound = 0;
  clEnqueueWriteBuffer(command_queue, d_found, CL_TRUE, 0, sizeof(int),
                       &initialFound, 0, NULL, NULL);

  size_t global_item_size = 1048576; // 1M threads per batch
  size_t local_item_size = 64;

  for (int len = 1; len <= max_len; len++) {
    unsigned long long totalCombinations = 1;
    for (int i = 0; i < len; i++) {
      if (totalCombinations > 0xFFFFFFFFFFFFFFFFULL / charsetLen) {
        totalCombinations = 0xFFFFFFFFFFFFFFFFULL;
        break;
      }
      totalCombinations *= charsetLen;
    }

    for (unsigned long long offset = 0; offset < totalCombinations;
         offset += global_item_size) {
      if (*should_stop)
        break;

      cl_ulong cl_offset = (cl_ulong)offset;

      err = clSetKernelArg(kernel, 0, sizeof(cl_mem), &d_charset);
      err |= clSetKernelArg(kernel, 1, sizeof(int), &charsetLen);
      err |= clSetKernelArg(kernel, 2, sizeof(int), &len);
      err |= clSetKernelArg(kernel, 3, sizeof(cl_ulong), &cl_offset);
      err |= clSetKernelArg(kernel, 4, sizeof(cl_mem), &d_target);
      err |= clSetKernelArg(kernel, 5, sizeof(int), &hashType);
      err |= clSetKernelArg(kernel, 6, sizeof(cl_mem), &d_salt);
      err |= clSetKernelArg(kernel, 7, sizeof(int), &saltLen);
      err |= clSetKernelArg(kernel, 8, sizeof(cl_mem), &d_found);
      err |= clSetKernelArg(kernel, 9, sizeof(cl_mem), &d_result);
      err |= clSetKernelArg(kernel, 10, sizeof(cl_mem), &d_index);

      size_t current_batch_size =
          (totalCombinations - offset < global_item_size)
              ? (size_t)(totalCombinations - offset)
              : global_item_size;

      if (current_batch_size % local_item_size != 0)
        current_batch_size =
            ((current_batch_size / local_item_size) + 1) * local_item_size;

      err = clEnqueueNDRangeKernel(command_queue, kernel, 1, NULL,
                                   &current_batch_size, &local_item_size, 0,
                                   NULL, NULL);
      if (attempts_out)
        *attempts_out += current_batch_size;
      clFinish(command_queue);

      int h_found = 0;
      clEnqueueReadBuffer(command_queue, d_found, CL_TRUE, 0, sizeof(int),
                          &h_found, 0, NULL, NULL);
      if (h_found) {
        clEnqueueReadBuffer(command_queue, d_result, CL_TRUE, 0, 256, result, 0,
                            NULL, NULL);
        if (attempts_out) {
          cl_ulong h_index = 0;
          clEnqueueReadBuffer(command_queue, d_index, CL_TRUE, 0,
                              sizeof(cl_ulong), &h_index, 0, NULL, NULL);
          *attempts_out = 0;
          for (int prev = 1; prev < len; prev++) {
            unsigned long long prevComb = 1;
            for (int j = 0; j < prev; j++) {
              if (prevComb > 0xFFFFFFFFFFFFFFFFULL / charsetLen) {
                prevComb = 0xFFFFFFFFFFFFFFFFULL;
                break;
              }
              prevComb *= charsetLen;
            }
            *attempts_out += prevComb;
          }
          *attempts_out += (h_index + 1);
        }
        goto cleanup;
      }
    }
  }

cleanup:
  clReleaseMemObject(d_charset);
  clReleaseMemObject(d_target);
  clReleaseMemObject(d_salt);
  clReleaseMemObject(d_found);
  clReleaseMemObject(d_result);
  clReleaseMemObject(d_index);
}

extern "C" void launch_opencl_hash_calc(const char *input, char *output_hex,
                                        int hashType) {
  cl_int err;
  int len = (int)strlen(input);

  cl_mem d_input =
      clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, len + 1,
                     (void *)input, &err);
  cl_mem d_output = clCreateBuffer(context, CL_MEM_WRITE_ONLY, 129, NULL, &err);

  cl_kernel calc_kernel =
      clCreateKernel(program, "hash_calculator_universal", &err);

  err = clSetKernelArg(calc_kernel, 0, sizeof(cl_mem), &d_input);
  err |= clSetKernelArg(calc_kernel, 1, sizeof(int), &len);
  err |= clSetKernelArg(calc_kernel, 2, sizeof(int), &hashType);
  err |= clSetKernelArg(calc_kernel, 3, sizeof(cl_mem), &d_output);

  size_t global_item_size = 1;
  err = clEnqueueNDRangeKernel(command_queue, calc_kernel, 1, NULL,
                               &global_item_size, NULL, 0, NULL, NULL);
  clFinish(command_queue);

  clEnqueueReadBuffer(command_queue, d_output, CL_TRUE, 0, 129, output_hex, 0,
                      NULL, NULL);

  clReleaseKernel(calc_kernel);
  clReleaseMemObject(d_input);
  clReleaseMemObject(d_output);
}
