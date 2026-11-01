#include <algorithm>
#include <atomic>
#include <chrono>
#include <fstream>
#include <iostream>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <unordered_set>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <cstdio>
#include <cstdlib>
#include <windows.h>
#endif

// Include local cryptographic headers
#include "base64.h"
#include "crc32.h"
#include "md4.h"
#include "md5.h"
#include "hmac.h"
#include "picosha2.h"
#include "sha1.h"
#include "sha224.h"
#include "sha512.h"

enum class HashType {
  UNKNOWN,
  TEXT,
  CRC32,         // IEEE 802.3 Checksum (8 hex chars)
  MD5,
  SHA1,
  SHA224,        // FIPS 180-4 (56 hex chars)
  SHA256,
  SHA384,        // FIPS 180-4 (96 hex chars)
  SHA512,
  BASE64,
  NTLM,          // Windows NT Hash (SAM/AD) [Standard Forensic]
  MD4,           // RFC 1320 [Standard Forensic]
  HMAC_MD5,      // RFC 2104 Keyed-Hash (MD5)
  HMAC_SHA1,     // RFC 2104 Keyed-Hash (SHA1)
  HMAC_SHA256,   // RFC 2104 Keyed-Hash (SHA256)
  SALTED_MD5,    // MD5 + Salt
  SALTED_SHA1,   // SHA1 + Salt
  SALTED_SHA256, // SHA256 + Salt
  SALTED_SHA512, // SHA512 + Salt
  WPA2_PBKDF2,   // WPA2 Key Derivation (PBKDF2-HMAC-SHA1)
  WPA3_SAE,      // WPA3 Dragonfly SAE Commit (PoC-Sim)
  BCRYPT,        // Bcrypt (PoC-Sim)
  SCRYPT,        // Scrypt (PoC-Sim)
  SOCIAL_FB,     // Facebook Profile (PoC-Sim)
  SOCIAL_IG,     // Instagram Profile (PoC-Sim)
  SOCIAL_TW,     // Twitter Profile (PoC-Sim)
};

struct Config {
  HashType type = HashType::MD5;
  std::string target;
  std::string targetHash; // For OpenCL
  int hashType = 0;       // For OpenCL kernel
  std::string salt;
  std::string charset;
  int maxLength = 16;
  bool useDictionary = false;
};

// --- Global Config for Compute Unit ---
enum class ComputeType { CPU, CUDA, OPENCL };
ComputeType globalCompute = ComputeType::CPU;

// --- OPENCL FUNCTIONS ---
extern "C" {
int initOpenCL();
void cleanupOpenCL();
const char *get_opencl_device_name();
unsigned long long get_opencl_vram_bytes();
void launch_opencl_brute_force(const char *charset, const char *target,
                               int max_len, char *result, int *should_stop,
                               int hashType, const char *salt,
                               unsigned long long *attempts_out);
void launch_opencl_hash_calc(const char *input, char *output_hex, int hashType);
void set_opencl_quiet(int q);
}

// --- Helper Functions ---
void sleepMs(int ms) {
  std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

// Map local HashType to Kernel-specific Algorithm IDs
int getKernelAlgoId(HashType type) {
  switch (type) {
  case HashType::MD5:
  case HashType::SALTED_MD5:
    return 0;
  case HashType::SHA1:
  case HashType::SALTED_SHA1:
    return 1;
  case HashType::SHA256:
  case HashType::SALTED_SHA256:
    return 2;
  case HashType::SHA512:
  case HashType::SALTED_SHA512:
    return 3;
  case HashType::WPA2_PBKDF2:
    return 4;
  case HashType::WPA3_SAE:
    return 5;
  case HashType::BCRYPT:
    return 6;
  case HashType::SCRYPT:
    return 7;
  case HashType::SOCIAL_FB:
    return 8;
  case HashType::SOCIAL_IG:
    return 9;
  case HashType::SOCIAL_TW:
    return 10;
  case HashType::NTLM:
    return 11;
  case HashType::MD4:
    return 12;
  default:
    return 2; // Default to SHA256
  }
}

std::string getRealGPUName() {
  static std::string cachedGPU = "";
  if (!cachedGPU.empty()) return cachedGPU;

  if (globalCompute == ComputeType::OPENCL) {
    const char *name = get_opencl_device_name();
    if (name && strlen(name) > 0 && strcmp(name, "Dispositivo OpenCL") != 0) {
      cachedGPU = name;
      return cachedGPU;
    }
  }

#if defined(ENABLE_CUDA)
  if (globalCompute == ComputeType::CUDA) {
    cudaDeviceProp prop;
    if (cudaGetDeviceProperties(&prop, 0) == cudaSuccess) {
      cachedGPU = prop.name;
      return cachedGPU;
    }
  }
#endif

  cachedGPU = "GPU Universal (OpenCL/CUDA)";
  return cachedGPU;
}

std::string getRealVRAM() {
  if (globalCompute == ComputeType::OPENCL) {
    unsigned long long vram = get_opencl_vram_bytes();
    if (vram > 0) {
      unsigned long long mb = vram / (1024 * 1024);
      return std::to_string(mb);
    }
  }
#if defined(ENABLE_CUDA)
  if (globalCompute == ComputeType::CUDA) {
    cudaDeviceProp prop;
    if (cudaGetDeviceProperties(&prop, 0) == cudaSuccess) {
      unsigned long long mb = prop.totalGlobalMem / (1024 * 1024);
      return std::to_string(mb);
    }
  }
#endif
  return "N/A";
}

// --- CUDA External Bindings ---
#if defined(ENABLE_CUDA)
extern "C" void launch_cuda_test(int *h_output);
extern "C" void launch_gpu_hash_calc(const char *input, char *output_hex);
extern "C" void launch_gpu_brute_force_ext(const char *charset, const char *target,
                                           int max_len, char *result, int hashType,
                                           const char *salt);

void initCUDA() {
  std::cout
      << "\n\x1b[1;32m[CUDA] Initializing NVIDIA CUDA Runtime...\x1b[0m\n";
  sleepMs(200);
  std::cout << "[CUDA] Detecting CUDA-capable devices...\n";
  std::string gpuName = getRealGPUName();
  std::cout << "  [+] Device 0: " << gpuName << " (Detected)\n";
  std::cout << "  [+] VRAM: " << getRealVRAM() << " MB\n";

  std::cout << "[CUDA] Verifying Kernel Execution...\n";
  int test_val = 0;
  try {
    launch_cuda_test(&test_val);
  } catch (...) {
    test_val = 0;
  }

  if (test_val == 1337) {
    std::cout << "\x1b[1;32m[CUDA] KERNEL EXECUTION SUCCESSFUL. GPU IS "
                 "ACTIVE.\x1b[0m\n";
    globalCompute = ComputeType::CUDA;
  } else {
    std::cout
        << "\x1b[1;33m[CUDA] Native execution verification unavailable. Switching to OpenCL Bridge...\x1b[0m\n";
    globalCompute = ComputeType::OPENCL;
    initOpenCL();
  }

  std::cout << "\x1b[1;32m[GPU] ENGINE READY.\x1b[0m\n\n";
}
#else
void initCUDA() {
  std::cout << "\n\x1b[1;33m[!] CUDA Native Disabled (Incompatible "
               "Toolkit/Hardware).\x1b[0m\n";
  std::cout << "[!] Switching to OpenCL Bridge for universal GPU support...\n";
  globalCompute = ComputeType::OPENCL;
  initOpenCL();
}
#endif

std::string getEngineName() {
  switch (globalCompute) {
  case ComputeType::CUDA:
    return "v3.0-CUDA (NVIDIA)";
  case ComputeType::OPENCL:
    return "v3.0-OPENCL (" + getRealGPUName() + ")";
  default:
    return "v2.0-PARALLEL (CPU)";
  }
}

bool fileExists(const std::string &name) {
  std::ifstream f(name.c_str());
  return f.good();
}

std::string getCharset(int option) {
  switch (option) {
  case 1:
    return "0123456789"; // Numeric
  case 2:
    return "abcdefghijklmnopqrstuvwxyz"; // Lowercase
  case 3:
    return "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; // Uppercase
  case 4:
    return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"; // Mixed Alpha
  case 5:
    return "abcdefghijklmnopqrstuvwxyz0123456789"; // Alphanumeric Lower
  case 6:
    return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"; // Alphanumeric Mixed
  case 7:
    return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%"
           "^&*()-_=+[]{}|;:,.<>?/`~"; // Full ASCII
  default:
    return "abcdefghijklmnopqrstuvwxyz0123456789"; // Default
  }
}

bool isHex(const std::string &input) {
  if (input.empty()) return false;
  for (char c : input) {
    if (!isxdigit(static_cast<unsigned char>(c)))
      return false;
  }
  return true;
}

// 100% Precise Base64 Validator
bool isBase64Strict(const std::string &input, std::string &decodedOut) {
  if (input.empty() || input.length() % 4 != 0) return false;

  size_t padCount = 0;
  bool hasSymbols = false;
  for (size_t i = 0; i < input.length(); i++) {
    char c = input[i];
    if (c == '+' || c == '/') {
      hasSymbols = true;
    } else if (c == '=') {
      padCount++;
      if (i < input.length() - 2) return false; // '=' can only be in the last 2 positions
    } else if (!isalnum(static_cast<unsigned char>(c))) {
      return false;
    }
  }
  if (padCount > 2) return false;

  std::string decoded = base64_decode(input);
  if (decoded.empty()) return false;

  // Verify that re-encoding matches the original input exactly
  std::string reencoded = base64_encode(reinterpret_cast<const unsigned char*>(decoded.data()),
                                        static_cast<unsigned int>(decoded.length()));
  if (reencoded != input) return false;

  // If explicit padding or symbols are present, it is definitely Base64
  if (padCount > 0 || hasSymbols) {
    decodedOut = decoded;
    return true;
  }

  // If no symbols or padding, verify that decoded bytes are printable text
  // (Prevents normal words like 'test' or 'password' from false-triggering)
  for (unsigned char c : decoded) {
    if (!isprint(c) && c != '\r' && c != '\n' && c != '\t') {
      return false;
    }
  }

  decodedOut = decoded;
  return true;
}

HashType identifyHash(const std::string &input) {
  // 1. Prefixed / Modular Crypt Formats (Forensic Standards)
  if (input.rfind("$2a$", 0) == 0 || input.rfind("$2b$", 0) == 0 || input.rfind("$2y$", 0) == 0) {
    return HashType::BCRYPT;
  }
  
  std::string upperInput = input;
  for (char &c : upperInput) c = static_cast<char>(toupper(static_cast<unsigned char>(c)));

  if (upperInput.rfind("SCRYPT:", 0) == 0) {
    return HashType::SCRYPT;
  }
  if (upperInput.rfind("FB_SHA256:", 0) == 0) {
    return HashType::SOCIAL_FB;
  }
  if (upperInput.rfind("IG_ARGON2:", 0) == 0) {
    return HashType::SOCIAL_IG;
  }
  if (upperInput.rfind("TW_BCRYPT:", 0) == 0) {
    return HashType::SOCIAL_TW;
  }

  // 2. Standard Hexadecimal Hashes
  if (isHex(input)) {
    if (input.length() == 8)
      return HashType::CRC32;
    if (input.length() == 32)
      return HashType::MD5; // Can also be NTLM or MD4
    if (input.length() == 40)
      return HashType::SHA1;
    if (input.length() == 56)
      return HashType::SHA224;
    if (input.length() == 64)
      return HashType::SHA256;
    if (input.length() == 96)
      return HashType::SHA384;
    if (input.length() == 128)
      return HashType::SHA512;
  }

  // 3. Strict Base64 validation
  std::string decodedOut;
  if (isBase64Strict(input, decodedOut)) {
    return HashType::BASE64;
  }

  return HashType::UNKNOWN;
}

std::string sha256(const std::string &input) {
  return picosha2::hash256_hex_string(input);
}

// Simple PBKDF2-HMAC-SHA1 Simulation (for WPA2 Proof of Concept)
std::string pbkdf2_sim(const std::string &pass, const std::string &salt) {
  return sha1(pass + salt + pass);
}

std::string hashFunctionExtended(const std::string &pass, HashType type,
                                 const std::string &salt = "") {
  switch (type) {
  case HashType::CRC32:
    return crc32(pass);
  case HashType::MD5:
    return md5(pass);
  case HashType::SHA1:
    return sha1(pass);
  case HashType::SHA224:
    return sha224(pass);
  case HashType::SHA256:
    return picosha2::hash256_hex_string(pass);
  case HashType::SHA384:
    return sha384(pass);
  case HashType::SHA512:
    return sha512(pass);
  case HashType::NTLM:
    return ntlm(pass);
  case HashType::MD4:
    return md4(pass);
  case HashType::HMAC_MD5:
    return hmac_md5(salt.empty() ? "key" : salt, pass);
  case HashType::HMAC_SHA1:
    return hmac_sha1(salt.empty() ? "key" : salt, pass);
  case HashType::HMAC_SHA256:
    return hmac_sha256(salt.empty() ? "key" : salt, pass);
  case HashType::BASE64:
    return base64_encode((unsigned char *)pass.c_str(),
                         (unsigned int)pass.length());

  // Salted Variations
  case HashType::SALTED_MD5:
    return md5(pass + salt);
  case HashType::SALTED_SHA1:
    return sha1(pass + salt);
  case HashType::SALTED_SHA256:
    return picosha2::hash256_hex_string(pass + salt);
  case HashType::SALTED_SHA512:
    return sha512(pass + salt);

  case HashType::WPA2_PBKDF2:
    return pbkdf2_sim(pass, salt);

  // Advanced Simulations for Audit Proof
  case HashType::WPA3_SAE:
    return sha256(pass + salt + "SAE_Dragonfly_Commit");
  case HashType::BCRYPT: {
    MD5 m(pass + salt);
    m.finalize();
    return "$2a$12$" + base64_encode(m.getDigest(), 16).substr(0, 22);
  }
  case HashType::SCRYPT:
    return "SCRYPT:" + sha256(pass + salt + "N=16384,r=8,p=1");

  // Social Media Profiles
  case HashType::SOCIAL_FB:
    return "FB_SHA256:" + sha256(salt + pass);
  case HashType::SOCIAL_IG:
    return "IG_ARGON2:" + sha512(pass + salt + "instagram_v1");
  case HashType::SOCIAL_TW:
    return "TW_BCRYPT:" + md5(pass + salt + "twitter_salt");

  default:
    return pass;
  }
}

std::string hashTypeName(HashType type) {
  switch (type) {
  case HashType::CRC32:
    return "CRC32 (IEEE 802.3)";
  case HashType::MD5:
    return "MD5";
  case HashType::SHA1:
    return "SHA1";
  case HashType::SHA224:
    return "SHA-224 (FIPS 180-4)";
  case HashType::SHA256:
    return "SHA-256";
  case HashType::SHA384:
    return "SHA-384 (FIPS 180-4)";
  case HashType::SHA512:
    return "SHA-512";
  case HashType::BASE64:
    return "Base64";
  case HashType::NTLM:
    return "NTLM (Windows SAM/AD)";
  case HashType::MD4:
    return "MD4 (RFC 1320)";
  case HashType::HMAC_MD5:
    return "HMAC-MD5 (RFC 2104)";
  case HashType::HMAC_SHA1:
    return "HMAC-SHA1 (RFC 2104)";
  case HashType::HMAC_SHA256:
    return "HMAC-SHA256 (RFC 2104)";
  case HashType::WPA2_PBKDF2:
    return "WPA2 (PBKDF2-Sim)";
  case HashType::SALTED_MD5:
    return "MD5 + Salt";
  case HashType::SALTED_SHA1:
    return "SHA1 + Salt";
  case HashType::SALTED_SHA256:
    return "SHA256 + Salt";
  case HashType::SALTED_SHA512:
    return "SHA512 + Salt";
  case HashType::WPA3_SAE:
    return "WPA3 (SAE/Dragonfly)";
  case HashType::BCRYPT:
    return "Bcrypt (Blowfish)";
  case HashType::SCRYPT:
    return "Scrypt (Memory-Hard)";
  case HashType::SOCIAL_FB:
    return "Facebook (SHA-256 Variant)";
  case HashType::SOCIAL_IG:
    return "Instagram (Argon2 Variant)";
  case HashType::SOCIAL_TW:
    return "Twitter (Bcrypt Variant)";
  case HashType::TEXT:
    return "Texto Plano";
  default:
    return "Desconhecido";
  }
}

void enableANSI() {
#ifdef _WIN32
  SetConsoleOutputCP(CP_UTF8);
  SetConsoleCP(CP_UTF8);
  HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
  if (hOut == INVALID_HANDLE_VALUE)
    return;
  DWORD dwMode = 0;
  if (!GetConsoleMode(hOut, &dwMode))
    return;
  dwMode |= 0x0004; // ENABLE_VIRTUAL_TERMINAL_PROCESSING
  SetConsoleMode(hOut, dwMode);
#endif
}

void exibirDesenho() {
  std::cout
      << "\n\x1b[1;36m  SENTINEL DATA SOLUTIONS \x1b[1;30m| \x1b[1;32mSTATUS: "
         "ACTIVE \x1b[1;30m| \x1b[1;34mMOTOR: " << getEngineName() << "\x1b[0m\n";
  std::cout << "\x1b[1;31m  " << R"(  ____  _____  ____   ____   _____  ____   _   _  ____  )" << "\n";
  std::cout << "\x1b[1;31m  " << R"( / ___|| ____||  _ \ | __ ) | ____||  _ \ | | | |/ ___| )" << "\n";
  std::cout << "\x1b[1;33m  " << R"(| |    |  _|  | |_) ||  _ \ |  _|  | |_) || | | |\___ \ )" << "\n";
  std::cout << "\x1b[1;33m  " << R"(| |___ | |___ |  _ < | |_) || |___ |  _ < | |_| | ___) |)" << "\n";
  std::cout << "\x1b[1;35m  " << R"( \____||_____||_| \_\|____/ |_____||_| \_\ \___/ |____/ )" << "\x1b[0m\n";
  std::cout << "\x1b[1;30m  ----------------------------------------------------------------------------\x1b[0m\n";
  std::cout << "  \x1b[1;37mCERBERUS FORENSIC SUITE \x1b[1;30m>> \x1b[38;5;208mDEVELOPED BY ZECA \x1b[1;30m>> \x1b[1;31mTRIPLE-HEADED RECOVERY\x1b[0m\n";
  std::cout << "\x1b[1;30m  ----------------------------------------------------------------------------\x1b[0m\n";
}

// --- Output & Formatting Helpers ---
bool globalQuiet = false;
bool globalVerbose = false;
bool globalJson = false;

// Format numbers with thousands separators (e.g. 13,686,207)
std::string formatNumber(long long n) {
  std::string s = std::to_string(n);
  int insertPos = (int)s.length() - 3;
  while (insertPos > 0) {
    s.insert(insertPos, ",");
    insertPos -= 3;
  }
  return s;
}

// Format duration from milliseconds to human-friendly string
std::string formatTime(long long ms) {
  if (ms <= 0) return "0ms (< 1ms)";
  if (ms < 1000) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%lldms (%.3fs)", ms, ms / 1000.0);
    return buf;
  }
  if (ms < 60000) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%.2fs", ms / 1000.0);
    return buf;
  }
  long long totalSec = ms / 1000;
  long long mins = totalSec / 60;
  long long secs = totalSec % 60;
  char buf[32];
  snprintf(buf, sizeof(buf), "%lldm %02llds", mins, secs);
  return buf;
}

// Format hashrates with dynamic units (H/s, kH/s, MH/s, GH/s)
std::string formatHashrate(double hps) {
  char buf[32];
  if (hps >= 1e9) {
    snprintf(buf, sizeof(buf), "%.2f GH/s", hps / 1e9);
  } else if (hps >= 1e6) {
    snprintf(buf, sizeof(buf), "%.2f MH/s", hps / 1e6);
  } else if (hps >= 1e3) {
    snprintf(buf, sizeof(buf), "%.2f kH/s", hps / 1e3);
  } else {
    snprintf(buf, sizeof(buf), "%lld H/s", (long long)hps);
  }
  return buf;
}

// Format visual progress bar
std::string formatProgressBar(double pct, int width = 12) {
  if (pct < 0.0) pct = 0.0;
  if (pct > 100.0) pct = 100.0;
  int filled = (int)(pct * width / 100.0);
  std::string bar = "[";
  for (int i = 0; i < width; i++) {
    bar += (i < filled) ? "=" : "-";
  }
  bar += "]";
  char pctBuf[16];
  snprintf(pctBuf, sizeof(pctBuf), " %5.1f%%", pct);
  return bar + pctBuf;
}

// Precise aligned box line formatter (Total line width = 76 characters)
void printBoxLine(const std::string &label, const std::string &val,
                  const std::string &colorVal, int totalWidth = 76) {
  const int labelWidth = 13;
  std::string formattedLabel = label;
  while (formattedLabel.length() < labelWidth) formattedLabel += " ";
  if (formattedLabel.length() > labelWidth) formattedLabel = formattedLabel.substr(0, labelWidth);

  int availForVal = 54;
  std::string displayVal = val;
  if ((int)displayVal.length() > availForVal) {
    if (displayVal.length() > 60) {
      displayVal = displayVal.substr(0, 24) + "..." + displayVal.substr(displayVal.length() - 24);
    } else {
      displayVal = displayVal.substr(0, availForVal - 3) + "...";
    }
  }

  std::cout << "\x1b[1;92m  |  \x1b[1;37m" << formattedLabel << ": "
            << colorVal << displayVal << "\x1b[1;92m";
  int pad = availForVal - (int)displayVal.length();
  if (pad < 0) pad = 0;
  for (int i = 0; i < pad; i++) std::cout << " ";
  std::cout << " |\x1b[0m\n";
}

// Forensic Potfile (Cracked Passwords Cache) Lookup
bool checkPotfile(const std::string &targetHash, const std::string &salt,
                  std::string &recoveredPass, HashType &recoveredType,
                  const std::string &potfilePath = "cracked_passwords.txt") {
  std::ifstream pot(potfilePath);
  if (!pot.is_open()) return false;

  std::string lowerTarget = targetHash;
  for (char &c : lowerTarget) c = tolower(static_cast<unsigned char>(c));

  std::string line;
  while (std::getline(pot, line)) {
    if (line.empty()) continue;
    std::stringstream ss(line);
    std::string item;
    std::vector<std::string> parts;
    while (std::getline(ss, item, '|')) {
      item.erase(0, item.find_first_not_of(" \t\r\n"));
      item.erase(item.find_last_not_of(" \t\r\n") + 1);
      parts.push_back(item);
    }
    if (parts.size() >= 4) {
      std::string savedHash = parts[0];
      for (char &c : savedHash) c = tolower(static_cast<unsigned char>(c));
      std::string savedSalt = parts[1];
      std::string savedPass = parts[3];

      if (savedHash == lowerTarget) {
        if (salt.empty() || savedSalt == salt || savedSalt == "-") {
          recoveredPass = savedPass;
          recoveredType = identifyHash(targetHash);
          return true;
        }
      }
    } else if (parts.size() == 3) {
      std::string savedHash = parts[0];
      for (char &c : savedHash) c = tolower(static_cast<unsigned char>(c));
      std::string savedSalt = parts[1];
      std::string savedPass = parts[2];

      if (savedHash == lowerTarget) {
        if (salt.empty() || savedSalt == salt || savedSalt == "-") {
          recoveredPass = savedPass;
          recoveredType = identifyHash(targetHash);
          return true;
        }
      }
    }
  }
  return false;
}

// Safe potfile recorder (strictly avoids duplicate writes)
void saveCrackedPassword(const std::string &target, const std::string &salt,
                         HashType type, const std::string &password) {
  std::string dummyPass;
  HashType dummyType;
  if (checkPotfile(target, salt, dummyPass, dummyType)) {
    return; // Already recorded in potfile
  }
  const std::string savePath = "cracked_passwords.txt";
  std::ofstream log(savePath, std::ios::app);
  if (log.is_open()) {
    std::string safeSalt = salt.empty() ? "-" : salt;
    log << target << " | " << safeSalt << " | " << hashTypeName(type) << " | " << password << "\n";
    log.close();
    if (!globalQuiet && !globalJson) {
      std::cout << "\x1b[1;32m  [+] Sincronizado em: " << savePath << "\x1b[0m\n\n";
    }
  }
}

// Forensic Potfile & History Viewer
void displayPotfileHistory(const std::string &potfilePath = "cracked_passwords.txt") {
  std::ifstream pot(potfilePath);
  if (!pot.is_open()) {
    std::cout << "\n\x1b[1;33m[!] Nenhum historico de credenciais encontrado (" << potfilePath << ").\x1b[0m\n";
    return;
  }
  std::vector<std::vector<std::string>> entries;
  std::string line;
  while (std::getline(pot, line)) {
    if (line.empty()) continue;
    std::stringstream ss(line);
    std::string item;
    std::vector<std::string> parts;
    while (std::getline(ss, item, '|')) {
      item.erase(0, item.find_first_not_of(" \t\r\n"));
      item.erase(item.find_last_not_of(" \t\r\n") + 1);
      parts.push_back(item);
    }
    if (parts.size() >= 3) {
      entries.push_back(parts);
    }
  }

  if (entries.empty()) {
    std::cout << "\n\x1b[1;33m[!] Historico vazio em '" << potfilePath << "'.\x1b[0m\n";
    return;
  }

  if (globalJson) {
    std::cout << "{\n  \"potfile\": \"" << potfilePath << "\",\n  \"total\": " << entries.size() << ",\n  \"entries\": [\n";
    for (size_t i = 0; i < entries.size(); i++) {
      const auto &p = entries[i];
      std::string h = p[0];
      std::string s = (p.size() >= 4) ? p[1] : "-";
      std::string a = (p.size() >= 4) ? p[2] : "MD5";
      std::string pass = (p.size() >= 4) ? p[3] : p[2];
      std::cout << "    {\"target\": \"" << h << "\", \"salt\": \"" << s << "\", \"algo\": \"" << a << "\", \"plaintext\": \"" << pass << "\"}"
                << (i + 1 < entries.size() ? ",\n" : "\n");
    }
    std::cout << "  ]\n}\n";
    return;
  }

  std::cout << "\n\x1b[1;36m";
  std::cout << "================================================================================\n";
  std::cout << "                 CERBERUS POTFILE // HISTORICO DE CREDENCIAIS                   \n";
  std::cout << "================================================================================\x1b[0m\n";
  std::cout << " Total de Registros : \x1b[1;32m" << entries.size() << "\x1b[0m\n";
  std::cout << " Arquivo de Origem  : " << potfilePath << "\n";
  std::cout << "================================================================================\n";
  std::cout << " ID  | HASH ALVO (Truncado)            | SALT     | ALGORITMO   | SENHA\n";
  std::cout << "-----+---------------------------------+----------+-------------+----------------\n";

  for (size_t i = 0; i < entries.size(); i++) {
    const auto &p = entries[i];
    std::string h = p[0];
    if (h.length() > 31) {
      h = h.substr(0, 14) + "..." + h.substr(h.length() - 14);
    }
    while (h.length() < 31) h += " ";

    std::string s = (p.size() >= 4) ? p[1] : "-";
    if (s.length() > 8) s = s.substr(0, 7) + ".";
    while (s.length() < 8) s += " ";

    std::string a = (p.size() >= 4) ? p[2] : "MD5/NTLM";
    if (a.length() > 11) a = a.substr(0, 11);
    while (a.length() < 11) a += " ";

    std::string pass = (p.size() >= 4) ? p[3] : p[2];
    if (pass.length() > 16) pass = pass.substr(0, 13) + "...";

    char idBuf[8];
    snprintf(idBuf, sizeof(idBuf), "%02zu", i + 1);

    std::cout << " " << idBuf << "  | " << h << " | "
              << "\x1b[1;37m" << s << "\x1b[0m | "
              << "\x1b[1;36m" << a << "\x1b[0m | "
              << "\x1b[1;93m" << pass << "\x1b[0m\n";
  }
  std::cout << "================================================================================\n\n";
}

// Detailed Forensic Success Card
void logSuccess(const std::string &password, const std::string &target,
                HashType type, const std::string &salt, long long attempts,
                long long ms, const std::string &method = "Força Bruta Automática",
                bool saveToPot = true) {
  if (globalQuiet) {
    std::cout << target << ":" << password << "\n";
    if (saveToPot) saveCrackedPassword(target, salt, type, password);
    return;
  }

  if (globalJson) {
    double rate = (ms > 0) ? ((double)attempts / (ms / 1000.0)) : 0.0;
    std::cout << "{\n"
              << "  \"status\": \"cracked\",\n"
              << "  \"target\": \"" << target << "\",\n"
              << "  \"plaintext\": \"" << password << "\",\n"
              << "  \"algorithm\": \"" << hashTypeName(type) << "\",\n"
              << "  \"salt\": \"" << (salt.empty() ? "" : salt) << "\",\n"
              << "  \"method\": \"" << method << "\",\n"
              << "  \"engine\": \"" << getEngineName() << "\",\n"
              << "  \"time_ms\": " << ms << ",\n"
              << "  \"attempts\": " << attempts << ",\n"
              << "  \"hashrate_hps\": " << (long long)rate << "\n"
              << "}\n";
    if (saveToPot) saveCrackedPassword(target, salt, type, password);
    return;
  }

  std::cout << "\n\n\x1b[1;92m";
  std::cout << "  ==========================================================================\n";
  std::cout << "  |  ✓ SUCESSO: CREDENCIAL RECUPERADA                                      |\n";
  std::cout << "  +------------------------------------------------------------------------+\x1b[0m\n";

  printBoxLine("HASH ALVO", target, "\x1b[1;97m");
  printBoxLine("SENHA", password, "\x1b[1;93m");
  printBoxLine("ALGORITMO", hashTypeName(type), "\x1b[1;36m");
  if (!salt.empty() && salt != "-") {
    printBoxLine("SALT", salt, "\x1b[1;37m");
  }
  printBoxLine("METODO", method, "\x1b[1;35m");
  printBoxLine("ENGINE", getEngineName(), "\x1b[1;34m");
  printBoxLine("TEMPO", formatTime(ms), "\x1b[1;93m");

  if (attempts > 0) {
    std::string attStr = formatNumber(attempts);
    if (ms > 0) {
      double rate = (double)attempts / (ms / 1000.0);
      attStr += " (" + formatHashrate(rate) + ")";
    }
    printBoxLine("TENTATIVAS", attStr, "\x1b[1;37m");
  }

  std::cout << "\x1b[1;92m  ==========================================================================\x1b[0m\n";

  if (saveToPot) {
    saveCrackedPassword(target, salt, type, password);
  }
}

// Dedicated Zero-Delay Potfile Cache Hit Card
void logPotfileHit(const std::string &target, const std::string &password,
                   HashType type, const std::string &salt = "") {
  if (globalQuiet) {
    std::cout << target << ":" << password << "\n";
    return;
  }

  if (globalJson) {
    std::cout << "{\n"
              << "  \"status\": \"cached\",\n"
              << "  \"target\": \"" << target << "\",\n"
              << "  \"plaintext\": \"" << password << "\",\n"
              << "  \"algorithm\": \"" << hashTypeName(type) << "\",\n"
              << "  \"source\": \"cracked_passwords.txt\",\n"
              << "  \"time_ms\": 0\n"
              << "}\n";
    return;
  }

  std::cout << "\n\n\x1b[1;96m";
  std::cout << "  ==========================================================================\n";
  std::cout << "  |  ⚡ POTFILE CACHE HIT (RECUPERAÇÃO INSTANTÂNEA)                         |\n";
  std::cout << "  +------------------------------------------------------------------------+\x1b[0m\n";

  printBoxLine("HASH ALVO", target, "\x1b[1;97m");
  printBoxLine("SENHA", password, "\x1b[1;93m");
  printBoxLine("ALGORITMO", hashTypeName(type), "\x1b[1;36m");
  if (!salt.empty() && salt != "-") {
    printBoxLine("SALT", salt, "\x1b[1;37m");
  }
  printBoxLine("ORIGEM", "cracked_passwords.txt (0ms de computação)", "\x1b[1;92m");
  std::cout << "\x1b[1;96m  ==========================================================================\x1b[0m\n\n";
}

// Actionable Keyspace Exhausted Failure Card
void logExhausted(const std::string &target, HashType type,
                  int minLen, int maxLen, int charsetSize,
                  long long attempts, long long ms,
                  const std::string &engineName) {
  if (globalQuiet) {
    std::cout << target << ":[NOT_FOUND]\n";
    return;
  }

  if (globalJson) {
    double rate = (ms > 0) ? ((double)attempts / (ms / 1000.0)) : 0.0;
    std::cout << "{\n"
              << "  \"status\": \"exhausted\",\n"
              << "  \"target\": \"" << target << "\",\n"
              << "  \"algorithm\": \"" << hashTypeName(type) << "\",\n"
              << "  \"engine\": \"" << engineName << "\",\n"
              << "  \"time_ms\": " << ms << ",\n"
              << "  \"attempts\": " << attempts << ",\n"
              << "  \"hashrate_hps\": " << (long long)rate << "\n"
              << "}\n";
    return;
  }

  std::cout << "\n\n\x1b[1;91m";
  std::cout << "  ==========================================================================\n";
  std::cout << "  |  ✗ ESGOTADO: SENHA NÃO ENCONTRADA                                      |\n";
  std::cout << "  +------------------------------------------------------------------------+\x1b[0m\n";

  printBoxLine("HASH ALVO", target, "\x1b[1;97m");
  printBoxLine("ALGORITMO", hashTypeName(type), "\x1b[1;36m");

  std::string keyspaceStr = "Tamanho " + std::to_string(minLen) + ".." + std::to_string(maxLen) +
                            " | Charset: " + std::to_string(charsetSize) + " chars";
  printBoxLine("KEYSPACE", keyspaceStr, "\x1b[1;33m");
  printBoxLine("ENGINE", engineName, "\x1b[1;34m");
  printBoxLine("TEMPO", formatTime(ms), "\x1b[1;93m");

  if (attempts > 0) {
    std::string attStr = formatNumber(attempts);
    if (ms > 0) {
      double rate = (double)attempts / (ms / 1000.0);
      attStr += " (" + formatHashrate(rate) + ")";
    }
    printBoxLine("TENTATIVAS", attStr, "\x1b[1;37m");
  }

  std::cout << "\x1b[1;91m  +------------------------------------------------------------------------+\n";
  std::cout << "  |  \x1b[1;33mSUGESTÕES FORENSES:                                                   \x1b[1;91m|\n";
  std::cout << "  |   - Expandir comprimento de busca: --max-len " << (maxLen + 2) << "                         \x1b[1;91m|\n";
  std::cout << "  |   - Incluir símbolos especiais no charset: --charset 6 ou 7            |\n";
  std::cout << "  |   - Utilizar wordlist estendida: --wordlist rockyou.txt                |\n";
  std::cout << "  ==========================================================================\x1b[0m\n\n";
}

// Attack result descriptor for batch auditing & reporting
struct AttackResult {
  bool success = false;
  bool fromPotfile = false;
  std::string target = "";
  std::string recoveredPass = "";
  HashType type = HashType::UNKNOWN;
  std::string method = "";
  long long attempts = 0;
  long long durationMs = 0;
};

// --- Attack Vectors ---

// Generator for mutations (Enhanced Forensic Rule Set)
std::vector<std::string> generateMutations(const std::string &base) {
  std::vector<std::string> mutations;
  if (base.empty()) return mutations;

  std::unordered_set<std::string> seen;
  auto addUnique = [&](const std::string &s) {
    if (!s.empty() && seen.insert(s).second) {
      mutations.push_back(s);
    }
  };

  addUnique(base);

  // 1. Lowercase and Uppercase full variants
  std::string lowerStr = base;
  for (char &c : lowerStr) c = tolower(static_cast<unsigned char>(c));
  addUnique(lowerStr);

  std::string upperStr = base;
  for (char &c : upperStr) c = toupper(static_cast<unsigned char>(c));
  addUnique(upperStr);

  // 2. Capitalize First Letter (Title Case)
  std::string cap = lowerStr;
  cap[0] = toupper(static_cast<unsigned char>(cap[0]));
  addUnique(cap);

  // 3. Reversed word (e.g. admin -> nimda)
  std::string reversed = base;
  std::reverse(reversed.begin(), reversed.end());
  addUnique(reversed);

  // 4. Duplicate word (e.g. admin -> adminadmin)
  addUnique(base + base);

  // 5. Classic & Advanced Leetspeak transformations
  std::string leet1 = lowerStr;
  for (char &c : leet1) {
    if (c == 'a') c = '4';
    else if (c == 'e') c = '3';
    else if (c == 'i') c = '1';
    else if (c == 'o') c = '0';
    else if (c == 's') c = '5';
    else if (c == 't') c = '7';
  }
  addUnique(leet1);

  std::string leet2 = lowerStr;
  for (char &c : leet2) {
    if (c == 'a') c = '@';
    else if (c == 's') c = '$';
    else if (c == 'i') c = '!';
    else if (c == 'e') c = '3';
    else if (c == 'o') c = '0';
  }
  addUnique(leet2);

  // 6. Common forensic suffixes on base and title-case
  const std::vector<std::string> suffixes = {
    "1", "12", "123", "1234", "12345", "123456", "01", "00", "99",
    "2024", "2025", "2026", "2027", "2023", "2022", "2021", "2020",
    "2019", "2018", "2000", "1999", "1990", "1980",
    "!", "@", "#", "$", "_", ".", "*",
    "123!", "2024!", "2025!", "2026!", "!@#"
  };

  for (const auto &s : suffixes) {
    addUnique(base + s);
    addUnique(cap + s);
    addUnique(leet1 + s);
  }

  // 7. Common forensic prefixes
  const std::vector<std::string> prefixes = { "123", "!", "@", "#", ".", "admin", "1234" };
  for (const auto &p : prefixes) {
    addUnique(p + base);
    addUnique(p + cap);
  }

  return mutations;
}

// Helper to load salts
std::vector<std::string> loadSalts(const Config &config) {
  std::vector<std::string> salts;
  if ((config.type >= HashType::SALTED_MD5 &&
       config.type <= HashType::SALTED_SHA512) ||
      config.type == HashType::HMAC_MD5 ||
      config.type == HashType::HMAC_SHA1 ||
      config.type == HashType::HMAC_SHA256 ||
      config.type == HashType::WPA2_PBKDF2 ||
      config.type == HashType::WPA3_SAE || config.type == HashType::BCRYPT ||
      config.type == HashType::SCRYPT || config.type == HashType::SOCIAL_FB ||
      config.type == HashType::SOCIAL_IG ||
      config.type == HashType::SOCIAL_TW) {
    if (!config.salt.empty()) {
      salts.push_back(config.salt);
    } else {
      std::ifstream saltFile("saltlist.txt");
      if (saltFile.is_open()) {
        std::string s;
        while (std::getline(saltFile, s)) {
          if (!s.empty() && s.back() == '\r')
            s.pop_back();
          salts.push_back(s);
        }
        std::cout << "[i] Carregado " << salts.size()
                  << " salts de 'saltlist.txt'.\n";
      } else {
        std::cout
            << "[!] Aviso: 'saltlist.txt' nao encontrado. Usando salt vazio.\n";
        salts.push_back("");
      }
    }
  } else {
    salts.push_back("");
  }
  return salts;
}

// --- Parallel Core & State ---
std::atomic<bool> found(false);
std::string crackedPassword = "";
std::atomic<long long> totalTentativas(0);
std::mutex foundMutex;
std::atomic<int> activeThreads(0);

bool dictionaryAttack(const Config &config,
                      const std::string &wordlistFile = "wordlist.txt") {
  if (!globalQuiet && !globalJson) {
    std::cout << "\n[!] Iniciando ataque via Dicionario (" << wordlistFile
              << ") + Mutations...\n";
  }
  std::ifstream file(wordlistFile);
  if (!file.is_open()) {
    if (!globalQuiet && !globalJson) {
      std::cout << "[X] Erro: Arquivo '" << wordlistFile << "' nao encontrado!\n";
    }
    return false;
  }

  std::vector<std::string> salts = loadSalts(config);

  std::string line;
  long long count = 0;
  auto start = std::chrono::high_resolution_clock::now();
  auto last_print = start;

  while (std::getline(file, line)) {
    while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t'))
      line.pop_back();

    std::vector<std::string> candidates = generateMutations(line);

    for (const auto &attempt : candidates) {
      for (const auto &currentSalt : salts) {
        std::string hashed =
            hashFunctionExtended(attempt, config.type, currentSalt);
        count++;

        if (hashed == config.target) {
          auto end = std::chrono::high_resolution_clock::now();
          auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
              end - start);
          std::cout << "\r\x1b[2K                                                                                \r" << std::flush;
          found = true;
          crackedPassword = attempt;
          totalTentativas = count;
          logSuccess(attempt, config.target, config.type, currentSalt, count,
                     duration.count(), "Dicionário Forense + Mutações");
          return true;
        }
      }
    }

    auto now = std::chrono::high_resolution_clock::now();
    long long elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_print).count();
    if (!globalQuiet && elapsed_ms >= 150) {
      last_print = now;
      long long total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
      double wps = (total_ms > 0) ? ((double)count / (total_ms / 1000.0)) : 0.0;
      std::string dispWord = line;
      if (dispWord.length() > 22) dispWord = dispWord.substr(0, 19) + "...";
      std::cout << "\r\x1b[2K\x1b[1;36m[Dicionário] Testando: \x1b[1;33m" << dispWord
                << "\x1b[0m (" << formatNumber(count) << " chaves | " << formatHashrate(wps) << ") " << std::flush;
    }
  }
  if (!globalQuiet && !globalJson) {
    std::cout << "\r\x1b[2K                                                                                \r" << std::flush;
    std::cout << "[!] Senha nao encontrada no dicionario.\n";
  }
  return false;
}

#if defined(ENABLE_CUDA)
void gpuBruteForceOrchestrator(const Config &config) {
  std::cout
      << "\n\x1b[1;36m[GPU] INICIANDO ORQUESTRADOR CUDA (NATIVE)...\x1b[0m\n";
  std::cout << "[GPU] Transferindo dados para VRAM...\n";

  char resultBuffer[128] = {0};

  auto start = std::chrono::high_resolution_clock::now();
  launch_gpu_brute_force_ext(
      config.charset.c_str(), config.target.c_str(), config.maxLength,
      resultBuffer, config.hashType, config.salt.c_str());
  auto end = std::chrono::high_resolution_clock::now();

  if (strlen(resultBuffer) > 0) {
    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::lock_guard<std::mutex> lock(foundMutex);
    found = true;
    crackedPassword = std::string(resultBuffer);
    logSuccess(resultBuffer, config.target, config.type, config.salt, 0, duration.count());
  } else {
    std::cout << "\n\x1b[1;31m[FALHA] Senha nao encontrada no keyspace.\x1b[0m\n";
  }
}
#endif

// Fast Multi-Threaded CPU Brute Force Worker with In-Place Character Increment
void bruteForceWorker(int threadId, int totalThreads, int length,
                      const Config &config,
                      const std::vector<std::string> &salts) {
  int numChars = static_cast<int>(config.charset.length());
  std::vector<int> indices(length, 0);
  long long localAttempts = 0;

  auto flushAttempts = [&]() {
    if (localAttempts > 0) {
      totalTentativas += localAttempts;
      localAttempts = 0;
    }
  };

  std::string attempt(length, config.charset[0]);

  for (int firstCharIndex = threadId; firstCharIndex < numChars;
       firstCharIndex += totalThreads) {
    if (found.load(std::memory_order_relaxed)) {
      flushAttempts();
      activeThreads--;
      return;
    }

    indices[0] = firstCharIndex;
    attempt[0] = config.charset[firstCharIndex];

    if (length == 1) {
      for (const auto &s : salts) {
        if (found.load(std::memory_order_relaxed)) {
          flushAttempts();
          activeThreads--;
          return;
        }
        localAttempts++;
        if (localAttempts >= 50000) flushAttempts();

        if (hashFunctionExtended(attempt, config.type, s) == config.target) {
          std::lock_guard<std::mutex> lock(foundMutex);
          if (!found) {
            found = true;
            crackedPassword = attempt;
          }
          flushAttempts();
          activeThreads--;
          return;
        }
      }
    } else {
      for (int i = 1; i < length; i++) {
        indices[i] = 0;
        attempt[i] = config.charset[0];
      }

      while (true) {
        if (found.load(std::memory_order_relaxed)) {
          flushAttempts();
          activeThreads--;
          return;
        }

        for (const auto &s : salts) {
          localAttempts++;
          if (localAttempts >= 50000) flushAttempts();

          if (hashFunctionExtended(attempt, config.type, s) == config.target) {
            std::lock_guard<std::mutex> lock(foundMutex);
            if (!found) {
              found = true;
              crackedPassword = attempt;
            }
            flushAttempts();
            activeThreads--;
            return;
          }
        }

        // In-place odometer increment from rightmost character:
        int pos = length - 1;
        while (pos >= 1) {
          indices[pos]++;
          if (indices[pos] < numChars) {
            attempt[pos] = config.charset[indices[pos]];
            break;
          }
          indices[pos] = 0;
          attempt[pos] = config.charset[0];
          pos--;
        }
        if (pos < 1) break; // Exhausted combinations for this firstCharIndex
      }
    }
  }
  flushAttempts();
  activeThreads--;
}

bool runParallelBruteForce(const Config &config) {
  // Check for GPU Mode
  if (globalCompute == ComputeType::CUDA) {
#if defined(ENABLE_CUDA)
    gpuBruteForceOrchestrator(config);
    return true;
#else
    if (!globalQuiet && !globalJson) {
      std::cout << "[!] GPU Mode Compiled Out. Fallback to CPU.\n";
    }
#endif
  }

  if (globalCompute == ComputeType::OPENCL) {
    if (!globalQuiet && !globalJson) {
      std::cout << "\n[OpenCL] Iniciando Ataque via GPU (Universal)...\n";
    }
    std::vector<std::string> salts = loadSalts(config);
    auto start_time = std::chrono::high_resolution_clock::now();
    char res_buf[256] = {0};
    int stop_flag = 0;

    char targetPad[256] = {0};
    if (config.targetHash.length() < 256) {
      memcpy(targetPad, config.targetHash.c_str(), config.targetHash.length());
    } else {
      memcpy(targetPad, config.targetHash.c_str(), 255);
    }

    unsigned long long totalGpuAttempts = 0;
    std::string matchedSalt = config.salt;

    for (const auto &curSalt : salts) {
      if (salts.size() > 1 && !globalQuiet && !globalJson) {
        std::cout << "[OpenCL] Testando salt: \"" << curSalt << "\"...\n";
      }
      unsigned long long localAttempts = 0;
      launch_opencl_brute_force(config.charset.c_str(), targetPad,
                                config.maxLength, res_buf, &stop_flag,
                                getKernelAlgoId(config.type), curSalt.c_str(),
                                &localAttempts);
      totalGpuAttempts += localAttempts;
      if (res_buf[0] != 0) {
        matchedSalt = curSalt;
        break;
      }
    }
    totalTentativas = totalGpuAttempts;

    auto end_time = std::chrono::high_resolution_clock::now();
    long long elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(end_time -
                                                              start_time)
            .count();

    if (res_buf[0] != 0) {
      std::lock_guard<std::mutex> lock(foundMutex);
      found = true;
      crackedPassword = std::string(res_buf);

      logSuccess(res_buf, config.targetHash, config.type,
                 matchedSalt, totalTentativas.load(), elapsed_ms, "Força Bruta GPU (OpenCL)");
      return true;
    } else {
      if (!globalQuiet && !globalJson) {
        std::cout << "[OpenCL] Senha nao encontrada neste range.\n";
      }
      return false;
    }
  }

  if (!globalQuiet && !globalJson) {
    std::cout << "\n\x1b[1;36m[!] Iniciando motor PARALELO (Multi-Threaded)...\x1b[0m\n";
  }
  std::vector<std::string> salts = loadSalts(config);
  int maxThreads = std::thread::hardware_concurrency();
  if (maxThreads == 0) maxThreads = 2;
  if (!globalQuiet && !globalJson) {
    std::cout << "[i] Threads Ativas: " << maxThreads << "\n";
  }

  found = false;
  totalTentativas = 0;
  auto start = std::chrono::high_resolution_clock::now();

  int maxL = (config.maxLength > 0) ? config.maxLength : 16;
  for (int length = 1; length <= maxL; ++length) {
    if (found) break;
    if (!globalQuiet && !globalJson) {
      std::cout << "[+] Verificando tamanho " << length << "... \n";
    }

    activeThreads = maxThreads;
    std::vector<std::thread> workers;
    for (int i = 0; i < maxThreads; ++i) {
      workers.emplace_back(bruteForceWorker, i, maxThreads, length,
                           std::ref(config), std::ref(salts));
    }

    // Monitoring loop with real-time ETA and formatted hashrate
    while (activeThreads > 0 && !found) {
      auto now = std::chrono::high_resolution_clock::now();
      auto duration_ms =
          std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
      if (!globalQuiet && duration_ms > 200) {
        double speed = (double)totalTentativas.load() / (duration_ms / 1000.0);

        unsigned long long lenComb = 1;
        for (int c = 0; c < length; c++) {
          if (lenComb > 0xFFFFFFFFFFFFFFFFULL / config.charset.length()) {
            lenComb = 0xFFFFFFFFFFFFFFFFULL;
            break;
          }
          lenComb *= config.charset.length();
        }
        double pct = (lenComb > 0) ? ((double)totalTentativas.load() * 100.0 / lenComb) : 0.0;
        if (pct > 100.0) pct = 100.0;

        std::string etaStr = "--:--";
        if (speed > 0 && lenComb > totalTentativas.load()) {
          unsigned long long rem = lenComb - totalTentativas.load();
          long long etaSec = (long long)(rem / speed);
          if (etaSec < 3600) {
            char buf[32];
            snprintf(buf, sizeof(buf), "%02lld:%02lld", etaSec / 60, etaSec % 60);
            etaStr = buf;
          } else {
            char buf[32];
            snprintf(buf, sizeof(buf), "%02lld:%02lld:%02lld", etaSec / 3600, (etaSec % 3600) / 60, etaSec % 60);
            etaStr = buf;
          }
        }

        long long elSec = duration_ms / 1000;
        char elBuf[32];
        snprintf(elBuf, sizeof(elBuf), "%02lld:%02lld", elSec / 60, elSec % 60);

        std::cout << "\r\x1b[2K\x1b[1;32m[CPU Multi-Thread] L" << length << "/" << maxL
                  << " " << formatProgressBar(pct, 10)
                  << " | " << formatHashrate(speed)
                  << " | ETA " << etaStr
                  << " | " << elBuf
                  << " \x1b[0m" << std::flush;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    for (auto &t : workers) {
      if (t.joinable()) t.join();
    }
    if (!globalQuiet) {
      std::cout << "\r\x1b[2K\r" << std::flush;
    }
  }

  if (found) {
    auto end = std::chrono::high_resolution_clock::now();
    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    logSuccess(crackedPassword, config.target, config.type,
               salts.size() == 1 ? salts[0] : "LIST-MODE", totalTentativas,
               duration.count(), "Força Bruta CPU Multi-Threaded");
    return true;
  }

  if (!globalQuiet && !globalJson) {
    std::cout << "\n[X] Falha na Forca Bruta.\n";
  }
  return false;
}

// --- Unified Self-Test System ---
bool typeRequiresSalt(HashType type) {
  switch (type) {
  case HashType::SALTED_MD5:
  case HashType::SALTED_SHA1:
  case HashType::SALTED_SHA256:
  case HashType::SALTED_SHA512:
  case HashType::HMAC_MD5:
  case HashType::HMAC_SHA1:
  case HashType::HMAC_SHA256:
  case HashType::WPA2_PBKDF2:
  case HashType::WPA3_SAE:
  case HashType::BCRYPT:
  case HashType::SCRYPT:
  case HashType::SOCIAL_FB:
  case HashType::SOCIAL_IG:
  case HashType::SOCIAL_TW:
    return true;
  default:
    return false;
  }
}

// Unified test runner — identical logic for ALL compute engines
bool runUnifiedTest(HashType type, const std::string &password,
                    const std::string &charset, const std::string &salt,
                    int maxLen) {
  if (type == HashType::BASE64) {
    std::string encoded = hashFunctionExtended(password, type, "");
    std::string decoded = base64_decode(encoded);
    bool ok = (decoded == password);
    if (ok) {
      std::lock_guard<std::mutex> lock(foundMutex);
      found = true;
      crackedPassword = decoded;
      totalTentativas = 1;
    }
    return ok;
  }

  std::string targetHash = hashFunctionExtended(password, type, salt);

  Config config;
  config.type = type;
  config.target = targetHash;
  config.targetHash = targetHash;
  config.salt = salt;
  config.charset = charset;
  config.maxLength = maxLen;
  config.hashType = getKernelAlgoId(type);

  found = false;
  crackedPassword = "";
  totalTentativas = 0;

  if (globalCompute == ComputeType::OPENCL) {
    char res_buf[256] = {0};
    int stop_flag = 0;
    unsigned long long localAttempts = 0;
    launch_opencl_brute_force(charset.c_str(), targetHash.c_str(), maxLen,
                              res_buf, &stop_flag, getKernelAlgoId(type),
                              salt.c_str(), &localAttempts);
    totalTentativas = localAttempts;
    if (res_buf[0] != 0) {
      found = true;
      crackedPassword = std::string(res_buf);
    }
  } else {
    std::vector<std::string> saltVec = {salt};
    int maxThreads = std::thread::hardware_concurrency();
    if (maxThreads == 0) maxThreads = 2;

    for (int len = 1; len <= maxLen && !found; len++) {
      activeThreads = 0;
      std::vector<std::thread> workers;
      for (int i = 0; i < maxThreads; ++i) {
        workers.emplace_back(bruteForceWorker, i, maxThreads, len,
                             std::ref(config), std::ref(saltVec));
      }
      for (auto &t : workers)
        if (t.joinable())
          t.join();
    }
  }

  return found && crackedPassword == password;
}

void runAllTests(bool interactive = true) {
  enableANSI();
  set_opencl_quiet(1);
#ifdef _WIN32
  std::system("cls");
#else
  std::system("clear");
#endif
  exibirDesenho();

  std::cout << "\x1b[1;35m[!] MATRIZ DE AUDITORIA FORENSE UNIVERSAL - ENGINE: "
            << getEngineName() << "\x1b[0m\n";
  std::cout << "==============================================================="
               "=========\n";
  std::cout << "  \x1b[1;37mMODO: \x1b[1;36m" << getEngineName() << "\x1b[0m\n";
  std::cout
      << "  \x1b[1;37mMETODO: Gerar hash (CPU) -> Quebrar via forca bruta ("
      << getEngineName() << ") -> Validar senha\x1b[0m\n";
  std::cout << "  \x1b[1;37mCOBERTURA: 18 algoritmos (basicos + forenses + salted + "
               "protocolos + redes sociais)\x1b[0m\n";
  std::cout << "==============================================================="
               "=========\n\n";

  const std::string testCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const int testMaxLen = 6;

  std::random_device rd;
  std::mt19937 rng(rd());

  auto randomStr = [&](int minLen, int maxLen) -> std::string {
    std::uniform_int_distribution<int> lenDist(minLen, maxLen);
    int len = lenDist(rng);
    std::uniform_int_distribution<int> charDist(0, static_cast<int>(testCharset.length()) - 1);
    std::string s;
    for (int i = 0; i < len; ++i) {
      s += testCharset[charDist(rng)];
    }
    return s;
  };

  struct TestCase {
    HashType type;
    std::string password;
    std::string salt;
    const char *category;
  };

  std::vector<TestCase> tests;
  int passMaxLen = (globalCompute == ComputeType::CPU) ? 3 : 5;

  // 1. Basic Hashes (Unsalted)
  tests.push_back({HashType::MD5, randomStr(3, passMaxLen), "", "BASICO"});
  tests.push_back({HashType::SHA1, randomStr(3, passMaxLen), "", "BASICO"});
  tests.push_back({HashType::SHA256, randomStr(3, passMaxLen), "", "BASICO"});
  tests.push_back({HashType::SHA512, randomStr(3, passMaxLen), "", "BASICO"});
  tests.push_back({HashType::BASE64, randomStr(3, passMaxLen), "", "BASICO"});

  // 2. Forensic Standards (Unsalted)
  tests.push_back({HashType::NTLM, randomStr(3, passMaxLen), "", "FORENSE"});
  tests.push_back({HashType::MD4, randomStr(3, passMaxLen), "", "FORENSE"});

  // 3. Salted Hashes
  tests.push_back(
      {HashType::SALTED_MD5, randomStr(3, passMaxLen), randomStr(4, 5), "SALTED"});
  tests.push_back(
      {HashType::SALTED_SHA1, randomStr(3, passMaxLen), randomStr(4, 5), "SALTED"});
  tests.push_back(
      {HashType::SALTED_SHA256, randomStr(3, passMaxLen), randomStr(4, 5), "SALTED"});
  tests.push_back(
      {HashType::SALTED_SHA512, randomStr(3, passMaxLen), randomStr(4, 5), "SALTED"});

  // 4. Protocol Hashes
  tests.push_back(
      {HashType::WPA2_PBKDF2, randomStr(3, passMaxLen), randomStr(4, 5), "PROTOCOL"});
  tests.push_back(
      {HashType::WPA3_SAE, randomStr(3, passMaxLen), randomStr(4, 5), "PROTOCOL"});
  tests.push_back(
      {HashType::BCRYPT, randomStr(3, passMaxLen), randomStr(4, 5), "PROTOCOL"});
  tests.push_back(
      {HashType::SCRYPT, randomStr(3, passMaxLen), randomStr(4, 5), "PROTOCOL"});

  // 5. Social Media Hashes
  tests.push_back(
      {HashType::SOCIAL_FB, randomStr(3, passMaxLen), randomStr(4, 5), "SOCIAL"});
  tests.push_back(
      {HashType::SOCIAL_IG, randomStr(3, passMaxLen), randomStr(4, 5), "SOCIAL"});
  tests.push_back(
      {HashType::SOCIAL_TW, randomStr(3, passMaxLen), randomStr(4, 5), "SOCIAL"});

  int passCount = 0, failCount = 0;
  bool globalPass = true;
  std::string lastCategory = "";

  auto startAll = std::chrono::high_resolution_clock::now();

  for (size_t i = 0; i < tests.size(); i++) {
    auto &test = tests[i];
    std::string name = hashTypeName(test.type);
    std::string salt = test.salt;

    if (std::string(test.category) != lastCategory) {
      lastCategory = test.category;
      std::cout << "\x1b[1;30m  --- " << lastCategory << " ---\x1b[0m\n";
    }

    std::string targetHash =
        hashFunctionExtended(test.password, test.type, salt);

    std::string displayHash = targetHash;
    if (displayHash.length() > 40)
      displayHash = displayHash.substr(0, 18) + "..." + displayHash.substr(displayHash.length() - 18);

    std::cout << "\x1b[1;36m  [" << (i + 1 < 10 ? "0" : "") << (i + 1)
              << "] \x1b[1;37m" << name;
    for (size_t s = name.length(); s < 25; s++)
      std::cout << " ";
    std::cout << "\x1b[1;30m| \x1b[0mHASH=\"\x1b[1;33m" << displayHash
              << "\x1b[0m\"";
    if (!salt.empty())
      std::cout << " SALT=\"" << salt << "\"";
    std::cout << "\n";

    {
      std::ofstream dlog("debug_log.txt", std::ios::app);
      dlog << "[TEST] Algo: " << name << " Pass: " << test.password
           << " Salt: " << salt << " Hash: " << targetHash << "\n";
    }

    auto startTest = std::chrono::high_resolution_clock::now();
    bool passed =
        runUnifiedTest(test.type, test.password, testCharset, salt, testMaxLen);
    auto endTest = std::chrono::high_resolution_clock::now();
    auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                          endTest - startTest)
                          .count();

    if (passed) {
      passCount++;
      std::string durStr = formatTime(durationMs);
      long long att = (test.type == HashType::BASE64) ? 1 : (long long)totalTentativas.load();
      std::string attStr = formatNumber(att) + " tentativas";
      if (durationMs > 0 && att > 1) {
        double rate = (double)att / (durationMs / 1000.0);
        attStr += " (" + formatHashrate(rate) + ")";
      }
      std::cout
          << "       \x1b[1;32m[PASS]\x1b[0m Senha recuperada: \"\x1b[1;32m"
          << crackedPassword << "\x1b[0m\" | " << durStr
          << " | " << attStr << "\n";

      std::ofstream dlog("debug_log.txt", std::ios::app);
      dlog << "[PASS] " << name << " -> " << crackedPassword << "\n";
    } else {
      failCount++;
      globalPass = false;
      std::cout << "       \x1b[1;31m[FAIL]\x1b[0m Esperado: \""
                << test.password << "\" Recuperado: \"" << crackedPassword
                << "\"\n";

      std::ofstream dlog("debug_log.txt", std::ios::app);
      dlog << "[FAIL] " << name << " Expected: " << test.password
           << " Got: " << crackedPassword << "\n";
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }

  auto endAll = std::chrono::high_resolution_clock::now();
  auto totalDuration =
      std::chrono::duration_cast<std::chrono::milliseconds>(endAll - startAll)
          .count();

  std::cout << "\n============================================================="
               "===========\n";
  std::cout << "  \x1b[1;37mRESULTADOS: \x1b[1;32m" << passCount
            << " PASS \x1b[1;30m| \x1b[1;31m" << failCount
            << " FAIL \x1b[1;30m| \x1b[1;37mTOTAL: " << tests.size()
            << "\x1b[0m\n";
  std::cout << "  \x1b[1;37mTEMPO TOTAL: \x1b[1;33m" << formatTime(totalDuration)
            << "\x1b[0m\n";
  std::cout << "  \x1b[1;37mENGINE: \x1b[1;36m" << getEngineName()
            << "\x1b[0m\n";
  std::cout << "==============================================================="
               "=========\n";

  if (globalPass) {
    std::cout << "\n\x1b[1;42;30m   SISTEMA INTEGRALMENTE OPERACIONAL - "
                 "TODOS OS " << tests.size() << " MODULOS VALIDADOS   \x1b[0m\n";
  } else {
    std::cout << "\n\x1b[1;41;37m   FALHA EM " << failCount
              << " MODULO(S) - REVISAR CODIGO   \x1b[0m\n";
  }

  if (interactive) {
    std::cout << "\n\x1b[1;33m[!] Pressione ENTER para voltar ao Menu "
                 "Principal...\x1b[0m";
    std::cin.ignore(10000, '\n');
    std::cin.clear();
    std::cin.get();
  }
  set_opencl_quiet(0);
}

// === BENCHMARK MODE ===
void runBenchmark() {
  enableANSI();
  exibirDesenho();
  std::cout << "\x1b[1;35m[!] BENCHMARK DE DESEMPENHO FORENSE (" << getEngineName() << ")\x1b[0m\n";
  std::cout << "----------------------------------------------------------------------------\n";
  std::cout << "Medindo taxa bruta de hashes por segundo (H/s)...\n\n";

  struct BenchItem {
    HashType type;
    const char *name;
  };

  std::vector<BenchItem> benchAlgos = {
    {HashType::MD5, "MD5"},
    {HashType::NTLM, "NTLM (Windows)"},
    {HashType::MD4, "MD4 (RFC 1320)"},
    {HashType::SHA1, "SHA1"},
    {HashType::SHA256, "SHA-256"},
    {HashType::SHA512, "SHA-512"}
  };

  const std::string benchCharset = "abcdefghijklmnopqrstuvwxyz0123456789";

  for (const auto &item : benchAlgos) {
    std::cout << "  [+] " << item.name;
    for (size_t s = strlen(item.name); s < 20; s++) std::cout << " ";
    std::cout << ": ";
    std::cout.flush();

    // Use impossible target to measure pure throughput
    std::string fakeTarget = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    if (item.type == HashType::MD5 || item.type == HashType::NTLM || item.type == HashType::MD4) fakeTarget = fakeTarget.substr(0, 32);
    else if (item.type == HashType::SHA1) fakeTarget = fakeTarget.substr(0, 40);
    else if (item.type == HashType::SHA512) fakeTarget = fakeTarget + fakeTarget;

    auto bStart = std::chrono::high_resolution_clock::now();
    unsigned long long attempts = 0;

    if (globalCompute == ComputeType::OPENCL) {
      char res[256] = {0};
      int stop = 0;
      launch_opencl_brute_force(benchCharset.c_str(), fakeTarget.c_str(), 4, res, &stop,
                                getKernelAlgoId(item.type), "", &attempts);
    } else {
      Config cfg;
      cfg.charset = benchCharset;
      cfg.target = fakeTarget;
      cfg.type = item.type;
      cfg.maxLength = 4;
      std::vector<std::string> emptySalt = {""};
      int threads = std::thread::hardware_concurrency();
      if (threads == 0) threads = 2;
      found = false;
      totalTentativas = 0;
      std::vector<std::thread> pool;
      for (int i = 0; i < threads; i++) {
        pool.emplace_back(bruteForceWorker, i, threads, 4, std::ref(cfg), std::ref(emptySalt));
      }
      for (auto &t : pool) if (t.joinable()) t.join();
      attempts = totalTentativas.load();
    }

    auto bEnd = std::chrono::high_resolution_clock::now();
    long long bMs = std::chrono::duration_cast<std::chrono::milliseconds>(bEnd - bStart).count();
    if (bMs < 1) bMs = 1;

    double rate = (double)attempts / (bMs / 1000.0);
    std::cout << "\x1b[1;32m" << formatHashrate(rate) << "\x1b[0m ("
              << formatNumber(attempts) << " chaves em " << formatTime(bMs) << ")\n";
  }

  std::cout << "----------------------------------------------------------------------------\n";
  std::cout << "[i] Benchmark finalizado com sucesso.\n\n";
}

// === CLI HELPER FUNCTIONS ===

std::string cliGetArgValue(int argc, char *argv[], const std::string &flag) {
  for (int i = 0; i < argc - 1; i++) {
    std::string arg = argv[i];
    std::transform(arg.begin(), arg.end(), arg.begin(), ::tolower);
    std::string flagLower = flag;
    std::transform(flagLower.begin(), flagLower.end(), flagLower.begin(), ::tolower);
    if (arg == flagLower)
      return std::string(argv[i + 1]);
  }
  return "";
}

bool cliHasFlag(int argc, char *argv[], const std::string &flag) {
  for (int i = 0; i < argc; i++) {
    std::string arg = argv[i];
    std::transform(arg.begin(), arg.end(), arg.begin(), ::tolower);
    std::string flagLower = flag;
    std::transform(flagLower.begin(), flagLower.end(), flagLower.begin(), ::tolower);
    if (arg == flagLower)
      return true;
  }
  return false;
}

void printHelp() {
  exibirDesenho();
  std::cout << R"(
  USAGE:
    cerberus                                       Modo interativo (menu intuitivo)
    cerberus <comando> [args] [opcoes]             Modo CLI direto

  COMMANDS:
    crack, c          <hash>                       Auto-detectar e quebrar hash
    crack-salt, cs    <hash> --salt <salt>         Hash + Salt
    decode, d         <base64>                     Decodificar Base64
    test-all, test, t                              Executar suite de 18 testes de precisao
    benchmark, b                                   Medir hashrate maximo de GPU/CPU
    hash, g           <texto>                      Gerar todos os hashes criptograficos
    file, batch, f    <arquivo.txt>                Auditar lista/lote de hashes em arquivo
    history, potfile  [arquivo.txt]                Exibir historico de senhas recuperadas
    help, h, ?                                     Mostrar esta ajuda
    version, v                                     Mostrar versao

  OPTIONS:
    --engine, -e <cpu|cuda|opencl>                 Selecionar unidade de computacao
    --algo, -a <md5|sha1|sha256|sha512|ntlm|md4>   Forcar algoritmo especifico
    --charset, -c <1-7>                            Charset para forca bruta
        1=Numerico 2=a-z 3=A-Z 4=a-zA-Z 5=a-z0-9 6=Alfanum 7=ASCII Total
    --salt, -s <valor>                             Salt explicito
    --wordlist, -w <arquivo>                       Wordlist customizada (default: wordlist.txt)
    --file, -f <arquivo>                           Auditar lista/lote de hashes em arquivo
    --no-dict, -n                                  Pular ataque de dicionario
    --no-potfile, --fresh                          Ignorar cache de senhas quebradas (potfile)
    --quiet, -q                                    Modo silencioso (apenas hash:senha para scripts)
    --verbose, -v                                  Modo detalhado com telemetria expandida
    --json                                         Exportar saida estruturada em JSON
    --max-len, -l <N>                              Comprimento maximo (default: 16)

  EXAMPLES:
    cerberus 0192023a7bbd73250516f069df18b500
    cerberus ZHVhcnRlMTIz
    cerberus minhasenha
    cerberus crack "5d41402abc4b2a76b9719d911017c592" --algo md5
    cerberus crack "8846f7eaee8fb117ad06bdd830b7586c" --algo ntlm
    cerberus file targets.txt --json
    cerberus history
    cerberus test
    cerberus benchmark
)" << std::endl;
}

void printVersion() {
  std::cout << "CERBERUS Forensic Suite v3.0-PRECISION\n";
  std::cout << "Developed by Zeca | Sentinel Data Solutions\n";
  std::cout << "Triple-Headed Password Recovery & Forensic Audit Engine\n";
  std::cout << "Engine Architecture: Potfile Cache | Mutation Dictionary | GPU OpenCL & CPU Multi-Threading\n";
}

void initHardwareAuto() {
#if defined(ENABLE_CUDA)
  int test_val = 0;
  try {
    launch_cuda_test(&test_val);
  } catch (...) {
    test_val = 0;
  }
  if (test_val == 1337) {
    globalCompute = ComputeType::CUDA;
    if (!globalQuiet && !globalJson) {
      std::cout << "\x1b[1;32m[+] Hardware Auto: NVIDIA CUDA Ativado (" << getRealGPUName() << ")\x1b[0m\n";
    }
    return;
  }
#endif

  if (initOpenCL()) {
    globalCompute = ComputeType::OPENCL;
    return;
  }

  globalCompute = ComputeType::CPU;
  if (!globalQuiet && !globalJson) {
    std::cout << "\x1b[1;36m[+] Hardware Auto: CPU Multi-Threaded ("
              << std::thread::hardware_concurrency() << " Threads) Ativo\x1b[0m\n";
  }
}

void initEngine(const std::string &engineStr) {
  if (engineStr == "cuda") {
    globalCompute = ComputeType::CUDA;
#if defined(ENABLE_CUDA)
    initCUDA();
#else
    std::cout << "[!] CUDA nativo indisponivel. Ativando OpenCL...\n";
    globalCompute = ComputeType::OPENCL;
    initOpenCL();
#endif
  } else if (engineStr == "opencl") {
    globalCompute = ComputeType::OPENCL;
    initOpenCL();
  } else {
    globalCompute = ComputeType::CPU;
  }
}

void generateAndDisplayHashes(const std::string &target, const std::string &salt = "salt") {
  std::string activeSalt = salt.empty() ? "salt" : salt;
  if (globalJson) {
    std::cout << "{\n"
              << "  \"plaintext\": \"" << target << "\",\n"
              << "  \"crc32\": \"" << crc32(target) << "\",\n"
              << "  \"base64\": \"" << base64_encode((unsigned char *)target.c_str(), (unsigned int)target.length()) << "\",\n"
              << "  \"md5\": \"" << md5(target) << "\",\n"
              << "  \"ntlm\": \"" << ntlm(target) << "\",\n"
              << "  \"md4\": \"" << md4(target) << "\",\n"
              << "  \"sha1\": \"" << sha1(target) << "\",\n"
              << "  \"sha224\": \"" << sha224(target) << "\",\n"
              << "  \"sha256\": \"" << picosha2::hash256_hex_string(target) << "\",\n"
              << "  \"sha384\": \"" << sha384(target) << "\",\n"
              << "  \"sha512\": \"" << sha512(target) << "\",\n"
              << "  \"hmac_md5\": \"" << hmac_md5(activeSalt, target) << "\",\n"
              << "  \"hmac_sha1\": \"" << hmac_sha1(activeSalt, target) << "\",\n"
              << "  \"hmac_sha256\": \"" << hmac_sha256(activeSalt, target) << "\",\n"
              << "  \"pbkdf2_sha1\": \"" << pbkdf2_hmac_sha1(target, activeSalt, 4096, 32) << "\"\n"
              << "}\n";
    return;
  }
  std::cout << "\n\x1b[1;36m[MATRIZ CRIPTOGRAFICA FORENSE]\x1b[0m Hashes gerados com precisao absoluta:\n";
  std::cout << "----------------------------------------------------------------------------\n";
  std::cout << "Texto:       \"" << target << "\"\n";
  std::cout << "CRC32:       " << crc32(target) << " \x1b[1;30m(IEEE 802.3 Checksum)\x1b[0m\n";
  std::cout << "Base64:      " << base64_encode((unsigned char *)target.c_str(), (unsigned int)target.length()) << "\n";
  std::cout << "MD5:         " << md5(target) << "\n";
  std::cout << "NTLM:        " << ntlm(target) << " \x1b[1;33m(Windows SAM / Active Directory)\x1b[0m\n";
  std::cout << "MD4:         " << md4(target) << "\n";
  std::cout << "SHA1:        " << sha1(target) << "\n";
  std::cout << "SHA224:      " << sha224(target) << " \x1b[1;30m(FIPS 180-4)\x1b[0m\n";
  std::cout << "SHA256:      " << picosha2::hash256_hex_string(target) << "\n";
  std::cout << "SHA384:      " << sha384(target) << " \x1b[1;30m(FIPS 180-4)\x1b[0m\n";
  std::cout << "SHA512:      " << sha512(target) << " \x1b[1;30m(FIPS 180-4)\x1b[0m\n";
  std::cout << "HMAC-MD5:    " << hmac_md5(activeSalt, target) << " \x1b[1;30m(key='" << activeSalt << "')\x1b[0m\n";
  std::cout << "HMAC-SHA1:   " << hmac_sha1(activeSalt, target) << " \x1b[1;30m(key='" << activeSalt << "')\x1b[0m\n";
  std::cout << "HMAC-SHA256: " << hmac_sha256(activeSalt, target) << " \x1b[1;30m(key='" << activeSalt << "')\x1b[0m\n";
  std::cout << "PBKDF2-SHA1: " << pbkdf2_hmac_sha1(target, activeSalt, 4096, 32) << " \x1b[1;30m(RFC 2898 / WPA2-PSK c=4096)\x1b[0m\n";
  std::cout << "----------------------------------------------------------------------------\n";
}

// --- Unified Auto-Pilot Execution (Zero-Click Pipeline) ---
AttackResult autoExecuteAttack(const std::string &rawTarget, const std::string &salt = "",
                               int charsetId = 5, int maxLen = 16, bool skipDict = false, int alvoId = 0,
                               const std::string &customWordlist = "wordlist.txt", bool noPotfile = false) {
  AttackResult result;
  std::string target = rawTarget;
  target.erase(0, target.find_first_not_of(" \"'\t\r\n"));
  if (target.empty()) return result;
  target.erase(target.find_last_not_of(" \"'\t\r\n") + 1);

  result.target = target;
  std::string activeSalt = salt;

  // Auto-detect 'hash:salt' or 'salt:hash' standard forensic formats
  if (activeSalt.empty()) {
    size_t sep = target.find_first_of(":");
    if (sep != std::string::npos && sep > 0 && sep < target.length() - 1) {
      std::string partA = target.substr(0, sep);
      std::string partB = target.substr(sep + 1);
      std::string partAUpper = partA;
      for (char &c : partAUpper) c = static_cast<char>(toupper(static_cast<unsigned char>(c)));
      if (partAUpper != "SCRYPT" && partAUpper != "FB_SHA256" &&
          partAUpper != "IG_ARGON2" && partAUpper != "TW_BCRYPT") {
        if (isHex(partA) && (partA.length() == 32 || partA.length() == 40 ||
                             partA.length() == 56 || partA.length() == 64 ||
                             partA.length() == 96 || partA.length() == 128)) {
          target = partA;
          activeSalt = partB;
        } else if (isHex(partB) && (partB.length() == 32 || partB.length() == 40 ||
                                    partB.length() == 56 || partB.length() == 64 ||
                                    partB.length() == 96 || partB.length() == 128)) {
          target = partB;
          activeSalt = partA;
        }
      }
    }
  }

  // If target is hex, normalize to lowercase for 100% match accuracy
  if (isHex(target)) {
    for (char &c : target) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
  } else {
    size_t colon = target.find(':');
    if (colon != std::string::npos && colon < target.length() - 1) {
      std::string pfx = target.substr(0, colon);
      std::string hx = target.substr(colon + 1);
      if (isHex(hx)) {
        for (char &c : hx) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
        target = pfx + ":" + hx;
      }
    }
  }

  result.target = target;
  HashType type = identifyHash(target);

  if (alvoId > 0) {
    switch (alvoId) {
    case 1: type = HashType::SALTED_MD5; break;
    case 2: type = HashType::SALTED_SHA1; break;
    case 3: type = HashType::WPA2_PBKDF2; break;
    case 4: type = HashType::SALTED_SHA256; break;
    case 5: type = HashType::SALTED_SHA512; break;
    case 6: type = HashType::WPA3_SAE; break;
    case 7: type = HashType::BCRYPT; break;
    case 8: type = HashType::SCRYPT; break;
    case 9: type = HashType::SOCIAL_FB; break;
    case 10: type = HashType::SOCIAL_IG; break;
    case 11: type = HashType::SOCIAL_TW; break;
    case 99: type = HashType::CRC32; break;
    case 100: type = HashType::MD5; break;
    case 101: type = HashType::SHA1; break;
    case 102: type = HashType::SHA256; break;
    case 103: type = HashType::SHA512; break;
    case 104: type = HashType::NTLM; break;
    case 105: type = HashType::MD4; break;
    case 106: type = HashType::BASE64; break;
    case 107: type = HashType::HMAC_SHA256; break;
    case 108: type = HashType::HMAC_SHA1; break;
    case 109: type = HashType::HMAC_MD5; break;
    case 110: type = HashType::SHA224; break;
    case 111: type = HashType::SHA384; break;
    default: break;
    }
  } else if (!activeSalt.empty()) {
    if (type == HashType::MD5) type = HashType::SALTED_MD5;
    else if (type == HashType::SHA1) type = HashType::SALTED_SHA1;
    else if (type == HashType::SHA256) type = HashType::SALTED_SHA256;
    else if (type == HashType::SHA512) type = HashType::SALTED_SHA512;
  }
  result.type = type;

  // Case 1: Base64 Decodification
  if (type == HashType::BASE64) {
    std::string decoded = base64_decode(target);
    if (!globalQuiet && !globalJson) {
      std::cout << "\n\x1b[1;36m[AUTO-DETECT]\x1b[0m Base64 detectado com precisao!\n";
      std::cout << "--------------------------------------------------\n";
      std::cout << "Decodificado: \x1b[1;32m" << decoded << "\x1b[0m\n";
      std::cout << "--------------------------------------------------\n";
    } else if (globalQuiet) {
      std::cout << target << ":" << decoded << "\n";
    } else if (globalJson) {
      std::cout << "{\n  \"status\": \"cracked\",\n  \"target\": \"" << target << "\",\n  \"plaintext\": \"" << decoded << "\",\n  \"algorithm\": \"Base64\"\n}\n";
    }
    result.success = true;
    result.recoveredPass = decoded;
    result.method = "Base64 Strict Decode";
    result.attempts = 1;
    result.durationMs = 0;
    return result;
  }

  // Case 2: Plaintext detected -> Complete Hash Matrix Calculator
  if (type == HashType::UNKNOWN && activeSalt.empty()) {
    generateAndDisplayHashes(target, "salt");
    result.success = true;
    result.recoveredPass = target;
    result.method = "Plaintext Hash Matrix";
    return result;
  }

  Config config;
  config.target = target;
  config.targetHash = target;
  config.type = type;
  config.hashType = getKernelAlgoId(type);
  config.salt = activeSalt;
  config.maxLength = maxLen;
  config.charset = getCharset(charsetId);

  // Case 3: Target is a Hash -> Auto Recovery Pipeline
  if (!globalQuiet && !globalJson) {
    std::cout << "\n\x1b[1;36m[CERBERUS FORENSIC PIPELINE]\x1b[0m\n";
    std::cout << "--------------------------------------------------\n";
    std::cout << "[i] Algoritmo: \x1b[1;33m" << hashTypeName(config.type);
    if (target.length() == 32 && alvoId == 0) {
      std::cout << " (Compativeis: NTLM, MD4)";
    }
    std::cout << "\x1b[0m\n";
    std::cout << "[i] Alvo:      \x1b[1;37m" << config.target << "\x1b[0m\n";
    if (!activeSalt.empty()) {
      std::cout << "[i] Salt:      " << activeSalt << "\n";
    }
    std::cout << "[i] Motor:     \x1b[1;32m" << getEngineName() << "\x1b[0m\n";
    std::cout << "[i] Charset:   " << config.charset.length() << " caracteres (Alfanumerico)\n";
    std::cout << "--------------------------------------------------\n";
  }

  // Step 0: Check Forensic Potfile / Cache
  std::string potPass;
  HashType potType = config.type;
  if (!noPotfile && checkPotfile(config.target, config.salt, potPass, potType)) {
    logPotfileHit(config.target, potPass, potType, config.salt);
    result.success = true;
    result.fromPotfile = true;
    result.recoveredPass = potPass;
    result.type = potType;
    result.method = "Potfile Cache";
    result.attempts = 1;
    result.durationMs = 0;
    return result;
  }

  auto attackStart = std::chrono::high_resolution_clock::now();

  // Step 1: Instant dictionary attack with rule mutations
  bool dictFound = false;
  std::string activeWordlist = customWordlist.empty() ? "wordlist.txt" : customWordlist;
  if (!skipDict && fileExists(activeWordlist)) {
    if (!globalQuiet && !globalJson) {
      std::cout << "[1/2] Verificando dicionario forense (" << activeWordlist << " + mutacoes)...\n";
    }
    dictFound = dictionaryAttack(config, activeWordlist);

    // If 32-hex and not found with MD5, automatically test NTLM hypothesis
    if (!dictFound && config.type == HashType::MD5 && activeSalt.empty()) {
      Config ntlmConf = config;
      ntlmConf.type = HashType::NTLM;
      if (!globalQuiet && !globalJson) {
        std::cout << "[i] Testando hipotese NTLM (Windows Hash) no dicionario...\n";
      }
      dictFound = dictionaryAttack(ntlmConf, activeWordlist);
      if (dictFound) {
        config.type = HashType::NTLM;
      }
    }
  } else if (skipDict && !globalQuiet && !globalJson) {
    std::cout << "[i] Ataque por dicionario pulado (--no-dict ativado).\n";
  }

  if (dictFound) {
    auto attackEnd = std::chrono::high_resolution_clock::now();
    result.success = true;
    result.recoveredPass = crackedPassword;
    result.type = config.type;
    result.method = "Dicionário Forense + Mutações";
    result.attempts = totalTentativas.load();
    result.durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(attackEnd - attackStart).count();
    return result;
  }

  // Step 2: Seamless automatic cascade to Brute Force!
  if (!globalQuiet && !globalJson) {
    std::cout << "\n[2/2] Nao encontrado no dicionario. Disparando Forca Bruta Automatica (" 
              << getEngineName() << ")...\n";
  }
  bool bfFound = runParallelBruteForce(config);
  auto attackEnd = std::chrono::high_resolution_clock::now();
  long long totalMs = std::chrono::duration_cast<std::chrono::milliseconds>(attackEnd - attackStart).count();

  if (bfFound) {
    result.success = true;
    result.recoveredPass = crackedPassword;
    result.type = config.type;
    result.method = (globalCompute == ComputeType::OPENCL) ? "Força Bruta GPU (OpenCL)" : "Força Bruta CPU Multi-Threaded";
    result.attempts = totalTentativas.load();
    result.durationMs = totalMs;
  } else {
    logExhausted(config.target, config.type, 1, config.maxLength, (int)config.charset.length(),
                 totalTentativas.load(), totalMs, getEngineName());
    result.success = false;
    result.type = config.type;
    result.attempts = totalTentativas.load();
    result.durationMs = totalMs;
  }
  return result;
}

// Multi-Hash Batch File Processing with Executive Summary Report
void auditHashFile(const std::string &filePath, const std::string &salt = "",
                   int charsetId = 5, int maxLen = 16, bool skipDict = false, int alvoId = 0,
                   const std::string &customWordlist = "wordlist.txt", bool noPotfile = false) {
  std::ifstream f(filePath);
  if (!f.is_open()) {
    std::cout << "\x1b[1;31m[!] Erro: Arquivo de lote '" << filePath << "' nao encontrado!\x1b[0m\n";
    return;
  }
  std::vector<std::string> targets;
  std::string line;
  while (std::getline(f, line)) {
    line.erase(0, line.find_first_not_of(" \"'\t\r\n"));
    if (!line.empty()) {
      line.erase(line.find_last_not_of(" \"'\t\r\n") + 1);
      if (!line.empty() && line[0] != '#') {
        targets.push_back(line);
      }
    }
  }

  if (targets.empty()) {
    std::cout << "\x1b[1;33m[!] Arquivo de lote vazio ou contendo apenas comentarios.\x1b[0m\n";
    return;
  }

  if (!globalQuiet && !globalJson) {
    std::cout << "\n\x1b[1;35m[LOTE FORENSE] Carregando arquivo de alvos: " << filePath << "\x1b[0m\n";
    std::cout << "[i] Total de alvos identificados: " << targets.size() << "\n";
    std::cout << "============================================================================\n";
  }

  auto startBatch = std::chrono::high_resolution_clock::now();
  std::vector<AttackResult> results;
  int crackedCount = 0;
  int cachedCount = 0;
  int failedCount = 0;
  long long totalBatchAttempts = 0;

  for (size_t i = 0; i < targets.size(); i++) {
    if (!globalQuiet && !globalJson) {
      std::cout << "\n\x1b[1;33m>>> ALVO [" << (i + 1) << "/" << targets.size() << "]: " << targets[i] << "\x1b[0m\n";
    }
    AttackResult res = autoExecuteAttack(targets[i], salt, charsetId, maxLen, skipDict, alvoId, customWordlist, noPotfile);
    results.push_back(res);

    if (res.success) {
      if (res.fromPotfile) cachedCount++;
      else crackedCount++;
    } else {
      failedCount++;
    }
    totalBatchAttempts += res.attempts;
  }

  auto endBatch = std::chrono::high_resolution_clock::now();
  long long totalBatchMs = std::chrono::duration_cast<std::chrono::milliseconds>(endBatch - startBatch).count();
  if (totalBatchMs < 1) totalBatchMs = 1;

  if (globalQuiet) return;

  if (globalJson) {
    std::cout << "{\n"
              << "  \"batch_file\": \"" << filePath << "\",\n"
              << "  \"total\": " << targets.size() << ",\n"
              << "  \"cracked\": " << crackedCount << ",\n"
              << "  \"cached\": " << cachedCount << ",\n"
              << "  \"failed\": " << failedCount << ",\n"
              << "  \"total_time_ms\": " << totalBatchMs << ",\n"
              << "  \"total_attempts\": " << totalBatchAttempts << ",\n"
              << "  \"items\": [\n";
    for (size_t i = 0; i < results.size(); i++) {
      std::cout << "    {\"target\": \"" << results[i].target << "\", "
                << "\"status\": \"" << (results[i].success ? (results[i].fromPotfile ? "cached" : "cracked") : "failed") << "\", "
                << "\"plaintext\": \"" << results[i].recoveredPass << "\"}"
                << (i + 1 < results.size() ? ",\n" : "\n");
    }
    std::cout << "  ]\n}\n";
    return;
  }

  // Executive Summary Report
  double totalRate = (double)totalBatchAttempts / (totalBatchMs / 1000.0);
  double successPct = ((double)(crackedCount + cachedCount) * 100.0) / targets.size();

  std::cout << "\n\n\x1b[1;36m";
  std::cout << "================================================================================\n";
  std::cout << "                         RELATÓRIO DE AUDITORIA EM LOTE                         \n";
  std::cout << "================================================================================\x1b[0m\n";
  std::cout << " Total de Alvos        : " << targets.size() << "\n";
  std::cout << " Recuperados (Sucesso) : \x1b[1;32m" << (crackedCount + cachedCount)
            << " (" << std::fixed << std::setprecision(1) << successPct << "%)\x1b[0m"
            << " [Novos: " << crackedCount << " | Cache Potfile: " << cachedCount << "]\n";
  std::cout << " Nao Recuperados       : \x1b[1;" << (failedCount > 0 ? "31m" : "32m") << failedCount
            << " (" << std::fixed << std::setprecision(1) << (100.0 - successPct) << "%)\x1b[0m\n";
  std::cout << " Tempo Total Auditado  : \x1b[1;33m" << formatTime(totalBatchMs) << "\x1b[0m\n";
  std::cout << " Tentativas Globais    : " << formatNumber(totalBatchAttempts) << " (" << formatHashrate(totalRate) << ")\n";
  std::cout << "================================================================================\n";
  std::cout << " ID  | HASH ALVO (Truncado)            | STATUS  | ALGORITMO   | SENHA RECUPERADA\n";
  std::cout << "-----+---------------------------------+---------+-------------+----------------\n";

  for (size_t i = 0; i < results.size(); i++) {
    const auto &r = results[i];
    std::string dispHash = r.target;
    if (dispHash.length() > 31) {
      dispHash = dispHash.substr(0, 14) + "..." + dispHash.substr(dispHash.length() - 14);
    }
    while (dispHash.length() < 31) dispHash += " ";

    std::string statusStr = r.success ? (r.fromPotfile ? "CACHED " : "CRACKED") : "FAILED ";
    std::string colorStatus = r.success ? "\x1b[1;32m" : "\x1b[1;31m";

    std::string algoStr = hashTypeName(r.type);
    if (algoStr.length() > 11) algoStr = algoStr.substr(0, 11);
    while (algoStr.length() < 11) algoStr += " ";

    std::string passStr = r.success ? r.recoveredPass : "[NAO ENCONTRADA]";
    if (passStr.length() > 16) passStr = passStr.substr(0, 13) + "...";

    char idBuf[8];
    snprintf(idBuf, sizeof(idBuf), "%02zu", i + 1);

    std::cout << " " << idBuf << "  | " << dispHash << " | "
              << colorStatus << statusStr << "\x1b[0m | "
              << algoStr << " | "
              << (r.success ? "\x1b[1;93m" : "\x1b[1;30m") << passStr << "\x1b[0m\n";
  }
  std::cout << "================================================================================\n";
  std::cout << "[i] Resultados sincronizados e persistidos em 'cracked_passwords.txt'.\n\n";
}

// --- Main Interface ---

int main(int argc, char *argv[]) {
  enableANSI();

  // === CLI MODE ===
  if (argc > 1) {
    globalQuiet = cliHasFlag(argc, argv, "--quiet") || cliHasFlag(argc, argv, "-q");
    globalVerbose = cliHasFlag(argc, argv, "--verbose") || cliHasFlag(argc, argv, "-v");
    globalJson = cliHasFlag(argc, argv, "--json");

    if (globalQuiet || globalJson) {
      set_opencl_quiet(1);
    }

    std::string arg1 = argv[1];
    std::string arg1Lower = arg1;
    std::transform(arg1Lower.begin(), arg1Lower.end(), arg1Lower.begin(), ::tolower);
    while (!arg1Lower.empty() && arg1Lower[0] == '-') arg1Lower.erase(0, 1);

    // Engine flag
    std::string engineOpt = cliGetArgValue(argc, argv, "--engine");
    if (engineOpt.empty()) engineOpt = cliGetArgValue(argc, argv, "-e");
    if (!engineOpt.empty()) {
      std::transform(engineOpt.begin(), engineOpt.end(), engineOpt.begin(), ::tolower);
      initEngine(engineOpt);
    } else {
      initHardwareAuto();
    }

    if (arg1Lower == "help" || arg1Lower == "h" || arg1Lower == "?") {
      printHelp();
      return 0;
    }

    if (arg1Lower == "version" || arg1Lower == "v") {
      printVersion();
      return 0;
    }

    if (arg1Lower == "history" || arg1Lower == "potfile" || arg1Lower == "show") {
      std::string potPath = (argc > 2) ? argv[2] : "cracked_passwords.txt";
      displayPotfileHistory(potPath);
      return 0;
    }

    if (arg1Lower == "test-all" || arg1Lower == "test" || arg1Lower == "t") {
      runAllTests(false);
      return 0;
    }

    if (arg1Lower == "benchmark" || arg1Lower == "bench" || arg1Lower == "b") {
      runBenchmark();
      return 0;
    }

    if (arg1Lower == "decode" || arg1Lower == "d") {
      if (argc < 3) {
        std::cout << "\x1b[1;31m[!] Uso: cerberus decode <base64>\x1b[0m\n";
        return 1;
      }
      std::cout << "Decodificado: \x1b[1;32m" << base64_decode(argv[2]) << "\x1b[0m\n";
      return 0;
    }

    if (arg1Lower == "hash" || arg1Lower == "g") {
      if (argc < 3) {
        std::cout << "\x1b[1;31m[!] Uso: cerberus hash <texto> [--salt <salt>]\x1b[0m\n";
        return 1;
      }
      std::string textToHash = argv[2];
      std::string saltVal = cliGetArgValue(argc, argv, "--salt");
      if (saltVal.empty()) saltVal = cliGetArgValue(argc, argv, "-s");
      generateAndDisplayHashes(textToHash, saltVal);
      return 0;
    }

    std::string targetHash = "";
    if (arg1Lower == "crack" || arg1Lower == "c" || arg1Lower == "crack-salt" || arg1Lower == "cs") {
      if (argc < 3) {
        std::cout << "\x1b[1;31m[!] Uso: cerberus crack <hash>\x1b[0m\n";
        return 1;
      }
      targetHash = argv[2];
    } else {
      targetHash = argv[1];
    }

    std::string salt = cliGetArgValue(argc, argv, "--salt");
    if (salt.empty()) salt = cliGetArgValue(argc, argv, "-s");

    std::string charsetStr = cliGetArgValue(argc, argv, "--charset");
    if (charsetStr.empty()) charsetStr = cliGetArgValue(argc, argv, "-c");
    int charsetId = charsetStr.empty() ? 5 : std::stoi(charsetStr);

    std::string maxLenStr = cliGetArgValue(argc, argv, "--max-len");
    if (maxLenStr.empty()) maxLenStr = cliGetArgValue(argc, argv, "-l");
    int maxLen = maxLenStr.empty() ? 16 : std::stoi(maxLenStr);

    bool noDict = cliHasFlag(argc, argv, "--no-dict") || cliHasFlag(argc, argv, "-n");
    bool noPotfile = cliHasFlag(argc, argv, "--no-potfile") || cliHasFlag(argc, argv, "--fresh");

    std::string customWordlist = cliGetArgValue(argc, argv, "--wordlist");
    if (customWordlist.empty()) customWordlist = cliGetArgValue(argc, argv, "-w");
    if (customWordlist.empty()) customWordlist = "wordlist.txt";

    std::string algoStr = cliGetArgValue(argc, argv, "--algo");
    if (algoStr.empty()) algoStr = cliGetArgValue(argc, argv, "-a");
    if (algoStr.empty()) algoStr = cliGetArgValue(argc, argv, "--alvo");

    int alvoId = 0;
    if (!algoStr.empty()) {
      std::string al = algoStr;
      std::transform(al.begin(), al.end(), al.begin(), ::tolower);
      if (al == "crc32") alvoId = 99;
      else if (al == "md5") alvoId = 100;
      else if (al == "sha1") alvoId = 101;
      else if (al == "sha256") alvoId = 102;
      else if (al == "sha512") alvoId = 103;
      else if (al == "ntlm") alvoId = 104;
      else if (al == "md4") alvoId = 105;
      else if (al == "base64") alvoId = 106;
      else if (al == "hmac-sha256" || al == "hmac_sha256" || al == "hmacsha256") alvoId = 107;
      else if (al == "hmac-sha1" || al == "hmac_sha1" || al == "hmacsha1") alvoId = 108;
      else if (al == "hmac-md5" || al == "hmac_md5" || al == "hmacmd5") alvoId = 109;
      else if (al == "sha224") alvoId = 110;
      else if (al == "sha384") alvoId = 111;
      else if (al == "salted-md5" || al == "md5-salt") alvoId = 1;
      else if (al == "salted-sha1" || al == "sha1-salt") alvoId = 2;
      else if (al == "wpa2" || al == "pbkdf2") alvoId = 3;
      else if (al == "salted-sha256" || al == "sha256-salt") alvoId = 4;
      else if (al == "salted-sha512" || al == "sha512-salt") alvoId = 5;
      else if (al == "wpa3" || al == "sae") alvoId = 6;
      else if (al == "bcrypt") alvoId = 7;
      else if (al == "scrypt") alvoId = 8;
      else if (al == "facebook" || al == "fb") alvoId = 9;
      else if (al == "instagram" || al == "ig") alvoId = 10;
      else if (al == "twitter" || al == "tw") alvoId = 11;
      else {
        try { alvoId = std::stoi(algoStr); } catch (...) { alvoId = 0; }
      }
    }

    // Check for Batch Multi-Hash File Mode
    std::string fileOpt = cliGetArgValue(argc, argv, "--file");
    if (fileOpt.empty()) fileOpt = cliGetArgValue(argc, argv, "-f");
    if (arg1Lower == "file" || arg1Lower == "batch" || !fileOpt.empty() ||
        (fileExists(targetHash) && targetHash.find(".txt") != std::string::npos &&
         targetHash != "wordlist.txt" && targetHash != "saltlist.txt" && targetHash != "cracked_passwords.txt")) {
      std::string targetFile = !fileOpt.empty() ? fileOpt : (arg1Lower == "file" || arg1Lower == "batch" ? (argc > 2 ? argv[2] : "") : targetHash);
      if (targetFile.empty()) {
        std::cout << "\x1b[1;31m[!] Uso: cerberus file <arquivo_de_hashes.txt>\x1b[0m\n";
        return 1;
      }
      if (!globalQuiet && !globalJson) {
        exibirDesenho();
      }
      auditHashFile(targetFile, salt, charsetId, maxLen, noDict, alvoId, customWordlist, noPotfile);
      cleanupOpenCL();
      return 0;
    }

    if (!globalQuiet && !globalJson) {
      exibirDesenho();
    }
    autoExecuteAttack(targetHash, salt, charsetId, maxLen, noDict, alvoId, customWordlist, noPotfile);
    cleanupOpenCL();
    return 0;
  }

  // === INTERACTIVE ZERO-CLICK MODE ===
  initHardwareAuto();

  while (true) {
#ifdef _WIN32
    std::system("cls");
#else
    std::system("clear");
#endif
    exibirDesenho();
    std::cout << "  STATUS: \x1b[1;32mONLINE\x1b[0m | MOTOR: \x1b[1;36m" << getEngineName() << "\x1b[0m\n";
    std::cout << "  ----------------------------------------------------------------------------\n";
    std::cout << "  \x1b[1;37mMODO INTUITIVO ZERO-CLICK:\x1b[0m Cole ou digite qualquer Hash, Base64 ou Texto!\n";
    std::cout << "  (Atalhos: '\x1b[1;33mtest\x1b[0m' = testes | '\x1b[1;33mbench\x1b[0m' = velocidade | '\x1b[1;33mpotfile\x1b[0m' = historico | '\x1b[1;33mfile <arq>\x1b[0m' = lote | '\x1b[1;33m0\x1b[0m' = sair)\n";
    std::cout << "  ----------------------------------------------------------------------------\n\n";
    std::cout << "  \x1b[1;36mcerberus >> \x1b[0m";

    std::string input;
    if (!std::getline(std::cin, input)) break;

    input.erase(0, input.find_first_not_of(" \"'\t\r\n"));
    if (input.empty()) continue;
    input.erase(input.find_last_not_of(" \"'\t\r\n") + 1);

    if (input == "0" || input == "sair" || input == "exit" || input == "quit" || input == "q") {
      std::cout << "\n[!] Encerrando sessao...\n";
      break;
    }

    if (input == "help" || input == "ajuda" || input == "h" || input == "?") {
      printHelp();
      std::cout << "\n\x1b[1;33mPressione ENTER para voltar...\x1b[0m";
      std::cin.get();
      continue;
    }

    if (input == "history" || input == "potfile" || input == "show") {
      displayPotfileHistory();
      std::cout << "\n\x1b[1;33mPressione ENTER para continuar...\x1b[0m";
      std::cin.get();
      continue;
    }

    if (input == "cpu") {
      globalCompute = ComputeType::CPU;
      std::cout << "\n\x1b[1;36m[+] Motor alterado para CPU Multi-Threaded!\x1b[0m\n";
      sleepMs(1000);
      continue;
    }

    if (input == "gpu" || input == "opencl") {
      if (initOpenCL()) {
        globalCompute = ComputeType::OPENCL;
        std::cout << "\n\x1b[1;32m[+] Motor alterado para GPU (OpenCL)!\x1b[0m\n";
      } else {
        std::cout << "\n\x1b[1;31m[!] Falha ao ativar OpenCL na GPU.\x1b[0m\n";
      }
      sleepMs(1000);
      continue;
    }

    if (input.rfind("file ", 0) == 0 || input.rfind("batch ", 0) == 0) {
      std::string fPath = input.substr(input.find(' ') + 1);
      fPath.erase(0, fPath.find_first_not_of(" \"'\t\r\n"));
      fPath.erase(fPath.find_last_not_of(" \"'\t\r\n") + 1);
      auditHashFile(fPath);
      std::cout << "\n\x1b[1;33mPressione ENTER para continuar...\x1b[0m";
      std::cin.get();
      continue;
    }

    if (input == "test" || input == "t" || input == "test-all") {
      runAllTests(true);
      continue;
    }

    if (input == "bench" || input == "benchmark" || input == "b") {
      runBenchmark();
      std::cout << "\x1b[1;33mPressione ENTER para voltar ao menu...\x1b[0m";
      std::cin.get();
      continue;
    }

    if (input == "salt" || input == "s") {
      std::cout << "\n\x1b[1;36m--- MODO SALT AVANCADO ---\x1b[0m\n";
      std::cout << "Insira o Hash: ";
      std::string targetHash;
      std::cin >> targetHash;
      std::cout << "Insira o Salt (ou '-' para saltlist.txt): ";
      std::string saltVal;
      std::cin >> saltVal;
      if (saltVal == "-") saltVal = "";
      std::cin.ignore(10000, '\n');

      autoExecuteAttack(targetHash, saltVal);
      std::cout << "\n\x1b[1;33mPressione ENTER para continuar...\x1b[0m";
      std::cin.get();
      continue;
    }

    autoExecuteAttack(input);

    std::cout << "\n\x1b[1;33mPressione ENTER para continuar...\x1b[0m";
    std::cin.get();
  }

  cleanupOpenCL();
  return 0;
}
