#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <mutex>
#include <new>
#include <random>
#include <sstream>
#include <stdexcept>
#include <streambuf>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include <unordered_set>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

#if defined(ENABLE_CUDA)
#include <cuda_runtime.h>
#endif

// Include local cryptographic headers
#include "algorithms/base64.h"
#include "algorithms/crc32.h"
#include "algorithms/md4.h"
#include "algorithms/md5.h"
#include "algorithms/hmac.h"
#include "algorithms/picosha2.h"
#include "algorithms/sha1.h"
#include "algorithms/sha224.h"
#include "algorithms/sha512.h"

extern "C" char *_crypt_blowfish_rn(const char *key, const char *setting,
                                    char *output, int size);

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
  WPA3_SAE,      // Passive SAE captures have no generic offline verifier.
  BCRYPT,        // bcrypt $2a$/$2b$/$2y$ verification via Openwall.
  SCRYPT,        // PHC $scrypt$ hashes verified on the CPU.
};

struct Config {
  HashType type = HashType::MD5;
  std::string target;
  std::string targetHash; // For OpenCL
  int hashType = 0;       // For OpenCL kernel
  std::string salt;
  bool saltProvided = false;
  std::string charset;
  int maxLength = 16;
  bool useDictionary = false;
};

// --- Global Config for Compute Unit ---
enum class ComputeType { CPU, CUDA, OPENCL };
ComputeType globalCompute = ComputeType::CPU;
bool globalEngineExplicitlySelected = false;
std::string globalEngineFailure;
extern bool globalQuiet;
extern bool globalJson;

// --- OPENCL FUNCTIONS ---
extern "C" {
int initOpenCL();
void cleanupOpenCL();
const char *get_opencl_device_name();
unsigned long long get_opencl_vram_bytes();
int launch_opencl_brute_force(const char *charset, const char *target,
                              int max_len, char *result, int *should_stop,
                              int hashType, const char *salt,
                              unsigned long long *attempts_out);
void launch_opencl_hash_calc(const char *input, char *output_hex, int hashType);
void set_opencl_quiet(int q);
}

// --- Helper Functions ---
void lowercaseAscii(std::string &value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
}

std::filesystem::path pathFromUtf8(const std::string &path) {
  return std::filesystem::u8path(path);
}

std::string pathToUtf8(const std::filesystem::path &path) {
  const std::u8string value = path.u8string();
  return std::string(reinterpret_cast<const char *>(value.data()), value.size());
}

std::string terminalSafeText(const std::string &value);

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
    // WPA2 PMK derivation uses PBKDF2-HMAC-SHA1 and is CPU-only here.
    return -1;
  case HashType::WPA3_SAE:
    return -1; // SAE captures do not provide a generic offline verifier.
  case HashType::BCRYPT:
  case HashType::SCRYPT:
    return -1; // Real CPU implementations; no GPU kernel is available.
  case HashType::NTLM:
    return 11;
  case HashType::MD4:
    return 12;
  default:
    return -1; // Unsupported algorithms must never silently become SHA-256.
  }
}

bool computeEngineSupportsHashType(ComputeType engine, HashType type) {
  if (engine == ComputeType::CPU) return true;
  const int kernelAlgo = getKernelAlgoId(type);
  if (engine == ComputeType::CUDA)
    return kernelAlgo == 0 || kernelAlgo == 1 || kernelAlgo == 2 ||
           kernelAlgo == 3 ||
           kernelAlgo == 11 || kernelAlgo == 12;
  return (kernelAlgo >= 0 && kernelAlgo <= 3) ||
         kernelAlgo == 11 || kernelAlgo == 12;
}

bool gpuKeyspaceFitsCounters(size_t charsetSize, int maxLength,
                             size_t saltCount, long long initialAttempts,
                             int &maxSupportedLength) {
  maxSupportedLength = 0;
  if (charsetSize == 0 || maxLength < 0 || saltCount == 0 ||
      initialAttempts < 0)
    return false;

  const unsigned long long reportLimit = static_cast<unsigned long long>(
      std::numeric_limits<long long>::max() - initialAttempts);
  const unsigned long long perSaltLimit =
      reportLimit / static_cast<unsigned long long>(saltCount);
  const unsigned long long radix = static_cast<unsigned long long>(charsetSize);
  unsigned long long combinations = 1;
  unsigned long long totalCombinations = 0;
  for (int length = 1; length <= maxLength; ++length) {
    if (combinations > std::numeric_limits<unsigned long long>::max() / radix)
      return false;
    combinations *= radix;
    if (totalCombinations > perSaltLimit ||
        combinations > perSaltLimit - totalCombinations)
      return false;
    totalCombinations += combinations;
    maxSupportedLength = length;
  }
  return true;
}

std::string getRealGPUName() {
  if (globalCompute == ComputeType::OPENCL) {
    const char *name = get_opencl_device_name();
    if (name && std::strlen(name) > 0 &&
        std::strcmp(name, "Dispositivo OpenCL") != 0) {
      return name;
    }
  }

#if defined(ENABLE_CUDA)
  if (globalCompute == ComputeType::CUDA) {
    cudaDeviceProp prop;
    if (cudaGetDeviceProperties(&prop, 0) == cudaSuccess) {
      return prop.name;
    }
  }
#endif

  return "GPU nao identificada";
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
using CudaProgressCallback = void (*)(void *, unsigned long long,
                                      unsigned long long, double, int, int);
extern "C" int launch_gpu_brute_force_ext(const char *charset, const char *target,
                                          int max_len, char *result, int hashType,
                                          const char *salt,
                                          unsigned long long *attempts_out,
                                          void *progress_context,
                                          CudaProgressCallback progress_callback);

bool initCUDA() {
  if (!globalQuiet && !globalJson)
    std::cout << "\n\x1b[1;32m[CUDA] Initializing NVIDIA CUDA Runtime...\x1b[0m\n";
  if (!globalQuiet && !globalJson) sleepMs(200);
  if (!globalQuiet && !globalJson) std::cout << "[CUDA] Detecting CUDA-capable devices...\n";
  cudaDeviceProp deviceProperties{};
  const bool cudaDeviceAvailable =
      cudaGetDeviceProperties(&deviceProperties, 0) == cudaSuccess;
  if (!globalQuiet && !globalJson) {
    const std::string gpuName = cudaDeviceAvailable
                                    ? terminalSafeText(deviceProperties.name)
                                    : "GPU nao identificada";
    std::cout << "  [+] Device 0: " << gpuName
              << (cudaDeviceAvailable ? " (Detected)\n" : " (Unavailable)\n");
    if (cudaDeviceAvailable) {
      const unsigned long long vramMb =
          static_cast<unsigned long long>(deviceProperties.totalGlobalMem) /
          (1024 * 1024);
      std::cout << "  [+] VRAM: " << vramMb << " MB\n";
    } else {
      std::cout << "  [+] VRAM: N/A\n";
    }
  }

  if (!globalQuiet && !globalJson) std::cout << "[CUDA] Verifying Kernel Execution...\n";
  int test_val = 0;
  if (cudaDeviceAvailable) {
    try {
      launch_cuda_test(&test_val);
    } catch (...) {
      test_val = 0;
    }
  }

  if (test_val == 1337) {
    if (!globalQuiet && !globalJson)
      std::cout << "\x1b[1;32m[CUDA] KERNEL EXECUTION SUCCESSFUL. GPU IS ACTIVE.\x1b[0m\n";
    globalCompute = ComputeType::CUDA;
    return true;
  } else {
    if (!globalQuiet && !globalJson)
      std::cout << "\x1b[1;33m[CUDA] Native execution verification failed.\x1b[0m\n";
    globalCompute = ComputeType::CPU;
    return false;
  }
}
#else
bool initCUDA() {
  if (!globalQuiet && !globalJson) {
    std::cout << "\n\x1b[1;33m[!] CUDA nativo nao foi incluido nesta build.\x1b[0m\n";
  }
  globalCompute = ComputeType::CPU;
  return false;
}
#endif

std::string getEngineName() {
  switch (globalCompute) {
  case ComputeType::CUDA:
    return "v3.0-CUDA (NVIDIA)";
  case ComputeType::OPENCL:
    return "v3.0-OPENCL (" + getRealGPUName() + ")";
  default:
    return "v3.0-CPU (Multi-Threaded)";
  }
}

bool fileExists(const std::string &name) {
  try {
    std::error_code error;
    return std::filesystem::is_regular_file(pathFromUtf8(name), error) && !error;
  } catch (const std::filesystem::filesystem_error &) {
    return false;
  }
}

std::filesystem::path executableDirectory() {
#ifdef _WIN32
  std::vector<wchar_t> buffer(512);
  while (buffer.size() <= 32768) {
    const DWORD length = GetModuleFileNameW(
        nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length == 0) return {};
    if (length < buffer.size()) {
      return std::filesystem::path(std::wstring(buffer.data(), length))
          .parent_path();
    }
    buffer.resize(buffer.size() * 2);
  }
#endif
  return {};
}

std::filesystem::path defaultDataFilePath(const std::string &fileName) {
  const std::filesystem::path workingDirectoryPath = pathFromUtf8(fileName);
  if (fileExists(fileName)) return workingDirectoryPath;

  // Bundled data lives in data/lists/ in a source checkout. Earlier releases
  // used lists/, and direct files in the current directory remain supported.
  if (!workingDirectoryPath.has_parent_path()) {
    const std::filesystem::path workingListPath =
        std::filesystem::path("lists") / workingDirectoryPath.filename();
    if (fileExists(pathToUtf8(workingListPath))) return workingListPath;

    const std::filesystem::path workingDataPath =
        std::filesystem::path("data") / "lists" /
        workingDirectoryPath.filename();
    if (fileExists(pathToUtf8(workingDataPath))) return workingDataPath;
  }

  const std::filesystem::path appDirectory = executableDirectory();
  if (appDirectory.empty()) return workingDirectoryPath;
  const std::filesystem::path appDataPath =
      appDirectory / workingDirectoryPath.filename();
  if (fileExists(pathToUtf8(appDataPath))) return appDataPath;

  if (!workingDirectoryPath.has_parent_path()) {
    const std::filesystem::path appListPath =
        appDirectory / "lists" / workingDirectoryPath.filename();
    if (fileExists(pathToUtf8(appListPath))) return appListPath;

    const std::filesystem::path appDataPath =
        appDirectory / "data" / "lists" / workingDirectoryPath.filename();
    if (fileExists(pathToUtf8(appDataPath))) return appDataPath;
  }
  return workingDirectoryPath;
}

bool streamHasReadError(const std::istream &input) {
  return input.bad() || (input.fail() && !input.eof());
}

bool readLineWithUniversalNewlines(std::istream &input, std::string &line) {
  line.clear();
  char character = '\0';
  while (input.get(character)) {
    if (character == '\n') return true;
    if (character == '\r') {
      if (input.peek() == '\n') input.get();
      return true;
    }
    line.push_back(character);
  }
  // Keep a final unterminated line only when the stream actually reached EOF.
  // A non-EOF failbit must not turn a truncated list entry into valid input.
  return input.eof() && !streamHasReadError(input) && !line.empty();
}

enum class WideTextBomStatus { NONE, PRESENT, READ_ERROR };

WideTextBomStatus probeWideTextBom(std::istream &input) {
  const std::streampos start = input.tellg();
  if (start == std::streampos(-1)) return WideTextBomStatus::READ_ERROR;

  unsigned char prefix[4] = {};
  input.read(reinterpret_cast<char *>(prefix), sizeof(prefix));
  const std::streamsize bytesRead = input.gcount();
  const bool readError = streamHasReadError(input);
  input.clear();
  input.seekg(start);
  if (readError || !input) return WideTextBomStatus::READ_ERROR;

  const bool utf16 =
      bytesRead >= 2 &&
      ((prefix[0] == 0xFF && prefix[1] == 0xFE) ||
       (prefix[0] == 0xFE && prefix[1] == 0xFF));
  const bool utf32BigEndian =
      bytesRead >= 4 && prefix[0] == 0x00 && prefix[1] == 0x00 &&
      prefix[2] == 0xFE && prefix[3] == 0xFF;
  return utf16 || utf32BigEndian ? WideTextBomStatus::PRESENT
                                 : WideTextBomStatus::NONE;
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
    return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"; // Printable ASCII
  default:
    return "abcdefghijklmnopqrstuvwxyz0123456789"; // Default
  }
}

bool isHex(const std::string &input) {
  if (input.empty()) return false;
  for (char c : input) {
    if (!std::isxdigit(static_cast<unsigned char>(c)))
      return false;
  }
  return true;
}

bool isValidUtf8(const std::string &input, size_t start = 0) {
  if (start > input.size()) return false;
  for (size_t i = start; i < input.size();) {
    const unsigned char first = static_cast<unsigned char>(input[i++]);
    if (first <= 0x7f) continue;
    uint32_t codepoint = 0;
    size_t continuationCount = 0;
    if (first >= 0xc2 && first <= 0xdf) {
      codepoint = first & 0x1f;
      continuationCount = 1;
    } else if (first >= 0xe0 && first <= 0xef) {
      codepoint = first & 0x0f;
      continuationCount = 2;
    } else if (first >= 0xf0 && first <= 0xf4) {
      codepoint = first & 0x07;
      continuationCount = 3;
    } else {
      return false;
    }
    if (i + continuationCount > input.size()) return false;
    for (size_t j = 0; j < continuationCount; ++j) {
      const unsigned char next = static_cast<unsigned char>(input[i++]);
      if ((next & 0xc0) != 0x80) return false;
      codepoint = (codepoint << 6) | (next & 0x3f);
    }
    if ((continuationCount == 1 && codepoint < 0x80) ||
        (continuationCount == 2 && codepoint < 0x800) ||
        (continuationCount == 3 && codepoint < 0x10000) ||
        (codepoint >= 0xd800 && codepoint <= 0xdfff) ||
        codepoint > 0x10ffff)
      return false;
  }
  return true;
}

std::string terminalSafeText(const std::string &value) {
  const bool validUtf8 = isValidUtf8(value);
  static const char hex[] = "0123456789ABCDEF";
  std::string safe;
  safe.reserve(value.size());

  auto appendByteEscape = [&safe](unsigned char byte) {
    safe += "\\x";
    safe += hex[byte >> 4];
    safe += hex[byte & 0x0F];
  };
  auto appendUnicodeEscape = [&safe](uint32_t codepoint) {
    static const char unicodeHex[] = "0123456789ABCDEF";
    safe += "\\u";
    for (int shift = 12; shift >= 0; shift -= 4)
      safe += unicodeHex[(codepoint >> shift) & 0x0F];
  };

  for (size_t i = 0; i < value.size();) {
    const unsigned char first = static_cast<unsigned char>(value[i]);
    if (first < 0x80) {
      if (first < 0x20 || first == 0x7F)
        appendByteEscape(first);
      else
        safe += static_cast<char>(first);
      ++i;
      continue;
    }
    if (!validUtf8) {
      appendByteEscape(first);
      ++i;
      continue;
    }

    size_t sequenceLength = 0;
    uint32_t codepoint = 0;
    if (first <= 0xDF) {
      sequenceLength = 2;
      codepoint = first & 0x1F;
    } else if (first <= 0xEF) {
      sequenceLength = 3;
      codepoint = first & 0x0F;
    } else {
      sequenceLength = 4;
      codepoint = first & 0x07;
    }
    for (size_t j = 1; j < sequenceLength; ++j) {
      codepoint = (codepoint << 6) |
                  (static_cast<unsigned char>(value[i + j]) & 0x3F);
    }

    const bool terminalControl =
        (codepoint >= 0x80 && codepoint <= 0x9F) ||
        (codepoint >= 0x200B && codepoint <= 0x200F) ||
        codepoint == 0x2028 || codepoint == 0x2029 ||
        (codepoint >= 0x202A && codepoint <= 0x202E) ||
        (codepoint >= 0x2060 && codepoint <= 0x206F) ||
        codepoint == 0x061C || codepoint == 0x180E ||
        codepoint == 0xFEFF || (codepoint >= 0xFFF9 && codepoint <= 0xFFFB);
    if (terminalControl)
      appendUnicodeEscape(codepoint);
    else
      safe.append(value, i, sequenceLength);
    i += sequenceLength;
  }
  return safe;
}

// Strict canonical Base64 validator
bool isBase64Strict(const std::string &input, std::string &decodedOut) {
  decodedOut.clear();
  if (input.length() % 4 != 0) return false;

  size_t padCount = 0;
  for (size_t i = 0; i < input.length(); i++) {
    char c = input[i];
    if (c == '=') {
      padCount++;
      if (i < input.length() - 2) return false; // '=' can only be in the last 2 positions
    } else if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                 (c >= '0' && c <= '9') || c == '+' || c == '/')) {
      return false;
    }
  }
  if (padCount > 2) return false;

  std::string decoded = base64_decode(input);

  // Verify that re-encoding matches the original input exactly
  std::string reencoded = base64_encode(reinterpret_cast<const unsigned char*>(decoded.data()),
                                        decoded.length());
  if (reencoded != input) return false;

  decodedOut = decoded;
  return true;
}

struct ScryptPhcTarget {
  unsigned int logN = 0;
  uint64_t r = 0;
  uint64_t p = 0;
  std::vector<uint8_t> salt;
  std::vector<uint8_t> checksum;
};

bool decodePhcBase64(const std::string &input, std::vector<uint8_t> &output) {
  static const std::string alphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  output.clear();
  if (input.empty() || input.size() % 4 == 1) return false;
  output.reserve((input.size() * 3) / 4);

  size_t i = 0;
  while (i + 4 <= input.size()) {
    const size_t a = alphabet.find(input[i]);
    const size_t b = alphabet.find(input[i + 1]);
    const size_t c = alphabet.find(input[i + 2]);
    const size_t d = alphabet.find(input[i + 3]);
    if (a == std::string::npos || b == std::string::npos ||
        c == std::string::npos || d == std::string::npos)
      return false;
    output.push_back(static_cast<uint8_t>((a << 2) | (b >> 4)));
    output.push_back(static_cast<uint8_t>((b << 4) | (c >> 2)));
    output.push_back(static_cast<uint8_t>((c << 6) | d));
    i += 4;
  }

  const size_t remaining = input.size() - i;
  if (remaining == 2) {
    const size_t a = alphabet.find(input[i]);
    const size_t b = alphabet.find(input[i + 1]);
    if (a == std::string::npos || b == std::string::npos || (b & 0x0F) != 0)
      return false;
    output.push_back(static_cast<uint8_t>((a << 2) | (b >> 4)));
  } else if (remaining == 3) {
    const size_t a = alphabet.find(input[i]);
    const size_t b = alphabet.find(input[i + 1]);
    const size_t c = alphabet.find(input[i + 2]);
    if (a == std::string::npos || b == std::string::npos ||
        c == std::string::npos || (c & 0x03) != 0)
      return false;
    output.push_back(static_cast<uint8_t>((a << 2) | (b >> 4)));
    output.push_back(static_cast<uint8_t>((b << 4) | (c >> 2)));
  }
  return true;
}

bool parseCanonicalUnsigned(const std::string &value, uint64_t &number) {
  if (value.empty() || (value.size() > 1 && value[0] == '0')) return false;
  uint64_t parsed = 0;
  for (unsigned char c : value) {
    if (c < '0' || c > '9') return false;
    const uint64_t digit = c - '0';
    if (parsed > (std::numeric_limits<uint64_t>::max() - digit) / 10)
      return false;
    parsed = parsed * 10 + digit;
  }
  number = parsed;
  return true;
}

bool parseScryptPhc(const std::string &target, ScryptPhcTarget &parsed) {
  parsed = ScryptPhcTarget{};
  if (target.size() > 1600) return false;
  std::vector<std::string> fields;
  size_t start = 0;
  while (start <= target.size()) {
    const size_t end = target.find('$', start);
    fields.push_back(end == std::string::npos
                         ? target.substr(start)
                         : target.substr(start, end - start));
    if (end == std::string::npos) break;
    start = end + 1;
  }
  if (fields.size() != 5 || !fields[0].empty() || fields[1] != "scrypt")
    return false;

  const std::string &params = fields[2];
  if (fields[3].size() > 1366 || fields[4].size() > 86) return false;
  const size_t comma1 = params.find(',');
  const size_t comma2 = comma1 == std::string::npos
                            ? std::string::npos
                            : params.find(',', comma1 + 1);
  if (comma1 == std::string::npos || comma2 == std::string::npos ||
      params.find(',', comma2 + 1) != std::string::npos ||
      params.compare(0, 3, "ln=") != 0 ||
      params.compare(comma1 + 1, 2, "r=") != 0 ||
      params.compare(comma2 + 1, 2, "p=") != 0)
    return false;

  uint64_t logN = 0;
  const std::string logNText = params.substr(3, comma1 - 3);
  const std::string rText = params.substr(comma1 + 3, comma2 - comma1 - 3);
  const std::string pText = params.substr(comma2 + 3);
  if (!parseCanonicalUnsigned(logNText, logN) || logN < 1 || logN > 63 ||
      !parseCanonicalUnsigned(rText, parsed.r) || parsed.r == 0 ||
      !parseCanonicalUnsigned(pText, parsed.p) || parsed.p == 0)
    return false;

  // RFC 7914 parameter constraints. Additional operational limits are applied
  // separately so valid, unusually expensive records can be reported clearly.
  if (parsed.r > std::numeric_limits<uint64_t>::max() / parsed.p ||
      parsed.r * parsed.p >= (uint64_t{1} << 30) ||
      (parsed.r <= 3 && logN >= 16 * parsed.r))
    return false;
  parsed.logN = static_cast<unsigned int>(logN);
  if (!decodePhcBase64(fields[3], parsed.salt) ||
      parsed.salt.empty() || parsed.salt.size() > 1024 ||
      !decodePhcBase64(fields[4], parsed.checksum) ||
      parsed.checksum.size() < 10 || parsed.checksum.size() > 64)
    return false;
  return true;
}

bool scryptWithinResourcePolicy(const ScryptPhcTarget &target) {
  // One verification is capped at 256 MiB and 2^26 N*r*p work units. The
  // scrypt brute-force worker is serialized to keep aggregate memory bounded.
  constexpr uint64_t maxMemoryBytes = 256ULL * 1024 * 1024;
  constexpr uint64_t maxWorkUnits = 1ULL << 26;
  const uint64_t n = uint64_t{1} << target.logN;
  if (target.r > std::numeric_limits<uint64_t>::max() / 128) return false;
  const uint64_t blockSize = 128 * target.r;
  if (n > maxMemoryBytes / blockSize) return false;
  const uint64_t romixMemory = n * blockSize;
  if (romixMemory > maxMemoryBytes - 2 * blockSize) return false;
  if (target.p > (maxMemoryBytes - romixMemory - 2 * blockSize) / blockSize)
    return false;
  if (target.r > maxWorkUnits / n) return false;
  const uint64_t nr = n * target.r;
  return target.p <= maxWorkUnits / nr;
}

uint32_t rotateLeft32(uint32_t value, unsigned int count) {
  return (value << count) | (value >> (32 - count));
}

void salsa208(uint32_t block[16]) {
  uint32_t x[16];
  std::memcpy(x, block, sizeof(x));
  for (int round = 0; round < 8; round += 2) {
    x[ 4] ^= rotateLeft32(x[ 0] + x[12], 7);
    x[ 8] ^= rotateLeft32(x[ 4] + x[ 0], 9);
    x[12] ^= rotateLeft32(x[ 8] + x[ 4], 13);
    x[ 0] ^= rotateLeft32(x[12] + x[ 8], 18);
    x[ 9] ^= rotateLeft32(x[ 5] + x[ 1], 7);
    x[13] ^= rotateLeft32(x[ 9] + x[ 5], 9);
    x[ 1] ^= rotateLeft32(x[13] + x[ 9], 13);
    x[ 5] ^= rotateLeft32(x[ 1] + x[13], 18);
    x[14] ^= rotateLeft32(x[10] + x[ 6], 7);
    x[ 2] ^= rotateLeft32(x[14] + x[10], 9);
    x[ 6] ^= rotateLeft32(x[ 2] + x[14], 13);
    x[10] ^= rotateLeft32(x[ 6] + x[ 2], 18);
    x[ 3] ^= rotateLeft32(x[15] + x[11], 7);
    x[ 7] ^= rotateLeft32(x[ 3] + x[15], 9);
    x[11] ^= rotateLeft32(x[ 7] + x[ 3], 13);
    x[15] ^= rotateLeft32(x[11] + x[ 7], 18);

    x[ 1] ^= rotateLeft32(x[ 0] + x[ 3], 7);
    x[ 2] ^= rotateLeft32(x[ 1] + x[ 0], 9);
    x[ 3] ^= rotateLeft32(x[ 2] + x[ 1], 13);
    x[ 0] ^= rotateLeft32(x[ 3] + x[ 2], 18);
    x[ 6] ^= rotateLeft32(x[ 5] + x[ 4], 7);
    x[ 7] ^= rotateLeft32(x[ 6] + x[ 5], 9);
    x[ 4] ^= rotateLeft32(x[ 7] + x[ 6], 13);
    x[ 5] ^= rotateLeft32(x[ 4] + x[ 7], 18);
    x[11] ^= rotateLeft32(x[10] + x[ 9], 7);
    x[ 8] ^= rotateLeft32(x[11] + x[10], 9);
    x[ 9] ^= rotateLeft32(x[ 8] + x[11], 13);
    x[10] ^= rotateLeft32(x[ 9] + x[ 8], 18);
    x[12] ^= rotateLeft32(x[15] + x[14], 7);
    x[13] ^= rotateLeft32(x[12] + x[15], 9);
    x[14] ^= rotateLeft32(x[13] + x[12], 13);
    x[15] ^= rotateLeft32(x[14] + x[13], 18);
  }
  for (size_t i = 0; i < 16; ++i) block[i] += x[i];
}

uint32_t loadLittle32(const uint8_t *input) {
  return static_cast<uint32_t>(input[0]) |
         (static_cast<uint32_t>(input[1]) << 8) |
         (static_cast<uint32_t>(input[2]) << 16) |
         (static_cast<uint32_t>(input[3]) << 24);
}

void storeLittle32(uint8_t *output, uint32_t value) {
  output[0] = static_cast<uint8_t>(value);
  output[1] = static_cast<uint8_t>(value >> 8);
  output[2] = static_cast<uint8_t>(value >> 16);
  output[3] = static_cast<uint8_t>(value >> 24);
}

void blockMixScrypt(std::vector<uint8_t> &block, uint64_t r,
                    std::vector<uint8_t> &scratch) {
  const size_t blockCount = static_cast<size_t>(2 * r);
  uint8_t x[64];
  uint32_t state[16];
  std::memcpy(x, block.data() + (blockCount - 1) * 64, sizeof(x));
  for (size_t i = 0; i < blockCount; ++i) {
    const uint8_t *input = block.data() + i * 64;
    for (size_t j = 0; j < sizeof(x); ++j) x[j] ^= input[j];
    for (size_t j = 0; j < 16; ++j) state[j] = loadLittle32(x + j * 4);
    salsa208(state);
    for (size_t j = 0; j < 16; ++j) storeLittle32(x + j * 4, state[j]);
    std::memcpy(scratch.data() + i * 64, x, sizeof(x));
  }
  for (size_t i = 0; i < blockCount; ++i) {
    const size_t yIndex = (i % 2 == 0) ? i / 2 : (blockCount / 2 + i / 2);
    std::memcpy(block.data() + i * 64, scratch.data() + yIndex * 64, 64);
  }
  std::fill(std::begin(state), std::end(state), 0);
  std::fill(std::begin(x), std::end(x), 0);
}

void pbkdf2Sha256OneIteration(const std::string &password,
                              const uint8_t *salt, size_t saltLength,
                              uint8_t *output, size_t outputLength) {
  const hmac_internal::Sha256HmacState hmacState(
      reinterpret_cast<const uint8_t *>(password.data()), password.size());
  const size_t blocks = (outputLength + 31) / 32;
  std::vector<uint8_t> message(saltLength + 4);
  if (saltLength != 0) std::memcpy(message.data(), salt, saltLength);
  for (size_t block = 1; block <= blocks; ++block) {
    const uint32_t index = static_cast<uint32_t>(block);
    message[saltLength] = static_cast<uint8_t>(index >> 24);
    message[saltLength + 1] = static_cast<uint8_t>(index >> 16);
    message[saltLength + 2] = static_cast<uint8_t>(index >> 8);
    message[saltLength + 3] = static_cast<uint8_t>(index);
    uint8_t digest[32];
    hmacState.hash(message.data(), message.size(), digest);
    const size_t offset = (block - 1) * 32;
    const size_t take = std::min<size_t>(32, outputLength - offset);
    std::memcpy(output + offset, digest, take);
    std::fill(std::begin(digest), std::end(digest), 0);
  }
  std::fill(message.begin(), message.end(), 0);
}

void secureClear(std::vector<uint8_t> &buffer) {
  volatile uint8_t *data = buffer.empty() ? nullptr : buffer.data();
  for (size_t i = 0; i < buffer.size(); ++i) data[i] = 0;
}

struct ScryptBufferWiper {
  std::vector<uint8_t> &initial;
  std::vector<uint8_t> &scratch;
  std::vector<uint8_t> &memory;
  std::vector<uint8_t> &block;
  ~ScryptBufferWiper() {
    secureClear(initial);
    secureClear(scratch);
    secureClear(memory);
    secureClear(block);
  }
};

bool deriveScrypt(const std::string &password, const ScryptPhcTarget &target,
                  std::vector<uint8_t> &derived) {
  if (!scryptWithinResourcePolicy(target)) return false;
  const uint64_t n = uint64_t{1} << target.logN;
  const size_t blockSize = static_cast<size_t>(128 * target.r);
  const size_t parallelBlocks = static_cast<size_t>(target.p);
  const size_t initialLength = blockSize * parallelBlocks;
  std::vector<uint8_t> initial(initialLength);
  std::vector<uint8_t> scratch(blockSize);
  std::vector<uint8_t> memory(static_cast<size_t>(n) * blockSize);
  std::vector<uint8_t> block(blockSize);
  derived.resize(target.checksum.size());
  const ScryptBufferWiper wipe{initial, scratch, memory, block};

  pbkdf2Sha256OneIteration(password, target.salt.data(), target.salt.size(),
                           initial.data(), initial.size());
  for (uint64_t lane = 0; lane < target.p; ++lane) {
    const size_t laneOffset = static_cast<size_t>(lane) * blockSize;
    std::memcpy(block.data(), initial.data() + laneOffset, blockSize);
    for (uint64_t i = 0; i < n; ++i) {
      std::memcpy(memory.data() + static_cast<size_t>(i) * blockSize,
                  block.data(), blockSize);
      blockMixScrypt(block, target.r, scratch);
    }
    for (uint64_t i = 0; i < n; ++i) {
      const size_t integerifyOffset = blockSize - 64;
      uint64_t integerify = 0;
      for (size_t j = 0; j < 8; ++j)
        integerify |= static_cast<uint64_t>(block[integerifyOffset + j])
                      << (8 * j);
      const uint64_t selected = integerify & (n - 1);
      const uint8_t *selectedBlock =
          memory.data() + static_cast<size_t>(selected) * blockSize;
      for (size_t j = 0; j < blockSize; ++j) block[j] ^= selectedBlock[j];
      blockMixScrypt(block, target.r, scratch);
    }
    std::memcpy(initial.data() + laneOffset, block.data(), blockSize);
  }
  pbkdf2Sha256OneIteration(password, initial.data(), initial.size(),
                           derived.data(), derived.size());
  return true;
}

bool constantTimeBytesEqual(const std::vector<uint8_t> &left,
                            const std::vector<uint8_t> &right) {
  if (left.size() != right.size()) return false;
  uint8_t difference = 0;
  for (size_t i = 0; i < left.size(); ++i)
    difference |= static_cast<uint8_t>(left[i] ^ right[i]);
  return difference == 0;
}

bool isLikelyBase64Text(const std::string &input,
                        const std::string &decoded) {
  if (input.find_first_of("+/=") != std::string::npos) return true;
  for (unsigned char c : decoded) {
    if (c < 0x20 && c != '\r' && c != '\n' && c != '\t') {
      return false;
    }
  }
  return isValidUtf8(decoded);
}

HashType identifyHash(const std::string &input) {
  // 1. Prefixed / Modular Crypt Formats (Forensic Standards)
  if (input.rfind("$scrypt$", 0) == 0) {
    return HashType::SCRYPT;
  }
  if (input.rfind("$2a$", 0) == 0 || input.rfind("$2b$", 0) == 0 || input.rfind("$2y$", 0) == 0) {
    return HashType::BCRYPT;
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
  if (isBase64Strict(input, decodedOut) &&
      isLikelyBase64Text(input, decodedOut)) {
    return HashType::BASE64;
  }

  return HashType::UNKNOWN;
}

HashType parseHashTypeLabel(std::string label) {
  lowercaseAscii(label);
  if (label == "crc32") return HashType::CRC32;
  if (label == "md5") return HashType::MD5;
  if (label == "sha1" || label == "sha-1") return HashType::SHA1;
  if (label == "sha224" || label == "sha-224") return HashType::SHA224;
  if (label == "sha256" || label == "sha-256") return HashType::SHA256;
  if (label == "sha384" || label == "sha-384") return HashType::SHA384;
  if (label == "sha512" || label == "sha-512") return HashType::SHA512;
  if (label == "ntlm") return HashType::NTLM;
  if (label == "md4") return HashType::MD4;
  if (label == "base64") return HashType::BASE64;
  if (label == "hmac-md5" || label == "hmac_md5") return HashType::HMAC_MD5;
  if (label == "hmac-sha1" || label == "hmac_sha1") return HashType::HMAC_SHA1;
  if (label == "hmac-sha256" || label == "hmac_sha256") return HashType::HMAC_SHA256;
  if (label == "salted-md5" || label == "md5-salt") return HashType::SALTED_MD5;
  if (label == "salted-sha1" || label == "sha1-salt") return HashType::SALTED_SHA1;
  if (label == "salted-sha256" || label == "sha256-salt") return HashType::SALTED_SHA256;
  if (label == "salted-sha512" || label == "sha512-salt") return HashType::SALTED_SHA512;
  if (label == "wpa2" || label == "pbkdf2") return HashType::WPA2_PBKDF2;
  if (label == "wpa3" || label == "sae") return HashType::WPA3_SAE;
  if (label == "bcrypt") return HashType::BCRYPT;
  if (label == "scrypt") return HashType::SCRYPT;
  return HashType::UNKNOWN;
}

HashType saltedTypeForDigestLength(size_t digestLength) {
  switch (digestLength) {
  case 32: return HashType::SALTED_MD5;
  case 40: return HashType::SALTED_SHA1;
  case 64: return HashType::SALTED_SHA256;
  case 128: return HashType::SALTED_SHA512;
  default: return HashType::UNKNOWN;
  }
}

bool isRecognizedDigestLength(size_t digestLength) {
  return digestLength == 32 || digestLength == 40 || digestLength == 56 ||
         digestLength == 64 || digestLength == 96 || digestLength == 128;
}

bool isValidHashTarget(const std::string &target, HashType type) {
  if (type == HashType::BCRYPT) return true; // Validated separately with bcryptCost.
  if (type == HashType::SCRYPT) {
    ScryptPhcTarget parsed;
    return parseScryptPhc(target, parsed);
  }
  if (type == HashType::BASE64) {
    if (target.empty()) return false;
    std::string decoded;
    return isBase64Strict(target, decoded);
  }

  size_t expectedLength = 0;
  switch (type) {
  case HashType::CRC32: expectedLength = 8; break;
  case HashType::MD5:
  case HashType::NTLM:
  case HashType::MD4:
  case HashType::HMAC_MD5:
  case HashType::SALTED_MD5: expectedLength = 32; break;
  case HashType::SHA1:
  case HashType::HMAC_SHA1:
  case HashType::SALTED_SHA1: expectedLength = 40; break;
  case HashType::SHA224: expectedLength = 56; break;
  case HashType::SHA256:
  case HashType::HMAC_SHA256:
  case HashType::SALTED_SHA256:
  case HashType::WPA2_PBKDF2: expectedLength = 64; break;
  case HashType::SHA384: expectedLength = 96; break;
  case HashType::SHA512:
  case HashType::SALTED_SHA512: expectedLength = 128; break;
  default: return false;
  }
  return target.size() == expectedLength && isHex(target);
}

int bcryptCost(const std::string &hash) {
  if (hash.size() != 60 || hash[0] != '$' || hash[1] != '2' ||
      (hash[2] != 'a' && hash[2] != 'b' && hash[2] != 'y') ||
      hash[3] != '$' || hash[6] != '$')
    return -1;
  if (!std::isdigit(static_cast<unsigned char>(hash[4])) ||
      !std::isdigit(static_cast<unsigned char>(hash[5])))
    return -1;
  const int cost = (hash[4] - '0') * 10 + hash[5] - '0';
  if (cost < 4 || cost > 31) return -1;
  static const std::string bcryptAlphabet =
      "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (size_t i = 7; i < hash.size(); ++i) {
    if (bcryptAlphabet.find(hash[i]) == std::string::npos) return -1;
  }
  // bcrypt encodes 16 salt bytes in 22 chars and 23 checksum bytes in 31
  // chars; the unused low bits in each final symbol must be zero.
  if (bcryptAlphabet.find(hash[28]) % 16 != 0 ||
      bcryptAlphabet.find(hash[59]) % 4 != 0)
    return -1;
  return cost;
}

void updateSha256InChunks(picosha2::hash256_one_by_one &hasher,
                          const std::string &part) {
  const size_t chunkLimit = 1024 * 1024;
  for (size_t offset = 0; offset < part.size();) {
    size_t chunk = part.size() - offset;
    if (chunk > chunkLimit) chunk = chunkLimit;
    hasher.process(part.data() + offset, part.data() + offset + chunk);
    offset += chunk;
  }
}

std::string sha256(const std::string &input) {
  picosha2::hash256_one_by_one hasher;
  updateSha256InChunks(hasher, input);
  hasher.finish();
  return picosha2::get_hash_hex_string(hasher);
}

std::string sha256(const std::string &input, const std::string &suffix) {
  picosha2::hash256_one_by_one hasher;
  updateSha256InChunks(hasher, input);
  updateSha256InChunks(hasher, suffix);
  hasher.finish();
  return picosha2::get_hash_hex_string(hasher);
}

std::string bcryptCandidateHash(const std::string &password,
                                const std::string &targetHash) {
  // The vendored crypt_blowfish API uses NUL-terminated C strings; accepting
  // embedded NUL would silently verify only a prefix of the candidate.
  if (password.find('\0') != std::string::npos ||
      targetHash.find('\0') != std::string::npos)
    return {};
  char output[128] = {0};
  char *result = _crypt_blowfish_rn(password.c_str(), targetHash.c_str(),
                                    output, static_cast<int>(sizeof(output)));
  return result ? std::string(result) : std::string();
}

// WPA2 PMK derivation: PBKDF2-HMAC-SHA1(passphrase, SSID, 4096, 32 bytes).
std::string deriveWpa2Pmk(const std::string &pass, const std::string &salt) {
  if (pass.length() == 64 && isHex(pass)) {
    std::string rawPsk = pass;
    for (char &c : rawPsk) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return rawPsk;
  }
  if (pass.length() < 8 || pass.length() > 63 || salt.empty() || salt.length() > 32)
    return "";
  return pbkdf2_hmac_sha1(pass, salt, 4096, 32);
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
    return sha256(pass);
  case HashType::SHA384:
    return sha384(pass);
  case HashType::SHA512:
    return sha512(pass);
  case HashType::NTLM:
    return ntlm(pass);
  case HashType::MD4:
    return md4(pass);
  case HashType::HMAC_MD5:
    return hmac_md5(salt, pass);
  case HashType::HMAC_SHA1:
    return hmac_sha1(salt, pass);
  case HashType::HMAC_SHA256:
    return hmac_sha256(salt, pass);
  case HashType::BASE64:
    return base64_encode(reinterpret_cast<const unsigned char *>(pass.data()),
                         pass.length());

  // Salted Variations
  case HashType::SALTED_MD5:
    return md5(pass, salt);
  case HashType::SALTED_SHA1:
    return sha1(pass, salt);
  case HashType::SALTED_SHA256:
    return sha256(pass, salt);
  case HashType::SALTED_SHA512:
    return sha512(pass, salt);

  case HashType::WPA2_PBKDF2:
    return deriveWpa2Pmk(pass, salt);

  // WPA3 capture and social account exports are not password-hash formats.
  case HashType::WPA3_SAE:
  case HashType::BCRYPT:
    return "";
  case HashType::SCRYPT:
    return ""; // Verified from the full PHC string in verifyCandidate().

  case HashType::TEXT:
    return pass;

  default:
    return "";
  }
}

bool verifyCandidate(const std::string &candidate, HashType type,
                     const std::string &target,
                     const std::string &salt = "") {
  if (target.empty() || type == HashType::UNKNOWN) return false;
  if (type == HashType::BCRYPT)
    return bcryptCandidateHash(candidate, target) == target;
  if (type == HashType::SCRYPT) {
    ScryptPhcTarget parsed;
    if (!parseScryptPhc(target, parsed) || !scryptWithinResourcePolicy(parsed))
      return false;
    std::vector<uint8_t> derived;
    try {
      if (!deriveScrypt(candidate, parsed, derived)) return false;
      const bool matches = constantTimeBytesEqual(derived, parsed.checksum);
      secureClear(derived);
      return matches;
    } catch (const std::bad_alloc &) {
      secureClear(derived);
      return false;
    } catch (const std::length_error &) {
      secureClear(derived);
      return false;
    }
  }
  return hashFunctionExtended(candidate, type, salt) == target;
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
    return "WPA2 PMK (PBKDF2-HMAC-SHA1)";
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
         "ACTIVE \x1b[1;30m| \x1b[1;34mMOTOR: "
      << terminalSafeText(getEngineName()) << "\x1b[0m\n";
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

std::string jsonEscape(const std::string &value) {
  const bool validUtf8 = isValidUtf8(value);
  std::string out;
  out.reserve(value.size() + 8);
  for (unsigned char c : value) {
    switch (c) {
    case '"': out += "\\\""; break;
    case '\\': out += "\\\\"; break;
    case '\b': out += "\\b"; break;
    case '\f': out += "\\f"; break;
    case '\n': out += "\\n"; break;
    case '\r': out += "\\r"; break;
    case '\t': out += "\\t"; break;
    default:
      if (c < 0x20 || (!validUtf8 && c >= 0x80)) {
        static const char hex[] = "0123456789abcdef";
        out += "\\u00";
        out += hex[c >> 4];
        out += hex[c & 0x0f];
      } else {
        out += static_cast<char>(c);
      }
    }
  }
  return out;
}

void writeJsonTextOrBase64(std::ostream &out, const std::string &field,
                           const std::string &value) {
  if (isValidUtf8(value)) {
    out << "\"" << field << "\": \"" << jsonEscape(value) << "\"";
  } else {
    out << "\"" << field << "\": null, \"" << field
        << "_base64\": \""
        << base64_encode(reinterpret_cast<const unsigned char *>(value.data()),
                         value.size())
        << "\"";
  }
}

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
    std::snprintf(buf, sizeof(buf), "%lldms (%.3fs)", ms, ms / 1000.0);
    return buf;
  }
  if (ms < 60000) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.2fs", ms / 1000.0);
    return buf;
  }
  long long totalSec = ms / 1000;
  long long mins = totalSec / 60;
  long long secs = totalSec % 60;
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%lldm %02llds", mins, secs);
  return buf;
}

// Format hashrates with dynamic units (H/s, kH/s, MH/s, GH/s)
std::string formatHashrate(double hps) {
  char buf[32];
  if (hps >= 1e9) {
    std::snprintf(buf, sizeof(buf), "%.2f GH/s", hps / 1e9);
  } else if (hps >= 1e6) {
    std::snprintf(buf, sizeof(buf), "%.2f MH/s", hps / 1e6);
  } else if (hps >= 1e3) {
    std::snprintf(buf, sizeof(buf), "%.2f kH/s", hps / 1e3);
  } else {
    std::snprintf(buf, sizeof(buf), "%lld H/s", (long long)hps);
  }
  return buf;
}

long long hashRateForJson(long long attempts, long long ms) {
  if (attempts <= 0 || ms <= 0) return 0;
  const long double rate =
      static_cast<long double>(attempts) * 1000.0L / ms;
  const long double limit = static_cast<long double>(
      std::numeric_limits<long long>::max());
  return rate >= limit ? std::numeric_limits<long long>::max()
                       : static_cast<long long>(rate);
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
  std::snprintf(pctBuf, sizeof(pctBuf), " %5.1f%%", pct);
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
  std::string displayVal = terminalSafeText(val);
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
std::string encodePotfileField(const std::string &value) {
  std::string encoded;
  static const char hex[] = "0123456789ABCDEF";
  for (unsigned char c : value) {
    if (c == '%' || c == '|' || c <= 0x20 || c >= 0x7f) {
      encoded += '%';
      encoded += hex[c >> 4];
      encoded += hex[c & 0x0f];
    } else {
      encoded += static_cast<char>(c);
    }
  }
  return encoded;
}

std::string encodeQuietField(const std::string &value) {
  std::string encoded;
  static const char hex[] = "0123456789ABCDEF";
  for (unsigned char c : value) {
    if (c == ':' || c == '%' || c <= 0x20 || c >= 0x7f) {
      encoded += '%';
      encoded += hex[c >> 4];
      encoded += hex[c & 0x0f];
    } else {
      encoded += static_cast<char>(c);
    }
  }
  return encoded;
}

int potfileHexValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

bool isValidEncodedPotfileField(const std::string &line, size_t begin,
                                size_t end) {
  for (size_t i = begin; i < end;) {
    const unsigned char c = static_cast<unsigned char>(line[i]);
    if (c == '%') {
      if (i + 2 >= end || potfileHexValue(line[i + 1]) < 0 ||
          potfileHexValue(line[i + 2]) < 0)
        return false;
      i += 3;
      continue;
    }
    // Versioned records encode whitespace, controls, and non-ASCII bytes.
    if (c <= 0x20 || c >= 0x7f) return false;
    ++i;
  }
  return true;
}

bool hasValidVersionedPotfileEncoding(const std::string &line) {
  size_t begin =
      line.size() >= 3 && static_cast<unsigned char>(line[0]) == 0xEF &&
              static_cast<unsigned char>(line[1]) == 0xBB &&
              static_cast<unsigned char>(line[2]) == 0xBF
          ? 3
          : 0;
  size_t end = line.size();
  if (end > begin && line[end - 1] == '\r') --end;

  std::vector<std::pair<size_t, size_t>> fields;
  size_t fieldStart = begin;
  for (size_t i = begin; i <= end; ++i) {
    if (i == end || line[i] == '|') {
      fields.emplace_back(fieldStart, i);
      fieldStart = i + 1;
    }
  }
  if (fields.size() != 5) return false;
  const size_t versionLength = fields[0].second - fields[0].first;
  if (versionLength != 2 ||
      (line.compare(fields[0].first, versionLength, "v2") != 0 &&
       line.compare(fields[0].first, versionLength, "v3") != 0))
    return false;
  for (size_t i = 1; i < fields.size(); ++i) {
    if (!isValidEncodedPotfileField(line, fields[i].first, fields[i].second))
      return false;
  }
  return true;
}

std::string decodePotfileField(const std::string &value) {
  std::string decoded;
  for (size_t i = 0; i < value.size(); ++i) {
    if (value[i] == '%' && i + 2 < value.size()) {
      int hi = potfileHexValue(value[i + 1]);
      int lo = potfileHexValue(value[i + 2]);
      if (hi >= 0 && lo >= 0) {
        decoded += static_cast<char>((hi << 4) | lo);
        i += 2;
      } else {
        decoded += value[i];
      }
    } else {
      decoded += value[i];
    }
  }
  return decoded;
}

std::vector<std::string> parsePotfileLine(const std::string &line) {
  std::vector<std::string> parts;
  const size_t startOfLine =
      line.size() >= 3 && static_cast<unsigned char>(line[0]) == 0xEF &&
              static_cast<unsigned char>(line[1]) == 0xBB &&
              static_cast<unsigned char>(line[2]) == 0xBF
          ? 3
          : 0;
  size_t start = startOfLine;
  while (start <= line.size()) {
    const size_t delimiter = line.find('|', start);
    std::string item = delimiter == std::string::npos
                           ? line.substr(start)
                           : line.substr(start, delimiter - start);
    item.erase(0, item.find_first_not_of(" \t\r\n"));
    item.erase(item.find_last_not_of(" \t\r\n") + 1);
    parts.push_back(item);
    if (delimiter == std::string::npos) break;
    start = delimiter + 1;
  }
  if (parts.size() == 5 && parts[0] == "v2") {
    if (!hasValidVersionedPotfileEncoding(line)) return {};
    return {decodePotfileField(parts[1]), decodePotfileField(parts[2]),
            decodePotfileField(parts[3]), decodePotfileField(parts[4]), "v2"};
  }
  if (parts.size() == 5 && parts[0] == "v3") {
    if (!hasValidVersionedPotfileEncoding(line)) return {};
    return {decodePotfileField(parts[1]), decodePotfileField(parts[2]),
            decodePotfileField(parts[3]), decodePotfileField(parts[4]), "v3"};
  }
  return parts;
}

HashType potfileTypeFromName(const std::string &name) {
  static const HashType supportedTypes[] = {
      HashType::CRC32,       HashType::MD5,        HashType::SHA1,
      HashType::SHA224,      HashType::SHA256,     HashType::SHA384,
      HashType::SHA512,      HashType::BASE64,     HashType::NTLM,
      HashType::MD4,         HashType::HMAC_MD5,   HashType::HMAC_SHA1,
      HashType::HMAC_SHA256, HashType::SALTED_MD5, HashType::SALTED_SHA1,
      HashType::SALTED_SHA256, HashType::SALTED_SHA512,
      HashType::WPA2_PBKDF2, HashType::BCRYPT, HashType::SCRYPT};
  for (HashType type : supportedTypes) {
    if (hashTypeName(type) == name) return type;
  }
  return HashType::UNKNOWN;
}

bool isStructurallyValidPotfileTarget(const std::string &target,
                                      HashType type) {
  if (type == HashType::UNKNOWN || !isValidHashTarget(target, type))
    return false;
  return type != HashType::BCRYPT || bcryptCost(target) >= 0;
}

HashType inferLegacyPotfileType(const std::string &target) {
  HashType type = identifyHash(target);
  if (type == HashType::UNKNOWN) {
    std::string decoded;
    if (isBase64Strict(target, decoded)) type = HashType::BASE64;
  }
  return type;
}

bool checkPotfile(const std::string &targetHash, const std::string &salt,
                  HashType expectedType,
                  std::string &recoveredPass, HashType &recoveredType,
                  const std::string &potfilePath = "cracked_passwords.txt",
                  bool allowAnySalt = false,
                  std::string *matchedSalt = nullptr) {
  std::ifstream pot(pathFromUtf8(potfilePath), std::ios::binary);
  if (!pot.is_open()) return false;

  std::string lowerTarget = targetHash;
  if (isHex(lowerTarget))
    for (char &c : lowerTarget) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

  std::string line;
  while (readLineWithUniversalNewlines(pot, line)) {
    if (line.empty()) continue;
    std::vector<std::string> parts = parsePotfileLine(line);
    if (parts.size() >= 4) {
      std::string savedHash = parts[0];
      if (isHex(savedHash))
        for (char &c : savedHash) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      std::string savedSalt = parts[1];
      std::string savedAlgo = parts[2];
      std::string savedPass = parts[3];
      const bool exactSaltRecord =
          parts.size() >= 5 && (parts[4] == "v2" || parts[4] == "v3");

      const HashType savedType = expectedType == HashType::UNKNOWN
                                     ? potfileTypeFromName(savedAlgo)
                                     : expectedType;
      const bool typeMatches = savedType != HashType::UNKNOWN &&
                               savedAlgo == hashTypeName(savedType);
      const bool legacyEmptySalt = !exactSaltRecord && savedSalt == "-";
      const std::string effectiveSalt = legacyEmptySalt ? "" : savedSalt;
      const bool saltMatches = effectiveSalt == salt || allowAnySalt;

      if (savedHash == lowerTarget && typeMatches && saltMatches &&
          verifyCandidate(savedPass, savedType, targetHash, effectiveSalt)) {
        recoveredPass = savedPass;
        recoveredType = savedType;
        if (matchedSalt) *matchedSalt = effectiveSalt;
        return true;
      }
    } else if (parts.size() == 3) {
      std::string savedHash = parts[0];
      if (isHex(savedHash))
        for (char &c : savedHash) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      std::string savedSalt = parts[1];
      std::string savedPass = parts[2];

      HashType legacyType = identifyHash(targetHash);
      const std::string legacySalt = savedSalt == "-" ? "" : savedSalt;
      const HashType verifyType = expectedType == HashType::UNKNOWN
          ? legacyType : expectedType;
      const bool saltMatches =
          ((salt.empty() && savedSalt == "-") || legacySalt == salt ||
           allowAnySalt);
      if (savedHash == lowerTarget && verifyType != HashType::UNKNOWN &&
          saltMatches &&
          verifyCandidate(savedPass, verifyType, targetHash, legacySalt)) {
        recoveredPass = savedPass;
        recoveredType = verifyType;
        if (matchedSalt) *matchedSalt = legacySalt;
        return true;
      }
    }
  }
  if (streamHasReadError(pot)) {
    std::cerr << "[!] Erro durante a leitura do potfile '"
              << terminalSafeText(potfilePath)
              << "'; a consulta de cache pode estar incompleta.\n";
  }
  return false;
}

// Safe potfile recorder (strictly avoids duplicate writes)
bool saveCrackedPassword(const std::string &target, const std::string &salt,
                         HashType type, const std::string &password) {
  std::string dummyPass;
  HashType dummyType;
  if (checkPotfile(target, salt, type, dummyPass, dummyType)) {
    return true; // Already recorded in potfile
  }
  const std::string savePath = "cracked_passwords.txt";
  std::ofstream log(pathFromUtf8(savePath), std::ios::app | std::ios::binary);
  if (!log.is_open()) {
    std::cerr << "[!] Senha recuperada, mas nao foi possivel abrir o potfile '"
              << savePath << "' para gravacao.\n";
    return false;
  }
  // The leading newline separates this record even if an older or manually
  // edited potfile does not end with one. Empty lines are ignored by readers.
  log << "\n"
      << "v3|" << encodePotfileField(target) << "|"
      << encodePotfileField(salt) << "|"
      << encodePotfileField(hashTypeName(type)) << "|"
      << encodePotfileField(password) << "\n";
  log.flush();
  bool writeSucceeded = log.good();
  log.close();
  writeSucceeded = writeSucceeded && !log.fail();
  if (!writeSucceeded) {
    std::cerr << "[!] Senha recuperada, mas houve falha ao gravar no potfile '"
              << savePath << "'.\n";
    return false;
  }
  if (!globalQuiet && !globalJson)
    std::cout << "\x1b[1;32m  [+] Sincronizado em: " << savePath << "\x1b[0m\n\n";
  return true;
}

// Forensic Potfile & History Viewer
int displayPotfileHistory(const std::string &potfilePath = "cracked_passwords.txt") {
  std::ifstream pot;
  try {
    pot.open(pathFromUtf8(potfilePath), std::ios::binary);
  } catch (const std::filesystem::filesystem_error &) {
    // Treat an invalid UTF-8 path the same as an unavailable history file.
  }
  if (!pot.is_open()) {
    if (globalJson)
      std::cout << "{\"status\":\"not_found\",\"potfile\":\""
                << jsonEscape(potfilePath) << "\",\"total\":0,\"entries\":[]}\n";
    else if (globalQuiet)
      std::cerr << "[!] Potfile nao encontrado: "
                << terminalSafeText(potfilePath) << "\n";
    else
      std::cout << "\n\x1b[1;33m[!] Nenhum historico de credenciais encontrado ("
                << terminalSafeText(potfilePath) << ").\x1b[0m\n";
    return 2;
  }
  std::vector<std::vector<std::string>> entries;
  bool malformedRecord = false;
  std::string line;
  while (readLineWithUniversalNewlines(pot, line)) {
    const size_t contentStart =
        line.size() >= 3 && static_cast<unsigned char>(line[0]) == 0xEF &&
                static_cast<unsigned char>(line[1]) == 0xBB &&
                static_cast<unsigned char>(line[2]) == 0xBF
            ? 3
            : 0;
    if (line.find_first_not_of(" \t\r\n", contentStart) == std::string::npos)
      continue;
    std::vector<std::string> parts = parsePotfileLine(line);
    const size_t recordStart =
        line.size() >= 3 && static_cast<unsigned char>(line[0]) == 0xEF &&
                static_cast<unsigned char>(line[1]) == 0xBB &&
                static_cast<unsigned char>(line[2]) == 0xBF
            ? 3
            : 0;
    const bool versionedPrefix =
        line.compare(recordStart, 3, "v2|") == 0 ||
        line.compare(recordStart, 3, "v3|") == 0;
    const HashType inferredLegacyType =
        parts.size() == 3 ? inferLegacyPotfileType(parts[0])
                          : HashType::UNKNOWN;
    const HashType legacyType =
        parts.size() == 4 ? potfileTypeFromName(parts[2])
                          : HashType::UNKNOWN;
    const HashType versionedType =
        parts.size() == 5 ? potfileTypeFromName(parts[2])
                          : HashType::UNKNOWN;
    const bool legacyThreeField =
        !versionedPrefix && parts.size() == 3 &&
        isStructurallyValidPotfileTarget(parts[0], inferredLegacyType);
    const bool legacyFourField =
        !versionedPrefix && parts.size() == 4 &&
        isStructurallyValidPotfileTarget(parts[0], legacyType);
    const bool versionedRecord =
        versionedPrefix && parts.size() == 5 &&
        (parts[4] == "v2" || parts[4] == "v3") &&
        isStructurallyValidPotfileTarget(parts[0], versionedType);
    if (legacyThreeField || legacyFourField || versionedRecord) {
      entries.push_back(parts);
    } else {
      malformedRecord = true;
    }
  }
  const bool historyReadError = streamHasReadError(pot);
  const bool historyIncomplete = historyReadError || malformedRecord;
  if (historyIncomplete) {
    std::cerr << "[!] Potfile '"
              << terminalSafeText(potfilePath)
              << "' contem registros invalidos ou houve interrupcao da leitura; o historico pode estar incompleto.\n";
  }

  if (globalJson) {
    std::cout << "{\n  \"status\": \""
              << (historyIncomplete ? "partial" : "ok")
              << "\",\n  \"read_error\": "
              << (historyReadError ? "true" : "false")
              << ",\n  \"invalid_records\": "
              << (malformedRecord ? "true" : "false")
              << ",\n  \"potfile\": \""
              << jsonEscape(potfilePath) << "\",\n  \"total\": "
              << entries.size() << ",\n  \"entries\": [\n";
    for (size_t i = 0; i < entries.size(); i++) {
      const auto &p = entries[i];
      std::string h = p[0];
      std::string s = (p.size() >= 4) ? p[1] : "-";
      std::string a = (p.size() >= 4) ? p[2] : "Unknown (legacy record)";
      std::string pass = (p.size() >= 4) ? p[3] : p[2];
      std::cout << "    {\"target\": \"" << jsonEscape(h) << "\", ";
      writeJsonTextOrBase64(std::cout, "salt", s);
      std::cout << ", \"algo\": \"" << jsonEscape(a) << "\", ";
      writeJsonTextOrBase64(std::cout, "plaintext", pass);
      std::cout << "}"
                << (i + 1 < entries.size() ? ",\n" : "\n");
    }
    std::cout << "  ]\n}\n";
    return historyIncomplete ? 1 : 0;
  }

  if (globalQuiet) {
    for (const auto &p : entries) {
      const std::string target = p[0];
      const std::string password = (p.size() >= 4) ? p[3] : p[2];
      std::cout << encodeQuietField(target) << ":"
                << encodeQuietField(password) << "\n";
    }
    return historyIncomplete ? 1 : 0;
  }

  if (entries.empty()) {
    std::cout << "\n\x1b[1;33m[!] Historico vazio em '"
              << terminalSafeText(potfilePath) << "'.\x1b[0m\n";
    return historyIncomplete ? 1 : 0;
  }

  std::cout << "\n\x1b[1;36m";
  std::cout << "================================================================================\n";
  std::cout << "                 CERBERUS POTFILE // HISTORICO DE CREDENCIAIS                   \n";
  std::cout << "================================================================================\x1b[0m\n";
  std::cout << " Total de Registros : \x1b[1;32m" << entries.size() << "\x1b[0m\n";
  std::cout << " Arquivo de Origem  : " << terminalSafeText(potfilePath) << "\n";
  std::cout << "================================================================================\n";
  std::cout << " ID  | HASH ALVO (Truncado)            | SALT     | ALGORITMO   | SENHA\n";
  std::cout << "-----+---------------------------------+----------+-------------+----------------\n";

  for (size_t i = 0; i < entries.size(); i++) {
    const auto &p = entries[i];
    std::string h = terminalSafeText(p[0]);
    if (h.length() > 31) {
      h = h.substr(0, 14) + "..." + h.substr(h.length() - 14);
    }
    while (h.length() < 31) h += " ";

    std::string s = terminalSafeText((p.size() >= 4) ? p[1] : "-");
    if (s.length() > 8) s = s.substr(0, 7) + ".";
    while (s.length() < 8) s += " ";

    std::string a = terminalSafeText((p.size() >= 4) ? p[2] : "Unknown (legacy)");
    if (a.length() > 11) a = a.substr(0, 11);
    while (a.length() < 11) a += " ";

    std::string pass = terminalSafeText((p.size() >= 4) ? p[3] : p[2]);
    if (pass.length() > 16) pass = pass.substr(0, 13) + "...";

    char idBuf[8];
    std::snprintf(idBuf, sizeof(idBuf), "%02zu", i + 1);

    std::cout << " " << idBuf << "  | " << h << " | "
              << "\x1b[1;37m" << s << "\x1b[0m | "
              << "\x1b[1;36m" << a << "\x1b[0m | "
              << "\x1b[1;93m" << pass << "\x1b[0m\n";
  }
  std::cout << "================================================================================\n\n";
  return historyIncomplete ? 1 : 0;
}

// Detailed Forensic Success Card
void logSuccess(const std::string &password, const std::string &target,
                HashType type, const std::string &salt, long long attempts,
                long long ms, const std::string &method = "Força Bruta Automática",
                bool saveToPot = true,
                const std::string &engineName = "") {
  if (globalQuiet) {
    std::cout << encodeQuietField(target) << ":"
              << encodeQuietField(password) << "\n";
    if (saveToPot) saveCrackedPassword(target, salt, type, password);
    return;
  }

  if (globalJson) {
    const std::string actualEngineName =
        engineName.empty() ? getEngineName() : engineName;
    const long long rate = hashRateForJson(attempts, ms);
    std::cout << "{\n"
              << "  \"status\": \"cracked\",\n"
              << "  \"target\": \"" << jsonEscape(target) << "\",\n  ";
    writeJsonTextOrBase64(std::cout, "plaintext", password);
    std::cout << ",\n"
              << "  \"algorithm\": \"" << jsonEscape(hashTypeName(type)) << "\",\n  ";
    writeJsonTextOrBase64(std::cout, "salt", salt);
    std::cout << ",\n"
              << "  \"method\": \"" << jsonEscape(method) << "\",\n"
              << "  \"engine\": \"" << jsonEscape(actualEngineName) << "\",\n"
              << "  \"time_ms\": " << ms << ",\n"
              << "  \"attempts\": " << attempts << ",\n"
              << "  \"hashrate_hps\": " << rate << "\n"
              << "}\n";
    if (saveToPot) saveCrackedPassword(target, salt, type, password);
    return;
  }

  std::cout << "\n\n\x1b[1;92m";
  const std::string actualEngineName =
      engineName.empty() ? getEngineName() : engineName;
  std::cout << "  ==========================================================================\n";
  std::cout << "  |  ✓ SUCESSO: CREDENCIAL RECUPERADA                                      |\n";
  std::cout << "  +------------------------------------------------------------------------+\x1b[0m\n";

  printBoxLine("HASH ALVO", target, "\x1b[1;97m");
  printBoxLine("SENHA", password, "\x1b[1;93m");
  printBoxLine("ALGORITMO", hashTypeName(type), "\x1b[1;36m");
  if (!salt.empty()) {
    printBoxLine("SALT", salt, "\x1b[1;37m");
  }
  printBoxLine("METODO", method, "\x1b[1;35m");
  printBoxLine("ENGINE", actualEngineName, "\x1b[1;34m");
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

// Report a verified potfile hit and the measured cache lookup time.
void logPotfileHit(const std::string &target, const std::string &password,
                   HashType type, const std::string &salt,
                   double cacheTimeMs) {
  if (globalQuiet) {
    std::cout << encodeQuietField(target) << ":"
              << encodeQuietField(password) << "\n";
    return;
  }

  if (globalJson) {
    std::ostringstream formattedTime;
    formattedTime << std::fixed << std::setprecision(3) << cacheTimeMs;
    std::cout << "{\n"
              << "  \"status\": \"cached\",\n"
              << "  \"target\": \"" << jsonEscape(target) << "\",\n"
              << "  ";
    writeJsonTextOrBase64(std::cout, "plaintext", password);
    std::cout << ",\n"
              << "  \"algorithm\": \"" << jsonEscape(hashTypeName(type)) << "\",\n  ";
    writeJsonTextOrBase64(std::cout, "salt", salt);
    std::cout << ",\n"
              << "  \"source\": \"cracked_passwords.txt\",\n"
              << "  \"time_ms\": " << formattedTime.str() << "\n"
              << "}\n";
    return;
  }

  std::cout << "\n\n\x1b[1;96m";
  std::cout << "  ==========================================================================\n";
  std::cout << "  |  ⚡ POTFILE CACHE HIT (RESULTADO SALVO)                                |\n";
  std::cout << "  +------------------------------------------------------------------------+\x1b[0m\n";

  printBoxLine("HASH ALVO", target, "\x1b[1;97m");
  printBoxLine("SENHA", password, "\x1b[1;93m");
  printBoxLine("ALGORITMO", hashTypeName(type), "\x1b[1;36m");
  if (!salt.empty()) {
    printBoxLine("SALT", salt, "\x1b[1;37m");
  }
  std::ostringstream formattedTime;
  formattedTime << std::fixed << std::setprecision(3) << cacheTimeMs << " ms";
  printBoxLine("TEMPO CACHE", formattedTime.str(), "\x1b[1;93m");
  printBoxLine("ORIGEM", "cracked_passwords.txt (resultado previamente salvo)", "\x1b[1;92m");
  std::cout << "\x1b[1;96m  ==========================================================================\x1b[0m\n\n";
}

// Actionable Keyspace Exhausted Failure Card
void logExhausted(const std::string &target, HashType type,
                  int minLen, int maxLen, int charsetSize,
                  long long attempts, long long ms,
                  const std::string &engineName) {
  if (globalQuiet) {
    std::cout << encodeQuietField(target) << ":[NOT_FOUND]\n";
    return;
  }

  if (globalJson) {
    const long long rate = hashRateForJson(attempts, ms);
    std::cout << "{\n"
              << "  \"status\": \"exhausted\",\n"
              << "  \"target\": \"" << jsonEscape(target) << "\",\n"
              << "  \"algorithm\": \"" << jsonEscape(hashTypeName(type)) << "\",\n"
              << "  \"engine\": \"" << jsonEscape(engineName) << "\",\n"
              << "  \"time_ms\": " << ms << ",\n"
              << "  \"attempts\": " << attempts << ",\n"
              << "  \"hashrate_hps\": " << rate << "\n"
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
  if (maxLen < 64) {
    std::cout << "  |   - Expandir comprimento de busca: --max-len "
              << std::min(maxLen + 2, 64) << "                         \x1b[1;91m|\n";
  } else {
    std::cout << "  |   - Limite maximo de 64 caracteres atingido; amplie a wordlist.    \x1b[1;91m|\n";
  }
  std::cout << "  |   - Incluir símbolos especiais no charset: --charset 7              |\n";
  std::cout << "  |   - Utilizar wordlist estendida: --wordlist rockyou.txt                |\n";
  std::cout << "  ==========================================================================\x1b[0m\n\n";
}

// Attack result descriptor for batch auditing & reporting
struct AttackResult {
  bool success = false;
  bool fromPotfile = false;
  std::string target = "";
  std::string recoveredPass = "";
  std::string salt = "";
  HashType type = HashType::UNKNOWN;
  std::string method = "";
  std::string engine = "not used";
  long long attempts = 0;
  long long durationMs = 0;
};

// --- Attack Vectors ---

// Generate and consume mutations one at a time to avoid retaining many copies
// of a long wordlist entry. The visitor returns false to stop after a match.
template <typename Visitor>
bool forEachMutation(const std::string &base, Visitor &&visitor) {
  if (base.empty()) return true;

  // Normal-sized words keep the old duplicate suppression. For unusually long
  // entries, avoid a set containing another full copy of every mutation.
  const bool trackDuplicates = base.size() <= 256;
  std::unordered_set<std::string> seen;
  auto addUnique = [&](const std::string &candidate) {
    if (candidate.empty()) return true;
    if (trackDuplicates && !seen.insert(candidate).second) return true;
    return visitor(candidate);
  };

  if (!addUnique(base)) return false;

  // 1. Lowercase and Uppercase full variants
  std::string lowerStr = base;
  for (char &c : lowerStr) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
  }
  if (!addUnique(lowerStr)) return false;

  {
    std::string upperStr = base;
    for (char &c : upperStr) {
      if (c >= 'a' && c <= 'z') c = static_cast<char>(c - ('a' - 'A'));
    }
    if (!addUnique(upperStr)) return false;
  }

  // 2. Capitalize First Letter (Title Case)
  std::string cap = lowerStr;
  if (cap[0] >= 'a' && cap[0] <= 'z')
    cap[0] = static_cast<char>(cap[0] - ('a' - 'A'));
  if (!addUnique(cap)) return false;

  // 3. Reversed word (e.g. admin -> nimda)
  {
    std::string reversed = base;
    std::reverse(reversed.begin(), reversed.end());
    if (!addUnique(reversed)) return false;
  }

  // 4. Duplicate word (e.g. admin -> adminadmin)
  if (!addUnique(base + base)) return false;

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
  if (!addUnique(leet1)) return false;

  {
    std::string leet2 = lowerStr;
    for (char &c : leet2) {
      if (c == 'a') c = '@';
      else if (c == 's') c = '$';
      else if (c == 'i') c = '!';
      else if (c == 'e') c = '3';
      else if (c == 'o') c = '0';
    }
    if (!addUnique(leet2)) return false;
  }

  // 6. Common forensic suffixes on base and title-case
  const std::vector<std::string> suffixes = {
    "1", "12", "123", "1234", "12345", "123456", "01", "00", "99",
    "2024", "2025", "2026", "2027", "2023", "2022", "2021", "2020",
    "2019", "2018", "2000", "1999", "1990", "1980",
    "!", "@", "#", "$", "_", ".", "*",
    "123!", "2024!", "2025!", "2026!", "!@#"
  };

  for (const auto &suffix : suffixes) {
    if (!addUnique(base + suffix) || !addUnique(cap + suffix) ||
        !addUnique(leet1 + suffix))
      return false;
  }

  // 7. Common forensic prefixes
  const std::vector<std::string> prefixes = { "123", "!", "@", "#", ".", "admin", "1234" };
  for (const auto &prefix : prefixes) {
    if (!addUnique(prefix + base) || !addUnique(prefix + cap)) return false;
  }

  return true;
}

bool loadWpa2SsidList(std::vector<std::string> &ssids) {
  ssids.clear();
  try {
    std::ifstream saltFile(defaultDataFilePath("saltlist.txt"),
                           std::ios::binary);
    if (!saltFile.is_open()) return false;
    if (probeWideTextBom(saltFile) != WideTextBomStatus::NONE) return false;

    std::unordered_set<std::string> uniqueSsids;
    std::string ssid;
    bool firstSsid = true;
    while (readLineWithUniversalNewlines(saltFile, ssid)) {
      if (firstSsid) {
        firstSsid = false;
        if (ssid.size() >= 3 &&
            static_cast<unsigned char>(ssid[0]) == 0xEF &&
            static_cast<unsigned char>(ssid[1]) == 0xBB &&
            static_cast<unsigned char>(ssid[2]) == 0xBF)
          ssid.erase(0, 3);
      }
      if (!ssid.empty() && ssid.back() == '\r') ssid.pop_back();
      // WPA2 SSIDs are 1..32 bytes; longer entries can never produce a PMK.
      if (!ssid.empty() && ssid.size() <= 32 &&
          uniqueSsids.insert(ssid).second)
        ssids.push_back(ssid);
    }
    if (streamHasReadError(saltFile)) {
      ssids.clear();
      return false;
    }
    return !ssids.empty();
  } catch (const std::bad_alloc &) {
    ssids.clear();
    return false;
  } catch (const std::length_error &) {
    ssids.clear();
    return false;
  } catch (const std::filesystem::filesystem_error &) {
    ssids.clear();
    return false;
  }
}

// Helper to load salts
std::vector<std::string> loadSalts(const Config &config,
                                   bool *readErrorOut = nullptr) {
  static bool missingSaltListWarningShown = false;
  static bool emptySaltListWarningShown = false;
  if (readErrorOut) *readErrorOut = false;
  try {
    std::vector<std::string> salts;
    if (config.type == HashType::HMAC_MD5 ||
        config.type == HashType::HMAC_SHA1 ||
        config.type == HashType::HMAC_SHA256) {
      // For HMAC, --salt is the key. An omitted key means the empty key;
      // saltlist.txt is not a key-guessing list.
      salts.push_back(config.salt);
      return salts;
    }
    if (config.type == HashType::WPA2_PBKDF2 && config.salt.empty()) {
      // Keep the empty salt for 64-hex raw PSKs, then try configured SSIDs when
      // no explicit --salt was provided.
      salts.push_back("");
      if (!config.saltProvided) {
        std::vector<std::string> ssids;
        if (loadWpa2SsidList(ssids)) {
          for (const auto &ssid : ssids) salts.push_back(ssid);
        }
      }
      return salts;
    }
    if (config.type == HashType::SCRYPT) {
      // Scrypt salt and parameters are embedded in its PHC target.
      salts.push_back("");
      return salts;
    }
    if ((config.type >= HashType::SALTED_MD5 &&
         config.type <= HashType::SALTED_SHA512) ||
        config.type == HashType::WPA2_PBKDF2) {
      if (!config.salt.empty() || config.saltProvided) {
        salts.push_back(config.salt);
      } else {
        const std::filesystem::path saltListPath =
            defaultDataFilePath("saltlist.txt");
        std::ifstream saltFile(saltListPath, std::ios::binary);
        if (saltFile.is_open()) {
          if (probeWideTextBom(saltFile) != WideTextBomStatus::NONE) {
            std::cerr << "[!] 'saltlist.txt' usa UTF-16/UTF-32 ou nao permite "
                         "verificar a codificacao; a busca nao e exaustiva.\n";
            if (readErrorOut) *readErrorOut = true;
            return {};
          }
          std::string s;
          bool firstSalt = true;
          std::unordered_set<std::string> uniqueSalts;
          while (readLineWithUniversalNewlines(saltFile, s)) {
            if (firstSalt) {
              firstSalt = false;
              if (s.size() >= 3 &&
                  static_cast<unsigned char>(s[0]) == 0xEF &&
                  static_cast<unsigned char>(s[1]) == 0xBB &&
                  static_cast<unsigned char>(s[2]) == 0xBF)
                s.erase(0, 3);
            }
            if (!s.empty() && s.back() == '\r')
              s.pop_back();
            if (s.empty()) continue;
            if (uniqueSalts.insert(s).second) salts.push_back(s);
          }
          if (streamHasReadError(saltFile)) {
            std::cerr << "[!] Erro durante a leitura de 'saltlist.txt'; a lista de salts pode estar incompleta.\n";
            if (readErrorOut) *readErrorOut = true;
            return {};
          }
          if (salts.empty()) {
            if (!emptySaltListWarningShown) {
              std::cerr << "[!] 'saltlist.txt' nao contem salts nao vazios; a busca nao pode enumerar salts. Informe --salt ou preencha a lista.\n";
              emptySaltListWarningShown = true;
            }
            if (readErrorOut) *readErrorOut = true;
            return {};
          }
          if (!globalQuiet && !globalJson)
            std::cout << "[i] Carregado " << salts.size()
                      << " salts de 'saltlist.txt'.\n";
        } else {
          std::error_code pathCheckError;
          const bool saltPathExists =
              std::filesystem::exists(saltListPath, pathCheckError);
          if (saltPathExists || pathCheckError) {
            std::cerr << "[!] 'saltlist.txt' existe, mas nao pode ser aberto; a busca nao e exaustiva.\n";
            if (readErrorOut) *readErrorOut = true;
            return {};
          }
          if (!missingSaltListWarningShown) {
            std::cerr << "[!] 'saltlist.txt' nao encontrado; a busca de hashes com salt nao pode enumerar salts. Informe --salt ou crie a lista.\n";
            missingSaltListWarningShown = true;
          }
          if (readErrorOut) *readErrorOut = true;
          return {};
        }
      }
    } else {
      salts.push_back("");
    }
    return salts;
  } catch (const std::bad_alloc &) {
    if (readErrorOut) *readErrorOut = true;
    std::cerr << "[!] Memoria insuficiente para carregar a lista de salts; a busca sera marcada como incompleta.\n";
    return {};
  } catch (const std::length_error &) {
    if (readErrorOut) *readErrorOut = true;
    std::cerr << "[!] Lista de salts excede o limite suportado; a busca sera marcada como incompleta.\n";
    return {};
  } catch (const std::filesystem::filesystem_error &) {
    if (readErrorOut) *readErrorOut = true;
    std::cerr << "[!] Nao foi possivel acessar a lista de salts; a busca sera marcada como incompleta.\n";
    return {};
  }
}

// --- Parallel Core & State ---
std::atomic<bool> found(false);
std::string crackedPassword = "";
std::string crackedSalt = "";
std::atomic<long long> totalTentativas(0);
std::mutex foundMutex;
std::atomic<int> activeThreads(0);

long long saturatingAttemptAdd(long long left, long long right) {
  if (left < 0) left = 0;
  if (right <= 0) return left;
  const long long limit = std::numeric_limits<long long>::max();
  return right > limit - left ? limit : left + right;
}

long long saturatingAttemptAddUnsigned(long long left,
                                       unsigned long long right) {
  if (left < 0) left = 0;
  const long long limit = std::numeric_limits<long long>::max();
  const unsigned long long remaining =
      static_cast<unsigned long long>(limit - left);
  return right > remaining ? limit : left + static_cast<long long>(right);
}

void addAttemptsSaturating(std::atomic<long long> &total, long long increment) {
  if (increment <= 0) return;
  long long current = total.load(std::memory_order_relaxed);
  while (true) {
    const long long next = saturatingAttemptAdd(current, increment);
    if (total.compare_exchange_weak(current, next, std::memory_order_relaxed,
                                    std::memory_order_relaxed))
      return;
  }
}

#if defined(ENABLE_CUDA)
struct CudaProgressState {
  long long initialAttempts = 0;
  unsigned long long pendingAttempts = 0;
  double progressPct = 0.0;
  int currentLength = 1;
  int maxLength = 1;
  std::chrono::steady_clock::time_point started;
  std::chrono::steady_clock::time_point lengthStarted;
  std::chrono::steady_clock::time_point lastRender;
};

void renderCudaProgress(CudaProgressState &state, bool force) {
  const auto now = std::chrono::steady_clock::now();
  const auto interval = now - state.lastRender;
  if (!force && interval < std::chrono::milliseconds(200)) return;

  const double intervalSeconds =
      std::chrono::duration<double>(interval).count();
  const double speed = intervalSeconds > 0.0
                           ? static_cast<double>(state.pendingAttempts) /
                                 intervalSeconds
                           : 0.0;
  state.pendingAttempts = 0;
  state.lastRender = now;

  const double lengthElapsedSeconds =
      std::chrono::duration<double>(now - state.lengthStarted).count();
  std::string eta = "--:--";
  if (state.progressPct >= 100.0) {
    eta = "00:00:00";
  } else if (state.progressPct > 0.0 && lengthElapsedSeconds > 0.0) {
    const long double remainingSeconds =
        static_cast<long double>(lengthElapsedSeconds) *
        (100.0L - state.progressPct) / state.progressPct;
    if (remainingSeconds <=
        static_cast<long double>(std::numeric_limits<long long>::max())) {
      const long long seconds = static_cast<long long>(remainingSeconds);
      char etaBuffer[32];
      std::snprintf(etaBuffer, sizeof(etaBuffer), "%02lld:%02lld:%02lld",
                    seconds / 3600, (seconds % 3600) / 60, seconds % 60);
      eta = etaBuffer;
    }
  }
  const long long elapsedMs =
      std::chrono::duration_cast<std::chrono::milliseconds>(now - state.started)
          .count();

  std::cout << "\r\x1b[2K\x1b[1;32m[CUDA] L" << state.currentLength << "/"
            << state.maxLength << " " << formatProgressBar(state.progressPct, 10)
            << " | " << formatHashrate(speed) << " | "
            << formatNumber(totalTentativas.load()) << " tentativas | ETA L"
            << state.currentLength << " " << eta << " | Total "
            << formatTime(elapsedMs) << "\x1b[0m"
            << std::flush;
}

void cudaProgressUpdate(void *context, unsigned long long batchAttempts,
                        unsigned long long cumulativeAttempts,
                        double progressPct, int currentLength, int maxLength) {
  if (!context) return;
  auto &state = *static_cast<CudaProgressState *>(context);
  const auto now = std::chrono::steady_clock::now();
  if (currentLength != state.currentLength) {
    state.currentLength = currentLength;
    state.lengthStarted = now;
    state.lastRender = now;
    state.pendingAttempts = 0;
  }
  state.progressPct = std::clamp(progressPct, 0.0, 100.0);
  state.maxLength = maxLength;
  const auto maxCount = std::numeric_limits<unsigned long long>::max();
  state.pendingAttempts =
      batchAttempts > maxCount - state.pendingAttempts
          ? maxCount
          : state.pendingAttempts + batchAttempts;
  totalTentativas = saturatingAttemptAddUnsigned(state.initialAttempts,
                                                cumulativeAttempts);
  renderCudaProgress(state, false);
}
#endif

bool dictionaryAttack(const Config &config,
                      const std::string &wordlistFile = "wordlist.txt",
                      long long *attemptsOut = nullptr,
                      long long priorAttempts = 0,
                      bool *saltListReadErrorOut = nullptr,
                      bool *wordlistReadErrorOut = nullptr) {
  found = false;
  crackedPassword.clear();
  crackedSalt.clear();
  if (attemptsOut) *attemptsOut = 0;
  if (!globalQuiet && !globalJson) {
    std::cout << "\n[!] Iniciando ataque via Dicionario ("
              << terminalSafeText(wordlistFile)
              << ") + Mutations...\n";
  }
  std::ifstream file(pathFromUtf8(wordlistFile), std::ios::binary);
  if (!file.is_open()) {
    std::cerr << "[!] Nao foi possivel abrir o dicionario '"
              << terminalSafeText(wordlistFile)
              << "'; a busca seguira sem ataque de dicionario.\n";
    if (wordlistReadErrorOut) *wordlistReadErrorOut = true;
    return false;
  }
  if (probeWideTextBom(file) != WideTextBomStatus::NONE) {
    std::cerr << "[!] Dicionario '" << terminalSafeText(wordlistFile)
              << "' usa UTF-16/UTF-32 ou nao permite verificar a codificacao; "
                 "a busca por dicionario foi marcada como incompleta.\n";
    if (wordlistReadErrorOut) *wordlistReadErrorOut = true;
    return false;
  }

  bool saltListReadError = false;
  std::vector<std::string> salts = loadSalts(config, &saltListReadError);
  if (saltListReadError) {
    if (saltListReadErrorOut) *saltListReadErrorOut = true;
    return false;
  }

  std::string line;
  long long count = 0;
  bool firstWord = true;
  bool emptyWordTried = false;
  auto start = std::chrono::high_resolution_clock::now();
  auto last_print = start;

  while (readLineWithUniversalNewlines(file, line)) {
    if (firstWord) {
      firstWord = false;
      if (line.size() >= 3 &&
          static_cast<unsigned char>(line[0]) == 0xEF &&
          static_cast<unsigned char>(line[1]) == 0xBB &&
          static_cast<unsigned char>(line[2]) == 0xBF)
        line.erase(0, 3);
    }
    if (!line.empty() && line.back() == '\r') line.pop_back();

    bool crackedThisLine = false;
    auto tryCandidate = [&](const std::string &attempt) {
      for (const auto &currentSalt : salts) {
        const bool matches = verifyCandidate(attempt, config.type,
                                             config.target, currentSalt);
        count = saturatingAttemptAdd(count, 1);

        if (matches) {
          found = true;
          crackedPassword = attempt;
          crackedSalt = currentSalt;
          crackedThisLine = true;
          return false;
        }
      }
      return true;
    };

    if (line.empty()) {
      if (emptyWordTried) continue;
      emptyWordTried = true;
      tryCandidate(line);
    } else {
      forEachMutation(line, tryCandidate);
    }

    if (crackedThisLine) {
      if (attemptsOut) *attemptsOut = count;
      const long long cumulativeAttempts =
          saturatingAttemptAdd(priorAttempts, count);
      auto end = std::chrono::high_resolution_clock::now();
      auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
          end - start);
      if (!globalQuiet && !globalJson)
        std::cout << "\r\x1b[2K                                                                                \r" << std::flush;
      totalTentativas = cumulativeAttempts;
      logSuccess(crackedPassword, config.target, config.type, crackedSalt,
                 cumulativeAttempts, duration.count(),
                 "Dicionário Forense + Mutações", true, "CPU (Dictionary)");
      return true;
    }

    auto now = std::chrono::high_resolution_clock::now();
    long long elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_print).count();
    if (!globalQuiet && !globalJson && elapsed_ms >= 150) {
      last_print = now;
      long long total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
      double wps = (total_ms > 0) ? ((double)count / (total_ms / 1000.0)) : 0.0;
      std::string dispWord = line;
      if (dispWord.length() > 22) dispWord = dispWord.substr(0, 19) + "...";
      dispWord = terminalSafeText(dispWord);
      std::cout << "\r\x1b[2K\x1b[1;36m[Dicionário] Testando: \x1b[1;33m" << dispWord
                << "\x1b[0m (" << formatNumber(count) << " chaves | " << formatHashrate(wps) << ") " << std::flush;
    }
  }
  const bool wordlistReadError = streamHasReadError(file);
  if (wordlistReadError) {
    std::cerr << "[!] Erro durante a leitura de '"
              << terminalSafeText(wordlistFile)
              << "'; o ataque de dicionario foi parcial.\n";
    if (wordlistReadErrorOut) *wordlistReadErrorOut = true;
  }
  if (!globalQuiet && !globalJson) {
    std::cout << "\r\x1b[2K                                                                                \r" << std::flush;
    std::cout << (wordlistReadError
                      ? "[!] Dicionario interrompido antes do fim do arquivo.\n"
                      : "[!] Senha nao encontrada no dicionario.\n");
  }
  if (attemptsOut) *attemptsOut = count;
  return false;
}

#if defined(ENABLE_CUDA)
int gpuBruteForceOrchestrator(const Config &config, bool reportResult,
                              long long initialAttempts = 0,
                              bool showProgress = true) {
  if (reportResult && !globalQuiet && !globalJson) {
    std::cout << "\n\x1b[1;36m[GPU] INICIANDO ORQUESTRADOR CUDA (NATIVE)...\x1b[0m\n";
    std::cout << "[GPU] Transferindo dados para VRAM...\n";
  }

  char resultBuffer[256] = {0};
  unsigned long long attempts = 0;

  auto start = std::chrono::high_resolution_clock::now();
  CudaProgressState progressState;
  progressState.initialAttempts = initialAttempts;
  progressState.maxLength = config.maxLength;
  progressState.started = std::chrono::steady_clock::now();
  progressState.lengthStarted = progressState.started;
  progressState.lastRender = progressState.started;
  const bool renderProgress = showProgress && !globalQuiet && !globalJson;
  const int executionSucceeded = launch_gpu_brute_force_ext(
      config.charset.c_str(), config.target.c_str(), config.maxLength,
      resultBuffer, config.hashType, config.salt.c_str(), &attempts,
      renderProgress ? &progressState : nullptr,
      renderProgress ? cudaProgressUpdate : nullptr);
  auto end = std::chrono::high_resolution_clock::now();
  totalTentativas = saturatingAttemptAddUnsigned(initialAttempts, attempts);
  if (renderProgress) {
    if (executionSucceeded && resultBuffer[0] == '\0') {
      progressState.progressPct = 100.0;
      progressState.currentLength = config.maxLength;
    }
    renderCudaProgress(progressState, true);
    std::cout << "\r\x1b[2K\r" << std::flush;
  }
  if (!executionSucceeded) return -1;

  if (std::strlen(resultBuffer) > 0) {
    const std::string candidate(resultBuffer);
    if (!verifyCandidate(candidate, config.type, config.target, config.salt))
      return -1;
    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::lock_guard<std::mutex> lock(foundMutex);
    found = true;
    crackedPassword = candidate;
    crackedSalt = config.salt;
    if (reportResult)
      logSuccess(candidate, config.target, config.type, config.salt,
                 saturatingAttemptAddUnsigned(initialAttempts, attempts),
                 duration.count());
    return 1;
  } else {
    if (reportResult && !globalQuiet && !globalJson)
      std::cout << "\n\x1b[1;31m[FALHA] Senha nao encontrada no keyspace.\x1b[0m\n";
    return 0;
  }
}
#endif

// Fast Multi-Threaded CPU Brute Force Worker with In-Place Character Increment
void bruteForceWorker(int threadId, const std::atomic<int> &workerCount,
                      const std::atomic<bool> &startWorkers, int length,
                      const Config &config,
                      const std::vector<std::string> &salts) {
  while (!startWorkers.load(std::memory_order_acquire))
    std::this_thread::yield();
  const int totalThreads = workerCount.load(std::memory_order_relaxed);
  if (totalThreads <= 0) {
    activeThreads--;
    return;
  }
  int numChars = static_cast<int>(config.charset.length());
  std::vector<int> indices(length, 0);
  long long localAttempts = 0;

  auto flushAttempts = [&]() {
    if (localAttempts > 0) {
      addAttemptsSaturating(totalTentativas, localAttempts);
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

        if (verifyCandidate(attempt, config.type, config.target, s)) {
          std::lock_guard<std::mutex> lock(foundMutex);
          if (!found) {
            found = true;
            crackedPassword = attempt;
            crackedSalt = s;
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
          if (found.load(std::memory_order_relaxed)) {
            flushAttempts();
            activeThreads--;
            return;
          }
          localAttempts++;
          if (localAttempts >= 50000) flushAttempts();

          if (verifyCandidate(attempt, config.type, config.target, s)) {
            std::lock_guard<std::mutex> lock(foundMutex);
            if (!found) {
              found = true;
              crackedPassword = attempt;
              crackedSalt = s;
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

bool runParallelBruteForce(const Config &config, bool reportResult = true,
                           bool *saltListReadErrorOut = nullptr,
                           bool showProgress = true) {
  crackedSalt.clear();
  crackedPassword.clear();
  found = false;
  totalTentativas = 0;
  auto rejectExplicitGpuFallback = [&](const std::string &reason) {
    if (!globalEngineExplicitlySelected ||
        globalCompute == ComputeType::CPU)
      return false;
    if (globalEngineFailure.empty()) globalEngineFailure = reason;
    return true;
  };
  const int kernelAlgo = getKernelAlgoId(config.type);
  bool saltListReadError = false;
  const std::vector<std::string> salts = loadSalts(config, &saltListReadError);
  if (saltListReadError) {
    if (saltListReadErrorOut) *saltListReadErrorOut = true;
    return false;
  }
  long long emptyCandidateAttempts = 0;
  for (const auto &salt : salts) {
    emptyCandidateAttempts++;
    if (verifyCandidate("", config.type, config.target, salt)) {
      found = true;
      crackedPassword.clear();
      crackedSalt = salt;
      totalTentativas = emptyCandidateAttempts;
      if (!globalEngineExplicitlySelected ||
          globalCompute == ComputeType::CPU)
        globalCompute = ComputeType::CPU;
      if (reportResult)
        logSuccess("", config.target, config.type, salt, emptyCandidateAttempts,
                   0, "Empty Password Candidate");
      return true;
    }
  }
  size_t maxSaltLength = 0;
  for (const auto &salt : salts) maxSaltLength = std::max(maxSaltLength, salt.length());
  const bool cudaSupported = kernelAlgo == 0 || kernelAlgo == 1 ||
                             kernelAlgo == 2 || kernelAlgo == 3 ||
                             kernelAlgo == 11 || kernelAlgo == 12;
  const bool openclSupported = (kernelAlgo >= 0 && kernelAlgo <= 3) ||
                               kernelAlgo == 11 || kernelAlgo == 12;
  const size_t cudaMaxInput =
      (config.type == HashType::SHA512 ||
       config.type == HashType::SALTED_SHA512) ? 239 : 119;
  const size_t openclMaxInput =
      (config.type == HashType::SHA512 ||
       config.type == HashType::SALTED_SHA512) ? 239 : 119;
  if (globalCompute == ComputeType::CUDA &&
      (salts.size() != 1 || salts[0] != config.salt)) {
    if (rejectExplicitGpuFallback(
            "CUDA nao percorre saltlist com multiplos salts"))
      return false;
    if (!globalQuiet && !globalJson)
      std::cout << "[!] CUDA nao percorre saltlist; usando CPU para testar todos os salts.\n";
    globalCompute = ComputeType::CPU;
  }
  const bool ntlmAsciiCharset = std::all_of(
      config.charset.begin(), config.charset.end(), [](unsigned char c) {
        return c < 0x80;
      });
  const bool ntlmGpuSafe = config.type != HashType::NTLM ||
                           (config.maxLength <= 59 && ntlmAsciiCharset);
  const bool gpuSaltsSafe = std::all_of(
      salts.begin(), salts.end(), [](const std::string &salt) {
        return salt.find('\0') == std::string::npos;
      });
  if ((globalCompute == ComputeType::CUDA ||
       globalCompute == ComputeType::OPENCL) && !gpuSaltsSafe) {
    if (rejectExplicitGpuFallback(
            "salt contem byte NUL, nao representavel pelos kernels GPU"))
      return false;
    std::cerr << "[!] Salt contem byte NUL, nao representavel pelos kernels GPU; usando CPU.\n";
    globalCompute = ComputeType::CPU;
  }
  if (globalCompute == ComputeType::CUDA &&
      static_cast<size_t>(config.maxLength) + maxSaltLength > cudaMaxInput) {
    if (rejectExplicitGpuFallback(
            "entrada excede o buffer seguro do kernel CUDA"))
      return false;
    if (!globalQuiet && !globalJson)
      std::cout << "[!] Entrada excede o buffer CUDA seguro; usando CPU.\n";
    globalCompute = ComputeType::CPU;
  }
  if (globalCompute == ComputeType::OPENCL &&
      static_cast<size_t>(config.maxLength) + maxSaltLength > openclMaxInput) {
    if (rejectExplicitGpuFallback(
            "entrada excede o buffer seguro do kernel OpenCL"))
      return false;
    if (!globalQuiet && !globalJson)
      std::cout << "[!] Entrada excede o buffer OpenCL seguro; usando CPU.\n";
    globalCompute = ComputeType::CPU;
  }
  if (globalCompute == ComputeType::CUDA && !ntlmGpuSafe) {
    if (rejectExplicitGpuFallback(
            "kernel NTLM exige charset ASCII e limite de 59 bytes"))
      return false;
    if (!globalQuiet && !globalJson)
      std::cout << "[!] Kernel NTLM exige charset ASCII e limite de 59 bytes; usando CPU.\n";
    globalCompute = ComputeType::CPU;
  }
  if (globalCompute == ComputeType::OPENCL && !ntlmGpuSafe) {
    if (rejectExplicitGpuFallback(
            "kernel NTLM exige charset ASCII e limite de 59 bytes"))
      return false;
    if (!globalQuiet && !globalJson)
      std::cout << "[!] Kernel NTLM exige charset ASCII e limite de 59 bytes; usando CPU.\n";
    globalCompute = ComputeType::CPU;
  }
  if (globalCompute == ComputeType::CUDA && !cudaSupported) {
    if (rejectExplicitGpuFallback("algoritmo nao implementado no kernel CUDA"))
      return false;
    if (!globalQuiet && !globalJson)
      std::cout << "[!] CUDA nao implementa este algoritmo; usando CPU.\n";
    globalCompute = ComputeType::CPU;
  }
  if (globalCompute == ComputeType::OPENCL && !openclSupported) {
    if (rejectExplicitGpuFallback("algoritmo nao implementado no kernel OpenCL"))
      return false;
    if (!globalQuiet && !globalJson)
      std::cout << "[!] OpenCL nao implementa este algoritmo; usando CPU.\n";
    globalCompute = ComputeType::CPU;
  }

  // OpenCL still indexes the complete keyspace with 64-bit counters. CUDA
  // partitions oversized lengths by a host-generated prefix and only indexes
  // the bounded suffix in each kernel launch.
  if (globalCompute == ComputeType::OPENCL) {
    int maxSupportedLength = 0;
    const bool gpuKeyspaceFits = gpuKeyspaceFitsCounters(
        config.charset.size(), config.maxLength, salts.size(),
        emptyCandidateAttempts, maxSupportedLength);
    if (!gpuKeyspaceFits) {
      const std::string engineName =
          globalCompute == ComputeType::CUDA ? "CUDA" : "OpenCL";
      const std::string reason =
          "max-len " + std::to_string(config.maxLength) +
          " exceeds " + engineName +
          " 64-bit keyspace/report limits for charset " +
          std::to_string(config.charset.size()) + " and " +
          std::to_string(salts.size()) + " salt(s); maximum supported max-len " +
          std::to_string(maxSupportedLength) + "; lower --max-len";
      if (rejectExplicitGpuFallback(
              reason))
        return false;
      if (!globalQuiet && !globalJson)
        std::cout << "[!] " << reason
                  << "; usando CPU para percorrer sem truncamento.\n";
      globalCompute = ComputeType::CPU;
    }
  }

  if (globalVerbose) {
    std::cerr << "[verbose] brute_force_backend="
              << terminalSafeText(getEngineName())
              << " max_length=" << config.maxLength
              << " charset_size=" << config.charset.size()
              << " salt_count=" << salts.size() << "\n";
  }

  // Check for GPU Mode
  long long priorGpuAttempts = emptyCandidateAttempts;
  if (globalCompute == ComputeType::CUDA) {
#if defined(ENABLE_CUDA)
    const int cudaResult = gpuBruteForceOrchestrator(
        config, reportResult, emptyCandidateAttempts, showProgress);
    if (cudaResult >= 0) return cudaResult == 1;
    if (rejectExplicitGpuFallback(
            "execucao CUDA falhou ou resultado nao passou na verificacao CPU"))
      return false;
    globalCompute = ComputeType::CPU;
    found = false;
    priorGpuAttempts = totalTentativas.load();
    if (!globalQuiet && !globalJson)
      std::cout << "[!] Falha CUDA ou resultado reprovado na verificacao CPU; reiniciando a busca na CPU.\n";
#else
    if (rejectExplicitGpuFallback("esta build nao inclui suporte CUDA"))
      return false;
    if (!globalQuiet && !globalJson) {
      std::cout << "[!] GPU Mode Compiled Out. Fallback to CPU.\n";
    }
    globalCompute = ComputeType::CPU;
#endif
  }

  if (globalCompute == ComputeType::OPENCL) {
    if (!globalQuiet && !globalJson) {
      std::cout << "\n[OpenCL] Iniciando busca na GPU...\n";
    }
    auto start_time = std::chrono::high_resolution_clock::now();
    char res_buf[256] = {0};
    int stop_flag = 0;

    char targetPad[256] = {0};
    if (config.targetHash.length() < 256) {
      std::memcpy(targetPad, config.targetHash.c_str(), config.targetHash.length());
    } else {
      std::memcpy(targetPad, config.targetHash.c_str(), 255);
    }

    unsigned long long totalGpuAttempts = 0;
    std::string matchedSalt = config.salt;
    bool openclExecutionOk = true;

    for (const auto &curSalt : salts) {
      if (salts.size() > 1 && !globalQuiet && !globalJson) {
        std::cout << "[OpenCL] Testando salt: \""
                  << terminalSafeText(curSalt) << "\"...\n";
      }
      unsigned long long localAttempts = 0;
      const int launchSucceeded = launch_opencl_brute_force(
          config.charset.c_str(), targetPad, config.maxLength, res_buf,
          &stop_flag, getKernelAlgoId(config.type), curSalt.c_str(),
          &localAttempts);
      totalGpuAttempts += localAttempts;
      if (!launchSucceeded) {
        openclExecutionOk = false;
        break;
      }
      if (res_buf[0] != 0) {
        const std::string candidate(res_buf);
        if (!verifyCandidate(candidate, config.type, config.target, curSalt)) {
          openclExecutionOk = false;
          break;
        }
        matchedSalt = curSalt;
        break;
      }
    }
    if (openclExecutionOk) {
      totalTentativas = emptyCandidateAttempts + totalGpuAttempts;
      auto end_time = std::chrono::high_resolution_clock::now();
      long long elapsed_ms =
          std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time)
              .count();

      if (res_buf[0] != 0) {
        std::lock_guard<std::mutex> lock(foundMutex);
        found = true;
        crackedPassword = std::string(res_buf);
        crackedSalt = matchedSalt;

        if (reportResult)
          logSuccess(res_buf, config.targetHash, config.type,
                     matchedSalt, totalTentativas.load(), elapsed_ms, "Força Bruta GPU (OpenCL)");
        return true;
      } else {
        if (!globalQuiet && !globalJson)
          std::cout << "[OpenCL] Senha nao encontrada neste range.\n";
        return false;
      }
    } else {
      if (rejectExplicitGpuFallback(
              "execucao OpenCL falhou ou resultado nao passou na verificacao CPU"))
        return false;
      globalCompute = ComputeType::CPU;
      priorGpuAttempts = emptyCandidateAttempts +
                         static_cast<long long>(totalGpuAttempts);
      totalTentativas = priorGpuAttempts;
      if (!globalQuiet && !globalJson)
        std::cout << "[!] Falha OpenCL ou resultado reprovado na verificacao CPU; reiniciando a busca na CPU.\n";
    }
  }

  if (!globalQuiet && !globalJson) {
    std::cout << "\n\x1b[1;36m[!] Iniciando motor PARALELO (Multi-Threaded)...\x1b[0m\n";
  }
  int maxThreads = config.type == HashType::SCRYPT
                       ? 1
                       : static_cast<int>(std::thread::hardware_concurrency());
  if (maxThreads == 0) maxThreads = 2;
  // Each worker owns one first-character slice. More workers than charset
  // symbols cannot add coverage and only create threads that exit immediately.
  if (config.charset.size() < static_cast<size_t>(maxThreads))
    maxThreads = static_cast<int>(config.charset.size());
  if (maxThreads <= 0) maxThreads = 1;
  if (!globalQuiet && !globalJson) {
    std::cout << "[i] Threads Ativas: " << maxThreads << "\n";
  }

  found = false;
  totalTentativas = priorGpuAttempts;
  auto start = std::chrono::high_resolution_clock::now();
  const long long cpuAttemptsAtStart = totalTentativas.load();

  int maxL = (config.maxLength > 0) ? config.maxLength : 16;
  for (int length = 1; length <= maxL; ++length) {
    if (found) break;
    const long long attemptsBeforeLength = totalTentativas.load();
    long double lengthAttemptBudget =
        static_cast<long double>(salts.size());
    for (int c = 0; c < length; ++c)
      lengthAttemptBudget *= config.charset.length();
    if (!globalQuiet && !globalJson) {
      std::cout << "[+] Verificando tamanho " << length << "... \n";
    }

    std::atomic<int> workerCount(0);
    std::atomic<bool> startWorkers(false);
    activeThreads = 0;
    std::vector<std::thread> workers;
    bool workerCreationFailed = false;
    try {
      workers.reserve(static_cast<size_t>(maxThreads));
    } catch (const std::exception &) {
      workerCreationFailed = true;
    }
    for (int i = 0; i < maxThreads; ++i) {
      if (workerCreationFailed) break;
      try {
        workers.emplace_back(bruteForceWorker, i, std::cref(workerCount),
                             std::cref(startWorkers), length,
                             std::ref(config), std::ref(salts));
      } catch (const std::exception &) {
        workerCreationFailed = true;
      }
    }
    if (workers.empty()) {
      // Resource limits prevented creating a worker; run this length on the caller.
      workerCount = 1;
      activeThreads = 1;
      startWorkers.store(true, std::memory_order_release);
      std::cerr << "[!] Nao foi possivel criar workers; busca continuara na thread principal.\n";
      bruteForceWorker(0, workerCount, startWorkers, length, config, salts);
    } else {
      workerCount = static_cast<int>(workers.size());
      activeThreads = static_cast<int>(workers.size());
      startWorkers.store(true, std::memory_order_release);
      if (workerCreationFailed) {
        std::cerr << "[!] Limite de threads do sistema; busca continuara com "
                  << workers.size() << " workers.\n";
      }
    }

    // Monitoring loop with real-time ETA and formatted hashrate
    while (activeThreads > 0 && !found) {
      auto now = std::chrono::high_resolution_clock::now();
      auto duration_ms =
          std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
      const long long attemptsNow = totalTentativas.load();
      if (!globalQuiet && !globalJson && duration_ms > 200) {
        const long long attemptsThisLength =
            attemptsNow > attemptsBeforeLength
                ? attemptsNow - attemptsBeforeLength
                : 0;
        const long long cpuAttempts =
            attemptsNow > cpuAttemptsAtStart
                ? attemptsNow - cpuAttemptsAtStart
                : 0;
        double speed = (double)cpuAttempts / (duration_ms / 1000.0);
        double pct = lengthAttemptBudget > 0.0L
                         ? static_cast<double>(
                               static_cast<long double>(attemptsThisLength) *
                               100.0L / lengthAttemptBudget)
                         : 0.0;
        if (pct > 100.0) pct = 100.0;

        std::string etaStr = "--:--";
        if (speed > 0 && lengthAttemptBudget > attemptsThisLength) {
          const long double etaValue =
              (lengthAttemptBudget - attemptsThisLength) / speed;
          if (etaValue <= static_cast<long double>(
                              std::numeric_limits<long long>::max())) {
            const long long etaSec = static_cast<long long>(etaValue);
            if (etaSec < 3600) {
              char buf[32];
              std::snprintf(buf, sizeof(buf), "%02lld:%02lld", etaSec / 60,
                            etaSec % 60);
              etaStr = buf;
            } else {
              char buf[32];
              std::snprintf(buf, sizeof(buf), "%02lld:%02lld:%02lld",
                            etaSec / 3600, (etaSec % 3600) / 60, etaSec % 60);
              etaStr = buf;
            }
          }
        }

        long long elSec = duration_ms / 1000;
        char elBuf[32];
        std::snprintf(elBuf, sizeof(elBuf), "%02lld:%02lld", elSec / 60,
                      elSec % 60);

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
    if (!globalQuiet && !globalJson) {
      std::cout << "\r\x1b[2K\r" << std::flush;
    }
  }

  if (found) {
    auto end = std::chrono::high_resolution_clock::now();
    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    if (reportResult)
      logSuccess(crackedPassword, config.target, config.type,
                 crackedSalt, totalTentativas,
                 duration.count(), "Força Bruta CPU Multi-Threaded");
    return true;
  }

  if (!globalQuiet && !globalJson) {
    std::cout << "\n[X] Falha na Forca Bruta.\n";
  }
  return false;
}

// --- Unified Self-Test System ---
// Run self-tests through the same compute orchestrator used by real searches.
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

  // A per-test CPU fallback must not change the backend selected for later tests.
  const ComputeType requestedEngine = globalCompute;
  const bool recovered = runParallelBruteForce(config, false, nullptr, false);
  globalCompute = requestedEngine;
  return recovered && crackedPassword == password;
}

bool runAllTests(bool interactive = true) {
  enableANSI();
  set_opencl_quiet(1);
#ifdef _WIN32
  std::system("cls");
#else
  std::system("clear");
#endif
  exibirDesenho();

  std::cout << "\x1b[1;35m[!] CASOS DE VALIDACAO LOCAL - ENGINE: "
            << terminalSafeText(getEngineName()) << "\x1b[0m\n";
  std::cout << "==============================================================="
               "=========\n";
  std::cout << "  \x1b[1;37mMODO: \x1b[1;36m"
            << terminalSafeText(getEngineName()) << "\x1b[0m\n";
  std::cout
      << "  \x1b[1;37mMETODO: Gerar hash (CPU) -> Quebrar via forca bruta ("
      << terminalSafeText(getEngineName()) << ") -> Validar senha\x1b[0m\n";
  std::cout << "  \x1b[1;37mCOBERTURA: 11 casos (MD5, SHA1, SHA256, SHA512, Base64, NTLM, MD4 e variantes salted)\x1b[0m\n";
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

  // Protocol and vendor formats are excluded until backed by real parsers.

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
      std::cout << " SALT=\"" << terminalSafeText(salt) << "\"";
    std::cout << "\n";

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

    } else {
      failCount++;
      globalPass = false;
      std::cout << "       \x1b[1;31m[FAIL]\x1b[0m Esperado: \""
                << test.password << "\" Recuperado: \"" << crackedPassword
                << "\"\n";

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
  std::cout << "  \x1b[1;37mENGINE: \x1b[1;36m"
            << terminalSafeText(getEngineName())
            << "\x1b[0m\n";
  std::cout << "==============================================================="
               "=========\n";

  if (globalPass) {
    std::cout << "\n\x1b[1;42;30m   TODOS OS " << tests.size()
              << " CASOS DESTE AUTOTESTE PASSARAM   \x1b[0m\n";
  } else {
    std::cout << "\n\x1b[1;41;37m   FALHA EM " << failCount
              << " CASO(S) - REVISAR IMPLEMENTACAO   \x1b[0m\n";
  }

  if (interactive) {
    std::cout << "\n\x1b[1;33m[!] Pressione ENTER para voltar ao Menu "
                 "Principal...\x1b[0m";
    std::cin.ignore(10000, '\n');
    std::cin.clear();
    std::cin.get();
  }
  set_opencl_quiet(0);
  return globalPass;
}

// === BENCHMARK MODE ===
bool runBenchmark() {
  enableANSI();
  exibirDesenho();
  std::cout << "\x1b[1;35m[!] BENCHMARK DE DESEMPENHO FORENSE\x1b[0m\n";
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
  const ComputeType requestedBenchEngine = globalCompute;
  bool benchmarkSucceeded = true;

  for (const auto &item : benchAlgos) {
    // An unsupported algorithm may fall back to CPU; retry the requested backend
    // for the next algorithm instead of silently benchmarking CPU for the rest.
    globalCompute = requestedBenchEngine;
    std::cout << "  [+] " << item.name;
    for (size_t s = std::strlen(item.name); s < 20; s++) std::cout << " ";
    std::cout << ": ";
    std::cout.flush();

    // Use impossible target to measure pure throughput
    std::string fakeTarget = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    if (item.type == HashType::MD5 || item.type == HashType::NTLM || item.type == HashType::MD4) fakeTarget = fakeTarget.substr(0, 32);
    else if (item.type == HashType::SHA1) fakeTarget = fakeTarget.substr(0, 40);
    else if (item.type == HashType::SHA512) fakeTarget = fakeTarget + fakeTarget;

    Config cfg;
    cfg.charset = benchCharset;
    cfg.target = fakeTarget;
    cfg.targetHash = fakeTarget;
    cfg.type = item.type;
    cfg.maxLength = 4;

    auto bStart = std::chrono::high_resolution_clock::now();
    found = false;
    runParallelBruteForce(cfg, false, nullptr, false);
    const unsigned long long attempts = totalTentativas.load();
    if (attempts == 0) benchmarkSucceeded = false;

    auto bEnd = std::chrono::high_resolution_clock::now();
    long long bMs = std::chrono::duration_cast<std::chrono::milliseconds>(bEnd - bStart).count();
    if (bMs < 1) bMs = 1;

    double rate = (double)attempts / (bMs / 1000.0);
    std::cout << (attempts > 0 ? "\x1b[1;32m" : "\x1b[1;31m")
              << formatHashrate(rate) << "\x1b[0m ("
              << formatNumber(attempts) << " chaves em " << formatTime(bMs)
              << "; " << terminalSafeText(getEngineName()) << ")\n";
  }

  std::cout << "----------------------------------------------------------------------------\n";
  std::cout << (benchmarkSucceeded ? "[i] Benchmark finalizado. "
                                   : "[!] Benchmark incompleto: uma ou mais medicoes nao executaram tentativas. ")
            << "O backend mostrado por algoritmo indica a unidade que executou a busca.\n\n";
  // Keep per-algorithm fallbacks local to this benchmark in interactive mode.
  globalCompute = requestedBenchEngine;
  return benchmarkSucceeded;
}

// === CLI HELPER FUNCTIONS ===

bool cliArgMatchesOption(const std::string &argLower,
                         const std::string &flagLower) {
  return argLower == flagLower ||
         (argLower.size() > flagLower.size() &&
          argLower.compare(0, flagLower.size(), flagLower) == 0 &&
          argLower[flagLower.size()] == '=');
}

std::string cliGetArgValue(int argc, char *argv[], const std::string &flag) {
  std::string flagLower = flag;
  lowercaseAscii(flagLower);
  const std::string equalsPrefix = flagLower + "=";
  for (int i = 0; i < argc; ++i) {
    const std::string rawArg = argv[i];
    std::string argLower = rawArg;
    lowercaseAscii(argLower);
    if (argLower == "--") break;
    if (argLower == flagLower) {
      if (i + 1 >= argc) return "";
      const std::string value = argv[i + 1];
      // Do not consume the next option as this option's value. A path or
      // literal beginning with '-' can be passed with --option=value.
      if (!value.empty() && value[0] == '-') return "";
      return value;
    }
    if (argLower.compare(0, equalsPrefix.size(), equalsPrefix) == 0)
      return rawArg.substr(equalsPrefix.size());
  }
  return "";
}

bool cliHasFlag(int argc, char *argv[], const std::string &flag) {
  for (int i = 0; i < argc; i++) {
    std::string arg = argv[i];
    lowercaseAscii(arg);
    if (arg == "--") break;
    std::string flagLower = flag;
    lowercaseAscii(flagLower);
    if (arg == flagLower)
      return true;
  }
  return false;
}

bool cliHasOption(int argc, char *argv[], const std::string &flag) {
  std::string flagLower = flag;
  lowercaseAscii(flagLower);
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    lowercaseAscii(arg);
    if (arg == "--") break;
    if (cliArgMatchesOption(arg, flagLower)) return true;
  }
  return false;
}

bool cliOptionRepeated(int argc, char *argv[],
                       const std::vector<std::string> &aliases) {
  size_t occurrences = 0;
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    lowercaseAscii(arg);
    if (arg == "--") break;
    for (const std::string &alias : aliases) {
      std::string normalizedAlias = alias;
      lowercaseAscii(normalizedAlias);
      if (cliArgMatchesOption(arg, normalizedAlias) && ++occurrences > 1)
        return true;
    }
  }
  return false;
}

bool cliOptionMissingValue(int argc, char *argv[], const std::string &flag) {
  std::string flagLower = flag;
  lowercaseAscii(flagLower);
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    lowercaseAscii(arg);
    if (arg == "--") break;
    if (arg == flagLower + "=") return true;
    if (arg == flagLower) {
      if (i + 1 >= argc) return true;
      const std::string value = argv[i + 1];
      if (!value.empty() && value[0] == '-') return true;
    }
  }
  return false;
}

std::vector<std::string> cliTrailingPositionals(
    int argc, char *argv[],
    const std::vector<std::vector<std::string>> &valuedOptionAliases) {
  std::vector<std::string> positionals;
  int index = 2;
  if (argc > 1) {
    std::string firstArg = argv[1];
    lowercaseAscii(firstArg);
    for (const auto &aliases : valuedOptionAliases) {
      for (const std::string &alias : aliases) {
        std::string normalizedAlias = alias;
        lowercaseAscii(normalizedAlias);
        if (cliArgMatchesOption(firstArg, normalizedAlias)) {
          index = 1;
          break;
        }
      }
      if (index == 1) break;
    }
  }

  for (; index < argc; ++index) {
    const std::string rawArg = argv[index];
    if (rawArg == "--") {
      for (++index; index < argc; ++index)
        positionals.emplace_back(argv[index]);
      break;
    }

    std::string argLower = rawArg;
    lowercaseAscii(argLower);
    bool isValuedOption = false;
    for (const auto &aliases : valuedOptionAliases) {
      for (const std::string &alias : aliases) {
        std::string normalizedAlias = alias;
        lowercaseAscii(normalizedAlias);
        if (cliArgMatchesOption(argLower, normalizedAlias)) {
          isValuedOption = true;
          if (argLower == normalizedAlias) ++index;
          break;
        }
      }
      if (isValuedOption) break;
    }
    if (isValuedOption ||
        (argLower.size() > 1 && argLower[0] == '-'))
      continue;
    positionals.push_back(rawArg);
  }
  return positionals;
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
    test-all, test, t                              Executar smoke test de integracao (11 casos)
    benchmark, b                                   Medir hashrate maximo de GPU/CPU
    hash, g           <texto>                      Gerar todos os hashes criptograficos
    file, batch, f    <arquivo.txt>                Auditar lista/lote de hashes em arquivo
    history, potfile  [arquivo.txt]                Exibir historico de senhas recuperadas
    doctor                                          Diagnosticar configuracao deste ambiente
    help, h, ?                                     Mostrar esta ajuda
    version, v                                     Mostrar versao
    --help                                         Mostrar esta ajuda
    --version                                      Mostrar versao

  OPTIONS:
    Opcoes com valor tambem aceitam --opcao=valor (inclusive valores iniciados por '-')
    --engine, -e <cpu|cuda|opencl>                 Selecao explicita; nao faz fallback
        Sem --engine ha deteccao automatica; wordlist/mutacoes e potfile usam CPU
    --algo, -a <algoritmo>                        Forcar o algoritmo do alvo
        crc32, md5, ntlm, md4, sha1, sha224, sha256, sha384, sha512, base64
        salted-md5/sha1/sha256/sha512, hmac-md5/sha1/sha256, wpa2, bcrypt
        scrypt (PHC $scrypt$...); WPA3/SAE em captura passiva nao permite ataque offline
    --charset, -c <1-7>                            Charset para forca bruta
        1=Numerico 2=a-z 3=A-Z 4=a-zA-Z 5=a-z0-9 6=Alfanum 7=ASCII imprimivel (95)
    --salt, -s <valor>                             Salt; chave HMAC ou SSID WPA2 quando aplicavel
    --wordlist, -w <arquivo>                       Wordlist customizada (default incluido: data/lists/wordlist.txt)
    --file, -f <arquivo>                           Auditar lista/lote de hashes em arquivo
    --no-dict, -n                                  Pular ataque de dicionario
    --no-potfile, --fresh                          Ignorar cache de senhas quebradas (potfile)
    --quiet, -q                                    Modo script: hash:senha com campos percent-encoded
    --verbose, -v                                  Modo detalhado com telemetria expandida
    --json                                         Exportar saida estruturada em JSON
    --max-len, -l <N>                              Comprimento maximo (default: 16)
    --                                             Encerrar opcoes; argumentos seguintes sao literais

  EXAMPLES:
    cerberus 0192023a7bbd73250516f069df18b500
    cerberus ZHVhcnRlMTIz
    cerberus minhasenha
    cerberus crack "5d41402abc4b2a76b9719d911017c592" --algo md5
    cerberus crack "8846f7eaee8fb117ad06bdd830b7586c" --algo ntlm
    cerberus file targets.txt --algo sha256 --json
    cerberus crack <hash_hmac> --algo hmac-sha256 --salt <chave>
    cerberus file targets.txt --json
    cerberus history
    cerberus doctor
    cerberus test
    cerberus benchmark
)" << std::endl;
}

void printVersion() {
  std::cout << "CERBERUS Forensic Suite v3.0\n";
  std::cout << "Developed by Zeca | Sentinel Data Solutions\n";
  std::cout << "Triple-Headed Password Recovery & Forensic Audit Engine\n";
  std::cout << "Engine Architecture: Explicit backend selection (strict); automatic fallback only when engine is not specified\n";
}

void initHardwareAuto() {
  globalEngineExplicitlySelected = false;
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
      std::cout << "\x1b[1;32m[+] Hardware Auto: NVIDIA CUDA Ativado ("
                << terminalSafeText(getRealGPUName()) << ")\x1b[0m\n";
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

bool initEngine(const std::string &engineStr) {
  globalEngineExplicitlySelected = true;
  if (engineStr == "cuda") {
    globalCompute = ComputeType::CPU;
    return initCUDA();
  } else if (engineStr == "opencl") {
    if (!initOpenCL()) {
      globalCompute = ComputeType::CPU;
      return false;
    }
    globalCompute = ComputeType::OPENCL;
    return true;
  } else {
    globalCompute = ComputeType::CPU;
    return true;
  }
}

int runEnvironmentDoctor() {
  const std::filesystem::path appDirectory = executableDirectory();
  std::error_code currentPathError;
  const std::filesystem::path workingDirectory =
      std::filesystem::current_path(currentPathError);
  const std::filesystem::path wordlistPath = defaultDataFilePath("wordlist.txt");
  const std::filesystem::path saltlistPath = defaultDataFilePath("saltlist.txt");
  const bool wordlistAvailable = fileExists(pathToUtf8(wordlistPath));
  const bool saltlistAvailable = fileExists(pathToUtf8(saltlistPath));
  const unsigned int cpuThreads = std::thread::hardware_concurrency();
#if defined(ENABLE_CUDA)
  const bool cudaCompiled = true;
#else
  const bool cudaCompiled = false;
#endif
  const std::string engineName = getEngineName();
  const std::string gpuName = getRealGPUName();
  const std::string vram = getRealVRAM();
  const std::string vramDisplay = vram == "N/A" ? vram : vram + " MB";
  const std::string appDirectoryText = pathToUtf8(appDirectory);
  const std::string workingDirectoryText =
      currentPathError ? std::string() : pathToUtf8(workingDirectory);

  if (globalJson) {
    std::cout << "{\"status\":\"ready\",\"engine\":\""
              << jsonEscape(engineName) << "\",\"device\":\""
              << jsonEscape(gpuName) << "\",\"vram_mb\":\""
              << jsonEscape(vram) << "\",\"cuda_compiled\":"
              << (cudaCompiled ? "true" : "false")
              << ",\"cpu_threads\":" << cpuThreads
              << ",\"executable_directory\":\""
              << jsonEscape(appDirectoryText) << "\",\"working_directory\":\""
              << jsonEscape(workingDirectoryText)
              << "\",\"wordlist_available\":"
              << (wordlistAvailable ? "true" : "false")
              << ",\"wordlist_path\":\""
              << jsonEscape(pathToUtf8(wordlistPath))
              << "\",\"saltlist_available\":"
              << (saltlistAvailable ? "true" : "false")
              << ",\"saltlist_path\":\""
              << jsonEscape(pathToUtf8(saltlistPath)) << "\"}\n";
    return 0;
  }
  if (globalQuiet) {
    std::cout << "engine:" << encodeQuietField(engineName) << "\n"
              << "device:" << encodeQuietField(gpuName) << "\n"
              << "cuda_compiled:" << (cudaCompiled ? "true" : "false")
              << "\n"
              << "cpu_threads:" << cpuThreads << "\n"
              << "executable_directory:"
              << encodeQuietField(appDirectoryText) << "\n"
              << "working_directory:" << encodeQuietField(workingDirectoryText)
              << "\n"
              << "wordlist_available:" << (wordlistAvailable ? "true" : "false")
              << "\n"
              << "wordlist_path:" << encodeQuietField(pathToUtf8(wordlistPath))
              << "\n"
              << "saltlist_available:" << (saltlistAvailable ? "true" : "false")
              << "\n"
              << "saltlist_path:" << encodeQuietField(pathToUtf8(saltlistPath))
              << "\n";
    return 0;
  }

  std::cout << "\n[CERBERUS] Configuracao detectada neste ambiente\n"
            << "-----------------------------------------------\n"
            << "Motor automatico : " << terminalSafeText(engineName) << "\n"
            << "Dispositivo      : " << terminalSafeText(gpuName) << "\n"
            << "VRAM             : " << terminalSafeText(vramDisplay) << "\n"
            << "CUDA na build    : " << (cudaCompiled ? "sim" : "nao") << "\n"
            << "Threads CPU      : " << cpuThreads << "\n"
            << "Executavel       : " << terminalSafeText(appDirectoryText) << "\n"
            << "Pasta atual      : " << terminalSafeText(workingDirectoryText)
            << "\n"
            << "Wordlist         : "
            << (wordlistAvailable ? "encontrada em " : "nao encontrada; esperado em ")
            << terminalSafeText(pathToUtf8(wordlistPath)) << "\n"
            << "Saltlist         : "
            << (saltlistAvailable ? "encontrada em " : "nao encontrada; esperado em ")
            << terminalSafeText(pathToUtf8(saltlistPath)) << "\n"
            << "Potfile          : "
            << terminalSafeText(pathToUtf8(
                   (currentPathError ? std::filesystem::path(".")
                                     : workingDirectory) /
                   "cracked_passwords.txt"))
            << "\n"
            << "Para usar deteccao automatica: cerberus crack <hash>\n"
            << "Para fixar o motor: acrescente --engine cpu, opencl ou cuda.\n";
  return 0;
}

void generateAndDisplayHashes(const std::string &target, const std::string &salt = "salt") {
  const std::string &activeSalt = salt;
  const std::string ntlmHash = ntlm(target);
  if (globalQuiet) {
    std::cout << "crc32:" << crc32(target) << "\n"
              << "base64:" << base64_encode(reinterpret_cast<const unsigned char *>(target.data()), target.length()) << "\n"
              << "md5:" << md5(target) << "\n"
              << "ntlm:" << (ntlmHash.empty() ? "[INVALID_UTF8]" : ntlmHash) << "\n"
              << "md4:" << md4(target) << "\n"
              << "sha1:" << sha1(target) << "\n"
              << "sha224:" << sha224(target) << "\n"
              << "sha256:" << sha256(target) << "\n"
              << "sha384:" << sha384(target) << "\n"
              << "sha512:" << sha512(target) << "\n"
              << "hmac-md5:" << hmac_md5(activeSalt, target) << "\n"
              << "hmac-sha1:" << hmac_sha1(activeSalt, target) << "\n"
              << "hmac-sha256:" << hmac_sha256(activeSalt, target) << "\n"
              << "pbkdf2-sha1:" << pbkdf2_hmac_sha1(target, activeSalt, 4096, 32) << "\n";
    return;
  }
  if (globalJson) {
    std::cout << "{\n  ";
    writeJsonTextOrBase64(std::cout, "plaintext", target);
    std::cout << ",\n  ";
    writeJsonTextOrBase64(std::cout, "hmac_key", activeSalt);
    std::cout << ",\n  ";
    writeJsonTextOrBase64(std::cout, "pbkdf2_salt", activeSalt);
    std::cout << ",\n"
              << "  \"pbkdf2_iterations\": 4096,\n"
              << "  \"crc32\": \"" << crc32(target) << "\",\n"
              << "  \"base64\": \"" << base64_encode(reinterpret_cast<const unsigned char *>(target.data()), target.length()) << "\",\n"
              << "  \"md5\": \"" << md5(target) << "\",\n";
    if (ntlmHash.empty()) {
      std::cout << "  \"ntlm\": null,\n"
                << "  \"ntlm_error\": \"Input must be valid UTF-8 for NTLM\",\n";
    } else {
      std::cout << "  \"ntlm\": \"" << ntlmHash << "\",\n";
    }
    std::cout << "  \"md4\": \"" << md4(target) << "\",\n"
              << "  \"sha1\": \"" << sha1(target) << "\",\n"
              << "  \"sha224\": \"" << sha224(target) << "\",\n"
              << "  \"sha256\": \"" << sha256(target) << "\",\n"
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
  std::cout << "Texto:       \"" << terminalSafeText(target) << "\"\n";
  std::cout << "CRC32:       " << crc32(target) << " \x1b[1;30m(IEEE 802.3 Checksum)\x1b[0m\n";
  std::cout << "Base64:      " << base64_encode(reinterpret_cast<const unsigned char *>(target.data()), target.length()) << "\n";
  std::cout << "MD5:         " << md5(target) << "\n";
  std::cout << "NTLM:        "
            << (ntlmHash.empty()
                    ? "[indisponivel: entrada nao e UTF-8 valido]"
                    : ntlmHash + " \x1b[1;33m(Windows SAM / Active Directory)\x1b[0m")
            << "\n";
  std::cout << "MD4:         " << md4(target) << "\n";
  std::cout << "SHA1:        " << sha1(target) << "\n";
  std::cout << "SHA224:      " << sha224(target) << " \x1b[1;30m(FIPS 180-4)\x1b[0m\n";
  std::cout << "SHA256:      " << sha256(target) << "\n";
  std::cout << "SHA384:      " << sha384(target) << " \x1b[1;30m(FIPS 180-4)\x1b[0m\n";
  std::cout << "SHA512:      " << sha512(target) << " \x1b[1;30m(FIPS 180-4)\x1b[0m\n";
  std::cout << "HMAC-MD5:    " << hmac_md5(activeSalt, target)
            << " \x1b[1;30m(key='" << terminalSafeText(activeSalt) << "')\x1b[0m\n";
  std::cout << "HMAC-SHA1:   " << hmac_sha1(activeSalt, target)
            << " \x1b[1;30m(key='" << terminalSafeText(activeSalt) << "')\x1b[0m\n";
  std::cout << "HMAC-SHA256: " << hmac_sha256(activeSalt, target)
            << " \x1b[1;30m(key='" << terminalSafeText(activeSalt) << "')\x1b[0m\n";
  std::cout << "PBKDF2-SHA1: " << pbkdf2_hmac_sha1(target, activeSalt, 4096, 32) << " \x1b[1;30m(RFC 2898 / WPA2-PSK c=4096)\x1b[0m\n";
  std::cout << "----------------------------------------------------------------------------\n";
}

// --- Unified Auto-Pilot Execution (Zero-Click Pipeline) ---
AttackResult autoExecuteAttack(const std::string &rawTarget, const std::string &salt = "",
                               int charsetId = 5, int maxLen = 16, bool skipDict = false, int alvoId = 0,
                               const std::string &customWordlist = "wordlist.txt", bool noPotfile = false,
                               bool requireHash = false, bool saltWasProvided = false) {
  AttackResult result;
  const ComputeType requestedEngine = globalCompute;
  globalEngineFailure.clear();
  std::string target = rawTarget;
  if (target.empty()) {
    result.method = "Invalid target";
    if (globalJson) {
      std::cout << "{\"status\":\"invalid_input\",\"target\":\"\","
                   "\"error\":\"Target must not be empty\"}\n";
    } else if (globalQuiet) {
      std::cout << ":[INVALID_TARGET]\n";
    } else {
      std::cerr << "[!] Alvo vazio: informe um hash ou texto.\n";
    }
    return result;
  }

  result.target = target;
  std::string activeSalt = salt;
  const bool explicitSalt = saltWasProvided || !salt.empty();
  HashType prefixedType = HashType::UNKNOWN;
  bool ambiguousInlineSaltFormat = false;

  // Auto-detect 'hash:salt' or 'salt:hash' standard forensic formats
  size_t sep = target.find_first_of(":");
  if (sep != std::string::npos && sep > 0 && sep < target.length() - 1) {
    std::string partA = target.substr(0, sep);
    std::string partB = target.substr(sep + 1);
    prefixedType = parseHashTypeLabel(partA);
    if (prefixedType != HashType::UNKNOWN) {
      target = partB;
      const size_t saltSep = target.find(':');
      if (saltSep != std::string::npos && saltSep > 0 &&
          saltSep < target.length() - 1) {
        const std::string digest = target.substr(0, saltSep);
        if (isHex(digest)) {
          const HashType saltedType = saltedTypeForDigestLength(digest.size());
          target = digest;
          if (!explicitSalt) activeSalt = partB.substr(saltSep + 1);
          if ((prefixedType == HashType::MD5 && saltedType == HashType::SALTED_MD5) ||
              (prefixedType == HashType::SHA1 && saltedType == HashType::SALTED_SHA1) ||
              (prefixedType == HashType::SHA256 && saltedType == HashType::SALTED_SHA256) ||
              (prefixedType == HashType::SHA512 && saltedType == HashType::SALTED_SHA512)) {
            prefixedType = saltedType;
          }
        }
      }
    } else {
      const bool partAIsDigest = isHex(partA) &&
                                 isRecognizedDigestLength(partA.size());
      // Split from the right so a salt such as "realm:account" remains
      // intact in the supported salt:hash representation.
      const size_t finalSep = target.rfind(':');
      const bool hasSaltAndDigest =
          finalSep != std::string::npos && finalSep > 0 &&
          finalSep < target.length() - 1;
      const std::string finalPart = hasSaltAndDigest
                                        ? target.substr(finalSep + 1)
                                        : std::string();
      const bool finalPartIsDigest =
          isHex(finalPart) && isRecognizedDigestLength(finalPart.size());
      if (partAIsDigest && finalPartIsDigest) {
        // Both orientations are syntactically plausible (for example, a
        // hexadecimal salt beside a hexadecimal digest). Do not guess.
        ambiguousInlineSaltFormat = true;
      } else if (partAIsDigest) {
        target = partA;
        const HashType saltedType = saltedTypeForDigestLength(partA.size());
        prefixedType = saltedType == HashType::UNKNOWN
                           ? identifyHash(partA)
                           : saltedType;
        if (!explicitSalt) activeSalt = partB;
      } else {
        if (finalPartIsDigest) {
          target = finalPart;
          const HashType saltedType =
              saltedTypeForDigestLength(finalPart.size());
          prefixedType = saltedType == HashType::UNKNOWN
                             ? identifyHash(finalPart)
                             : saltedType;
          if (!explicitSalt) activeSalt = rawTarget.substr(0, finalSep);
        }
      }
    }
  }

  // Preserve the requested or inline salt in batch results even when this
  // target is invalid, unsupported, incomplete, or exhausted. Successful
  // results replace it with the salt that actually matched.
  result.salt = activeSalt;

  if (ambiguousInlineSaltFormat) {
    result.target = rawTarget;
    result.method = "Invalid target";
    if (globalJson) {
      std::cout << "{\"status\":\"invalid_input\",\"target\":\""
                << jsonEscape(rawTarget)
                << "\",\"error\":\"Inline salt/hash orientation is ambiguous; provide the digest alone and pass the salt with --salt\"}\n";
    } else if (globalQuiet) {
      std::cout << encodeQuietField(rawTarget) << ":[INVALID_TARGET]\n";
    } else {
      std::cerr << "[!] A orientacao entre salt e hash e ambigua; informe apenas o digest e passe o salt com --salt.\n";
    }
    return result;
  }

  // Include salts extracted from inline target forms, not only --salt.
  const bool saltRequested = explicitSalt || !activeSalt.empty();

  // Hex digests are case-insensitive, while Base64 is case-sensitive. A
  // Base64 target may consist only of hex characters, so preserve its case
  // when explicitly selected or recognized by automatic detection/fallback.
  bool base64Requested = prefixedType == HashType::BASE64 || alvoId == 106;
  if (!base64Requested && prefixedType == HashType::UNKNOWN && alvoId == 0 &&
      isHex(target)) {
    const HashType detectedType = identifyHash(target);
    if (detectedType == HashType::BASE64) {
      base64Requested = true;
    } else if (requireHash && detectedType == HashType::UNKNOWN) {
      std::string decodedBase64;
      base64Requested = isBase64Strict(target, decodedBase64);
    }
  }
  if (!base64Requested && isHex(target)) {
    for (char &c : target) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  } else {
    size_t colon = target.find(':');
    if (colon != std::string::npos && colon < target.length() - 1) {
      std::string pfx = target.substr(0, colon);
      std::string hx = target.substr(colon + 1);
      if (isHex(hx)) {
        for (char &c : hx) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        target = pfx + ":" + hx;
      }
    }
  }

  result.target = target;
  HashType type = prefixedType != HashType::UNKNOWN
                      ? prefixedType
                      : identifyHash(target);
  if (type == HashType::UNKNOWN && requireHash) {
    std::string decodedBase64;
    if (isBase64Strict(target, decodedBase64)) type = HashType::BASE64;
  }
  const bool algorithmPinned = prefixedType != HashType::UNKNOWN || alvoId > 0;

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
  } else if (explicitSalt) {
    if (type == HashType::MD5) type = HashType::SALTED_MD5;
    else if (type == HashType::SHA1) type = HashType::SALTED_SHA1;
    else if (type == HashType::SHA256) type = HashType::SALTED_SHA256;
    else if (type == HashType::SHA512) type = HashType::SALTED_SHA512;
  }
  result.type = type;

  if (saltRequested &&
      (type == HashType::SHA224 || type == HashType::SHA384)) {
    result.method = "Invalid target";
    if (globalJson) {
      std::cout << "{\"status\":\"invalid_input\",\"target\":\""
                << jsonEscape(target) << "\",\"algorithm\":\""
                << jsonEscape(hashTypeName(type))
                << "\",\"error\":\"Salted SHA-224 and SHA-384 are not supported\"}\n";
    } else if (globalQuiet) {
      std::cout << encodeQuietField(target) << ":[INVALID_TARGET]\n";
    } else {
      std::cerr << "[!] Salted SHA-224/SHA-384 nao estao implementados; remova o salt ou use um algoritmo salted suportado.\n";
    }
    return result;
  }

  if ((requireHash || saltRequested) && type == HashType::UNKNOWN) {
    result.method = "Invalid target";
    if (globalQuiet) {
      std::cout << encodeQuietField(target) << ":[INVALID_TARGET]\n";
    } else if (globalJson) {
      std::cout << "{\n  \"status\": \"invalid_input\",\n  \"target\": \""
                << jsonEscape(target) << "\",\n  \"error\": \"Target is not a recognized hash or encoding\"\n}\n";
    } else {
      std::cout << "[!] Alvo invalido: informe um hash reconhecido ou selecione --algo.\n";
    }
    return result;
  }

  if (type == HashType::WPA3_SAE) {
    result.method = "Unsupported real format";
    if (globalQuiet) {
      std::cout << encodeQuietField(target) << ":[UNSUPPORTED_FORMAT]\n";
    } else if (globalJson) {
      std::cout << "{\n  \"status\": \"unsupported\",\n  \"target\": \"" << jsonEscape(target)
                << "\",\n  \"algorithm\": \"" << jsonEscape(hashTypeName(type))
                << "\",\n  \"error\": \"A passive SAE capture does not provide a generic offline password verifier\"\n}\n";
    } else {
      std::cout << "[!] WPA3 SAE em captura passiva nao fornece um verificador offline generico; nenhuma tentativa foi executada.\n";
    }
    return result;
  }

  const bool typeUsesSalt =
      type == HashType::HMAC_MD5 || type == HashType::HMAC_SHA1 ||
      type == HashType::HMAC_SHA256 ||
      (type >= HashType::SALTED_MD5 && type <= HashType::SALTED_SHA512) ||
      type == HashType::WPA2_PBKDF2;
  if (saltRequested && !typeUsesSalt) {
    result.method = "Invalid target";
    if (globalJson) {
      std::cout << "{\"status\":\"invalid_input\",\"target\":\""
                << jsonEscape(target)
                << "\",\"algorithm\":\"" << jsonEscape(hashTypeName(type))
                << "\",\"error\":\"The selected algorithm does not use a salt; choose a salted variant or remove --salt\"}\n";
    } else if (globalQuiet) {
      std::cout << encodeQuietField(target) << ":[INVALID_TARGET]\n";
    } else {
      std::cerr << "[!] O algoritmo " << hashTypeName(type)
                << " nao usa salt; selecione uma variante salted ou remova --salt.\n";
    }
    return result;
  }

  if (type == HashType::BCRYPT) {
    const int cost = bcryptCost(target);
    if (cost < 0) {
      result.method = "Invalid target";
      if (globalQuiet) {
        std::cout << encodeQuietField(target) << ":[INVALID_TARGET]\n";
      } else if (globalJson) {
        std::cout << "{\"status\":\"invalid_input\",\"target\":\""
                  << jsonEscape(target)
                  << "\",\"algorithm\":\"bcrypt\",\"error\":\"Malformed bcrypt hash\"}\n";
      } else {
        std::cout << "[!] Hash bcrypt malformado.\n";
      }
      return result;
    }
    if (cost > 20) {
      result.method = "Invalid or unsupported bcrypt cost";
      if (globalQuiet) {
        std::cout << encodeQuietField(target) << ":[UNSUPPORTED_BCRYPT_COST]\n";
      } else if (globalJson) {
        std::cout << "{\"status\":\"unsupported\",\"target\":\""
                  << jsonEscape(target)
                  << "\",\"algorithm\":\"bcrypt\",\"error\":\"Valid bcrypt hashes with cost 4..20 are supported\"}\n";
      } else {
        std::cout << "[!] Hash bcrypt valido, mas o custo excede o limite suportado (maximo 20).\n";
      }
      return result;
    }
  }

  if (type != HashType::UNKNOWN && !isValidHashTarget(target, type)) {
    result.method = "Invalid target";
    if (globalQuiet) {
      std::cout << encodeQuietField(target) << ":[INVALID_TARGET]\n";
    } else if (globalJson) {
      std::cout << "{\"status\":\"invalid_input\",\"target\":\""
                << jsonEscape(target)
                << "\",\"algorithm\":\"" << jsonEscape(hashTypeName(type))
                << "\",\"error\":\"Target encoding or digest length is invalid\"}\n";
    } else {
      std::cout << "[!] O alvo nao corresponde ao formato esperado para "
                << hashTypeName(type) << ".\n";
    }
    return result;
  }

  if (type == HashType::SCRYPT) {
    ScryptPhcTarget parsed;
    if (!parseScryptPhc(target, parsed)) {
      result.method = "Invalid target";
      if (globalQuiet) {
        std::cout << encodeQuietField(target) << ":[INVALID_TARGET]\n";
      } else if (globalJson) {
        std::cout << "{\"status\":\"invalid_input\",\"target\":\""
                  << jsonEscape(target)
                  << "\",\"algorithm\":\"scrypt\",\"error\":\"Malformed scrypt PHC string\"}\n";
      } else {
        std::cout << "[!] String scrypt PHC malformada.\n";
      }
      return result;
    }
    if (!scryptWithinResourcePolicy(parsed)) {
      result.method = "Invalid or unsupported scrypt cost";
      if (globalQuiet) {
        std::cout << encodeQuietField(target) << ":[UNSUPPORTED_SCRYPT_COST]\n";
      } else if (globalJson) {
        std::cout << "{\"status\":\"unsupported\",\"target\":\""
                  << jsonEscape(target)
                  << "\",\"algorithm\":\"scrypt\",\"error\":\"PHC cost exceeds configured limits (256 MiB and 2^26 N*r*p work units)\"}\n";
      } else {
        std::cout << "[!] O custo scrypt e valido, mas excede o limite operacional do CERBERUS (256 MiB ou 2^26 unidades N*r*p).\n";
      }
      return result;
    }
  }

  // Hex digests are case-insensitive. Canonicalize them before the CPU/GPU
  // verifiers compare their lowercase output with the requested target.
  if (type != HashType::UNKNOWN && type != HashType::TEXT &&
      type != HashType::BASE64 && type != HashType::BCRYPT && isHex(target)) {
    lowercaseAscii(target);
  }

  if (type == HashType::WPA2_PBKDF2 && activeSalt.length() > 32) {
    result.method = "Invalid WPA2 SSID";
    if (globalQuiet) {
      std::cout << encodeQuietField(target) << ":[INVALID_SSID]\n";
    } else if (globalJson) {
      std::cout << "{\n  \"status\": \"invalid_input\",\n  \"target\": \""
                << jsonEscape(target) << "\",\n  \"algorithm\": \"WPA2 PMK (PBKDF2-HMAC-SHA1)\",\n"
                << "  \"error\": \"WPA2 SSID must be at most 32 bytes\"\n}\n";
    } else {
      std::cout << "[!] O SSID WPA2 deve ter no maximo 32 bytes; informe o SSID em --salt.\n";
    }
    return result;
  }

  // Case 1: Base64 Decodification
  if (type == HashType::BASE64) {
    std::string decoded = base64_decode(target);
    if (!globalQuiet && !globalJson) {
      std::cout << "\n\x1b[1;36m[AUTO-DETECT]\x1b[0m Base64 detectado com precisao!\n";
      std::cout << "--------------------------------------------------\n";
      std::cout << "Decodificado: \x1b[1;32m"
                << terminalSafeText(decoded) << "\x1b[0m\n";
      std::cout << "--------------------------------------------------\n";
    } else if (globalQuiet) {
      std::cout << encodeQuietField(target) << ":"
                << encodeQuietField(decoded) << "\n";
    } else if (globalJson) {
      std::cout << "{\n  \"status\": \"decoded\",\n  \"target\": \""
                << jsonEscape(target) << "\",\n  ";
      writeJsonTextOrBase64(std::cout, "plaintext", decoded);
      std::cout << ",\n  \"algorithm\": \"Base64\"\n}\n";
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
  config.saltProvided = saltWasProvided || !activeSalt.empty();
  config.maxLength = maxLen;
  config.charset = getCharset(charsetId);
  if (globalVerbose) {
    std::cerr << "[verbose] algorithm=" << hashTypeName(config.type)
              << " backend_before_search=" << terminalSafeText(getEngineName())
              << " candidate_lengths=1.." << config.maxLength
              << " charset_size=" << config.charset.size()
              << " dictionary=" << (skipDict ? "disabled" : "enabled")
              << " potfile=" << (noPotfile ? "disabled" : "enabled")
              << "\n";
  }

  // Case 3: Target is a Hash -> Auto Recovery Pipeline
  if (!globalQuiet && !globalJson) {
    std::cout << "\n\x1b[1;36m[CERBERUS FORENSIC PIPELINE]\x1b[0m\n";
    std::cout << "--------------------------------------------------\n";
    std::cout << "[i] Algoritmo: \x1b[1;33m" << hashTypeName(config.type);
    if (target.length() == 32 && !algorithmPinned) {
      std::cout << " (Compativeis: NTLM, MD4)";
    }
    std::cout << "\x1b[0m\n";
    std::cout << "[i] Alvo:      \x1b[1;37m"
              << terminalSafeText(config.target) << "\x1b[0m\n";
    if (!activeSalt.empty()) {
      std::cout << "[i] Salt:      " << terminalSafeText(activeSalt) << "\n";
    }
    std::cout << "[i] Motor:     \x1b[1;32m"
              << terminalSafeText(getEngineName()) << "\x1b[0m\n";
    std::cout << "[i] Charset:   " << config.charset.length() << " caracteres (Alfanumerico)\n";
    std::cout << "--------------------------------------------------\n";
  }

  // Step 0: Check Forensic Potfile / Cache
  std::string potPass;
  HashType potType = config.type;
  std::string potSalt;
  const bool allowPotfileAnySalt = !explicitSalt && activeSalt.empty() &&
      ((config.type >= HashType::SALTED_MD5 &&
        config.type <= HashType::SALTED_SHA512) ||
       config.type == HashType::WPA2_PBKDF2);
  const auto cacheLookupStart = std::chrono::steady_clock::now();
  bool potHit = !noPotfile &&
      checkPotfile(config.target, config.salt, config.type, potPass, potType,
                   "cracked_passwords.txt", allowPotfileAnySalt, &potSalt);
  if (!potHit && !noPotfile && config.type == HashType::MD5 &&
      activeSalt.empty() && !algorithmPinned) {
    for (HashType alternative : {HashType::NTLM, HashType::MD4}) {
      if (checkPotfile(config.target, config.salt, alternative, potPass, potType)) {
        potHit = true;
        break;
      }
    }
  }
  if (potHit) {
    const double cacheLookupMs = std::chrono::duration<double, std::milli>(
                                     std::chrono::steady_clock::now() -
                                     cacheLookupStart)
                                     .count();
    logPotfileHit(config.target, potPass, potType, potSalt, cacheLookupMs);
    result.success = true;
    result.fromPotfile = true;
    result.recoveredPass = potPass;
    result.salt = potSalt;
    result.type = potType;
    result.method = "Potfile Cache";
    result.engine = "CPU (potfile verification)";
    // A cache lookup verifies no candidate guesses; keep attack statistics at 0.
    result.attempts = 0;
    result.durationMs = 0;
    return result;
  }

  auto attackStart = std::chrono::high_resolution_clock::now();
  long long dictionaryAttempts = 0;
  auto reportSelectedEngineFailure = [&](const std::string &reason,
                                         long long attempts = 0) {
    result.method = "Unsupported selected engine";
    result.type = config.type;
    result.engine = getEngineName();
    result.attempts = attempts;
    result.durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now() - attackStart).count();
    if (globalJson) {
      std::cout << "{\"status\":\"unsupported\",\"target\":\""
                << jsonEscape(config.target) << "\",\"algorithm\":\""
                << jsonEscape(hashTypeName(config.type)) << "\",\"engine\":\""
                << jsonEscape(getEngineName()) << "\",\"attempts\":"
                << result.attempts << ",\"time_ms\":" << result.durationMs
                << ",\"error\":\""
                << jsonEscape(reason) << "\"}\n";
    } else if (globalQuiet) {
      std::cout << encodeQuietField(config.target) << ":[UNSUPPORTED_ENGINE]\n";
    } else {
      std::cerr << "[!] Motor selecionado incompatível: " << reason
                << ". Nenhum fallback para outro motor foi feito.\n";
    }
  };
  if (globalEngineExplicitlySelected && globalCompute != ComputeType::CPU &&
      !computeEngineSupportsHashType(globalCompute, config.type)) {
    reportSelectedEngineFailure(
        hashTypeName(config.type) + " nao possui kernel " +
        (globalCompute == ComputeType::CUDA ? "CUDA" : "OpenCL"));
    return result;
  }

  auto reportIncompleteSaltList = [&]() {
    result.method = "Incomplete salt list";
    result.type = config.type;
    result.attempts = dictionaryAttempts;
    result.durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now() - attackStart).count();
    if (globalJson) {
      std::cout << "{\"status\":\"incomplete\",\"target\":\""
                << jsonEscape(config.target) << "\",\"algorithm\":\""
                << jsonEscape(hashTypeName(config.type)) << "\",\"attempts\":"
                << result.attempts << ",\"time_ms\":" << result.durationMs
                << ",\"error\":\"saltlist.txt could not be opened or read completely; search was not exhaustive\"}\n";
    } else if (globalQuiet) {
      std::cout << encodeQuietField(config.target) << ":[INCOMPLETE_SALTLIST]\n";
    }
  };

  if (globalEngineExplicitlySelected && globalCompute != ComputeType::CPU) {
    bool selectedSaltListReadError = false;
    const std::vector<std::string> selectedSalts =
        loadSalts(config, &selectedSaltListReadError);
    if (selectedSaltListReadError) {
      reportIncompleteSaltList();
      return result;
    }
    size_t maxSaltLength = 0;
    for (const auto &selectedSalt : selectedSalts)
      maxSaltLength = std::max(maxSaltLength, selectedSalt.size());
    std::string incompatibility;
    if (globalCompute == ComputeType::CUDA &&
        (selectedSalts.size() != 1 || selectedSalts[0] != config.salt)) {
      incompatibility = "CUDA nao percorre saltlist com multiplos salts";
    } else if (std::any_of(
                   selectedSalts.begin(), selectedSalts.end(),
                   [](const std::string &selectedSalt) {
                     return selectedSalt.find('\0') != std::string::npos;
                   })) {
      incompatibility =
          "salt contem byte NUL, nao representavel pelos kernels GPU";
    } else if (globalCompute == ComputeType::CUDA &&
               static_cast<size_t>(config.maxLength) + maxSaltLength >
                   ((config.type == HashType::SHA512 ||
                     config.type == HashType::SALTED_SHA512) ? 239 : 119)) {
      incompatibility = "entrada excede o buffer seguro do kernel CUDA";
    } else if (globalCompute == ComputeType::OPENCL &&
               static_cast<size_t>(config.maxLength) + maxSaltLength >
                   ((config.type == HashType::SHA512 ||
                     config.type == HashType::SALTED_SHA512) ? 239 : 119)) {
      incompatibility = "entrada excede o buffer seguro do kernel OpenCL";
    } else if (config.type == HashType::NTLM &&
               (config.maxLength > 59 ||
                !std::all_of(config.charset.begin(), config.charset.end(),
                             [](unsigned char c) { return c < 0x80; }))) {
      incompatibility =
          "kernel NTLM exige charset ASCII e limite de 59 bytes";
    }
    if (!incompatibility.empty()) {
      reportSelectedEngineFailure(incompatibility);
      return result;
    }
    int maxSupportedLength = 0;
    if (globalCompute == ComputeType::OPENCL &&
        !gpuKeyspaceFitsCounters(config.charset.size(), config.maxLength,
                                 selectedSalts.size(), 0,
                                 maxSupportedLength)) {
      reportSelectedEngineFailure(
          "max-len " + std::to_string(config.maxLength) + " exceeds " +
          "OpenCL 64-bit keyspace/report limits for charset " +
          std::to_string(config.charset.size()) + " and " +
          std::to_string(selectedSalts.size()) + " salt(s); maximum supported "
          "max-len is " + std::to_string(maxSupportedLength) +
          "; choose a lower --max-len");
      return result;
    }
  }

  // Step 1: Dictionary attack with rule mutations
  bool dictFound = false;
  bool saltListReadError = false;
  bool wordlistReadError = false;
  std::string activeWordlist = customWordlist.empty() ? "wordlist.txt" : customWordlist;
  if (activeWordlist == "wordlist.txt")
    activeWordlist = pathToUtf8(defaultDataFilePath(activeWordlist));
  const bool wordlistAvailable = fileExists(activeWordlist);
  if (!skipDict && wordlistAvailable) {
    result.engine = "CPU (Dictionary)";
    if (!globalQuiet && !globalJson) {
      if (globalEngineExplicitlySelected &&
          globalCompute != ComputeType::CPU)
        std::cout << "[i] Wordlist/mutacoes e potfile usam CPU; o motor selecionado sera usado na busca de forca bruta.\n";
      std::cout << "[1/2] Verificando dicionario forense ("
                << terminalSafeText(activeWordlist) << " + mutacoes)...\n";
    }
    long long currentDictionaryAttempts = 0;
    dictFound = dictionaryAttack(config, activeWordlist, &currentDictionaryAttempts,
                                 dictionaryAttempts, &saltListReadError,
                                 &wordlistReadError);
    dictionaryAttempts =
        saturatingAttemptAdd(dictionaryAttempts, currentDictionaryAttempts);

    // A bare 32-hex target is ambiguous: try NTLM and raw MD4 unless pinned by --algo.
    if (!saltListReadError && !wordlistReadError && !dictFound &&
        config.type == HashType::MD5 && activeSalt.empty() &&
        !algorithmPinned) {
      const HashType alternatives[] = {HashType::NTLM, HashType::MD4};
      for (HashType alternative : alternatives) {
        Config alternateConfig = config;
        alternateConfig.type = alternative;
        alternateConfig.hashType = getKernelAlgoId(alternative);
        if (!globalQuiet && !globalJson)
          std::cout << "[i] Testando hipotese " << hashTypeName(alternative)
                    << " no dicionario...\n";
        currentDictionaryAttempts = 0;
        dictFound = dictionaryAttack(alternateConfig, activeWordlist,
                                     &currentDictionaryAttempts,
                                     dictionaryAttempts, &saltListReadError,
                                     &wordlistReadError);
        dictionaryAttempts =
            saturatingAttemptAdd(dictionaryAttempts, currentDictionaryAttempts);
        if (dictFound) {
          config = alternateConfig;
          break;
        }
      }
    }
  } else if (!skipDict && !wordlistAvailable) {
    static bool missingWordlistWarningShown = false;
    if (!missingWordlistWarningShown) {
      std::cerr << "[!] Dicionario padrao/selecionado '"
                << terminalSafeText(activeWordlist)
                << "' nao encontrado; busca seguira sem ataque de dicionario.\n";
      missingWordlistWarningShown = true;
    }
    wordlistReadError = true;
  } else if (skipDict && !globalQuiet && !globalJson) {
    std::cout << "[i] Ataque por dicionario pulado (--no-dict ativado).\n";
  }

  if (saltListReadError) {
    reportIncompleteSaltList();
    return result;
  }

  if (dictFound) {
    auto attackEnd = std::chrono::high_resolution_clock::now();
    result.success = true;
    result.recoveredPass = crackedPassword;
    result.salt = crackedSalt;
    result.type = config.type;
    result.method = "Dicionário Forense + Mutações";
    result.engine = "CPU (Dictionary)";
    result.attempts = dictionaryAttempts;
    result.durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(attackEnd - attackStart).count();
    return result;
  }

  bool hasWpa2SsidList = false;
  if (config.type == HashType::WPA2_PBKDF2 && activeSalt.empty() &&
      !saltWasProvided) {
    std::vector<std::string> ssids;
    hasWpa2SsidList = loadWpa2SsidList(ssids);
  }
  if (config.type == HashType::WPA2_PBKDF2 && activeSalt.empty() &&
      (saltWasProvided || !hasWpa2SsidList)) {
    // An explicitly empty SSID permits checking raw 64-hex PMKs from the
    // dictionary, but cannot verify passphrases and must not be called
    // exhaustive after a brute-force pass over candidates PBKDF2 rejects.
    result.method = "Incomplete WPA2 SSID";
    result.type = config.type;
    result.attempts = dictionaryAttempts;
    result.durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now() - attackStart).count();
    std::string error =
        "SSID is required to verify WPA2 passphrases; provide --salt or add SSIDs to readable saltlist.txt; without an SSID only 64-hex raw PSK candidates can be checked from the dictionary and brute-force is skipped";
    if (wordlistReadError) {
      error += "; wordlist '" + activeWordlist +
               "' could not be opened or read completely";
    }
    if (globalJson) {
      std::cout << "{\"status\":\"incomplete\",\"target\":\""
                << jsonEscape(config.target) << "\",\"algorithm\":\""
                << jsonEscape(hashTypeName(config.type)) << "\",\"attempts\":"
                << result.attempts << ",\"time_ms\":" << result.durationMs
                << ",\"error\":\"" << jsonEscape(error) << "\"}\n";
    } else if (globalQuiet) {
      std::cout << encodeQuietField(config.target)
                << ":[INCOMPLETE_WPA2_SSID]\n";
    } else {
      std::cerr << "[!] SSID necessario para validar passphrases WPA2; informe --salt ou adicione SSIDs ao saltlist.txt legivel. Sem SSID, somente candidatos PSK brutos de 64 caracteres hexadecimais da wordlist podem ser verificados e a forca bruta e pulada.";
      if (wordlistReadError)
        std::cerr << " Wordlist '" << terminalSafeText(activeWordlist)
                  << "' tambem nao foi lido por completo.";
      std::cerr << "\n";
    }
    return result;
  }

  // Step 2: Seamless automatic cascade to Brute Force!
  if (!globalQuiet && !globalJson) {
    std::cout << "\n[2/2] Nao encontrado no dicionario. Disparando Forca Bruta Automatica ("
              << terminalSafeText(getEngineName()) << ")...\n";
  }
  bool bfFound = runParallelBruteForce(config, false, &saltListReadError);
  if (saltListReadError) {
    reportIncompleteSaltList();
    return result;
  }
  if (!globalEngineFailure.empty()) {
    reportSelectedEngineFailure(
        globalEngineFailure,
        saturatingAttemptAdd(dictionaryAttempts, totalTentativas.load()));
    return result;
  }
  long long totalAttackAttempts =
      saturatingAttemptAdd(dictionaryAttempts, totalTentativas.load());
  if (!bfFound && config.type == HashType::MD5 && activeSalt.empty() &&
      !algorithmPinned) {
    const HashType alternatives[] = {HashType::NTLM, HashType::MD4};
    for (HashType alternative : alternatives) {
      Config alternateConfig = config;
      alternateConfig.type = alternative;
      alternateConfig.hashType = getKernelAlgoId(alternative);
      if (!globalQuiet && !globalJson)
        std::cout << "[i] Tentando hipotese " << hashTypeName(alternative)
                  << " na busca de forca bruta...\n";
      bfFound = runParallelBruteForce(alternateConfig, false,
                                      &saltListReadError);
      if (saltListReadError) {
        reportIncompleteSaltList();
        return result;
      }
      if (!globalEngineFailure.empty()) {
        reportSelectedEngineFailure(
            globalEngineFailure,
            saturatingAttemptAdd(totalAttackAttempts,
                                 totalTentativas.load()));
        return result;
      }
      totalAttackAttempts =
          saturatingAttemptAdd(totalAttackAttempts, totalTentativas.load());
      if (bfFound) {
        config = alternateConfig;
        break;
      }
    }
  }
  totalTentativas = totalAttackAttempts;
  auto attackEnd = std::chrono::high_resolution_clock::now();
  long long totalMs = std::chrono::duration_cast<std::chrono::milliseconds>(attackEnd - attackStart).count();

  if (bfFound) {
    config.salt = crackedSalt;
    const std::string method = globalCompute == ComputeType::OPENCL
        ? "Força Bruta GPU (OpenCL)"
        : (globalCompute == ComputeType::CUDA ? "Força Bruta GPU (CUDA)"
                                             : "Força Bruta CPU Multi-Threaded");
    logSuccess(crackedPassword, config.target, config.type, config.salt,
               totalAttackAttempts, totalMs, method);
    result.success = true;
    result.recoveredPass = crackedPassword;
    result.salt = config.salt;
    result.type = config.type;
    result.method = method;
    result.engine = getEngineName();
    result.attempts = totalAttackAttempts;
    result.durationMs = totalMs;
  } else {
    result.success = false;
    result.type = config.type;
    result.engine = getEngineName();
    result.attempts = totalAttackAttempts;
    result.durationMs = totalMs;
    if (wordlistReadError) {
      result.method = "Incomplete wordlist";
      if (globalJson) {
        std::cout << "{\"status\":\"incomplete\",\"target\":\""
                  << jsonEscape(config.target)
                  << "\",\"algorithm\":\"" << jsonEscape(hashTypeName(config.type))
                  << "\",\"attempts\":" << result.attempts
                  << ",\"time_ms\":" << result.durationMs
                  << ",\"error\":\"wordlist '" << jsonEscape(activeWordlist)
                  << "' could not be opened or read completely; search was not exhaustive\"}\n";
      } else if (globalQuiet) {
        std::cout << encodeQuietField(config.target) << ":[INCOMPLETE_WORDLIST]\n";
      }
    } else {
      result.method = "Exhausted";
      logExhausted(config.target, config.type, 1, config.maxLength,
                   static_cast<int>(config.charset.length()), totalAttackAttempts,
                   totalMs, getEngineName());
    }
  }
  // The result above records the backend used; preserve the selection for the
  // next interactive operation after any CPU fallback.
  globalCompute = requestedEngine;
  return result;
}

// Multi-Hash Batch File Processing with Executive Summary Report
bool readHashTargetLines(const std::string &filePath,
                         std::vector<std::string> &lines) {
  try {
    std::vector<std::string> parsedLines;
    std::ifstream file;
    file.open(pathFromUtf8(filePath), std::ios::binary);
    if (!file.is_open()) return false;

    unsigned char prefix[3] = {};
    file.read(reinterpret_cast<char *>(prefix), sizeof(prefix));
    const std::streamsize prefixSize = file.gcount();
    if (streamHasReadError(file)) return false;

    bool utf16LittleEndian = prefixSize >= 2 &&
                             prefix[0] == 0xFF && prefix[1] == 0xFE;
    bool utf16BigEndian = prefixSize >= 2 &&
                          prefix[0] == 0xFE && prefix[1] == 0xFF;
    std::streamoff dataOffset = 0;
    if (utf16LittleEndian || utf16BigEndian) {
      dataOffset = 2;
    } else if (prefixSize >= 3 && prefix[0] == 0xEF &&
               prefix[1] == 0xBB && prefix[2] == 0xBF) {
      dataOffset = 3;
    }
    file.clear();
    file.seekg(dataOffset, std::ios::beg);
    if (!file) return false;

    std::string line;
    if (!utf16LittleEndian && !utf16BigEndian) {
      while (readLineWithUniversalNewlines(file, line)) {
        if (!isValidUtf8(line)) return false;
        for (unsigned char c : line) {
          if (c < 0x20 && c != '\t') return false;
        }
        parsedLines.push_back(std::move(line));
        line.clear();
      }
      if (streamHasReadError(file)) return false;
      lines = std::move(parsedLines);
      return true;
    }

    enum class UnitStatus { VALUE, END, FAILURE };
    auto readUnit = [&file, utf16LittleEndian](uint16_t &unit) {
      const int first = file.get();
      if (first == std::char_traits<char>::eof())
        return file.eof() && !streamHasReadError(file) ? UnitStatus::END
                                                       : UnitStatus::FAILURE;
      const int second = file.get();
      if (second == std::char_traits<char>::eof()) return UnitStatus::FAILURE;
      const uint8_t firstByte = static_cast<uint8_t>(first);
      const uint8_t secondByte = static_cast<uint8_t>(second);
      unit = utf16LittleEndian
          ? static_cast<uint16_t>(firstByte |
                                  (static_cast<uint16_t>(secondByte) << 8))
          : static_cast<uint16_t>((static_cast<uint16_t>(firstByte) << 8) |
                                  secondByte);
      return UnitStatus::VALUE;
    };
    auto appendUtf8 = [&line](uint32_t cp) {
      if (cp <= 0x7F) {
        line.push_back(static_cast<char>(cp));
      } else if (cp <= 0x7FF) {
        line.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        line.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
      } else if (cp <= 0xFFFF) {
        line.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        line.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        line.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
      } else {
        line.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        line.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        line.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        line.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
      }
    };

    bool hasPendingUnit = false;
    uint16_t pendingUnit = 0;
    auto nextUnit = [&](uint16_t &unit) {
      if (hasPendingUnit) {
        unit = pendingUnit;
        hasPendingUnit = false;
        return UnitStatus::VALUE;
      }
      return readUnit(unit);
    };
    while (true) {
      uint16_t unit = 0;
      const UnitStatus status = nextUnit(unit);
      if (status == UnitStatus::END) break;
      if (status == UnitStatus::FAILURE) return false;

      if (unit == '\r' || unit == '\n') {
        parsedLines.push_back(std::move(line));
        line.clear();
        if (unit == '\r') {
          uint16_t next = 0;
          const UnitStatus nextStatus = readUnit(next);
          if (nextStatus == UnitStatus::FAILURE) return false;
          if (nextStatus == UnitStatus::VALUE && next != '\n') {
            pendingUnit = next;
            hasPendingUnit = true;
          }
        }
        continue;
      }
      if (unit < 0x20 && unit != '\t') return false;

      uint32_t codepoint = unit;
      if (unit >= 0xD800 && unit <= 0xDBFF) {
        uint16_t low = 0;
        if (nextUnit(low) != UnitStatus::VALUE || low < 0xDC00 ||
            low > 0xDFFF)
          return false;
        codepoint = 0x10000 +
                    ((static_cast<uint32_t>(unit) - 0xD800) << 10) +
                    (low - 0xDC00);
      } else if (unit >= 0xDC00 && unit <= 0xDFFF) {
        return false;
      }
      appendUtf8(codepoint);
    }
    if (!line.empty()) parsedLines.push_back(std::move(line));
    lines = std::move(parsedLines);
    return true;
  } catch (const std::bad_alloc &) {
    lines.clear();
    return false;
  } catch (const std::length_error &) {
    lines.clear();
    return false;
  } catch (const std::filesystem::filesystem_error &) {
    lines.clear();
    return false;
  }
}

void normalizeBatchTargetLine(std::string &line) {
  const size_t first = line.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) {
    line.clear();
    return;
  }
  const size_t last = line.find_last_not_of(" \t\r\n");
  line = line.substr(first, last - first + 1);

  if (line.size() >= 2 &&
      ((line.front() == '"' && line.back() == '"') ||
       (line.front() == '\'' && line.back() == '\''))) {
    line = line.substr(1, line.size() - 2);
  }
}

bool isSaltFirstBatchTarget(const std::string &line) {
  const size_t separator = line.rfind(':');
  if (separator == std::string::npos || separator == 0 ||
      separator + 1 >= line.size())
    return false;
  const std::string digest = line.substr(separator + 1);
  return isRecognizedDigestLength(digest.size()) && isHex(digest);
}

class DiscardOutputBuffer : public std::streambuf {
protected:
  int_type overflow(int_type character) override {
    return traits_type::not_eof(character);
  }

  std::streamsize xsputn(const char *, std::streamsize count) override {
    return count;
  }
};

int auditHashFile(const std::string &filePath, const std::string &salt = "",
                   int charsetId = 5, int maxLen = 16, bool skipDict = false, int alvoId = 0,
                   const std::string &customWordlist = "wordlist.txt", bool noPotfile = false,
                   bool saltWasProvided = false) {
  std::vector<std::string> fileLines;
  if (!readHashTargetLines(filePath, fileLines)) {
    if (globalJson) {
      std::cout << "{\"status\":\"invalid_input\",\"error\":\"Batch file could not be opened, decoded, or loaded\",\"file\":\""
                << jsonEscape(filePath) << "\"}\n";
    } else if (globalQuiet) {
      std::cerr << "[ERROR] batch file could not be opened, decoded, or loaded\n";
    } else {
      std::cout << "\x1b[1;31m[!] Arquivo de lote '"
                << terminalSafeText(filePath)
                << "' nao pode ser aberto, decodificado ou carregado.\x1b[0m\n";
    }
    return 2;
  }
  size_t targetCount = 0;
  for (size_t i = 0; i < fileLines.size(); ++i) {
    std::string &line = fileLines[i];
    normalizeBatchTargetLine(line);
    if (line.empty() ||
        (line[0] == '#' && !isSaltFirstBatchTarget(line)))
      continue;
    if (targetCount != i) fileLines[targetCount] = std::move(line);
    ++targetCount;
  }
  fileLines.resize(targetCount);
  std::vector<std::string> targets = std::move(fileLines);

  if (targets.empty()) {
    if (globalJson)
      std::cout << "{\"status\":\"invalid_input\",\"error\":\"Batch file has no targets\"}\n";
    else if (globalQuiet)
      std::cerr << "[ERROR] batch file has no targets\n";
    else
      std::cout << "\x1b[1;33m[!] Arquivo de lote vazio ou contendo apenas comentarios.\x1b[0m\n";
    return 2;
  }

  if (!globalQuiet && !globalJson) {
    std::cout << "\n\x1b[1;35m[LOTE FORENSE] Carregando arquivo de alvos: "
              << terminalSafeText(filePath) << "\x1b[0m\n";
    std::cout << "[i] Total de alvos identificados: " << targets.size() << "\n";
    std::cout << "============================================================================\n";
  }

  auto startBatch = std::chrono::high_resolution_clock::now();
  DiscardOutputBuffer discardedOutput;
  std::streambuf *originalCout = nullptr;
  if (globalJson) originalCout = std::cout.rdbuf(&discardedOutput);
  std::vector<AttackResult> results;
  int crackedCount = 0;
  int cachedCount = 0;
  int decodedCount = 0;
  int unsupportedCount = 0;
  int invalidCount = 0;
  int incompleteCount = 0;
  int exhaustedCount = 0;
  int failedCount = 0;
  long long totalBatchAttempts = 0;
  const ComputeType batchEngine = globalCompute;

  for (size_t i = 0; i < targets.size(); i++) {
    globalCompute = batchEngine;
    if (!globalQuiet && !globalJson) {
      std::cout << "\n\x1b[1;33m>>> ALVO [" << (i + 1) << "/"
                << targets.size() << "]: " << terminalSafeText(targets[i])
                << "\x1b[0m\n";
    }
    AttackResult res = autoExecuteAttack(targets[i], salt, charsetId, maxLen, skipDict,
                                         alvoId, customWordlist, noPotfile, true,
                                         saltWasProvided);
    results.push_back(res);

    if (res.success) {
      if (res.fromPotfile) cachedCount++;
      else if (res.method == "Base64 Strict Decode") decodedCount++;
      else crackedCount++;
    } else if (res.method == "Incomplete salt list" ||
               res.method == "Incomplete wordlist" ||
               res.method == "Incomplete WPA2 SSID") {
      incompleteCount++;
    } else if (res.method == "Unsupported real format" ||
               res.method == "Invalid or unsupported bcrypt cost" ||
               res.method == "Invalid or unsupported scrypt cost" ||
               res.method == "Unsupported selected engine") {
      unsupportedCount++;
    } else if (res.method == "Invalid target" ||
               res.method == "Invalid WPA2 SSID") {
      invalidCount++;
    } else if (res.method == "Exhausted") {
      exhaustedCount++;
    } else {
      failedCount++;
    }
    totalBatchAttempts =
        saturatingAttemptAdd(totalBatchAttempts, res.attempts);
  }
  if (originalCout) std::cout.rdbuf(originalCout);

  auto endBatch = std::chrono::high_resolution_clock::now();
  long long totalBatchMs = std::chrono::duration_cast<std::chrono::milliseconds>(endBatch - startBatch).count();
  if (totalBatchMs < 1) totalBatchMs = 1;

  const int unresolvedCount =
      failedCount + exhaustedCount + unsupportedCount + invalidCount +
      incompleteCount;
  if (globalQuiet) return unresolvedCount == 0 ? 0 : 1;

  if (globalJson) {
    std::cout << "{\n"
              << "  \"batch_file\": \"" << jsonEscape(filePath) << "\",\n"
              << "  \"total\": " << targets.size() << ",\n"
              << "  \"cracked\": " << crackedCount << ",\n"
              << "  \"cached\": " << cachedCount << ",\n"
              << "  \"decoded\": " << decodedCount << ",\n"
              << "  \"unsupported\": " << unsupportedCount << ",\n"
              << "  \"incomplete\": " << incompleteCount << ",\n"
              << "  \"invalid\": " << invalidCount << ",\n"
              << "  \"exhausted\": " << exhaustedCount << ",\n"
              << "  \"failed\": " << failedCount << ",\n"
              << "  \"total_time_ms\": " << totalBatchMs << ",\n"
              << "  \"total_attempts\": " << totalBatchAttempts << ",\n"
              << "  \"items\": [\n";
    for (size_t i = 0; i < results.size(); i++) {
      const std::string status = results[i].success
          ? (results[i].fromPotfile ? "cached"
             : (results[i].method == "Base64 Strict Decode" ? "decoded"
                                                              : "cracked"))
          : ((results[i].method == "Incomplete salt list" ||
              results[i].method == "Incomplete wordlist" ||
              results[i].method == "Incomplete WPA2 SSID") ? "incomplete"
             : ((results[i].method == "Unsupported real format" ||
              results[i].method == "Invalid or unsupported bcrypt cost" ||
              results[i].method == "Invalid or unsupported scrypt cost" ||
              results[i].method == "Unsupported selected engine") ? "unsupported"
             : ((results[i].method == "Invalid target" ||
                 results[i].method == "Invalid WPA2 SSID") ? "invalid_input"
             : (results[i].method == "Exhausted" ? "exhausted" : "failed"))));
      std::cout << "    {\"target\": \"" << jsonEscape(results[i].target) << "\", "
                << "\"status\": \"" << status << "\", "
                << "\"algorithm\": \"" << jsonEscape(hashTypeName(results[i].type)) << "\", "
                << "\"method\": \"" << jsonEscape(results[i].method) << "\", "
                << "\"engine\": \"" << jsonEscape(results[i].engine) << "\", ";
      writeJsonTextOrBase64(std::cout, "salt", results[i].salt);
      std::cout << ", ";
      if (results[i].success) {
        writeJsonTextOrBase64(std::cout, "plaintext", results[i].recoveredPass);
      } else {
        std::cout << "\"plaintext\": null";
      }
      std::cout << "}" << (i + 1 < results.size() ? ",\n" : "\n");
    }
    std::cout << "  ]\n}\n";
    return unresolvedCount == 0 ? 0 : 1;
  }

  // Executive Summary Report
  double totalRate = (double)totalBatchAttempts / (totalBatchMs / 1000.0);
  const int resolvedCount = crackedCount + cachedCount + decodedCount;
  double successPct = ((double)resolvedCount * 100.0) / targets.size();

  std::cout << "\n\n\x1b[1;36m";
  std::cout << "================================================================================\n";
  std::cout << "                         RELATÓRIO DE AUDITORIA EM LOTE                         \n";
  std::cout << "================================================================================\x1b[0m\n";
  std::cout << " Total de Alvos        : " << targets.size() << "\n";
  std::cout << " Resolvidos            : \x1b[1;32m" << resolvedCount
            << " (" << std::fixed << std::setprecision(1) << successPct << "%)\x1b[0m"
            << " [Novos: " << crackedCount << " | Cache Potfile: " << cachedCount
            << " | Base64 decodificados: " << decodedCount << "]\n";
  std::cout << " Nao Resolvidos        : \x1b[1;" << (unresolvedCount > 0 ? "31m" : "32m") << unresolvedCount
            << " (" << std::fixed << std::setprecision(1) << (100.0 - successPct) << "%)\x1b[0m\n";
  std::cout << "   Esgotados: " << exhaustedCount << " | Falhas: " << failedCount
            << " | Inválidos: " << invalidCount
            << " | Não suportados: " << unsupportedCount
            << " | Incompletos: " << incompleteCount << "\n";
  std::cout << " Tempo Total Auditado  : \x1b[1;33m" << formatTime(totalBatchMs) << "\x1b[0m\n";
  std::cout << " Tentativas Globais    : " << formatNumber(totalBatchAttempts) << " (" << formatHashrate(totalRate) << ")\n";
  std::cout << "================================================================================\n";
  std::cout << " ID  | HASH ALVO (Truncado)            | STATUS  | ALGORITMO   | SENHA RECUPERADA | MOTOR REAL\n";
  std::cout << "-----+---------------------------------+---------+-------------+------------------+----------------\n";

  for (size_t i = 0; i < results.size(); i++) {
    const auto &r = results[i];
    std::string dispHash = r.target;
    dispHash = terminalSafeText(dispHash);
    if (dispHash.length() > 31) {
      dispHash = dispHash.substr(0, 14) + "..." + dispHash.substr(dispHash.length() - 14);
    }
    while (dispHash.length() < 31) dispHash += " ";

    std::string statusStr = r.success ? (r.fromPotfile ? "CACHED "
        : (r.method == "Base64 Strict Decode" ? "DECODED" : "CRACKED"))
        : ((r.method == "Incomplete salt list" ||
            r.method == "Incomplete wordlist" ||
            r.method == "Incomplete WPA2 SSID") ? "PARTIAL"
        : (r.method == "Unsupported real format" ||
           r.method == "Invalid or unsupported bcrypt cost" ||
           r.method == "Invalid or unsupported scrypt cost" ||
           r.method == "Unsupported selected engine" ? "UNSUPP "
           : (r.method == "Invalid target" || r.method == "Invalid WPA2 SSID"
                  ? "INVALID"
                  : (r.method == "Exhausted" ? "EXHAUST" : "FAILED "))));
    std::string colorStatus = r.success ? "\x1b[1;32m"
        : ((statusStr == "FAILED " || statusStr == "EXHAUST")
               ? "\x1b[1;31m" : "\x1b[1;33m");

    std::string algoStr = hashTypeName(r.type);
    if (algoStr.length() > 11) algoStr = algoStr.substr(0, 11);
    while (algoStr.length() < 11) algoStr += " ";

    std::string passStr = r.success ? r.recoveredPass : "[NAO ENCONTRADA]";
    passStr = terminalSafeText(passStr);
    if (passStr.length() > 16) passStr = passStr.substr(0, 13) + "...";
    const std::string engineStr = terminalSafeText(r.engine);

    char idBuf[8];
    std::snprintf(idBuf, sizeof(idBuf), "%02zu", i + 1);

    std::cout << " " << idBuf << "  | " << dispHash << " | "
              << colorStatus << statusStr << "\x1b[0m | "
              << algoStr << " | "
              << (r.success ? "\x1b[1;93m" : "\x1b[1;30m") << passStr << "\x1b[0m | "
              << "\x1b[1;36m" << engineStr << "\x1b[0m\n";
  }
  std::cout << "================================================================================\n";
  std::cout << "[i] Auditoria em lote concluida. Falhas de gravacao do potfile sao informadas no stderr.\n\n";
  return unresolvedCount == 0 ? 0 : 1;
}

// --- Main Interface ---

int cerberusMain(int argc, char *argv[]) {
  enableANSI();

  // === CLI MODE ===
  if (argc > 1) {
    globalQuiet = cliHasFlag(argc, argv, "--quiet") || cliHasFlag(argc, argv, "-q");
    globalVerbose = cliHasFlag(argc, argv, "--verbose") || cliHasFlag(argc, argv, "-v");
    globalJson = cliHasFlag(argc, argv, "--json");
    if (globalJson) globalQuiet = false;
    auto reportCliInputError = [](const std::string &message) {
      if (globalJson)
        std::cout << "{\"status\":\"invalid_input\",\"error\":\""
                  << jsonEscape(message) << "\"}\n";
      else
        std::cerr << "[!] " << terminalSafeText(message) << "\n";
    };

    const std::vector<std::vector<std::string>> valuedOptionAliases = {
        {"--engine", "-e"}, {"--salt", "-s"},
        {"--charset", "-c"}, {"--max-len", "-l"},
        {"--wordlist", "-w"}, {"--algo", "-a", "--alvo"},
        {"--file", "-f"}};
    const std::vector<std::string> knownOptions = {
        "--help", "--version", "--json", "--quiet", "-q", "--verbose", "-v", "--no-dict", "-n",
        "--no-potfile", "--fresh", "--engine", "-e", "--salt", "-s",
        "--charset", "-c", "--max-len", "-l", "--wordlist", "-w",
        "--algo", "-a", "--alvo", "--file", "-f"};
    for (int i = 1; i < argc; ++i) {
      std::string arg = argv[i];
      lowercaseAscii(arg);
      if (arg == "--") break;
      if (arg.size() > 1 && arg[0] == '-' &&
          std::find(knownOptions.begin(), knownOptions.end(), arg) ==
              knownOptions.end()) {
        bool validEqualsOption = false;
        const size_t equals = arg.find('=');
        if (equals != std::string::npos) {
          const std::string optionName = arg.substr(0, equals);
          for (const auto &aliases : valuedOptionAliases) {
            if (std::find(aliases.begin(), aliases.end(), optionName) !=
                aliases.end()) {
              validEqualsOption = true;
              break;
            }
          }
        }
        if (!validEqualsOption) {
          reportCliInputError("Unknown option: " + arg);
          return 2;
        }
      }
    }

    for (const auto &aliases : valuedOptionAliases) {
      if (cliOptionRepeated(argc, argv, aliases)) {
        reportCliInputError("A valued option may be specified only once");
        return 2;
      }
    }
    for (const auto &aliases : valuedOptionAliases) {
      for (const std::string &alias : aliases) {
        if (cliOptionMissingValue(argc, argv, alias)) {
          reportCliInputError(alias + " requires a value");
          return 2;
        }
      }
    }

    if (globalQuiet || globalJson) {
      set_opencl_quiet(1);
    }

    std::string arg1 = argv[1];
    std::string arg1Lower = arg1;
    lowercaseAscii(arg1Lower);
    while (!arg1Lower.empty() && arg1Lower[0] == '-') arg1Lower.erase(0, 1);

    if (arg1Lower == "help" || arg1Lower == "h" || arg1Lower == "?" ||
        cliHasFlag(argc, argv, "--help")) {
      printHelp();
      return 0;
    }
    if (arg1Lower == "version" || arg1Lower == "v" ||
        cliHasFlag(argc, argv, "--version")) {
      printVersion();
      return 0;
    }

    const std::vector<std::string> trailingPositionals =
        cliTrailingPositionals(argc, argv, valuedOptionAliases);
    const bool batchCommandArg = arg1Lower == "file" ||
                                 arg1Lower == "batch" || arg1Lower == "f";
    const bool hasFileOptionAtCliLevel = cliHasOption(argc, argv, "--file") ||
                                         cliHasOption(argc, argv, "-f");
    const bool requiresOneTrailingPositional =
        arg1Lower == "crack" || arg1Lower == "c" ||
        arg1Lower == "crack-salt" || arg1Lower == "cs" ||
        arg1Lower == "decode" || arg1Lower == "d" ||
        arg1Lower == "hash" || arg1Lower == "g";
    const bool noTrailingPositionals =
        arg1Lower == "test-all" || arg1Lower == "test" || arg1Lower == "t" ||
        arg1Lower == "benchmark" || arg1Lower == "bench" || arg1Lower == "b" ||
        arg1Lower == "doctor" ||
        arg1Lower == "help" || arg1Lower == "h" || arg1Lower == "?" ||
        arg1Lower == "version" || arg1Lower == "v";

    if (hasFileOptionAtCliLevel && !batchCommandArg) {
      reportCliInputError("--file can only be used with the file/batch command");
      return 2;
    }
    if (batchCommandArg) {
      if (hasFileOptionAtCliLevel && !trailingPositionals.empty()) {
        reportCliInputError("Specify the batch input once: use a positional path or --file");
        return 2;
      }
      if (!hasFileOptionAtCliLevel && trailingPositionals.size() != 1) {
        reportCliInputError(trailingPositionals.empty()
                                ? "file requires a batch file path"
                                : "file accepts exactly one batch file path");
        return 2;
      }
    } else if (arg1Lower == "history" || arg1Lower == "potfile" ||
               arg1Lower == "show") {
      if (trailingPositionals.size() > 1) {
        reportCliInputError("history accepts at most one potfile path");
        return 2;
      }
    } else if (requiresOneTrailingPositional) {
      if (trailingPositionals.size() != 1) {
        reportCliInputError("command requires exactly one positional argument");
        return 2;
      }
    } else if (noTrailingPositionals && !trailingPositionals.empty()) {
      reportCliInputError("command does not accept positional arguments");
      return 2;
    } else if (!noTrailingPositionals && !trailingPositionals.empty()) {
      reportCliInputError("unexpected extra positional argument");
      return 2;
    }

    std::vector<std::string> allowedCommandOptions = {
        "--help", "--version", "--json", "--quiet", "-q", "--verbose", "-v"};
    if (batchCommandArg) {
      const std::vector<std::string> batchOptions = {
          "--engine", "-e", "--salt", "-s", "--charset", "-c",
          "--max-len", "-l", "--wordlist", "-w", "--algo", "-a",
          "--alvo", "--file", "-f", "--no-dict", "-n",
          "--no-potfile", "--fresh"};
      allowedCommandOptions.insert(allowedCommandOptions.end(),
                                   batchOptions.begin(), batchOptions.end());
    } else if (arg1Lower == "hash" || arg1Lower == "g") {
      allowedCommandOptions.insert(allowedCommandOptions.end(), {"--salt", "-s"});
    } else if (arg1Lower == "test-all" || arg1Lower == "test" ||
               arg1Lower == "t" || arg1Lower == "benchmark" ||
               arg1Lower == "bench" || arg1Lower == "b") {
      allowedCommandOptions.insert(allowedCommandOptions.end(), {"--engine", "-e"});
    } else if (arg1Lower == "doctor") {
      allowedCommandOptions.insert(allowedCommandOptions.end(), {"--engine", "-e"});
    } else if (arg1Lower != "decode" && arg1Lower != "d" &&
               arg1Lower != "history" && arg1Lower != "potfile" &&
               arg1Lower != "show" && arg1Lower != "help" &&
               arg1Lower != "h" && arg1Lower != "?" &&
               arg1Lower != "version" && arg1Lower != "v" &&
               arg1Lower != "doctor") {
      const std::vector<std::string> attackOptions = {
          "--engine", "-e", "--salt", "-s", "--charset", "-c",
          "--max-len", "-l", "--wordlist", "-w", "--algo", "-a",
          "--alvo", "--no-dict", "-n", "--no-potfile", "--fresh"};
      allowedCommandOptions.insert(allowedCommandOptions.end(),
                                   attackOptions.begin(), attackOptions.end());
    }
    for (int i = 1; i < argc; ++i) {
      std::string arg = argv[i];
      if (arg == "--") break;
      lowercaseAscii(arg);
      if (arg.empty() || arg[0] != '-') continue;
      const size_t equals = arg.find('=');
      const std::string optionName = arg.substr(0, equals);
      if (std::find(allowedCommandOptions.begin(),
                    allowedCommandOptions.end(), optionName) ==
          allowedCommandOptions.end()) {
        reportCliInputError("Option " + optionName +
                            " is not valid for this command");
        return 2;
      }
    }

    // Engine flag
    const bool engineOptionProvided = cliHasOption(argc, argv, "--engine") ||
                                      cliHasOption(argc, argv, "-e");
    std::string engineOpt = cliGetArgValue(argc, argv, "--engine");
    if (engineOpt.empty()) engineOpt = cliGetArgValue(argc, argv, "-e");
    if (engineOptionProvided && engineOpt.empty()) {
      reportCliInputError("--engine requires cpu, opencl, or cuda");
      return 2;
    }
    if (!engineOpt.empty()) {
      std::transform(engineOpt.begin(), engineOpt.end(), engineOpt.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      if (engineOpt != "cpu" && engineOpt != "opencl" && engineOpt != "cuda") {
        if (globalJson) {
          std::cout << "{\"status\":\"invalid_input\",\"error\":\"Unknown compute engine\",\"engine\":\""
                    << jsonEscape(engineOpt) << "\"}\n";
        } else if (globalQuiet) {
          std::cerr << "[ERROR] unknown compute engine: "
                    << terminalSafeText(engineOpt) << "\n";
        } else {
          std::cerr << "[!] Motor desconhecido: "
                    << terminalSafeText(engineOpt)
                    << " (use cpu, opencl ou cuda).\n";
        }
        return 2;
      }
    }
    auto initializeRequestedEngine = [&]() {
      if (engineOpt.empty()) {
        initHardwareAuto();
        return true;
      }
      if (initEngine(engineOpt)) return true;
      cleanupOpenCL();
      reportCliInputError("Requested engine is unavailable in this build or on this device; no fallback was performed");
      return false;
    };

    if (arg1Lower == "doctor") {
      if (!initializeRequestedEngine()) return 2;
      const int doctorResult = runEnvironmentDoctor();
      cleanupOpenCL();
      return doctorResult;
    }

    if (arg1Lower == "history" || arg1Lower == "potfile" || arg1Lower == "show") {
      std::string potPath = "cracked_passwords.txt";
      for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--") {
          if (i + 1 < argc) potPath = argv[i + 1];
          break;
        }
        lowercaseAscii(arg);
        if (arg == "--json" || arg == "--quiet" || arg == "-q" ||
            arg == "--verbose" || arg == "-v")
          continue;
        if (arg == "--engine" || arg == "-e" ||
            arg == "--salt" || arg == "-s" ||
            arg == "--charset" || arg == "-c" ||
            arg == "--max-len" || arg == "-l" ||
            arg == "--wordlist" || arg == "-w" ||
            arg == "--algo" || arg == "-a" || arg == "--alvo" ||
            arg == "--file" || arg == "-f") {
          if (i + 1 < argc) ++i;
          continue;
        }
        if (!arg.empty() && arg[0] != '-') {
          potPath = argv[i];
          break;
        }
      }
      return displayPotfileHistory(potPath);
    }

    if (arg1Lower == "test-all" || arg1Lower == "test" || arg1Lower == "t") {
      if (globalJson || globalQuiet) {
        reportCliInputError("test currently supports only human-readable output");
        return 2;
      }
      if (!initializeRequestedEngine()) return 2;
      const bool testsPassed = runAllTests(false);
      cleanupOpenCL();
      return testsPassed ? 0 : 1;
    }

    if (arg1Lower == "benchmark" || arg1Lower == "bench" || arg1Lower == "b") {
      if (globalJson || globalQuiet) {
        reportCliInputError("benchmark currently supports only human-readable output");
        return 2;
      }
      if (!initializeRequestedEngine()) return 2;
      const bool benchmarkSucceeded = runBenchmark();
      cleanupOpenCL();
      return benchmarkSucceeded ? 0 : 1;
    }

    if (arg1Lower == "decode" || arg1Lower == "d") {
      if (trailingPositionals.size() != 1) {
        reportCliInputError("decode requires a Base64 argument");
        return 2;
      }
      const std::string &encoded = trailingPositionals.front();
      std::string decoded;
      if (!isBase64Strict(encoded, decoded)) {
        reportCliInputError("Invalid Base64 input");
        return 2;
      }
      if (globalJson) {
        std::cout << "{\"status\":\"decoded\",\"input\":\""
                  << jsonEscape(encoded) << "\", ";
        writeJsonTextOrBase64(std::cout, "plaintext", decoded);
        std::cout << "}\n";
      } else if (globalQuiet) {
        std::cout << encodeQuietField(encoded) << ":"
                  << encodeQuietField(decoded) << "\n";
      } else {
        std::cout << "Decodificado: \x1b[1;32m"
                  << terminalSafeText(decoded) << "\x1b[0m\n";
      }
      return 0;
    }

    if (arg1Lower == "hash" || arg1Lower == "g") {
      if (trailingPositionals.size() != 1) {
        reportCliInputError("hash requires a plaintext argument");
        return 2;
      }
      const std::string &textToHash = trailingPositionals.front();
      const bool saltOptionProvided = cliHasOption(argc, argv, "--salt") ||
                                      cliHasOption(argc, argv, "-s");
      if (cliOptionMissingValue(argc, argv, "--salt") ||
          cliOptionMissingValue(argc, argv, "-s")) {
        reportCliInputError("--salt requires a value (use an empty quoted value for an empty key)");
        return 2;
      }
      std::string saltVal = cliGetArgValue(argc, argv, "--salt");
      if (saltVal.empty()) saltVal = cliGetArgValue(argc, argv, "-s");
      generateAndDisplayHashes(textToHash,
                               saltOptionProvided ? saltVal : "salt");
      return 0;
    }

    const bool firstArgIsOption = arg1.size() > 1 && arg1[0] == '-' &&
        arg1Lower != "file" && arg1Lower != "batch" && arg1Lower != "f";
    if (firstArgIsOption) {
      reportCliInputError("A target or command is required before options");
      return 2;
    }

    std::string targetHash = "";
    if (arg1Lower == "crack" || arg1Lower == "c" || arg1Lower == "crack-salt" || arg1Lower == "cs") {
      if (trailingPositionals.size() != 1) {
        reportCliInputError("crack requires a hash argument");
        return 2;
      }
      targetHash = trailingPositionals.front();
    } else {
      targetHash = argv[1];
    }

    const bool saltOptionProvided = cliHasOption(argc, argv, "--salt") ||
                                    cliHasOption(argc, argv, "-s");
    if ((arg1Lower == "crack-salt" || arg1Lower == "cs") &&
        !saltOptionProvided) {
      reportCliInputError("crack-salt requires --salt (use --salt \"\" for an empty salt)");
      return 2;
    }

    std::string salt = cliGetArgValue(argc, argv, "--salt");
    if (salt.empty()) salt = cliGetArgValue(argc, argv, "-s");
    if (cliOptionMissingValue(argc, argv, "--salt") ||
        cliOptionMissingValue(argc, argv, "-s")) {
      reportCliInputError("--salt requires a value");
      return 2;
    }

    std::string charsetStr = cliGetArgValue(argc, argv, "--charset");
    if (charsetStr.empty()) charsetStr = cliGetArgValue(argc, argv, "-c");
    const bool charsetOptionProvided = cliHasOption(argc, argv, "--charset") ||
                                       cliHasOption(argc, argv, "-c");
    std::string maxLenStr = cliGetArgValue(argc, argv, "--max-len");
    if (maxLenStr.empty()) maxLenStr = cliGetArgValue(argc, argv, "-l");
    const bool maxLenOptionProvided = cliHasOption(argc, argv, "--max-len") ||
                                      cliHasOption(argc, argv, "-l");
    int charsetId = 5;
    int maxLen = 16;
    if (charsetOptionProvided && charsetStr.empty()) {
      reportCliInputError("--charset requires an integer from 1 to 7");
      return 2;
    }
    if (maxLenOptionProvided && maxLenStr.empty()) {
      reportCliInputError("--max-len requires an integer from 1 to 64");
      return 2;
    }
    try {
      auto parseInteger = [](const std::string &value) {
        size_t consumed = 0;
        int parsed = std::stoi(value, &consumed);
        if (consumed != value.size()) throw std::invalid_argument("trailing characters");
        return parsed;
      };
      if (!charsetStr.empty()) charsetId = parseInteger(charsetStr);
      if (!maxLenStr.empty()) maxLen = parseInteger(maxLenStr);
    } catch (const std::exception &) {
      reportCliInputError("--charset and --max-len must be integers");
      return 2;
    }
    if (charsetId < 1 || charsetId > 7 || maxLen < 1 || maxLen > 64) {
      reportCliInputError("Valid ranges: --charset 1..7 and --max-len 1..64");
      return 2;
    }

    bool noDict = cliHasFlag(argc, argv, "--no-dict") || cliHasFlag(argc, argv, "-n");
    bool noPotfile = cliHasFlag(argc, argv, "--no-potfile") || cliHasFlag(argc, argv, "--fresh");

    const bool wordlistOptionProvided = cliHasOption(argc, argv, "--wordlist") ||
                                        cliHasOption(argc, argv, "-w");
    std::string customWordlist = cliGetArgValue(argc, argv, "--wordlist");
    if (customWordlist.empty()) customWordlist = cliGetArgValue(argc, argv, "-w");
    if (wordlistOptionProvided && customWordlist.empty()) {
      if (globalJson)
        std::cout << "{\"status\":\"invalid_input\",\"error\":\"--wordlist requires a file path\"}\n";
      else if (globalQuiet)
        std::cerr << "[ERROR] --wordlist requires a file path\n";
      else
        std::cerr << "[!] --wordlist precisa do caminho de um arquivo.\n";
      return 2;
    }
    if (customWordlist.empty()) customWordlist = "wordlist.txt";
    if (customWordlist == "wordlist.txt") {
      customWordlist = pathToUtf8(defaultDataFilePath(customWordlist));
    }
    if (wordlistOptionProvided && !noDict && !fileExists(customWordlist)) {
      if (globalJson)
        std::cout << "{\"status\":\"invalid_input\",\"error\":\"Wordlist file not found\",\"file\":\""
                  << jsonEscape(customWordlist) << "\"}\n";
      else if (globalQuiet)
        std::cerr << "[ERROR] wordlist file not found: "
                  << terminalSafeText(customWordlist) << "\n";
      else
        std::cerr << "[!] Dicionario nao encontrado: "
                  << terminalSafeText(customWordlist) << "\n";
      return 2;
    }

    std::string algoStr = cliGetArgValue(argc, argv, "--algo");
    if (algoStr.empty()) algoStr = cliGetArgValue(argc, argv, "-a");
    if (algoStr.empty()) algoStr = cliGetArgValue(argc, argv, "--alvo");
    const bool algoOptionProvided = cliHasOption(argc, argv, "--algo") ||
                                    cliHasOption(argc, argv, "-a") ||
                                    cliHasOption(argc, argv, "--alvo");
    if (algoOptionProvided && algoStr.empty()) {
      reportCliInputError("--algo requires an algorithm name");
      return 2;
    }

    int alvoId = 0;
    bool invalidAlgo = false;
    if (!algoStr.empty()) {
      std::string al = algoStr;
      std::transform(al.begin(), al.end(), al.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      if (al == "crc32") alvoId = 99;
      else if (al == "md5") alvoId = 100;
      else if (al == "sha1" || al == "sha-1") alvoId = 101;
      else if (al == "sha256" || al == "sha-256") alvoId = 102;
      else if (al == "sha512" || al == "sha-512") alvoId = 103;
      else if (al == "ntlm") alvoId = 104;
      else if (al == "md4") alvoId = 105;
      else if (al == "base64") alvoId = 106;
      else if (al == "hmac-sha256" || al == "hmac_sha256" || al == "hmacsha256") alvoId = 107;
      else if (al == "hmac-sha1" || al == "hmac_sha1" || al == "hmacsha1") alvoId = 108;
      else if (al == "hmac-md5" || al == "hmac_md5" || al == "hmacmd5") alvoId = 109;
      else if (al == "sha224" || al == "sha-224") alvoId = 110;
      else if (al == "sha384" || al == "sha-384") alvoId = 111;
      else if (al == "salted-md5" || al == "md5-salt") alvoId = 1;
      else if (al == "salted-sha1" || al == "sha1-salt") alvoId = 2;
      else if (al == "wpa2" || al == "pbkdf2") alvoId = 3;
      else if (al == "salted-sha256" || al == "sha256-salt") alvoId = 4;
      else if (al == "salted-sha512" || al == "sha512-salt") alvoId = 5;
      else if (al == "wpa3" || al == "sae") alvoId = 6;
      else if (al == "bcrypt") alvoId = 7;
      else if (al == "scrypt") alvoId = 8;
      else {
        try {
          size_t consumed = 0;
          const int numericId = std::stoi(algoStr, &consumed);
          const bool validNumericId =
              consumed == algoStr.size() &&
              ((numericId >= 1 && numericId <= 8) ||
               (numericId >= 99 && numericId <= 111));
          if (validNumericId) alvoId = numericId;
          else invalidAlgo = true;
        } catch (const std::exception &) {
          invalidAlgo = true;
        }
      }
    }

    if (invalidAlgo) {
      if (globalJson) {
        std::cout << "{\"status\":\"invalid_input\",\"error\":\"Unknown algorithm selection\",\"algorithm\":\""
                  << jsonEscape(algoStr) << "\"}\n";
      } else if (globalQuiet) {
        std::cerr << "[ERROR] unknown algorithm selection: "
                  << terminalSafeText(algoStr) << "\n";
      } else {
        std::cerr << "[!] Algoritmo desconhecido: "
                  << terminalSafeText(algoStr) << "\n";
      }
      return 2;
    }

    // Check for Batch Multi-Hash File Mode
    std::string fileOpt = cliGetArgValue(argc, argv, "--file");
    if (fileOpt.empty()) fileOpt = cliGetArgValue(argc, argv, "-f");
    const bool fileOptionProvided = cliHasOption(argc, argv, "--file") ||
                                    cliHasOption(argc, argv, "-f");
    const bool batchCommand = arg1Lower == "file" || arg1Lower == "batch" ||
                              arg1Lower == "f";
    bool positionalBatchFile = false;
    if (!batchCommand && fileOpt.empty() && fileExists(targetHash)) {
      try {
        const std::filesystem::path targetPath = pathFromUtf8(targetHash);
        std::string targetExtension = pathToUtf8(targetPath.extension());
        std::string targetBaseName = pathToUtf8(targetPath.filename());
        lowercaseAscii(targetExtension);
        lowercaseAscii(targetBaseName);
        const bool isReservedDataFile = targetBaseName == "wordlist.txt" ||
                                        targetBaseName == "saltlist.txt" ||
                                        targetBaseName == "cracked_passwords.txt";
        positionalBatchFile = targetExtension == ".txt" && !isReservedDataFile;
      } catch (const std::filesystem::filesystem_error &) {
        positionalBatchFile = false;
      }
    }
    if (fileOptionProvided && fileOpt.empty()) {
      reportCliInputError("--file requires a file path");
      return 2;
    }
    if (batchCommand || !fileOpt.empty() || positionalBatchFile) {
      std::string targetFile = !fileOpt.empty() ? fileOpt : targetHash;
      if (batchCommand && fileOpt.empty()) {
        targetFile.clear();
        for (int i = 2; i < argc; ++i) {
          std::string arg = argv[i];
          lowercaseAscii(arg);
          if (arg == "--") {
            if (i + 1 < argc) targetFile = argv[i + 1];
            break;
          }
          if (arg == "--json" || arg == "--quiet" || arg == "-q" ||
              arg == "--verbose" || arg == "-v" || arg == "--no-dict" ||
              arg == "-n" || arg == "--no-potfile" || arg == "--fresh")
            continue;
          if (arg == "--algo" || arg == "-a" || arg == "--alvo" ||
              arg == "--salt" || arg == "-s" || arg == "--engine" ||
              arg == "-e" || arg == "--charset" || arg == "-c" ||
              arg == "--max-len" || arg == "-l" || arg == "--wordlist" ||
              arg == "-w" || arg == "--file" || arg == "-f") {
            if (i + 1 < argc) ++i;
            continue;
          }
          if (!arg.empty() && arg[0] != '-') {
            targetFile = argv[i];
            break;
          }
        }
      }
      if (targetFile.empty()) {
        reportCliInputError("file requires a batch file path");
        return 2;
      }
      if (!initializeRequestedEngine()) return 2;
      if (!globalQuiet && !globalJson) {
        exibirDesenho();
      }
      int batchExit = auditHashFile(targetFile, salt, charsetId, maxLen, noDict,
                                    alvoId, customWordlist, noPotfile,
                                    saltOptionProvided);
      cleanupOpenCL();
      return batchExit;
    }

    if (!initializeRequestedEngine()) return 2;
    if (!globalQuiet && !globalJson) exibirDesenho();
    const bool requireHash = arg1Lower == "crack" || arg1Lower == "c" ||
                             arg1Lower == "crack-salt" || arg1Lower == "cs";
    AttackResult attack = autoExecuteAttack(targetHash, salt, charsetId, maxLen,
                                            noDict, alvoId, customWordlist,
                                            noPotfile, requireHash,
                                            saltOptionProvided);
    cleanupOpenCL();
    return attack.success ? 0 : 1;
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
    std::cout << "  STATUS: \x1b[1;32mONLINE\x1b[0m | MOTOR: \x1b[1;36m"
              << terminalSafeText(getEngineName()) << "\x1b[0m\n";
    std::cout << "  ----------------------------------------------------------------------------\n";
    std::cout << "  \x1b[1;37mMODO INTUITIVO ZERO-CLICK:\x1b[0m Cole ou digite qualquer Hash, Base64 ou Texto!\n";
    std::cout << "  (Atalhos: '\x1b[1;33mtest\x1b[0m' = testes | '\x1b[1;33mbench\x1b[0m' = velocidade | '\x1b[1;33mpotfile\x1b[0m' = historico | '\x1b[1;33mfile <arq>\x1b[0m' = lote | '\x1b[1;33m0\x1b[0m' = sair)\n";
    std::cout << "  ----------------------------------------------------------------------------\n\n";
    std::cout << "  \x1b[1;36mcerberus >> \x1b[0m";

    std::string input;
    if (!std::getline(std::cin, input)) break;

    const size_t firstCommandChar = input.find_first_not_of(" \t\r\n");
    if (firstCommandChar == std::string::npos) continue;
    const size_t lastCommandChar = input.find_last_not_of(" \t\r\n");
    const std::string commandInput =
        input.substr(firstCommandChar, lastCommandChar - firstCommandChar + 1);

    if (commandInput == "0" || commandInput == "sair" || commandInput == "exit" || commandInput == "quit" || commandInput == "q") {
      std::cout << "\n[!] Encerrando sessao...\n";
      break;
    }

    if (commandInput == "help" || commandInput == "ajuda" || commandInput == "h" || commandInput == "?") {
      printHelp();
      std::cout << "\n\x1b[1;33mPressione ENTER para voltar...\x1b[0m";
      std::cin.get();
      continue;
    }

    if (commandInput == "history" || commandInput == "potfile" || commandInput == "show") {
      displayPotfileHistory();
      std::cout << "\n\x1b[1;33mPressione ENTER para continuar...\x1b[0m";
      std::cin.get();
      continue;
    }

    if (commandInput == "cpu") {
      cleanupOpenCL();
      globalCompute = ComputeType::CPU;
      globalEngineExplicitlySelected = true;
      std::cout << "\n\x1b[1;36m[+] Motor alterado para CPU Multi-Threaded!\x1b[0m\n";
      sleepMs(1000);
      continue;
    }

    if (commandInput == "gpu" || commandInput == "opencl") {
      if (initOpenCL()) {
        globalCompute = ComputeType::OPENCL;
        globalEngineExplicitlySelected = true;
        std::cout << "\n\x1b[1;32m[+] Motor alterado para GPU (OpenCL)!\x1b[0m\n";
      } else {
        std::cout << "\n\x1b[1;31m[!] Falha ao ativar OpenCL na GPU.\x1b[0m\n";
      }
      sleepMs(1000);
      continue;
    }

    if (commandInput.rfind("file ", 0) == 0 || commandInput.rfind("batch ", 0) == 0) {
      std::string fPath = commandInput.substr(commandInput.find(' ') + 1);
      fPath.erase(0, fPath.find_first_not_of(" \"'\t\r\n"));
      fPath.erase(fPath.find_last_not_of(" \"'\t\r\n") + 1);
      auditHashFile(fPath);
      std::cout << "\n\x1b[1;33mPressione ENTER para continuar...\x1b[0m";
      std::cin.get();
      continue;
    }

    if (commandInput == "test" || commandInput == "t" || commandInput == "test-all") {
      runAllTests(true);
      continue;
    }

    if (commandInput == "bench" || commandInput == "benchmark" || commandInput == "b") {
      runBenchmark();
      std::cout << "\x1b[1;33mPressione ENTER para voltar ao menu...\x1b[0m";
      std::cin.get();
      continue;
    }

    if (commandInput == "salt" || commandInput == "s") {
      std::cout << "\n\x1b[1;36m--- MODO SALT AVANCADO ---\x1b[0m\n";
      std::cout << "Insira o Hash: ";
      std::string targetHash;
      if (!std::getline(std::cin, targetHash)) break;
      const size_t targetStart = targetHash.find_first_not_of(" \t\r\n");
      if (targetStart == std::string::npos) {
        targetHash.clear();
      } else {
        targetHash = targetHash.substr(targetStart,
            targetHash.find_last_not_of(" \t\r\n") - targetStart + 1);
      }
      std::cout << "Insira o Salt (linha vazia = salt vazio; '-' = saltlist.txt): ";
      std::string saltVal;
      if (!std::getline(std::cin, saltVal)) break;
      const bool saltWasProvided = saltVal != "-";
      if (!saltWasProvided) saltVal.clear();

      autoExecuteAttack(targetHash, saltVal, 5, 16, false, 0,
                        "wordlist.txt", false, false, saltWasProvided);
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

#ifdef _WIN32
int wmain(int argc, wchar_t *wideArgv[]) {
  std::vector<std::string> utf8Args;
  utf8Args.reserve(static_cast<size_t>(argc));
  std::vector<char *> narrowArgv(static_cast<size_t>(argc) + 1, nullptr);

  for (int i = 0; i < argc; ++i) {
    const int requiredBytes = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, wideArgv[i], -1, nullptr, 0, nullptr,
        nullptr);
    if (requiredBytes <= 0) {
      std::fputs("[!] Argument contains invalid Unicode.\n", stderr);
      return 2;
    }

    std::string utf8Arg(static_cast<size_t>(requiredBytes), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wideArgv[i], -1,
                            utf8Arg.data(), requiredBytes, nullptr, nullptr) <=
        0) {
      std::fputs("[!] Could not convert command-line argument to UTF-8.\n",
                 stderr);
      return 2;
    }
    utf8Arg.resize(static_cast<size_t>(requiredBytes - 1));
    utf8Args.push_back(std::move(utf8Arg));
  }

  for (int i = 0; i < argc; ++i)
    narrowArgv[static_cast<size_t>(i)] = utf8Args[static_cast<size_t>(i)].data();
  return cerberusMain(argc, narrowArgv.data());
}
#else
int main(int argc, char *argv[]) { return cerberusMain(argc, argv); }
#endif
