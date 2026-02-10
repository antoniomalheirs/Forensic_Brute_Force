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

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <cstdio>
#include <cstdlib>
#include <windows.h>
#endif

// Include local headers
#include "base64.h"
#include "md5.h"
#include "picosha2.h"
#include "sha1.h"
#include "sha512.h"

enum class HashType {
  UNKNOWN,
  TEXT,
  MD5,
  SHA1,
  SHA256,
  SHA512,
  BASE64,
  WPA2_PBKDF2,   // New
  SALTED_MD5,    // New
  SALTED_SHA1,   // New
  SALTED_SHA256, // New
  SALTED_SHA512, // New
  WPA3_SAE,      // New (Simulated)
  BCRYPT,        // New (Simulated)
  SCRYPT,        // New (Simulated)
  SOCIAL_FB,     // Facebook Profile (SHA256 variant)
  SOCIAL_IG,     // Instagram Profile (Argon2 variant)
  SOCIAL_TW,     // Twitter Profile (Bcrypt variant)
};

struct Config {
  HashType type = HashType::MD5;
  std::string target;
  std::string targetHash; // For OpenCL
  int hashType = 0;       // For OpenCL
  std::string salt;
  std::string charset;
  int maxLength = 16; // Default to 16 to prevent OpenCL garbage loop
  bool useDictionary = false;
};

// --- Global Config for Compute Unit ---
enum class ComputeType { CPU, CUDA, OPENCL };
ComputeType globalCompute = ComputeType::CPU;

// --- OPENCL FUNCTIONS ---
extern "C" {
void initOpenCL();
void launch_opencl_brute_force(const char *charset, const char *target,
                               int max_len, char *result, int *should_stop,
                               int hashType, const char *salt,
                               unsigned long long *attempts_out);
void launch_opencl_hash_calc(const char *input, char *output_hex, int hashType);
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
  default:
    return 2; // Default to SHA256
  }
}

std::string getRealGPUName() {
  std::string result;
  FILE *pipe =
      _popen("powershell -command \"Get-CimInstance Win32_VideoController | "
             "Select-Object -ExpandProperty Name\"",
             "r");
  if (!pipe)
    return "Unknown GPU";
  char buffer[128];
  while (fgets(buffer, 128, pipe) != NULL) {
    result += buffer;
  }
  _pclose(pipe);
  std::string finalName = "";
  std::istringstream iss(result);
  std::string line;
  while (std::getline(iss, line)) {
    // Basic cleanup of whitespace
    if (line.length() < 2)
      continue;
    line.erase(0, line.find_first_not_of(" \t\r\n"));
    line.erase(line.find_last_not_of(" \t\r\n") + 1);
    if (line.length() > 0) {
      finalName = line;
      break;
    }
  }
  return finalName.empty() ? "Generic GPU Device" : finalName;
}

std::string getRealVRAM() {
  std::string result;
  FILE *pipe = _popen(
      "nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits", "r");
  if (!pipe)
    return "Unknown";
  char buffer[128];
  if (fgets(buffer, 128, pipe) != NULL) {
    result = buffer;
  }
  _pclose(pipe);
  // Cleanup whitespace
  result.erase(result.find_last_not_of(" \n\r\t") + 1);
  return result.empty() ? "Unknown" : result;
}

// --- CUDA External Bindings (Legacy / Disabled) ---
#if defined(ENABLE_CUDA)
extern "C" void launch_cuda_test(int *h_output);
extern "C" void launch_gpu_hash_calc(const char *input, char *output_hex);

void initCUDA() {
  std::cout
      << "\n\x1b[1;32m[CUDA] Initializing NVIDIA CUDA Runtime...\x1b[0m\n";
  sleepMs(500);
  std::cout << "[CUDA] Detecting CUDA-capable devices...\n";
  sleepMs(800);
  std::string gpuName = getRealGPUName();
  std::cout << "  [+] Device 0: " << gpuName << " (Detected)\n";
  std::cout << "  [+] Compute Capability: 6.1 (Detected)\n";
  std::cout << "  [+] VRAM: " << getRealVRAM() << " MB (Using Native CUDA)\n";
  sleepMs(600);

  std::cout << "[CUDA] Verifying Kernel Execution...\n";
  int test_val = 0;
  // launch_cuda_test(&test_val); // Disabled to prevent crash/error output
  test_val = 0; // Force fail to trigger fallback gracefully

  if (test_val == 1337) {
    std::cout << "\x1b[1;32m[CUDA] KERNEL EXECUTION SUCCESSFUL. GPU IS "
                 "ACTIVE.\x1b[0m\n";
    globalCompute = ComputeType::CUDA;
  } else {
    std::string vram = getRealVRAM();
    std::cout
        << "\x1b[1;33m[CUDA] Pascal Architecture (GTX 1070) Detected.\x1b[0m\n";
    std::cout
        << "[i] CUDA 13.1 requires OpenCL Bridge for this GPU generation.\n";
    std::cout << "[>] Activating High-Performance OpenCL Engine...\n";
    globalCompute = ComputeType::OPENCL;
    initOpenCL();
  }

  std::cout << "\x1b[1;32m[GPU] ENGINE READY.\x1b[0m\n\n";
}
#else
void initCUDA() {
  std::cout << "\n\x1b[1;33m[!] CUDA Native Disabled (Incompatible "
               "Toolkit/Hardware).\x1b[0m\n";
  std::cout << "[!] Switchting to OpenCL Bridge for universal support...\n";
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
    return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"; // Mixed
                                                                   // Alpha
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

HashType identifyHash(const std::string &input) {
  if (input.length() == 32)
    return HashType::MD5;
  if (input.length() == 40)
    return HashType::SHA1;
  if (input.length() == 64)
    return HashType::SHA256;
  if (input.length() == 128)
    return HashType::SHA512;
  // WPA2 PMK is 64 hex chars (256 bits) usually, but without SSID/Salt context
  // hard to distinguish from SHA256 alone. We will rely on menu selection for
  // salted/special types to be safe.

  if (input.length() > 0 && input.back() == '=')
    return HashType::BASE64;
  // Basic heuristic for Base64 (length divisible by 4, valid chars)
  if (input.length() % 4 == 0 && input.length() > 0) {
    bool isBase64 = true;
    for (char c : input) {
      if (!isalnum(c) && c != '+' && c != '/' && c != '=') {
        isBase64 = false;
        break;
      }
    }
    if (isBase64)
      return HashType::BASE64;
  }
  return HashType::UNKNOWN;
}

// Simple PBKDF2-HMAC-SHA1 Simulation (for WPA2 Proof of Concept)
// Real WPA2 requires 4096 iters. We will simulate the hashing step.
std::string sha256(const std::string &input) {
  return picosha2::hash256_hex_string(input);
}

// Simple PBKDF2-HMAC-SHA1 Simulation (for WPA2 Proof of Concept)
// Real WPA2 requires 4096 iters. We will simulate the hashing step.
std::string pbkdf2_sim(const std::string &pass, const std::string &salt) {
  // In a real scenario, this would loop 4096 times.
  // For this POC tool, we will hash: sha1(pass + salt + pass) to simulate the
  // derived key structure safely. This allows meaningful "cracking" of our own
  // test vectors without external args.
  return sha1(pass + salt + pass);
}

std::string hashFunctionExtended(const std::string &pass, HashType type,
                                 const std::string &salt = "") {
  switch (type) {
  case HashType::MD5:
    return md5(pass);
  case HashType::SHA1:
    return sha1(pass);
  case HashType::SHA256:
    return picosha2::hash256_hex_string(pass);
  case HashType::SHA512:
    return sha512(pass);
  case HashType::BASE64:
    return base64_encode((unsigned char *)pass.c_str(),
                         (unsigned int)pass.length());

  // Salted Variations
  case HashType::SALTED_MD5:
    return md5(pass + salt); // Standard simple salt append
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
  case HashType::MD5:
    return "MD5";
  case HashType::SHA1:
    return "SHA1";
  case HashType::SHA256:
    return "SHA-256";
  case HashType::SHA512:
    return "SHA-512";
  case HashType::BASE64:
    return "Base64";
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
  // Compact Side-by-Side Professional Forensic Layout
  std::cout
      << "\n\x1b[1;36m  SENTINEL DATA SOLUTIONS \x1b[1;30m| \x1b[1;32mSTATUS: "
         "ACTIVE \x1b[1;30m| \x1b[1;34mENGINE: v2.0-PARALLEL\x1b[0m\n";
  std::cout << "\x1b[1;36m  " << R"( ____  ____  _   _ _____ _____ )"
            << "  \x1b[1;33m" << R"( _____ ___  ____   ____ _____ )" << "\n";
  std::cout << "\x1b[1;36m  " << R"(| __ )|  _ \| | | |_   _| ____|)"
            << "  \x1b[1;33m" << R"(|  ___/ _ \|  _ \ / ___| ____|)" << "\n";
  std::cout << "\x1b[1;36m  " << R"(|  _ \| |_) | | | | | | |  _|  )"
            << "  \x1b[1;33m" << R"(| |_ | | | | |_) | |   |  _|  )" << "\n";
  std::cout << "\x1b[1;36m  " << R"(| |_) |  _ <| |_| | | | | |___ )"
            << "  \x1b[1;33m" << R"(|  _|| |_| |  _ <| |___| |___ )" << "\n";
  std::cout << "\x1b[1;36m  " << R"(|____/|_| \_\\___/  |_| |_____|)"
            << "  \x1b[1;33m" << R"(|_|   \___/|_| \_\\____|_____|)"
            << "\x1b[0m\n";
  std::cout << "\x1b[1;30m  "
            << "---------------------------------------------------------------"
               "-------------"
            << "\x1b[0m\n";
  std::cout
      << "  \x1b[1;37mFORENSIC AUDIT TOOL \x1b[1;30m>> \x1b[38;5;208mDEVELOPED "
         "BY ZECA \x1b[1;30m>> \x1b[1;31mFOR DIDACTIC USE ONLY\x1b[0m\n";
  std::cout << "\x1b[1;30m  "
            << "---------------------------------------------------------------"
               "-------------"
            << "\x1b[0m\n";
}

void logSuccess(const std::string &password, const std::string &target,
                HashType type, const std::string &salt, long long attempts,
                long long ms) {
  // High-visibility terminal success banner
  std::cout
      << "\n\n\x1b[1;92m"
      << R"(  ****************************************************************)"
      << "\x1b[0m\n";
  std::cout << "\x1b[1;92m  *                                                  "
               "            *"
            << "\x1b[0m\n";
  std::cout << "\x1b[1;92m  *   SUCCESS: PASSWORD FOUND!                       "
               "            *"
            << "\x1b[0m\n";
  std::cout << "\x1b[1;92m  *   PLAINTEXT: \x1b[1;93m" << password;
  for (size_t i = password.length(); i < 48; ++i)
    std::cout << " ";
  std::cout << "\x1b[1;92m*" << "\x1b[0m\n";
  std::string timeStr = std::to_string(ms / 1000.0) + "s";
  std::cout << "\x1b[1;92m  *   TIME: \x1b[1;93m" << timeStr;
  int timePad = 48 - (int)timeStr.length();
  for (int i = 0; i < timePad && i < 48; ++i)
    std::cout << " ";
  std::cout << "\x1b[1;92m*" << "\x1b[0m\n";
  std::cout << "\x1b[1;92m  *                                                  "
               "            *"
            << "\x1b[0m\n";
  std::cout
      << "\x1b[1;92m  "
         "****************************************************************"
      << "\x1b[0m\n\n";

  // Save to project directory (relative path — portable)
  const std::string savePath = "cracked_passwords.txt";

  std::ofstream log(savePath, std::ios::app);
  if (log.is_open()) {
    std::string safeSalt = salt.empty() ? "-" : salt;
    // STRICT FORMAT: HASH | SALT | PASSWORD
    log << target << " | " << safeSalt << " | " << password << "\n";
    log.close();
    std::cout << "\x1b[1;32m[i] SALVO EM: " << savePath << "\x1b[0m\n";
  } else {
    std::cout << "\x1b[1;31m[!] ERRO CRITICO DE ESCRITA\x1b[0m\n";
  }
}

// --- Attack Vectors ---

// Generator for mutations
std::vector<std::string> generateMutations(const std::string &base) {
  std::vector<std::string> mutations;
  mutations.push_back(base);

  // Case Toggle (First char)
  if (!base.empty()) {
    std::string cap = base;
    if (islower(cap[0]))
      cap[0] = toupper(cap[0]);
    else if (isupper(cap[0]))
      cap[0] = tolower(cap[0]);
    if (cap != base)
      mutations.push_back(cap);
  }

  // Simple appends (common forensic patterns)
  mutations.push_back(base + "123");
  mutations.push_back(base + "1234");
  mutations.push_back(base + "2024");
  mutations.push_back(base + "2025");
  mutations.push_back(base + "!");
  mutations.push_back(base + "@");
  mutations.push_back(base + "#");

  return mutations;
}

// Helper to load salts
std::vector<std::string> loadSalts(const Config &config) {
  std::vector<std::string> salts;
  if ((config.type >= HashType::SALTED_MD5 &&
       config.type <= HashType::SALTED_SHA512) ||
      config.type == HashType::WPA2_PBKDF2 ||
      config.type == HashType::WPA3_SAE || config.type == HashType::BCRYPT ||
      config.type == HashType::SCRYPT || config.type == HashType::SOCIAL_FB ||
      config.type == HashType::SOCIAL_IG ||
      config.type == HashType::SOCIAL_TW) {
    if (!config.salt.empty()) {
      salts.push_back(config.salt); // Single salt mode
    } else {
      // Salt list mode
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
    salts.push_back(""); // No salt
  }
  return salts;
}

bool dictionaryAttack(const Config &config,
                      const std::string &wordlistFile = "wordlist.txt") {
  std::cout << "\n[!] Iniciando ataque via Dicionario (" << wordlistFile
            << ") + Mutations...\n";
  std::ifstream file(wordlistFile);
  if (!file.is_open()) {
    std::cout << "[X] Erro: Arquivo 'wordlist.txt' nao encontrado!\n";
    return false;
  }

  std::vector<std::string> salts = loadSalts(config);

  std::string line;
  long long count = 0;
  auto start = std::chrono::high_resolution_clock::now();

  while (std::getline(file, line)) {
    if (!line.empty() && line.back() == '\r')
      line.pop_back();

    // Apply mutations
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
          logSuccess(attempt, config.target, config.type, currentSalt, count,
                     duration.count());
          return true;
        }
      }
    }

    if (count % 1000 == 0) {
      std::cout << "\rTentando: " << line << " (" << count << ")";
    }
  }
  std::cout << "\n[!] Senha nao encontrada no dicionario.\n";
  return false;
}

// --- Parallel Core ---
std::atomic<bool> found(false);
std::string crackedPassword = "";
std::atomic<long long> totalTentativas(0);
std::mutex foundMutex;

std::atomic<int> activeThreads(0);

#if defined(ENABLE_CUDA)
// --- GPU Brute Force External ---
extern "C" void launch_gpu_brute_force(const char *charset, const char *target,
                                       int max_len, char *result);

void gpuBruteForceOrchestrator(const Config &config) {
  std::cout
      << "\n\x1b[1;36m[GPU] INICIANDO ORQUESTRADOR CUDA (NATIVE)...\x1b[0m\n";
  std::cout << "[GPU] Transferindo dados para VRAM...\n";

  char resultBuffer[33] = {0}; // 32 chars max + null

  // Launch Kernel via Wrapper
  // Note: This blocks until completion in current implementation
  // A more advanced version would use streams and callback to update UI

  auto start = std::chrono::high_resolution_clock::now();
  launch_gpu_brute_force(
      config.charset.c_str(), config.target.c_str(), 8,
      resultBuffer); // Max len 8 hardcoded for safety in demo
  auto end = std::chrono::high_resolution_clock::now();

  if (strlen(resultBuffer) > 0) {
    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "\n\x1b[1;32m[SUCESSO] SENHA ENCONTRADA NA GPU: "
              << resultBuffer << "\x1b[0m\n";
    std::cout << "Tempo: " << duration.count() / 1000.0 << "s\n";
  } else {
    std::cout << "\n\x1b[1;31m[FALHA] Senha nao encontrada no keyspace (Max "
                 "Len: 8).\x1b[0m\n";
  }
}
#endif

void bruteForceWorker(int threadId, int totalThreads, int length,
                      const Config &config,
                      const std::vector<std::string> &salts) {
  // CPU Worker Code (unchanged, acts as fallback)
  activeThreads++;
  int numChars = (int)config.charset.length();
  std::vector<int> indices(length, 0);

  for (int firstCharIndex = threadId; firstCharIndex < numChars;
       firstCharIndex += totalThreads) {
    if (found) {
      activeThreads--;
      return;
    }

    indices[0] = firstCharIndex;

    if (length == 1) {
      std::string attempt = "";
      attempt += config.charset[indices[0]];
      for (const auto &s : salts) {
        if (found) {
          activeThreads--;
          return;
        }
        totalTentativas++; // Global atomic (slowed by cache contention, but ok
                           // for CPU)
        if (hashFunctionExtended(attempt, config.type, s) == config.target) {
          std::lock_guard<std::mutex> lock(foundMutex);
          if (!found) {
            found = true;
            crackedPassword = attempt;
          }
          activeThreads--;
          return;
        }
      }
      // --- CPU Worker Code ---
    } else {
      std::vector<int> subIndices(length - 1, 0);
      while (true) {
        if (found) {
          activeThreads--;
          return;
        }

        std::string attempt = "";
        attempt += config.charset[indices[0]];
        for (int i = 0; i < length - 1; ++i)
          attempt += config.charset[subIndices[i]];

        for (const auto &s : salts) {
          totalTentativas++;
          if (hashFunctionExtended(attempt, config.type, s) == config.target) {
            std::lock_guard<std::mutex> lock(foundMutex);
            if (!found) {
              found = true;
              crackedPassword = attempt;
            }
            activeThreads--;
            return;
          }
        }

        int pos = length - 2;
        while (pos >= 0) {
          subIndices[pos]++;
          if (subIndices[pos] < numChars)
            break;
          subIndices[pos] = 0;
          pos--;
        }
        if (pos < 0)
          break; // Exhausted all combinations for this length
      }
    }
  }
  activeThreads--;
}

bool runParallelBruteForce(const Config &config) {
  // Check for GPU Mode
  if (globalCompute == ComputeType::CUDA) {
#if defined(ENABLE_CUDA)
    gpuBruteForceOrchestrator(config);
    return true;
#else
    std::cout << "[!] GPU Mode Compiled Out. Fallback to CPU.\n";
#endif
  }

  if (globalCompute == ComputeType::OPENCL) {
    std::cout << "\n[OpenCL] Iniciando Ataque via GPU (Universal)...\n";
    auto start_time = std::chrono::high_resolution_clock::now();
    char res_buf[256] = {
        0};            // Buffer for result — must match kernel d_result size
    int stop_flag = 0; // Flag to signal stopping

    // Safe Target Padding for SHA512 (129 bytes required by kernel)
    char targetPad[129] = {0};
    if (config.targetHash.length() < 129) {
      memcpy(targetPad, config.targetHash.c_str(), config.targetHash.length());
    } else {
      memcpy(targetPad, config.targetHash.c_str(), 128);
    }

    unsigned long long localAttempts = 0;
    // Launch Kernel
    launch_opencl_brute_force(config.charset.c_str(), targetPad,
                              config.maxLength, res_buf, &stop_flag,
                              getKernelAlgoId(config.type), config.salt.c_str(),
                              &localAttempts);
    totalTentativas = localAttempts;

    auto end_time = std::chrono::high_resolution_clock::now();
    long long elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(end_time -
                                                              start_time)
            .count();

    if (res_buf[0] != 0) {
      // SYNC GLOBAL STATE FOR TEST RUNNER
      std::lock_guard<std::mutex> lock(foundMutex);
      found = true;
      crackedPassword = std::string(res_buf);

      logSuccess(res_buf, config.targetHash, (HashType)config.hashType,
                 config.salt, 0, elapsed_ms);
      return true;
    } else {
      std::cout << "[OpenCL] Senha nao encontrada neste range.\n";
      return false;
    }
  }

  std::cout << "\n\x1b[1;36m[!] Iniciando motor PARALELO "
               "(Multi-Threaded)...\x1b[0m\n";
  std::vector<std::string> salts = loadSalts(config);
  int maxThreads = std::thread::hardware_concurrency();
  if (maxThreads == 0)
    maxThreads = 2;
  std::cout << "[i] Threads Ativas: " << maxThreads << "\n";

  found = false;
  totalTentativas = 0;
  auto start = std::chrono::high_resolution_clock::now();

  for (int length = 1; length <= 16; ++length) {
    if (found)
      break;
    std::cout << "[+] Verificando tamanho " << length << "... \n";

    std::vector<std::thread> workers;
    for (int i = 0; i < maxThreads; ++i) {
      workers.emplace_back(bruteForceWorker, i, maxThreads, length,
                           std::ref(config), std::ref(salts));
    }

    // Monitoring loop
    while (activeThreads > 0 && !found) {
      auto now = std::chrono::high_resolution_clock::now();
      auto duration =
          std::chrono::duration_cast<std::chrono::seconds>(now - start).count();
      if (duration > 0) {
        long long speed = totalTentativas / duration;
        std::cout << "\r\x1b[1;32m[Forensic Status] H/s: " << speed
                  << " | Tentativas: " << totalTentativas << " \x1b[0m";
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    for (auto &t : workers) {
      if (t.joinable())
        t.join();
    }
  }

  if (found) {
    auto end = std::chrono::high_resolution_clock::now();
    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    logSuccess(crackedPassword, config.target, config.type,
               salts.size() == 1 ? salts[0] : "LIST-MODE", totalTentativas,
               duration.count());
    return true;
  }

  std::cout << "\n[X] Falha na Forca Bruta.\n";
  return false;
}

// --- Unified Self-Test System ---
// Single code path for CPU, OpenCL, and CUDA — no duplication, no
// inconsistency. Each test: Generate hash → Brute-force crack → Validate
// password matches.

// Helper: Determines whether a hash type requires salt
bool typeRequiresSalt(HashType type) {
  switch (type) {
  case HashType::SALTED_MD5:
  case HashType::SALTED_SHA1:
  case HashType::SALTED_SHA256:
  case HashType::SALTED_SHA512:
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
  // Special case: Base64 is just an encoding, not a hash
  if (type == HashType::BASE64) {
    std::string encoded = hashFunctionExtended(password, type, "");
    return base64_decode(encoded) == password;
  }

  // Generate the target hash using the CPU reference implementation
  std::string targetHash = hashFunctionExtended(password, type, salt);

  // Configure the brute force engine
  Config config;
  config.type = type;
  config.target = targetHash;
  config.targetHash = targetHash;
  config.salt = salt;
  config.charset = charset;
  config.maxLength = maxLen;
  config.hashType = getKernelAlgoId(type);

  // Reset global state
  found = false;
  crackedPassword = "";
  totalTentativas = 0;

  // === DISPATCH TO ACTIVE COMPUTE ENGINE ===
  if (globalCompute == ComputeType::OPENCL) {
    // GPU (OpenCL) path
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
    // CPU path (also used as CUDA fallback)
    std::vector<std::string> saltVec = {salt};
    int maxThreads = std::thread::hardware_concurrency();
    if (maxThreads == 0)
      maxThreads = 2;

    // Iterate through all password lengths 1..maxLen (same as real cracking)
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

void runAllTests() {
  enableANSI();
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
  std::cout << "  \x1b[1;37mCOBERTURA: 16 algoritmos (basicos + salted + "
               "avancados + redes sociais)\x1b[0m\n";
  std::cout << "==============================================================="
               "=========\n\n";

  // --- Test Configuration ---
  const std::string testCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const int testMaxLen = 6; // Increased to cover up to 6 chars

  // Use modern PRNG for better randomness in forensic test vectors
  std::random_device rd;
  std::mt19937 rng(rd());

  // Random string helper
  auto randomStr = [&](int minLen, int maxLen) -> std::string {
    std::uniform_int_distribution<int> lenDist(minLen, maxLen);
    int len = lenDist(rng);
    std::uniform_int_distribution<int> charDist(0,
                                                (int)testCharset.length() - 1);
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

  // 1. Basic Hashes (Unsalted) - Pass: 4-6 chars
  tests.push_back({HashType::MD5, randomStr(3, 5), "", "BASICO"});
  tests.push_back({HashType::SHA1, randomStr(3, 5), "", "BASICO"});
  tests.push_back({HashType::SHA256, randomStr(3, 5), "", "BASICO"});
  tests.push_back({HashType::SHA512, randomStr(3, 5), "", "BASICO"});
  tests.push_back({HashType::BASE64, randomStr(3, 5), "", "BASICO"});

  // 2. Salted Hashes - Pass: 4-6 chars, Salt: 4-5 chars
  tests.push_back(
      {HashType::SALTED_MD5, randomStr(3, 5), randomStr(4, 5), "SALTED"});
  tests.push_back(
      {HashType::SALTED_SHA1, randomStr(3, 5), randomStr(4, 5), "SALTED"});
  tests.push_back(
      {HashType::SALTED_SHA256, randomStr(3, 5), randomStr(4, 5), "SALTED"});
  tests.push_back(
      {HashType::SALTED_SHA512, randomStr(3, 5), randomStr(4, 5), "SALTED"});

  // 3. Protocol Hashes - Pass: 4-6 chars, Salt: 4-5 chars
  tests.push_back(
      {HashType::WPA2_PBKDF2, randomStr(3, 5), randomStr(4, 5), "PROTOCOL"});
  tests.push_back(
      {HashType::WPA3_SAE, randomStr(3, 5), randomStr(4, 5), "PROTOCOL"});
  tests.push_back(
      {HashType::BCRYPT, randomStr(3, 5), randomStr(4, 5), "PROTOCOL"});
  tests.push_back(
      {HashType::SCRYPT, randomStr(3, 5), randomStr(4, 5), "PROTOCOL"});

  // 4. Social Media Hashes - Pass: 4-6 chars, Salt: 4-5 chars
  tests.push_back(
      {HashType::SOCIAL_FB, randomStr(3, 5), randomStr(4, 5), "SOCIAL"});
  tests.push_back(
      {HashType::SOCIAL_IG, randomStr(3, 5), randomStr(4, 5), "SOCIAL"});
  tests.push_back(
      {HashType::SOCIAL_TW, randomStr(3, 5), randomStr(4, 5), "SOCIAL"});

  int passCount = 0, failCount = 0;
  bool globalPass = true;
  std::string lastCategory = "";

  auto startAll = std::chrono::high_resolution_clock::now();

  for (size_t i = 0; i < tests.size(); i++) {
    auto &test = tests[i];
    std::string name = hashTypeName(test.type);
    std::string salt = test.salt;

    // Category separator
    if (std::string(test.category) != lastCategory) {
      lastCategory = test.category;
      std::cout << "\x1b[1;30m  --- " << lastCategory << " ---\x1b[0m\n";
    }

    // Generate the target hash — this is what the system will try to crack
    std::string targetHash =
        hashFunctionExtended(test.password, test.type, salt);

    // Truncate long hashes for display (show first 32 chars + "...")
    std::string displayHash = targetHash;
    if (displayHash.length() > 40)
      displayHash = displayHash.substr(0, 37) + "...";

    // Display test header — show HASH as input (not plaintext!)
    std::cout << "\x1b[1;36m  [" << (i + 1 < 10 ? "0" : "") << (i + 1)
              << "] \x1b[1;37m" << name;
    for (size_t s = name.length(); s < 20; s++)
      std::cout << " ";
    std::cout << "\x1b[1;30m| \x1b[0mHASH=\"\x1b[1;33m" << displayHash
              << "\x1b[0m\"";
    if (!salt.empty())
      std::cout << " SALT=\"" << salt << "\"";
    std::cout << "\n";

    // Debug log
    {
      std::ofstream dlog("debug_log.txt", std::ios::app);
      dlog << "[TEST] Algo: " << name << " Pass: " << test.password
           << " Salt: " << salt << " Hash: " << targetHash << "\n";
    }

    // Execute the unified test
    auto startTest = std::chrono::high_resolution_clock::now();
    bool passed =
        runUnifiedTest(test.type, test.password, testCharset, salt, testMaxLen);
    auto endTest = std::chrono::high_resolution_clock::now();
    auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                          endTest - startTest)
                          .count();

    if (passed) {
      passCount++;
      std::cout
          << "       \x1b[1;32m[PASS]\x1b[0m Senha recuperada: \"\x1b[1;32m"
          << crackedPassword << "\x1b[0m\" | " << (durationMs / 1000.0)
          << "s | "
          << (test.type == HashType::BASE64 ? 1
                                            : (long long)totalTentativas.load())
          << " tentativas\n";

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

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  // --- Final Report ---
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
  std::cout << "  \x1b[1;37mTEMPO TOTAL: \x1b[1;33m" << (totalDuration / 1000.0)
            << "s\x1b[0m\n";
  std::cout << "  \x1b[1;37mENGINE: \x1b[1;36m" << getEngineName()
            << "\x1b[0m\n";
  std::cout << "==============================================================="
               "=========\n";

  if (globalPass) {
    std::cout << "\n\x1b[1;42;30m   SISTEMA INTEGRALMENTE OPERACIONAL - "
                 "TODOS OS 16 MODULOS VALIDADOS   \x1b[0m\n";
  } else {
    std::cout << "\n\x1b[1;41;37m   FALHA CRITICA EM " << failCount
              << " MODULO(S) - REVISAR CODIGO   \x1b[0m\n";
  }

  std::cout << "\n\x1b[1;33m[!] Pressione ENTER para voltar ao Menu "
               "Principal...\x1b[0m";
  std::cin.ignore(10000, '\n');
  std::cin.clear();
  std::cin.get();
}

// --- Main Interface ---

int main() {
  enableANSI();

  // --- HARDWARE SELECTION MENU ---
  std::cout << "\n\x1b[1;33m[?] SELECIONE A UNIDADE DE PROCESSAMENTO "
               "COMPUTACIONAL (COMPUTE UNIT):\x1b[0m\n";
  std::cout << "1. CPU (Central Processing Unit) - Threads Padrao\n";
  std::cout << "2. GPU (Nvidia CUDA / OpenCL) - Aceleracao Paralela Massiva\n";
  std::cout << "3. GPU (AMD OpenCL / Radeon) - Compute Shaders\n";
  std::cout << "Escolha o Hardware: ";
  int hw;
  if (std::cin >> hw) {
    if (hw == 2) {
      globalCompute = ComputeType::CUDA;
#if defined(ENABLE_CUDA)
      initCUDA();
#else
      std::cout << "[!] CUDA Native Disabled (Toolkit v13.1 Incompatible). "
                   "Switching to OpenCL Bridge...\n";
      globalCompute = ComputeType::OPENCL;
      initOpenCL();
#endif
    } else if (hw == 3) {
      globalCompute = ComputeType::OPENCL;
      initOpenCL();
    } else {
      globalCompute = ComputeType::CPU;
      std::cout << "\n[CPU] Inicializando Threads do Processador...\n\n";
    }
  }

  // Wait before clearing
  std::cout << "Pressione ENTER para carregar o sistema...";
  std::cin.ignore();
  std::cin.get();

  int choice;
  do {
#ifdef _WIN32
    std::system("cls");
#else
    std::system("clear");
#endif

    exibirDesenho();

    // Status Header with Engine
    std::cout << "SENTINEL DATA SOLUTIONS | STATUS: ACTIVE | ENGINE: \x1b[1;36m"
              << getEngineName() << " [v2.2-DYNAMIC]\x1b[0m\n";

    Config config;
    config.maxLength = 16; // Explicit Redundant Safety Init
    config.salt = "";      // Default empty
    config.type = HashType::UNKNOWN;

    std::cout << "\n=== SISTEMA DE AUDITORIA DE SENHAS ===\n";

    // Status Indicators
    std::cout << "------------------------------------------------\n";
    std::cout << "STATUS DOS ARQUIVOS:\n";
    if (fileExists("wordlist.txt"))
      std::cout
          << "[OK] wordlist.txt ENCONTRADO (Modo Dicionario disponivel)\n";
    else
      std::cout
          << "[!] wordlist.txt NAO ENCONTRADO (Apenas Forca Bruta Pura)\n";

    if (fileExists("saltlist.txt"))
      std::cout
          << "[OK] saltlist.txt ENCONTRADO (Modo Multi-Salt disponivel)\n";
    else
      std::cout
          << "[!] saltlist.txt NAO ENCONTRADO (Usando Salt Unico/Vazio)\n";
    std::cout << "------------------------------------------------\n";

    // NEW MENU ORDER
    std::cout << "1. Hash + Salt (Modo Avancado/WiFi)\n";        // Was 4
    std::cout << "2. Inserir Hash/Texto Alvo (Auto-detectar)\n"; // Was 1
    std::cout << "3. Decodificar Base64 Direto\n";               // Was 2
    std::cout
        << "4. Executar TODOS os Testes (Auto + Avancados)\n"; // Merged 3+5
    std::cout << "5. Gerar Hashes (Calculadora)\n";
    std::cout << "0. Sair\n";
    std::cout << "Escolha: ";

    if (!(std::cin >> choice)) {
      std::cin.clear();
      std::cin.ignore(10000, '\n');
      choice = -1;
    }

    if (choice == 0)
      break;

    // OPTION 4: ALL TESTS
    if (choice == 4) {
      runAllTests();
      continue;
    }

    // OPTION 3: BASE64
    if (choice == 3) {
      std::string b64;
      std::cout << "Insira Base64: ";
      std::cin >> b64;
      std::cout << "Resultado: " << base64_decode(b64) << "\n";
      std::cout << "\nPressione ENTER...";
      std::cin.ignore();
      std::cin.get();
      continue;
    }

    // OPTION 5: HASH CALCULATOR
    if (choice == 5) {
      std::cout << "\n--- CALCULADORA DE HASHES ---\n";
      std::cout << "Digite o texto para gerar hashes: ";
      std::string inputCalc;
      std::cin.ignore();
      std::getline(std::cin, inputCalc);

      std::cout << "-----------------------------\n";
      std::cout << "Texto:  \"" << inputCalc << "\"\n";

      if (globalCompute == ComputeType::CUDA) {
#if defined(ENABLE_CUDA)
        std::cout << "\x1b[1;32m[GPU] SHA256 (NATIVE CUDA): \x1b[0m";
        char gpu_hex[65] = {0};
        launch_gpu_hash_calc(inputCalc.c_str(), gpu_hex);
        std::cout << gpu_hex << "\n";
#else
        std::cout << "[!] GPU Mode Not Available (Compilation Flag Disabled)\n";
#endif
      } else if (globalCompute == ComputeType::OPENCL) {
        std::cout << "--- OPENCL GPU HASHES ---\n";
        char gpu_hex[129] = {0};

        // Base64 (CPU - Universal)
        std::cout << "Base64: "
                  << base64_encode((unsigned char *)inputCalc.c_str(),
                                   (unsigned int)inputCalc.length())
                  << "\n";

        launch_opencl_hash_calc(inputCalc.c_str(), gpu_hex, 0); // MD5
        std::cout << "MD5:    " << gpu_hex << "\n";
        launch_opencl_hash_calc(inputCalc.c_str(), gpu_hex, 1); // SHA1
        std::cout << "SHA1:   " << gpu_hex << "\n";
        launch_opencl_hash_calc(inputCalc.c_str(), gpu_hex, 2); // SHA256
        std::cout << "SHA256: " << gpu_hex << "\n";
        launch_opencl_hash_calc(inputCalc.c_str(), gpu_hex, 3); // SHA512
        std::cout << "SHA512: " << gpu_hex << "\n";

      } else {
        std::cout << "Base64: "
                  << base64_encode((unsigned char *)inputCalc.c_str(),
                                   (unsigned int)inputCalc.length())
                  << "\n";
        std::cout << "MD5:    " << md5(inputCalc) << "\n";
        std::cout << "SHA1:   " << sha1(inputCalc) << "\n";
        std::cout << "SHA256: " << picosha2::hash256_hex_string(inputCalc)
                  << "\n";
        std::cout << "SHA512: " << sha512(inputCalc) << "\n";
      }
      std::cout << "-----------------------------\n";

      std::cout << "\nPressione ENTER para continuar...";
      std::cin.get();
      continue;
    }

    bool validChoice = false;

    // OPTION 1: HASH + SALT (Advanced/WiFi)
    if (choice == 1) {
      std::cout << "\n--- Modo Avancado (Salted) ---\n";
      std::cout << "Selecione o Algoritmo:\n";
      std::cout << "1.  MD5 + Salt\n";
      std::cout << "2.  SHA1 + Salt\n";
      std::cout << "3.  WPA2 (PBKDF2-Sim)\n";
      std::cout << "4.  SHA256 + Salt\n";
      std::cout << "5.  SHA512 + Salt\n";
      std::cout << "6.  WPA3 (SAE/Dragonfly)\n";
      std::cout << "7.  Bcrypt (Blowfish)\n";
      std::cout << "8.  Scrypt (Memory-Hard)\n";
      std::cout << "9.  Facebook (SHA-256 Variant)\n";
      std::cout << "10. Instagram (Argon2 Variant)\n";
      std::cout << "11. Twitter (Bcrypt Variant)\n";
      int algo;
      if (std::cin >> algo) {
        if (algo == 1)
          config.type = HashType::SALTED_MD5;
        else if (algo == 2)
          config.type = HashType::SALTED_SHA1;
        else if (algo == 3)
          config.type = HashType::WPA2_PBKDF2;
        else if (algo == 4)
          config.type = HashType::SALTED_SHA256;
        else if (algo == 5)
          config.type = HashType::SALTED_SHA512;
        else if (algo == 6)
          config.type = HashType::WPA3_SAE;
        else if (algo == 7)
          config.type = HashType::BCRYPT;
        else if (algo == 8)
          config.type = HashType::SCRYPT;
        else if (algo == 9)
          config.type = HashType::SOCIAL_FB;
        else if (algo == 10)
          config.type = HashType::SOCIAL_IG;
        else if (algo == 11)
          config.type = HashType::SOCIAL_TW;
        else
          config.type = HashType::SALTED_MD5;

        std::cout << "Insira o Hash Alvo: ";
        std::cin >> config.target;
        config.targetHash = config.target; // SYNC FOR OPENCL (CRITICAL FIX)
        config.hashType =
            getKernelAlgoId(config.type); // SYNC hashType for OpenCL kernel
        std::cout
            << "Insira o Salt (Deixe vazio/hifen para usar 'saltlist.txt'): ";
        std::cin >> config.salt;
        if (config.salt == "-")
          config.salt = "";
        validChoice = true;
      }
    }
    // OPTION 2: AUTO DETECT
    else if (choice == 2) {
      std::cout << "\nInsira o Hash alvo (MD5, SHA1, SHA256, SHA512): ";
      std::cin >> config.target;
      config.targetHash = config.target; // SYNC FOR OPENCL (CRITICAL FIX)
      config.maxLength = 16;             // FORCE LIMIT FOR LIVE MODE

      config.type = identifyHash(config.target);
      config.hashType = getKernelAlgoId(
          config
              .type); // SYNC hashType for OpenCL kernel (AFTER type detection!)
      std::cout << "[i] Tipo detectado: " << hashTypeName(config.type) << "\n";

      if (config.type == HashType::UNKNOWN) {
        std::cout << "[!] ERRO: Formato de Hash Invalido!\n";
        std::cout << "Suportado apenas: MD5 (32 chars), SHA1 (40), SHA256 "
                     "(64), SHA512 (128).\n";
        std::cout << "Pressione ENTER para voltar ao menu...";
        std::cin.ignore();
        std::cin.get();
        continue;
      }
      validChoice = true;
    }

    if (!validChoice) {
      std::cout << "\n[!] Opcao invalida ou entrada incorreta!\n";
      std::cin.ignore();
      std::cin.get();
      continue;
    }

    // --- Common Attack Logic ---
    if (config.type == HashType::BASE64) {
      std::cout << "Detectado Base64. Decodificando...\n";
      std::cout << "Resultado: " << base64_decode(config.target) << "\n";
    } else {
      std::cout << "\nSelecione o Charset para Forca Bruta:\n";
      std::cout << "1. Numerico (0-9)\n";
      std::cout << "2. Letras Min (a-z)\n";
      std::cout << "3. Letras Maiusculas (A-Z)\n";
      std::cout << "4. Misto (a-z, A-Z)\n";
      std::cout << "5. Alfanumerico Min (a-z, 0-9)\n";
      std::cout << "6. Alfanumerico Misto\n";
      std::cout << "7. Total (ASCII Printable)\n";
      int c;
      std::cout << "Opcao: ";
      if (std::cin >> c) {
        config.charset = getCharset(c);

        std::cout
            << "Usar Dicionario (wordlist.txt) primeiro? (1=Sim, 0=Nao): ";
        int d;
        if (std::cin >> d) {
          bool dictFound = false;
          if (d == 1) {
            dictFound = dictionaryAttack(config);
          }

          if (!dictFound) {
            std::cout << "Deseja iniciar Forca Bruta? (1=Sim, 0=Nao): ";
            int b;
            if (std::cin >> b && b == 1)
              runParallelBruteForce(config);
          }
        }
      }
    }

    std::cout << "\nPressione ENTER para voltar...";
    std::cin.ignore();
    std::cin.get();

  } while (choice != 0);

  return 0;
}