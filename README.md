<p align="center">
  <img src="https://img.shields.io/badge/C%2B%2B-17-00599C?style=for-the-badge&logo=cplusplus&logoColor=white" alt="C++17" />
  <img src="https://img.shields.io/badge/CUDA-11%2B-76B900?style=for-the-badge&logo=nvidia&logoColor=white" alt="CUDA" />
  <img src="https://img.shields.io/badge/OpenCL-Universal-ED1C24?style=for-the-badge&logo=khronos&logoColor=white" alt="OpenCL" />
  <img src="https://img.shields.io/badge/Platform-Windows_x64-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="Windows" />
  <img src="https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge" alt="MIT License" />
</p>

<h1 align="center">
  🛡️ SENTINEL DATA SOLUTIONS
</h1>

<h3 align="center">
  <em>Advanced Cryptographic Analysis & Forensic Auditing System</em>
</h3>

<p align="center">
  <strong>A high-performance, GPU-accelerated cryptographic auditing framework designed for forensic investigators, penetration testers, and security researchers. Built from the ground up in C++17 with native CUDA and OpenCL compute backends.</strong>
</p>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [Supported Hash Algorithms](#-supported-hash-algorithms)
- [Attack Vectors](#-attack-vectors)
- [System Requirements](#-system-requirements)
- [Build Instructions](#-build-instructions)
- [Usage Guide](#-usage-guide)
- [Audit Logging](#-audit-logging)
- [Project Structure](#-project-structure)
- [Legal Disclaimer](#%EF%B8%8F-legal-disclaimer--ethical-use-policy)
- [Author](#-author)

---

## 🔍 Overview

**Sentinel Data Solutions** is a forensic-grade cryptographic auditing suite that demonstrates the mathematical vulnerability of weak passwords against modern hardware. Originally conceived as an educational brute-force simulator, it has evolved into a comprehensive multi-engine analysis platform capable of auditing **16 distinct hash algorithms** across **3 compute backends** — CPU multi-threading, NVIDIA CUDA, and OpenCL — providing investigators with a tangible, reproducible framework for password strength assessment.

> [!IMPORTANT]
> This tool is intended **exclusively** for authorized security auditing, academic research, and forensic education. Unauthorized use against systems you do not own or have explicit written permission to test is **illegal** and **unethical**.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   SENTINEL DATA SOLUTIONS               │
│              Forensic Audit Control Plane                │
├────────────┬────────────────────┬───────────────────────┤
│  DICTIONARY│   BRUTE FORCE      │   SELF-TEST MATRIX    │
│  + MUTATION│   INCREMENTAL      │   (16-Module Audit)   │
├────────────┴────────────────────┴───────────────────────┤
│              HASH ENGINE ABSTRACTION LAYER              │
│   MD5 │ SHA-1 │ SHA-256 │ SHA-512 │ PBKDF2 │ Bcrypt    │
│   Scrypt │ WPA3-SAE │ Argon2 (sim) │ Base64 │ + Salts  │
├─────────────────────────────────────────────────────────┤
│               COMPUTE BACKEND SELECTOR                  │
│  ┌──────────┐  ┌──────────────┐  ┌────────────────┐    │
│  │   CPU    │  │ NVIDIA CUDA  │  │    OpenCL      │    │
│  │ (x86-64) │  │ (GTX/RTX)    │  │ (AMD/Intel/NV) │    │
│  │ N-Thread │  │  .cu Kernels │  │  .cl Kernels   │    │
│  └──────────┘  └──────────────┘  └────────────────┘    │
├─────────────────────────────────────────────────────────┤
│  LOGGING: cracked_passwords.txt  │  FORMAT: HASH|SALT  │
└─────────────────────────────────────────────────────────┘
```

### Compute Engines

| Engine | Technology | Use Case | Requirements |
|:---|:---|:---|:---|
| **CPU** | C++17 `std::thread` | Universal fallback, baseline benchmarks | Any x86-64 processor |
| **CUDA** | NVIDIA CUDA 11+ | Maximum throughput on NVIDIA hardware | NVIDIA GPU + CUDA Toolkit |
| **OpenCL** | Khronos OpenCL 1.2+ | Cross-vendor GPU acceleration | AMD, Intel, or NVIDIA GPU |

The engine is selected at runtime. If CUDA initialization fails (e.g., incompatible hardware), the system automatically falls back to the **OpenCL bridge**, ensuring GPU acceleration is available on virtually any modern discrete GPU.

---

## 🔐 Supported Hash Algorithms

Sentinel audits **16 cryptographic algorithms** spanning legacy, modern, and protocol-specific constructions:

### Core Algorithms (Native CPU + GPU Kernels)

| # | Algorithm | Type | Digest Length | Salt Support |
|:---:|:---|:---|:---:|:---:|
| 1 | `MD5` | Legacy | 128-bit | ❌ |
| 2 | `MD5 + Salt` | Legacy | 128-bit | ✅ |
| 3 | `SHA-1` | Legacy | 160-bit | ❌ |
| 4 | `SHA-1 + Salt` | Legacy | 160-bit | ✅ |
| 5 | `SHA-256` | NIST Standard | 256-bit | ❌ |
| 6 | `SHA-256 + Salt` | NIST Standard | 256-bit | ✅ |
| 7 | `SHA-512` | NIST Standard | 512-bit | ❌ |
| 8 | `SHA-512 + Salt` | NIST Standard | 512-bit | ✅ |
| 9 | `Base64` | Encoding | Variable | ❌ |

### Protocol & KDF Simulations

| # | Algorithm | Protocol | Notes |
|:---:|:---|:---|:---|
| 10 | `WPA2 (PBKDF2-Sim)` | IEEE 802.11i | HMAC-SHA1 derived key simulation |
| 11 | `WPA3 (SAE/Dragonfly)` | IEEE 802.11s | Simultaneous Authentication of Equals |
| 12 | `Bcrypt (Blowfish)` | UNIX crypt | Cost factor `$2a$12$` |
| 13 | `Scrypt (Memory-Hard)` | RFC 7914 | Parameters: `N=16384, r=8, p=1` |

### Social Media Profile Simulations

| # | Algorithm | Platform | Construction |
|:---:|:---|:---|:---|
| 14 | `Facebook` | Meta | `SHA-256(salt ∥ password)` |
| 15 | `Instagram` | Meta | `SHA-512(password ∥ salt ∥ "instagram_v1")` (Argon2 sim) |
| 16 | `Twitter/X` | X Corp | `MD5(password ∥ salt ∥ "twitter_salt")` (Bcrypt sim) |

> [!NOTE]
> Protocol and social media modules are **forensic simulations** designed for educational demonstration. They replicate the structural behavior of each algorithm for proof-of-concept auditing without requiring external network access.

---

## ⚔️ Attack Vectors

### 1. Smart Dictionary Attack
Loads candidates from `wordlist.txt` and applies **automatic mutation rules** to each entry:

| Mutation | Example (`password`) |
|:---|:---|
| Original | `password` |
| Case Toggle | `Password` |
| Numeric Append | `password123`, `password1234` |
| Year Append | `password2024`, `password2025` |
| Symbol Append | `password!`, `password@`, `password#` |

Each mutated candidate is tested against every loaded salt (from `saltlist.txt` or a single specified salt), dramatically expanding dictionary coverage without proportional increase in file size.

### 2. Incremental Brute Force
Exhaustive keyspace enumeration from length 1 to 16 characters, with **7 configurable character sets**:

| Set | Characters | Keyspace (8-char) |
|:---:|:---|:---|
| 1 | `0-9` | 10⁸ |
| 2 | `a-z` | ~2.1 × 10¹¹ |
| 3 | `A-Z` | ~2.1 × 10¹¹ |
| 4 | `a-zA-Z` | ~5.3 × 10¹³ |
| 5 | `a-z0-9` | ~2.8 × 10¹² |
| 6 | `a-zA-Z0-9` | ~2.2 × 10¹⁴ |
| 7 | Full ASCII (printable) | ~6.6 × 10¹⁵ |

On GPU, each candidate is hashed in parallel across thousands of CUDA cores or OpenCL work-items.

### 3. Automated Audit Matrix (Self-Test)
A fully automated **16-module validation suite** that:
1. Generates a random password and salt per algorithm
2. Computes the target hash
3. Launches the configured engine to crack it
4. Reports success/failure with timing metrics

This mode serves as a **proof-of-concept showcase** and a regression test for all hash modules.

### 4. Hash Calculator (Utility)
A non-destructive utility that accepts plaintext input and instantly generates fingerprints across all supported hash algorithms — useful for evidence tagging, file integrity verification, and quick reference.

---

## 💻 System Requirements

| Component | Minimum | Recommended |
|:---|:---|:---|
| **OS** | Windows 10 x64 | Windows 11 x64 |
| **Compiler** | MSVC 2019 (v142) | MSVC 2022 (v143) |
| **C++ Standard** | C++17 | C++17 |
| **CPU** | 2 cores | 8+ cores (Ryzen / Core i7) |
| **GPU (CUDA)** | GTX 900 Series | RTX 3000+ Series |
| **GPU (OpenCL)** | Any OpenCL 1.2 device | Discrete GPU w/ 4GB+ VRAM |
| **CUDA Toolkit** | 11.0 | 12.0+ |
| **RAM** | 4 GB | 16 GB |

---

## 🔧 Build Instructions

### Option 1 — Automated Build (Recommended)

The included `build.bat` script handles compilation of C++ host code, CUDA kernels, and final linking:

```cmd
:: 1. Verify paths in build.bat (Visual Studio & CUDA Toolkit)
:: 2. Run from Developer Command Prompt or PowerShell
.\build.bat
```

### Option 2 — Manual Compilation

**CPU + OpenCL Only** (no NVIDIA dependency):
```cmd
g++ "Brute Force Methods.cpp" opencl_kernels.cpp -o sentinel_audit.exe -O3 -std=c++17 -lOpenCL
```

**CPU + CUDA** (native NVIDIA acceleration):
```cmd
nvcc "Brute Force Methods.cpp" gpu_kernels.cu -o sentinel_audit_cuda.exe -O3 -std=c++17 -DENABLE_CUDA
```

**CPU Only** (minimal build, no GPU):
```cmd
g++ "Brute Force Methods.cpp" -o sentinel_cpu.exe -O3 -std=c++17 -DCPU_ONLY
```

> [!TIP]
> If using Visual Studio, open `Brute Force Methods.sln` and build via the IDE. CUDA kernels require the CUDA build customization to be installed.

---

## 🎯 Usage Guide

### Engine Selection (Startup)

Upon execution, the system performs hardware detection and prompts for engine selection:

```
[1] CPU     — Multi-threaded (All Cores)
[2] NVIDIA  — CUDA Native (GTX/RTX)
[3] OpenCL  — Universal GPU (AMD/Intel/NVIDIA)
```

### Main Menu

```
┌──────────────────────────────────────────────┐
│  [1] Advanced Mode    — Salted/WiFi hashes   │
│  [2] Auto-Detect      — Paste hash, auto-ID  │
│  [3] Base64 Decode    — Quick decode utility  │
│  [4] Run All Tests    — 16-Module audit       │
│  [5] Hash Calculator  — Generate fingerprints │
└──────────────────────────────────────────────┘
```

| Mode | Description |
|:---|:---|
| **Advanced Mode** | For complex targets: WPA2, Bcrypt, Scrypt, or any hash with a known salt. Prompts for hash type, target, salt, and charset. |
| **Auto-Detect** | Paste a raw hash — the system identifies its type (MD5/SHA-1/SHA-256/SHA-512/Base64) by length heuristics and launches the appropriate attack. |
| **Base64 Decode** | Instant Base64 → plaintext decoder. |
| **Run All Tests** | The **flagship demo mode**. Sequentially generates and cracks test vectors for all 16 modules, producing a full audit report. |
| **Hash Calculator** | Enter plaintext → receive MD5, SHA-1, SHA-256, and SHA-512 digests simultaneously. |

### Support Files

| File | Purpose |
|:---|:---|
| `wordlist.txt` | Dictionary of candidate passwords for dictionary attacks |
| `saltlist.txt` | List of salts for batch auditing of salted hashes |

---

## 📄 Audit Logging

All successful cracks are persisted to disk for chain-of-custody documentation:

- **File:** `cracked_passwords.txt`
- **Format:** `HASH | SALT | DECRYPTED_PASSWORD`

```
5d41402abc4b2a76b9719d911017c592 | - | hello
e99a18c428cb38d5f260853678922e03 | s4lt | abc123
```

Each entry provides the **original hash**, the **salt used** (or `-` if unsalted), and the **recovered plaintext** — suitable for inclusion in forensic audit reports.

---

## 📁 Project Structure

```
Brute_Force_Methods/
├── Brute Force Methods.cpp    # Main application (1400+ lines)
├── Brute Force Methods.sln    # Visual Studio solution
├── gpu_kernels.cu             # CUDA compute kernels
├── opencl_kernels.cpp         # OpenCL compute kernels
├── md5.h                      # MD5 implementation
├── sha1.h                     # SHA-1 implementation
├── picosha2.h                 # SHA-256 implementation (PicoSHA2)
├── sha512.h                   # SHA-512 implementation
├── base64.h                   # Base64 encode/decode
├── build.bat                  # Automated build script
├── wordlist.txt               # Dictionary for attacks
├── saltlist.txt               # Salt list for batch audits
├── cracked_passwords.txt      # Audit results log
├── LICENSE                    # MIT License
└── README.md                  # This document
```

---

## ⚠️ Legal Disclaimer & Ethical Use Policy

> [!CAUTION]
> **THIS SOFTWARE IS PROVIDED FOR AUTHORIZED SECURITY AUDITING, FORENSIC EDUCATION, AND ACADEMIC RESEARCH PURPOSES ONLY.**

By using Sentinel Data Solutions, you agree to the following:

1. **Authorization Required** — You will **only** use this tool against systems, networks, files, or hashes that you **own** or have **explicit written authorization** to audit.

2. **Educational Intent** — This tool was built to demonstrate the mathematical insecurity of weak passwords and the critical importance of strong, modern cryptographic practices (key stretching, salting, memory-hard KDFs).

3. **No Liability** — The author(s) assume **no responsibility** for any misuse of this software. All liability rests with the end user.

4. **Compliance** — Users are responsible for ensuring their use of this tool complies with all applicable local, national, and international laws, including but not limited to the Computer Fraud and Abuse Act (CFAA), GDPR, and equivalent legislation.

---

## 👤 Author

**Antônio Malheiros (Zeca)**

C++ High-Performance Computing · GPU Compute · Forensic Security Research

<p align="center">
  <sub>© 2026 Antônio Malheiros · Released under the <a href="LICENSE">MIT License</a></sub>
</p>
