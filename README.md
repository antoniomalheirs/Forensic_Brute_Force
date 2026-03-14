# 🛡️ Forensic Brute Force (High-Speed Methods)

[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue?style=for-the-badge&logo=cplusplus)](https://isocpp.org/)
[![Performance](https://img.shields.io/badge/Engine-SIMD_Optimized-red?style=for-the-badge)](https://en.wikipedia.org/wiki/SIMD)

A specialized C++20 framework for high-performance cryptographic recovery and hash auditing. Designed for forensic professionals, this tool implements advanced multi-threaded attack vectors to recover access to protected data with maximum efficiency.

## ⚔️ Multi-Vector Attack Architecture

The system supports multiple concurrent attack methodologies, each optimized for specific data types.

```mermaid
graph TD
    Input[Protected Target / Hash] --> Dispatch[Vector Dispatcher]
    
    subgraph "Attack Vectors"
        Dispatch --> Dictionary[Dictionary Attack - Rule Based]
        Dispatch --> Brute[Brute Force - Incremental]
        Dispatch --> Hybrid[Hybrid / Mask Attack]
    end
    
    Dictionary --> Threading[Parallel Execution Engine]
    Brute --> Threading
    Hybrid --> Threading
    
    Threading --> SIMD[SIMD Optimization - AVX2/AVX-512]
    SIMD --> Success[Key/Password Recovered]
```

## 🛠️ Technical Specifications
- **Hardware Acceleration**: Utilizes SIMD instructions (AVX2/AVX-512) for a 10x speedup in hash comparisons.
- **Rule-based Engine**: Supports complex dictionary mutations (Leetspeak, append, prepend).
- **Checkpointing**: Real-time state persistence allowed pausing and resuming long-running tasks.

---
**Sentinel Data Solutions** | *Advanced Forensic Cryptography*
**Developed by Zeca**
