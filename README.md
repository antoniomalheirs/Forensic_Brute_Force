<div align="center">
  <p>
    <a href="#english-version">🇺🇸 English</a> &nbsp; | &nbsp; <a href="#versão-em-português">🇧🇷 Português</a>
  </p>
</div>

---

<a id="english-version"></a>

```text
  ____  _____  ____   ____   _____  ____   _   _  ____  
 / ___|| ____||  _ \ | __ ) | ____||  _ \ | | | |/ ___| 
| |    |  _|  | |_) ||  _ \ |  _|  | |_) || | | |\___ \ 
| |___ | |___ |  _ < | |_) || |___ |  _ < | |_| | ___) |
 \____||_____||_| \_\|____/ |_____||_| \_\ \___/ |____/ 
----------------------------------------------------------------------------
 CERBERUS FORENSIC SUITE >> TRIPLE-HEADED PASSWORD RECOVERY & AUDIT ENGINE
----------------------------------------------------------------------------
```

<div align="center">

  <img src="https://img.shields.io/badge/C++-20-00599C?style=for-the-badge&logo=cplusplus&logoColor=white" alt="C++20">
  <img src="https://img.shields.io/badge/CERBERUS-v3.0--FORENSIC-red?style=for-the-badge" alt="Cerberus">
  <img src="https://img.shields.io/badge/Architecture-Triple--Headed-purple?style=for-the-badge" alt="Triple-Headed">
  <img src="https://img.shields.io/badge/Hardware-OpenCL_&_CUDA-blue?style=for-the-badge" alt="Acceleration">
  <img src="https://img.shields.io/badge/Grade-Kali_Linux_Ready-557C93?style=for-the-badge&logo=kalilinux&logoColor=white" alt="Kali Ready">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="MIT License">
  <br><br>

  <p><b>CERBERUS is an industrial-grade cryptographic recovery and forensic audit framework.<br>
  Built on modern C++20 for forensic investigators, penetration testers, and security research teams,<br>
  featuring multi-threaded CPU parallel dispatch and massive OpenCL/CUDA GPU acceleration.</b></p>
</div>

<br>

### 🔱 The Triple-Headed Engine Architecture

Named after the mythical guardian of the underworld, **CERBERUS** attacks password entropy through three unified, synchronized vectors:

```
                     ┌──────────────────────────────┐
                     │       C E R B E R U S        │
                     └──────────────┬───────────────┘
            ┌───────────────────────┼───────────────────────┐
            │                       │                       │
       [HEAD I]                 [HEAD II]               [HEAD III]
     Memory Head             Heuristic Head         Brute-Force Head
  (Potfile Cache 0ms)     (Mutation Dictionary)   (GPU OpenCL/CUDA + CPU)
```

1. **Head I — The Memory Head (Forensic Potfile Cache)**
   - Ultra-fast $0\text{ ms}$ cache lookup against `cracked_passwords.txt` before engaging any compute resources.
   - Prevents duplicate computing and provides instant retrieval for previously recovered hashes.
   - Built-in interactive and CLI potfile viewer (`cerberus history` / `cerberus potfile`).

2. **Head II — The Heuristic Head (Rule-Based Mutation Dictionary)**
   - High-throughput wordlist stream with real-time heuristic mutations (case inversion, title case, leetspeak, reversals, word doubling).
   - Automated MD5 $\leftrightarrow$ NTLM cascade hypothesis for 32-character hexadecimal targets.

3. **Head III — The Brute-Force Head (Universal GPU & CPU Parallel Core)**
   - **OpenCL 3.0 Universal GPU Engine:** High-performance JIT-compiled kernels supporting NVIDIA, AMD, and Intel GPUs (~$860+\text{ MH/s}$ on modern hardware).
   - **NVIDIA CUDA Runtime Engine:** Native warp and thread-block execution.
   - **CPU Multi-Threaded Engine:** Low-overhead thread-pool permuting combinations with zero-heap in-place odometer mutation.

---

### ⚡ Hardware Performance Benchmarks

Measured on dedicated hardware (**NVIDIA GeForce GTX 1070 8GB**):

| Algorithm | Standard / Target | Throughput (Hashrate) | Method |
| :--- | :--- | :---: | :--- |
| **NTLM** | Windows SAM / Active Directory | **863.84 MH/s** | OpenCL GPU Universal Kernel |
| **MD4** | RFC 1320 Legacy Standard | **863.84 MH/s** | OpenCL GPU Universal Kernel |
| **MD5** | RFC 1321 Cryptographic Hash | **345.54 MH/s** | OpenCL GPU Universal Kernel |
| **SHA-256** | FIPS 180-4 NIST Standard | **287.95 MH/s** | OpenCL GPU Universal Kernel |
| **SHA-1** | FIPS 180-1 Security Standard | **246.81 MH/s** | OpenCL GPU Universal Kernel |
| **SHA-512** | FIPS 180-4 High-Entropy Hash | **132.90 MH/s** | OpenCL GPU Universal Kernel |
| **CPU Worker Pool** | All Algorithms (Multi-Core) | **~45+ MH/s** | C++20 Thread Pool (Batched Atomic) |

---

### 🛡️ Cryptographic Coverage Matrix

- **Standard Primitives & Forensic Formats:** CRC32 (IEEE 802.3), MD5 (RFC 1321), SHA-1 (FIPS 180-1), SHA-224 (FIPS 180-4), SHA-256 (FIPS 180-4), SHA-384 (FIPS 180-4), SHA-512 (FIPS 180-4), **NTLM** (Windows SAM / Active Directory NT-Hash), **MD4** (RFC 1320), Base64 (RFC 4648 strict).
- **Salted Hash Variants:** Salted MD5, Salted SHA-1, Salted SHA-256, Salted SHA-512 (single-salt or `saltlist.txt` list mode, auto-detects `hash:salt` and `salt:hash`).
- **HMAC & PBKDF2 Primitives:** HMAC-MD5, HMAC-SHA1, HMAC-SHA256 (RFC 2104), PBKDF2-HMAC-SHA1 (RFC 2898 / RFC 6070).
- **Simulated Protocols & Social Media Profiles:** WPA2 (PBKDF2-Sim), WPA3 (SAE Dragonfly Commit-Sim), Bcrypt ($2a$), Scrypt, Facebook (FB_SHA256), Instagram (IG_ARGON2), Twitter (TW_BCRYPT).

---

### 🖥️ User Experience (UX) & Terminal Telemetry

CERBERUS features a modern terminal interface designed for 80-column terminals with ANSI styling and zero console ghosting:

#### 1. Real-Time Telemetry Display
Dynamic single-line progress updates with visual progress bar, hashrate, real-time ETA, and elapsed time counter:
```text
[CPU Multi-Thread] L4/16 [====------]  38.5% | 18.42 MH/s | ETA 00:04 | 00:02
[OpenCL] L3/5            [=========---] 75.0% | 85.20 MH/s | ETA 00:01 | 00:00
```

#### 2. Forensic Result Cards
```text
  ==========================================================================
  |  ✓ SUCESSO: CREDENCIAL RECUPERADA                                      |
  +------------------------------------------------------------------------+
  |  HASH ALVO    : 5d41402abc4b2a76b9719d911017c592                       |
  |  SENHA        : hello                                                  |
  |  ALGORITMO    : MD5                                                    |
  |  METODO       : Força Bruta GPU (OpenCL)                              |
  |  ENGINE       : v3.0-OPENCL (NVIDIA GeForce GTX 1070)                  |
  |  TEMPO        : 22ms (0.022s)                                          |
  |  TENTATIVAS   : 13,686,207 (622.10 MH/s)                               |
  ==========================================================================
    [+] Sincronizado em: cracked_passwords.txt
```

#### 3. Potfile Cache Hit Card (0ms Computation)
```text
  ==========================================================================
  |  ⚡ POTFILE CACHE HIT (RECUPERAÇÃO INSTANTÂNEA)                         |
  +------------------------------------------------------------------------+
  |  HASH ALVO    : 5d41402abc4b2a76b9719d911017c592                       |
  |  SENHA        : hello                                                  |
  |  ALGORITMO    : MD5                                                    |
  |  ORIGEM       : cracked_passwords.txt (0ms de computação)              |
  ==========================================================================
```

#### 4. Actionable Keyspace Exhausted Card
```text
  ==========================================================================
  |  ✗ ESGOTADO: SENHA NÃO ENCONTRADA                                      |
  +------------------------------------------------------------------------+
  |  HASH ALVO    : 5d41402abc4b2a76b9719d911017c592                       |
  |  ALGORITMO    : MD5                                                    |
  |  KEYSPACE     : Tamanho 1..3 | Charset: 36 chars                       |
  |  ENGINE       : v3.0-OPENCL (NVIDIA GeForce GTX 1070)                  |
  |  TEMPO        : 8ms (0.008s)                                           |
  |  TENTATIVAS   : 47,988 (5.99 MH/s)                                     |
  +------------------------------------------------------------------------+
  |  SUGESTÕES FORENSES:                                                   |
  |   - Expandir comprimento de busca: --max-len 5                         |
  |   - Incluir símbolos especiais no charset: --charset 6 ou 7            |
  |   - Utilizar wordlist estendida: --wordlist rockyou.txt                |
  ==========================================================================
```

#### 5. Multi-Hash Batch Audit Executive Summary
```text
================================================================================
                         RELATÓRIO DE AUDITORIA EM LOTE                         
================================================================================
 Total de Alvos        : 3
 Recuperados (Sucesso) : 3 (100.0%) [Novos: 1 | Cache Potfile: 2]
 Nao Recuperados       : 0 (0.0%)
 Tempo Total Auditado  : 14ms (0.014s)
 Tentativas Globais    : 13,686,209 (977.59 MH/s)
================================================================================
 ID  | HASH ALVO (Truncado)            | STATUS  | ALGORITMO   | SENHA RECUPERADA
-----+---------------------------------+---------+-------------+----------------
 01  | 0192023a7bbd73...16f069df18b500 | CACHED  | MD5         | admin123
 02  | 5d41402abc4b2a...719d911017c592 | CRACKED | MD5         | hello
 03  | 209c6174da490c...22f3fa5a7ae634 | CACHED  | NTLM (Windo | admin
================================================================================
```

---

### 🕹️ Command Reference & CLI Options

#### Command Hierarchy

| Command | Aliases | Arguments | Description |
| :--- | :--- | :--- | :--- |
| `crack` | `c` | `<hash>` | Auto-detects and breaks hash via the 3-headed pipeline |
| `crack-salt` | `cs` | `<hash> -s <salt>` | Breaks salted hash or composite `hash:salt` string |
| `decode` | `d` | `<base64>` | Instant strict Base64 decoding |
| `hash` | `g` | `<text> [-s salt]` | Generates full cryptographic matrix for plain text |
| `file` / `batch` | `f` | `<targets.txt>` | Batch multi-target audit with executive table report |
| `history` | `potfile`, `show` | `[file.txt]` | Displays all cracked credentials from potfile database |
| `test-all` | `test`, `t` | *(none)* | Comprehensive 18-module precision test suite |
| `benchmark` | `bench`, `b` | *(none)* | Maximum hardware throughput benchmark (GPU/CPU) |
| `help` | `h`, `?` | *(none)* | Displays complete syntax help and examples |
| `version` | `v` | *(none)* | Displays version, engine capabilities, and metadata |

#### CLI Flags & Modifiers

* `--engine, -e <cpu|opencl|cuda>`: Explicitly select compute unit.
* `--algo, -a <md5|sha1|sha256|sha512|ntlm|md4|...>`: Override auto-detection and force specific algorithm.
* `--charset, -c <1-7>`: Select keyspace character set (1=Numeric, 2=a-z, 4=a-zA-Z, 5=a-z0-9, 6=Alphanumeric, 7=Full ASCII).
* `--max-len, -l <N>`: Maximum permutation search length (default: 16).
* `--salt, -s <value>`: Explicit salt value.
* `--wordlist, -w <file>`: Custom wordlist file (default: `wordlist.txt`).
* `--file, -f <file>`: Target file for batch multi-hash audit.
* `--no-dict, -n`: Skip dictionary attack and proceed directly to brute-force.
* `--no-potfile, --fresh`: Ignore potfile cache and force re-computation.
* `--quiet, -q`: Minimalist scriptable output (`hash:password`) for Unix pipelines.
* `--verbose, -v`: Verbose output with detailed telemetry.
* `--json`: Structured machine-readable JSON output for SIEM/toolchain automation.

---

### 🚀 Build and Installation

#### Prerequisites
- Windows 10/11 x64 (or Linux x64 with OpenCL runtime)
- Visual Studio 2022 Community (Desktop development with C++)
- Any GPU supporting OpenCL 1.2+ or NVIDIA CUDA

#### Compilation
```cmd
:: Build native Windows binary (cerberus.exe) using MSVC v143 (C++20)
build.bat
```

#### CLI Examples
```bash
# 🎯 Zero-Click Auto-Pilot (Pass hash, Base64, or plaintext directly):
cerberus 5d41402abc4b2a76b9719d911017c592       # Auto-detects MD5, runs cache, dictionary, and GPU brute-force
cerberus 209c6174da490caeb422f3fa5a7ae634       # NTLM Windows NT-Hash (auto-detected and recovered)
cerberus ZHVhcnRlMTIz                            # Strict Base64 validation and instant decode
cerberus mypassword                              # Auto-detects plaintext and outputs complete cryptographic matrix
cerberus test                                    # Full 18-module cryptographic validation test suite (100% PASS)
cerberus benchmark                               # Maximum hardware throughput benchmark (OpenCL / CPU)

# 📋 Potfile & History:
cerberus history                                 # Display cracked credentials database in formatted table

# 📁 Multi-Hash Batch Auditing:
cerberus file hashes.txt                         # Multi-target batch file audit with executive summary report

# 🤖 Scripting & DevOps:
cerberus crack "5d41402abc4b2a76b9719d911017c592" --quiet     # Script-ready output (hash:pass)
cerberus crack "5d41402abc4b2a76b9719d911017c592" --json      # Structured JSON forensic report output
```

> ⚠️ **Notice:** This software is engineered strictly for authorized security auditing, penetration testing, forensic investigations, and educational research.

### 👨‍💻 Author
Developed by **[Antônio Malheiros (Zeca)](https://github.com/antoniomalheirs)**.

---
---

<a id="versão-em-português"></a>

```text
  ____  _____  ____   ____   _____  ____   _   _  ____  
 / ___|| ____||  _ \ | __ ) | ____||  _ \ | | | |/ ___| 
| |    |  _|  | |_) ||  _ \ |  _|  | |_) || | | |\___ \ 
| |___ | |___ |  _ < | |_) || |___ |  _ < | |_| | ___) |
 \____||_____||_| \_\|____/ |_____||_| \_\ \___/ |____/ 
----------------------------------------------------------------------------
 CERBERUS FORENSIC SUITE >> MOTOR DE RECUPERAÇÃO E AUDITORIA DE SENHAS
----------------------------------------------------------------------------
```

<div align="center">

  <img src="https://img.shields.io/badge/C++-20-00599C?style=for-the-badge&logo=cplusplus&logoColor=white" alt="C++20">
  <img src="https://img.shields.io/badge/CERBERUS-v3.0--FORENSE-red?style=for-the-badge" alt="Cerberus">
  <img src="https://img.shields.io/badge/Arquitetura-Três_Cabeças-purple?style=for-the-badge" alt="Três Cabeças">
  <img src="https://img.shields.io/badge/Aceleração-OpenCL_&_CUDA-blue?style=for-the-badge" alt="Aceleração">
  <img src="https://img.shields.io/badge/Padrão-Kali_Linux_Ready-557C93?style=for-the-badge&logo=kalilinux&logoColor=white" alt="Kali Ready">
  <img src="https://img.shields.io/badge/Licença-MIT-yellow?style=for-the-badge" alt="Licença MIT">
  <br><br>

  <p><b>CERBERUS é uma suíte industrial de recuperação criptográfica e auditoria forense de senhas.<br>
  Desenvolvida em C++20 moderno para peritos digitais, analistas de segurança ofensiva e laboratórios de inteligência,<br>
  com paralelismo multi-threaded em CPU e aceleração massiva por GPU via OpenCL e CUDA.</b></p>
</div>

<br>

### 🔱 Arquitetura do Motor de Três Cabeças

Inspirado no lendário guardião mitológico de três cabeças, o **CERBERUS** ataca a entropia das senhas através de 3 vetores unificados:

```
                     ┌──────────────────────────────┐
                     │       C E R B E R U S        │
                     └──────────────┬───────────────┘
            ┌───────────────────────┼───────────────────────┐
            │                       │                       │
      [CABEÇA I]              [CABEÇA II]             [CABEÇA III]
   Memória Forense         Heurística Forense       Força Bruta Massiva
  (Potfile Cache 0ms)     (Dicionário + Mutações)  (GPU OpenCL/CUDA + CPU)
```

1. **Cabeça I — A Cabeça da Memória (Cache Potfile Forense)**
   - Verificação instantânea ($0\text{ ms}$) em `cracked_passwords.txt` antes de despachar carga computacional para o hardware.
   - Elimina processamento redundante e assegura resposta instantânea para credenciais já decifradas.
   - Visualizador de histórico integrado via terminal (`cerberus history` ou `cerberus potfile`).

2. **Cabeça II — A Cabeça Heurística (Dicionário com Mutações por Regras)**
   - Processamento de wordlists com regras dinâmicas de mutação (inversão de maiúsculas/minúsculas, leetspeak, espelhamento, sufixos de anos).
   - Teste de hipótese de cascata automática entre hashes MD5 e NTLM para alvos de 32 caracteres hexadecimais.

3. **Cabeça III — A Cabeça da Força Bruta (Núcleo Universal GPU & CPU)**
   - **Motor Universal OpenCL 3.0:** Kernels JIT de alto rendimento para placas NVIDIA, AMD e Intel (~$860+\text{ MH/s}$).
   - **Motor Nativo NVIDIA CUDA:** Execução direta no hardware através de blocos e warps.
   - **Motor Multi-Threaded CPU:** Mutação in-place estilo hodômetro sem alocação em heap e com sincronização atômica em lote.

---

### ⚡ Benchmarks de Desempenho em Hardware

Medições realizadas em hardware dedicado (**NVIDIA GeForce GTX 1070 8GB**):

| Algoritmo | Padrão / Tipo | Taxa de Hash (Hashrate) | Método de Execução |
| :--- | :--- | :---: | :--- |
| **NTLM** | Windows SAM / Active Directory | **863.84 MH/s** | Kernel Universal OpenCL GPU |
| **MD4** | RFC 1320 Padrão Legado | **863.84 MH/s** | Kernel Universal OpenCL GPU |
| **MD5** | RFC 1321 Hash Criptográfico | **345.54 MH/s** | Kernel Universal OpenCL GPU |
| **SHA-256** | FIPS 180-4 Padrão NIST | **287.95 MH/s** | Kernel Universal OpenCL GPU |
| **SHA-1** | FIPS 180-1 Padrão de Segurança | **246.81 MH/s** | Kernel Universal OpenCL GPU |
| **SHA-512** | FIPS 180-4 Alta Entropia | **132.90 MH/s** | Kernel Universal OpenCL GPU |
| **Pool de CPU** | Todos os Algoritmos (Multi-Core) | **~45+ MH/s** | Thread Pool C++20 (Batched Atomic) |

---

### 🛡️ Matriz de Algoritmos Suportados

- **Hashes Primitivos & Padrões Forenses:** CRC32 (IEEE 802.3), MD5 (RFC 1321), SHA-1 (FIPS 180-1), SHA-224 (FIPS 180-4), SHA-256 (FIPS 180-4), SHA-384 (FIPS 180-4), SHA-512 (FIPS 180-4), **NTLM** (Windows SAM / Active Directory NT-Hash), **MD4** (RFC 1320), Base64 (RFC 4648 estrito).
- **Variantes com Salt:** MD5 + Salt, SHA-1 + Salt, SHA-256 + Salt, SHA-512 + Salt (salt único ou lista via `saltlist.txt`, detecta `hash:salt` e `salt:hash`).
- **Primitivas HMAC e PBKDF2:** HMAC-MD5, HMAC-SHA1, HMAC-SHA256 (RFC 2104), PBKDF2-HMAC-SHA1 (RFC 2898 / RFC 6070).
- **Protocolos e Perfis Simulados:** WPA2 (PBKDF2-Sim), WPA3 (SAE Dragonfly Commit-Sim), Bcrypt ($2a$), Scrypt, Facebook (FB_SHA256), Instagram (IG_ARGON2), Twitter (TW_BCRYPT).

---

### 🖥️ Experiência de Usuário (UX) & Telemetria em Tempo Real

O CERBERUS possui formatação rigorosa de 76 colunas para evitar quebras de linha indesejadas em qualquer terminal:

#### 1. Telemetria em Tempo Real
```text
[CPU Multi-Thread] L4/16 [====------]  38.5% | 18.42 MH/s | ETA 00:04 | 00:02
[OpenCL] L3/5            [=========---] 75.0% | 85.20 MH/s | ETA 00:01 | 00:00
```

#### 2. Card de Credencial Recuperada (Sucesso)
```text
  ==========================================================================
  |  ✓ SUCESSO: CREDENCIAL RECUPERADA                                      |
  +------------------------------------------------------------------------+
  |  HASH ALVO    : 5d41402abc4b2a76b9719d911017c592                       |
  |  SENHA        : hello                                                  |
  |  ALGORITMO    : MD5                                                    |
  |  METODO       : Força Bruta GPU (OpenCL)                              |
  |  ENGINE       : v3.0-OPENCL (NVIDIA GeForce GTX 1070)                  |
  |  TEMPO        : 22ms (0.022s)                                          |
  |  TENTATIVAS   : 13,686,207 (622.10 MH/s)                               |
  ==========================================================================
    [+] Sincronizado em: cracked_passwords.txt
```

#### 3. Card de Potfile Hit (0ms de Custo Computacional)
```text
  ==========================================================================
  |  ⚡ POTFILE CACHE HIT (RECUPERAÇÃO INSTANTÂNEA)                         |
  +------------------------------------------------------------------------+
  |  HASH ALVO    : 5d41402abc4b2a76b9719d911017c592                       |
  |  SENHA        : hello                                                  |
  |  ALGORITMO    : MD5                                                    |
  |  ORIGEM       : cracked_passwords.txt (0ms de computação)              |
  ==========================================================================
```

#### 4. Relatório Executivo de Auditoria em Lote (Multi-Hash)
```text
================================================================================
                         RELATÓRIO DE AUDITORIA EM LOTE                         
================================================================================
 Total de Alvos        : 3
 Recuperados (Sucesso) : 3 (100.0%) [Novos: 1 | Cache Potfile: 2]
 Nao Recuperados       : 0 (0.0%)
 Tempo Total Auditado  : 14ms (0.014s)
 Tentativas Globais    : 13,686,209 (977.59 MH/s)
================================================================================
 ID  | HASH ALVO (Truncado)            | STATUS  | ALGORITMO   | SENHA RECUPERADA
-----+---------------------------------+---------+-------------+----------------
 01  | 0192023a7bbd73...16f069df18b500 | CACHED  | MD5         | admin123
 02  | 5d41402abc4b2a...719d911017c592 | CRACKED | MD5         | hello
 03  | 209c6174da490c...22f3fa5a7ae634 | CACHED  | NTLM (Windo | admin
================================================================================
```

---

### 🕹️ Tabela Completa de Comandos e Opções CLI

#### Comandos Principais

| Comando | Aliases | Argumentos | Descrição |
| :--- | :--- | :--- | :--- |
| `crack` | `c` | `<hash>` | Auto-detecta e quebra o hash através do pipeline das 3 cabeças |
| `crack-salt`| `cs` | `<hash> -s <salt>` | Processa hash com salt ou formato composto `hash:salt` |
| `decode` | `d` | `<base64>` | Decodifica Base64 estrito instantaneamente |
| `hash` | `g` | `<texto> [-s salt]`| Gera a matriz completa de hashes criptográficos para um texto |
| `file` / `batch`| `f` | `<alvos.txt>` | Auditoria pericial em lote com relatório executivo consolidado |
| `history` | `potfile`, `show` | `[arquivo.txt]` | Exibe o histórico de credenciais recuperadas em tabela formatada |
| `test-all` | `test`, `t` | *(nenhum)* | Executa a suíte de validação de 18 módulos criptográficos |
| `benchmark` | `bench`, `b`| *(nenhum)* | Mede a taxa bruta de permutações por segundo (H/s) de GPU e CPU |
| `help` | `h`, `?` | *(nenhum)* | Exibe o manual de ajuda completo e sintaxe |
| `version` | `v` | *(nenhum)* | Exibe versão, motor ativo e metadados de compilação |

#### Modificadores e Flags

* `--engine, -e <cpu|opencl|cuda>`: Seleciona o motor de computação.
* `--algo, -a <md5|sha1|sha256|sha512|ntlm|md4|...>`: Força o algoritmo específico.
* `--charset, -c <1-7>`: Seleciona o conjunto de caracteres (1=Números, 2=a-z, 4=a-zA-Z, 5=a-z0-9, 6=Alfanumérico, 7=ASCII Completo).
* `--max-len, -l <N>`: Comprimento máximo da permutação (default: 16).
* `--salt, -s <valor>`: Salt explícito.
* `--wordlist, -w <arquivo>`: Dicionário customizado (default: `wordlist.txt`).
* `--file, -f <arquivo>`: Arquivo de lote para auditoria multi-hash.
* `--no-dict, -n`: Pula o ataque de dicionário.
* `--no-potfile, --fresh`: Ignora o cache do potfile e força nova computação.
* `--quiet, -q`: Modo silencioso para scripts Unix (`hash:senha`).
* `--verbose, -v`: Modo detalhado com telemetria expandida.
* `--json`: Exportação estruturada em JSON nativo para SIEMs e toolchains.

---

### 🚀 Compilação e Uso

#### Pré-requisitos
- Windows 10/11 x64 (ou Linux com runtime OpenCL)
- Visual Studio 2022 Community (C++ Desktop)
- Placa de vídeo compatível com OpenCL 1.2+ ou NVIDIA CUDA

#### Compilação
```cmd
:: Compilação automatizada gerando cerberus.exe com C++20 e OpenCL
build.bat
```

#### Exemplos de Uso via Linha de Comando (CLI)
```bash
# 🎯 Modo Heurístico Zero-Click:
cerberus 5d41402abc4b2a76b9719d911017c592       # Auto-detecta MD5, consulta cache, roda dicionário e força bruta GPU
cerberus 209c6174da490caeb422f3fa5a7ae634       # NTLM Windows NT-Hash (detectado e recuperado na hora)
cerberus ZHVhcnRlMTIz                            # Validação estrita de Base64 e decodificação instantânea
cerberus minhasenha                              # Detecta texto plano e gera a matriz criptográfica completa
cerberus test                                    # Executa suíte de validação com 18 módulos (100% PASS)
cerberus benchmark                               # Mede o hashrate máximo de GPU e CPU

# 📋 Histórico & Potfile:
cerberus history                                 # Exibe todas as credenciais recuperadas em tabela formatada

# 📁 Auditoria em Lote (Multi-Hash):
cerberus file alvos.txt                          # Auditoria de múltiplos alvos com relatório executivo consolidado

# 🔬 Automação e DevOps:
cerberus crack "5d41402abc4b2a76b9719d911017c592" --quiet     # Saída limpa para scripts Unix (hash:senha)
cerberus crack "5d41402abc4b2a76b9719d911017c592" --json      # Exportação estruturada em JSON nativo
```

> ⚠️ **Aviso Legal:** Esta ferramenta destina-se estritamente a auditorias autorizadas de segurança, testes de intrusão autorizados, investigações periciais e estudos acadêmicos.

### 👨‍💻 Autor
Desenvolvido por **[Antônio Malheiros (Zeca)](https://github.com/antoniomalheirs)**.
