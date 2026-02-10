# 🛡️ Sentinel Data Solutions | Forensic Audit Tool

![C++](https://img.shields.io/badge/Language-C%2B%2B17-blue.svg?style=for-the-badge&logo=c%2B%2B)
![CUDA](https://img.shields.io/badge/Calculo-NVIDIA_CUDA-76B900.svg?style=for-the-badge&logo=nvidia)
![OpenCL](https://img.shields.io/badge/Calculo-OpenCL-orange.svg?style=for-the-badge&logo=opencl)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6.svg?style=for-the-badge&logo=windows)
![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)

> **"Advanced Cryptographic Analysis & Forensic Auditing System"**

Bem-vindo ao **Sentinel Data Solutions (Simulador)**. Este projeto evoluiu de um simples script de força bruta para uma suíte completa de auditoria forense, capaz de utilizar aceleração de hardware (GPU) para demonstrar a vulnerabilidade de senhas e a importância de algoritmos de hash robustos modernamente.

---

## 🚀 Funcionalidades Principais

### 🖥️ Multi-Engine Compute Core
O sistema opera em três modos de processamento distintos, selecionáveis na inicialização:
1.  **CPU (Standard Logic):** Utiliza todas as threads disponíveis do processador (Multi-threading) para ataques básicos e compatibilidade universal.
2.  **GPU CUDA (NVIDIA Native):** Utiliza kernels `.cu` compilados via `nvcc` para performance máxima em placas NVIDIA (GTX/RTX series). *Requer Toolkit 11+*.
3.  **GPU OpenCL (Universal Bridge):** Camada de compatibilidade para **AMD Radeon**, **Intel Arc**, e **NVIDIA** (fallback), permitindo aceleração massiva em qualquer hardware moderno.

### 🔐 16 Módulos de Hash
Suporte nativo (CPU/GPU) para auditoria dos seguintes algoritmos:

| Categoria | Algoritmos Suportados |
| :--- | :--- |
| **Básico (Legacy)** | `MD5`, `MD5+Salt`, `SHA-1`, `SHA1+Salt`, `Base64` (Decode) |
| **Padrão (NIST)** | `SHA-256`, `SHA256+Salt`, `SHA-512`, `SHA512+Salt` |
| **Protocolos** | `WPA2 (PBKDF2-Sim)`, `WPA3 (SAE/Dragonfly)`, `Bcrypt`, `Scrypt` |
| **Redes Sociais** | `Facebook (SHA256)`, `Instagram (Argon2)`, `Twitter (Bcrypt)` |

### 🛠️ Vetores de Ataque
*   **Ataque de Dicionário Inteligente:** Carrega `wordlist.txt` e aplica mutações automáticas (ex: `senha` -> `Senha123`, `Senha!`, etc.).
*   **Força Bruta Incremental:** Varredura exaustiva de todas as combinações de caracteres (1 a 16+ chars).
*   **Matriz de Auditoria (Self-Test):** Modo de demonstração que valida todos os 16 módulos sequencialmente, gerando hashes aleatórios e quebrando-os em tempo real para prova de conceito.
*   **Calculadora de Hashes:** Utilitário para gerar fingerprints de texto plano em múltiplos formatos instantaneamente.

---

## 📦 Compilação e Instalação

### Opção 1: Compilação Automática (Recomendado)
Incluímos o script `build.bat` para automatizar o processo.
1.  Edite `build.bat` para verificar os caminhos do **Visual Studio** e **CUDA Toolkit**.
2.  Execute `build.bat` no terminal.
3.  O script irá compilar o código host (C++), os kernels CUDA (.cu) e linkar tudo automaticamente.

### Opção 2: Compilação Manual
**Sem CUDA (Apenas OpenCL + CPU):**
```cmd
g++ "Brute Force Methods.cpp" opencl_kernels.cpp -o sentinel_audit.exe -O3 -std=c++17 -lOpenCL
```

**Com CUDA (Nativo):**
```cmd
nvcc "Brute Force Methods.cpp" gpu_kernels.cu -o sentinel_audit_cuda.exe -O3 -DENABLE_CUDA
```

---

## 🎮 Guia de Uso

1.  **Hardware Selection:** Ao iniciar, escolha sua unidade de processamento (1=CPU, 2=NVIDIA, 3=AMD/Intel).
2.  **Menu Principal:**
    *   **[1] Advanced Mode (WiFi/Salted):** Para hashes complexos (WPA2, Bcrypt) ou com Salt conhecido.
    *   **[2] Auto-Detect:** Cole um hash simples (MD5/SHA) para o sistema identificar o tipo e iniciar o ataque.
    *   **[3] Base64 Decode:** Ferramenta rápida de decodificação.
    *   **[4] Run All Tests:** O "Showcase" do sistema. Executa uma bateria de testes visuais.
    *   **[5] Hash Calculator:** Gera hashes a partir de texto.
3.  **Arquivos de Apoio:**
    *   `wordlist.txt`: Coloque suas senhas candidatas aqui para o ataque de dicionário.
    *   `saltlist.txt`: Lista de salts para ataques em lote.

### 📄 Logs de Auditoria
Todos os sucessos (senhas quebradas) são salvos automaticamente em:
*   Arquivo: `cracked_passwords.txt`
*   Formato: `HASH | SALT | SENHA_DESCOBERTA`

---

## ⚠️ Aviso Legal e Ético

> **ESTE SOFTWARE É PARA FINS EDUCACIONAIS E DE AUDITORIA AUTORIZADA.**

O **Sentinel Data Solutions** foi desenvolvido para demonstrar matematicamente a insegurança de senhas fracas e a necessidade de criptografia robusta.
*   **NÃO** utilize esta ferramenta contra sistemas, redes ou arquivos que você não possui ou não tem permissão explícita para auditar.
*   O autor não se responsabiliza por qualquer uso indevido deste código. A responsabilidade é inteiramente do usuário final.

---

⭐ **Desenvolvido por Zeca** | *C++ High Performance Computing*
