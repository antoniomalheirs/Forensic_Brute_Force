# CERBERUS

**CERBERUS is a C++20 tool for authorized hash auditing and password recovery.** It combines dictionary and mutation searches with brute-force search on CPU, OpenCL, or CUDA where the selected algorithm supports that backend.

[![Release workflow](https://github.com/antoniomalheirs/Forensic_Brute_Force/actions/workflows/release.yml/badge.svg)](https://github.com/antoniomalheirs/Forensic_Brute_Force/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

[English](#cerberus) · [Português](#português)

CERBERUS operates on hash values and files supplied by the user. It does not retrieve credentials from accounts or devices. Use it only for data you own or are explicitly authorized to audit.

## Features

- Detects supported hash formats or accepts an explicit algorithm with `--algo`.
- Searches a wordlist, applies built-in mutations, then runs brute force unless disabled.
- Uses CPU, OpenCL, or CUDA for brute force when supported by the selected algorithm.
- Audits multiple targets from a text file and supports JSON output for automation.
- Provides environment diagnostics, performance benchmarking, and a local recovery history (potfile).

## Supported formats

| Format | Notes and processing |
| --- | --- |
| CRC32, MD4, MD5, NTLM, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 | Hash verification and recovery. GPU brute-force kernels are available for MD4, MD5, NTLM, SHA-1, SHA-256, and SHA-512. |
| Salted MD5, SHA-1, SHA-256, SHA-512 | Supports a supplied salt or entries in the salt list. The corresponding GPU kernels support brute force. |
| HMAC-MD5, HMAC-SHA1, HMAC-SHA256 | Supply the key through `--salt`; an omitted key means an empty key. CPU processing. |
| bcrypt (`$2a$`, `$2b$`, `$2y$`) | CPU verification, cost 4–20. |
| scrypt PHC (`$scrypt$ln=…,r=…,p=…$…$…`) | CPU verification with an operational limit of 256 MiB and `N*r*p <= 2^26`. |
| WPA2 PMK | Verifies a PMK using the SSID, or checks raw 64-hex PSK candidates from the dictionary. It does not parse packet captures or EAPOL handshakes. |
| Base64 | Strict decoding; Base64 is not treated as a password hash. |

OpenCL and CUDA brute-force kernels are available for MD4, MD5, NTLM, SHA-1, SHA-256, and SHA-512, including the supported salted variants. Other implemented formats use CPU processing. Dictionary mutations and potfile checks always run on the CPU. An explicitly selected engine does not silently fall back to another engine; without `--engine`, CERBERUS selects an available backend automatically.

WPA3/SAE captures and social-network account exports are not supported password-hash inputs. For ambiguous 32-character hexadecimal values, specify `--algo` to avoid relying on format heuristics.

## Installation

### Download a release

Download the Windows release assets from [GitHub Releases](https://github.com/antoniomalheirs/Forensic_Brute_Force/releases). Keep `cerberus.exe`, any packaged CUDA runtime DLL, and the provided data files together, then run:

~~~powershell
.\setup.bat
.\cerberus.exe doctor
~~~

`setup.bat` checks an existing executable and reports the detected engine, device, and data files. In a source checkout, it builds CERBERUS when the executable is absent.

### Build from source

Source builds require Windows x64 and Visual Studio 2022 C++ x64 build tools. CUDA Toolkit 12.x is optional and is needed only to compile CUDA support; running CUDA also requires a compatible NVIDIA driver. OpenCL support requires a compatible OpenCL runtime/driver on the target machine.

~~~powershell
.\setup.bat --build        # Detect this machine and build
.\setup.bat --cpu-only     # Build without CUDA
.\setup.bat --require-cuda # Fail unless CUDA is compiled
~~~

The setup script selects a CUDA architecture from the local environment when possible. The Visual Studio solution is `build/windows/cerberus.sln`; the command-line build script is `build/windows/build.bat`.

## Usage

~~~powershell
.\cerberus.exe doctor
.\cerberus.exe crack 5d41402abc4b2a76b9719d911017c592 --algo md5
.\cerberus.exe crack 8846f7eaee8fb117ad06bdd830b7586c --algo ntlm --engine cuda
.\cerberus.exe decode ZGVtbw==
.\cerberus.exe hash "hello" --json
.\cerberus.exe file hashes.txt --algo sha256 --json
.\cerberus.exe history
.\cerberus.exe benchmark
~~~

Use `--engine cpu`, `--engine opencl`, or `--engine cuda` to select the brute-force backend. `--max-len` controls the maximum brute-force candidate length (default: 16); `--charset` selects the candidate character set. Run `cerberus.exe --help` for the full command and option list.

`file` reads one target per line. Lines beginning with `#` are comments; supported salted targets may use `hash:salt` or `salt:hash`. The `--json` option provides structured output for supported commands, and `--quiet` emits percent-encoded `hash:password` records for scripts.

## Wordlists and recovered data

The bundled starter files are `data/lists/wordlist.txt` and `data/lists/saltlist.txt`. They are small examples, not comprehensive password or SSID corpora. Provide an authorized list with `--wordlist <path>` and a salt or SSID with `--salt <value>` when needed. List files accept LF, CRLF, and CR line endings. The default lookup order is the current directory, `lists/`, and `data/lists/`, followed by the same locations beside the executable. Root-level files and the earlier `lists/` layout remain supported for compatibility.

Recovered passwords and salts are stored in `cracked_passwords.txt` in the current working directory. Values are percent-encoded for storage, but the file is **not encrypted** and contains credential material. Protect it accordingly. `--no-potfile` and `--fresh` skip cache lookup; newly recovered credentials are still saved.

## Repository layout

~~~text
src/                         Application and algorithm implementations
data/lists/                  Bundled word and salt lists
dependencies/                OpenCL files and bcrypt source
build/windows/               Visual Studio project and Windows build scripts
build/windows/tools/         Developer diagnostics and smoke-test launcher
licenses/                    Third-party notices and licenses
setup.bat                    Environment setup entry point
~~~

## Validation and license

`cerberus.exe test` runs the built-in integration smoke cases. These cases are not independent cryptographic validation. For machine-specific performance measurements, run `cerberus.exe benchmark`.

CERBERUS is distributed under the MIT License; see [LICENSE](LICENSE). Third-party terms are documented under `licenses/`.

Maintainer: [Antônio Malheiros](https://github.com/antoniomalheirs).

## Português

<details>
<summary>Leia a documentação em português</summary>

CERBERUS é uma ferramenta em C++20 para auditoria autorizada de hashes e recuperação de senhas. Ela combina busca por dicionário e mutações com força bruta em CPU, OpenCL ou CUDA quando o algoritmo escolhido oferece suporte ao motor.

O CERBERUS processa hashes e arquivos fornecidos pelo usuário. Não obtém credenciais de contas ou dispositivos. Use somente dados próprios ou para os quais você tenha autorização explícita.

### Recursos

- Detecta formatos implementados ou aceita algoritmo explícito com `--algo`.
- Pesquisa uma wordlist, aplica mutações e executa força bruta, salvo quando essa etapa é desativada.
- Usa CPU, OpenCL ou CUDA na força bruta conforme o suporte do algoritmo.
- Audita vários alvos em arquivo e oferece saída JSON para automação.
- Inclui diagnóstico do ambiente, benchmark e histórico local de recuperações (potfile).

### Formatos suportados

| Formato | Observações e processamento |
| --- | --- |
| CRC32, MD4, MD5, NTLM, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 | Verificação e recuperação. Há kernels de força bruta em GPU para MD4, MD5, NTLM, SHA-1, SHA-256 e SHA-512. |
| MD5, SHA-1, SHA-256 e SHA-512 com salt | Aceita salt informado ou entradas da lista de salts; as variantes compatíveis usam os kernels correspondentes na força bruta em GPU. |
| HMAC-MD5, HMAC-SHA1 e HMAC-SHA256 | Informe a chave em `--salt`; sem chave, usa chave vazia. Processamento em CPU. |
| bcrypt (`$2a$`, `$2b$`, `$2y$`) | Verificação em CPU, custo 4–20. |
| scrypt PHC (`$scrypt$ln=…,r=…,p=…$…$…`) | Verificação em CPU limitada a 256 MiB e `N*r*p <= 2^26`. |
| WPA2 PMK | Verifica uma PMK usando o SSID ou consulta candidatos PSK brutos de 64 caracteres hexadecimais na wordlist. Não interpreta capturas nem handshakes EAPOL. |
| Base64 | Decodificação estrita; Base64 não é tratado como hash de senha. |

Os kernels OpenCL e CUDA estão disponíveis para força bruta de MD4, MD5, NTLM, SHA-1, SHA-256 e SHA-512, incluindo as variantes com salt implementadas. Os demais formatos usam CPU. Mutações da wordlist e consultas ao potfile também usam CPU. A seleção explícita de motor não faz fallback silencioso; sem `--engine`, o CERBERUS escolhe um motor disponível automaticamente.

Capturas WPA3/SAE e exportações de contas de redes sociais não são formatos de hash de senha suportados. Para valores hexadecimais ambíguos de 32 caracteres, informe `--algo` explicitamente.

### Instalação

Baixe os arquivos da versão para Windows em [GitHub Releases](https://github.com/antoniomalheirs/Forensic_Brute_Force/releases). Mantenha `cerberus.exe`, eventual DLL de runtime CUDA e os arquivos de dados juntos. Execute:

~~~powershell
.\setup.bat
.\cerberus.exe doctor
~~~

`setup.bat` verifica o executável existente e mostra o motor, o dispositivo e os arquivos de dados detectados. No checkout do código-fonte, compila o CERBERUS quando o executável ainda não existe.

Para compilar do código-fonte, é necessário Windows x64 e Visual Studio 2022 com ferramentas C++ x64. O CUDA Toolkit 12.x é opcional e só é necessário para compilar suporte CUDA; para executar com CUDA, também é necessário um driver NVIDIA compatível. Para usar OpenCL, o computador precisa de runtime/driver compatível.

~~~powershell
.\setup.bat --build        # Detecta este computador e compila
.\setup.bat --cpu-only     # Compila sem CUDA
.\setup.bat --require-cuda # Falha se CUDA não for compilado
~~~

A solução do Visual Studio está em `build/windows/cerberus.sln`; o script de compilação fica em `build/windows/build.bat`.

### Uso

~~~powershell
.\cerberus.exe doctor
.\cerberus.exe crack 5d41402abc4b2a76b9719d911017c592 --algo md5
.\cerberus.exe crack 8846f7eaee8fb117ad06bdd830b7586c --algo ntlm --engine cuda
.\cerberus.exe decode ZGVtbw==
.\cerberus.exe hash "hello" --json
.\cerberus.exe file hashes.txt --algo sha256 --json
.\cerberus.exe history
.\cerberus.exe benchmark
~~~

Use `--engine cpu`, `--engine opencl` ou `--engine cuda` para escolher o motor da força bruta. `--max-len` define o tamanho máximo das tentativas (padrão: 16), e `--charset` seleciona o conjunto de caracteres. Execute `cerberus.exe --help` para ver todas as opções.

O comando `file` lê um alvo por linha. Linhas iniciadas por `#` são comentários; alvos com salt podem usar `hash:salt` ou `salt:hash`. `--json` gera saída estruturada nos comandos compatíveis; `--quiet` emite registros `hash:senha` com percent-encoding para scripts.

### Wordlists e dados recuperados

As listas iniciais incluídas são `data/lists/wordlist.txt` e `data/lists/saltlist.txt`. São pequenas e não representam bases abrangentes de senhas ou SSIDs. Para fornecer uma lista autorizada, use `--wordlist <caminho>`; quando necessário, informe salt ou SSID com `--salt <valor>`. As listas aceitam finais de linha LF, CRLF e CR. A busca padrão verifica o diretório atual, `lists/` e `data/lists/`, depois os mesmos locais ao lado do executável. Arquivos antigos na raiz e no formato anterior `lists/` continuam compatíveis.

Senhas recuperadas e salts são salvos em `cracked_passwords.txt`, no diretório de trabalho atual. Os valores são percent-encoded, mas o arquivo **não é criptografado** e contém credenciais. Proteja-o adequadamente. `--no-potfile` e `--fresh` ignoram a consulta ao cache, mas novas recuperações continuam sendo salvas.

### Estrutura do repositório

~~~text
src/                         Aplicativo e implementações dos algoritmos
data/lists/                  Wordlist e lista de salts incluídas
dependencies/                Arquivos OpenCL e fonte bcrypt
build/windows/               Projeto Visual Studio e scripts de build
build/windows/tools/         Diagnósticos e iniciador dos smoke tests
licenses/                    Avisos e licenças de terceiros
setup.bat                    Entrada para configurar o ambiente
~~~

### Verificação e licença

`cerberus.exe test` executa casos internos de integração; eles não substituem uma validação criptográfica independente. Para medir o desempenho no computador alvo, execute `cerberus.exe benchmark`.

O CERBERUS é distribuído sob a licença MIT; consulte [LICENSE](LICENSE). Os termos de terceiros estão documentados em `licenses/`.

Mantenedor: [Antônio Malheiros](https://github.com/antoniomalheirs).

</details>
