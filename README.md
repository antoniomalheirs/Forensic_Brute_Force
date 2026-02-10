# BruteForce Explorer C++

![C++](https://img.shields.io/badge/language-C%2B%2B-blue.svg)
![Uso](https://img.shields.io/badge/Uso-Educacional-yellow?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green.svg)

Bem-vindo ao **BruteForce Explorer**, um projeto de console em C++ desenvolvido para fins educacionais. O objetivo principal desta ferramenta não é ser um software de cracking de senhas prático, mas sim **demonstrar visualmente os conceitos, a matemática e o tempo computacional envolvidos em ataques de força bruta**.

Este projeto nasceu como um script simples e evoluiu para uma ferramenta interativa que explora diferentes cenários de ataques, desde a adivinhação de texto plano até a quebra de hashes criptográficos como o SHA-256.

---

## 🚀 Funcionalidades

O programa apresenta um menu interativo com os seguintes modos de ataque:

* **1. Força Bruta em Texto Plano:** O modo mais básico. O programa gera strings aleatórias de um comprimento específico até encontrar uma correspondência exata com a string alvo.
* **2. Força Bruta em Hash (Comprimento Conhecido):** Um cenário mais realista onde o alvo é um hash SHA-256 e o atacante conhece o comprimento da senha original. O programa gera strings de tamanho fixo, calcula seus hashes e os compara com o alvo.
* **3. Força Bruta TOTAL em Hash (Incremental):** A demonstração definitiva do poder e da lentidão da força bruta. O programa tenta quebrar um hash SHA-256 **sem saber o tamanho da senha**, testando sequencialmente todas as possibilidades, começando com 1 caractere, depois 2, e assim por diante.

---

## 🛠️ Como Compilar e Usar

Para executar este projeto, você precisará de um compilador C++ (como G++, Clang ou MSVC) e do arquivo de cabeçalho `picosha2.h`.

1.  **Dependência:** Faça o download do arquivo `picosha2.h` do [repositório oficial](https://github.com/okdshin/picosha2) e coloque-o na mesma pasta do código-fonte.

2.  **Clone este repositório:**
    ```bash
    git clone [https://github.com/SEU-USUARIO/SEU-REPOSITORIO.git](https://github.com/SEU-USUARIO/SEU-REPOSITORIO.git)
    cd SEU-REPOSITORIO
    ```

3.  **Compile o código:**
    Use o seu compilador C++. Exemplo com G++:
    ```bash
    g++ main.cpp -o brute_force -O2 -std=c++17
    ```
    * `-o brute_force`: Define o nome do arquivo executável.
    * `-O2`: Habilita otimizações de compilação para melhor desempenho.
    * `-std=c++17`: Especifica o padrão do C++.

4.  **Execute:**
    ```bash
    ./brute_force
    ```

---

## ⚠️ Aviso Ético e de Viabilidade

> **Este software foi criado estritamente para fins de aprendizado e demonstração.** O objetivo é educar sobre segurança da informação, mostrando por que senhas fortes e algoritmos de hash seguros (com *salt*) são essenciais.
>
> O uso desta ferramenta contra sistemas, hashes ou dados aos quais você não tem permissão explícita é **ilegal e antiético**. O autor não se responsabiliza por qualquer mau uso deste software.
>
> Além disso, esteja ciente de que a força bruta é **computacionalmente inviável** para senhas com mais de 7 ou 8 caracteres simples, podendo levar anos ou séculos em um computador pessoal.

---

## 📈 Melhorias Futuras

* [ ] Adicionar suporte a mais algoritmos de hash (MD5, SHA-1).
* [ ] Permitir que o usuário defina o conjunto de caracteres a ser usado (ex: maiúsculas, símbolos).
* [ ] Implementar multi-threading para acelerar o processo de busca.
* [ ] Adicionar um modo de ataque de dicionário.
