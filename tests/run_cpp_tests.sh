#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temp_root="$(mktemp -d)"
trap 'rm -rf "$temp_root"' EXIT

gcc -O2 -c "$repo_root/dependencies/crypt_blowfish/crypt_blowfish.c" \
  -o "$temp_root/crypt_blowfish.o"
g++ -O2 -std=c++20 -pthread -DCERBERUS_TESTING \
  -I"$repo_root/dependencies/opencl/include" \
  -I"$repo_root/dependencies/crypt_blowfish" \
  "$repo_root/tests/cpp/cerberus_unit_tests.cpp" \
  "$repo_root/src/algorithms/opencl_kernels.cpp" \
  "$temp_root/crypt_blowfish.o" -ldl \
  -o "$temp_root/cerberus_cpp_unit_tests"

"$temp_root/cerberus_cpp_unit_tests"
