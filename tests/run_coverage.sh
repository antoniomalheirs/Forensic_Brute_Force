#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
coverage_root="$repo_root/build/.cache/coverage"
app_dir="$coverage_root/app"
native_dir="$coverage_root/native"
report_dir="$coverage_root/report"
mkdir -p "$app_dir" "$native_dir" "$report_dir"

common_flags=(
  -O0 -g --coverage -fprofile-abs-path -std=c++20 -pthread
  -DCERBERUS_TESTING
  -I"$repo_root/dependencies/opencl/include"
  -I"$repo_root/dependencies/crypt_blowfish"
)

gcc -O0 -g --coverage -fprofile-abs-path \
  -c "$repo_root/dependencies/crypt_blowfish/crypt_blowfish.c" \
  -o "$app_dir/crypt_blowfish.o"
g++ "${common_flags[@]}" -c "$repo_root/src/cerberus.cpp" \
  -o "$app_dir/cerberus.o"
g++ "${common_flags[@]}" -c "$repo_root/src/algorithms/opencl_kernels.cpp" \
  -o "$app_dir/opencl_kernels.o"
g++ --coverage -pthread "$app_dir/cerberus.o" \
  "$app_dir/opencl_kernels.o" "$app_dir/crypt_blowfish.o" -ldl \
  -o "$app_dir/cerberus.exe"
mkdir -p "$app_dir/data"
cp -R "$repo_root/data/lists" "$app_dir/data/lists"

gcc -O0 -g --coverage -fprofile-abs-path \
  -c "$repo_root/dependencies/crypt_blowfish/crypt_blowfish.c" \
  -o "$native_dir/crypt_blowfish.o"
g++ "${common_flags[@]}" -c "$repo_root/tests/cpp/cerberus_unit_tests.cpp" \
  -o "$native_dir/cerberus_unit_tests.o"
g++ "${common_flags[@]}" -c "$repo_root/src/algorithms/opencl_kernels.cpp" \
  -o "$native_dir/opencl_kernels.o"
g++ --coverage -pthread "$native_dir/cerberus_unit_tests.o" \
  "$native_dir/opencl_kernels.o" "$native_dir/crypt_blowfish.o" -ldl \
  -o "$native_dir/cerberus_cpp_unit_tests"

test_status=0
CERBERUS_REQUIRE_OPENCL=1 "$native_dir/cerberus_cpp_unit_tests" || test_status=$?
CERBERUS_EXE="$app_dir/cerberus.exe" CERBERUS_REQUIRE_OPENCL=1 \
  python3 -m unittest discover -s "$repo_root/tests" -p 'test_*.py' -v \
  || test_status=$?

gcovr --root "$repo_root" --filter 'src/' --branches --print-summary \
  --html-details "$report_dir/index.html" --xml-pretty \
  --output "$report_dir/coverage.xml" "$coverage_root"

exit "$test_status"
