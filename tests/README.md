# CERBERUS correctness and false-positive suite

This suite drives the built `cerberus.exe` through its public CLI. It uses
independent references from Python's standard library, an RFC 1320 MD4
implementation checked against RFC vectors, and the published Openwall
`crypt_blowfish` bcrypt vector. It checks exact recovered plaintexts and
requires negative cases to return no plaintext. On Windows with Visual Studio
C++ build tools installed, it also compiles and runs a native harness against
the implementation's internal helpers and algorithms.

## Run

From a Windows source checkout after building CERBERUS:

```powershell
py -3 -m unittest discover -s tests -p "test_*.py" -v
```

Set `CERBERUS_EXE` to test a separately built binary. CUDA and OpenCL CLI checks
run when their respective runtimes are ready. Set `CERBERUS_TEST_CUDA=1` to
compile the direct CUDA harness; `CERBERUS_TEST_CUDA_ARCH` selects its compile
target (default `sm_61`). Set `CERBERUS_REQUIRE_CUDA=1` and/or
`CERBERUS_REQUIRE_OPENCL=1` to turn a missing backend into a failure instead of
a skip. The OpenCL CI job compiles the harness with `CERBERUS_TESTING`, which
allows PoCL's CPU device to execute the same kernels while production builds
remain GPU-only.

The release workflow runs the suite before uploading artifacts. The separate
compatibility workflow builds with CUDA 12.8 and 12.9, compiles every GPU
architecture advertised by each NVCC, and runs the native OpenCL kernel suite
on PoCL. It also exercises `setup.bat --cpu-only`, `--build`, and
`--require-cuda` in temporary source copies when a Windows compiler/toolkit is
available. GPU execution checks run only on hosts with a compatible device;
CI compile checks do not claim to execute CUDA kernels without one.

The coverage workflow builds an instrumented Linux binary and native harness,
runs the CLI and PoCL checks, then uploads HTML and Cobertura line/branch
reports. To run it locally on Linux, use `bash tests/run_coverage.sh`; reports
are written to `build/.cache/coverage/report/` (`index.html` and
`coverage.xml`). GCC coverage measures C++ host code, including OpenCL runtime
orchestration. It does not measure CUDA device code in `gpu_kernels.cu` or the
OpenCL C kernel source compiled dynamically by the runtime. CUDA error paths
are injected in the Windows native harness.

## Coverage

- Independent digest matrix: CRC32, Base64, MD4, MD5, NTLM, SHA-1/224/256/384/512,
  HMAC-MD5/SHA-1/SHA-256, and WPA2 PBKDF2-HMAC-SHA1, including deterministic
  input vectors around digest padding/block boundaries and empty plaintexts.
- Positive recovery vectors for all implemented CPU formats, including salted
  hashes, bcrypt `$2a$`/`$2b$`/`$2y$`, scrypt PHC, WPA2 PMK, and UTF-8 entries.
- Boundary vectors for bcrypt's 72-byte behavior, multiple scrypt `N/r/p` values,
  and maximum valid WPA2 passphrase/SSID lengths.
- Native helper checks for UTF-8 and target validation, canonical PHC/Base64
  parsing, bcrypt/scrypt policy limits, output escaping, mutations, potfile
  records, batch decoding, progress formatting, and saturating attempt counters.
- Negative validation for changed digest nibbles, wrong candidates, algorithm
  confusion, wrong salts/keys, corrupted potfile records, malformed inputs,
  unsupported resource costs, and ambiguous inline salts.
- CLI JSON and quiet output, option validation, charset/length selection,
  wordlist and saltlist discovery from the release layout, UTF-8 BOM and UTF-16
  little/big-endian inputs, rejection of malformed UTF-8/UTF-16/UTF-32, Unicode
  filenames, mutation rules (case, reverse, duplication, leetspeak, prefixes,
  suffixes), legacy and current potfile records, binary plaintext field encoding,
  batch files and aliases, diagnostics/setup, and the built-in smoke test,
  help/version commands, and clean interactive exit.
- Multi-entry salted-hash and WPA2 SSID lists, exact salt recovery, duplicate
  salt suppression, and exact-attempt-count invariance when list duplicates are
  present.
- Test-only backend failure injection for OpenCL driver/platform discovery,
  context and queue creation, kernel compilation/creation, buffer allocation,
  queue writes, argument setup, submission, result reads, and queue completion.
  Each failure must return an empty result, and follow-up work checks recovery.
  CUDA tests inject driver initialization, partial allocation, transfers,
  launch, launch-status, synchronization, and readback failures. Without a CUDA
  device, the deterministic driver and first-allocation failure cases still run.
  A deliberately malformed CUDA kernel source in a temporary project confirms
  that a required-CUDA build fails without replacing the previous executable.
- GCC line and branch coverage for the C++ host and OpenCL implementation,
  excluding dynamically compiled OpenCL C kernels, published as HTML and
  Cobertura XML by the coverage workflow.
- Optional exact-result checks for CUDA and OpenCL kernels, including salted
  variants, plus mutated-target rejection checks for every GPU kernel and a
  bounded benchmark smoke check for all six measured algorithms. CUDA progress
  output and explicit-engine buffer/keyspace rejection are checked as well. The
  native harness directly exercises GPU padding/block edges, maximum supported
  input sizes, salted combined-input limits, NTLM limits, output clearing on
  invalid calls, and exact attempt counts. Direct OpenCL tests cross the
  1,048,576-candidate batch boundary and assert the independent exact result
  plus the exact dispatched-attempt count. CUDA partitioning is exercised with
  a synthetic small counter limit so it does not require a giant keyspace. The
  benchmark tests check completion only, never a speed target.

## Limits of the claim

No finite test suite can mathematically prove that a program will never produce
a false positive for every possible input. These checks establish that the
covered formats match independent known answers and that representative
negative inputs are rejected. CRC32 is a non-cryptographic 32-bit checksum and
has collisions by design; a CRC32 match is not proof of a unique original
password. Run this suite for a particular release artifact and hardware
combination, and keep the test logs with that build.
