#define CERBERUS_NO_ENTRYPOINT
#include "../../src/cerberus.cpp"
#include "../../src/algorithms/test_faults.h"

#include <iostream>

#if defined(ENABLE_CUDA) && defined(CERBERUS_TESTING)
extern "C" int launch_gpu_brute_force_ext_test_limit(
    const char *charset, const char *target, int max_len, char *result,
    int hashType, const char *salt, unsigned long long *attempts_out,
    unsigned long long indexLimit);
#endif

namespace {
int checks = 0;
int failures = 0;

void check(bool condition, const char *name) {
  ++checks;
  if (!condition) {
    ++failures;
    std::cerr << "[FAIL] " << name << "\n";
  }
}

bool writeBytes(const std::filesystem::path &path, const std::string &bytes) {
  std::ofstream output(path, std::ios::binary);
  if (!output) return false;
  output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  return output.good();
}

void testCryptoOracles() {
  check(md4("abc") == "a448017aaf21d8525fc10ae87aa6729d", "MD4 RFC vector");
  check(md5("abc") == "900150983cd24fb0d6963f7d28e17f72", "MD5 vector");
  check(sha1("abc") == "a9993e364706816aba3e25717850c26c9cd0d89d", "SHA-1 vector");
  check(sha224("abc") == "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
        "SHA-224 vector");
  check(sha256("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "SHA-256 vector");
  check(sha384("abc") ==
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
            "8086072ba1e7cc2358baeca134c825a7",
        "SHA-384 vector");
  check(sha512("abc") ==
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "SHA-512 vector");
  check(crc32("123456789") == "cbf43926", "CRC-32 IEEE vector");
  check(ntlm("password") == "8846f7eaee8fb117ad06bdd830b7586c", "NTLM vector");

  check(hmac_sha256("Jefe", "what do ya want for nothing?") ==
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        "HMAC-SHA-256 RFC 4231 vector");
  check(hmac_sha256(std::string(131, static_cast<char>(0xaa)),
                    "Test Using Larger Than Block-Size Key - Hash Key First") ==
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        "HMAC-SHA-256 long-key vector");
  check(pbkdf2_hmac_sha1("password", "IEEE", 4096, 32) ==
            "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e",
        "WPA2 PBKDF2 known-answer vector");

  check(hashFunctionExtended("abc", HashType::SALTED_MD5, "salt") ==
            md5("abcsalt"), "salted MD5 concatenation");
  check(hashFunctionExtended("abc", HashType::SALTED_SHA1, "salt") ==
            sha1("abcsalt"), "salted SHA-1 concatenation");
  check(hashFunctionExtended("abc", HashType::SALTED_SHA256, "salt") ==
            sha256("abcsalt"), "salted SHA-256 concatenation");
  check(hashFunctionExtended("abc", HashType::SALTED_SHA512, "salt") ==
            sha512("abcsalt"), "salted SHA-512 concatenation");
}

void testEncodingsAndTargets() {
  check(isValidUtf8("café-語-🙂"), "valid UTF-8 including supplementary codepoint");
  check(!isValidUtf8(std::string("\xC0\xAF", 2)), "reject overlong UTF-8");
  check(!isValidUtf8(std::string("\xED\xA0\x80", 3)), "reject UTF-8 surrogate");
  check(!isValidUtf8(std::string("\xF0\x9F\x92", 3)), "reject truncated UTF-8");
  check(!isValidUtf8(std::string("\xE2\x28\xA1", 3)), "reject invalid UTF-8 continuation");
  check(!isValidUtf8(std::string("\xF4\x90\x80\x80", 4)), "reject codepoints above Unicode range");
  check(terminalSafeText(std::string("A\n\x1b", 3)) == "A\\x0A\\x1B",
        "terminal output escapes ASCII controls");
  check(terminalSafeText("x\xE2\x80\xAEy") == "x\\u202Ey",
        "terminal output escapes bidi controls");
  check(jsonEscape("quote\"\\\n") == "quote\\\"\\\\\\n",
        "JSON escaping for quotes, slashes, and newlines");
  check(jsonEscape(std::string("\xFF", 1)) == "\\u00ff",
        "JSON escaping for invalid UTF-8 bytes");

  std::string decoded;
  check(isBase64Strict("Zm9v", decoded) && decoded == "foo",
        "strict Base64 positive vector");
  check(!isBase64Strict("Zh==", decoded), "strict Base64 rejects nonzero pad bits");
  std::vector<uint8_t> phcBytes;
  check(decodePhcBase64("Zg", phcBytes) && phcBytes == std::vector<uint8_t>{'f'},
        "PHC Base64 unpadded one-byte vector");
  check(!decodePhcBase64("Zh", phcBytes), "PHC Base64 rejects noncanonical pad bits");

  check(identifyHash("deadbeef") == HashType::CRC32, "CRC32 auto-detection");
  check(identifyHash(std::string(32, 'a')) == HashType::MD5,
        "32-hex digest uses explicit MD5 ambiguity policy");
  check(identifyHash("Zm9v") == HashType::BASE64,
        "Base64 auto-detection accepts printable decoded text");
  check(identifyHash("AQID") == HashType::UNKNOWN,
        "Base64 auto-detection rejects decoded control bytes");
  check(identifyHash("$scrypt$ln=4,r=1,p=1$YQ$AAAAAAAAAAAAAA") ==
            HashType::SCRYPT,
        "scrypt PHC prefix detection");
  check(identifyHash("$2b$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW") ==
            HashType::BCRYPT,
        "bcrypt modular hash detection");
  check(identifyHash("not-a-target") == HashType::UNKNOWN,
        "unknown target stays unknown");
  check(parseHashTypeLabel("SHA256") == HashType::SHA256,
        "case-insensitive algorithm label");
  check(parseHashTypeLabel("md5-salt") == HashType::SALTED_MD5,
        "salted algorithm alias");
  check(parseHashTypeLabel("unrecognized") == HashType::UNKNOWN,
        "unknown algorithm label");
  check(isValidHashTarget("deadbeef", HashType::CRC32), "valid CRC32 target");
  check(!isValidHashTarget("deadbee", HashType::CRC32), "invalid CRC32 length");
  check(!isValidHashTarget("", HashType::BASE64), "empty Base64 target rejected");
}

void testScryptAndBcryptValidation() {
  const std::string phc =
      "$scrypt$ln=4,r=1,p=1$Y2VyYmVydXMtdGVzdC1zYWx0$"
      "grAlGCwgqRElW7JIbCRO1LlMXTctjKj9aMeXcW9vRZk";
  ScryptPhcTarget parsed;
  check(parseScryptPhc(phc, parsed), "parse valid scrypt PHC record");
  check(parsed.logN == 4 && parsed.r == 1 && parsed.p == 1,
        "scrypt PHC parameters parsed exactly");
  check(scryptWithinResourcePolicy(parsed), "small scrypt parameters within policy");
  check(verifyCandidate("scrypt-pass", HashType::SCRYPT, phc),
        "scrypt PHC known-answer verification");
  check(!verifyCandidate("wrong-pass", HashType::SCRYPT, phc),
        "scrypt rejects wrong candidate");
  check(!parseScryptPhc(phc + "$extra", parsed), "scrypt rejects extra PHC field");
  check(!parseScryptPhc(
            "$scrypt$ln=04,r=1,p=1$Y2VyYmVydXMtdGVzdC1zYWx0$"
            "grAlGCwgqRElW7JIbCRO1LlMXTctjKj9aMeXcW9vRZk", parsed),
        "scrypt rejects noncanonical integer encoding");
  check(!parseScryptPhc(
            "$scrypt$ln=4,r=1,p=1$Y2VyYmVydXMtdGVzdC1zYWx0$Zh", parsed),
        "scrypt rejects noncanonical checksum encoding");
  uint64_t canonicalNumber = 0;
  check(parseCanonicalUnsigned("18446744073709551615", canonicalNumber) &&
            canonicalNumber == std::numeric_limits<uint64_t>::max(),
        "unsigned PHC integer accepts maximum 64-bit value");
  check(!parseCanonicalUnsigned("18446744073709551616", canonicalNumber),
        "unsigned PHC integer rejects overflow");
  check(!parseCanonicalUnsigned("01", canonicalNumber),
        "unsigned PHC integer rejects leading zero");
  check(!parseCanonicalUnsigned("-1", canonicalNumber),
        "unsigned PHC integer rejects sign");
  ScryptPhcTarget tooExpensive;
  tooExpensive.logN = 18;
  tooExpensive.r = 9;
  tooExpensive.p = 1;
  check(!scryptWithinResourcePolicy(tooExpensive),
        "scrypt operational memory ceiling enforced");

  const std::string bcrypt =
      "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
  check(bcryptCost(bcrypt) == 5, "bcrypt cost parse");
  check(verifyCandidate("U*U", HashType::BCRYPT, bcrypt),
        "bcrypt Openwall known-answer verification");
  check(!verifyCandidate("wrong", HashType::BCRYPT, bcrypt),
        "bcrypt rejects wrong candidate");
  check(bcryptCost(bcrypt.substr(0, 4) + "03" + bcrypt.substr(6)) == -1,
        "bcrypt rejects cost below policy");
  check(bcryptCost(bcrypt.substr(0, 4) + "32" + bcrypt.substr(6)) == -1,
        "bcrypt rejects cost above supported range");
  check(!verifyCandidate(std::string("U*U\0suffix", 10), HashType::BCRYPT, bcrypt),
        "bcrypt rejects embedded NUL rather than truncating the candidate");
}

void testCliHelpersAndCounters() {
  check(getCharset(1) == "0123456789", "numeric charset");
  check(getCharset(2) == "abcdefghijklmnopqrstuvwxyz", "lowercase charset");
  check(getCharset(3) == "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "uppercase charset");
  check(getCharset(4).size() == 52, "mixed alphabet charset size");
  check(getCharset(5) == "abcdefghijklmnopqrstuvwxyz0123456789",
        "lowercase alphanumeric charset");
  check(getCharset(6).size() == 62, "mixed alphanumeric charset size");
  check(getCharset(7).size() > getCharset(6).size(), "printable charset size");
  check(getCharset(999) == getCharset(0), "unknown charset selects documented default");

  std::string target = "  \"deadbeef\" \t";
  normalizeBatchTargetLine(target);
  check(target == "deadbeef", "batch whitespace and quote normalization");
  target = " \t\r\n";
  normalizeBatchTargetLine(target);
  check(target.empty(), "empty batch line normalization");
  const std::string md5LikeDigest(32, 'a');
  check(isSaltFirstBatchTarget("realm:" + md5LikeDigest),
        "salt-first batch target detection");
  check(!isSaltFirstBatchTarget(":" + md5LikeDigest),
        "empty batch salt is not salt-first");
  check(!isSaltFirstBatchTarget("realm:not-a-digest"),
        "invalid batch digest is rejected");

  int maximum = -1;
  check(gpuKeyspaceFitsCounters(10, 2, 1, 0, maximum) && maximum == 2,
        "GPU counter accepts bounded keyspace");
  check(!gpuKeyspaceFitsCounters(10, 19, 1, 0, maximum) && maximum == 18,
        "GPU counter rejects overflowing keyspace and reports boundary");
  check(!gpuKeyspaceFitsCounters(10, 1, 0, 0, maximum), "GPU counter rejects empty salt set");
  check(!gpuKeyspaceFitsCounters(10, 1, 1, -1, maximum), "GPU counter rejects negative attempts");
  check(saturatingAttemptAdd(10, 5) == 15, "attempt counter ordinary addition");
  check(saturatingAttemptAdd(-1, 5) == 5, "attempt counter clamps negative state");
  check(saturatingAttemptAdd(std::numeric_limits<long long>::max() - 1, 5) ==
            std::numeric_limits<long long>::max(),
        "attempt counter saturates at signed limit");
  check(saturatingAttemptAddUnsigned(
            std::numeric_limits<long long>::max() - 1, 2) ==
            std::numeric_limits<long long>::max(),
        "unsigned attempt counter saturates without overflow");
  check(hashRateForJson(2000, 1000) == 2000, "JSON hashrate calculation");
  check(hashRateForJson(0, 1000) == 0 && hashRateForJson(1, 0) == 0,
        "JSON hashrate handles empty measurements");

  check(formatNumber(1234567) == "1,234,567", "number grouping");
  check(formatTime(0) == "0ms (< 1ms)", "zero-duration formatting");
  check(formatTime(61000) == "1m 01s", "long-duration formatting");
  check(formatHashrate(1500.0) == "1.50 kH/s", "hashrate unit formatting");
  const std::string progress = formatProgressBar(150.0, 4);
  check(progress.find("[====]") == 0 && progress.find("100.0%") != std::string::npos,
        "progress clamps values above 100 percent");

  std::atomic<long long> attempts{std::numeric_limits<long long>::max() - 1};
  addAttemptsSaturating(attempts, 20);
  check(attempts.load() == std::numeric_limits<long long>::max(),
        "atomic attempt counter saturates");
  addAttemptsSaturating(attempts, -1);
  check(attempts.load() == std::numeric_limits<long long>::max(),
        "atomic attempt counter ignores negative increments");

  std::atomic<long long> concurrentAttempts{0};
  std::vector<std::thread> workers;
  for (int worker = 0; worker < 8; ++worker) {
    workers.emplace_back([&concurrentAttempts]() {
      for (int increment = 0; increment < 1000; ++increment)
        addAttemptsSaturating(concurrentAttempts, 1);
    });
  }
  for (auto &worker : workers) worker.join();
  check(concurrentAttempts.load() == 8000,
        "atomic attempt counter preserves concurrent updates");

  std::vector<uint8_t> secretBuffer{1, 2, 3, 255};
  secureClear(secretBuffer);
  check(secretBuffer.size() == 4 &&
            std::all_of(secretBuffer.begin(), secretBuffer.end(),
                        [](uint8_t value) { return value == 0; }),
        "secure clear zeroes allocated secret bytes");

  char arg0[] = "cerberus";
  char arg1[] = "crack";
  char arg2[] = "--SALT";
  char arg3[] = "case-sensitive-value";
  char arg4[] = "--max-len=2";
  char arg5[] = "--verbose";
  char *argv[] = {arg0, arg1, arg2, arg3, arg4, arg5};
  check(cliGetArgValue(6, argv, "--salt") == "case-sensitive-value",
        "CLI option value lookup is case-insensitive");
  check(cliGetArgValue(6, argv, "--max-len") == "2",
        "CLI equals-form option value lookup");
  check(cliHasFlag(6, argv, "--verbose") &&
            cliHasOption(6, argv, "--max-len"),
        "CLI flag and option detection");
  check(!cliOptionMissingValue(6, argv, "--salt"),
        "CLI accepts a present option value");
  check(!cliOptionRepeated(6, argv, {"--salt", "-s"}),
        "CLI accepts a single option alias");

  char missingArg0[] = "cerberus";
  char missingArg1[] = "crack";
  char missingArg2[] = "--salt";
  char missingArg3[] = "--json";
  char *missingArgv[] = {missingArg0, missingArg1, missingArg2, missingArg3};
  check(cliOptionMissingValue(4, missingArgv, "--salt") &&
            cliGetArgValue(4, missingArgv, "--salt").empty(),
        "CLI does not consume another option as a value");
  char repeatedArg0[] = "cerberus";
  char repeatedArg1[] = "crack";
  char repeatedArg2[] = "--salt=a";
  char repeatedArg3[] = "-s";
  char repeatedArg4[] = "b";
  char *repeatedArgv[] = {repeatedArg0, repeatedArg1, repeatedArg2,
                          repeatedArg3, repeatedArg4};
  check(cliOptionRepeated(5, repeatedArgv, {"--salt", "-s"}),
        "CLI detects repeated option aliases");

  std::ostringstream boxOutput;
  std::streambuf *previousOutput = std::cout.rdbuf(boxOutput.rdbuf());
  printBoxLine("SENHA", "recovered", "");
  std::cout.rdbuf(previousOutput);
  check(boxOutput.str().find("SENHA") != std::string::npos &&
            boxOutput.str().find("recovered") != std::string::npos,
        "human output formats and prints a result row");

  DiscardOutputBuffer discardBuffer;
  const auto discardedCharacter = discardBuffer.sputc('x');
  check(discardedCharacter == std::char_traits<char>::to_int_type('x'),
        "quiet output buffer safely discards a single-character write");
}

void testExplicitGpuFallbackGuard() {
  const ComputeType previousEngine = globalCompute;
  const bool previousExplicitSelection = globalEngineExplicitlySelected;
  const bool previousQuiet = globalQuiet;
  const bool previousJson = globalJson;
  auto expectRejected = [](ComputeType engine, HashType type,
                           const std::string &target,
                           const std::string &charset, int maxLength,
                           const std::string &salt,
                           const std::string &expectedReason,
                           const char *testName) {
    Config config;
    config.type = type;
    config.target = target;
    config.salt = salt;
    config.saltProvided = true;
    config.charset = charset;
    config.maxLength = maxLength;
    globalCompute = engine;
    globalEngineExplicitlySelected = true;
    globalQuiet = true;
    globalJson = false;
    globalEngineFailure.clear();
    const bool recovered = runParallelBruteForce(config, false, nullptr, false);
    check(!recovered, testName);
    check(globalEngineFailure.find(expectedReason) != std::string::npos,
          "explicit GPU rejection reports its precise policy reason");
  };

  expectRejected(ComputeType::OPENCL, HashType::WPA2_PBKDF2,
                 std::string(64, '0'), "01", 1, "test-ssid",
                 "algoritmo nao implementado no kernel OpenCL",
                 "explicit unsupported OpenCL algorithm is rejected");
  expectRejected(ComputeType::CUDA, HashType::WPA2_PBKDF2,
                 std::string(64, '0'), "01", 1, "test-ssid",
                 "algoritmo nao implementado no kernel CUDA",
                 "explicit unsupported CUDA algorithm is rejected");
  expectRejected(ComputeType::OPENCL, HashType::SALTED_MD5,
                 std::string(32, '0'), "01", 1, std::string("a\0b", 3),
                 "salt contem byte NUL",
                 "OpenCL rejects NUL salt without falling back");
  expectRejected(ComputeType::CUDA, HashType::SALTED_MD5,
                 std::string(32, '0'), "01", 1, std::string("a\0b", 3),
                 "salt contem byte NUL",
                 "CUDA rejects NUL salt without falling back");
  expectRejected(ComputeType::OPENCL, HashType::MD5,
                 std::string(32, '0'), "01", 120, "",
                 "entrada excede o buffer seguro do kernel OpenCL",
                 "OpenCL rejects inputs beyond its kernel buffer");
  expectRejected(ComputeType::CUDA, HashType::MD5,
                 std::string(32, '0'), "01", 120, "",
                 "entrada excede o buffer seguro do kernel CUDA",
                 "CUDA rejects inputs beyond its kernel buffer");
  expectRejected(ComputeType::OPENCL, HashType::NTLM,
                 std::string(32, '0'), "\xC3\xA9", 1, "",
                 "kernel NTLM exige charset ASCII",
                 "OpenCL rejects Unicode charset for NTLM");
  expectRejected(ComputeType::CUDA, HashType::NTLM,
                 std::string(32, '0'), "01", 60, "",
                 "kernel NTLM exige charset ASCII",
                 "CUDA rejects NTLM candidates above 59 bytes");
  expectRejected(ComputeType::OPENCL, HashType::MD5,
                 std::string(32, '0'), std::string(62, 'a'), 11, "",
                 "64-bit keyspace/report limits",
                 "OpenCL rejects keyspaces beyond its 64-bit counter");
#if !defined(ENABLE_CUDA)
  expectRejected(ComputeType::CUDA, HashType::MD5,
                 std::string(32, '0'), "01", 1, "",
                 "esta build nao inclui suporte CUDA",
                 "non-CUDA build rejects explicit CUDA without fallback");
#endif

  globalCompute = previousEngine;
  globalEngineExplicitlySelected = previousExplicitSelection;
  globalQuiet = previousQuiet;
  globalJson = previousJson;
  globalEngineFailure.clear();
}

void testMutationAndPotfileHelpers() {
  std::unordered_set<std::string> variants;
  const bool completed = forEachMutation("password", [&](const std::string &value) {
    variants.insert(value);
    return true;
  });
  check(completed, "mutation visitor completes");
  for (const std::string &expected : {"password", "PASSWORD", "drowssap",
                                      "passwordpassword", "p455w0rd", "p@$$w0rd",
                                      "password2026", "123password"})
    check(variants.count(expected) == 1, "mutation candidate present");
  check(variants.size() > 20, "mutation rule family produces distinct variants");
  int visited = 0;
  check(!forEachMutation("stop", [&](const std::string &) {
          ++visited;
          return false;
        }) && visited == 1,
        "mutation visitor can stop early");
  std::string longWord(300, 'a');
  check(forEachMutation(longWord, [&](const std::string &value) {
          return value.size() >= longWord.size();
        }),
        "long word mutation path completes without duplicate tracking");

  const std::string bytes("a|b%\n\xC3\xA9", 7);
  check(encodePotfileField(bytes) == "a%7Cb%25%0A%C3%A9",
        "potfile field percent encoding");
  check(encodeQuietField("a:b%") == "a%3Ab%25", "quiet field percent encoding");
  check(potfileHexValue('F') == 15 && potfileHexValue('g') == -1,
        "potfile hexadecimal decoder");
  check(isValidEncodedPotfileField("abc%7C", 0, 6), "valid encoded potfile field");
  check(!isValidEncodedPotfileField("abc%7x", 0, 6), "reject malformed potfile escape");
  check(hasValidVersionedPotfileEncoding("v3|deadbeef||CRC32%20(IEEE%202.3)|pass"),
        "versioned potfile encoding validation");
  check(!hasValidVersionedPotfileEncoding("v3|dead%Q0||MD5|pass"),
        "versioned potfile rejects malformed escape");
  check(decodePotfileField("one%7Ctwo%25") == "one|two%",
        "potfile percent decoding");
  check(parsePotfileLine("deadbeef|-|password").size() == 3,
        "legacy potfile record parse");
  const auto v3 = parsePotfileLine("v3|deadbeef||MD5|one%7Ctwo");
  check(v3.size() == 5 && v3[3] == "one|two" && v3[4] == "v3",
        "versioned potfile record parse and decoding");
  check(parsePotfileLine("v3|dead%Q0||MD5|pass").empty(),
        "malformed versioned potfile record is ignored");
  check(potfileTypeFromName("MD5") == HashType::MD5,
        "potfile algorithm lookup");
  check(inferLegacyPotfileType("deadbeef") == HashType::CRC32,
        "legacy potfile algorithm inference");
  check(inferLegacyPotfileType(std::string(32, 'a')) == HashType::MD5,
        "legacy potfile infers 32-character hexadecimal digest");
  check(inferLegacyPotfileType(std::string(40, 'a')) == HashType::SHA1,
        "legacy potfile infers 40-character hexadecimal digest");
  check(inferLegacyPotfileType(std::string(56, 'a')) == HashType::SHA224,
        "legacy potfile infers 56-character hexadecimal digest");
  check(inferLegacyPotfileType(std::string(64, 'a')) == HashType::SHA256,
        "legacy potfile resolves 64-character digest ambiguity consistently");
  check(inferLegacyPotfileType(std::string(96, 'a')) == HashType::SHA384,
        "legacy potfile infers 96-character hexadecimal digest");
  check(inferLegacyPotfileType(std::string(128, 'a')) == HashType::SHA512,
        "legacy potfile infers 128-character hexadecimal digest");
  check(inferLegacyPotfileType("not-a-digest") == HashType::UNKNOWN,
        "legacy potfile leaves unrecognized targets untyped");
  check(saltedTypeForDigestLength(32) == HashType::SALTED_MD5 &&
            saltedTypeForDigestLength(40) == HashType::SALTED_SHA1 &&
            saltedTypeForDigestLength(64) == HashType::SALTED_SHA256 &&
            saltedTypeForDigestLength(128) == HashType::SALTED_SHA512,
        "salted digest lengths map to implemented hash types");
  check(saltedTypeForDigestLength(56) == HashType::UNKNOWN &&
            saltedTypeForDigestLength(96) == HashType::UNKNOWN &&
            saltedTypeForDigestLength(0) == HashType::UNKNOWN,
        "unsupported salted digest lengths remain unknown");

  std::ostringstream json;
  writeJsonTextOrBase64(json, "plaintext", std::string("\xFF", 1));
  check(json.str() == "\"plaintext\": null, \"plaintext_base64\": \"/w==\"",
        "JSON binary plaintext fallback");
}

void testStreamsAndBatchFiles() {
  std::istringstream universal("first\r\nsecond\rthird\nlast");
  std::string line;
  const std::vector<std::string> expected = {"first", "second", "third", "last"};
  for (const auto &item : expected)
    check(readLineWithUniversalNewlines(universal, line) && line == item,
          "universal newline reader");
  check(!readLineWithUniversalNewlines(universal, line), "newline reader reaches EOF cleanly");

  std::istringstream utf8Bom("\xEF\xBB\xBFtext");
  check(probeWideTextBom(utf8Bom) == WideTextBomStatus::NONE,
        "UTF-8 BOM is not misclassified as wide text");
  std::istringstream utf16Bom("\xFF\xFEtext");
  check(probeWideTextBom(utf16Bom) == WideTextBomStatus::PRESENT,
        "UTF-16 BOM detection");
  std::istringstream utf32BeBom(std::string("\x00\x00\xFE\xFFtext", 8));
  check(probeWideTextBom(utf32BeBom) == WideTextBomStatus::PRESENT,
        "UTF-32 big-endian BOM detection");

  const auto unique = std::chrono::steady_clock::now().time_since_epoch().count();
  const auto root = std::filesystem::temp_directory_path() /
                    ("cerberus-cpp-unit-" + std::to_string(unique));
  std::filesystem::create_directories(root);
  const auto cleanup = [&root]() {
    std::error_code error;
    std::filesystem::remove_all(root, error);
  };

  const auto utf8Path = root / L"targets-語.txt";
  check(writeBytes(utf8Path, std::string("\xEF\xBB\xBF") + "deadbeef\r\n"),
        "write UTF-8 BOM batch fixture");
  std::vector<std::string> lines;
  check(readHashTargetLines(pathToUtf8(utf8Path), lines) &&
            lines == std::vector<std::string>{"deadbeef"},
        "UTF-8 BOM batch reader and Unicode path");

  const auto badUtf8Path = root / L"invalid-utf8.txt";
  check(writeBytes(badUtf8Path, std::string("\xFF\n", 2)),
        "write malformed UTF-8 batch fixture");
  check(!readHashTargetLines(pathToUtf8(badUtf8Path), lines),
        "batch reader rejects malformed UTF-8");

  const auto utf16Path = root / L"utf16-le.txt";
  const std::string utf16Le =
      std::string("\xFF\xFE", 2) + std::string("h\0i\0\r\0\n\0", 8);
  check(writeBytes(utf16Path, utf16Le), "write UTF-16LE batch fixture");
  check(readHashTargetLines(pathToUtf8(utf16Path), lines) &&
            lines == std::vector<std::string>{"hi"},
        "UTF-16LE batch conversion");

  const auto truncatedPath = root / L"truncated-utf16.txt";
  check(writeBytes(truncatedPath, std::string("\xFF\xFE", 2) + "a"),
        "write truncated UTF-16 batch fixture");
  check(!readHashTargetLines(pathToUtf8(truncatedPath), lines),
        "batch reader rejects truncated UTF-16 unit");
  cleanup();
}

struct KernelBoundaryCase {
  HashType type;
  int passLength;
  std::string salt;
  const char *name;
};

std::vector<KernelBoundaryCase> kernelBoundaryCases() {
  return {
      {HashType::MD4, 55, "", "MD4 one-block edge"},
      {HashType::MD4, 56, "", "MD4 two-block edge"},
      {HashType::MD5, 55, "", "MD5 one-block edge"},
      {HashType::MD5, 56, "", "MD5 two-block edge"},
      {HashType::SHA1, 55, "", "SHA-1 one-block edge"},
      {HashType::SHA1, 56, "", "SHA-1 two-block edge"},
      {HashType::SHA256, 55, "", "SHA-256 one-block edge"},
      {HashType::SHA256, 56, "", "SHA-256 two-block edge"},
      {HashType::SHA256, 119, "", "SHA-256 maximum supported input"},
      {HashType::SHA512, 111, "", "SHA-512 one-block edge"},
      {HashType::SHA512, 112, "", "SHA-512 two-block edge"},
      {HashType::SHA512, 239, "", "SHA-512 maximum supported input"},
      {HashType::NTLM, 27, "", "NTLM UTF-16 one-block edge"},
      {HashType::NTLM, 28, "", "NTLM UTF-16 two-block edge"},
      {HashType::NTLM, 59, "", "NTLM maximum supported input"},
      {HashType::SALTED_MD5, 55, "S", "salted MD5 block edge"},
      {HashType::SALTED_SHA1, 55, "S", "salted SHA-1 block edge"},
      {HashType::SALTED_SHA256, 55, "S", "salted SHA-256 block edge"},
      {HashType::SALTED_SHA512, 111, "S", "salted SHA-512 block edge"},
      {HashType::SALTED_SHA256, 118, "S", "salted SHA-256 maximum combined input"},
      {HashType::SALTED_SHA512, 238, "S", "salted SHA-512 maximum combined input"},
  };
}

bool requiredBackend(const char *variable) {
  const char *value = std::getenv(variable);
  return value && std::string(value) == "1";
}

void runKernelBoundaryCases(bool cuda) {
  for (const auto &item : kernelBoundaryCases()) {
    const std::string candidate(static_cast<size_t>(item.passLength), '7');
    const std::string target =
        hashFunctionExtended(candidate, item.type, item.salt);
    const int kernelId = getKernelAlgoId(item.type);
    char recovered[256] = {};
    unsigned long long attempts = 0;
    int succeeded = 0;
    if (cuda) {
#if defined(ENABLE_CUDA)
      succeeded = launch_gpu_brute_force_ext(
          "7", target.c_str(), item.passLength, recovered, kernelId,
          item.salt.c_str(), &attempts, nullptr, nullptr);
#endif
    } else {
      int stop = 0;
      succeeded = launch_opencl_brute_force(
          "7", target.c_str(), item.passLength, recovered, &stop, kernelId,
          item.salt.c_str(), &attempts);
    }
    std::string label = std::string(cuda ? "CUDA " : "OpenCL ") + item.name;
    check(succeeded == 1, (label + " executes").c_str());
    check(std::string(recovered) == candidate,
          (label + " returns exact boundary candidate").c_str());
    check(attempts == static_cast<unsigned long long>(item.passLength),
          (label + " reports exact single-character keyspace").c_str());
  }

  for (const auto &item : std::vector<KernelBoundaryCase>{
           {HashType::SHA256, 120, "", "SHA-256 over-limit input"},
           {HashType::SHA512, 240, "", "SHA-512 over-limit input"},
           {HashType::NTLM, 60, "", "NTLM over-limit input"},
           {HashType::SALTED_SHA256, 119, "S", "salted SHA-256 over-limit combined input"},
           {HashType::SALTED_SHA512, 239, "S", "salted SHA-512 over-limit combined input"},
       }) {
    const std::string target = hashFunctionExtended("7", item.type, item.salt);
    char recovered[256] = {};
    unsigned long long attempts = 0;
    int succeeded = 0;
    if (cuda) {
#if defined(ENABLE_CUDA)
      succeeded = launch_gpu_brute_force_ext(
          "7", target.c_str(), item.passLength, recovered,
          getKernelAlgoId(item.type), item.salt.c_str(), &attempts, nullptr,
          nullptr);
#endif
    } else {
      int stop = 0;
      succeeded = launch_opencl_brute_force(
          "7", target.c_str(), item.passLength, recovered, &stop,
          getKernelAlgoId(item.type), item.salt.c_str(), &attempts);
    }
    check(succeeded == 0,
          (std::string(cuda ? "CUDA " : "OpenCL ") + item.name + " rejected")
              .c_str());
    check(recovered[0] == '\0',
          (std::string(cuda ? "CUDA " : "OpenCL ") + item.name +
           " returns no candidate")
              .c_str());
  }

  char recovered[16] = "stale";
  unsigned long long attempts = 99;
  if (cuda) {
#if defined(ENABLE_CUDA)
    check(launch_gpu_brute_force_ext("7", "invalid", 0, recovered, 2, "",
                                     &attempts, nullptr, nullptr) == 0,
          "CUDA rejects zero maximum length");
    check(recovered[0] == '\0' && attempts == 0,
          "CUDA clears result state on invalid request");
    attempts = 99;
    check(launch_gpu_brute_force_ext("7", "invalid", 1, nullptr, 2, "",
                                     &attempts, nullptr, nullptr) == 0 &&
              attempts == 0,
          "CUDA clears attempt count when result buffer is null");
    char hashOutput[129] = "stale";
    const std::string maxSha256(119, 'x');
    launch_gpu_hash_calc(maxSha256.c_str(), hashOutput);
    check(std::string(hashOutput) == sha256(maxSha256),
          "CUDA hash calculator maximum SHA-256 input");
    std::memset(hashOutput, 'x', sizeof(hashOutput));
    const std::string tooLongSha256(120, 'x');
    launch_gpu_hash_calc(tooLongSha256.c_str(), hashOutput);
    check(hashOutput[0] == '\0', "CUDA hash calculator clears unsupported input");
#endif
  } else {
    int stop = 0;
    check(launch_opencl_brute_force("7", "invalid", 0, recovered, &stop, 2,
                                    "", &attempts) == 0,
          "OpenCL rejects zero maximum length");
    check(recovered[0] == '\0' && attempts == 0,
          "OpenCL clears result state on invalid request");
  }
}

#if defined(CERBERUS_TESTING)
void testOpenCLFaultInjection() {
  set_opencl_quiet(1);
  if (!initOpenCL()) {
    if (requiredBackend("CERBERUS_REQUIRE_OPENCL"))
      check(false, "required OpenCL backend is available for fault injection");
    else
      std::cout << "[SKIP] OpenCL fault injection: no usable OpenCL device\n";
    return;
  }
  cleanupOpenCL();

  const std::vector<std::pair<int, const char *>> initializationFaults = {
      {CERBERUS_OPENCL_FAIL_LIBRARY_LOAD, "OpenCL runtime library load"},
      {CERBERUS_OPENCL_FAIL_PLATFORM_ENUMERATION, "platform/driver query"},
      {CERBERUS_OPENCL_FAIL_DEVICE_ENUMERATION, "device enumeration"},
      {CERBERUS_OPENCL_FAIL_CONTEXT_CREATE, "context allocation"},
      {CERBERUS_OPENCL_FAIL_QUEUE_CREATE, "command queue creation"},
      {CERBERUS_OPENCL_FAIL_PROGRAM_CREATE, "program allocation"},
      {CERBERUS_OPENCL_FAIL_PROGRAM_BUILD, "kernel compilation"},
      {CERBERUS_OPENCL_FAIL_KERNEL_CREATE, "kernel object creation"},
  };
  for (const auto &[fault, name] : initializationFaults) {
    cerberusOpenCLTestFailAfter(fault, 0);
    const bool failedAsExpected = initOpenCL() == 0;
    cerberusOpenCLTestResetFault();
    check(failedAsExpected,
          (std::string("OpenCL injected ") + name + " failure is rejected")
              .c_str());
    if (!failedAsExpected) {
      cleanupOpenCL();
      set_opencl_quiet(0);
      return;
    }
  }

  if (initOpenCL() != 1) {
    check(false, "OpenCL recovers after initialization fault injection");
    cleanupOpenCL();
    set_opencl_quiet(0);
    return;
  }
  check(true, "OpenCL recovers after initialization fault injection");
  const std::string target = sha256("7");
  auto expectExecutionFailure = [&](int fault, int skip,
                                    unsigned long long expectedAttempts,
                                    const char *name) {
    char recovered[32] = "stale";
    unsigned long long attempts = 99;
    int stop = 0;
    cerberusOpenCLTestFailAfter(fault, skip);
    const int succeeded = launch_opencl_brute_force(
        "7", target.c_str(), 1, recovered, &stop, 2, "", &attempts);
    cerberusOpenCLTestResetFault();
    check(succeeded == 0,
          (std::string("OpenCL injected ") + name + " failure is reported")
              .c_str());
    check(recovered[0] == '\0',
          (std::string("OpenCL injected ") + name +
           " failure returns no candidate")
              .c_str());
    check(attempts == expectedAttempts,
          (std::string("OpenCL injected ") + name +
           " failure preserves the dispatched-attempt count")
              .c_str());

    char verified[32] = {};
    attempts = 0;
    stop = 0;
    const int recoveredAfterFailure = launch_opencl_brute_force(
        "7", target.c_str(), 1, verified, &stop, 2, "", &attempts);
    check(recoveredAfterFailure == 1 && std::string(verified) == "7" &&
              attempts == 1,
          (std::string("OpenCL recovers after injected ") + name + " failure")
              .c_str());
  };

  expectExecutionFailure(CERBERUS_OPENCL_FAIL_BUFFER_CREATE, 2, 0,
                         "partial buffer allocation");
  expectExecutionFailure(CERBERUS_OPENCL_FAIL_BUFFER_WRITE, 0, 0,
                         "queue buffer write");
  expectExecutionFailure(CERBERUS_OPENCL_FAIL_KERNEL_ARGUMENT, 0, 0,
                         "kernel argument setup");
  expectExecutionFailure(CERBERUS_OPENCL_FAIL_KERNEL_SUBMIT, 0, 0,
                         "kernel queue submission");
  expectExecutionFailure(CERBERUS_OPENCL_FAIL_FOUND_READ, 0, 0,
                         "found-flag readback");
  expectExecutionFailure(CERBERUS_OPENCL_FAIL_RESULT_READ, 0, 1,
                         "candidate readback");

  char hashOutput[129] = "stale";
  cerberusOpenCLTestFailAfter(CERBERUS_OPENCL_FAIL_KERNEL_CREATE, 0);
  launch_opencl_hash_calc("abc", hashOutput, 2);
  cerberusOpenCLTestResetFault();
  check(hashOutput[0] == '\0',
        "OpenCL hash calculator clears output after kernel allocation failure");

  std::strcpy(hashOutput, "stale");
  cerberusOpenCLTestFailAfter(CERBERUS_OPENCL_FAIL_KERNEL_SUBMIT, 0);
  launch_opencl_hash_calc("abc", hashOutput, 2);
  cerberusOpenCLTestResetFault();
  check(hashOutput[0] == '\0',
        "OpenCL hash calculator clears output after execution failure");

  std::strcpy(hashOutput, "stale");
  cerberusOpenCLTestFailAfter(CERBERUS_OPENCL_FAIL_FINISH, 0);
  launch_opencl_hash_calc("abc", hashOutput, 2);
  cerberusOpenCLTestResetFault();
  check(hashOutput[0] == '\0',
        "OpenCL hash calculator clears output after queue finish failure");

  launch_opencl_hash_calc("abc", hashOutput, 2);
  check(std::string(hashOutput) == sha256("abc"),
        "OpenCL hash calculator recovers after queue failure");

  launch_opencl_hash_calc("abc", hashOutput, 11);
  check(std::string(hashOutput) == ntlm("abc"),
        "OpenCL NTLM hash calculator handles ASCII input");
  const std::string nonAsciiNtlm = "caf\xC3\xA9";
  launch_opencl_hash_calc(nonAsciiNtlm.c_str(), hashOutput, 11);
  check(hashOutput[0] == '\0',
        "OpenCL NTLM hash calculator rejects non-ASCII input");

  const char unsafeLog[] = "build\x1B\x7F\xC3\xA9";
  check(std::string(cerberusTestTerminalSafeOpenCLText(unsafeLog)) ==
            "build\\x1B\\x7F\\xC3\\xA9",
        "OpenCL build log sanitizer escapes terminal controls and non-ASCII bytes");
  cleanupOpenCL();
  set_opencl_quiet(0);
}

#if defined(ENABLE_CUDA)
void testCudaFaultInjection(bool deviceAvailable) {
  const std::string target = sha256("7");
  auto expectFailure = [&](int fault, int skip,
                           unsigned long long expectedAttempts,
                           const char *name, bool needsDevice) {
    if (needsDevice && !deviceAvailable) return;
    char recovered[32] = "stale";
    unsigned long long attempts = 99;
    cerberusCudaTestFailAfter(fault, skip);
    const int succeeded = launch_gpu_brute_force_ext(
        "7", target.c_str(), 1, recovered, 2, "", &attempts, nullptr, nullptr);
    cerberusCudaTestResetFault();
    check(succeeded == 0,
          (std::string("CUDA injected ") + name + " failure is reported")
              .c_str());
    check(recovered[0] == '\0',
          (std::string("CUDA injected ") + name +
           " failure returns no candidate")
              .c_str());
    check(attempts == expectedAttempts,
          (std::string("CUDA injected ") + name +
           " failure preserves the dispatched-attempt count")
              .c_str());

    if (deviceAvailable) {
      char verified[32] = {};
      attempts = 0;
      const int recoveredAfterFailure = launch_gpu_brute_force_ext(
          "7", target.c_str(), 1, verified, 2, "", &attempts, nullptr,
          nullptr);
      check(recoveredAfterFailure == 1 && std::string(verified) == "7" &&
                attempts == 1,
            (std::string("CUDA recovers after injected ") + name + " failure")
                .c_str());
    }
  };

  expectFailure(CERBERUS_CUDA_FAIL_DRIVER_INITIALIZATION, 0, 0,
                "driver initialization", false);
  expectFailure(CERBERUS_CUDA_FAIL_ALLOCATION, 0, 0, "first allocation", false);
  expectFailure(CERBERUS_CUDA_FAIL_ALLOCATION, 3, 0,
                "partial allocation", true);
  expectFailure(CERBERUS_CUDA_FAIL_HOST_TO_DEVICE_COPY, 0, 0,
                "input transfer", true);
  expectFailure(CERBERUS_CUDA_FAIL_HOST_TO_DEVICE_COPY, 3, 0,
                "prefix transfer", true);
  expectFailure(CERBERUS_CUDA_FAIL_MEMSET, 0, 0, "device initialization", true);
  expectFailure(CERBERUS_CUDA_FAIL_KERNEL_LAUNCH, 0, 0,
                "kernel launch", true);
  expectFailure(CERBERUS_CUDA_FAIL_LAUNCH_STATUS, 0, 0,
                "launch status query", true);
  expectFailure(CERBERUS_CUDA_FAIL_SYNCHRONIZE, 0, 0,
                "device synchronization", true);
  expectFailure(CERBERUS_CUDA_FAIL_DEVICE_TO_HOST_COPY, 0, 1,
                "found-flag readback", true);
  expectFailure(CERBERUS_CUDA_FAIL_DEVICE_TO_HOST_COPY, 1, 1,
                "candidate readback", true);
}
#endif
#endif

void testOptionalGpuKernelBoundaries() {
  globalQuiet = true;
  globalJson = true;

  set_opencl_quiet(1);
  if (initOpenCL()) {
    runKernelBoundaryCases(false);
    const std::string splitCandidate = "1" + std::string(20, '0');
    const std::string splitTarget =
        "c344e9487bfbd5c4e03c9fb90d62a5dde5e00b54d55c46e9f4a803aea162b80c";
    char splitResult[256] = {};
    int stop = 0;
    unsigned long long splitAttempts = 0;
    const int splitSucceeded = launch_opencl_brute_force(
        "01", splitTarget.c_str(), 21, splitResult, &stop, 2, "",
        &splitAttempts);
    check(splitSucceeded == 1,
          "OpenCL completes a keyspace that crosses the one-million-item batch boundary");
    check(std::string(splitResult) == splitCandidate,
          "OpenCL second batch returns the independently hashed boundary candidate");
    check(splitAttempts == 4194302ULL,
          "OpenCL reports exactly the dispatched keyspace across both batches");
    cleanupOpenCL();
  } else if (requiredBackend("CERBERUS_REQUIRE_OPENCL")) {
    check(false, "required OpenCL backend is available for direct kernel tests");
  } else {
    std::cout << "[SKIP] OpenCL direct kernel boundaries: no usable OpenCL device\n";
  }

#if defined(ENABLE_CUDA)
  int deviceCount = 0;
  const cudaError_t deviceStatus = cudaGetDeviceCount(&deviceCount);
  const bool deviceAvailable = deviceStatus == cudaSuccess && deviceCount > 0;
#if defined(CERBERUS_TESTING)
  testCudaFaultInjection(deviceAvailable);
#endif
  if (deviceAvailable) {
    check(cudaSetDevice(0) == cudaSuccess, "CUDA selects device zero");
    int smokeResult = 0;
    launch_cuda_test(&smokeResult);
    check(smokeResult == 1337, "CUDA direct kernel execution smoke test");
    runKernelBoundaryCases(true);
#if defined(CERBERUS_TESTING)
    const std::string partitionCandidate = "101";
    const std::string partitionTarget =
        "16dc368a89b428b2485484313ba67a3912ca03f2b2b42429174a4f8b3dc84e44";
    char partitionResult[256] = {};
    unsigned long long partitionAttempts = 0;
    const int partitionSucceeded = launch_gpu_brute_force_ext_test_limit(
        "01", partitionTarget.c_str(), 3, partitionResult, 2, "",
        &partitionAttempts, 3);
    check(partitionSucceeded == 1,
          "CUDA executes a synthetic small-counter keyspace partition");
    check(std::string(partitionResult) == partitionCandidate,
          "CUDA prefix odometer returns the exact partitioned candidate");
    check(partitionAttempts == 12,
          "CUDA partitioned search counts each launched suffix exactly once");
#endif
  } else if (requiredBackend("CERBERUS_REQUIRE_CUDA")) {
    check(false, "required CUDA backend is available for direct kernel tests");
  } else {
    std::cout << "[SKIP] CUDA direct kernel boundaries: no usable CUDA device\n";
  }
#else
  if (requiredBackend("CERBERUS_REQUIRE_CUDA"))
    check(false, "CUDA direct kernel tests require a CUDA-enabled harness build");
#endif
  globalQuiet = false;
  globalJson = false;
}
} // namespace

int main() {
  testCryptoOracles();
  testEncodingsAndTargets();
  testScryptAndBcryptValidation();
  testCliHelpersAndCounters();
  testExplicitGpuFallbackGuard();
  testMutationAndPotfileHelpers();
  testStreamsAndBatchFiles();
  testOptionalGpuKernelBoundaries();
#if defined(CERBERUS_TESTING)
  testOpenCLFaultInjection();
#endif
  std::cout << checks - failures << "/" << checks << " native CERBERUS checks passed\n";
  return failures == 0 ? 0 : 1;
}
