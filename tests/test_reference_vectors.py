from __future__ import annotations

import base64
import hashlib
import hmac
import random
import string
import zlib

from support import CerberusCase, md4, ntlm, oracle_hash, scrypt_phc


class IndependentReferenceTests(CerberusCase):
    def test_md4_reference_matches_rfc_1320_vectors(self) -> None:
        vectors = {
            b"": "31d6cfe0d16ae931b73c59d7e0c089c0",
            b"a": "bde52cb31de33e46245e05fbdbd6fb24",
            b"abc": "a448017aaf21d8525fc10ae87aa6729d",
            b"message digest": "d9130a8164549fe818874806e1c7014b",
            b"abcdefghijklmnopqrstuvwxyz": "d79e1c308aa5bbcdeea8ed63df412da9",
        }
        for message, expected in vectors.items():
            with self.subTest(message=message):
                self.assertEqual(md4(message).hex(), expected)

    def test_hash_command_matches_independent_reference_matrix(self) -> None:
        password = "CERBERUS-reference-42"
        key = "independent-key"
        completed, result = self.invoke_json("hash", password, "--salt", key)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["plaintext"], password)
        self.assertEqual(result["crc32"], f"{zlib.crc32(password.encode()) & 0xffffffff:08x}")
        self.assertEqual(result["base64"], base64.b64encode(password.encode()).decode())
        for algo in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512"):
            with self.subTest(algo=algo):
                self.assertEqual(result[algo], hashlib.new(algo, password.encode()).hexdigest())
        self.assertEqual(result["md4"], md4(password.encode()).hex())
        self.assertEqual(result["ntlm"], ntlm(password))
        for algo in ("md5", "sha1", "sha256"):
            with self.subTest(hmac=algo):
                self.assertEqual(
                    result[f"hmac_{algo}"],
                    hmac.new(key.encode(), password.encode(), algo).hexdigest(),
                )
        self.assertEqual(
            result["pbkdf2_sha1"],
            hashlib.pbkdf2_hmac("sha1", password.encode(), key.encode(), 4096, 32).hex(),
        )

    def test_hash_matrix_matches_independent_oracles_at_padding_boundaries(self) -> None:
        rng = random.Random(0xCEB3)
        alphabet = string.ascii_letters + string.digits + " _!@$%^&*()+=:/.,?"
        key = "boundary-salt:1"
        for length in (0, 1, 27, 28, 31, 32, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129):
            password = "".join(rng.choice(alphabet) for _ in range(length))
            with self.subTest(utf8_byte_length=length):
                completed, result = self.invoke_json("hash", password, "--salt", key)
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                payload = password.encode("utf-8")
                self.assertEqual(result["plaintext"], password)
                self.assertEqual(result["crc32"], f"{zlib.crc32(payload) & 0xffffffff:08x}")
                self.assertEqual(result["base64"], base64.b64encode(payload).decode("ascii"))
                self.assertEqual(result["md4"], md4(payload).hex())
                self.assertEqual(result["ntlm"], ntlm(password))
                for algo in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512"):
                    self.assertEqual(result[algo], hashlib.new(algo, payload).hexdigest(), algo)
                for algo in ("md5", "sha1", "sha256"):
                    self.assertEqual(
                        result[f"hmac_{algo}"],
                        hmac.new(key.encode(), payload, algo).hexdigest(), algo,
                    )
                self.assertEqual(
                    result["pbkdf2_sha1"],
                    hashlib.pbkdf2_hmac("sha1", payload, key.encode(), 4096, 32).hex(),
                )

    def test_all_cpu_recovery_formats_return_the_exact_candidate(self) -> None:
        password = "correct1"
        salt = "forensic-salt:realm"
        hmac_key = "hmac:independent-key"
        cases = [
            ("crc32", oracle_hash("crc32", password)),
            ("md4", oracle_hash("md4", password)),
            ("md5", oracle_hash("md5", password)),
            ("ntlm", oracle_hash("ntlm", password)),
            ("sha1", oracle_hash("sha1", password)),
            ("sha224", oracle_hash("sha224", password)),
            ("sha256", oracle_hash("sha256", password)),
            ("sha384", oracle_hash("sha384", password)),
            ("sha512", oracle_hash("sha512", password)),
            ("salted-md5", oracle_hash("salted-md5", password, salt), salt),
            ("salted-sha1", oracle_hash("salted-sha1", password, salt), salt),
            ("salted-sha256", oracle_hash("salted-sha256", password, salt), salt),
            ("salted-sha512", oracle_hash("salted-sha512", password, salt), salt),
            ("hmac-md5", oracle_hash("hmac-md5", password, hmac_key), hmac_key),
            ("hmac-sha1", oracle_hash("hmac-sha1", password, hmac_key), hmac_key),
            ("hmac-sha256", oracle_hash("hmac-sha256", password, hmac_key), hmac_key),
            ("wpa2", oracle_hash("wpa2", password, "test-network"), "test-network"),
        ]
        display_names = {
            "crc32": "CRC32 (IEEE 802.3)",
            "md4": "MD4 (RFC 1320)",
            "md5": "MD5",
            "ntlm": "NTLM (Windows SAM/AD)",
            "sha1": "SHA1",
            "sha224": "SHA-224 (FIPS 180-4)",
            "sha256": "SHA-256",
            "sha384": "SHA-384 (FIPS 180-4)",
            "sha512": "SHA-512",
            "salted-md5": "MD5 + Salt",
            "salted-sha1": "SHA1 + Salt",
            "salted-sha256": "SHA256 + Salt",
            "salted-sha512": "SHA512 + Salt",
            "hmac-md5": "HMAC-MD5 (RFC 2104)",
            "hmac-sha1": "HMAC-SHA1 (RFC 2104)",
            "hmac-sha256": "HMAC-SHA256 (RFC 2104)",
            "wpa2": "WPA2 PMK (PBKDF2-HMAC-SHA1)",
        }
        for case in cases:
            algorithm, target, *salt_arg = case
            with self.subTest(algorithm=algorithm):
                completed, result = self.crack(
                    algorithm, target, password,
                    salt=salt_arg[0] if salt_arg else None,
                    timeout=90 if algorithm == "wpa2" else 60,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(result["status"], "cracked", result)
                self.assertEqual(result["plaintext"], password, result)
                self.assertEqual(result["algorithm"], display_names[algorithm])

    def test_hmac_accepts_an_empty_default_key_and_empty_salted_hash(self) -> None:
        candidate = "empty-key-check"
        completed, result = self.crack(
            "hmac-sha256", oracle_hash("hmac-sha256", candidate), candidate
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["status"], "cracked", result)
        self.assertEqual(result["plaintext"], candidate)

        empty_salt_candidate = "empty-salt-check"
        completed, result = self.crack(
            "salted-md5", oracle_hash("salted-md5", empty_salt_candidate),
            empty_salt_candidate, salt="",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["status"], "cracked", result)
        self.assertEqual(result["plaintext"], empty_salt_candidate)
        self.assertEqual(result["salt"], "")

    def test_salted_hash_verifiers_cross_digest_padding_boundaries(self) -> None:
        cases = (
            ("salted-md5", "m" * 55, "s"),
            ("salted-sha1", "h" * 55, "s"),
            ("salted-sha256", "s" * 55, "s"),
            ("salted-sha512", "t" * 111, "s"),
        )
        for algorithm, password, salt in cases:
            with self.subTest(algorithm=algorithm, candidate_length=len(password)):
                completed, result = self.crack(
                    algorithm, oracle_hash(algorithm, password, salt), password,
                    salt=salt,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(result["status"], "cracked", result)
                self.assertEqual(result["plaintext"], password)
                self.assertEqual(result["salt"], salt)

    def test_wpa2_maximum_valid_passphrase_and_ssid_lengths(self) -> None:
        password = "P" * 63
        ssid = "S" * 32
        target = hashlib.pbkdf2_hmac(
            "sha1", password.encode(), ssid.encode(), 4096, 32
        ).hex()
        completed, result = self.crack("wpa2", target, password, salt=ssid)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["status"], "cracked", result)
        self.assertEqual(result["plaintext"], password)
        self.assertEqual(result["salt"], ssid)

    def test_bcrypt_openwall_and_scrypt_phc_vectors(self) -> None:
        # Openwall crypt_blowfish test vector, also present in wrapper.c.
        bcrypt_targets = (
            "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
            "$2b$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
            "$2y$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
        )
        for bcrypt_target in bcrypt_targets:
            with self.subTest(algorithm="bcrypt", prefix=bcrypt_target[:4]):
                completed, result = self.crack("bcrypt", bcrypt_target, "U*U")
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(result["status"], "cracked", result)
                self.assertEqual(result["plaintext"], "U*U")

        password = "scrypt-pass"
        for params in ((4, 1, 1, 32), (5, 2, 1, 32), (4, 1, 2, 16)):
            log_n, r, p, dklen = params
            with self.subTest(algorithm="scrypt", params=params):
                completed, result = self.crack(
                    "scrypt", scrypt_phc(password, log_n=log_n, r=r, p=p, dklen=dklen),
                    password, timeout=90,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(result["status"], "cracked", result)
                self.assertEqual(result["plaintext"], password)

        # Openwall's published wrapper vector verifies 72-byte truncation.
        long_password = (
            "0123456789abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            "chars after 72 are ignored"
        )
        long_target = "$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui"
        with self.subTest(algorithm="bcrypt", boundary="72-byte limit"):
            completed, result = self.crack("bcrypt", long_target, long_password)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(result["status"], "cracked", result)
            self.assertEqual(result["plaintext"], long_password)

    def test_base64_decode_is_exact_and_utf8_aware(self) -> None:
        original = "forensic café"
        encoded = base64.b64encode(original.encode()).decode()
        for command in ("decode", "d"):
            with self.subTest(command=command):
                completed, result = self.invoke_json(command, encoded)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(result["status"], "decoded")
                self.assertEqual(result["plaintext"], original)

    def test_base64_decoder_rejects_noncanonical_or_invalid_encodings(self) -> None:
        for encoded in ("Zg=", "Zg===", "Z g==", "%%%%", "Zm9v="):
            with self.subTest(encoded=encoded):
                completed, result = self.invoke_json("decode", encoded)
                self.assertNotEqual(completed.returncode, 0, result)
                self.assertEqual(result["status"], "invalid_input", result)
                self.assertIsNone(result.get("plaintext"), result)

    def test_wordlist_reads_utf8_and_all_common_line_endings(self) -> None:
        target = hashlib.sha256("café".encode()).hexdigest()
        wordlist = self.write_file("mixed-lines.txt", b"wrong\rcaf\xc3\xa9\r\nother\n")
        completed, result = self.invoke_json(
            "crack", target, "--algo", "sha256", "--engine", "cpu",
            "--wordlist", str(wordlist), "--charset", "1", "--max-len", "1",
            "--no-potfile",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["status"], "cracked", result)
        self.assertEqual(result["plaintext"], "café")

    def test_wordlist_accepts_utf8_bom_and_flags_wide_encoding_as_incomplete(self) -> None:
        candidate = "BOM-candidate"
        target = hashlib.sha256(candidate.encode()).hexdigest()
        wordlist = self.write_file(
            "listas/café-密码.txt", b"\xef\xbb\xbf" + candidate.encode() + b"\n"
        )
        completed, result = self.invoke_json(
            "crack", target, "--algo", "sha256", "--engine", "cpu",
            "--wordlist", str(wordlist), "--charset", "1", "--max-len", "1",
            "--no-potfile",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["status"], "cracked", result)
        self.assertEqual(result["plaintext"], candidate)

        wide_wordlist = self.write_file(
            "wide-wordlist.txt", "not-the-target\n".encode("utf-16")
        )
        wide_run, wide_result = self.invoke_json(
            "crack", target, "--algo", "sha256", "--engine", "cpu",
            "--wordlist", str(wide_wordlist), "--charset", "1", "--max-len", "1",
            "--no-potfile",
        )
        self.assertNotEqual(wide_run.returncode, 0, wide_result)
        self.assertEqual(wide_result["status"], "incomplete", wide_result)
        self.assertIsNone(wide_result.get("plaintext"), wide_result)

    def test_ntlm_utf8_candidate_matches_utf16le_reference(self) -> None:
        password = "café-語"
        target = ntlm(password)
        self.write_file("wordlist.txt", (password + "\n").encode("utf-8"))
        completed, result = self.invoke_json(
            "crack", target, "--algo", "ntlm", "--engine", "cpu",
            "--wordlist", "wordlist.txt", "--charset", "1", "--max-len", "1",
            "--no-potfile",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["status"], "cracked", result)
        self.assertEqual(result["plaintext"], password)

    def test_empty_wordlist_entry_is_returned_exactly_for_empty_password_hashes(self) -> None:
        for algorithm in ("md4", "md5", "sha256", "sha512"):
            with self.subTest(algorithm=algorithm):
                target = oracle_hash(algorithm, "")
                completed, result = self.crack(algorithm, target, "")
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(result["status"], "cracked", result)
                self.assertEqual(result["plaintext"], "")

    def test_non_utf8_wordlist_candidate_round_trips_through_json_and_potfile(self) -> None:
        candidate = b"\xff"
        target = hashlib.md5(candidate).hexdigest()
        self.write_file("wordlist.txt", candidate + b"\n")
        args = (
            "crack", target, "--algo", "md5", "--engine", "cpu",
            "--wordlist", "wordlist.txt", "--charset", "1", "--max-len", "1",
        )
        first, first_result = self.invoke_json(*args)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first_result["status"], "cracked", first_result)
        self.assertIsNone(first_result["plaintext"])
        self.assertEqual(first_result["plaintext_base64"], "/w==")

        second, second_result = self.invoke_json(*args)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(second_result["status"], "cached", second_result)
        self.assertIsNone(second_result["plaintext"])
        self.assertEqual(second_result["plaintext_base64"], "/w==")
