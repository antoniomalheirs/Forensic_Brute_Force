from __future__ import annotations

import hashlib
import re

from support import CerberusCase, ROOT, oracle_hash


class WorkflowTests(CerberusCase):
    def test_mutation_rules_find_a_documented_suffix_variant(self) -> None:
        cases = (
            ("secret", "Secret1"),       # title case + common suffix
            ("password", "PASSWORD"),    # uppercase
            ("password", "drowssap"),    # reverse
            ("password", "passwordpassword"),  # duplicate
            ("password", "p455w0rd"),     # leetspeak
            ("password", "p@$$w0rd"),     # alternate leetspeak
            ("password", "password2026"), # year suffix
            ("password", "123password"), # common prefix
        )
        for base, expected in cases:
            with self.subTest(expected=expected):
                target = hashlib.md5(expected.encode()).hexdigest()
                self.write_file("wordlist.txt", base + "\n")
                completed, result = self.invoke_json(
                    "crack", target, "--algo", "md5", "--engine", "cpu",
                    "--wordlist", "wordlist.txt", "--charset", "1", "--max-len", "1",
                    "--no-potfile",
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(result["status"], "cracked", result)
                self.assertEqual(result["plaintext"], expected)

    def test_potfile_hit_is_reported_as_cached_only_after_verification(self) -> None:
        candidate = "cached:proof|%"
        target = hashlib.sha256(candidate.encode()).hexdigest()
        self.write_file("wordlist.txt", candidate + "\n")
        args = ("crack", target, "--algo", "sha256", "--engine", "cpu",
                "--wordlist", "wordlist.txt", "--charset", "1", "--max-len", "1")
        first, first_result = self.invoke_json(*args)
        second, second_result = self.invoke_json(*args)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first_result["status"], "cracked", first_result)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(second_result["status"], "cached", second_result)
        self.assertEqual(second_result["plaintext"], candidate)

        history, entries = self.invoke_json("history")
        self.assertEqual(history.returncode, 0, history.stderr)
        self.assertEqual(entries["status"], "ok", entries)
        self.assertTrue(any(item["target"] == target and item["plaintext"] == candidate
                            for item in entries["entries"]))

        # --fresh bypasses a valid cache hit, but a newly found candidate is
        # still returned accurately and stored according to the CLI contract.
        fresh, fresh_result = self.invoke_json(*args, "--fresh")
        self.assertEqual(fresh.returncode, 0, fresh.stderr)
        self.assertEqual(fresh_result["status"], "cracked", fresh_result)
        self.assertEqual(fresh_result["plaintext"], candidate)

    def test_legacy_and_versioned_potfile_records_are_verified_before_cache_hits(self) -> None:
        candidate = "legacy-potfile-proof"
        target = hashlib.md5(candidate.encode()).hexdigest()
        args = (
            "crack", target, "--algo", "md5", "--engine", "cpu",
            "--no-dict", "--charset", "1", "--max-len", "1",
        )
        records = (
            ("legacy-three-field", f"{target}|-|{candidate}\n"),
            ("version-two", f"v2|{target}||MD5|{candidate}\n"),
        )
        for name, record in records:
            with self.subTest(record=name):
                self.write_file("cracked_passwords.txt", record)
                completed, result = self.invoke_json(*args)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(result["status"], "cached", result)
                self.assertEqual(result["plaintext"], candidate)

    def test_history_parses_legacy_and_versioned_records_and_marks_corruption(self) -> None:
        md5_target = hashlib.md5(b"legacy-three").hexdigest()
        sha256_target = hashlib.sha256(b"legacy-four").hexdigest()
        sha1_target = hashlib.sha1(b"versioned").hexdigest()
        content = (
            "\ufeff" + f"{md5_target}|-|legacy-three\n"
            + f"{sha256_target}||SHA-256|legacy-four\n"
            + f"v2|{sha1_target}||SHA1|with%7Cdelimiter\n"
            + "v3|malformed%Q1||MD5|ignored\n"
        )
        potfile = self.write_file("history-語.txt", content.encode("utf-8"))
        for command in ("history", "potfile", "show"):
            with self.subTest(command=command):
                completed, result = self.invoke_json(command, str(potfile))
                self.assertEqual(completed.returncode, 1, result)
                self.assertEqual(result["status"], "partial", result)
                self.assertTrue(result["invalid_records"], result)
                self.assertEqual(result["total"], 3, result)
                self.assertEqual(
                    [entry["plaintext"] for entry in result["entries"]],
                    ["legacy-three", "legacy-four", "with|delimiter"],
                )

    def test_crack_and_crack_salt_short_aliases_recover_the_exact_candidate(self) -> None:
        candidate = "7"
        self.write_file("wordlist.txt", candidate + "\n")
        plain, plain_result = self.invoke_json(
            "c", hashlib.sha256(candidate.encode()).hexdigest(), "--algo", "sha256",
            "--engine", "cpu", "--wordlist", "wordlist.txt", "--charset", "1",
            "--max-len", "1", "--no-potfile",
        )
        self.assertEqual(plain.returncode, 0, plain_result)
        self.assertEqual(plain_result["plaintext"], candidate)

        salt = "alias-salt"
        salted, salted_result = self.invoke_json(
            "cs", hashlib.md5((candidate + salt).encode()).hexdigest(),
            "--salt", salt, "--engine", "cpu", "--wordlist", "wordlist.txt",
            "--charset", "1", "--max-len", "1", "--no-potfile",
        )
        self.assertEqual(salted.returncode, 0, salted_result)
        self.assertEqual(salted_result["plaintext"], candidate)

    def test_failed_potfile_write_does_not_change_a_verified_recovery(self) -> None:
        candidate = "potfile-write-failure-proof"
        target = hashlib.sha256(candidate.encode()).hexdigest()
        self.write_file("wordlist.txt", candidate + "\n")
        (self.cwd / "cracked_passwords.txt").mkdir()
        completed, result = self.invoke_json(
            "crack", target, "--algo", "sha256", "--engine", "cpu",
            "--wordlist", "wordlist.txt", "--charset", "1", "--max-len", "1",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["status"], "cracked", result)
        self.assertEqual(result["plaintext"], candidate)
        self.assertIn("nao foi possivel abrir o potfile", completed.stderr)

    def test_missing_wordlist_and_wide_saltlist_are_never_reported_as_exhaustive(self) -> None:
        target = hashlib.sha256(b"not-in-the-numeric-keyspace").hexdigest()
        missing, missing_result = self.invoke_json(
            "crack", target, "--algo", "sha256", "--engine", "cpu",
            "--wordlist", "missing-wordlist.txt", "--charset", "1", "--max-len", "1",
            "--no-potfile",
        )
        self.assertNotEqual(missing.returncode, 0, missing_result)
        self.assertEqual(missing_result["status"], "invalid_input", missing_result)
        self.assertIsNone(missing_result.get("plaintext"), missing_result)

        candidate = "saltlist-read-error"
        salt = "hidden-in-utf16-list"
        self.write_file("wordlist.txt", candidate + "\n")
        self.write_file("saltlist.txt", (salt + "\n").encode("utf-16"))
        salted_target = hashlib.sha256((candidate + salt).encode()).hexdigest()
        salted, salted_result = self.invoke_json(
            "crack", salted_target, "--algo", "salted-sha256", "--engine", "cpu",
            "--wordlist", "wordlist.txt", "--charset", "1", "--max-len", "1",
            "--no-potfile",
        )
        self.assertNotEqual(salted.returncode, 0, salted_result)
        self.assertEqual(salted_result["status"], "incomplete", salted_result)
        self.assertIsNone(salted_result.get("plaintext"), salted_result)

    def test_saltlist_tries_multiple_entries_and_skips_duplicates(self) -> None:
        candidate = "multi-salt-proof-91"
        matching_salt = "target-salt"
        target = oracle_hash("salted-sha256", candidate, matching_salt)
        self.write_file("wordlist.txt", candidate + "\n")
        self.write_file(
            "saltlist.txt",
            "wrong-salt\n" + matching_salt + "\n" + matching_salt + "\n\n",
        )
        completed, result = self.invoke_json(
            "crack", target, "--algo", "salted-sha256", "--engine", "cpu",
            "--wordlist", "wordlist.txt", "--charset", "1", "--max-len", "1",
            "--no-potfile",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["status"], "cracked", result)
        self.assertEqual(result["plaintext"], candidate)
        self.assertEqual(result["salt"], matching_salt)
        self.assertEqual(result["attempts"], 2, result)

        # A complete miss still visits every unique salt. Duplicating list
        # entries must not inflate the verified-attempt count.
        miss = hashlib.sha256(b"not a candidate for either configured salt").hexdigest()
        self.write_file("wordlist.txt", "dedup-saltlist-proof\n")
        self.write_file("saltlist.txt", "one\ntwo\n")
        unique, unique_result = self.invoke_json(
            "crack", miss, "--algo", "salted-sha256", "--engine", "cpu",
            "--wordlist", "wordlist.txt", "--charset", "1", "--max-len", "1",
            "--no-potfile",
        )
        self.write_file("saltlist.txt", "one\ntwo\none\ntwo\n")
        duplicate, duplicate_result = self.invoke_json(
            "crack", miss, "--algo", "salted-sha256", "--engine", "cpu",
            "--wordlist", "wordlist.txt", "--charset", "1", "--max-len", "1",
            "--no-potfile",
        )
        self.assertNotEqual(unique.returncode, 0, unique_result)
        self.assertNotEqual(duplicate.returncode, 0, duplicate_result)
        self.assertEqual(unique_result["status"], "exhausted", unique_result)
        self.assertEqual(duplicate_result["status"], "exhausted", duplicate_result)
        self.assertIsNone(unique_result.get("plaintext"), unique_result)
        self.assertIsNone(duplicate_result.get("plaintext"), duplicate_result)
        self.assertEqual(duplicate_result["attempts"], unique_result["attempts"])

    def test_wpa2_saltlist_tries_multiple_unique_ssids(self) -> None:
        candidate = "wpa2-multi-ssid-proof"
        matching_ssid = "target-network"
        target = hashlib.pbkdf2_hmac(
            "sha1", candidate.encode(), matching_ssid.encode(), 4096, 32
        ).hex()
        self.write_file("wordlist.txt", candidate + "\n")
        self.write_file(
            "saltlist.txt",
            "decoy-network\n" + matching_ssid + "\n" + matching_ssid + "\n",
        )
        completed, result = self.invoke_json(
            "crack", target, "--algo", "wpa2", "--engine", "cpu",
            "--wordlist", "wordlist.txt", "--charset", "1", "--max-len", "1",
            "--no-potfile",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["status"], "cracked", result)
        self.assertEqual(result["plaintext"], candidate)
        self.assertEqual(result["salt"], matching_ssid)
        self.assertEqual(result["attempts"], 3, result)

    def test_auto_detection_and_crack_salt_command_match_expected_formats(self) -> None:
        candidate = "auto-detected"
        for algorithm in ("crc32", "md4", "md5", "ntlm", "sha1", "sha224",
                          "sha256", "sha384", "sha512"):
            with self.subTest(algorithm=algorithm):
                target = oracle_hash(algorithm, candidate)
                self.write_file("wordlist.txt", candidate + "\n")
                completed, result = self.invoke_json(
                    "crack", target, "--engine", "cpu", "--wordlist", "wordlist.txt",
                    "--charset", "1", "--max-len", "1", "--no-potfile",
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(result["status"], "cracked", result)
                self.assertEqual(result["plaintext"], candidate)

        salt = "explicit-salt"
        target = oracle_hash("salted-sha256", candidate, salt)
        self.write_file("wordlist.txt", candidate + "\n")
        completed, result = self.invoke_json(
            "crack-salt", target, "--salt", salt, "--engine", "cpu",
            "--wordlist", "wordlist.txt", "--charset", "1", "--max-len", "1",
            "--no-potfile",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["status"], "cracked", result)
        self.assertEqual(result["plaintext"], candidate)

    def test_release_bundled_wordlist_and_saltlist_are_discovered_beside_executable(self) -> None:
        bundled_wordlist = (ROOT / "data" / "lists" / "wordlist.txt").read_text(
            encoding="utf-8"
        ).splitlines()
        bundled_salts = (ROOT / "data" / "lists" / "saltlist.txt").read_text(
            encoding="utf-8"
        ).splitlines()
        self.assertIn("password", bundled_wordlist)
        self.assertIn("s4lt", bundled_salts)

        # Deliberately provide neither --wordlist nor --salt. CWD is an empty
        # temporary directory, so the executable-relative packaged lists must
        # supply both values for this recovery.
        target = oracle_hash("salted-md5", "password", "s4lt")
        completed, result = self.invoke_json(
            "crack", target, "--algo", "salted-md5", "--engine", "cpu",
            "--charset", "1", "--max-len", "1", "--no-potfile",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["status"], "cracked", result)
        self.assertEqual(result["plaintext"], "password")
        self.assertEqual(result["salt"], "s4lt")

    def test_current_and_legacy_lists_directories_override_packaged_data(self) -> None:
        candidate = "directory-priority-91c4"
        salt = "workspace-only-salt"
        target = oracle_hash("salted-sha256", candidate, salt)
        self.write_file("wordlist.txt", candidate + "\n")
        self.write_file("saltlist.txt", b"\xef\xbb\xbf" + salt.encode() + b"\n")
        completed, result = self.invoke_json(
            "crack", target, "--algo", "salted-sha256", "--engine", "cpu",
            "--charset", "1", "--max-len", "1", "--no-potfile",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["plaintext"], candidate)
        self.assertEqual(result["salt"], salt)

        # The older lists/ layout remains a supported fallback after direct
        # current-directory files are absent.
        (self.cwd / "wordlist.txt").unlink()
        (self.cwd / "saltlist.txt").unlink()
        self.write_file("lists/wordlist.txt", candidate + "\n")
        self.write_file("lists/saltlist.txt", salt + "\n")
        completed, result = self.invoke_json(
            "crack", target, "--algo", "salted-sha256", "--engine", "cpu",
            "--charset", "1", "--max-len", "1", "--no-potfile",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["plaintext"], candidate)
        self.assertEqual(result["salt"], salt)

    def test_explicit_salt_overrides_salt_embedded_in_target(self) -> None:
        candidate = "salt-precedence"
        actual_salt = "actual:realm"
        embedded_salt = "decoy:realm"
        target = f"{embedded_salt}:{oracle_hash('salted-sha256', candidate, actual_salt)}"
        self.write_file("wordlist.txt", candidate + "\n")
        completed, result = self.invoke_json(
            "crack", target, "--salt", actual_salt, "--engine", "cpu",
            "--wordlist", "wordlist.txt", "--charset", "1", "--max-len", "1",
            "--no-potfile",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["status"], "cracked", result)
        self.assertEqual(result["plaintext"], candidate)
        self.assertEqual(result["salt"], actual_salt)

    def test_uppercase_hex_digest_is_case_insensitive(self) -> None:
        candidate = "uppercase-digest"
        target = hashlib.sha256(candidate.encode()).hexdigest().upper()
        self.write_file("wordlist.txt", candidate + "\n")
        completed, result = self.invoke_json(
            "crack", target, "--algo", "sha256", "--engine", "cpu",
            "--wordlist", "wordlist.txt", "--charset", "1", "--max-len", "1",
            "--no-potfile",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["status"], "cracked", result)
        self.assertEqual(result["plaintext"], candidate)

    def test_batch_accepts_utf8_bom_and_both_utf16_endiannesses_and_aliases(self) -> None:
        candidate = "unicode-batch-語"
        target = hashlib.sha256(candidate.encode()).hexdigest()
        self.write_file("wordlist.txt", candidate + "\n")
        utf16_le = b"\xff\xfe" + (target + "\r\n").encode("utf-16-le")
        utf16_be = b"\xfe\xff" + (target + "\r\n").encode("utf-16-be")
        cases = (
            ("file", "--file", "utf8-bom.txt", b"\xef\xbb\xbf" + target.encode() + b"\n"),
            ("batch", "-f", "utf16-le.txt", utf16_le),
            ("f", "--file", "utf16-be.txt", utf16_be),
        )
        for command, option, filename, contents in cases:
            with self.subTest(command=command, option=option, filename=filename):
                batch = self.write_file(filename, contents)
                completed, result = self.invoke_json(
                    command, option, str(batch), "--engine", "cpu", "--wordlist",
                    "wordlist.txt", "--charset", "1", "--max-len", "1", "--no-potfile",
                )
                self.assertEqual(completed.returncode, 0, result)
                self.assertEqual(result["total"], 1, result)
                self.assertEqual(result["items"][0]["plaintext"], candidate)

    def test_batch_rejects_malformed_utf8_truncated_utf16_and_utf32(self) -> None:
        invalid_files = (
            ("invalid-utf8.txt", b"\xff\xfe"),
            ("truncated-utf16.txt", b"\xff\xfeA"),
            ("utf32-le.txt", b"\xff\xfe\x00\x00" + "a".encode("utf-32-le")),
            ("utf32-be.txt", b"\x00\x00\xfe\xff" + "a".encode("utf-32-be")),
        )
        for filename, contents in invalid_files:
            with self.subTest(filename=filename):
                batch = self.write_file(filename, contents)
                completed, result = self.invoke_json("file", str(batch))
                self.assertNotEqual(completed.returncode, 0, result)
                self.assertEqual(result.get("status"), "invalid_input", result)
                self.assertIsNone(result.get("plaintext"), result)
                for item in result.get("items", []):
                    self.assertIsNone(item.get("plaintext"), item)

    def test_missing_and_empty_batch_files_return_invalid_input(self) -> None:
        for path, expected in (("missing-targets.txt", 2),
                               ("empty-targets.txt", 2)):
            if path.startswith("empty"):
                self.write_file(path, "# only a comment\n\n")
            with self.subTest(path=path):
                completed, result = self.invoke_json("file", path)
                self.assertEqual(completed.returncode, expected, result)
                self.assertEqual(result["status"], "invalid_input", result)
                self.assertNotIn("plaintext", result)

    def test_wpa2_raw_64_hex_psk_wordlist_path(self) -> None:
        raw_psk = "a1" * 32
        self.write_file("wordlist.txt", raw_psk + "\n")
        completed, result = self.invoke_json(
            "crack", raw_psk, "--algo", "wpa2", "--engine", "cpu",
            "--wordlist", "wordlist.txt", "--charset", "1", "--max-len", "1",
            "--no-potfile",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["status"], "cracked", result)
        self.assertEqual(result["plaintext"], raw_psk)

    def test_quiet_output_uses_unambiguous_percent_encoded_fields(self) -> None:
        candidate = "quiet:secret"
        target = hashlib.sha256(candidate.encode()).hexdigest()
        self.write_file("wordlist.txt", candidate + "\n")
        completed = self.invoke(
            "crack", target, "--algo", "sha256", "--engine", "cpu",
            "--wordlist", "wordlist.txt", "--charset", "1", "--max-len", "1",
            "--no-potfile", "--quiet",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), f"{target}:quiet%3Asecret")

    def test_human_success_output_includes_recovered_credential(self) -> None:
        candidate = "human-output-secret"
        target = hashlib.sha256(candidate.encode()).hexdigest()
        self.write_file("wordlist.txt", candidate + "\n")
        completed = self.invoke(
            "crack", target, "--algo", "sha256", "--engine", "cpu",
            "--wordlist", "wordlist.txt", "--charset", "1", "--max-len", "1",
            "--no-potfile",
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("HASH ALVO", completed.stdout)
        self.assertIn("SENHA", completed.stdout)
        self.assertIn(candidate, completed.stdout)

    def test_human_exhaustion_output_reports_no_recovery(self) -> None:
        target = hashlib.sha256(b"outside-the-digit-keyspace").hexdigest()
        completed = self.invoke(
            "crack", target, "--algo", "sha256", "--engine", "cpu",
            "--no-dict", "--charset", "1", "--max-len", "1",
            "--no-potfile",
        )
        self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
        self.assertIn("ESGOTADO: SENHA", completed.stdout)
        self.assertIn("TENTATIVAS", completed.stdout)
        self.assertNotIn("[NOT_FOUND]", completed.stdout)

    def test_human_potfile_hit_and_history_display(self) -> None:
        candidate = "human-cache-proof"
        target = hashlib.sha256(candidate.encode()).hexdigest()
        self.write_file("wordlist.txt", candidate + "\n")
        args = (
            "crack", target, "--algo", "sha256", "--engine", "cpu",
            "--wordlist", "wordlist.txt", "--charset", "1", "--max-len", "1",
        )
        first = self.invoke(*args)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        cached = self.invoke(*args)
        self.assertEqual(cached.returncode, 0, cached.stdout + cached.stderr)
        self.assertIn("POTFILE CACHE HIT", cached.stdout)
        self.assertIn("TEMPO CACHE", cached.stdout)

        with (self.cwd / "cracked_passwords.txt").open("a", encoding="utf-8") as potfile:
            potfile.write("v3|bad%Q0||MD5|ignored\n")
        history = self.invoke("history")
        self.assertEqual(history.returncode, 1, history.stdout + history.stderr)
        self.assertIn("HISTORICO DE CREDENCIAIS", history.stdout)
        self.assertIn(candidate[:13] + "...", history.stdout)
        self.assertIn("registros invalidos", history.stderr)

    def test_human_batch_output_reports_recovered_target(self) -> None:
        candidate = "human-batch-proof"
        target = hashlib.sha256(candidate.encode()).hexdigest()
        self.write_file("wordlist.txt", candidate + "\n")
        self.write_file("targets.txt", target + "\n")
        completed = self.invoke(
            "file", "targets.txt", "--engine", "cpu", "--wordlist", "wordlist.txt",
            "--charset", "1", "--max-len", "1", "--no-potfile",
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("LOTE FORENSE", completed.stdout)
        self.assertIn(candidate, completed.stdout)

    def test_mixed_batch_reports_exact_per_target_results(self) -> None:
        a = hashlib.sha256(b"batch-alpha").hexdigest()
        b = hashlib.sha1(b"batch-bravo").hexdigest()
        bad = hashlib.sha256(b"nobody-knows").hexdigest()
        bad = ("0" if bad[0] != "0" else "1") + bad[1:]
        self.write_file("wordlist.txt", "batch-alpha\nbatch-bravo\n")
        self.write_file("targets.txt", f"# mixed hash batch\r\n{a}\r{b}\n{bad}\r")
        completed, result = self.invoke_json(
            "file", "targets.txt", "--engine", "cpu", "--wordlist", "wordlist.txt",
            "--charset", "1", "--max-len", "1", "--no-potfile",
        )
        self.assertEqual(completed.returncode, 1, result)
        self.assertEqual(result["total"], 3, result)
        self.assertEqual(result["cracked"], 2, result)
        self.assertEqual(result["exhausted"], 1, result)
        self.assertEqual([item["plaintext"] for item in result["items"]],
                         ["batch-alpha", "batch-bravo", None])
        self.assertEqual([item["status"] for item in result["items"]],
                         ["cracked", "cracked", "exhausted"])

    def test_inline_salt_hash_orientations_and_ambiguous_form(self) -> None:
        password = "inline-proof"
        salt_a = "realm:account-a"
        salt_b = "realm:account-b"
        digest_a = oracle_hash("salted-sha256", password, salt_a)
        digest_b = oracle_hash("salted-sha256", password, salt_b)
        self.write_file("wordlist.txt", password + "\n")
        self.write_file("targets.txt", f"{digest_a}:{salt_a}\n{salt_b}:{digest_b}\n")
        completed, result = self.invoke_json(
            "file", "targets.txt", "--engine", "cpu", "--wordlist", "wordlist.txt",
            "--charset", "1", "--max-len", "1", "--no-potfile",
        )
        self.assertEqual(completed.returncode, 0, result)
        self.assertEqual(result["cracked"], 2, result)
        self.assertEqual([item["plaintext"] for item in result["items"]], [password, password])
        self.assertEqual([item["salt"] for item in result["items"]], [salt_a, salt_b])

        ambiguous = "a" * 32 + ":" + hashlib.md5(password.encode()).hexdigest()
        self.write_file("ambiguous.txt", ambiguous + "\n")
        bad_run, bad_result = self.invoke_json(
            "file", "ambiguous.txt", "--engine", "cpu", "--wordlist", "wordlist.txt",
            "--charset", "1", "--max-len", "1", "--no-potfile",
        )
        self.assertEqual(bad_run.returncode, 1, bad_result)
        self.assertEqual(bad_result["invalid"], 1, bad_result)
        self.assertEqual(bad_result["items"][0]["status"], "invalid_input", bad_result)
        self.assertIsNone(bad_result["items"][0]["plaintext"])

    def test_input_validation_never_emits_a_plaintext(self) -> None:
        wordlist = self.write_file("wordlist.txt", "candidate\n")
        cases = [
            ("crack", "not-a-digest", "--algo", "md5"),
            ("crack", "$scrypt$ln=4,r=1,p=1$%%%$%%%", "--algo", "scrypt"),
            ("crack", "malformed", "--algo", "bcrypt"),
            ("crack", "%%%%", "--algo", "base64"),
            ("crack", "not-an-ssid", "--algo", "wpa3"),
            ("crack", "{\"format\":\"SAE capture\"}", "--algo", "wpa3"),
            ("crack", "{\"platform\":\"facebook\",\"archive\":[]}", "--algo", "facebook"),
            ("crack", "{\"platform\":\"instagram\",\"archive\":[]}", "--algo", "instagram"),
            ("crack", "{\"platform\":\"twitter\",\"archive\":[]}", "--algo", "twitter"),
        ]
        for command in cases:
            with self.subTest(command=command):
                completed, result = self.invoke_json(
                    *command, "--engine", "cpu", "--wordlist", str(wordlist),
                    "--charset", "1", "--max-len", "1", "--no-potfile",
                )
                self.assertIn(result["status"], {"invalid_input", "unsupported"}, result)
                self.assertIsNone(result.get("plaintext"), result)
                self.assertNotEqual(completed.returncode, 0)

    def test_resource_limits_reject_valid_but_excessive_cost_parameters(self) -> None:
        # Valid PHC syntax with N=2^22 would exceed the product's memory cap.
        over_limit = "$scrypt$ln=4,r=1,p=1$c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        over_limit = over_limit.replace("ln=4,r=1", "ln=18,r=9")
        completed, result = self.invoke_json(
            "crack", over_limit, "--algo", "scrypt", "--engine", "cpu",
            "--no-dict", "--no-potfile", "--charset", "1", "--max-len", "1",
        )
        self.assertEqual(completed.returncode, 1, result)
        self.assertEqual(result["status"], "unsupported", result)
        self.assertIsNone(result.get("plaintext"), result)

        bcrypt_valid = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"
        bcrypt_over_limit = bcrypt_valid[:4] + "31" + bcrypt_valid[6:]
        completed, result = self.invoke_json(
            "crack", bcrypt_over_limit, "--algo", "bcrypt", "--engine", "cpu",
            "--no-dict", "--no-potfile", "--charset", "1", "--max-len", "1",
        )
        self.assertEqual(completed.returncode, 1, result)
        self.assertEqual(result["status"], "unsupported", result)
        self.assertIsNone(result.get("plaintext"), result)

    def test_overlong_wpa2_ssid_is_invalid_and_never_recovers(self) -> None:
        target = "0" * 64
        completed, result = self.invoke_json(
            "crack", target, "--algo", "wpa2", "--engine", "cpu",
            "--salt", "S" * 33, "--no-dict", "--no-potfile",
            "--charset", "1", "--max-len", "1",
        )
        self.assertEqual(completed.returncode, 1, result)
        self.assertEqual(result["status"], "invalid_input", result)
        self.assertIsNone(result.get("plaintext"), result)

    def test_cli_option_errors_are_structured_and_nonzero(self) -> None:
        for args in (("crack", "0" * 32, "--typo"),
                     ("crack", "0" * 32, "--algo", "md5", "--max-len=0"),
                     ("crack", "0" * 32, "--salt"),
                     ("crack", "0" * 32, "--engine", "not-an-engine")):
            with self.subTest(args=args):
                completed, result = self.invoke_json(*args)
                self.assertEqual(completed.returncode, 2, result)
                self.assertEqual(result["status"], "invalid_input", result)
                self.assertNotIn("plaintext", result)

    def test_doctor_json_reports_release_data_paths_and_runtime_state(self) -> None:
        completed, result = self.invoke_json("doctor")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(result["status"], {"ready", "degraded"})
        self.assertIn("engine", result)
        self.assertIn("wordlist_available", result)
        self.assertIn("saltlist_available", result)
        self.assertTrue((ROOT / "data" / "lists" / "wordlist.txt").is_file())
        self.assertTrue((ROOT / "data" / "lists" / "saltlist.txt").is_file())

    def test_internal_integration_smoke_remains_green(self) -> None:
        completed = self.invoke("test", "--engine", "cpu", timeout=90)
        stripped = re.sub(r"\x1b\[[0-9;]*m", "", completed.stdout)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("11 PASS", stripped)
        self.assertIn("TOTAL: 11", stripped)
