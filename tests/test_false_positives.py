from __future__ import annotations

import hashlib

from support import CerberusCase, oracle_hash, scrypt_phc


class FalsePositiveTests(CerberusCase):
    def test_mutated_digest_nibbles_never_recover_the_wordlist_candidate(self) -> None:
        password = "decoy-candidate"
        for algorithm in ("md4", "md5", "ntlm", "sha1", "sha224", "sha256", "sha384", "sha512", "crc32"):
            original = oracle_hash(algorithm, password)
            for position in sorted({0, len(original) - 1}):
                replacement = "1" if original[position] != "1" else "2"
                target = original[:position] + replacement + original[position + 1:]
                with self.subTest(algorithm=algorithm, position=position):
                    completed, result = self.crack(algorithm, target, password)
                    self.assertNotEqual(result.get("status"), "cracked", result)
                    self.assertIsNone(result.get("plaintext"), result)
                    self.assertNotEqual(completed.returncode, 0)

    def test_salted_hmac_and_wpa2_variants_reject_mutated_digests(self) -> None:
        password = "decoy-candidate"
        cases = [
            ("salted-md5", "salt-A"),
            ("salted-sha1", "salt-B"),
            ("salted-sha256", "salt-C"),
            ("salted-sha512", "salt-D"),
            ("hmac-md5", "key-A"),
            ("hmac-sha1", "key-B"),
            ("hmac-sha256", "key-C"),
            ("wpa2", "test-network"),
        ]
        for algorithm, salt in cases:
            original = oracle_hash(algorithm, password, salt)
            replacement = "1" if original[-1] != "1" else "2"
            target = original[:-1] + replacement
            with self.subTest(algorithm=algorithm):
                completed, result = self.crack(
                    algorithm, target, password, salt=salt,
                    timeout=90 if algorithm == "wpa2" else 60,
                )
                self.assertNotEqual(result.get("status"), "cracked", result)
                self.assertIsNone(result.get("plaintext"), result)
                self.assertNotEqual(completed.returncode, 0)

    def test_wrong_salts_and_hmac_keys_never_return_plaintext(self) -> None:
        candidate = "7"
        cases = (
            ("salted-md5", "correct-md5-salt", "wrong-md5-salt"),
            ("salted-sha1", "correct-sha1-salt", "wrong-sha1-salt"),
            ("salted-sha256", "correct-sha256-salt", "wrong-sha256-salt"),
            ("salted-sha512", "correct-sha512-salt", "wrong-sha512-salt"),
            ("hmac-md5", "correct-md5-key", "wrong-md5-key"),
            ("hmac-sha1", "correct-sha1-key", "wrong-sha1-key"),
            ("hmac-sha256", "correct-sha256-key", "wrong-sha256-key"),
            ("wpa2", "correct-network", "wrong-network"),
        )
        for algorithm, actual_salt, supplied_salt in cases:
            target = oracle_hash(algorithm, candidate, actual_salt)
            with self.subTest(algorithm=algorithm):
                completed, result = self.crack(
                    algorithm, target, candidate, salt=supplied_salt,
                    no_dict=True, charset_id=1, max_len=1,
                    timeout=90 if algorithm == "wpa2" else 60,
                )
                self.assertEqual(result["status"], "exhausted", result)
                self.assertIsNone(result.get("plaintext"), result)
                self.assertNotEqual(completed.returncode, 0)

    def test_valid_bcrypt_target_does_not_accept_a_different_candidate(self) -> None:
        target = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"
        completed, result = self.crack("bcrypt", target, "wrong-candidate")
        self.assertEqual(result["status"], "exhausted", result)
        self.assertIsNone(result.get("plaintext"), result)
        self.assertNotEqual(completed.returncode, 0)

    def test_malformed_bcrypt_checksum_is_rejected_without_a_recovery(self) -> None:
        valid = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"
        replacement = "A" if valid[-1] != "A" else "B"
        malformed = valid[:-1] + replacement
        completed, result = self.crack("bcrypt", malformed, "U*U")
        self.assertEqual(result["status"], "invalid_input", result)
        self.assertIsNone(result.get("plaintext"), result)
        self.assertNotEqual(completed.returncode, 0)

    def test_wrong_candidate_is_never_reported_as_a_recovery(self) -> None:
        target = hashlib.sha256(b"actual-secret").hexdigest()
        completed, result = self.crack("sha256", target, "unrelated-decoy")
        self.assertEqual(result["status"], "exhausted", result)
        self.assertIsNone(result.get("plaintext"), result)
        self.assertNotEqual(completed.returncode, 0)

    def test_ambiguous_32_hex_target_is_bound_to_requested_algorithm(self) -> None:
        password = "algorithm-boundary"
        ntlm_target = oracle_hash("ntlm", password)
        completed, result = self.crack("md5", ntlm_target, password)
        self.assertEqual(result["status"], "exhausted", result)
        self.assertIsNone(result.get("plaintext"), result)
        self.assertNotEqual(completed.returncode, 0)

    def test_forged_potfile_record_is_reverified_before_returning_plaintext(self) -> None:
        password = "potfile-truth"
        target = hashlib.sha256(password.encode()).hexdigest()
        self.write_file("cracked_passwords.txt", f"v3|{target}|-|SHA-256|false-password\n")
        completed, result = self.crack("sha256", target, password)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["status"], "cracked", result)
        self.assertNotEqual(result["status"], "cached")
        self.assertEqual(result["plaintext"], password)

    def test_corrupted_scrypt_checksum_never_matches(self) -> None:
        password = "scrypt-negative"
        valid = scrypt_phc(password)
        pieces = valid.split("$")
        checksum = pieces[-1]
        pieces[-1] = ("A" if checksum[0] != "A" else "B") + checksum[1:]
        target = "$".join(pieces)
        completed, result = self.crack("scrypt", target, password, timeout=90)
        self.assertEqual(result["status"], "exhausted", result)
        self.assertIsNone(result.get("plaintext"), result)
        self.assertNotEqual(completed.returncode, 0)

\n