from __future__ import annotations

import json
import os
import re
import unittest
from functools import lru_cache

from support import CerberusCase, EXE, oracle_hash


GPU_KERNEL_CASES = (
    ("md4", ""), ("md5", ""), ("ntlm", ""),
    ("sha1", ""), ("sha256", ""), ("sha512", ""),
    ("salted-md5", "kernel-salt"), ("salted-sha1", "kernel-salt"),
    ("salted-sha256", "kernel-salt"), ("salted-sha512", "kernel-salt"),
)


@lru_cache(maxsize=None)
def engine_available(engine: str) -> bool:
    try:
        completed = __import__("subprocess").run(
            [str(EXE), "doctor", "--engine", engine, "--json"],
            capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=20, check=False,
        )
        info = json.loads(completed.stdout)
        return info.get("status") == "ready" and engine in info.get("engine", "").lower()
    except (OSError, ValueError, TimeoutError):
        return False


def mutate_last_hex_digit(value: str) -> str:
    replacement = "1" if value[-1] != "1" else "2"
    return value[:-1] + replacement


class EngineCorrectnessTests(CerberusCase):
    def test_required_gpu_backends_are_not_silently_skipped(self) -> None:
        if os.environ.get("CERBERUS_REQUIRE_CUDA") == "1":
            self.assertTrue(engine_available("cuda"), "CUDA was required but is unavailable")
        if os.environ.get("CERBERUS_REQUIRE_OPENCL") == "1":
            self.assertTrue(engine_available("opencl"), "OpenCL was required but is unavailable")

    def test_explicit_cpu_engine_is_reported_as_the_executing_engine(self) -> None:
        target = oracle_hash("sha256", "7")
        completed, result = self.crack("sha256", target, "7", no_dict=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["plaintext"], "7")
        self.assertEqual(result["status"], "cracked")
        self.assertIn("cpu", result["engine"].lower())

    def test_cpu_bruteforce_respects_selected_charset_and_candidate_length(self) -> None:
        candidate = "AZ"
        completed, result = self.crack(
            "sha256", oracle_hash("sha256", candidate), candidate,
            no_dict=True, charset_id=3, max_len=2,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertEqual(result["status"], "cracked", result)
        self.assertEqual(result["plaintext"], candidate)

    @unittest.skipUnless(engine_available("cuda"), "CUDA device/runtime not available on this host")
    def test_cuda_does_not_fall_back_for_an_unimplemented_kernel(self) -> None:
        completed, result = self.crack(
            "sha224", oracle_hash("sha224", "7"), "7", no_dict=True,
            engine="cuda",
        )
        self.assertEqual(completed.returncode, 1, result)
        self.assertEqual(result["status"], "unsupported", result)
        self.assertIsNone(result.get("plaintext"), result)
        self.assertIn("cuda", result["engine"].lower())

    @unittest.skipUnless(engine_available("cuda"), "CUDA device/runtime not available on this host")
    def test_every_cuda_hash_kernel_returns_the_exact_candidate(self) -> None:
        candidate = "7"
        for algorithm, salt in GPU_KERNEL_CASES:
            with self.subTest(algorithm=algorithm, salt=salt):
                target = oracle_hash(algorithm, candidate, salt)
                completed, result = self.crack(
                    algorithm, target, candidate, salt=salt or None,
                    no_dict=True, engine="cuda", timeout=90,
                )
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                self.assertEqual(result["status"], "cracked", result)
                self.assertEqual(result["plaintext"], candidate, result)
                self.assertIn("cuda", result["engine"].lower())

    @unittest.skipUnless(engine_available("cuda"), "CUDA device/runtime not available on this host")
    def test_every_cuda_hash_kernel_rejects_a_mutated_target(self) -> None:
        candidate = "7"
        for algorithm, salt in GPU_KERNEL_CASES:
            with self.subTest(algorithm=algorithm, salt=salt):
                correct_target = oracle_hash(algorithm, candidate, salt)
                wrong_target = mutate_last_hex_digit(correct_target)
                completed, result = self.crack(
                    algorithm, wrong_target, candidate, salt=salt or None,
                    no_dict=True, engine="cuda", timeout=90,
                )
                self.assertNotEqual(completed.returncode, 0, result)
                self.assertEqual(result["status"], "exhausted", result)
                self.assertIsNone(result.get("plaintext"), result)
                self.assertIn("cuda", result["engine"].lower())

    @unittest.skipUnless(engine_available("cuda"), "CUDA device/runtime not available on this host")
    def test_cuda_progress_labels_per_length_eta_and_total_elapsed_time(self) -> None:
        target = oracle_hash("sha256", "99")
        completed = self.invoke(
            "crack", target, "--algo", "sha256", "--engine", "cuda",
            "--no-dict", "--charset", "1", "--max-len", "2", "--no-potfile",
            timeout=60,
        )
        output = re.sub(r"\x1b\[[0-9;]*m", "", completed.stdout).replace("\r", "\n")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("[CUDA] L2/2", output)
        self.assertIn("ETA L2", output)
        self.assertIn("| Total ", output)

    @unittest.skipUnless(engine_available("cuda"), "CUDA device/runtime not available on this host")
    def test_cuda_benchmark_runs_every_measured_algorithm(self) -> None:
        completed = self.invoke("benchmark", "--engine", "cuda", timeout=30)
        output = re.sub(r"\x1b\[[0-9;]*m", "", completed.stdout)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("Benchmark finalizado", output)
        self.assertEqual(output.count("chaves em"), 6, output)
        for name in ("MD5", "NTLM (Windows)", "MD4 (RFC 1320)", "SHA1", "SHA-256", "SHA-512"):
            self.assertIn(name, output)

    @unittest.skipUnless(engine_available("opencl"), "OpenCL device/runtime not available on this host")
    def test_every_opencl_hash_kernel_returns_the_exact_candidate(self) -> None:
        candidate = "7"
        for algorithm, salt in GPU_KERNEL_CASES:
            with self.subTest(algorithm=algorithm, salt=salt):
                target = oracle_hash(algorithm, candidate, salt)
                completed, result = self.crack(
                    algorithm, target, candidate, salt=salt or None,
                    no_dict=True, engine="opencl", timeout=90,
                )
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                self.assertEqual(result["status"], "cracked", result)
                self.assertEqual(result["plaintext"], candidate, result)
                self.assertIn("opencl", result["engine"].lower())

    @unittest.skipUnless(engine_available("opencl"), "OpenCL device/runtime not available on this host")
    def test_every_opencl_hash_kernel_rejects_a_mutated_target(self) -> None:
        candidate = "7"
        for algorithm, salt in GPU_KERNEL_CASES:
            with self.subTest(algorithm=algorithm, salt=salt):
                correct_target = oracle_hash(algorithm, candidate, salt)
                wrong_target = mutate_last_hex_digit(correct_target)
                completed, result = self.crack(
                    algorithm, wrong_target, candidate, salt=salt or None,
                    no_dict=True, engine="opencl", timeout=90,
                )
                self.assertNotEqual(completed.returncode, 0, result)
                self.assertEqual(result["status"], "exhausted", result)
                self.assertIsNone(result.get("plaintext"), result)
                self.assertIn("opencl", result["engine"].lower())

    @unittest.skipUnless(engine_available("cuda"), "CUDA device/runtime not available on this host")
    def test_cuda_rejects_kernel_buffer_and_ntlm_boundaries_without_cpu_fallback(self) -> None:
        cases = (
            ("salted-sha256", "S" * 56, 64),
            ("salted-sha512", "T" * 176, 64),
            ("ntlm", None, 60),
        )
        for algorithm, salt, max_len in cases:
            candidate = "7"
            target = oracle_hash(algorithm, candidate, salt or "")
            with self.subTest(algorithm=algorithm, max_len=max_len):
                completed, result = self.crack(
                    algorithm, target, candidate, salt=salt, no_dict=True,
                    engine="cuda", charset_id=1, max_len=max_len,
                )
                self.assertEqual(completed.returncode, 1, result)
                self.assertEqual(result["status"], "unsupported", result)
                self.assertIsNone(result.get("plaintext"), result)
                self.assertIn("cuda", result["engine"].lower())

    @unittest.skipUnless(engine_available("opencl"), "OpenCL device/runtime not available on this host")
    def test_opencl_rejects_kernel_buffer_and_keyspace_boundaries_without_fallback(self) -> None:
        cases = (
            ("salted-sha256", "S" * 56, 64),
            ("salted-sha512", "T" * 176, 64),
            ("ntlm", None, 60),
        )
        for algorithm, salt, max_len in cases:
            candidate = "7"
            target = oracle_hash(algorithm, candidate, salt or "")
            with self.subTest(algorithm=algorithm, max_len=max_len):
                completed, result = self.crack(
                    algorithm, target, candidate, salt=salt, no_dict=True,
                    engine="opencl", charset_id=1, max_len=max_len,
                )
                self.assertEqual(completed.returncode, 1, result)
                self.assertEqual(result["status"], "unsupported", result)
                self.assertIsNone(result.get("plaintext"), result)
                self.assertIn("opencl", result["engine"].lower())

        target = oracle_hash("sha256", "7")
        completed, result = self.crack(
            "sha256", target, "7", no_dict=True, engine="opencl",
            charset_id=1, max_len=19,
        )
        self.assertEqual(completed.returncode, 1, result)
        self.assertEqual(result["status"], "unsupported", result)
        self.assertIsNone(result.get("plaintext"), result)
        self.assertIn("opencl", result["engine"].lower())

    @unittest.skipUnless(engine_available("opencl"), "OpenCL device/runtime not available on this host")
    def test_opencl_benchmark_runs_every_measured_algorithm(self) -> None:
        completed = self.invoke("benchmark", "--engine", "opencl", timeout=30)
        output = re.sub(r"\x1b\[[0-9;]*m", "", completed.stdout)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("Benchmark finalizado", output)
        self.assertEqual(output.count("chaves em"), 6, output)
        for name in ("MD5", "NTLM (Windows)", "MD4 (RFC 1320)", "SHA1", "SHA-256", "SHA-512"):
            self.assertIn(name, output)

    @unittest.skipUnless(engine_available("opencl"), "OpenCL device/runtime not available on this host")
    def test_opencl_does_not_fall_back_for_an_unimplemented_kernel(self) -> None:
        completed, result = self.crack(
            "sha224", oracle_hash("sha224", "7"), "7", no_dict=True,
            engine="opencl",
        )
        self.assertEqual(completed.returncode, 1, result)
        self.assertEqual(result["status"], "unsupported", result)
        self.assertIsNone(result.get("plaintext"), result)
        self.assertIn("opencl", result["engine"].lower())
