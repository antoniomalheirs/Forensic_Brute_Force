"""Shared independent references and subprocess helpers for CERBERUS tests."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import subprocess
import tempfile
import unittest
import zlib
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
EXE = Path(os.environ.get("CERBERUS_EXE", ROOT / "cerberus.exe")).resolve()


def md4(data: bytes) -> bytes:
    """Small RFC 1320 MD4 reference used only by this test suite."""
    mask = 0xFFFFFFFF

    def rol32(value: int, count: int) -> int:
        value &= mask
        return ((value << count) | (value >> (32 - count))) & mask

    original_length = len(data)
    padded = bytearray(data)
    padded.append(0x80)
    while len(padded) % 64 != 56:
        padded.append(0)
    padded.extend((original_length * 8).to_bytes(8, "little"))

    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    round2_order = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
    round3_order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]

    for offset in range(0, len(padded), 64):
        words = [int.from_bytes(padded[offset + i : offset + i + 4], "little")
                 for i in range(0, 64, 4)]
        a, b, c, d = a0, b0, c0, d0

        for i in range(16):
            f = (b & c) | (~b & d)
            a, b, c, d = d, rol32(a + f + words[i], (3, 7, 11, 19)[i % 4]), b, c

        for i, word_index in enumerate(round2_order):
            g = (b & c) | (b & d) | (c & d)
            a, b, c, d = d, rol32(a + g + words[word_index] + 0x5A827999,
                                   (3, 5, 9, 13)[i % 4]), b, c

        for i, word_index in enumerate(round3_order):
            hh = b ^ c ^ d
            a, b, c, d = d, rol32(a + hh + words[word_index] + 0x6ED9EBA1,
                                   (3, 9, 11, 15)[i % 4]), b, c

        a0 = (a0 + a) & mask
        b0 = (b0 + b) & mask
        c0 = (c0 + c) & mask
        d0 = (d0 + d) & mask

    return b"".join(value.to_bytes(4, "little") for value in (a0, b0, c0, d0))


def ntlm(password: str) -> str:
    return md4(password.encode("utf-16le")).hex()


def crc32(data: bytes) -> str:
    return f"{zlib.crc32(data) & 0xFFFFFFFF:08x}"


def scrypt_phc(password: str, *, salt: bytes = b"cerberus-test-salt",
               log_n: int = 4, r: int = 1, p: int = 1,
               dklen: int = 32) -> str:
    derived = hashlib.scrypt(password.encode(), salt=salt, n=1 << log_n,
                             r=r, p=p, dklen=dklen, maxmem=32 * 1024 * 1024)
    b64 = lambda value: base64.b64encode(value).decode("ascii").rstrip("=")
    return f"$scrypt$ln={log_n},r={r},p={p}${b64(salt)}${b64(derived)}"


def oracle_hash(name: str, password: str, salt: str = "") -> str:
    payload = password.encode("utf-8")
    suffix = salt.encode("utf-8")
    if name == "crc32":
        return crc32(payload)
    if name == "md4":
        return md4(payload).hex()
    if name == "md5":
        return hashlib.md5(payload).hexdigest()
    if name == "ntlm":
        return ntlm(password)
    if name == "sha1":
        return hashlib.sha1(payload).hexdigest()
    if name == "sha224":
        return hashlib.sha224(payload).hexdigest()
    if name == "sha256":
        return hashlib.sha256(payload).hexdigest()
    if name == "sha384":
        return hashlib.sha384(payload).hexdigest()
    if name == "sha512":
        return hashlib.sha512(payload).hexdigest()
    if name.startswith("salted-"):
        digest = name.removeprefix("salted-")
        return hashlib.new(digest, payload + suffix).hexdigest()
    if name.startswith("hmac-"):
        digest = name.removeprefix("hmac-")
        return hmac.new(suffix, payload, digest).hexdigest()
    if name == "wpa2":
        return hashlib.pbkdf2_hmac("sha1", payload, suffix, 4096, 32).hex()
    if name == "base64":
        return base64.b64encode(payload).decode("ascii")
    raise ValueError(f"No independent oracle for {name}")


class CerberusCase(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        if not EXE.is_file():
            self.fail(f"CERBERUS executable not found: {EXE}; build it first or set CERBERUS_EXE")
        self._temp = tempfile.TemporaryDirectory(prefix="cerberus-tests-")
        self.addCleanup(self._temp.cleanup)
        self.cwd = Path(self._temp.name)

    def write_file(self, name: str, contents: bytes | str) -> Path:
        path = self.cwd / name
        path.parent.mkdir(parents=True, exist_ok=True)
        data = contents.encode("utf-8") if isinstance(contents, str) else contents
        path.write_bytes(data)
        return path

    def invoke(self, *args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(EXE), *map(str, args)], cwd=self.cwd, capture_output=True,
            text=True, encoding="utf-8", errors="replace", timeout=timeout,
            check=False,
        )

    def invoke_json(self, *args: str, timeout: int = 60) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
        completed = self.invoke(*args, "--json", timeout=timeout)
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            self.fail(
                f"CERBERUS did not emit valid JSON (exit {completed.returncode}): {error}\n"
                f"stdout={completed.stdout!r}\nstderr={completed.stderr!r}"
            )
        self.assertIsInstance(payload, dict, completed.stdout)
        return completed, payload

    def crack(self, algorithm: str, target: str, candidate: str, *,
              salt: str | None = None, no_dict: bool = False,
              engine: str = "cpu", extra: Iterable[str] = (),
              charset_id: int = 1, max_len: int = 1,
              timeout: int = 60) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
        args = ["crack", target, "--algo", algorithm, "--engine", engine,
                "--charset", str(charset_id), "--max-len", str(max_len),
                "--no-potfile"]
        if salt is not None:
            args.extend(["--salt", salt])
        if no_dict:
            args.append("--no-dict")
        else:
            self.write_file("wordlist.txt", candidate.encode("utf-8") + b"\n")
            args.extend(["--wordlist", "wordlist.txt"])
        args.extend(extra)
        return self.invoke_json(*args, timeout=timeout)
