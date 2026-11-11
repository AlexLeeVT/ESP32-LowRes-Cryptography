#!/usr/bin/env python3
"""Build the Ascon implementation and verify it against the supplied KAT file."""

from __future__ import annotations

import argparse
import ctypes
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Kat:
    count: int
    key: bytes
    nonce: bytes
    plaintext: bytes
    associated_data: bytes
    ciphertext: bytes
    valid: bool = True
    categories: tuple[str, ...] = ("uncategorized",)


_FIELD = re.compile(r"^(Count|Key|Nonce|PT|AD|CT) = ?([0-9A-Fa-f]*)$")


def parse_kats(path: Path) -> list[Kat]:
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}

    for line_number, line in enumerate(
        path.read_text(encoding="ascii").splitlines(), start=1
    ):
        line = line.strip()
        if not line:
            if current:
                records.append(current)
                current = {}
            continue
        match = _FIELD.fullmatch(line)
        if not match:
            raise ValueError(f"{path}:{line_number}: invalid KAT line: {line!r}")
        field, value = match.groups()
        if field in current:
            raise ValueError(f"{path}:{line_number}: duplicate field {field}")
        current[field] = value
    if current:
        records.append(current)

    required = {"Count", "Key", "Nonce", "PT", "AD", "CT"}
    kats: list[Kat] = []
    for index, record in enumerate(records, start=1):
        missing = required - record.keys()
        if missing:
            raise ValueError(f"KAT {index} is missing: {', '.join(sorted(missing))}")
        try:
            decoded = {
                field: bytes.fromhex(value)
                for field, value in record.items()
                if field != "Count"
            }
            count = int(record["Count"])
        except ValueError as exc:
            raise ValueError(f"KAT {index} contains invalid hex or count") from exc
        if len(decoded["Key"]) != 16 or len(decoded["Nonce"]) != 16:
            raise ValueError(f"KAT {count} has an invalid key or nonce length")
        if len(decoded["CT"]) != len(decoded["PT"]) + 16:
            raise ValueError(f"KAT {count} has an invalid ciphertext length")
        kats.append(
            Kat(
                count,
                decoded["Key"],
                decoded["Nonce"],
                decoded["PT"],
                decoded["AD"],
                decoded["CT"],
                categories=("legacy",),
            )
        )
    if not kats:
        raise ValueError(f"{path} contains no KAT records")
    return kats


def parse_json_kats(path: Path) -> list[Kat]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        groups = document["testGroups"]
        tests = [test for group in groups for test in group["tests"]]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path} is not a valid Ascon JSON KAT file") from exc

    kats: list[Kat] = []
    for test in tests:
        try:
            count = int(test["tcId"])
            key = bytes.fromhex(test["key"])
            nonce = bytes.fromhex(test["iv"])
            plaintext = bytes.fromhex(test["msg"])
            associated_data = bytes.fromhex(test["aad"])
            ciphertext = bytes.fromhex(test["ct"] + test["tag"])
            valid = test["result"] == "valid"
            categories = tuple(test.get("flags", ("uncategorized",)))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"{path} contains an invalid JSON KAT") from exc
        if len(key) != 16 or len(nonce) != 16:
            raise ValueError(f"{path} KAT {count} has an invalid key or nonce length")
        if len(ciphertext) != len(plaintext) + 16:
            raise ValueError(f"{path} KAT {count} has an invalid ciphertext length")
        if test["result"] not in {"valid", "invalid"}:
            raise ValueError(f"{path} KAT {count} has an invalid result")
        kats.append(
            Kat(
                count,
                key,
                nonce,
                plaintext,
                associated_data,
                ciphertext,
                valid,
                categories,
            )
        )
    if not kats:
        raise ValueError(f"{path} contains no KAT records")
    return kats


def parse_kat_file(path: Path) -> list[Kat]:
    if path.suffix.lower() == ".json":
        return parse_json_kats(path)
    return parse_kats(path)


def print_category_summaries(kats_by_file: list[tuple[Path, list[Kat]]]) -> None:
    categories: Counter[str] = Counter()
    valid_by_category: Counter[str] = Counter()
    for _, kats in kats_by_file:
        for kat in kats:
            for category in kat.categories:
                categories[category] += 1
                if kat.valid:
                    valid_by_category[category] += 1

    if len(categories) <= 1:
        return
    print("Category summaries:")
    for category in sorted(categories):
        total = categories[category]
        valid = valid_by_category[category]
        print(f"  {category}: {total} KATs ({valid} valid, {total - valid} invalid)")


def _buffer(data: bytes, size: int | None = None) -> ctypes.Array[ctypes.c_char]:
    # A non-null one-byte buffer keeps zero-length inputs valid for every ABI.
    return ctypes.create_string_buffer(data, max(1, len(data), size or 0))


def build_library(source: Path, compiler: str, output: Path) -> None:
    command = [
        compiler,
        "-shared",
        "-O2",
        "-std=c99",
        str(source),
        "-o",
        str(output),
    ]
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise RuntimeError(f"compiler not found: {compiler}") from exc
    except subprocess.CalledProcessError as exc:
        details = (exc.stderr or exc.stdout).strip()
        raise RuntimeError(f"failed to build implementation:\n{details}") from exc


def verify(kats: list[Kat], library_path: Path) -> None:
    library = ctypes.CDLL(str(library_path))
    encrypt = library.crypto_aead_encrypt
    decrypt = library.crypto_aead_decrypt
    encrypt.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ulonglong),
        ctypes.c_void_p,
        ctypes.c_ulonglong,
        ctypes.c_void_p,
        ctypes.c_ulonglong,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    encrypt.restype = ctypes.c_int
    decrypt.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ulonglong),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_ulonglong,
        ctypes.c_void_p,
        ctypes.c_ulonglong,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    decrypt.restype = ctypes.c_int

    for kat in kats:
        key = _buffer(kat.key)
        nonce = _buffer(kat.nonce)
        plaintext = _buffer(kat.plaintext)
        associated_data = _buffer(kat.associated_data)
        ciphertext = _buffer(kat.ciphertext)
        produced = _buffer(b"", len(kat.ciphertext))
        produced_length = ctypes.c_ulonglong()

        if kat.valid:
            result = encrypt(
                produced,
                ctypes.byref(produced_length),
                plaintext,
                len(kat.plaintext),
                associated_data,
                len(kat.associated_data),
                None,
                nonce,
                key,
            )
            actual = bytes(produced.raw[: produced_length.value])
            if (
                result != 0
                or produced_length.value != len(kat.ciphertext)
                or actual != kat.ciphertext
            ):
                raise AssertionError(
                    f"KAT {kat.count} encryption mismatch "
                    f"(return={result}, length={produced_length.value}, actual={actual.hex().upper()})"
                )

        recovered = _buffer(b"", len(kat.plaintext))
        recovered_length = ctypes.c_ulonglong()
        result = decrypt(
            recovered,
            ctypes.byref(recovered_length),
            None,
            ciphertext,
            len(kat.ciphertext),
            associated_data,
            len(kat.associated_data),
            nonce,
            key,
        )
        if kat.valid:
            if result != 0 or recovered_length.value != len(kat.plaintext) or bytes(
                recovered.raw[: recovered_length.value]
            ) != kat.plaintext:
                raise AssertionError(f"KAT {kat.count} decryption failed (return={result})")
        elif result == 0:
            raise AssertionError(f"KAT {kat.count} accepted an invalid ciphertext")

        if kat.valid:
            tampered = bytearray(kat.ciphertext)
            tampered[-1] ^= 1
            tampered_buffer = _buffer(bytes(tampered))
            result = decrypt(
                recovered,
                ctypes.byref(recovered_length),
                None,
                tampered_buffer,
                len(tampered),
                associated_data,
                len(kat.associated_data),
                nonce,
                key,
            )
            if result == 0:
                raise AssertionError(f"KAT {kat.count} accepted a tampered tag")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, help="path to aead.c")
    parser.add_argument(
        "--kat",
        type=Path,
        action="append",
        help=(
            "KAT file to verify (may be repeated; default: legacy text and "
            "ascon_sp800_232_aead128_test.json)"
        ),
    )
    parser.add_argument("--compiler", default="gcc", help="C compiler command (default: gcc)")
    parser.add_argument(
        "--keep-build",
        action="store_true",
        help="keep the temporary compiled library and print its path",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parent
    source = (args.source or root / "aead.c").resolve()
    kat_paths = [
        path.resolve()
        for path in (
            args.kat
            or [
                root / "LWC_AEAD_KAT_128_128.txt",
                root / "ascon_sp800_232_aead128_test.json",
            ]
        )
    ]
    try:
        kats_by_file = [(path, parse_kat_file(path)) for path in kat_paths]
        build_dir = Path(tempfile.mkdtemp(prefix="ascon-kat-"))
        library_path = build_dir / "ascon_kat.dll"
        build_library(source, args.compiler, library_path)
        for path, kats in kats_by_file:
            verify(kats, library_path)
    except (AssertionError, OSError, RuntimeError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    finally:
        if "build_dir" in locals() and (not args.keep_build or "library_path" not in locals()):
            shutil.rmtree(build_dir, ignore_errors=True)

    total_kats = sum(len(kats) for _, kats in kats_by_file)
    print(f"PASS: {total_kats} KATs verified (encrypt, decrypt, and tag rejection)")
    print_category_summaries(kats_by_file)
    if args.keep_build:
        print(f"Built library: {library_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
