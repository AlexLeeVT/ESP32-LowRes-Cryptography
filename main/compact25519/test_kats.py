"""Run the bundled X25519 and Ed25519 known-answer tests.

The harness uses ctypes, so it does not require a Python crypto package. By
default it builds compact25519.c with gcc/clang and loads the resulting shared
library. A prebuilt library can be supplied with --library.
"""

from __future__ import annotations

import argparse
import ctypes
import gc
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent
HEX = re.compile(r"^[0-9a-fA-F]+$")


def parse_hex(value: str, size: int, description: str) -> bytes:
    value = value.strip()
    if len(value) != size * 2 or not HEX.fullmatch(value):
        raise ValueError(f"{description}: expected {size} bytes of hexadecimal data")
    return bytes.fromhex(value)


def parse_x25519_vectors(path: Path) -> list[tuple[bytes, bytes, bytes]]:
    text = path.read_text(encoding="ascii")
    scalars = re.findall(r"^\s*Input scalar:\s*$\n\s*([0-9a-fA-F]{64})\s*$", text, re.MULTILINE)
    inputs = re.findall(r"^\s*Input u-coordinate:\s*$\n\s*([0-9a-fA-F]{64})\s*$", text, re.MULTILINE)
    outputs = re.findall(r"^\s*Output u-coordinate:\s*$\n\s*([0-9a-fA-F]{64})\s*$", text, re.MULTILINE)
    if not (len(scalars) == len(inputs) == len(outputs)):
        raise ValueError(f"{path}: incomplete X25519 vector set")
    return [
        (bytes.fromhex(scalar), bytes.fromhex(input_u), bytes.fromhex(output))
        for scalar, input_u, output in zip(scalars, inputs, outputs)
    ]


def parse_wycheproof_x25519(
    path: Path,
) -> list[tuple[str, bytes, bytes, bytes, int, tuple[str, ...], str]]:
    vectors = []
    for line_number, line in enumerate(path.read_text(encoding="ascii").splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 7:
            raise ValueError(f"{path}:{line_number}: expected 7 tab-delimited fields")
        test_id, result, private, public, shared, flags, comment = fields
        vectors.append(
            (
                result,
                parse_hex(private, 32, f"{path}:{line_number} private key"),
                parse_hex(public, 32, f"{path}:{line_number} public key"),
                parse_hex(shared, 32, f"{path}:{line_number} shared secret"),
                int(test_id),
                tuple(flag for flag in flags.split(",") if flag),
                comment or flags,
            )
        )
    return vectors


def parse_ed25519_vectors(path: Path) -> list[tuple[bytes, bytes, bytes, bytes]]:
    vectors = []
    for line_number, line in enumerate(path.read_text(encoding="ascii").splitlines(), 1):
        if not line.strip():
            continue
        fields = line.split(":")
        if len(fields) == 5 and fields[-1] == "":
            fields.pop()
        if len(fields) != 4:
            raise ValueError(f"{path}:{line_number}: expected 4 colon-delimited fields")
        private_key = parse_hex(fields[0], 64, f"{path}:{line_number} private key")
        public_key = parse_hex(fields[1], 32, f"{path}:{line_number} public key")
        message = fields[2]
        if len(message) % 2 or (message and not HEX.fullmatch(message)):
            raise ValueError(f"{path}:{line_number}: invalid message encoding")
        encoded_signature = fields[3]
        if len(encoded_signature) != 128 + len(message) or not encoded_signature.endswith(message):
            raise ValueError(f"{path}:{line_number}: signature record does not end with the message")
        signature = parse_hex(
            encoded_signature[:128], 64, f"{path}:{line_number} signature"
        )
        vectors.append((private_key, public_key, bytes.fromhex(message), signature))
    if not vectors:
        raise ValueError(f"{path}: no Ed25519 vectors found")
    return vectors


def parse_wycheproof_ed25519(
    path: Path,
) -> list[tuple[str, bytes, bytes, bytes, int, tuple[str, ...], str]]:
    vectors = []
    for line_number, line in enumerate(path.read_text(encoding="ascii").splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 7:
            raise ValueError(f"{path}:{line_number}: expected 7 tab-delimited fields")
        test_id, result, public, message, signature, flags, comment = fields
        vectors.append(
            (
                result,
                parse_hex(public, 32, f"{path}:{line_number} public key"),
                bytes.fromhex(message),
                bytes.fromhex(signature),
                int(test_id),
                tuple(flag for flag in flags.split(",") if flag),
                comment or flags,
            )
        )
    return vectors


def compiler_command(compiler: str, source: Path, output: Path) -> list[str]:
    if os.name == "nt":
        return [compiler, "-shared", "-O2", "-o", str(output), str(source)]
    return [compiler, "-shared", "-fPIC", "-O2", "-o", str(output), str(source)]


def build_library(compiler: str, directory: Path) -> Path:
    output = directory / ("compact25519_kat.dll" if os.name == "nt" else "libcompact25519_kat.so")
    command = compiler_command(compiler, ROOT / "compact25519.c", output)
    try:
        subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)
    except FileNotFoundError as error:
        raise RuntimeError(f"compiler not found: {compiler}") from error
    except subprocess.CalledProcessError as error:
        details = (error.stderr or error.stdout).strip()
        raise RuntimeError(f"failed to build shared library:\n{details}") from error
    return output


class Compact25519:
    def __init__(self, library: Path):
        self.library = ctypes.CDLL(str(library))
        byte32 = ctypes.POINTER(ctypes.c_uint8)
        byte64 = ctypes.POINTER(ctypes.c_uint8)

        self.x25519_shared = self.library.compact_x25519_shared
        self.x25519_shared.argtypes = [byte32, byte32, byte32]
        self.x25519_shared.restype = None

        self.ed25519_calc_public_key = self.library.compact_ed25519_calc_public_key
        self.ed25519_calc_public_key.argtypes = [byte32, byte64]
        self.ed25519_calc_public_key.restype = None

        self.ed25519_sign = self.library.compact_ed25519_sign
        self.ed25519_sign.argtypes = [byte64, byte64, ctypes.c_void_p, ctypes.c_size_t]
        self.ed25519_sign.restype = None

        self.ed25519_verify = self.library.compact_ed25519_verify
        self.ed25519_verify.argtypes = [byte64, byte32, ctypes.c_void_p, ctypes.c_size_t]
        self.ed25519_verify.restype = ctypes.c_bool

        self.ed25519_verify_length = self.library.compact_ed25519_verify_length
        self.ed25519_verify_length.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            byte32,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        self.ed25519_verify_length.restype = ctypes.c_bool

    def close(self) -> None:
        for name in (
            "compact_x25519_shared",
            "compact_ed25519_calc_public_key",
            "compact_ed25519_sign",
            "compact_ed25519_verify",
            "compact_ed25519_verify_length",
        ):
            try:
                delattr(self.library, name)
            except AttributeError:
                pass
        self.x25519_shared = None
        self.ed25519_calc_public_key = None
        self.ed25519_sign = None
        self.ed25519_verify = None
        self.ed25519_verify_length = None
        self.library = None
        gc.collect()


def byte_array(value: bytes) -> ctypes.Array[ctypes.c_uint8]:
    return (ctypes.c_uint8 * len(value)).from_buffer_copy(value)


def run_x25519(api: Compact25519, vectors: list[tuple[bytes, bytes, bytes]]) -> int:
    failures = 0
    for number, (scalar, input_u, expected) in enumerate(vectors, 1):
        actual = (ctypes.c_uint8 * 32)()
        api.x25519_shared(actual, byte_array(scalar), byte_array(input_u))
        result = bytes(actual)
        if result != expected:
            failures += 1
            print(f"X25519 vector {number} failed")
    print(f"X25519: {len(vectors)} vectors checked")
    return failures


def run_ed25519(
    api: Compact25519,
    vectors: list[tuple[bytes, bytes, bytes, bytes]],
) -> int:
    failures = 0
    for number, (private_key, expected_public, message, expected_signature) in enumerate(vectors, 1):
        actual_public = (ctypes.c_uint8 * 32)()
        api.ed25519_calc_public_key(actual_public, byte_array(private_key))

        actual_signature = (ctypes.c_uint8 * 64)()
        message_buffer = ctypes.create_string_buffer(message, max(1, len(message)))
        api.ed25519_sign(
            actual_signature,
            byte_array(private_key),
            ctypes.cast(message_buffer, ctypes.c_void_p),
            len(message),
        )
        valid = api.ed25519_verify(
            actual_signature,
            byte_array(expected_public),
            ctypes.cast(message_buffer, ctypes.c_void_p),
            len(message),
        )
        result_public = bytes(actual_public)
        result_signature = bytes(actual_signature)
        if result_public != expected_public or result_signature != expected_signature or not valid:
            failures += 1
            print(f"Ed25519 vector {number} failed")
            if result_public != expected_public:
                print(f"  public key expected: {expected_public.hex()}")
                print(f"  public key actual:   {result_public.hex()}")
            if result_signature != expected_signature:
                print(f"  signature expected: {expected_signature.hex()}")
                print(f"  signature actual:   {result_signature.hex()}")
            if not valid:
                print("  generated signature did not verify")
    print(f"Ed25519: {len(vectors)} vectors checked")
    return failures


def run_wycheproof_x25519(
    api: Compact25519,
    vectors: list[tuple[str, bytes, bytes, bytes, int, tuple[str, ...], str]],
) -> int:
    failures = 0
    for expected_result, private, public, expected, test_id, _, description in vectors:
        actual = (ctypes.c_uint8 * 32)()
        api.x25519_shared(actual, byte_array(private), byte_array(public))
        result = bytes(actual)
        matches_expected = result == expected
        if expected_result == "valid":
            passed = matches_expected
        elif expected_result == "acceptable":
            passed = matches_expected
        else:
            passed = not matches_expected
        if not passed:
            failures += 1
            print(f"Wycheproof X25519 test {test_id} failed: {description}")
    print(f"Wycheproof X25519: {len(vectors)} vectors checked")
    return failures


def run_wycheproof_ed25519(
    api: Compact25519,
    vectors: list[tuple[str, bytes, bytes, bytes, int, tuple[str, ...], str]],
) -> int:
    failures = 0
    for expected_result, public, message, signature, test_id, _, description in vectors:
        message_buffer = ctypes.create_string_buffer(message, max(1, len(message)))
        actual = bool(
            api.ed25519_verify_length(
                byte_array(signature),
                len(signature),
                byte_array(public),
                ctypes.cast(message_buffer, ctypes.c_void_p),
                len(message),
            )
        )
        expected = expected_result == "valid"
        passed = actual == expected
        if not passed:
            failures += 1
            print(f"Wycheproof Ed25519 test {test_id} failed: {description}")
    print(f"Wycheproof Ed25519: {len(vectors)} vectors checked")
    return failures


def print_test_summaries(
    x25519_vectors: list[tuple[bytes, bytes, bytes]],
    ed25519_vectors: list[tuple[bytes, bytes, bytes, bytes]],
    wycheproof_x25519: list[tuple[str, bytes, bytes, bytes, int, tuple[str, ...], str]],
    wycheproof_ed25519: list[tuple[str, bytes, bytes, bytes, int, tuple[str, ...], str]],
) -> None:
    category_results: dict[str, Counter[str]] = {
        "X25519": Counter(valid=len(x25519_vectors)),
        "Ed25519": Counter(valid=len(ed25519_vectors)),
        "Wycheproof X25519": Counter(),
        "Wycheproof Ed25519": Counter(),
    }
    for name, vectors in (
        ("Wycheproof X25519", wycheproof_x25519),
        ("Wycheproof Ed25519", wycheproof_ed25519),
    ):
        results = category_results[name]
        results["valid"] = sum(vector[0] != "invalid" for vector in vectors)
        results["invalid"] = sum(vector[0] == "invalid" for vector in vectors)

    for vectors in (wycheproof_x25519, wycheproof_ed25519):
        for vector in vectors:
            for category in vector[5]:
                results = category_results.setdefault(category, Counter())
                results["valid" if vector[0] != "invalid" else "invalid"] += 1

    print("Category summaries:")
    for category, results in sorted(category_results.items()):
        total = results["valid"] + results["invalid"]
        print(
            f"  {category}: {total} KATs "
            f"({results['valid']} valid, {results['invalid']} invalid)"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, help="prebuilt compact25519 shared library/DLL")
    parser.add_argument("--compiler", default=shutil.which("gcc") or shutil.which("clang") or "gcc")
    parser.add_argument("--x25519-kat", type=Path, default=ROOT / "X25519_KAT.txt")
    parser.add_argument("--ed25519-kat", type=Path, default=ROOT / "Ed25519_KAT.txt")
    parser.add_argument("--wycheproof-x25519", type=Path)
    parser.add_argument("--wycheproof-ed25519", type=Path)
    args = parser.parse_args()

    try:
        x25519_vectors = parse_x25519_vectors(args.x25519_kat)
        ed25519_vectors = parse_ed25519_vectors(args.ed25519_kat)
        wycheproof_x25519 = (
            parse_wycheproof_x25519(args.wycheproof_x25519)
            if args.wycheproof_x25519
            else []
        )
        wycheproof_ed25519 = (
            parse_wycheproof_ed25519(args.wycheproof_ed25519)
            if args.wycheproof_ed25519
            else []
        )
        if args.library:
            library = args.library.resolve()
            if not library.is_file():
                raise RuntimeError(f"library not found: {library}")
            api = Compact25519(library)
            try:
                print_test_summaries(
                    x25519_vectors,
                    ed25519_vectors,
                    wycheproof_x25519,
                    wycheproof_ed25519,
                )
                return (
                    run_x25519(api, x25519_vectors)
                    + run_ed25519(api, ed25519_vectors)
                    + run_wycheproof_x25519(api, wycheproof_x25519)
                    + run_wycheproof_ed25519(api, wycheproof_ed25519)
                )
            finally:
                api.close()
                del api
        build_directory = Path(tempfile.mkdtemp(prefix="compact25519-kat-"))
        library = build_library(args.compiler, build_directory)
        api = Compact25519(library)
        try:
            print_test_summaries(
                x25519_vectors,
                ed25519_vectors,
                wycheproof_x25519,
                wycheproof_ed25519,
            )
            failures = run_x25519(api, x25519_vectors)
            failures += run_ed25519(api, ed25519_vectors)
            failures += run_wycheproof_x25519(api, wycheproof_x25519)
            failures += run_wycheproof_ed25519(api, wycheproof_ed25519)
            return failures
        finally:
            api.close()
            del api
    except (OSError, RuntimeError, ValueError, AttributeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
