"""Download and format the current Wycheproof X25519 and Ed25519 vectors."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.request import urlopen


BASE_URL = "https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1"
FILES = {
    "x25519": ("x25519_test.json", "Wycheproof_X25519_KAT.txt"),
    "ed25519": ("ed25519_test.json", "Wycheproof_Ed25519_KAT.txt"),
}


def download(name: str) -> dict:
    filename, _ = FILES[name]
    with urlopen(f"{BASE_URL}/{filename}") as response:
        return json.load(response)


def format_x25519(data: dict) -> str:
    lines = ["# tcId result private public shared flags comment"]
    for group in data["testGroups"]:
        for test in group["tests"]:
            lines.append(
                "\t".join(
                    [
                        str(test["tcId"]),
                        test["result"],
                        test["private"],
                        test["public"],
                        test["shared"],
                        ",".join(test.get("flags", [])),
                        test.get("comment", ""),
                    ]
                )
            )
    return "\n".join(lines) + "\n"


def format_ed25519(data: dict) -> str:
    lines = ["# tcId result public message signature flags comment"]
    for group in data["testGroups"]:
        public_key = group["publicKey"]["pk"]
        for test in group["tests"]:
            lines.append(
                "\t".join(
                    [
                        str(test["tcId"]),
                        test["result"],
                        public_key,
                        test["msg"],
                        test["sig"],
                        ",".join(test.get("flags", [])),
                        test.get("comment", ""),
                    ]
                )
            )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="directory for formatted KAT files",
    )
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    for name, (_, output_name) in FILES.items():
        data = download(name)
        formatter = format_x25519 if name == "x25519" else format_ed25519
        (args.output_dir / output_name).write_text(
            formatter(data), encoding="ascii", newline="\n"
        )
        print(f"{output_name}: {data['numberOfTests']} vectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
