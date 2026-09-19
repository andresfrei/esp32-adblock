#!/usr/bin/env python3
"""Compile and run the production domain and allowlist helpers on the host."""

from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tools" / "fixtures" / "domain_rules_test.cpp"


def compiler_path() -> str:
    for name in ("c++", "g++", "clang++"):
        path = shutil.which(name)
        if path:
            return path
    raise SystemExit("no C++ compiler found (tried c++, g++, clang++)")


def main() -> None:
    compiler = compiler_path()
    with tempfile.TemporaryDirectory(prefix="domain-rules-") as directory:
        executable = Path(directory) / "domain_rules_test"
        subprocess.run(
            [
                compiler,
                "-std=c++11",
                "-Wall",
                "-Wextra",
                "-pedantic",
                "-Isrc",
                str(FIXTURE),
                "-o",
                str(executable),
            ],
            cwd=ROOT,
            check=True,
        )
        subprocess.run([str(executable)], cwd=ROOT, check=True)
    print("PASS production domain and allowlist helpers compiled with the host C++ compiler")


if __name__ == "__main__":
    main()
