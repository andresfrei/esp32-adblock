#!/usr/bin/env python3
"""Compile and run the production upstream configuration helper with a fake NVS store."""

from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tools" / "fixtures" / "upstream_config_test.cpp"


def compiler_path() -> str:
    for name in ("c++", "g++", "clang++"):
        path = shutil.which(name)
        if path:
            return path
    raise SystemExit("no C++ compiler found (tried c++, g++, clang++)")


def main() -> None:
    compiler = compiler_path()
    with tempfile.TemporaryDirectory(prefix="upstream-config-") as directory:
        executable = Path(directory) / "upstream_config_test"
        subprocess.run(
            [compiler, "-std=c++11", "-Wall", "-Wextra", "-pedantic", "-Isrc", str(FIXTURE), "-o", str(executable)],
            cwd=ROOT,
            check=True,
        )
        subprocess.run([str(executable)], cwd=ROOT, check=True)
    print("PASS production upstream helper compiled with the host C++ compiler")


if __name__ == "__main__":
    main()
