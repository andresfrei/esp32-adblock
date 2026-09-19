#!/usr/bin/env python3
"""Compile and exercise the production S3 network integration seams."""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tools" / "fixtures" / "network_control_test.cpp"


def main() -> None:
    compiler = next((shutil.which(name) for name in ("c++", "g++", "clang++") if shutil.which(name)), None)
    if not compiler:
        raise SystemExit("no C++ compiler found")
    with tempfile.TemporaryDirectory(prefix="network-control-") as directory:
        executable = Path(directory) / "network_control_test"
        subprocess.run([compiler, "-std=c++11", "-Wall", "-Wextra", "-pedantic", "-Isrc", str(FIXTURE), "-o", str(executable)], cwd=ROOT, check=True)
        subprocess.run([str(executable)], cwd=ROOT, check=True)
    print("PASS production S3 network controller, socket gating, and HTTP policy")


if __name__ == "__main__":
    main()
