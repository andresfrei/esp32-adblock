#!/usr/bin/env python3
"""Regression test for optional compile-time Wi-Fi credentials."""

from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
CREDENTIALS_HEADER = ROOT / "src" / "wifi_credentials.h"
SYNTHETIC_SECRETS = """#pragma once
static const char* WIFI_SSID = \"synthetic-public-ssid\";
static const char* WIFI_PASS = \"synthetic-public-password\";
"""
HARNESS = r'''#include <cstring>
#include "wifi_credentials.h"

int main() {
    return std::strcmp(WIFI_SSID, EXPECTED_SSID) == 0 &&
                   std::strcmp(WIFI_PASS, EXPECTED_PASS) == 0
               ? 0
               : 1;
}
'''


def compiler_path() -> str:
    for name in ("c++", "g++", "clang++"):
        path = shutil.which(name)
        if path:
            return path
    raise SystemExit("no C++ compiler found (tried c++, g++, clang++)")


def run_case(compiler: str, name: str, with_secrets: bool, expected_ssid: str, expected_pass: str) -> None:
    with tempfile.TemporaryDirectory(prefix="wifi-credentials-") as directory:
        isolated = Path(directory)
        shutil.copyfile(CREDENTIALS_HEADER, isolated / "wifi_credentials.h")
        if with_secrets:
            (isolated / "secrets.h").write_text(SYNTHETIC_SECRETS)
        source = isolated / "test.cpp"
        source.write_text(
            f'#define EXPECTED_SSID "{expected_ssid}"\n'
            f'#define EXPECTED_PASS "{expected_pass}"\n'
            + HARNESS
        )
        preprocessed = subprocess.run(
            [compiler, "-std=c++11", "-E", "-P", "-I", str(isolated), str(source)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        for expected in (expected_ssid, expected_pass):
            if expected not in preprocessed:
                raise AssertionError(f"{name}: expected fixture missing from preprocessed source: {expected}")
        executable = isolated / "test"
        subprocess.run(
            [compiler, "-std=c++11", "-I", str(isolated), str(source), "-o", str(executable)],
            check=True,
        )
        subprocess.run([str(executable)], check=True)
    print(f"PASS {name}: isolated preprocess, compile, and value assertion")


def main() -> None:
    compiler = compiler_path()
    run_case(compiler, "header absent", False, "", "")
    run_case(
        compiler,
        "documented static variables",
        True,
        "synthetic-public-ssid",
        "synthetic-public-password",
    )


if __name__ == "__main__":
    main()
