#!/usr/bin/env python3
"""Compile and exercise the production captive-portal rendering/selection helpers."""

from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tools" / "fixtures" / "wifi_portal_test.cpp"
MAIN = ROOT / "src" / "main.cpp"


def compiler_path() -> str:
    for name in ("c++", "g++", "clang++"):
        path = shutil.which(name)
        if path:
            return path
    raise SystemExit("no C++ compiler found (tried c++, g++, clang++)")


def source_contract() -> None:
    source = MAIN.read_text()
    required = (
        'web.on("/wifisave", HTTP_POST, handleWifiSave)',
        'web.arg("s")',
        'web.arg("manual")',
        'prefs.putString("ssid", ss)',
        'prefs.putString("pass", pw)',
        'wifiPortalNetworkOptions(portalSsids, portalNetworkCount)',
        'wifiPortalSelectSSID(web.arg("mode")',
        "<select id=network-select name=s",
        "No 2.4 GHz networks were found",
    )
    for fragment in required:
        if fragment not in source:
            raise AssertionError(f"production portal contract missing: {fragment}")
    if "<datalist" in source or "jesc(WiFi.SSID" in source:
        raise AssertionError("portal must not render a datalist or JSON escaping for SSIDs")


def main() -> None:
    source_contract()
    compiler = compiler_path()
    with tempfile.TemporaryDirectory(prefix="wifi-portal-") as directory:
        executable = Path(directory) / "wifi_portal_test"
        subprocess.run(
            [compiler, "-std=c++11", "-Wall", "-Wextra", "-pedantic", "-Isrc", str(FIXTURE), "-o", str(executable)],
            cwd=ROOT,
            check=True,
        )
        subprocess.run([str(executable)], cwd=ROOT, check=True)
    print("PASS production Wi-Fi portal rendering and selection helpers")


if __name__ == "__main__":
    main()
