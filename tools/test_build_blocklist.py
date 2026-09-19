#!/usr/bin/env python3
"""Host tests for the production blocklist generator."""

from pathlib import Path
import hashlib
import importlib.util
import json
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("build_blocklist", ROOT / "tools" / "build_blocklist.py")
assert SPEC and SPEC.loader
build_blocklist = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build_blocklist)


class FakeResponse:
    def __init__(self, payload, content_type="text/plain", status=200):
        self.payload = payload
        self.headers = {"Content-Type": content_type}
        self.status = status

    def read(self):
        return self.payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class BuildBlocklistTests(unittest.TestCase):
    def test_mixed_hosts_plain_and_simple_adblock_parsing(self):
        data = b"""
# comment
! adblock comment
0.0.0.0 ads.example.com
127.0.0.1 WWW.Example.com.
::1 localhost
::1 192.0.2.1
0.0.0.0 localhost.localdomain
||tracker.example.net^$third-party
plain.example.org
plain.example.org
https://not-a-domain.example/
@@||exception.example^
/regex.example/
"""
        domains, accepted_count = build_blocklist.parse_domains(data)
        self.assertEqual(
            domains,
            {"ads.example.com", "example.com", "tracker.example.net", "plain.example.org", "localhost.localdomain"},
        )
        self.assertEqual(accepted_count, 6)
        _, counts = build_blocklist._parse_domain_records(data)
        self.assertEqual(counts["raw_line_count"], 14)
        self.assertEqual(counts["candidate_record_count"], 9)
        self.assertEqual(counts["accepted_record_count"], 6)
        self.assertEqual(counts["rejected_record_count"], 3)
        self.assertEqual(counts["unsupported_record_count"], 2)
        self.assertEqual(counts["unsupported_exception_count"], 1)
        self.assertEqual(counts["unsupported_regex_count"], 1)

    def test_normalization_matches_production_domain_rules_vectors(self):
        valid = {
            " WWW.Example.COM. ": "example.com",
            "www.foo.example.com": "foo.example.com",
            "a-1.example.com": "a-1.example.com",
            "1.2.3.999.example": "1.2.3.999.example",
        }
        for raw, expected in valid.items():
            normalized = build_blocklist.norm(raw)
            self.assertEqual(normalized, expected)
            self.assertTrue(build_blocklist._valid_domain(normalized), raw)

        invalid = [
            "192.0.2.1",
            "-edge.example.com",
            "edge-.example.com",
            "bad_char.example.com",
            "noné.example.com",
            "\u00a0example.com",
            "K.example.com",
            "one..two.example",
            "singlelabel",
            "a" * 64 + ".example",
            "a" * 249 + ".com",
        ]
        for value in invalid:
            self.assertFalse(build_blocklist._valid_domain(build_blocklist.norm(value)), value)

    def test_known_fnv40_vectors_and_little_endian_blob(self):
        self.assertEqual(build_blocklist.fnv(b""), 0xE484222325)
        self.assertEqual(build_blocklist.fnv(b"example.com"), 0x634E2714C6)
        self.assertEqual(build_blocklist.fnv(b"doubleclick.net"), 0xCD127775CD)

        source = b"doubleclick.net\nexample.com\n"
        with mock.patch.object(build_blocklist, "read_source", return_value=source):
            result = build_blocklist.generate(["fixture"])
        blob = result["blob"]
        hashes = result["hashes"]
        self.assertEqual(blob, b"".join(value.to_bytes(5, "little") for value in hashes))
        self.assertEqual(hashes, sorted(hashes))
        self.assertEqual(len(blob) % build_blocklist.HASH_BYTES, 0)
        self.assertEqual(result["report"]["output"]["sha256"], hashlib.sha256(blob).hexdigest())

    def test_deterministic_cap_required_member_and_full_union_report(self):
        source = b"""z.example
alpha.example
gamma.example
doubleclick.net
github.com
"""
        with mock.patch.object(build_blocklist, "read_source", return_value=source):
            first = build_blocklist.generate(
                ["fixture"], max_domains=3, required_domains=["doubleclick.net"]
            )
            second = build_blocklist.generate(
                ["fixture"], max_domains=3, required_domains=["doubleclick.net"]
            )
        self.assertEqual(first["blob"], second["blob"])
        self.assertEqual(first["domains"], {"doubleclick.net", "alpha.example", "gamma.example"})
        self.assertTrue(first["report"]["union"]["truncated"])
        self.assertEqual(first["report"]["union"]["normalized_domain_count"], 5)
        self.assertEqual(first["report"]["union"]["selected_domain_count"], 3)
        required_hash = build_blocklist.fnv(b"doubleclick.net")
        self.assertIn(required_hash, first["hashes"])
        self.assertEqual(first["report"]["selection"]["required_domains"], ["doubleclick.net"])
        self.assertTrue(first["report"]["validation"]["required_domains_selected"]["doubleclick.net"])

    def test_each_source_must_have_a_valid_record_and_report_counters(self):
        sources = {
            "one": b"0.0.0.0 a.example\na.example\n# comment\n",
            "two": b"b.example\n",
        }
        with mock.patch.object(build_blocklist, "read_source", side_effect=sources.__getitem__):
            result = build_blocklist.generate(["one", "two"])
        self.assertFalse(result["report"]["union"]["truncated"])
        self.assertEqual(result["report"]["union"]["normalized_domain_count"], 2)
        source = result["report"]["sources"][0]
        self.assertEqual(source["raw_line_count"], 3)
        self.assertEqual(source["candidate_record_count"], 2)
        self.assertEqual(source["accepted_record_count"], 2)
        self.assertEqual(source["normalized_domain_count"], 1)
        self.assertEqual(source["rejected_record_count"], 0)
        self.assertEqual(source["skipped_record_count"], 1)
        self.assertTrue(result["report"]["validation"]["all_sources_have_valid_domains"])

    def test_bad_cap_and_missing_required_domain_fail(self):
        with mock.patch.object(build_blocklist, "read_source", return_value=b"a.example\n"):
            with self.assertRaises(build_blocklist.BuildError):
                build_blocklist.generate(["fixture"], max_domains=0)
            with self.assertRaisesRegex(build_blocklist.BuildError, "absent"):
                build_blocklist.generate(["fixture"], required_domains=["doubleclick.net"])

    def test_empty_source_alongside_good_source_preserves_blob_and_report(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "blocklist.bin"
            report = Path(directory) / "report.json"
            output.write_bytes(b"old-live-list")
            report.write_bytes(b'{"old": true}\n')
            with mock.patch.object(
                build_blocklist,
                "read_source",
                side_effect=[b"a.example\n", b"# no domains\n127.0.0.1 localhost\n"],
            ):
                self.assertEqual(build_blocklist.main([str(output), "one", "two", "--report", str(report)]), 2)
            self.assertEqual(output.read_bytes(), b"old-live-list")
            self.assertEqual(report.read_bytes(), b'{"old": true}\n')

    def test_http_200_html_source_alongside_good_source_preserves_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "blocklist.bin"
            report = Path(directory) / "report.json"
            output.write_bytes(b"old-live-list")
            report.write_bytes(b'{"old": true}\n')
            with mock.patch.object(
                build_blocklist,
                "read_source",
                side_effect=[b"a.example\n", b"<!doctype html><html><body>Not found</body></html>"],
            ):
                self.assertEqual(build_blocklist.main([str(output), "one", "two", "--report", str(report)]), 2)
            self.assertEqual(output.read_bytes(), b"old-live-list")
            self.assertEqual(report.read_bytes(), b'{"old": true}\n')

    def test_http_200_content_type_html_is_rejected(self):
        response = FakeResponse(b"an.example\n", content_type="text/html; charset=utf-8")
        with mock.patch.object(build_blocklist.urllib.request, "urlopen", return_value=response):
            with self.assertRaisesRegex(build_blocklist.BuildError, "HTML"):
                build_blocklist.read_source("https://fixture.invalid/list")

    def test_source_failure_exits_and_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "blocklist.bin"
            output.write_bytes(b"old-live-list")
            with mock.patch.object(
                build_blocklist,
                "read_source",
                side_effect=[b"a.example\n", OSError("network unavailable")],
            ):
                self.assertEqual(build_blocklist.main([str(output), "one", "two"]), 2)
            self.assertEqual(output.read_bytes(), b"old-live-list")

    def test_output_and_report_same_resolved_path_are_rejected_before_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "same"
            path.write_bytes(b"old")
            with mock.patch.object(build_blocklist, "read_source") as read_source:
                self.assertEqual(build_blocklist.main([str(path), "fixture", "--report", str(path)]), 2)
            read_source.assert_not_called()
            self.assertEqual(path.read_bytes(), b"old")

    def test_empty_sources_fail_without_creating_empty_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "blocklist.bin"
            with mock.patch.object(build_blocklist, "read_source", return_value=b"# no domains\n127.0.0.1 localhost\n"):
                self.assertEqual(build_blocklist.main([str(output), "empty"]), 2)
            self.assertFalse(output.exists())

    def test_report_is_compact_json_with_source_hash_and_timestamp(self):
        with mock.patch.object(build_blocklist, "read_source", return_value=b"a.example\n"):
            result = build_blocklist.generate(["https://fixture.invalid/list"])
        report = json.loads(json.dumps(result["report"]))
        source = report["sources"][0]
        self.assertEqual(source["content_sha256"], hashlib.sha256(b"a.example\n").hexdigest())
        self.assertTrue(source["retrieved_at"].endswith("Z"))
        self.assertEqual(report["output"]["size_bytes"], len(result["blob"]))
        self.assertEqual(report["provenance"]["official_metadata"]["official_entry_count"], 39661)


if __name__ == "__main__":
    unittest.main()
