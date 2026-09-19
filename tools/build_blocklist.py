#!/usr/bin/env python3
"""Build the firmware's sorted, unique five-byte FNV-1a40 blocklist blob.

Usage: build_blocklist.py [options] [out.bin] [src ...]

With no sources, the required sources are StevenBlack base and HaGeZi Light.
The optional ``--max-domains`` selects a deterministic subset of the normalized
union; it does not claim to represent the complete feeds when truncation occurs.
The output is replaced only after every source is fetched and validated.

The firmware format is exactly HASH_BYTES-byte little-endian FNV-1a40 values,
sorted numerically and deduplicated. HASH_BYTES and the constants must match
``src/main.cpp``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
import tempfile
from datetime import datetime, timezone
import urllib.request
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

HASH_BYTES = 5                          # 40-bit hashes -- must match firmware
MASK = (1 << (HASH_BYTES * 8)) - 1
FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME = 0x100000001b3
U64 = (1 << 64) - 1

DEFAULT_SOURCES = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt",
]
HOSTS_PREFIXES = {"0.0.0.0", "127.0.0.1", "::1", "::"}
HAgeZI_WILDCARD_URL = DEFAULT_SOURCES[1]


class BuildError(Exception):
    """An expected input or source failure that must not modify the output."""


def fnv(b: bytes) -> int:
    h = FNV_OFFSET
    for c in b:
        h = ((h ^ c) * FNV_PRIME) & U64
    return h & MASK


def _trim_firmware_space(value: str) -> str:
    return value.strip(" \t\r\n\f\v")


def norm(d: str) -> str:
    """Match domain_rules::normalize's ASCII lowercase/trim rules."""
    d = _trim_firmware_space(d)
    d = "".join(chr(ord(value) + (ord("a") - ord("A"))) if "A" <= value <= "Z" else value for value in d)
    if d.startswith("www."):
        d = d[4:]
    if d.endswith("."):
        d = d[:-1]
    return d


def _valid_domain(d: str) -> bool:
    """Mirror src/domain_rules.h without adding host-side normalization."""
    if not d or len(d) > 253 or "." not in d:
        return False
    if any(ord(ch) < 33 or ord(ch) > 126 for ch in d):
        return False
    has_dot = False
    possible_ipv4 = True
    label_count = 0
    labels = d.split(".")
    for label in labels:
        if not label or len(label) > 63 or label[0] == "-" or label[-1] == "-":
            return False
        label_count += 1
        label_numeric = True
        numeric_value = 0
        for value in label:
            if not ("a" <= value <= "z" or "A" <= value <= "Z" or "0" <= value <= "9" or value == "-"):
                return False
            if value == "-" or value.isalpha():
                label_numeric = False
                possible_ipv4 = False
            elif numeric_value <= 255:
                numeric_value = numeric_value * 10 + (ord(value) - ord("0"))
        if label_count > 4 or not label_numeric or numeric_value > 255:
            possible_ipv4 = False
        if label_count < len(labels):
            has_dot = True
    return has_dot and not (possible_ipv4 and label_count == 4)


def _candidate_status(line: str) -> Tuple[Optional[str], str]:
    """Extract only supported hosts/plain/simple-ABP records.

    Full ABP filters, regexes, exceptions, and URL/path rules are intentionally
    skipped rather than being presented as compatible with the firmware hash
    lookup format.
    """
    if line.startswith("@@"):
        return None, "unsupported_exception"
    if line.startswith("/"):
        return None, "unsupported_regex"
    if line.startswith("||"):
        body = line[2:]
        if "/" in body or "\\" in body:
            return None, "unsupported_syntax"
        candidate = _trim_firmware_space(body.split("^", 1)[0].split("$", 1)[0])
        return (candidate, "candidate") if candidate else (None, "unsupported_syntax")

    parts = line.split()
    if len(parts) >= 2 and parts[0] in HOSTS_PREFIXES:
        return parts[1], "candidate"
    if len(parts) == 1:
        return parts[0], "candidate"
    return None, "unsupported_syntax"


def _candidate_from_line(line: str) -> Optional[str]:
    """Extract a domain from a hosts, plain-domain, or simple adblock line."""
    return _candidate_status(line)[0]


def _parse_domain_records(data: bytes) -> Tuple[Set[str], Dict[str, int]]:
    lines = data.decode("utf-8", "ignore").splitlines()
    domains: Set[str] = set()
    counts = {
        "raw_line_count": len(lines),
        "candidate_record_count": 0,
        "accepted_record_count": 0,
        "rejected_record_count": 0,
        "skipped_record_count": 0,
        "comment_or_blank_count": 0,
        "unsupported_record_count": 0,
        "unsupported_exception_count": 0,
        "unsupported_regex_count": 0,
        "unsupported_syntax_count": 0,
    }
    for raw_line in lines:
        line = _trim_firmware_space(raw_line.lstrip("\ufeff").split("#", 1)[0])
        if not line or line[0] in "![]":
            counts["skipped_record_count"] += 1
            counts["comment_or_blank_count"] += 1
            continue
        candidate, status = _candidate_status(line)
        if candidate is None:
            counts["skipped_record_count"] += 1
            counts["unsupported_record_count"] += 1
            counts[f"{status}_count"] += 1
            continue
        counts["candidate_record_count"] += 1
        candidate = norm(candidate)
        if not _valid_domain(candidate):
            counts["rejected_record_count"] += 1
            continue
        counts["accepted_record_count"] += 1
        domains.add(candidate)
    counts["normalized_domain_count"] = len(domains)
    return domains, counts


def parse_domains(data: bytes) -> Tuple[Set[str], int]:
    """Return normalized unique domains and accepted (not unique) record count."""
    domains, counts = _parse_domain_records(data)
    return domains, counts["accepted_record_count"]


def _looks_like_html(data: bytes) -> bool:
    """Detect clear HTML while ignoring commented hosts-file examples."""
    text = data.decode("utf-8", "ignore")
    visible_lines = []
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("!"):
            continue
        visible_lines.append(stripped)
        if len("\n".join(visible_lines)) >= 8192:
            break
    sample = "\n".join(visible_lines)[:8192]
    return bool(re.search(r"(?is)<!doctype\s+html|<html(?:\s|>)|<(?:head|body|title|script|meta)\b", sample))


def _validate_source_payload(data: bytes, content_type: Optional[str], source: str) -> bytes:
    normalized_type = (content_type or "").split(";", 1)[0].strip().lower()
    if normalized_type in {"text/html", "application/xhtml+xml"}:
        raise BuildError(f"required source returned HTML content: {source}")
    if _looks_like_html(data):
        raise BuildError(f"required source returned HTML/error markup: {source}")
    return data


def read_source(src: str) -> bytes:
    """Read a local fixture or HTTPS/URL source with normal certificate checks."""
    if os.path.exists(src):
        with open(src, "rb") as handle:
            return _validate_source_payload(handle.read(), None, src)
    print(f"  downloading {src} ...", file=sys.stderr)
    # urllib's default HTTPS context performs certificate verification. Do not
    # use set_insecure, an unverified context, or a retry that hides a failure.
    try:
        with urllib.request.urlopen(src, timeout=180) as response:
            status = getattr(response, "status", None)
            if status is not None and not 200 <= status < 300:
                raise BuildError(f"required source returned HTTP {status}: {src}")
            headers = getattr(response, "headers", None)
            content_type = headers.get("Content-Type") if headers is not None else None
            return _validate_source_payload(response.read(), content_type, src)
    except BuildError:
        raise


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _source_format(source: str) -> str:
    if source.endswith("/hosts"):
        return "hosts"
    if source == HAgeZI_WILDCARD_URL:
        return "WildcardDomains (plain domains without subdomains)"
    return "plain domains or simple ABP records"


def _select_domains(domains: Set[str], max_domains: Optional[int], required: Set[str]) -> Tuple[Set[str], bool]:
    if max_domains is None or len(domains) <= max_domains:
        return set(domains), False
    if len(required) > max_domains:
        raise BuildError("--max-domains is smaller than the required-domain set")
    selected = set(required)
    for domain in sorted(domains):
        if domain not in selected:
            selected.add(domain)
        if len(selected) == max_domains:
            break
    return selected, True


def generate(
    sources: Sequence[str],
    max_domains: Optional[int] = None,
    required_domains: Iterable[str] = (),
) -> Dict[str, object]:
    """Fetch and generate a blob/report-ready result without writing files."""
    if max_domains is not None and max_domains <= 0:
        raise BuildError("--max-domains must be a positive integer")

    required = {norm(domain) for domain in required_domains}
    if any(not _valid_domain(domain) for domain in required):
        raise BuildError("--require-domain must be a valid domain name")

    source_reports: List[Dict[str, object]] = []
    union: Set[str] = set()
    for source in sources:
        try:
            data = read_source(source)
        except Exception as exc:
            raise BuildError(f"required source failed: {source}: {exc}") from exc
        source_domains, counts = _parse_domain_records(data)
        if counts["accepted_record_count"] == 0:
            raise BuildError(f"required source produced zero valid domains: {source}")
        source_reports.append(
            {
                "source": source,
                "url": source,
                "format": _source_format(source),
                "retrieved_at": _timestamp(),
                "content_sha256": hashlib.sha256(data).hexdigest(),
                **counts,
                "valid_source": True,
            }
        )
        union.update(source_domains)

    if not union:
        raise BuildError("all required sources produced zero valid domains")
    missing = sorted(required - union)
    if missing:
        raise BuildError("required domain absent from source union: " + ", ".join(missing))

    selected, truncated = _select_domains(union, max_domains, required)
    hashes = sorted({fnv(domain.encode("ascii")) for domain in selected})
    blob = b"".join(value.to_bytes(HASH_BYTES, "little") for value in hashes)
    collision_count = len(selected) - len(hashes)
    required_presence = {domain: domain in union for domain in sorted(required)}
    required_selection = {domain: domain in selected for domain in sorted(required)}

    report: Dict[str, object] = {
        "generated_at": _timestamp(),
        "provenance": {
            "official_metadata": {
                "readme_url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/README.md",
                "wildcard_url": HAgeZI_WILDCARD_URL,
                "title": "HaGeZi MultiLIGHT basic protection",
                "modified": "18Sep2026 08:36UTC",
                "version": "2026.0918.0836.15",
                "syntax": "Domains without subdomains",
                "official_entry_count": 39661,
                "note": "Official README/header metadata; not a recount of this download.",
            },
            "download_evidence": "Source counts, timestamps, digests, and output identity below are from this local generation.",
        },
        "sources": source_reports,
        "validation": {
            "all_sources_have_valid_domains": True,
            "required_domains_present_in_union": required_presence,
            "required_domains_selected": required_selection,
        },
        "union": {
            "normalized_domain_count": len(union),
            "accepted_record_count": sum(item["accepted_record_count"] for item in source_reports),
            "selected_domain_count": len(selected),
            "truncated": truncated,
        },
        "selection": {
            "max_domains": max_domains,
            "required_domains": sorted(required),
            "algorithm": "required domains first, then lexicographically sorted normalized domains",
            "note": "The cap is a maximum only. When truncated, this deterministic subset is not the complete current feed union; the list is never padded.",
        },
        "output": {
            "hash_bytes": HASH_BYTES,
            "hash_bits": HASH_BYTES * 8,
            "unique_hash_count": len(hashes),
            "size_bytes": len(blob),
            "sha256": hashlib.sha256(blob).hexdigest(),
            "domain_collision_count": collision_count,
        },
    }
    return {"blob": blob, "report": report, "domains": selected, "hashes": hashes}


def _resolved(path: str) -> Path:
    return Path(path).expanduser().resolve()


def _validate_output_paths(output: str, report_path: Optional[str]) -> None:
    if report_path and _resolved(output) == _resolved(report_path):
        raise BuildError("output and report paths must be different files")


def _atomic_write(path: str, content: bytes) -> None:
    target = Path(path)
    parent = target.parent if str(target.parent) else Path(".")
    parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=str(parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _write_result(result: Dict[str, object], output: str, report_path: Optional[str]) -> None:
    _validate_output_paths(output, report_path)
    blob = result["blob"]
    assert isinstance(blob, bytes)
    # Prepare the optional report before replacing the blob so a report error
    # cannot leave a new blob paired with an old report.
    if report_path:
        report_bytes = (json.dumps(result["report"], indent=2, sort_keys=True) + "\n").encode("utf-8")
        _atomic_write(report_path, report_bytes)
    _atomic_write(output, blob)


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", nargs="?", default="blocklist.bin", help="output blob (default: blocklist.bin)")
    parser.add_argument("sources", nargs="*", help="local files or URLs; defaults to StevenBlack base and HaGeZi Light")
    parser.add_argument("--max-domains", type=_positive_int, help="deterministically select at most this many normalized domains")
    parser.add_argument("--require-domain", action="append", default=[], help="require this normalized domain in the selected list")
    parser.add_argument("--report", help="write a compact JSON source/output report")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    sources = args.sources or DEFAULT_SOURCES
    try:
        _validate_output_paths(args.output, args.report)
        result = generate(sources, args.max_domains, args.require_domain)
        _write_result(result, args.output, args.report)
    except (BuildError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = result["report"]
    assert isinstance(report, dict)
    union = report["union"]
    output = report["output"]
    assert isinstance(union, dict) and isinstance(output, dict)
    selected = union["selected_domain_count"]
    print(f"source domains   : {union['normalized_domain_count']:,} total; {selected:,} selected")
    if union["truncated"]:
        print("selection        : deterministic subset; not the complete current feed union")
    print(f"hash entries     : {output['unique_hash_count']:,} ({HASH_BYTES}-byte / {HASH_BYTES * 8}-bit)")
    print(f"domain collisions: {output['domain_collision_count']} (domains sharing a hash)")
    print(f"flash blob       : {output['size_bytes']:,} bytes ({output['size_bytes'] / 1024 / 1024:.2f} MB) -> {args.output}")
    print(f"blob sha256       : {output['sha256']}")
    print(f"lookup           : ~{math.ceil(math.log2(max(output['unique_hash_count'], 2)))} reads/query")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
