#!/usr/bin/env python3
"""Fail CI if the public repository crosses ProofKit's disclosure boundary."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from technocore_proofkit.cli import _read_json
from technocore_proofkit.core import SCHEMA, ProofError, verify_manifest

ROOT = Path(__file__).resolve().parents[1]
IGNORED_PARTS = {".git", ".pytest_cache", ".ruff_cache", ".venv", "__pycache__", "dist"}
MAX_TRACKED_FILE_BYTES = 5 * 1024 * 1024
ALLOWED_TEXT_SUFFIXES = {
    ".json",
    ".lock",
    ".md",
    ".patch",
    ".py",
    ".svg",
    ".toml",
    ".txt",
    ".yml",
}
ALLOWED_EXTENSIONLESS_NAMES = {".gitignore", "LICENSE", "NOTICE"}
ALLOWED_TRACKED_PATHS = {
    ".github/workflows/ci.yml",
    ".gitignore",
    ".gitleaks.toml",
    "LICENSE",
    "NOTICE",
    "README.md",
    "SECURITY.md",
    "docs/DEMO.md",
    "docs/X_THREAD_EN.md",
    "docs/X_THREAD_ZH.md",
    "docs/assets/did-vs-wallet-en.svg",
    "docs/assets/did-vs-wallet-zh.svg",
    "docs/assets/technocore-flow-en.svg",
    "docs/assets/technocore-flow-zh.svg",
    "evidence/README.md",
    "evidence/did-7b12b1399005a4c0.json",
    "pyproject.toml",
    "repro/README.md",
    "repro/permalink-regression.patch",
    "repro/upstream-issue.md",
    "schemas/technocore-contributor-evidence-v3.schema.json",
    "scripts/__init__.py",
    "scripts/scan_repository.py",
    "src/technocore_proofkit/__init__.py",
    "src/technocore_proofkit/__main__.py",
    "src/technocore_proofkit/cli.py",
    "src/technocore_proofkit/core.py",
    "tests/test_core.py",
    "uv.lock",
}
ARCHIVE_OR_BINARY_MAGIC = (
    b"PK\x03\x04",
    b"\x1f\x8b",
    b"BZh",
    b"\xfd7zXZ\x00",
    b"7z\xbc\xaf\x27\x1c",
    b"%PDF-",
    b"\x7fELF",
)
ALLOWED_EVIDENCE_PATHS = {
    "evidence/README.md",
    "evidence/did-7b12b1399005a4c0.json",
}

EVM_ADDRESS_RE = re.compile(r"(?<![0-9A-Fa-f])0[xX][0-9A-Fa-f]{40}(?![0-9A-Fa-f])")
LOCAL_PATH_RE = re.compile(
    r"(?:/" + r"(?:Users|home)/[^\s'\"]+|[A-Za-z]:[\\/]" + r"Users[\\/][^\s'\"]+)",
    re.IGNORECASE,
)
STANDALONE_B64U_86_RE = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{86}(?![A-Za-z0-9_-])")
ALLOWED_ATTESTATION_LINE_RE = re.compile(
    r'^\s*"attestation_b64u"\s*:\s*"[A-Za-z0-9_-]{86}"\s*,?\s*$'
)
ROUTE_SIGNATURE_RE = re.compile(
    r"""["'](?:outbound_signature_b64u|signature_b64u|signature|sig)["']\s*:\s*"""
    r"""["'][A-Za-z0-9_-]{86}["']"""
)


def _tracked_files() -> list[Path]:
    output = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    return [ROOT / item.decode("utf-8") for item in output.split(b"\x00") if item]


def _scan_text(path: Path, text: str, failures: list[str]) -> None:
    relative = path.relative_to(ROOT).as_posix()
    if EVM_ADDRESS_RE.search(text):
        failures.append(f"{relative}: full EVM address is forbidden in the public tree")
    if LOCAL_PATH_RE.search(text):
        failures.append(f"{relative}: local user path is forbidden in the public tree")
    if ROUTE_SIGNATURE_RE.search(text):
        failures.append(f"{relative}: routeable Technocore signature literal detected")
    for match in STANDALONE_B64U_86_RE.finditer(text):
        line_start = text.rfind("\n", 0, match.start()) + 1
        line_end = text.find("\n", match.end())
        if line_end < 0:
            line_end = len(text)
        line = text[line_start:line_end]
        if (
            relative == "evidence/did-7b12b1399005a4c0.json"
            and ALLOWED_ATTESTATION_LINE_RE.fullmatch(line) is not None
        ):
            continue
        failures.append(f"{relative}: standalone 86-character base64url token detected")


def _decode_public_text(relative: Path, raw: bytes, failures: list[str]) -> str | None:
    relative_text = relative.as_posix()
    if (
        relative.name not in ALLOWED_EXTENSIONLESS_NAMES
        and relative.suffix.casefold() not in ALLOWED_TEXT_SUFFIXES
    ):
        failures.append(f"{relative_text}: tracked file type is outside the text-only policy")
        return None
    if b"\x00" in raw or any(raw.startswith(magic) for magic in ARCHIVE_OR_BINARY_MAGIC):
        failures.append(f"{relative_text}: archive or binary content is forbidden")
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        failures.append(f"{relative_text}: tracked text must be valid UTF-8")
        return None


def _scan_evidence(path: Path, failures: list[str]) -> None:
    relative = path.relative_to(ROOT).as_posix()
    try:
        document = _read_json(path)
    except ProofError as exc:
        failures.append(f"{relative}: evidence is not valid UTF-8 JSON: {exc}")
        return
    if document.get("schema") != SCHEMA:
        failures.append(f"{relative}: only the current public evidence schema is allowed")
        return
    try:
        verify_manifest(document)
    except ProofError as exc:
        failures.append(f"{relative}: evidence verification failed: {exc}")
        return
def _scan_authors(failures: list[str]) -> None:
    output = subprocess.run(
        ["git", "log", "--all", "--format=%an%x00%ae%x00%cn%x00%ce"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout
    allowed_email = "voxvex@users.noreply.github.com"
    for line_number, line in enumerate(output.splitlines(), start=1):
        fields = line.split("\x00")
        if fields != ["voxvex", allowed_email, "voxvex", allowed_email]:
            failures.append(
                f"git history entry {line_number}: author/committer must be voxvex only"
            )
    tag_output = subprocess.run(
        [
            "git",
            "for-each-ref",
            "--format=%(refname)%00%(objecttype)%00%(taggername)%00%(taggeremail)",
            "refs/tags",
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout
    expected_tagger_email = f"<{allowed_email}>"
    for line in tag_output.splitlines():
        refname, object_type, tagger_name, tagger_email = line.split("\x00")
        if object_type != "tag":
            failures.append(f"{refname}: release tag must be annotated")
        elif tagger_name != "voxvex" or tagger_email != expected_tagger_email:
            failures.append(f"{refname}: tagger must be voxvex only")


def main() -> int:
    failures: list[str] = []
    evidence_files: list[Path] = []
    for path in _tracked_files():
        relative = path.relative_to(ROOT)
        if any(part in IGNORED_PARTS for part in relative.parts):
            continue
        if relative.as_posix() not in ALLOWED_TRACKED_PATHS:
            failures.append(f"{relative.as_posix()}: path is outside the public allowlist")
            continue
        if path.is_symlink() or not path.is_file():
            failures.append(f"{relative.as_posix()}: tracked input must be a regular file")
            continue
        if path.stat().st_size > MAX_TRACKED_FILE_BYTES:
            failures.append(
                f"{relative.as_posix()}: tracked file exceeds the repository size limit"
            )
            continue
        try:
            raw = path.read_bytes()
        except OSError as exc:
            failures.append(f"{relative.as_posix()}: cannot read: {exc}")
            continue
        text = _decode_public_text(relative, raw, failures)
        if text is None:
            continue
        _scan_text(path, text, failures)
        if relative.parts and relative.parts[0] == "evidence":
            relative_text = relative.as_posix()
            if relative_text not in ALLOWED_EVIDENCE_PATHS:
                failures.append(f"{relative_text}: unexpected file in the public evidence tree")
            if relative_text != "evidence/did-7b12b1399005a4c0.json":
                continue
            evidence_files.append(path)
            _scan_evidence(path, failures)

    if len(evidence_files) != 1:
        failures.append("the public tree must contain exactly one sanitized evidence JSON file")
    _scan_authors(failures)

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    print("PUBLIC_BOUNDARY_SCAN=PASS")
    print("SANITIZED_EVIDENCE_FILES=1")
    print("ROUTEABLE_SIGNATURE_LITERALS=0")
    print("STANDALONE_B64URL_86_TOKENS=1_DOMAIN_ATTESTATION_ONLY")
    print("FULL_EVM_ADDRESSES=0")
    print("KNOWN_LOCAL_USER_PATH_PATTERNS=0")
    print("GIT_IDENTITY=voxvex")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
