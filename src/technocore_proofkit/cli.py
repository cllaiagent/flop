"""Command-line interface for Technocore ProofKit."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .core import MAX_DEPTH, MAX_INPUT_BYTES, ProofError, finalize_manifest, verify_manifest


def _check_lexical_nesting(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise ProofError(f"JSON exceeds the {MAX_DEPTH}-level lexical nesting limit")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise ProofError("JSON contains an unmatched closing delimiter")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProofError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_json_number(value: str) -> Any:
    preview = value[:32] + ("..." if len(value) > 32 else "")
    raise ProofError(f"JSON number is not allowed in public evidence: {preview}")


def _read_json(path: Path) -> Any:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise ProofError(f"input must be a regular non-symlink file: {path}")
        if metadata.st_size > MAX_INPUT_BYTES:
            raise ProofError(f"input exceeds the {MAX_INPUT_BYTES}-byte limit")
        raw = path.read_bytes()
        if len(raw) > MAX_INPUT_BYTES:
            raise ProofError(f"input exceeds the {MAX_INPUT_BYTES}-byte limit")
        text = raw.decode("utf-8")
        _check_lexical_nesting(text)
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_int=_reject_json_number,
            parse_float=_reject_json_number,
            parse_constant=_reject_json_number,
        )
    except ProofError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ProofError(f"cannot read JSON from {path}: {exc}") from exc


def _write_json_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="technocore-proofkit",
        description="Verify sanitized, non-routeable Technocore evidence attestations.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    finalize = subparsers.add_parser(
        "finalize",
        help="validate an already-attested draft and fill its RFC 8785 content commitment",
    )
    finalize.add_argument("draft", type=Path)
    finalize.add_argument("--output", "-o", type=Path, required=True)

    verify = subparsers.add_parser(
        "verify", help="verify the DID attestation and minimized evidence offline"
    )
    verify.add_argument("manifest", type=Path)
    verify.add_argument("--json", action="store_true", help="print the verification result as JSON")
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(arguments)
    try:
        if args.command == "finalize":
            finalized = finalize_manifest(_read_json(args.draft))
            _write_json_atomic(args.output, finalized)
            result = verify_manifest(finalized)
            print(
                json.dumps(
                    {**result, "output": str(args.output)},
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
            return 0

        result = verify_manifest(_read_json(args.manifest))
        if args.json:
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        else:
            print("PASS")
            print(f"did: {result['did']}")
            print(f"activity seq: {', '.join(result['activity_sequences'])}")
            print(f"subject sha256: {result['subject_sha256']}")
            print(f"content sha256: {result['content_sha256']}")
            print("domain-separated DID attestation: PASS")
            print("routeable Technocore signatures: absent")
            print("known forbidden patterns: absent")
            print("absolute secret absence proven: no")
            print("server receipt claims: DID-attested, not server-signed")
        return 0
    except ProofError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
