from __future__ import annotations

import base64
import hashlib
import io
import json
import subprocess
import zipfile
from pathlib import Path
from urllib.parse import quote

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

import scripts.scan_repository as repository_scanner
from technocore_proofkit.cli import _read_json, main
from technocore_proofkit.core import (
    ATTESTATION_CLAIM,
    ATTESTATION_DOMAIN,
    ATTESTATION_TYPE,
    B58,
    CANONICALIZATION,
    CONTENT_SCOPE,
    MAX_DEPTH,
    MAX_INPUT_BYTES,
    MAX_STRING_UTF8_BYTES,
    MULTICODEC_ED25519,
    NAME_RE,
    SCHEMA,
    SERVER_OBSERVATION,
    ProofError,
    attestation_preimage,
    canonical_json,
    canonical_message,
    did_fingerprint,
    finalize_manifest,
    normalized_server_record,
    public_key_from_did,
    sha256_hex,
    subject_sha256,
    validate_resource_limits,
    verify_manifest,
)

SYNTHETIC_EVM_ADDRESS = "0x" + ("ab" * 20)
SYNTHETIC_LOCAL_PATH = "/" + "Users/example/key.json"
SYNTHETIC_HOME_PATH = "/" + "home/example/key.json"
SYNTHETIC_WINDOWS_PATH = "C:/" + "Users/example/key.json"
SYNTHETIC_CREDENTIAL_URL = "https://" + "user:password@example.com/repo"
SYNTHETIC_USER_URL = "https://" + "user@example.com/repo"


def _published_schema() -> dict:
    schema_path = (
        Path(__file__).parents[1] / "schemas" / "technocore-contributor-evidence-v3.schema.json"
    )
    return json.loads(schema_path.read_text(encoding="utf-8"))


def _b58encode(value: bytes) -> str:
    number = int.from_bytes(value, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = B58[remainder] + encoded
    leading_zeroes = len(value) - len(value.lstrip(b"\x00"))
    return ("1" * leading_zeroes) + encoded


def _b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _activity(key: Ed25519PrivateKey, did: str, seq: str = "42") -> dict:
    room = "lobby"
    nonce = "1700000000001"
    text = "ProofKit deterministic public test vector"
    canonical = canonical_message(room, nonce, text)
    timestamp = "2026-08-25T06:47:13.630150Z"
    record = normalized_server_record(
        room=room,
        seq_decimal=seq,
        timestamp=timestamp,
        did=did,
        nonce_decimal=nonce,
        text=text,
    )
    return {
        "kind": "INITIAL_DID_PROOF",
        "room": room,
        "signed_nonce_decimal": nonce,
        "exact_message": text,
        "canonical_message_sha256": sha256_hex(canonical.encode("utf-8")),
        "protocol_signature_sha256": sha256_hex(key.sign(canonical.encode("utf-8"))),
        "server_observed": {
            "seq_decimal": seq,
            "observed_nonce_decimal": str(int(nonce)),
            "timestamp": timestamp,
            "normalized_record_sha256": sha256_hex(canonical_json(record)),
            "write_response_sha256": hashlib.sha256(b"write response").hexdigest(),
            "readback_response_sha256": hashlib.sha256(b"read response").hexdigest(),
            "public_permalink": f"https://technocore.chat/humans#r/{room}/{seq}",
            "verification": SERVER_OBSERVATION,
        },
    }


def draft_manifest() -> tuple[dict, Ed25519PrivateKey]:
    # Deterministic fixture only; it is not used by a real identity.
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public_key = key.public_key().public_bytes_raw()
    did = "did:key:z" + _b58encode(MULTICODEC_ED25519 + public_key)
    manifest = {
        "schema": SCHEMA,
        "subject": {
            "generated_at": "2026-08-25T07:00:00Z",
            "identity": {
                "did": did,
                "did_fingerprint": did_fingerprint(did),
                "key_type": "Ed25519",
            },
            "activities": [_activity(key, did)],
            "contribution": {
                "status": "IN_PROGRESS",
                "title": "Technocore ProofKit",
                "summary": "Sanitized evidence attestations for Technocore messages.",
                "github_repository": "https://github.com/cllaiagent/flop",
                "commit_sha": None,
                "release_tag": None,
                "issue_url": None,
                "pull_request_url": None,
                "x_thread_zh_url": None,
                "x_thread_en_url": None,
                "demo_url": None,
            },
        },
        "proof": {
            "type": ATTESTATION_TYPE,
            "domain": ATTESTATION_DOMAIN,
            "subject_sha256": "0" * 64,
            "attestation_b64u": "A" * 86,
            "claim": ATTESTATION_CLAIM,
        },
        "integrity": {
            "canonicalization": CANONICALIZATION,
            "hash_algorithm": "SHA-256",
            "content_scope": CONTENT_SCOPE,
            "content_sha256": None,
            "known_forbidden_patterns_present": False,
            "routeable_technocore_signatures_present": False,
        },
    }
    digest = subject_sha256(manifest)
    manifest["proof"]["subject_sha256"] = digest
    manifest["proof"]["attestation_b64u"] = _b64u(key.sign(attestation_preimage(digest)))
    return manifest, key


def _resign(manifest: dict, key: Ed25519PrivateKey) -> None:
    digest = subject_sha256(manifest)
    manifest["proof"]["subject_sha256"] = digest
    manifest["proof"]["attestation_b64u"] = _b64u(key.sign(attestation_preimage(digest)))
    manifest["integrity"]["content_sha256"] = None


def test_finalize_and_verify_round_trip():
    draft, _ = draft_manifest()
    finalized = finalize_manifest(draft)
    result = verify_manifest(finalized)
    assert result["status"] == "PASS"
    assert result["activity_sequences"] == ["42"]
    assert result["domain_separated_attestation"] == "PASS"
    assert result["routeable_technocore_signatures_present"] is False
    assert result["known_forbidden_patterns_present"] is False
    assert result["secret_absence_proven"] is False
    assert result["server_claims_independently_authenticated"] is False
    assert finalized["integrity"]["content_sha256"] == result["content_sha256"]


def test_domain_attestation_is_not_a_routeable_room_signature():
    draft, _ = draft_manifest()
    finalized = finalize_manifest(draft)
    did = finalized["subject"]["identity"]["did"]
    signature = base64.urlsafe_b64decode(finalized["proof"]["attestation_b64u"] + "==")
    activity = finalized["subject"]["activities"][0]
    routeable = canonical_message(
        activity["room"], activity["signed_nonce_decimal"], activity["exact_message"]
    ).encode("utf-8")
    with pytest.raises(InvalidSignature):
        Ed25519PublicKey.from_public_bytes(public_key_from_did(did)).verify(signature, routeable)

    kv_routeable = b"owners|proof|1700000000001|did:key:example"
    with pytest.raises(InvalidSignature):
        Ed25519PublicKey.from_public_bytes(public_key_from_did(did)).verify(signature, kv_routeable)


def test_domain_preimage_cannot_parse_as_room_or_kv_canonical_grammar():
    preimage = attestation_preimage("0" * 64)
    first_delimited_field = preimage.split(b"|", 1)[0]
    assert b"\x00" in first_delimited_field
    assert NAME_RE.fullmatch(first_delimited_field.decode("ascii")) is None


def test_domain_attestation_fixed_known_answer_vector():
    draft, _ = draft_manifest()
    digest = subject_sha256(draft)
    assert digest == "ff2c619bc815be73620aefde7612e5a791c130773755b95e1fa8035395c8c089"
    assert attestation_preimage(digest).hex() == (
        "75726e3a746563686e6f636f72652d70726f6f666b69743a65766964656e63653a763300"
        "ff2c619bc815be73620aefde7612e5a791c130773755b95e1fa8035395c8c089"
    )
    expected_attestation = "".join(
        (
            "0QcOmWqpdovMD2WG_ldrTX",
            "nCm2FK7o9RZ38k0ROS2K6K",
            "vy0rcD1hddI-pc_df2HsX8",
            "OApArMULZv7uOeEpJ3DA",
        )
    )
    assert draft["proof"]["attestation_b64u"] == expected_attestation


def test_subject_tampering_invalidates_attestation():
    draft, _ = draft_manifest()
    finalized = finalize_manifest(draft)
    finalized["subject"]["contribution"]["summary"] = "changed after signing"
    with pytest.raises(ProofError, match="subject_sha256"):
        verify_manifest(finalized)


def test_content_hash_detects_proof_tampering():
    draft, _ = draft_manifest()
    finalized = finalize_manifest(draft)
    finalized["integrity"]["content_sha256"] = "0" * 64
    with pytest.raises(ProofError, match="content_sha256 does not match"):
        verify_manifest(finalized)


@pytest.mark.parametrize(
    "field",
    [
        "unexpected_metadata",
        "unsupported_identity_link",
    ],
)
def test_unknown_identity_fields_are_rejected(field):
    draft, _ = draft_manifest()
    draft["subject"]["identity"][field] = "unexpected"
    with pytest.raises(ProofError, match="fields are invalid"):
        finalize_manifest(draft)


def test_routeable_protocol_signature_field_is_rejected():
    draft, _ = draft_manifest()
    draft["subject"]["activities"][0]["unexpected_signature_material"] = _b64u(
        bytes(range(64))
    )
    with pytest.raises(ProofError, match="secret-or-signature-shaped token|fields are invalid"):
        finalize_manifest(draft)


def test_generic_signature_field_is_rejected():
    draft, _ = draft_manifest()
    draft["subject"]["activities"][0]["unexpected_signature"] = _b64u(bytes(range(64)))
    with pytest.raises(ProofError, match="secret-or-signature-shaped token|fields are invalid"):
        finalize_manifest(draft)


@pytest.mark.parametrize(
    "value",
    [
        _b64u(bytes(range(32))),
        _b64u(bytes(32)),
        _b64u(bytes(range(48))),
        base64.b64encode(bytes(range(32))).decode("ascii"),
        bytes(range(32)).hex(),
    ],
)
def test_secret_shaped_free_text_is_rejected(value):
    draft, _ = draft_manifest()
    draft["subject"]["contribution"]["summary"] = value
    with pytest.raises(ProofError, match="secret-or-signature-shaped token"):
        finalize_manifest(draft)


def test_valid_domain_attestation_signature_is_only_allowed_at_proof_path():
    draft, _ = draft_manifest()
    signature = draft["proof"]["attestation_b64u"]
    draft["subject"]["contribution"]["summary"] = signature
    with pytest.raises(ProofError, match="secret-or-signature-shaped token"):
        finalize_manifest(draft)


@pytest.mark.parametrize(
    "url",
    [
        SYNTHETIC_CREDENTIAL_URL,
        SYNTHETIC_USER_URL,
        "https://user%40example.com/repo",
        "https://example.com/repo?token=value",
        "https://example.com/repo?signature=value",
    ],
)
def test_credential_bearing_or_sensitive_urls_are_rejected(url):
    draft, _ = draft_manifest()
    draft["subject"]["contribution"]["github_repository"] = url
    with pytest.raises(ProofError, match="unsafe URL|userinfo|sensitive query"):
        finalize_manifest(draft)


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (SYNTHETIC_EVM_ADDRESS, "full EVM address"),
        (SYNTHETIC_LOCAL_PATH, "local user path"),
        (SYNTHETIC_HOME_PATH, "local user path"),
        (SYNTHETIC_WINDOWS_PATH, "local user path"),
        ("See " + SYNTHETIC_CREDENTIAL_URL, "unsafe URL"),
    ],
)
def test_sensitive_decoded_text_is_rejected_everywhere(value, message):
    draft, _ = draft_manifest()
    draft["subject"]["contribution"]["summary"] = value
    with pytest.raises(ProofError, match=message):
        finalize_manifest(draft)


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (quote(SYNTHETIC_EVM_ADDRESS, safe=""), "full EVM address"),
        (quote(SYNTHETIC_LOCAL_PATH, safe=""), "local user path"),
        (quote(SYNTHETIC_CREDENTIAL_URL, safe=""), "unsafe URL"),
        (
            "https://example.com/?redirect=" + quote(SYNTHETIC_CREDENTIAL_URL, safe=""),
            "unsafe URL",
        ),
    ],
)
def test_percent_encoding_cannot_hide_sensitive_text(value, message):
    draft, _ = draft_manifest()
    draft["subject"]["contribution"]["summary"] = value
    with pytest.raises(ProofError, match=message):
        finalize_manifest(draft)


def test_unknown_subject_metadata_is_rejected():
    draft, _ = draft_manifest()
    draft["subject"]["unexpected_metadata"] = "not part of the public proof"
    with pytest.raises(ProofError, match="fields are invalid"):
        finalize_manifest(draft)


def test_json_escape_cannot_hide_an_evm_address(tmp_path: Path):
    draft, _ = draft_manifest()
    draft["subject"]["contribution"]["summary"] = SYNTHETIC_EVM_ADDRESS
    encoded = json.dumps(draft).replace("0xabab", r"\u0030xabab")
    path = tmp_path / "escaped.json"
    path.write_text(encoded, encoding="utf-8")
    parsed = _read_json(path)
    with pytest.raises(ProofError, match="full EVM address"):
        finalize_manifest(parsed)


def test_uppercase_evm_prefix_is_rejected():
    draft, _ = draft_manifest()
    draft["subject"]["contribution"]["summary"] = SYNTHETIC_EVM_ADDRESS.replace("0x", "0X")
    with pytest.raises(ProofError, match="full EVM address"):
        finalize_manifest(draft)


@pytest.mark.parametrize(
    "url",
    [
        "https://technocore.chat:443/humans#r/lobby/42",
        "https://example.com/path with-space",
        "https://ｅxample.com/repo",
        "https://example.com/repo#access_token=value",
        "https://example.com/repo?first=1;token=value",
        "https://example.com/repo?api-key=value",
        "HTTPS://example.com/repo",
    ],
)
def test_noncanonical_or_sensitive_public_urls_are_rejected(url):
    draft, _ = draft_manifest()
    draft["subject"]["contribution"]["github_repository"] = url
    with pytest.raises(ProofError, match="unsafe URL|userinfo|hostname|sensitive query"):
        finalize_manifest(draft)


@pytest.mark.parametrize(
    "url",
    [
        "https://localhost/repo",
        "https://127.0.0.1/repo",
    ],
)
def test_local_or_ip_public_urls_are_rejected(url):
    draft, _ = draft_manifest()
    draft["subject"]["contribution"]["github_repository"] = url
    with pytest.raises(ProofError, match="unsafe URL|hostname"):
        finalize_manifest(draft)


@pytest.mark.parametrize(
    "timestamp",
    [
        "not-a-time",
        "2026-08-25 07:00:00Z",
        "2026-08-25T07:00:00",
        "2026-08-25T07:00:00+00:00",
        "2026-02-30T07:00:00Z",
        "2026-08-25T07:00:00.1234567Z",
    ],
)
def test_runtime_and_schema_reject_noncanonical_timestamps(timestamp):
    draft, _ = draft_manifest()
    draft["subject"]["generated_at"] = timestamp
    with pytest.raises(ProofError, match="timestamp|RFC 3339"):
        finalize_manifest(draft)

    valid, _ = draft_manifest()
    finalized = finalize_manifest(valid)
    finalized["subject"]["generated_at"] = timestamp
    with pytest.raises(ValidationError):
        Draft202012Validator(_published_schema(), format_checker=FormatChecker()).validate(
            finalized
        )


def test_schema_and_runtime_reject_noncanonical_attestation_pad_bits():
    draft, _ = draft_manifest()
    draft["proof"]["attestation_b64u"] = draft["proof"]["attestation_b64u"][:-1] + "B"
    with pytest.raises(ProofError, match="attestation_b64u"):
        finalize_manifest(draft)
    with pytest.raises(ValidationError):
        Draft202012Validator(_published_schema()).validate(draft)


def test_unswept_text_is_rejected():
    draft, _ = draft_manifest()
    draft["subject"]["activities"][0]["exact_message"] = "line one\nline two"
    with pytest.raises(ProofError, match="post-sweep"):
        finalize_manifest(draft)


@pytest.mark.parametrize("nonce", ["", True, 1, "-1", "10000000000000000000"])
def test_signed_nonce_must_be_the_exact_protocol_decimal_string(nonce):
    draft, _ = draft_manifest()
    draft["subject"]["activities"][0]["signed_nonce_decimal"] = nonce
    with pytest.raises(ProofError, match="signed_nonce_decimal"):
        finalize_manifest(draft)


def test_leading_zero_signed_nonce_preserves_signed_text_and_normalizes_readback():
    draft, key = draft_manifest()
    activity = draft["subject"]["activities"][0]
    activity["signed_nonce_decimal"] = "0001"
    canonical = canonical_message(activity["room"], "0001", activity["exact_message"])
    activity["canonical_message_sha256"] = sha256_hex(canonical.encode("utf-8"))
    activity["protocol_signature_sha256"] = sha256_hex(key.sign(canonical.encode("utf-8")))
    observed = activity["server_observed"]
    observed["observed_nonce_decimal"] = "1"
    record = normalized_server_record(
        room=activity["room"],
        seq_decimal=observed["seq_decimal"],
        timestamp=observed["timestamp"],
        did=draft["subject"]["identity"]["did"],
        nonce_decimal="1",
        text=activity["exact_message"],
    )
    observed["normalized_record_sha256"] = sha256_hex(canonical_json(record))
    _resign(draft, key)
    assert verify_manifest(finalize_manifest(draft))["status"] == "PASS"


def test_observed_nonce_must_normalize_the_signed_nonce():
    draft, key = draft_manifest()
    draft["subject"]["activities"][0]["server_observed"]["observed_nonce_decimal"] = "2"
    _resign(draft, key)
    with pytest.raises(ProofError, match="does not normalize"):
        finalize_manifest(draft)


def test_large_javascript_unsafe_nonce_is_supported_as_a_string():
    draft, key = draft_manifest()
    activity = draft["subject"]["activities"][0]
    activity["signed_nonce_decimal"] = "9007199254740992"
    canonical = canonical_message(
        activity["room"], activity["signed_nonce_decimal"], activity["exact_message"]
    )
    activity["canonical_message_sha256"] = sha256_hex(canonical.encode("utf-8"))
    activity["protocol_signature_sha256"] = sha256_hex(key.sign(canonical.encode("utf-8")))
    observed = activity["server_observed"]
    observed["observed_nonce_decimal"] = activity["signed_nonce_decimal"]
    record = normalized_server_record(
        room=activity["room"],
        seq_decimal=observed["seq_decimal"],
        timestamp=observed["timestamp"],
        did=draft["subject"]["identity"]["did"],
        nonce_decimal=activity["signed_nonce_decimal"],
        text=activity["exact_message"],
    )
    observed["normalized_record_sha256"] = sha256_hex(canonical_json(record))
    _resign(draft, key)
    assert verify_manifest(finalize_manifest(draft))["status"] == "PASS"


def test_a_later_activity_may_use_a_smaller_unique_nonce():
    draft, key = draft_manifest()
    did = draft["subject"]["identity"]["did"]
    second = _activity(key, did, seq="43")
    second["kind"] = "CONTRIBUTION_ANNOUNCEMENT"
    second["signed_nonce_decimal"] = "1"
    canonical = canonical_message(second["room"], "1", second["exact_message"])
    second["canonical_message_sha256"] = sha256_hex(canonical.encode("utf-8"))
    second["protocol_signature_sha256"] = sha256_hex(key.sign(canonical.encode("utf-8")))
    second["server_observed"]["observed_nonce_decimal"] = "1"
    record = normalized_server_record(
        room=second["room"],
        seq_decimal="43",
        timestamp=second["server_observed"]["timestamp"],
        did=did,
        nonce_decimal="1",
        text=second["exact_message"],
    )
    second["server_observed"]["normalized_record_sha256"] = sha256_hex(canonical_json(record))
    draft["subject"]["activities"].append(second)
    _resign(draft, key)
    assert verify_manifest(finalize_manifest(draft))["status"] == "PASS"


def test_v1_manifest_gets_an_explicit_replay_warning():
    with pytest.raises(ProofError, match="deprecated.*routeable signatures"):
        verify_manifest({"schema": "technocore-contributor-evidence/v1"})


def test_resource_depth_limit_is_iterative_and_explicit():
    value: object = "leaf"
    for _ in range(MAX_DEPTH + 1):
        value = [value]
    with pytest.raises(ProofError, match="depth limit"):
        validate_resource_limits(value)


def test_finalize_checks_depth_before_deepcopy():
    draft, _ = draft_manifest()
    nested: object = "leaf"
    for _ in range(MAX_DEPTH + 1):
        nested = [nested]
    draft["unexpected"] = nested
    with pytest.raises(ProofError, match="depth limit"):
        finalize_manifest(draft)


def test_resource_node_limit_is_explicit():
    with pytest.raises(ProofError, match="node limit"):
        validate_resource_limits([[None] * 100 for _ in range(6)])


def test_resource_string_limit_is_explicit():
    with pytest.raises(ProofError, match="byte limit"):
        validate_resource_limits("x" * (MAX_STRING_UTF8_BYTES + 1))


def test_cli_rejects_duplicate_json_keys(tmp_path: Path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema":"one","schema":"two"}', encoding="utf-8")
    with pytest.raises(ProofError, match="duplicate JSON key"):
        _read_json(path)


def test_cli_rejects_oversized_input_before_parsing(tmp_path: Path):
    path = tmp_path / "oversized.json"
    path.write_bytes(b" " * (MAX_INPUT_BYTES + 1))
    with pytest.raises(ProofError, match="byte limit"):
        _read_json(path)


def test_cli_rejects_extremely_large_integer_without_a_traceback(tmp_path: Path):
    path = tmp_path / "integer.json"
    path.write_text('{"value":' + ("9" * 5000) + "}", encoding="utf-8")
    with pytest.raises(ProofError, match="JSON number is not allowed"):
        _read_json(path)


def test_cli_human_output_uses_narrow_security_claims(tmp_path: Path, capsys):
    draft, _ = draft_manifest()
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(finalize_manifest(draft)), encoding="utf-8")
    assert main(["verify", str(path)]) == 0
    output = capsys.readouterr().out
    assert "domain-separated DID attestation: PASS" in output
    assert "routeable Technocore signatures: absent" in output
    assert "known forbidden patterns: absent" in output
    assert "absolute secret absence proven: no" in output


def test_fixture_matches_the_published_json_schema():
    draft, _ = draft_manifest()
    finalized = finalize_manifest(draft)
    Draft202012Validator(_published_schema(), format_checker=FormatChecker()).validate(finalized)


def test_schema_rejects_unexpected_subject_metadata():
    draft, _ = draft_manifest()
    finalized = finalize_manifest(draft)
    finalized["subject"]["unexpected_metadata"] = None
    with pytest.raises(ValidationError):
        Draft202012Validator(_published_schema()).validate(finalized)


def test_repository_policy_accepts_a_cryptographically_valid_attestation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    draft, _ = draft_manifest()
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    path = evidence_dir / "did-7b12b1399005a4c0.json"
    path.write_text(json.dumps(finalize_manifest(draft)), encoding="utf-8")
    monkeypatch.setattr(repository_scanner, "ROOT", tmp_path)
    failures: list[str] = []
    repository_scanner._scan_evidence(path, failures)
    assert failures == []


def test_repository_scanner_rejects_uppercase_evm_and_standalone_signatures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(repository_scanner, "ROOT", tmp_path)
    path = tmp_path / "notes.md"
    signature = _b64u(bytes(range(64)))
    text = "\n".join(
        (
            SYNTHETIC_EVM_ADDRESS.replace("0x", "0X"),
            json.dumps({"signature": signature}),
        )
    )
    failures: list[str] = []
    repository_scanner._scan_text(path, text, failures)
    assert any("full EVM address" in failure for failure in failures)
    assert any("routeable Technocore signature" in failure for failure in failures)
    assert any("standalone 86-character" in failure for failure in failures)


def test_repository_scanner_allows_one_exact_attestation_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(repository_scanner, "ROOT", tmp_path)
    path = tmp_path / "evidence" / "did-7b12b1399005a4c0.json"
    signature = _b64u(bytes(range(64)))
    failures: list[str] = []
    repository_scanner._scan_text(
        path,
        json.dumps({"attestation_b64u": signature}, indent=2),
        failures,
    )
    assert failures == []


def test_repository_scanner_rejects_archives_even_when_the_payload_is_text():
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, mode="w") as archive:
        archive.writestr(
            "old-evidence.json",
            SYNTHETIC_EVM_ADDRESS + "\n" + _b64u(bytes(range(64))),
        )
    failures: list[str] = []
    decoded = repository_scanner._decode_public_text(
        Path("docs/leak.zip"), payload.getvalue(), failures
    )
    assert decoded is None
    assert any("text-only policy" in failure for failure in failures)


def test_repository_scanner_rejects_non_utf8_tracked_text():
    failures: list[str] = []
    decoded = repository_scanner._decode_public_text(
        Path("docs/not-text.md"), b"\xff\xfe", failures
    )
    assert decoded is None
    assert any("valid UTF-8" in failure for failure in failures)


def test_repository_scanner_accepts_utf8_svg_as_scannable_text():
    failures: list[str] = []
    decoded = repository_scanner._decode_public_text(
        Path("docs/assets/diagram.svg"),
        b'<svg xmlns="http://www.w3.org/2000/svg"><text>public diagram</text></svg>',
        failures,
    )
    assert decoded is not None
    assert failures == []


def test_repository_author_policy_scans_every_ref(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    subprocess.run(["git", "init", "-b", "main"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "voxvex"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "voxvex@users.noreply.github.com"],
        cwd=tmp_path,
        check=True,
    )
    (tmp_path / "main.txt").write_text("main\n", encoding="utf-8")
    subprocess.run(["git", "add", "main.txt"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "main"], cwd=tmp_path, check=True, capture_output=True)

    subprocess.run(
        ["git", "switch", "--orphan", "legacy"], cwd=tmp_path, check=True, capture_output=True
    )
    subprocess.run(["git", "config", "user.name", "not-voxvex"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "not-voxvex@example.invalid"],
        cwd=tmp_path,
        check=True,
    )
    (tmp_path / "legacy.txt").write_text("legacy\n", encoding="utf-8")
    subprocess.run(["git", "add", "legacy.txt"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "legacy"], cwd=tmp_path, check=True, capture_output=True)

    monkeypatch.setattr(repository_scanner, "ROOT", tmp_path)
    failures: list[str] = []
    repository_scanner._scan_authors(failures)
    assert any("voxvex only" in failure for failure in failures)
