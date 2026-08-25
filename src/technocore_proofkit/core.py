"""Strict verification for minimized Technocore DID evidence.

The public format never contains a routeable Technocore protocol signature. It
retains only SHA-256 commitments to the decoded 64-byte signatures and lets the
same did:key attest to the sanitized evidence using an Ed25519 preimage that
cannot match Technocore's room or KV signing grammars.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import ipaddress
import math
import re
import unicodedata
from datetime import datetime
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA = "technocore-contributor-evidence/v3"
KEY_TYPE = "Ed25519"
DID_PREFIX = "did:key:"
MULTICODEC_ED25519 = b"\xed\x01"

ATTESTATION_TYPE = "Ed25519DomainSeparatedAttestation"
ATTESTATION_DOMAIN = "urn:technocore-proofkit:evidence:v3"
ATTESTATION_CLAIM = "DID_ATTESTS_TO_SANITIZED_SUBJECT"
SERVER_OBSERVATION = "CLIENT_ATTESTED_IMMEDIATE_JSON_READBACK"
CANONICALIZATION = "RFC8785"
CONTENT_SCOPE = "RFC8785({schema,subject,proof})"

MAX_INPUT_BYTES = 262_144
MAX_DEPTH = 16
MAX_NODES = 512
MAX_OBJECT_KEYS = 64
MAX_ARRAY_ITEMS = 100
MAX_STRING_UTF8_BYTES = 20_480
MAX_URL_BYTES = 2_048

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_INDEX = {character: index for index, character in enumerate(B58)}
INVISIBLE_CATEGORIES = frozenset(("Cc", "Cf", "Cs", "Co", "Zl", "Zp"))
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
HEX_16_RE = re.compile(r"^[0-9a-f]{16}$")
HEX_40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
B64U_86_RE = re.compile(r"^[A-Za-z0-9_-]{85}[AQgw]$")
SIGNED_NONCE_DECIMAL_RE = re.compile(r"^[0-9]{1,19}$")
NONCE_DECIMAL_RE = re.compile(r"^(?:0|[1-9][0-9]{0,18})$")
POSITIVE_DECIMAL_RE = re.compile(r"^[1-9][0-9]{0,18}$")

TOKEN_B64U_RE = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{32,171}(?![A-Za-z0-9_-])")
TOKEN_B64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{32,171}={0,2}(?![A-Za-z0-9+/=])")
TOKEN_HEX_64_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])")
EVM_ADDRESS_RE = re.compile(r"(?<![0-9A-Fa-f])0[xX][0-9A-Fa-f]{40}(?![0-9A-Fa-f])")
LOCAL_USER_PATH_RE = re.compile(
    r"(?:/" + r"(?:Users|home)/[^\s'\"]+|[A-Za-z]:[\\/]" + r"Users[\\/][^\s'\"]+)",
    re.IGNORECASE,
)
URL_SCHEME_RE = re.compile(r"\b[a-z][a-z0-9+.-]*://", re.IGNORECASE)
ENCODED_BLOCK_RE = re.compile(r"-----BEGIN [A-Z0-9][A-Z0-9 -]{0,63}-----", re.IGNORECASE)
RFC3339_UTC_RE = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,6})?Z$"
)

TOP_LEVEL_KEYS = {"schema", "subject", "proof", "integrity"}
SUBJECT_KEYS = {"generated_at", "identity", "activities", "contribution"}
IDENTITY_KEYS = {"did", "did_fingerprint", "key_type"}
ACTIVITY_KEYS = {
    "kind",
    "room",
    "signed_nonce_decimal",
    "exact_message",
    "canonical_message_sha256",
    "protocol_signature_sha256",
    "server_observed",
}
SERVER_OBSERVED_KEYS = {
    "seq_decimal",
    "observed_nonce_decimal",
    "timestamp",
    "normalized_record_sha256",
    "write_response_sha256",
    "readback_response_sha256",
    "public_permalink",
    "verification",
}
ACTIVITY_KINDS = {"INITIAL_DID_PROOF", "CONTRIBUTION_ANNOUNCEMENT"}
CONTRIBUTION_KEYS = {
    "status",
    "title",
    "summary",
    "github_repository",
    "commit_sha",
    "release_tag",
    "issue_url",
    "pull_request_url",
    "x_thread_zh_url",
    "x_thread_en_url",
    "demo_url",
}
PROOF_KEYS = {"type", "domain", "subject_sha256", "attestation_b64u", "claim"}
INTEGRITY_KEYS = {
    "canonicalization",
    "hash_algorithm",
    "content_scope",
    "content_sha256",
    "known_forbidden_patterns_present",
    "routeable_technocore_signatures_present",
}

SENSITIVE_QUERY_KEYS = {
    "token",
    "accesstoken",
    "apikey",
    "key",
    "secret",
    "password",
    "sig",
    "signature",
}


class ProofError(ValueError):
    """The public evidence is invalid or cannot be verified as claimed."""


def validate_resource_limits(value: Any) -> None:
    """Bound every traversal before schema, pattern, or cryptographic work."""
    stack: list[tuple[Any, int, str]] = [(value, 0, "$")]
    nodes = 0
    while stack:
        current, depth, path = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            raise ProofError(f"manifest exceeds the {MAX_NODES}-node limit")
        if depth > MAX_DEPTH:
            raise ProofError(f"manifest exceeds the {MAX_DEPTH}-level depth limit at {path}")
        if isinstance(current, dict):
            if len(current) > MAX_OBJECT_KEYS:
                raise ProofError(f"object at {path} has too many fields")
            for key, nested in current.items():
                if type(key) is not str or not key or len(key.encode("utf-8")) > 128:
                    raise ProofError(f"object at {path} contains an invalid key")
                stack.append((nested, depth + 1, f"{path}.{key}"))
        elif isinstance(current, list):
            if len(current) > MAX_ARRAY_ITEMS:
                raise ProofError(f"array at {path} has too many items")
            for index, nested in enumerate(current):
                stack.append((nested, depth + 1, f"{path}[{index}]"))
        elif type(current) is str:
            try:
                length = len(current.encode("utf-8"))
            except UnicodeEncodeError as exc:
                raise ProofError(f"string at {path} is not valid UTF-8") from exc
            if length > MAX_STRING_UTF8_BYTES:
                raise ProofError(f"string at {path} exceeds the byte limit")
        elif type(current) is float:
            if not math.isfinite(current):
                raise ProofError(f"non-finite number at {path} is not valid evidence")
            raise ProofError(f"floating-point number at {path} is not allowed")
        elif current is not None and type(current) not in (bool, int):
            raise ProofError(f"unsupported value at {path}")


def canonical_json(value: Any) -> bytes:
    """Return the RFC 8785 JSON Canonicalization Scheme serialization."""
    validate_resource_limits(value)
    try:
        encoded = rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, RecursionError, TypeError) as exc:
        raise ProofError(f"value cannot be canonicalized with RFC 8785: {exc}") from exc
    if len(encoded) > MAX_INPUT_BYTES:
        raise ProofError(f"canonical evidence exceeds {MAX_INPUT_BYTES} bytes")
    return encoded


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _b64u_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64u_decode(value: str, *, expected_bytes: int, label: str) -> bytes:
    if type(value) is not str or "=" in value:
        raise ProofError(f"{label} must be unpadded base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise ProofError(f"{label} is not valid base64url") from exc
    if len(decoded) != expected_bytes or _b64u_encode(decoded) != value:
        raise ProofError(f"{label} is not canonical {expected_bytes}-byte base64url")
    return decoded


def _b58decode(value: str) -> bytes:
    if not value:
        raise ProofError("did:key multibase payload is empty")
    number = 0
    for character in value:
        digit = B58_INDEX.get(character)
        if digit is None:
            raise ProofError(f"did:key contains non-base58btc character {character!r}")
        number = number * 58 + digit
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading_zeroes = len(value) - len(value.lstrip("1"))
    return (b"\x00" * leading_zeroes) + body


def public_key_from_did(did: str) -> bytes:
    """Extract the raw 32-byte Ed25519 public key from a did:key."""
    if type(did) is not str or not did.startswith(f"{DID_PREFIX}z"):
        raise ProofError("DID must be an Ed25519 did:key multibase identifier")
    decoded = _b58decode(did[len(DID_PREFIX) + 1 :])
    if len(decoded) != 34 or not decoded.startswith(MULTICODEC_ED25519):
        raise ProofError("DID is not multicodec ed25519-pub")
    return decoded[len(MULTICODEC_ED25519) :]


def did_fingerprint(did: str) -> str:
    public_key_from_did(did)
    return sha256_hex(did.encode("utf-8"))[:16]


def sweep_text(text: str) -> str:
    """Mirror technocore-chat's public single-line sweep."""
    if type(text) is not str:
        raise ProofError("message text must be a string")
    cleaned = "".join(
        " " if unicodedata.category(character) in INVISIBLE_CATEGORIES else character
        for character in text
    ).strip()
    if not cleaned:
        raise ProofError("message is empty after Technocore's single-line sweep")
    if len(cleaned) > 4096:
        raise ProofError("message exceeds Technocore's 4096-character limit")
    return cleaned


def _require_decimal(value: Any, label: str, *, positive: bool) -> str:
    expression = POSITIVE_DECIMAL_RE if positive else NONCE_DECIMAL_RE
    if type(value) is not str or expression.fullmatch(value) is None:
        qualifier = "positive " if positive else "canonical "
        raise ProofError(f"{label} must be a {qualifier}1-19 digit decimal string")
    return value


def _require_signed_nonce(value: Any, label: str) -> str:
    if type(value) is not str or SIGNED_NONCE_DECIMAL_RE.fullmatch(value) is None:
        raise ProofError(f"{label} must be the exact 1-19 digit string covered by the signature")
    return value


def canonical_message(room: str, signed_nonce_decimal: str, text: str) -> str:
    if type(room) is not str or NAME_RE.fullmatch(room) is None:
        raise ProofError("room does not match Technocore's name grammar")
    nonce = _require_signed_nonce(signed_nonce_decimal, "signed nonce")
    cleaned = sweep_text(text)
    if cleaned != text:
        raise ProofError("exact_message is not the post-sweep text that Technocore stored")
    return f"{room}|{nonce}|{text}"


def normalized_server_record(
    *,
    room: str,
    seq_decimal: str,
    timestamp: str,
    did: str,
    nonce_decimal: str,
    text: str,
) -> dict[str, str]:
    """Build the type-stable public projection of an observed room record."""
    return {
        "room": room,
        "seq_decimal": seq_decimal,
        "timestamp": timestamp,
        "from": did,
        "nonce_decimal": nonce_decimal,
        "text": text,
    }


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ProofError(f"{label} must be a JSON object")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    missing = expected - set(value)
    extra = set(value) - expected
    if missing or extra:
        details = []
        if missing:
            details.append(f"missing {sorted(missing)}")
        if extra:
            details.append(f"unexpected {sorted(extra)}")
        raise ProofError(f"{label} fields are invalid: {'; '.join(details)}")


def _require_string(
    value: Any,
    label: str,
    *,
    maximum_chars: int,
    maximum_bytes: int | None = None,
) -> str:
    if type(value) is not str or not value:
        raise ProofError(f"{label} must be a non-empty string")
    if len(value) > maximum_chars:
        raise ProofError(f"{label} exceeds {maximum_chars} characters")
    byte_limit = maximum_bytes if maximum_bytes is not None else MAX_STRING_UTF8_BYTES
    if len(value.encode("utf-8")) > byte_limit:
        raise ProofError(f"{label} exceeds {byte_limit} UTF-8 bytes")
    return value


def _require_sha256(value: Any, label: str) -> str:
    if type(value) is not str or HEX_64_RE.fullmatch(value) is None:
        raise ProofError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _require_timestamp(value: Any, label: str) -> str:
    text = _require_string(value, label, maximum_chars=64, maximum_bytes=64)
    if RFC3339_UTC_RE.fullmatch(text) is None:
        raise ProofError(f"{label} must be a canonical RFC 3339 UTC timestamp ending in Z")
    try:
        datetime.fromisoformat(text.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise ProofError(f"{label} is not a real calendar timestamp") from exc
    return text


def _normalized_parameter_keys(query: str, fragment: str) -> set[str]:
    parameter_text = "&".join((query, fragment)).replace(";", "&").replace("?", "&")
    return {
        re.sub(r"[-_.]", "", key.casefold())
        for key, _ in parse_qsl(parameter_text, keep_blank_values=True)
    }


def _require_url_or_none(value: Any, label: str) -> str | None:
    if value is None:
        return None
    text = _require_string(
        value,
        label,
        maximum_chars=MAX_URL_BYTES,
        maximum_bytes=MAX_URL_BYTES,
    )
    try:
        parsed = urlsplit(text)
        port = parsed.port
    except ValueError as exc:
        raise ProofError(f"{label} is not a valid URL") from exc
    hostname = parsed.hostname
    if (
        parsed.scheme != "https"
        or not text.startswith("https://")
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or "@" in parsed.netloc
        or "%" in hostname
        or port is not None
        or "\\" in text
        or any(
            character.isspace() or ord(character) < 32 or ord(character) == 127
            for character in text
        )
    ):
        raise ProofError(f"{label} must be an https URL without userinfo")
    try:
        hostname.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ProofError(f"{label} hostname must be ASCII") from exc
    labels = hostname.split(".")
    if (
        len(labels) < 2
        or len(hostname) > 253
        or any(
            not part
            or len(part) > 63
            or re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", part) is None
            for part in labels
        )
    ):
        raise ProofError(f"{label} hostname is invalid")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ProofError(f"{label} hostname must not be an IP address")
    if _normalized_parameter_keys(parsed.query, parsed.fragment) & SENSITIVE_QUERY_KEYS:
        raise ProofError(f"{label} contains a sensitive query parameter")
    return text


def _contains_unsafe_url(value: str) -> bool:
    for match in URL_SCHEME_RE.finditer(value):
        candidate = re.split(r"[\s<>\"']", value[match.start() :], maxsplit=1)[0].rstrip(".,);]")
        try:
            _require_url_or_none(candidate, "embedded URL")
        except ProofError:
            return True
    return False


def _decoded_text_variants(value: str) -> list[str]:
    variants = [value]
    current = value
    for _ in range(2):
        try:
            decoded = unquote(current, errors="strict")
        except UnicodeDecodeError as exc:
            raise ProofError("percent-encoded text is not valid UTF-8") from exc
        if decoded == current:
            break
        variants.append(decoded)
        current = decoded
    return variants


def _entropy(value: bytes) -> float:
    if not value:
        return 0.0
    counts = {byte: value.count(byte) for byte in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def _decoded_token(candidate: str, *, urlsafe: bool) -> bytes | None:
    try:
        if urlsafe:
            decoded = base64.urlsafe_b64decode(candidate + "=" * (-len(candidate) % 4))
            if _b64u_encode(decoded) != candidate:
                return None
        else:
            decoded = base64.b64decode(candidate, validate=True)
            if base64.b64encode(decoded).decode("ascii") != candidate:
                return None
    except (ValueError, TypeError):
        return None
    return decoded


def _has_secret_shaped_token(value: str) -> bool:
    if TOKEN_HEX_64_RE.search(value):
        return True
    for expression, urlsafe in ((TOKEN_B64U_RE, True), (TOKEN_B64_RE, False)):
        for match in expression.finditer(value):
            decoded = _decoded_token(match.group(0), urlsafe=urlsafe)
            if decoded is None:
                continue
            if len(decoded) in {32, 64}:
                return True
            if 24 <= len(decoded) <= 128 and _entropy(decoded) >= 4.0:
                return True
    return False


def _path_allows_crypto_material(path: str) -> bool:
    if path in {
        "$.schema",
        "$.subject.identity.did",
        "$.subject.identity.did_fingerprint",
        "$.subject.identity.key_type",
        "$.subject.contribution.status",
        "$.proof.type",
        "$.proof.domain",
        "$.proof.subject_sha256",
        "$.proof.attestation_b64u",
        "$.proof.claim",
        "$.integrity.canonicalization",
        "$.integrity.hash_algorithm",
        "$.integrity.content_scope",
        "$.integrity.content_sha256",
        "$.subject.contribution.commit_sha",
    }:
        return True
    activity_hash_suffixes = (
        ".kind",
        ".canonical_message_sha256",
        ".protocol_signature_sha256",
        ".server_observed.normalized_record_sha256",
        ".server_observed.write_response_sha256",
        ".server_observed.readback_response_sha256",
        ".server_observed.verification",
    )
    return path.startswith("$.subject.activities[") and path.endswith(activity_hash_suffixes)


def _scan_public_values(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            nested_path = f"{path}.{key}"
            _scan_public_values(nested, nested_path)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _scan_public_values(nested, f"{path}[{index}]")
    elif type(value) is str:
        for candidate in _decoded_text_variants(value):
            if ENCODED_BLOCK_RE.search(candidate):
                raise ProofError(f"encoded credential block at {path}")
            if EVM_ADDRESS_RE.search(candidate):
                raise ProofError(f"full EVM address at {path}")
            if LOCAL_USER_PATH_RE.search(candidate):
                raise ProofError(f"local user path at {path}")
            if _contains_unsafe_url(candidate):
                raise ProofError(f"unsafe URL at {path}")
            if not _path_allows_crypto_material(path) and _has_secret_shaped_token(candidate):
                raise ProofError(f"secret-or-signature-shaped token at {path}")


def subject_projection(manifest: dict[str, Any]) -> dict[str, Any]:
    return {"schema": manifest["schema"], "subject": copy.deepcopy(manifest["subject"])}


def subject_sha256(manifest: dict[str, Any]) -> str:
    return sha256_hex(canonical_json(subject_projection(manifest)))


def attestation_preimage(subject_digest: str) -> bytes:
    digest = bytes.fromhex(_require_sha256(subject_digest, "proof subject digest"))
    return ATTESTATION_DOMAIN.encode("utf-8") + b"\x00" + digest


def content_projection(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": manifest["schema"],
        "subject": copy.deepcopy(manifest["subject"]),
        "proof": copy.deepcopy(manifest["proof"]),
    }


def content_sha256(manifest: dict[str, Any]) -> str:
    return sha256_hex(canonical_json(content_projection(manifest)))


def _verify_activity(activity: Any, did: str, label: str) -> tuple[str, str, str]:
    value = _require_object(activity, label)
    _exact_keys(value, ACTIVITY_KEYS, label)
    kind = _require_string(value["kind"], f"{label}.kind", maximum_chars=64)
    if kind not in ACTIVITY_KINDS:
        raise ProofError(f"{label}.kind is not recognized")
    room = _require_string(value["room"], f"{label}.room", maximum_chars=48)
    nonce = _require_signed_nonce(value["signed_nonce_decimal"], f"{label}.signed_nonce_decimal")
    message = _require_string(value["exact_message"], f"{label}.exact_message", maximum_chars=4096)
    canonical = canonical_message(room, nonce, message)
    expected_canonical_hash = sha256_hex(canonical.encode("utf-8"))
    if value["canonical_message_sha256"] != expected_canonical_hash:
        raise ProofError(f"{label}.canonical_message_sha256 does not match room|nonce|text")
    _require_sha256(value["protocol_signature_sha256"], f"{label}.protocol_signature_sha256")

    observed = _require_object(value["server_observed"], f"{label}.server_observed")
    _exact_keys(observed, SERVER_OBSERVED_KEYS, f"{label}.server_observed")
    seq = _require_decimal(
        observed["seq_decimal"],
        f"{label}.server_observed.seq_decimal",
        positive=True,
    )
    observed_nonce = _require_decimal(
        observed["observed_nonce_decimal"],
        f"{label}.server_observed.observed_nonce_decimal",
        positive=False,
    )
    if int(observed_nonce) != int(nonce):
        raise ProofError(
            f"{label}.server_observed.observed_nonce_decimal does not normalize the signed nonce"
        )
    timestamp = _require_timestamp(observed["timestamp"], f"{label}.server_observed.timestamp")
    record = normalized_server_record(
        room=room,
        seq_decimal=seq,
        timestamp=timestamp,
        did=did,
        nonce_decimal=observed_nonce,
        text=message,
    )
    expected_record_hash = sha256_hex(canonical_json(record))
    if observed["normalized_record_sha256"] != expected_record_hash:
        raise ProofError(f"{label}.server_observed.normalized_record_sha256 does not match")
    for field in ("write_response_sha256", "readback_response_sha256"):
        _require_sha256(observed[field], f"{label}.server_observed.{field}")
    if observed["verification"] != SERVER_OBSERVATION:
        raise ProofError(f"{label}.server_observed.verification must be {SERVER_OBSERVATION}")

    permalink = _require_url_or_none(
        observed["public_permalink"], f"{label}.server_observed.public_permalink"
    )
    assert permalink is not None
    parsed_permalink = urlsplit(permalink)
    if (
        parsed_permalink.scheme != "https"
        or parsed_permalink.netloc != "technocore.chat"
        or parsed_permalink.path != "/humans"
        or parsed_permalink.query
        or parsed_permalink.fragment != f"r/{room}/{seq}"
    ):
        raise ProofError(f"{label}.server_observed.public_permalink does not identify room and seq")
    return kind, seq, nonce


def verify_manifest(manifest: Any, *, require_hash: bool = True) -> dict[str, Any]:
    """Verify the public structure, commitments, attestation, and safety rules."""
    validate_resource_limits(manifest)
    document = _require_object(manifest, "manifest")
    if document.get("schema") == "technocore-contributor-evidence/v1":
        raise ProofError("v1 evidence is deprecated because it can expose routeable signatures")
    _exact_keys(document, TOP_LEVEL_KEYS, "manifest")
    if document["schema"] != SCHEMA:
        raise ProofError(f"unsupported schema {document['schema']!r}")
    _scan_public_values(document)

    subject = _require_object(document["subject"], "subject")
    _exact_keys(subject, SUBJECT_KEYS, "subject")
    _require_timestamp(subject["generated_at"], "subject.generated_at")

    identity = _require_object(subject["identity"], "subject.identity")
    _exact_keys(identity, IDENTITY_KEYS, "subject.identity")
    did = _require_string(identity["did"], "subject.identity.did", maximum_chars=128)
    public_key = public_key_from_did(did)
    fingerprint = _require_string(
        identity["did_fingerprint"],
        "subject.identity.did_fingerprint",
        maximum_chars=16,
        maximum_bytes=16,
    )
    if HEX_16_RE.fullmatch(fingerprint) is None or fingerprint != did_fingerprint(did):
        raise ProofError("subject.identity.did_fingerprint does not match the DID")
    if identity["key_type"] != KEY_TYPE:
        raise ProofError("subject.identity.key_type must be Ed25519")

    activities = subject["activities"]
    if type(activities) is not list or not 1 <= len(activities) <= len(ACTIVITY_KINDS):
        raise ProofError("subject.activities must contain 1-2 records")
    kinds: set[str] = set()
    receipts: set[tuple[str, str]] = set()
    last_seq_by_room: dict[str, int] = {}
    nonces_by_room: dict[str, set[int]] = {}
    sequences: list[str] = []
    for index, activity in enumerate(activities):
        label = f"subject.activities[{index}]"
        kind, seq, nonce = _verify_activity(activity, did, label)
        if kind in kinds:
            raise ProofError(f"duplicate activity kind {kind}")
        kinds.add(kind)
        receipt = (str(activity["room"]), seq)
        if receipt in receipts:
            raise ProofError("duplicate room/seq receipt")
        receipts.add(receipt)
        room = str(activity["room"])
        current_seq = int(seq)
        previous_seq = last_seq_by_room.get(room)
        if previous_seq is not None and current_seq <= previous_seq:
            raise ProofError(f"activity sequences for room {room} are not strictly ordered")
        normalized_nonce = int(nonce)
        seen_nonces = nonces_by_room.setdefault(room, set())
        if normalized_nonce in seen_nonces:
            raise ProofError(f"duplicate normalized nonce for room {room}")
        seen_nonces.add(normalized_nonce)
        last_seq_by_room[room] = current_seq
        sequences.append(seq)
    if "INITIAL_DID_PROOF" not in kinds:
        raise ProofError("subject.activities must include INITIAL_DID_PROOF")

    contribution = _require_object(subject["contribution"], "subject.contribution")
    _exact_keys(contribution, CONTRIBUTION_KEYS, "subject.contribution")
    if contribution["status"] not in {"IN_PROGRESS", "PUBLISHED", "ANNOUNCED", "ADOPTED"}:
        raise ProofError("subject.contribution.status is not recognized")
    _require_string(contribution["title"], "subject.contribution.title", maximum_chars=200)
    _require_string(contribution["summary"], "subject.contribution.summary", maximum_chars=2000)
    for field in (
        "github_repository",
        "issue_url",
        "pull_request_url",
        "x_thread_zh_url",
        "x_thread_en_url",
        "demo_url",
    ):
        _require_url_or_none(contribution[field], f"subject.contribution.{field}")
    commit_sha = contribution["commit_sha"]
    if commit_sha is not None and (
        type(commit_sha) is not str or HEX_40_RE.fullmatch(commit_sha) is None
    ):
        raise ProofError(
            "subject.contribution.commit_sha must be a lowercase 40-hex commit or null"
        )
    release_tag = contribution["release_tag"]
    if release_tag is not None:
        _require_string(
            release_tag,
            "subject.contribution.release_tag",
            maximum_chars=128,
            maximum_bytes=128,
        )
    if contribution["status"] in {"ANNOUNCED", "ADOPTED"} and (
        "CONTRIBUTION_ANNOUNCEMENT" not in kinds
        or contribution["github_repository"] is None
        or contribution["issue_url"] is None
    ):
        raise ProofError("an announced contribution needs its attested activity and public links")

    proof = _require_object(document["proof"], "proof")
    _exact_keys(proof, PROOF_KEYS, "proof")
    if proof["type"] != ATTESTATION_TYPE:
        raise ProofError(f"proof.type must be {ATTESTATION_TYPE}")
    if proof["domain"] != ATTESTATION_DOMAIN:
        raise ProofError("proof.domain is not the fixed ProofKit domain")
    digest = subject_sha256(document)
    if proof["subject_sha256"] != digest:
        raise ProofError("proof.subject_sha256 does not match the sanitized subject")
    if proof["claim"] != ATTESTATION_CLAIM:
        raise ProofError(f"proof.claim must be {ATTESTATION_CLAIM}")
    signature_text = _require_string(
        proof["attestation_b64u"],
        "proof.attestation_b64u",
        maximum_chars=86,
        maximum_bytes=86,
    )
    if B64U_86_RE.fullmatch(signature_text) is None:
        raise ProofError("proof.attestation_b64u must be 86 base64url characters")
    signature = _b64u_decode(signature_text, expected_bytes=64, label="proof.attestation_b64u")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature,
            attestation_preimage(digest),
        )
    except InvalidSignature as exc:
        raise ProofError("domain-separated DID evidence attestation does not verify") from exc

    integrity = _require_object(document["integrity"], "integrity")
    _exact_keys(integrity, INTEGRITY_KEYS, "integrity")
    if integrity["canonicalization"] != CANONICALIZATION:
        raise ProofError("integrity.canonicalization must be RFC8785")
    if integrity["hash_algorithm"] != "SHA-256":
        raise ProofError("integrity.hash_algorithm must be SHA-256")
    if integrity["content_scope"] != CONTENT_SCOPE:
        raise ProofError("integrity.content_scope is not the ProofKit rule")
    if integrity["known_forbidden_patterns_present"] is not False:
        raise ProofError("integrity.known_forbidden_patterns_present must be false")
    if integrity["routeable_technocore_signatures_present"] is not False:
        raise ProofError("integrity.routeable_technocore_signatures_present must be false")

    complete_digest = content_sha256(document)
    supplied = integrity["content_sha256"]
    if require_hash:
        _require_sha256(supplied, "integrity.content_sha256")
        if supplied != complete_digest:
            raise ProofError("integrity.content_sha256 does not match the content projection")
    elif supplied is not None and supplied != complete_digest:
        raise ProofError("pre-filled integrity.content_sha256 is incorrect")

    return {
        "status": "PASS",
        "schema": SCHEMA,
        "did": did,
        "did_fingerprint": fingerprint,
        "activity_sequences": sequences,
        "subject_sha256": digest,
        "content_sha256": complete_digest,
        "domain_separated_attestation": "PASS",
        "routeable_technocore_signatures_present": False,
        "known_forbidden_patterns_present": False,
        "secret_absence_proven": False,
        "server_claims_independently_authenticated": False,
    }


def finalize_manifest(manifest: Any) -> dict[str, Any]:
    """Validate an already-attested draft and fill its content commitment."""
    validate_resource_limits(manifest)
    try:
        document = copy.deepcopy(_require_object(manifest, "manifest"))
    except RecursionError as exc:
        raise ProofError("manifest cannot be copied within the resource limits") from exc
    verify_manifest(document, require_hash=False)
    document["integrity"]["content_sha256"] = content_sha256(document)
    verify_manifest(document, require_hash=True)
    return document
