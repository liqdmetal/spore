#!/usr/bin/env python3
"""Replay Spore DAO review conformance vectors without Go or third-party packages."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
VECTOR_DIR = ROOT / "internal" / "daoreview" / "testdata" / "conformance"
CERT_FILE = "dao-review-certificate-v1.json"
HANDOFF_FILE = "dao-review-handoff-v1.json"

MANIFEST_DOMAIN = "spore/dao-review/manifest/v1"
DECISION_DOMAIN = "spore/dao-review/decision/v1"
CERTIFICATE_DOMAIN = "spore/dao-review/certificate/v1"
HANDOFF_DOMAIN = "spore/private-handoff/v1"
MAX_CONTENT = 16 << 10
MAX_POLICY = 8 << 10
MAX_MESSAGE = 96 << 10
MAX_CERTIFICATE = 64 << 10

# JSON struct field order is part of Spore's typed encoding.
PEER = ["address", "pinned_sig"]
WORK_ORDER = ["objective_id", "owner_pseudonym", "description_commitment", "policy_hash"]
REGISTRATION = ["source", "version", "relay_url", "actor_id", "objective", "observed_at"]
TERMS = ["id", "registration", "buyer", "provider", "expires_at"]
MESSAGE = ["version", "terms", "event_id", "sequence", "previous", "kind", "content", "policy", "result_hash"]
MANIFEST = ["version", "id", "dao", "proposal", "epoch", "coordinator", "evidence_hash", "policy_hash", "reviewers", "threshold", "created_at", "deadline", "expires_at"]
SIGNED_MANIFEST = ["domain", "manifest", "signature"]
DECISION = ["version", "review_hash", "handoff_id", "brief_hash", "reviewer", "choice", "at"]
SIGNED_DECISION = ["domain", "decision", "signature"]
CERTIFICATE = ["domain", "version", "review", "approvals"]
ENVELOPE = ["domain", "message", "signature"]
PACKET = ["review", "policy"]


class Invalid(ValueError):
    pass


def fail(message: str) -> None:
    raise Invalid(message)


def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    seen: set[str] = set()
    for key, value in pairs:
        folded = key.lower()
        if folded in seen:
            fail(f"duplicate JSON key {key!r}")
        seen.add(folded)
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    fail(f"non-JSON numeric constant {value}")


def check_tree(value: Any, depth: int = 0) -> None:
    if depth > 32:
        fail("JSON nesting exceeds 32 levels")
    if value is None:
        fail("null is not permitted")
    if isinstance(value, dict):
        for child in value.values():
            check_tree(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            check_tree(child, depth + 1)


def parse_json(raw: bytes, limit: int) -> Any:
    if not raw or len(raw) > limit:
        fail("JSON input is empty or exceeds its size limit")
    try:
        text = raw.decode("utf-8", "strict")
        decoder = json.JSONDecoder(object_pairs_hook=no_duplicates, parse_constant=reject_constant)
        value, end = decoder.raw_decode(text)
        if text[end:].strip():
            fail("trailing JSON value")
        check_tree(value)
        return value
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"invalid JSON: {exc}")


def exact_fields(obj: Any, required: list[str], optional: tuple[str, ...] = ()) -> dict[str, Any]:
    if not isinstance(obj, dict):
        fail("expected JSON object")
    allowed = set(required) | set(optional)
    missing = set(required) - obj.keys()
    unknown = obj.keys() - allowed
    if missing:
        fail(f"missing fields: {', '.join(sorted(missing))}")
    if unknown:
        fail(f"unknown fields: {', '.join(sorted(unknown))}")
    return obj


def ordered(obj: dict[str, Any], fields: list[str], optional: tuple[str, ...] = ()) -> dict[str, Any]:
    exact_fields(obj, [f for f in fields if f not in optional], optional)
    out: dict[str, Any] = {}
    for key in fields:
        if key not in obj:
            continue
        value = obj[key]
        if key in ("coordinator", "reviewer", "buyer", "provider") and isinstance(value, dict):
            value = ordered(value, PEER)
        elif key == "objective" and isinstance(value, dict):
            value = ordered(value, WORK_ORDER)
        elif key == "registration" and isinstance(value, dict):
            value = ordered(value, REGISTRATION, ("source",))
        elif key == "terms" and isinstance(value, dict):
            value = ordered(value, TERMS)
        elif key == "manifest" and isinstance(value, dict):
            value = ordered(value, MANIFEST)
        elif key == "review" and isinstance(value, dict):
            # The review may be a SignedManifest or a Packet depending on parent;
            # callers use the explicit normalizers below for those containers.
            value = ordered(value, SIGNED_MANIFEST)
        elif key == "decision" and isinstance(value, dict):
            value = ordered(value, DECISION)
        elif key == "message" and isinstance(value, dict):
            value = ordered(value, MESSAGE, ("content", "policy", "result_hash"))
        elif key == "approvals" and isinstance(value, list):
            value = [normalize_signed_decision(item) for item in value]
        out[key] = value
    # encoding/json omits zero-length byte slices and empty strings tagged omitempty.
    for key in optional:
        if key in out and out[key] in ("", None):
            out.pop(key)
    return out


def normalize_peer(obj: Any) -> dict[str, Any]:
    return ordered(obj, PEER)


def normalize_work_order(obj: Any) -> dict[str, Any]:
    return ordered(obj, WORK_ORDER)


def normalize_registration(obj: Any) -> dict[str, Any]:
    exact_fields(obj, [f for f in REGISTRATION if f != "source"], ("source",))
    out = {k: obj[k] for k in REGISTRATION if k in obj}
    if out.get("source") == "":
        out.pop("source")
    out["objective"] = normalize_work_order(out["objective"])
    return out


def normalize_terms(obj: Any) -> dict[str, Any]:
    exact_fields(obj, TERMS)
    return {"id": obj["id"], "registration": normalize_registration(obj["registration"]),
            "buyer": normalize_peer(obj["buyer"]), "provider": normalize_peer(obj["provider"]),
            "expires_at": obj["expires_at"]}


def normalize_message(obj: Any) -> dict[str, Any]:
    exact_fields(obj, [k for k in MESSAGE if k not in ("content", "policy", "result_hash")], ("content", "policy", "result_hash"))
    out = {k: obj[k] for k in MESSAGE if k in obj}
    out["terms"] = normalize_terms(out["terms"])
    # Go's []byte fields marshal as base64, and omit empty slices.
    for key in ("content", "policy"):
        if key in out:
            decoded = b64(out[key])
            if not decoded:
                out.pop(key)
    if out.get("result_hash") == "":
        out.pop("result_hash", None)
    return out


def normalize_manifest(obj: Any) -> dict[str, Any]:
    exact_fields(obj, MANIFEST)
    out = {k: obj[k] for k in MANIFEST}
    out["coordinator"] = normalize_peer(out["coordinator"])
    out["reviewers"] = [normalize_peer(p) for p in out["reviewers"]]
    return out


def normalize_signed_manifest(obj: Any) -> dict[str, Any]:
    exact_fields(obj, SIGNED_MANIFEST)
    return {"domain": obj["domain"], "manifest": normalize_manifest(obj["manifest"]), "signature": obj["signature"]}


def normalize_decision(obj: Any) -> dict[str, Any]:
    exact_fields(obj, DECISION)
    out = {k: obj[k] for k in DECISION}
    out["reviewer"] = normalize_peer(out["reviewer"])
    return out


def normalize_signed_decision(obj: Any) -> dict[str, Any]:
    exact_fields(obj, SIGNED_DECISION)
    return {"domain": obj["domain"], "decision": normalize_decision(obj["decision"]), "signature": obj["signature"]}


def normalize_certificate(obj: Any) -> dict[str, Any]:
    exact_fields(obj, CERTIFICATE)
    return {"domain": obj["domain"], "version": obj["version"],
            "review": normalize_signed_manifest(obj["review"]),
            "approvals": [normalize_signed_decision(x) for x in obj["approvals"]]}


def normalize_envelope(obj: Any) -> dict[str, Any]:
    exact_fields(obj, ENVELOPE)
    return {"domain": obj["domain"], "message": normalize_message(obj["message"]), "signature": obj["signature"]}


def go_json(value: Any) -> bytes:
    # All vector protocol strings are ASCII. Match encoding/json's HTML-safe escapes.
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    return (text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")).encode("utf-8")


def sha256(raw: bytes) -> bytes:
    return hashlib.sha256(raw).digest()


def commitment(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hex()


def hash_typed(obj: dict[str, Any], normalizer) -> str:
    return commitment(go_json(normalizer(obj)))


def b64(value: Any) -> bytes:
    if not isinstance(value, str):
        fail("expected base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        fail(f"invalid base64: {exc}")


def hex_bytes(value: Any, size: int) -> bytes:
    if not isinstance(value, str) or len(value) != size * 2 or value.lower() != value:
        fail("invalid lowercase hex encoding")
    try:
        out = bytes.fromhex(value)
    except ValueError:
        fail("invalid hex encoding")
    if len(out) != size:
        fail("invalid hex length")
    return out


# Minimal strict RFC 8032 Ed25519 verification, using only Python integers.
_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)
_ID = (0, 1, 1, 0)


def ed_decode(encoded: bytes) -> tuple[int, int, int, int]:
    if len(encoded) != 32:
        fail("Ed25519 point has wrong length")
    value = int.from_bytes(encoded, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= _Q:
        fail("non-canonical Ed25519 point")
    y2 = y * y % _Q
    xx = (y2 - 1) * pow((_D * y2 + 1) % _Q, _Q - 2, _Q) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q:
        x = x * _I % _Q
    if (x * x - xx) % _Q:
        fail("invalid Ed25519 point")
    if x == 0 and sign:
        fail("non-canonical Ed25519 sign bit")
    if (x & 1) != sign:
        x = _Q - x
    return (x, y, 1, x * y % _Q)


def ed_add(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _Q
    b = (y1 + x1) * (y2 + x2) % _Q
    c = 2 * _D * t1 * t2 % _Q
    d = 2 * z1 * z2 % _Q
    e, f, g, h = (b - a) % _Q, (d - c) % _Q, (d + c) % _Q, (b + a) % _Q
    return (e * f % _Q, g * h % _Q, f * g % _Q, e * h % _Q)


def ed_mul(scalar: int, point: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    result = _ID
    addend = point
    while scalar:
        if scalar & 1:
            result = ed_add(result, addend)
        addend = ed_add(addend, addend)
        scalar >>= 1
    return result


def ed_equal(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> bool:
    return (p[0] * q[2] - q[0] * p[2]) % _Q == 0 and (p[1] * q[2] - q[1] * p[2]) % _Q == 0


def ed_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        r_enc, s_enc = signature[:32], signature[32:]
        scalar = int.from_bytes(s_enc, "little")
        if scalar >= _L:
            return False
        public_point = ed_decode(public_key)
        r_point = ed_decode(r_enc)
        # Strict verification rejects small-order public keys and R encodings.
        if ed_equal(ed_mul(8, public_point), _ID) or ed_equal(ed_mul(8, r_point), _ID):
            return False
        base_y = (4 * pow(5, _Q - 2, _Q)) % _Q
        base = ed_decode(base_y.to_bytes(32, "little"))
        challenge = int.from_bytes(hashlib.sha512(r_enc + public_key + message).digest(), "little") % _L
        return ed_equal(ed_mul(scalar, base), ed_add(r_point, ed_mul(challenge, public_point)))
    except Invalid:
        return False


def verify_signature(domain: str, body: dict[str, Any], pin: str, signature: str, normalizer) -> None:
    public_key = hex_bytes(pin, 32)
    sig = hex_bytes(signature, 64)
    message = (domain + "\0").encode("ascii") + go_json(normalizer(body))
    if not ed_verify(public_key, message, sig):
        fail("Ed25519 signature verification failed")


def valid_hash(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("sha256:") and value == value.lower() and len(value) == 71 and all(c in "0123456789abcdef" for c in value[7:])


def validate_peer(peer: Any) -> None:
    exact_fields(peer, PEER)
    address, pin = peer["address"], peer["pinned_sig"]
    if not isinstance(address, str) or not address or address.strip() != address or len(address.encode()) > 512 or any(c in address for c in "\r\n\0"):
        fail("invalid participant address")
    hex_bytes(pin, 32)


def validate_manifest(signed: Any) -> None:
    exact_fields(signed, SIGNED_MANIFEST)
    if signed["domain"] != MANIFEST_DOMAIN:
        fail("wrong manifest domain")
    m = signed["manifest"]
    exact_fields(m, MANIFEST)
    validate_peer(m["coordinator"])
    if m["version"] != 1 or type(m["version"]) is not int:
        fail("unsupported manifest version")
    hex_bytes(m["id"], 16)
    for label in (m["dao"], m["proposal"]):
        if not isinstance(label, str) or not label or label.strip() != label or len(label.encode()) > 256 or any(c in label for c in "\0\r\n"):
            fail("invalid manifest label")
    if type(m["epoch"]) is not int or m["epoch"] <= 0 or not valid_hash(m["evidence_hash"]) or not valid_hash(m["policy_hash"]):
        fail("invalid epoch or commitments")
    reviewers = m["reviewers"]
    if not isinstance(reviewers, list) or not 1 <= len(reviewers) <= 16:
        fail("invalid reviewer count")
    prior = ""
    addresses: set[str] = set()
    pins: set[str] = set()
    for reviewer in reviewers:
        validate_peer(reviewer)
        address, pin = reviewer["address"], reviewer["pinned_sig"]
        if address == m["coordinator"]["address"] or pin == m["coordinator"]["pinned_sig"] or address in addresses or pin in pins or pin <= prior:
            fail("invalid reviewer roster order or membership")
        addresses.add(address)
        pins.add(pin)
        prior = pin
    n, threshold = len(reviewers), m["threshold"]
    if type(threshold) is not int or threshold <= n // 2 or threshold > n:
        fail("threshold is not a strict majority")
    created, deadline, expires = m["created_at"], m["deadline"], m["expires_at"]
    if any(type(x) is not int for x in (created, deadline, expires)) or created <= 0 or deadline <= created or expires <= deadline or expires - created > 30 * 86400:
        fail("invalid manifest time window")
    verify_signature(MANIFEST_DOMAIN, m, m["coordinator"]["pinned_sig"], signed["signature"], normalize_manifest)


def review_hash(signed: dict[str, Any]) -> str:
    return hash_typed(signed, normalize_signed_manifest)


def invitation_id(signed: dict[str, Any], reviewer: dict[str, Any]) -> str:
    body = {"review_hash": review_hash(signed), "reviewer": normalize_peer(reviewer)}
    return sha256(go_json(body)).hex()[:32]


def verify_decision(signed_decision: Any, signed_review: Any, now: int | None = None) -> None:
    exact_fields(signed_decision, SIGNED_DECISION)
    if signed_decision["domain"] != DECISION_DOMAIN:
        fail("wrong decision domain")
    d = signed_decision["decision"]
    exact_fields(d, DECISION)
    validate_manifest(signed_review)
    m = signed_review["manifest"]
    if d["version"] != 1 or type(d["version"]) is not int or d["review_hash"] != review_hash(signed_review):
        fail("decision is bound to wrong review")
    if not isinstance(d["handoff_id"], str) or d["handoff_id"] != invitation_id(signed_review, d["reviewer"]):
        fail("decision is bound to wrong invitation")
    if not valid_hash(d["brief_hash"]):
        fail("invalid brief hash")
    validate_peer(d["reviewer"])
    if d["reviewer"] not in m["reviewers"]:
        fail("reviewer is not in signed roster")
    if d["choice"] not in ("approve", "reject"):
        fail("invalid review choice")
    if type(d["at"]) is not int or d["at"] < m["created_at"] or d["at"] >= m["deadline"]:
        fail("decision is outside review window")
    if now is not None and d["at"] > now:
        fail("future decision")
    verify_signature(DECISION_DOMAIN, d, d["reviewer"]["pinned_sig"], signed_decision["signature"], normalize_decision)


def verify_certificate(cert: Any, expected_hash: str, now: int) -> int:
    exact_fields(cert, CERTIFICATE)
    signed_review = cert["review"]
    if cert["domain"] != CERTIFICATE_DOMAIN or cert["version"] != 1 or type(cert["version"]) is not int:
        fail("wrong certificate domain or version")
    validate_manifest(signed_review)
    actual_hash = review_hash(signed_review)
    if not valid_hash(expected_hash) or actual_hash != expected_hash:
        fail("certificate does not match trusted review hash")
    m = signed_review["manifest"]
    if now < m["created_at"] or now >= m["expires_at"]:
        fail("review outside certificate lifetime")
    approvals = cert["approvals"]
    if not isinstance(approvals, list) or len(approvals) > 16:
        fail("invalid approvals list")
    seen: set[str] = set()
    approval_pins: list[str] = []
    for decision in approvals:
        verify_decision(decision, signed_review, now)
        d = decision["decision"]
        if d["choice"] != "approve":
            fail("non-approval in approvals list")
        pin = d["reviewer"]["pinned_sig"]
        if pin in seen:
            fail("duplicate reviewer approval")
        seen.add(pin)
        approval_pins.append(pin)
    if len(approvals) < m["threshold"]:
        fail("approval quorum not met")
    if approval_pins != sorted(approval_pins):
        fail("approvals are not canonically sorted")
    return len(approvals)


def decode_envelope(encoded: str) -> tuple[dict[str, Any], bytes]:
    raw = b64(encoded)
    obj = parse_json(raw, MAX_MESSAGE)
    exact_fields(obj, ENVELOPE)
    return obj, raw


def verify_handoff_envelope(envelope: Any) -> None:
    exact_fields(envelope, ENVELOPE)
    if envelope["domain"] != HANDOFF_DOMAIN:
        fail("wrong handoff signing domain")
    m = envelope["message"]
    exact_fields(m, [k for k in MESSAGE if k not in ("content", "policy", "result_hash")], ("content", "policy", "result_hash"))
    t = m["terms"]
    exact_fields(t, TERMS)
    reg = t["registration"]
    exact_fields(reg, [k for k in REGISTRATION if k != "source"], ("source",))
    obj = reg["objective"]
    exact_fields(obj, WORK_ORDER)
    validate_peer(t["buyer"])
    validate_peer(t["provider"])
    validate_peer(m["kind"] == "deliver" and t["provider"] or t["buyer"])
    if t["buyer"]["address"] == t["provider"]["address"] or t["buyer"]["pinned_sig"] == t["provider"]["pinned_sig"]:
        fail("buyer and provider must be distinct")
    if m["version"] != 1 or type(m["version"]) is not int or type(m["sequence"]) is not int:
        fail("invalid handoff version/sequence")
    hex_bytes(t["id"], 16)
    hex_bytes(m["event_id"], 16)
    if type(t["expires_at"]) is not int or t["expires_at"] <= 0 or type(reg["observed_at"]) is not int or reg["observed_at"] <= 0 or t["expires_at"] <= reg["observed_at"]:
        fail("invalid handoff expiry")
    if reg.get("source", "") != "local-dao-review" or reg["version"] != 1 or reg["relay_url"] != "" or reg["actor_id"] != "":
        fail("not a local DAO review registration")
    if not isinstance(obj["objective_id"], str) or not obj["objective_id"].strip() or len(obj["objective_id"]) > 256 or not isinstance(obj["owner_pseudonym"], str) or not obj["owner_pseudonym"].strip() or len(obj["owner_pseudonym"]) > 256 or not valid_hash(obj["description_commitment"]) or not valid_hash(obj["policy_hash"]):
        fail("invalid local objective commitments")
    kind = m["kind"]
    content = b64(m["content"]) if "content" in m else b""
    policy = b64(m["policy"]) if "policy" in m else b""
    if len(content) > MAX_CONTENT or len(policy) > MAX_POLICY:
        fail("content or policy exceeds handoff limit")
    if kind == "brief":
        if m["sequence"] != 1 or m["previous"] != "" or not content or not policy or m.get("result_hash", "") != "":
            fail("invalid brief shape")
        if commitment(content) != obj["description_commitment"] or commitment(policy) != obj["policy_hash"]:
            fail("brief body does not match objective commitments")
    elif kind == "deliver":
        if m["sequence"] != 2 or not valid_hash(m["previous"]) or not content or policy or commitment(content) != m.get("result_hash"):
            fail("invalid deliver shape")
    else:
        fail("unsupported handoff kind")
    sender = t["provider"] if kind == "deliver" else t["buyer"]
    verify_signature(HANDOFF_DOMAIN, m, sender["pinned_sig"], envelope["signature"], normalize_message)


def verify_brief(envelope: dict[str, Any]) -> dict[str, Any]:
    verify_handoff_envelope(envelope)
    m = envelope["message"]
    if m["kind"] != "brief":
        fail("expected original brief")
    packet_raw = b64(m["policy"])
    packet = parse_json(packet_raw, MAX_POLICY)
    exact_fields(packet, PACKET)
    signed_review = packet["review"]
    validate_manifest(signed_review)
    policy = b64(packet["policy"])
    review = signed_review["manifest"]
    if not policy or commitment(policy) != review["policy_hash"]:
        fail("private policy commitment mismatch")
    terms = m["terms"]
    reg = terms["registration"]
    expected_id = invitation_id(signed_review, terms["provider"])
    if reg["source"] != "local-dao-review" or reg["objective"]["objective_id"] != "dao-review:" + review["id"] or reg["objective"]["owner_pseudonym"] != review["coordinator"]["pinned_sig"] or terms["id"] != expected_id or terms["buyer"] != review["coordinator"] or terms["provider"] not in review["reviewers"] or terms["expires_at"] != review["expires_at"] or commitment(b64(m["content"])) != review["evidence_hash"]:
        fail("brief does not match proposal commitments or participants")
    return signed_review


def verify_handoff_decision(encoded: str, signed_review: dict[str, Any]) -> dict[str, Any]:
    raw = b64(encoded)
    if len(raw) > MAX_CONTENT:
        fail("decision exceeds content limit")
    decision = parse_json(raw, MAX_CONTENT)
    verify_decision(decision, signed_review)
    return decision


def envelope_hash(envelope: dict[str, Any]) -> str:
    return hash_typed(envelope, normalize_envelope)


def verify_record(brief: dict[str, Any], deliver: dict[str, Any]) -> None:
    review = verify_brief(brief)
    verify_handoff_envelope(deliver)
    bmsg, dmsg = brief["message"], deliver["message"]
    decision = verify_handoff_decision(base64.b64encode(b64(dmsg["content"])).decode("ascii"), review)
    d = decision["decision"]
    if dmsg["terms"] != bmsg["terms"] or dmsg["sequence"] != 2 or dmsg["kind"] != "deliver" or dmsg["previous"] != envelope_hash(brief) or dmsg["terms"]["provider"] != d["reviewer"] or d["handoff_id"] != bmsg["terms"]["id"] or d["brief_hash"] != envelope_hash(brief):
        fail("decision deliver does not bind the exact invitation/brief chain")


def run_case(name: str, expected: str, fn) -> tuple[bool, str]:
    try:
        actual = fn()
        if expected == "reject":
            return False, "accepted unexpectedly"
        return True, "accepted"
    except (Invalid, KeyError, TypeError, ValueError, OverflowError) as exc:
        if expected == "reject":
            return True, f"rejected ({exc})"
        return False, f"rejected unexpectedly ({exc})"


def ed25519_self_test() -> None:
    # RFC 8032 §7.1, TEST 1 (empty message).
    public_key = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    signature = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    if not ed_verify(public_key, b"", signature):
        fail("internal Ed25519 self-test failed (RFC 8032 TEST 1)")
    bad_signature = bytearray(signature)
    bad_signature[0] ^= 1
    if ed_verify(public_key, b"", bytes(bad_signature)):
        fail("internal Ed25519 negative self-test failed")


def replay_certificate_file(path: pathlib.Path, verbose: bool) -> tuple[int, int]:
    data = parse_json(path.read_bytes(), 2 << 20)
    if data.get("format") != "spore/dao-review/conformance/v1":
        fail("wrong certificate vector format")
    fixture = data["fixture"]
    manifest = parse_json(fixture["manifest_canonical_json"].encode(), 64 << 10)
    if go_json(normalize_manifest(manifest)).decode() != fixture["manifest_canonical_json"]:
        fail("fixture canonical manifest mismatch")
    signing_input = (MANIFEST_DOMAIN + "\0").encode() + go_json(normalize_manifest(manifest))
    if signing_input.hex() != fixture["manifest_signing_input_hex"]:
        fail("fixture signing input mismatch")
    review = {"domain": MANIFEST_DOMAIN, "manifest": manifest,
              "signature": data["vectors"][0]["certificate_base64"]}
    # Use the actual signed review in the first certificate; fixture anchors must match it.
    first_cert = parse_json(b64(data["vectors"][0]["certificate_base64"]), MAX_CERTIFICATE)
    review = first_cert["review"]
    if review_hash(review) != fixture["review_hash"]:
        fail("fixture review hash mismatch")
    if go_json(normalize_manifest(review["manifest"])).decode() != fixture["manifest_canonical_json"]:
        fail("certificate manifest differs from fixture manifest")
    passed = 0
    for vector in data["vectors"]:
        def check(v=vector):
            cert = parse_json(b64(v["certificate_base64"]), MAX_CERTIFICATE)
            count = verify_certificate(cert, v["expected_review_hash"], v["now"])
            if v["expect"] == "accept" and count != v.get("approvals"):
                fail(f"approval count {count} != expected {v.get('approvals')}")
        ok, note = run_case(vector["name"], vector["expect"], check)
        if not ok:
            print(f"FAIL certificate/{vector['name']}: {note}")
        elif verbose:
            print(f"PASS certificate/{vector['name']}: {note}")
        passed += int(ok)
    return passed, len(data["vectors"])


def replay_handoff_file(path: pathlib.Path, verbose: bool) -> tuple[int, int]:
    data = parse_json(path.read_bytes(), 4 << 20)
    if data.get("format") != "spore/dao-review/handoff-conformance/v1":
        fail("wrong handoff vector format")
    passed = total = 0
    for vector in data["briefs"]:
        def check(v=vector):
            verify_brief(decode_envelope(v["brief_base64"])[0])
        ok, note = run_case("brief/" + vector["name"], vector["expect"], check)
        if not ok: print(f"FAIL brief/{vector['name']}: {note}")
        elif verbose: print(f"PASS brief/{vector['name']}: {note}")
        passed += int(ok); total += 1
    for vector in data["decisions"]:
        def check(v=vector):
            review = verify_brief(decode_envelope(v["brief_base64"])[0])
            verify_handoff_decision(v["decision_base64"], review)
        ok, note = run_case("decision/" + vector["name"], vector["expect"], check)
        if not ok: print(f"FAIL decision/{vector['name']}: {note}")
        elif verbose: print(f"PASS decision/{vector['name']}: {note}")
        passed += int(ok); total += 1
    for vector in data["records"]:
        def check(v=vector):
            brief = decode_envelope(v["brief_base64"])[0]
            deliver = decode_envelope(v["deliver_base64"])[0]
            verify_record(brief, deliver)
        ok, note = run_case("record/" + vector["name"], vector["expect"], check)
        if not ok: print(f"FAIL record/{vector['name']}: {note}")
        elif verbose: print(f"PASS record/{vector['name']}: {note}")
        passed += int(ok); total += 1
    return passed, total


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vectors-dir", type=pathlib.Path, default=VECTOR_DIR,
                        help="directory containing the two checked-in vector JSON files")
    parser.add_argument("-v", "--verbose", action="store_true", help="print each vector result")
    args = parser.parse_args()
    try:
        ed25519_self_test()
        cert_ok, cert_total = replay_certificate_file(args.vectors_dir / CERT_FILE, args.verbose)
        handoff_ok, handoff_total = replay_handoff_file(args.vectors_dir / HANDOFF_FILE, args.verbose)
    except (OSError, Invalid, KeyError, TypeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    total_ok, total = cert_ok + handoff_ok, cert_total + handoff_total
    print(f"DAO review vectors: {total_ok}/{total} passed ({cert_ok}/{cert_total} certificates, {handoff_ok}/{handoff_total} handoff)")
    return 0 if total_ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
