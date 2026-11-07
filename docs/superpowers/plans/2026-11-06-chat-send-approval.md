# Chat Send Approval Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a hardened bridge skip the native send dialog only when an enrolled Ed25519 public key verifies a signature over the exact previewed message, and keep every other send on the native dialog.

**Architecture:** `send_gate.py` continues to mint and atomically consume the 60-second nonce. A new verify-only module checks an optional `chat_approval` object against a root-owned config. `helper.py` calls that check only when the request contains `chat_approval`; otherwise it calls `_run_send_confirmation` as it does today. No code in this plan signs with an owner key or contacts a Grok endpoint.

**Tech Stack:** Python 3.9+ stdlib, existing `unittest` suite, `./tools/test.sh v1.4.8`. Ed25519 verify is pure Python (RFC 8032). No new package.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-11-06-chat-send-approval-design.md`. Follow it. Do not widen it.
- Protocol version becomes `1.3`. `HELPER_VERSION` stays `1.4.8`. Skill frontmatter stays `1.4.8`. `shared-core.json` `identity.helper_version` stays `1.4.8`.
- Audience string is `grokbot-imessage-send`. Statement version is `grokbot-imessage-send-approval-v1`. Nonce TTL stays `60`.
- Config path is `/Library/Application Support/GrokBotIMessage/users/<uid>/config/chat_approval.json`. No environment variable may select another path.
- Chat verification runs only when `COWORK_IMESSAGE_REQUIRE_ROOT_POLICY` is `1` and `load_config(..., require_root=True)` accepts the file.
- A request that omits `chat_approval` uses the native dialog, including when other fields say `approval: true` or the body is `Send it`.
- A present `chat_approval` that fails verification does not call `_run_send_confirmation` and does not call `_run_osascript`.
- Blocklist, group-id rejection, and send-policy behavior stay as they are. `action_send` does not start consulting the read allowlist.
- Do not add a sign function or a private key to `bin/`. `tests/ed25519_signer.py` is the only signer, and it is not installed.
- Do not invent a Grok URL, card, or header. Do not send a message, run an installer on a Mac, or edit a jeffhuber repository.
- Update this fork's `shared-core.json` hashes for files this plan edits. Do not add the new modules to that manifest. `helper.py` and `send_gate.py` edits fail `check_shared_core.py` until Task 8 writes the new digests. Run `./tools/test.sh v1.4.8` after Task 8.
- Reason tokens are `not-hardened`, `not-enrolled`, `disabled`, `invalid-config`, `malformed-approval`, `unknown-key`, `revoked`, `bad-signature`, `audit-failed`. The helper error is `chat approval rejected: <reason>`.

---

### Task 1: Ed25519 verify

**Files:**
- Create: `bin/ed25519_verify.py`
- Create: `tests/ed25519_signer.py`
- Test: `tests/test_ed25519_verify.py`

**Interfaces:**
- Consumes: nothing
- Produces: `verify(public_key: bytes, message: bytes, signature: bytes) -> bool` on the loaded `ed25519_verify` module
- Produces underscored curve helpers used by the test signer: `_B`, `_L`, `_bit`, `_encodeint`, `_encodepoint`, `_hint`, `_scalarmult`, `_sha512`
- Produces `tests/ed25519_signer.sign(message: bytes, seed: bytes) -> tuple[bytes, bytes]` returning `(signature, public_key)`

- [ ] **Step 1: Write the failing test**

Create `tests/test_ed25519_verify.py`:

```python
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Ed25519VerifyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verify_mod = _load(
            "ed25519_verify", REPO_ROOT / "bin" / "ed25519_verify.py"
        )
        self.signer = _load(
            "ed25519_signer", REPO_ROOT / "tests" / "ed25519_signer.py"
        )

    def test_rfc8032_vector_empty_message(self) -> None:
        seed = bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        )
        signature, public = self.signer.sign(b"", seed)
        self.assertEqual(
            public.hex(),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        )
        self.assertEqual(
            signature.hex(),
            "e5564300c360ac729086e2cc806e828a"
            "84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46b"
            "d25bf5f0595bbe24655141438e7a100b",
        )
        self.assertTrue(self.verify_mod.verify(public, b"", signature))

    def test_rfc8032_vector_single_byte(self) -> None:
        seed = bytes.fromhex(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
        )
        message = bytes.fromhex("72")
        signature, public = self.signer.sign(message, seed)
        self.assertEqual(
            public.hex(),
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        )
        self.assertTrue(self.verify_mod.verify(public, message, signature))
        self.assertFalse(self.verify_mod.verify(public, b"R", signature))

    def test_rejects_short_and_flipped_signatures(self) -> None:
        _signature, public = self.signer.sign(b"payload", b"\x11" * 32)
        self.assertFalse(self.verify_mod.verify(public, b"payload", b"\x00" * 63))
        signature, _public = self.signer.sign(b"payload", b"\x11" * 32)
        flipped = signature[:-1] + bytes([signature[-1] ^ 0x01])
        self.assertFalse(self.verify_mod.verify(public, b"payload", flipped))

    def test_production_module_has_no_sign_function(self) -> None:
        source = (REPO_ROOT / "bin" / "ed25519_verify.py").read_text(encoding="utf-8")
        self.assertNotIn("\ndef sign(", source)
        self.assertNotIn("PRIVATE", source)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_ed25519_verify -v`

Expected: FAIL while importing `bin/ed25519_verify.py` (file missing).

- [ ] **Step 3: Write minimal implementation**

Create `bin/ed25519_verify.py` with this verify-only module. These point helpers are what `tests/ed25519_signer.py` calls. There is no `sign` function here.

```python
"""RFC 8032 pure Ed25519 verification.

``verify`` is the only production entry point. This file holds no private key
and does not sign.
"""

from __future__ import annotations

import hashlib

_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_B_BITS = 256


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _inv(value: int) -> int:
    return pow(value, _Q - 2, _Q)


_D = (-121665 * _inv(121666)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _xrecover(y_coord: int) -> int:
    xx = (y_coord * y_coord - 1) * _inv(_D * y_coord * y_coord + 1) % _Q
    x_coord = pow(xx, (_Q + 3) // 8, _Q)
    if (x_coord * x_coord - xx) % _Q != 0:
        x_coord = (x_coord * _I) % _Q
    if x_coord % 2 != 0:
        x_coord = _Q - x_coord
    return x_coord


_BY = (4 * _inv(5)) % _Q
_BX = _xrecover(_BY)
_B = [_BX % _Q, _BY % _Q]


def _edwards(point_p: list[int], point_q: list[int]) -> list[int]:
    x1, y1 = point_p
    x2, y2 = point_q
    product = _D * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + product)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - product)
    return [x3 % _Q, y3 % _Q]


def _scalarmult(point: list[int], scalar: int) -> list[int]:
    result = [0, 1]
    current = point
    while scalar:
        if scalar & 1:
            result = _edwards(result, current)
        current = _edwards(current, current)
        scalar >>= 1
    return result


def _encodeint(value: int) -> bytes:
    return value.to_bytes(_B_BITS // 8, "little")


def _encodepoint(point: list[int]) -> bytes:
    x_coord, y_coord = point
    packed = y_coord | ((x_coord & 1) << (_B_BITS - 1))
    return packed.to_bytes(_B_BITS // 8, "little")


def _bit(digest: bytes, index: int) -> int:
    return (digest[index // 8] >> (index % 8)) & 1


def _hint(message: bytes) -> int:
    digest = _sha512(message)
    return sum(2**i * _bit(digest, i) for i in range(2 * _B_BITS))


def _isoncurve(point: list[int]) -> bool:
    x_coord, y_coord = point
    return (-x_coord * x_coord + y_coord * y_coord - 1 - _D * x_coord * x_coord * y_coord * y_coord) % _Q == 0


def _decodeint(data: bytes) -> int:
    return int.from_bytes(data, "little")


def _decodepoint(data: bytes) -> list[int]:
    y_coord = int.from_bytes(data, "little") & ((1 << (_B_BITS - 1)) - 1)
    if y_coord >= _Q:
        raise ValueError("non-canonical y")
    x_coord = _xrecover(y_coord)
    if (x_coord & 1) != (data[31] >> 7):
        x_coord = _Q - x_coord
    point = [x_coord, y_coord]
    if not _isoncurve(point):
        raise ValueError("point not on curve")
    return point


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Return True when ``signature`` is a valid Ed25519 signature."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        encoded_r = _decodepoint(signature[:32])
        encoded_a = _decodepoint(public_key)
        scalar_s = _decodeint(signature[32:])
        if scalar_s >= _L:
            return False
        challenge = _hint(signature[:32] + public_key + message)
        return _scalarmult(_B, scalar_s) == _edwards(
            encoded_r, _scalarmult(encoded_a, challenge)
        )
    except Exception:
        return False
```

Create `tests/ed25519_signer.py`:

```python
"""Test-only Ed25519 signer.

Not installed, not imported by the helper, and not an owner key.
"""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

_MODULE = None


def _verify_module():
    global _MODULE
    if _MODULE is None:
        path = Path(__file__).resolve().parent.parent / "bin" / "ed25519_verify.py"
        spec = importlib.util.spec_from_file_location("ed25519_verify_for_tests", path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"cannot load {path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _MODULE = module
    return _MODULE


def sign(message: bytes, seed: bytes) -> tuple[bytes, bytes]:
    """Return ``(signature, public_key)`` for a 32-byte seed."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    module = _verify_module()
    digest = hashlib.sha512(seed).digest()
    scalar = 2 ** (module._B_BITS - 2) + sum(
        2**i * module._bit(digest, i) for i in range(3, module._B_BITS - 2)
    )
    public = module._encodepoint(module._scalarmult(module._B, scalar))
    nonce = module._hint(digest[32:64] + message)
    encoded_r = module._encodepoint(module._scalarmult(module._B, nonce))
    challenge = module._hint(encoded_r + public + message)
    scalar_s = (nonce + challenge * scalar) % module._L
    return encoded_r + module._encodeint(scalar_s), public
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_ed25519_verify -v`

Expected: PASS for all four tests.

- [ ] **Step 5: Commit**

```bash
git add bin/ed25519_verify.py tests/ed25519_signer.py tests/test_ed25519_verify.py
git commit -m "Add verify-only Ed25519 checked against RFC 8032 vectors"
```

---

### Task 2: Canonical statement and in-memory verification

**Files:**
- Create: `bin/chat_approval.py`
- Test: `tests/test_chat_approval.py`

**Interfaces:**
- Consumes: `ed25519_verify.verify`
- Produces:
  - `ChatApprovalError` with `.reason: str`
  - `AUDIENCE = "grokbot-imessage-send"`
  - `STATEMENT_VERSION = "grokbot-imessage-send-approval-v1"`
  - `canonical_statement(*, pending_id: str, expires_at: int, installation_id: str, service: str, recipient: str, body: str) -> bytes`
  - `verify_request(config: dict, *, approval, pending_id, expires_at: int, service: str, recipient: str, body: str, now: int) -> None`
  - `preview_approval(config: dict, *, pending_id: str, expires_at: int, service: str, recipient: str, body: str) -> dict`
  - `audit_event(*, result: str, reason: str, pending_id, recipient: str, body: str, service: str, key_id) -> dict`
  - `default_config_path(uid: int | None = None) -> Path`
  - `load_config(path: Path, *, require_root: bool = True) -> dict` (filesystem behavior is Task 3; this task only needs the function to exist by the end of Task 3)

- [ ] **Step 1: Write the failing test**

Create `tests/test_chat_approval.py` with the loader, the sample config builder, and these tests. Keep the file, and append the later tasks' tests to it.

```python
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from tests._helper_loader import REPO_ROOT, helper
from tests.ed25519_signer import sign


def _load_chat():
    path = REPO_ROOT / "bin" / "chat_approval.py"
    spec = importlib.util.spec_from_file_location("chat_approval", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _config(public_key: bytes, *, enabled: bool = True, status: str = "active") -> dict:
    return {
        "version": 1,
        "enabled": enabled,
        "audience": "grokbot-imessage-send",
        "installation_id": "ab" * 32,
        "keys": [
            {
                "key_id": "owner-2026-11",
                "public_key": base64.b64encode(public_key).decode("ascii"),
                "status": status,
            }
        ],
    }


class StatementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.chat = _load_chat()
        self.seed = b"\x42" * 32
        self.signature, self.public = sign(b"unused", self.seed)
        self.body = "Confirmed for 3pm."
        self.fields = {
            "pending_id": "pending-example",
            "expires_at": 1762400000,
            "installation_id": "ab" * 32,
            "service": "iMessage",
            "recipient": "+14155551234",
            "body": self.body,
        }

    def _approval_for(self, **overrides) -> dict:
        fields = dict(self.fields)
        fields.update(overrides)
        statement = self.chat.canonical_statement(**fields)
        signature, public = sign(statement, self.seed)
        self.public = public
        return {
            "key_id": "owner-2026-11",
            "signature": base64.b64encode(signature).decode("ascii"),
        }

    def test_worked_example_hashes(self) -> None:
        statement = self.chat.canonical_statement(**self.fields)
        self.assertEqual(
            hashlib.sha256(self.body.encode("utf-8")).hexdigest(),
            "7dc97dc29dc2ec4081b1d539b6985b6dcc6b5b4d4ecd0515968b42795b914cd2",
        )
        self.assertEqual(
            hashlib.sha256(statement).hexdigest(),
            "356c86b8941e291b185afaa11dd262c282c4a9887e3d6fdc748bb5a27014f515",
        )
        self.assertTrue(statement.endswith(b"\n"))
        self.assertEqual(statement.count(b"\n"), 8)

    def _verify(self, approval, config, **overrides) -> None:
        fields = dict(self.fields)
        fields.update(overrides)
        self.chat.verify_request(
            config,
            approval=approval,
            pending_id=fields["pending_id"],
            expires_at=fields["expires_at"],
            service=fields["service"],
            recipient=fields["recipient"],
            body=fields["body"],
            now=1762400000,
        )

    def test_matching_signature_is_accepted(self) -> None:
        approval = self._approval_for()
        self._verify(approval, _config(self.public))

    def test_tampered_statement_fields_are_bad_signature(self) -> None:
        approval = self._approval_for()
        config = _config(self.public)
        cases = {
            "body": {"body": "Confirmed for 4pm."},
            "recipient": {"recipient": "+14155551235"},
            "service": {"service": "SMS"},
            "pending_id": {"pending_id": "other-pending"},
            "expires_at": {"expires_at": 1762400001},
        }
        for name, override in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(self.chat.ChatApprovalError) as caught:
                    self._verify(approval, config, **override)
                self.assertEqual(caught.exception.reason, "bad-signature")
        moved = _config(self.public)
        moved["installation_id"] = "cd" * 32
        with self.assertRaises(self.chat.ChatApprovalError) as caught:
            self._verify(approval, moved)
        self.assertEqual(caught.exception.reason, "bad-signature")

    def test_wrong_audience_bytes_are_bad_signature(self) -> None:
        forged = (
            "grokbot-imessage-send-approval-v1\n"
            "pending_id:pending-example\n"
            "expires_at:1762400000\n"
            "audience:other-audience\n"
            "installation_id:" + ("ab" * 32) + "\n"
            "service:iMessage\n"
            "recipient:+14155551234\n"
            "body_sha256:"
            + hashlib.sha256(self.body.encode("utf-8")).hexdigest()
            + "\n"
        ).encode("utf-8")
        signature, public = sign(forged, self.seed)
        approval = {
            "key_id": "owner-2026-11",
            "signature": base64.b64encode(signature).decode("ascii"),
        }
        with self.assertRaises(self.chat.ChatApprovalError) as caught:
            self.chat.verify_request(
                _config(public), approval=approval, now=1762400000, **self.fields
            )
        self.assertEqual(caught.exception.reason, "bad-signature")

    def test_revoked_and_unknown_keys(self) -> None:
        approval = self._approval_for()
        with self.assertRaises(self.chat.ChatApprovalError) as revoked:
            self.chat.verify_request(
                _config(self.public, status="revoked"),
                approval=approval,
                now=1762400000,
                **self.fields,
            )
        self.assertEqual(revoked.exception.reason, "revoked")
        approval["key_id"] = "someone-else"
        with self.assertRaises(self.chat.ChatApprovalError) as unknown:
            self.chat.verify_request(
                _config(self.public),
                approval=approval,
                now=1762400000,
                **self.fields,
            )
        self.assertEqual(unknown.exception.reason, "unknown-key")

    def test_malformed_approval_object(self) -> None:
        for approval in (True, "Send it", {}, {"key_id": "owner-2026-11"}, {"signature": "aa", "key_id": "owner-2026-11", "extra": 1}):
            with self.subTest(approval=approval):
                with self.assertRaises(self.chat.ChatApprovalError) as caught:
                    self.chat.verify_request(
                        _config(self.public),
                        approval=approval,
                        now=1762400000,
                        **self.fields,
                    )
                self.assertEqual(caught.exception.reason, "malformed-approval")

    def test_preview_descriptor_when_enabled(self) -> None:
        approval = self._approval_for()
        descriptor = self.chat.preview_approval(
            _config(self.public),
            pending_id=self.fields["pending_id"],
            expires_at=self.fields["expires_at"],
            service=self.fields["service"],
            recipient=self.fields["recipient"],
            body=self.fields["body"],
        )
        self.assertEqual(descriptor["mode"], "chat_signature")
        self.assertEqual(descriptor["pending_id"], "pending-example")
        self.assertEqual(descriptor["expires_at"], 1762400000)
        self.assertEqual(descriptor["audience"], "grokbot-imessage-send")
        self.assertEqual(
            descriptor["canonical_sha256"],
            "356c86b8941e291b185afaa11dd262c282c4a9887e3d6fdc748bb5a27014f515",
        )
        self.assertNotIn("signature", descriptor)

    def test_preview_descriptor_when_disabled(self) -> None:
        self.assertEqual(
            self.chat.preview_approval(
                _config(self.public, enabled=False),
                pending_id=self.fields["pending_id"],
                expires_at=self.fields["expires_at"],
                service=self.fields["service"],
                recipient=self.fields["recipient"],
                body=self.fields["body"],
            ),
            {"mode": "native"},
        )

    def test_audit_event_hashes_recipient_and_body(self) -> None:
        event = self.chat.audit_event(
            result="rejected",
            reason="bad-signature",
            pending_id="pending-example",
            recipient="+14155551234",
            body=self.body,
            service="iMessage",
            key_id="owner-2026-11",
        )
        encoded = json.dumps(event)
        self.assertNotIn("+14155551234", encoded)
        self.assertNotIn(self.body, encoded)
        self.assertEqual(
            event["recipient_sha256"],
            hashlib.sha256(b"+14155551234").hexdigest(),
        )
        self.assertEqual(event["service"], "iMessage")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_chat_approval.StatementTests -v`

Expected: FAIL while importing `bin/chat_approval.py`.

- [ ] **Step 3: Write minimal implementation**

Create `bin/chat_approval.py` with the statement, verifier, preview descriptor, and audit-event helper. Include `load_config`, `status_descriptor`, and `append_audit` in this same file so later tasks only extend tests; their behavior is specified here and covered in Tasks 3 and 5.

```python
"""Opt-in chat-approval verifier.

The helper calls this after a nonce consume when the request contains
``chat_approval``. This module does not sign and does not choose a config
path from the environment.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import re
import stat
import time
from pathlib import Path

AUDIENCE = "grokbot-imessage-send"
STATEMENT_VERSION = "grokbot-imessage-send-approval-v1"
_KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_INSTALLATION_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_KEYS = 8
_AUDIT_MAX_BYTES = 256 * 1024
_AUDIT_KEEP_LINES = 100
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_NOFOLLOW | os.O_CLOEXEC


class ChatApprovalError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _load_verify():
    sibling = Path(__file__).parent / "ed25519_verify.py"
    own = os.lstat(__file__)
    try:
        metadata = os.lstat(sibling)
    except OSError as exc:
        raise ChatApprovalError("invalid-config") from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ChatApprovalError("invalid-config")
    if metadata.st_uid != own.st_uid:
        raise ChatApprovalError("invalid-config")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ChatApprovalError("invalid-config")
    spec = importlib.util.spec_from_file_location("ed25519_verify", sibling)
    if spec is None or spec.loader is None:
        raise ChatApprovalError("invalid-config")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.verify


_ed25519_verify = _load_verify()


def default_config_path(uid: int | None = None) -> Path:
    owner = os.getuid() if uid is None else uid
    return (
        Path("/Library/Application Support/GrokBotIMessage")
        / "users"
        / str(owner)
        / "config"
        / "chat_approval.json"
    )


def canonical_statement(
    *,
    pending_id: str,
    expires_at: int,
    installation_id: str,
    service: str,
    recipient: str,
    body: str,
) -> bytes:
    if not isinstance(pending_id, str) or not pending_id or "\n" in pending_id:
        raise ChatApprovalError("malformed-approval")
    if isinstance(expires_at, bool) or not isinstance(expires_at, int):
        raise ChatApprovalError("malformed-approval")
    if not isinstance(installation_id, str) or _INSTALLATION_RE.fullmatch(installation_id) is None:
        raise ChatApprovalError("invalid-config")
    if service not in ("iMessage", "SMS"):
        raise ChatApprovalError("malformed-approval")
    if not isinstance(recipient, str) or "\n" in recipient:
        raise ChatApprovalError("malformed-approval")
    if not isinstance(body, str):
        raise ChatApprovalError("malformed-approval")
    body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
    text = (
        f"{STATEMENT_VERSION}\n"
        f"pending_id:{pending_id}\n"
        f"expires_at:{expires_at}\n"
        f"audience:{AUDIENCE}\n"
        f"installation_id:{installation_id}\n"
        f"service:{service}\n"
        f"recipient:{recipient}\n"
        f"body_sha256:{body_hash}\n"
    )
    return text.encode("utf-8")


def _b64_32(value: str, reason: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ChatApprovalError(reason) from exc
    if len(decoded) != 32:
        raise ChatApprovalError(reason)
    return decoded


def load_config(path: Path, *, require_root: bool = True) -> dict:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ChatApprovalError("not-enrolled") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ChatApprovalError("invalid-config")
    if require_root and metadata.st_uid != 0:
        raise ChatApprovalError("invalid-config")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ChatApprovalError("invalid-config")
    try:
        fd = os.open(path, os.O_RDONLY | _FILE_FLAGS)
    except OSError as exc:
        raise ChatApprovalError("invalid-config") from exc
    try:
        chunks = []
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            chunks.append(block)
            if sum(len(part) for part in chunks) > 65536:
                raise ChatApprovalError("invalid-config")
    finally:
        os.close(fd)
    try:
        parsed = json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ChatApprovalError("invalid-config") from exc
    if not isinstance(parsed, dict):
        raise ChatApprovalError("invalid-config")
    if parsed.get("version") != 1 or parsed.get("audience") != AUDIENCE:
        raise ChatApprovalError("invalid-config")
    if not isinstance(parsed.get("enabled"), bool):
        raise ChatApprovalError("invalid-config")
    installation_id = parsed.get("installation_id")
    if not isinstance(installation_id, str) or _INSTALLATION_RE.fullmatch(installation_id) is None:
        raise ChatApprovalError("invalid-config")
    keys = parsed.get("keys")
    if not isinstance(keys, list) or len(keys) > _MAX_KEYS:
        raise ChatApprovalError("invalid-config")
    seen = set()
    for key in keys:
        if not isinstance(key, dict) or set(key) != {"key_id", "public_key", "status"}:
            raise ChatApprovalError("invalid-config")
        key_id = key["key_id"]
        if not isinstance(key_id, str) or _KEY_ID_RE.fullmatch(key_id) is None or key_id in seen:
            raise ChatApprovalError("invalid-config")
        seen.add(key_id)
        if key["status"] not in ("active", "revoked"):
            raise ChatApprovalError("invalid-config")
        if not isinstance(key["public_key"], str):
            raise ChatApprovalError("invalid-config")
        _b64_32(key["public_key"], "invalid-config")
    return parsed


def verify_request(
    config: dict,
    *,
    approval,
    pending_id,
    expires_at: int,
    service: str,
    recipient: str,
    body: str,
    now: int,
) -> None:
    if not isinstance(config, dict) or config.get("enabled") is not True:
        raise ChatApprovalError("disabled")
    if config.get("audience") != AUDIENCE:
        raise ChatApprovalError("invalid-config")
    if not isinstance(approval, dict) or set(approval) != {"key_id", "signature"}:
        raise ChatApprovalError("malformed-approval")
    key_id = approval["key_id"]
    signature_text = approval["signature"]
    if not isinstance(key_id, str) or not isinstance(signature_text, str):
        raise ChatApprovalError("malformed-approval")
    if isinstance(expires_at, bool) or not isinstance(expires_at, int) or int(now) > expires_at:
        raise ChatApprovalError("bad-signature")
    matches = [item for item in config.get("keys", []) if item.get("key_id") == key_id]
    if not matches:
        raise ChatApprovalError("unknown-key")
    if matches[0].get("status") != "active":
        raise ChatApprovalError("revoked")
    try:
        signature = base64.b64decode(signature_text, validate=True)
    except Exception as exc:
        raise ChatApprovalError("malformed-approval") from exc
    if len(signature) != 64:
        raise ChatApprovalError("malformed-approval")
    public = _b64_32(matches[0]["public_key"], "invalid-config")
    statement = canonical_statement(
        pending_id=pending_id,
        expires_at=expires_at,
        installation_id=config["installation_id"],
        service=service,
        recipient=recipient,
        body=body,
    )
    if not _ed25519_verify(public, statement, signature):
        raise ChatApprovalError("bad-signature")


def preview_approval(
    config: dict,
    *,
    pending_id: str,
    expires_at: int,
    service: str,
    recipient: str,
    body: str,
) -> dict:
    active = [
        item for item in config.get("keys", [])
        if isinstance(item, dict) and item.get("status") == "active"
    ]
    if config.get("enabled") is not True or not active:
        return {"mode": "native"}
    statement = canonical_statement(
        pending_id=pending_id,
        expires_at=expires_at,
        installation_id=config["installation_id"],
        service=service,
        recipient=recipient,
        body=body,
    )
    return {
        "mode": "chat_signature",
        "statement_version": STATEMENT_VERSION,
        "audience": AUDIENCE,
        "installation_id": config["installation_id"],
        "pending_id": pending_id,
        "expires_at": expires_at,
        "canonical_sha256": hashlib.sha256(statement).hexdigest(),
    }


def status_descriptor(path: Path) -> dict:
    try:
        config = load_config(path, require_root=True)
    except ChatApprovalError as exc:
        if exc.reason == "not-enrolled":
            return {"enrolled": False, "enabled": False, "mode": "native"}
        return {
            "enrolled": False,
            "enabled": False,
            "mode": "native",
            "reason": "invalid-config",
        }
    active = [item["key_id"] for item in config["keys"] if item["status"] == "active"]
    enabled = config["enabled"] is True and bool(active)
    return {
        "enrolled": True,
        "enabled": enabled,
        "mode": "chat_signature" if enabled else "native",
        "active_key_ids": active,
    }


def audit_event(
    *,
    result: str,
    reason: str,
    pending_id,
    recipient: str,
    body: str,
    service: str,
    key_id,
) -> dict:
    def digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    pending = pending_id if isinstance(pending_id, str) else ""
    return {
        "ts": int(time.time()),
        "result": result,
        "reason": reason,
        "pending_id_sha256": digest(pending),
        "recipient_sha256": digest(recipient),
        "body_sha256": digest(body),
        "service": service,
        "key_id": key_id if isinstance(key_id, str) else "",
    }


def _open_private_dir(root: Path, child: str) -> int:
    if not root.is_absolute():
        raise ChatApprovalError("audit-failed")
    fd = os.open("/", _DIR_FLAGS)
    try:
        for part in root.parts[1:]:
            nxt = os.open(part, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nxt
        metadata = os.fstat(fd)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise ChatApprovalError("audit-failed")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ChatApprovalError("audit-failed")
        control = os.open(child, _DIR_FLAGS, dir_fd=fd)
    except ChatApprovalError:
        os.close(fd)
        raise
    except OSError as exc:
        os.close(fd)
        raise ChatApprovalError("audit-failed") from exc
    os.close(fd)
    info = os.fstat(control)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        os.close(control)
        raise ChatApprovalError("audit-failed")
    return control


def append_audit(bridge: Path, event: dict) -> None:
    if not isinstance(event, dict):
        raise ChatApprovalError("audit-failed")
    line = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    directory = _open_private_dir(bridge, "control")
    name = "chat_approval_audit.jsonl"
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | _FILE_FLAGS
        fd = os.open(name, flags, 0o600, dir_fd=directory)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise ChatApprovalError("audit-failed")
            os.write(fd, line)
            size = os.fstat(fd).st_size
        finally:
            os.close(fd)
        if size <= _AUDIT_MAX_BYTES:
            return
        read_fd = os.open(name, os.O_RDONLY | _FILE_FLAGS, dir_fd=directory)
        try:
            payload = os.read(read_fd, size + 1)
        finally:
            os.close(read_fd)
        kept = b"\n".join(payload.splitlines()[-_AUDIT_KEEP_LINES]) + b"\n"
        tmp = f".{name}.{time.time_ns()}.tmp"
        tmp_fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _FILE_FLAGS, 0o600, dir_fd=directory)
        try:
            os.write(tmp_fd, kept)
        finally:
            os.close(tmp_fd)
        os.replace(tmp, name, src_dir_fd=directory, dst_dir_fd=directory)
    except ChatApprovalError:
        raise
    except OSError as exc:
        raise ChatApprovalError("audit-failed") from exc
    finally:
        os.close(directory)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_chat_approval.StatementTests tests.test_ed25519_verify -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add bin/chat_approval.py tests/test_chat_approval.py
git commit -m "Verify chat approvals against the canonical statement"
```

---

### Task 3: Config file checks

**Files:**
- Modify: `tests/test_chat_approval.py`
- Modify: `bin/chat_approval.py` only if a Task 3 test fails against the Task 2 loader

**Interfaces:**
- Consumes: `load_config`, `status_descriptor`, `default_config_path`
- Produces: the same functions, proven against owner, mode, symlink, and malformed JSON

- [ ] **Step 1: Write the failing test**

Append `ConfigTests` to `tests/test_chat_approval.py`:

```python
class ConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.chat = _load_chat()
        self.tmp = tempfile.TemporaryDirectory(prefix="chat-approval-config-")
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "chat_approval.json"
        self.public = b"\x03" * 32
        self.doc = _config(self.public)

    def _write(self, payload, mode=0o600) -> None:
        text = payload if isinstance(payload, str) else json.dumps(payload)
        self.path.write_text(text, encoding="utf-8")
        self.path.chmod(mode)

    def test_loader_accepts_private_regular_file(self) -> None:
        self._write(self.doc)
        loaded = self.chat.load_config(self.path, require_root=False)
        self.assertTrue(loaded["enabled"])
        self.assertEqual(loaded["keys"][0]["key_id"], "owner-2026-11")

    def test_wrong_mode_symlink_and_garbage_fail(self) -> None:
        self._write(self.doc, mode=0o644)
        with self.assertRaises(self.chat.ChatApprovalError) as mode:
            self.chat.load_config(self.path, require_root=False)
        self.assertEqual(mode.exception.reason, "invalid-config")
        self.path.unlink()
        self.path.symlink_to("/etc/passwd")
        with self.assertRaises(self.chat.ChatApprovalError) as link:
            self.chat.load_config(self.path, require_root=False)
        self.assertEqual(link.exception.reason, "invalid-config")
        self.path.unlink()
        self._write("{", mode=0o600)
        with self.assertRaises(self.chat.ChatApprovalError) as garbage:
            self.chat.load_config(self.path, require_root=False)
        self.assertEqual(garbage.exception.reason, "invalid-config")

    def test_bad_audience_and_string_enabled_fail(self) -> None:
        bad_audience = dict(self.doc)
        bad_audience["audience"] = "other-audience"
        self._write(bad_audience)
        with self.assertRaises(self.chat.ChatApprovalError) as audience:
            self.chat.load_config(self.path, require_root=False)
        self.assertEqual(audience.exception.reason, "invalid-config")
        bad_flag = dict(self.doc)
        bad_flag["enabled"] = "true"
        self._write(bad_flag)
        with self.assertRaises(self.chat.ChatApprovalError) as flag:
            self.chat.load_config(self.path, require_root=False)
        self.assertEqual(flag.exception.reason, "invalid-config")

    def test_missing_file_is_not_enrolled(self) -> None:
        with self.assertRaises(self.chat.ChatApprovalError) as caught:
            self.chat.load_config(self.path, require_root=False)
        self.assertEqual(caught.exception.reason, "not-enrolled")

    def test_require_root_rejects_current_user_owner(self) -> None:
        self._write(self.doc)
        with self.assertRaises(self.chat.ChatApprovalError) as caught:
            self.chat.load_config(self.path, require_root=True)
        self.assertEqual(caught.exception.reason, "invalid-config")

    def test_public_key_wrong_length_is_invalid(self) -> None:
        doc = _config(self.public)
        doc["keys"][0]["public_key"] = base64.b64encode(b"\x01" * 64).decode("ascii")
        self._write(doc)
        with self.assertRaises(self.chat.ChatApprovalError) as caught:
            self.chat.load_config(self.path, require_root=False)
        self.assertEqual(caught.exception.reason, "invalid-config")

    def test_duplicate_key_id_is_invalid(self) -> None:
        doc = _config(self.public)
        doc["keys"].append(dict(doc["keys"][0]))
        self._write(doc)
        with self.assertRaises(self.chat.ChatApprovalError) as caught:
            self.chat.load_config(self.path, require_root=False)
        self.assertEqual(caught.exception.reason, "invalid-config")

    def test_unknown_top_level_key_is_invalid(self) -> None:
        doc = dict(self.doc)
        doc["note"] = "hello"
        self._write(doc)
        with self.assertRaises(self.chat.ChatApprovalError) as caught:
            self.chat.load_config(self.path, require_root=False)
        self.assertEqual(caught.exception.reason, "invalid-config")

    def test_default_path_is_fixed(self) -> None:
        path = self.chat.default_config_path(501)
        self.assertEqual(
            str(path),
            "/Library/Application Support/GrokBotIMessage/users/501/config/chat_approval.json",
        )
        source = (REPO_ROOT / "bin" / "chat_approval.py").read_text(encoding="utf-8")
        self.assertNotIn("IMESSAGE_CHAT_APPROVAL", source)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_chat_approval.ConfigTests.test_unknown_top_level_key_is_invalid -v`

Expected: FAIL. The Task 2 loader accepts a document that contains `note`. The assertion wants `ChatApprovalError` reason `invalid-config`.

- [ ] **Step 3: Write minimal implementation**

In `load_config`, immediately after `if not isinstance(parsed, dict)`, reject any other top-level key:

```python
    if set(parsed) != {"version", "enabled", "audience", "installation_id", "keys"}:
        raise ChatApprovalError("invalid-config")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_chat_approval.ConfigTests -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add bin/chat_approval.py tests/test_chat_approval.py
git commit -m "Reject unsafe or malformed chat-approval configs"
```

---

### Task 4: Nonce expiry return and single consume

**Files:**
- Modify: `bin/send_gate.py` (`mint_send_nonce` around the record write, `consume_send_nonce` success path)
- Modify: `bin/helper.py` re-exports near `mint_send_nonce = _send_gate.mint_send_nonce`
- Test: `tests/test_chat_approval.py`

**Interfaces:**
- Consumes: existing `mint_send_nonce` / `consume_send_nonce`
- Produces:
  - `mint_send_nonce_record(to: str, body: str, service: str) -> tuple[str, int]`
  - `mint_send_nonce(...) -> str` still returns only the nonce
  - `consume_send_nonce(...) -> int` returns the stored `expires_at` after the winning claim

- [ ] **Step 1: Write the failing test**

Append `NonceTests` to `tests/test_chat_approval.py`:

```python
class NonceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="chat-approval-nonce-")
        self.addCleanup(self.tmp.cleanup)
        self.old = os.environ.get("IMESSAGE_BRIDGE_DIR")
        os.environ["IMESSAGE_BRIDGE_DIR"] = os.path.realpath(self.tmp.name)
        os.environ["COWORK_IMESSAGE_BRIDGE_DIR"] = os.environ["IMESSAGE_BRIDGE_DIR"]
        self.addCleanup(self._restore)

    def _restore(self) -> None:
        if self.old is None:
            os.environ.pop("IMESSAGE_BRIDGE_DIR", None)
        else:
            os.environ["IMESSAGE_BRIDGE_DIR"] = self.old

    def test_record_expiry_round_trips(self) -> None:
        nonce, expires_at = helper.mint_send_nonce_record("+14155551234", "hello", "iMessage")
        self.assertGreaterEqual(expires_at, int(time.time()))
        self.assertLessEqual(expires_at, int(time.time()) + helper.SEND_NONCE_TTL)
        returned = helper.consume_send_nonce(nonce, "+14155551234", "hello", "iMessage")
        self.assertEqual(returned, expires_at)

    def test_payload_mismatch_still_burns_nonce(self) -> None:
        nonce, _expires = helper.mint_send_nonce_record("+14155551234", "hello", "iMessage")
        with self.assertRaisesRegex(helper.SendGateError, "differs"):
            helper.consume_send_nonce(nonce, "+14155559876", "hello", "iMessage")
        with self.assertRaises(helper.SendGateError):
            helper.consume_send_nonce(nonce, "+14155551234", "hello", "iMessage")

    def test_concurrent_consume_has_one_winner(self) -> None:
        nonce, _expires = helper.mint_send_nonce_record("+14155551234", "hello", "SMS")
        results = []
        errors = []

        def attempt() -> None:
            try:
                results.append(
                    helper.consume_send_nonce(nonce, "+14155551234", "hello", "SMS")
                )
            except helper.SendGateError as exc:
                errors.append(str(exc))

        threads = [threading.Thread(target=attempt) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(results), 1)
        self.assertEqual(len(errors), 7)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_chat_approval.NonceTests -v`

Expected: FAIL with `mint_send_nonce_record` missing, or `consume_send_nonce` returning `None`.

- [ ] **Step 3: Write minimal implementation**

In `bin/send_gate.py`, replace `mint_send_nonce` with:

```python
def mint_send_nonce_record(to: str, body: str, service: str) -> tuple:
    """Persist a nonce bound to the payload. Return ``(nonce, expires_at)``."""
    nonce = secrets.token_urlsafe(24)
    expires_at = int(time.time()) + SEND_NONCE_TTL
    record = {
        "preview_hash": _preview_hash(to, body, service),
        "expires_at": expires_at,
    }
    name = f"{nonce}.json"
    tmp = f".{nonce}.json.tmp"
    with _nonce_dir_fd() as nonce_fd:
        fd = os.open(
            tmp,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _FILE_NOFOLLOW_FLAGS,
            0o600,
            dir_fd=nonce_fd,
        )
        try:
            _validate_nonce_file(fd, tmp)
            with os.fdopen(fd, "w") as handle:
                fd = -1
                json.dump(record, handle)
            os.replace(tmp, name, src_dir_fd=nonce_fd, dst_dir_fd=nonce_fd)
        finally:
            if fd >= 0:
                os.close(fd)
            _unlink_at(nonce_fd, tmp)
    return nonce, expires_at


def mint_send_nonce(to: str, body: str, service: str) -> str:
    nonce, _expires_at = mint_send_nonce_record(to, body, service)
    return nonce
```

On the success path of `consume_send_nonce`, after the final `_unlink_at(nonce_fd, claimed)`, return the integer expiry already validated:

```python
        _unlink_at(nonce_fd, claimed)
        return int(expires_at)
```

In `bin/helper.py`, next to the existing send-gate bindings:

```python
mint_send_nonce_record = _send_gate.mint_send_nonce_record
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_chat_approval.NonceTests tests.test_core.SendGateTests -v`

Expected: PASS. Existing replay and mismatch tests still pass.

- [ ] **Step 5: Commit**

```bash
git add bin/send_gate.py bin/helper.py tests/test_chat_approval.py
git commit -m "Return nonce expiry and keep consume single-use"
```

---

### Task 5: Helper send branch

**Files:**
- Modify: `bin/helper.py` (`action_send`, new `_load_chat_approval`, `_load_chat_approval_config`, `_authorize_chat_send`)
- Test: `tests/test_chat_approval.py`

**Interfaces:**
- Consumes: `consume_send_nonce` return value, `chat_approval.verify_request`, `chat_approval.append_audit`, `chat_approval.audit_event`
- Produces: `action_send` behavior described in the spec. Tests monkeypatch `_load_chat_approval` and `_load_chat_approval_config`. Production `_load_chat_approval_config` calls `load_config(default_config_path(), require_root=True)`.

- [ ] **Step 1: Write the failing test**

Append `HelperSendTests` to `tests/test_chat_approval.py`:

```python
class HelperSendTests(unittest.TestCase):
    def setUp(self) -> None:
        self.chat = _load_chat()
        self.tmp = tempfile.TemporaryDirectory(prefix="chat-approval-send-")
        self.addCleanup(self.tmp.cleanup)
        bridge = Path(os.path.realpath(self.tmp.name))
        (bridge / "control").mkdir(mode=0o700)
        self.old_bridge = os.environ.get("IMESSAGE_BRIDGE_DIR")
        self.old_root = os.environ.get("COWORK_IMESSAGE_REQUIRE_ROOT_POLICY")
        os.environ["IMESSAGE_BRIDGE_DIR"] = str(bridge)
        os.environ["COWORK_IMESSAGE_BRIDGE_DIR"] = str(bridge)
        os.environ["COWORK_IMESSAGE_REQUIRE_ROOT_POLICY"] = "1"
        self.addCleanup(self._restore)
        self.bridge = bridge
        self.seed = b"\x07" * 32
        self.body = "Confirmed for 3pm."
        self.recipient = "+14155551234"

    def _restore(self) -> None:
        if self.old_bridge is None:
            os.environ.pop("IMESSAGE_BRIDGE_DIR", None)
        else:
            os.environ["IMESSAGE_BRIDGE_DIR"] = self.old_bridge
        if self.old_root is None:
            os.environ.pop("COWORK_IMESSAGE_REQUIRE_ROOT_POLICY", None)
        else:
            os.environ["COWORK_IMESSAGE_REQUIRE_ROOT_POLICY"] = self.old_root

    def _signed(self, nonce: str, expires_at: int, **overrides):
        fields = {
            "pending_id": nonce,
            "expires_at": expires_at,
            "installation_id": "ab" * 32,
            "service": "iMessage",
            "recipient": self.recipient,
            "body": self.body,
        }
        fields.update(overrides)
        statement = self.chat.canonical_statement(**fields)
        signature, public = sign(statement, self.seed)
        config = _config(public)
        approval = {
            "key_id": "owner-2026-11",
            "signature": base64.b64encode(signature).decode("ascii"),
        }
        return config, approval

    def _send(self, params, config):
        with mock.patch.object(helper, "_load_chat_approval", return_value=self.chat), \
             mock.patch.object(helper, "_load_chat_approval_config", return_value=config), \
             mock.patch.object(helper, "_run_send_confirmation", return_value=True) as confirm, \
             mock.patch.object(helper, "_run_osascript", return_value=(0, "", "")) as script:
            result = helper.action_send(params, None, {}, [])
        return result, confirm, script

    def test_valid_signature_skips_dialog_and_sends(self) -> None:
        nonce, expires_at = helper.mint_send_nonce_record(self.recipient, self.body, "iMessage")
        config, approval = self._signed(nonce, expires_at)
        result, confirm, script = self._send(
            {
                "to": self.recipient,
                "text": self.body,
                "service": "iMessage",
                "send_nonce": nonce,
                "chat_approval": approval,
            },
            config,
        )
        confirm.assert_not_called()
        script.assert_called_once()
        self.assertEqual(result["sent"]["to"], self.recipient)
        audit = (self.bridge / "control" / "chat_approval_audit.jsonl").read_text(encoding="utf-8")
        self.assertNotIn(self.recipient, audit)
        self.assertNotIn(self.body, audit)
        self.assertIn("accepted", audit)

    def test_bad_signature_does_not_open_dialog_or_send(self) -> None:
        nonce, expires_at = helper.mint_send_nonce_record(self.recipient, self.body, "iMessage")
        config, approval = self._signed(nonce, expires_at, body="other body")
        with mock.patch.object(helper, "_load_chat_approval", return_value=self.chat), \
             mock.patch.object(helper, "_load_chat_approval_config", return_value=config), \
             mock.patch.object(helper, "_run_send_confirmation", return_value=True) as confirm, \
             mock.patch.object(helper, "_run_osascript") as script:
            with self.assertRaisesRegex(RuntimeError, "chat approval rejected: bad-signature"):
                helper.action_send(
                    {
                        "to": self.recipient,
                        "text": self.body,
                        "service": "iMessage",
                        "send_nonce": nonce,
                        "chat_approval": approval,
                    },
                    None,
                    {},
                    [],
                )
        confirm.assert_not_called()
        script.assert_not_called()

    def test_absent_chat_approval_still_uses_native_dialog(self) -> None:
        nonce, _expires = helper.mint_send_nonce_record(self.recipient, "Send it", "iMessage")
        with mock.patch.object(helper, "_run_send_confirmation", return_value=True) as confirm, \
             mock.patch.object(helper, "_run_osascript", return_value=(0, "", "")) as script:
            helper.action_send(
                {
                    "to": self.recipient,
                    "text": "Send it",
                    "send_nonce": nonce,
                    "approval": True,
                },
                None,
                {},
                [],
            )
        confirm.assert_called_once()
        script.assert_called_once()

    def test_blocklist_rejects_before_dialog_even_with_signature(self) -> None:
        nonce, expires_at = helper.mint_send_nonce_record(self.recipient, self.body, "iMessage")
        config, approval = self._signed(nonce, expires_at)
        with mock.patch.object(helper, "_load_chat_approval", return_value=self.chat), \
             mock.patch.object(helper, "_load_chat_approval_config", return_value=config), \
             mock.patch.object(helper, "_run_osascript") as script:
            with self.assertRaisesRegex(ValueError, "blocked"):
                helper.action_send(
                    {
                        "to": self.recipient,
                        "text": self.body,
                        "send_nonce": nonce,
                        "chat_approval": approval,
                    },
                    None,
                    {},
                    [self.recipient],
                )
        script.assert_not_called()
        self.assertTrue((self.bridge / "nonces" / f"{nonce}.json").exists())

    def test_group_and_send_policy_still_reject(self) -> None:
        with self.assertRaisesRegex(ValueError, "group chat"):
            helper.action_send(
                {"to": "chat12345", "text": "hi", "chat_approval": {"key_id": "owner-2026-11", "signature": "aa"}},
                None,
                {},
                [],
            )
        with mock.patch.object(helper, "is_send_policy_enabled", return_value=False):
            with self.assertRaisesRegex(ValueError, "disabled by policy"):
                helper.action_send(
                    {"to": self.recipient, "text": "hi"},
                    None,
                    {},
                    [],
                )

    def test_loader_source_requires_root_and_fixed_path(self) -> None:
        source = (REPO_ROOT / "bin" / "helper.py").read_text(encoding="utf-8")
        self.assertIn("require_root=True", source)
        self.assertIn("default_config_path()", source)
        self.assertIn("metadata.st_uid != 0", source)
        self.assertNotIn("IMESSAGE_CHAT_APPROVAL", source)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_chat_approval.HelperSendTests -v`

Expected: FAIL because `action_send` has no chat branch (`_load_chat_approval` missing, or the dialog is still called).

- [ ] **Step 3: Write minimal implementation**

Add these functions to `bin/helper.py` above `action_send`. They lazy-load the sibling of `SEND_GATE_PATH`.

```python
def _load_chat_approval():
    path = SEND_GATE_PATH.parent / "chat_approval.py"
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RuntimeError("chat approval rejected: invalid-config") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError("chat approval rejected: invalid-config")
    if os.environ.get("COWORK_IMESSAGE_REQUIRE_ROOT_POLICY") == "1":
        if metadata.st_uid != 0:
            raise RuntimeError("chat approval rejected: invalid-config")
    elif metadata.st_uid not in (0, os.getuid()):
        raise RuntimeError("chat approval rejected: invalid-config")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise RuntimeError("chat approval rejected: invalid-config")
    spec = _importlib_util.spec_from_file_location("chat_approval", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("chat approval rejected: invalid-config")
    module = _importlib_util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_chat_approval_config():
    module = _load_chat_approval()
    return module.load_config(module.default_config_path(), require_root=True)


def _live_bridge_dir() -> Path:
    override = os.environ.get("IMESSAGE_BRIDGE_DIR", "")
    if not override:
        raise RuntimeError("chat approval rejected: audit-failed")
    return Path(os.path.abspath(override))


def _approval_key_id(approval) -> str:
    if isinstance(approval, dict) and isinstance(approval.get("key_id"), str):
        return approval["key_id"]
    return ""


def _authorize_chat_send(*, params, expires_at, to, text, service) -> None:
    module = _load_chat_approval()
    pending_id = params.get("send_nonce")
    key_id = _approval_key_id(params.get("chat_approval"))
    try:
        if os.environ.get("COWORK_IMESSAGE_REQUIRE_ROOT_POLICY") != "1":
            raise module.ChatApprovalError("not-hardened")
        config = _load_chat_approval_config()
        module.verify_request(
            config,
            approval=params.get("chat_approval"),
            pending_id=pending_id,
            expires_at=expires_at,
            service=service,
            recipient=to,
            body=text,
            now=int(time.time()),
        )
        module.append_audit(
            _live_bridge_dir(),
            module.audit_event(
                result="accepted",
                reason="ok",
                pending_id=pending_id,
                recipient=to,
                body=text,
                service=service,
                key_id=key_id,
            ),
        )
        return
    except module.ChatApprovalError as exc:
        reason = exc.reason
    try:
        module.append_audit(
            _live_bridge_dir(),
            module.audit_event(
                result="rejected",
                reason=reason,
                pending_id=pending_id,
                recipient=to,
                body=text,
                service=service,
                key_id=key_id,
            ),
        )
    except module.ChatApprovalError as exc:
        raise RuntimeError("chat approval rejected: audit-failed") from exc
    raise RuntimeError(f"chat approval rejected: {reason}")
```

In `action_send`, replace the block that starts at `consume_send_nonce` and ends at the cancelled-dialog `RuntimeError` with:

```python
    expires_at = consume_send_nonce(params.get("send_nonce"), to, text, service)

    if "chat_approval" in params:
        _authorize_chat_send(
            params=params,
            expires_at=expires_at,
            to=to,
            text=text,
            service=service,
        )
    else:
        resolved_name = _resolve_contact_name(to, contacts)
        if not _run_send_confirmation(
            to=to,
            resolved_name=resolved_name,
            service=service,
            text=text,
        ):
            raise RuntimeError(
                "send cancelled by user or timed out (60s dialog limit)"
            )
```

Leave the AppleScript construction below that block unchanged.

The happy-path tests monkeypatch `_load_chat_approval` because CI cannot put a uid-0 file in the repo. The source assertion locks the production loader to `require_root=True`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_chat_approval.HelperSendTests tests.test_safety_privacy.SendConfirmationTests -v`

Expected: PASS. Existing native-dialog tests still call `_run_send_confirmation`.

- [ ] **Step 5: Commit**

```bash
git add bin/helper.py tests/test_chat_approval.py
git commit -m "Skip the native dialog only after a verified chat signature"
```

---

### Task 6: Preview, status, and docs

**Files:**
- Modify: `bin/helper.py` (`action_send_preview`, `action_status`)
- Modify: `docs/PROTOCOL.md`
- Modify: `SECURITY.md`
- Modify: `SKILL.md` sending steps
- Modify: `CHANGELOG.md`
- Modify: `tests/test_list_chats.py` protocol assertion
- Test: `tests/test_chat_approval.py`

**Interfaces:**
- Consumes: `mint_send_nonce_record`, `preview_approval`, `status_descriptor`
- Produces: `send_nonce_expires_at`, `approval` on preview, `chat_approval` on status, protocol string `1.3`

- [ ] **Step 1: Write the failing test**

Append `PreviewStatusTests` to `tests/test_chat_approval.py`:

```python
class PreviewStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="chat-approval-preview-")
        self.addCleanup(self.tmp.cleanup)
        self.old_bridge = os.environ.get("IMESSAGE_BRIDGE_DIR")
        self.old_root = os.environ.get("COWORK_IMESSAGE_REQUIRE_ROOT_POLICY")
        os.environ["IMESSAGE_BRIDGE_DIR"] = os.path.realpath(self.tmp.name)
        os.environ["COWORK_IMESSAGE_BRIDGE_DIR"] = os.environ["IMESSAGE_BRIDGE_DIR"]
        os.environ.pop("COWORK_IMESSAGE_REQUIRE_ROOT_POLICY", None)
        self.addCleanup(self._restore)

    def _restore(self) -> None:
        if self.old_bridge is None:
            os.environ.pop("IMESSAGE_BRIDGE_DIR", None)
        else:
            os.environ["IMESSAGE_BRIDGE_DIR"] = self.old_bridge
        if self.old_root is None:
            os.environ.pop("COWORK_IMESSAGE_REQUIRE_ROOT_POLICY", None)
        else:
            os.environ["COWORK_IMESSAGE_REQUIRE_ROOT_POLICY"] = self.old_root

    def test_unarmed_preview_is_native_and_reports_expiry(self) -> None:
        result = helper.action_send_preview(
            {"to": "+14155551234", "text": "Confirmed for 3pm."},
            None,
            {},
            [],
        )
        self.assertEqual(result["approval"], {"mode": "native"})
        self.assertEqual(result["send_nonce_ttl_seconds"], 60)
        self.assertIsInstance(result["send_nonce_expires_at"], int)
        self.assertNotIn("installation_id", result["approval"])

    def test_status_unarmed_is_native(self) -> None:
        status = helper.action_status({}, None, {}, [])
        self.assertEqual(helper.PROTOCOL_VERSION, "1.3")
        self.assertEqual(status["protocol_version"], "1.3")
        self.assertEqual(
            status["chat_approval"],
            {"enrolled": False, "enabled": False, "mode": "native"},
        )
```

In `tests/test_list_chats.py`, inside `RoleGateTests.test_manager_status_reports_role`, change the protocol assertion from `"1.2"` to `"1.3"`.

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_chat_approval.PreviewStatusTests tests.test_list_chats.RoleGateTests.test_manager_status_reports_role -v`

Expected: FAIL because preview has no `approval` and protocol is still `1.2`.

- [ ] **Step 3: Write minimal implementation**

In `bin/helper.py` set `PROTOCOL_VERSION = "1.3"`.

Change the nonce line in `action_send_preview` to:

```python
    send_nonce, send_nonce_expires_at = mint_send_nonce_record(to, text, service)
    approval = {"mode": "native"}
    if os.environ.get("COWORK_IMESSAGE_REQUIRE_ROOT_POLICY") == "1":
        try:
            module = _load_chat_approval()
            config = _load_chat_approval_config()
            approval = module.preview_approval(
                config,
                pending_id=send_nonce,
                expires_at=send_nonce_expires_at,
                service=service,
                recipient=to,
                body=text,
            )
        except Exception as exc:
            reason = getattr(exc, "reason", type(exc).__name__)
            log(f"chat approval preview unavailable: {reason}")
            approval = {"mode": "native"}
```

Add to the returned dict:

```python
        "send_nonce_expires_at": send_nonce_expires_at,
        "approval": approval,
```

Add to the `action_status` dict:

```python
def _chat_approval_status() -> dict:
    if os.environ.get("COWORK_IMESSAGE_REQUIRE_ROOT_POLICY") != "1":
        return {"enrolled": False, "enabled": False, "mode": "native"}
    try:
        module = _load_chat_approval()
        return module.status_descriptor(module.default_config_path())
    except Exception:
        return {
            "enrolled": False,
            "enabled": False,
            "mode": "native",
            "reason": "invalid-config",
        }
```

Call it as `"chat_approval": _chat_approval_status()`.

In `docs/PROTOCOL.md`, set the header to protocol `1.3` and add this history bullet under the existing `1.2` bullet:

```markdown
- `1.3` — optional `chat_approval` on `send`, plus `send_nonce_expires_at` and `approval` on `send_preview`. Verification is off unless a root-owned config is enrolled. Absent `chat_approval` still uses the native dialog.
```

In the `send_preview` response example, add `"send_nonce_expires_at": 1762400000` and `"approval": {"mode": "native"}`. In the `send` section, document the optional `chat_approval` object and the sentence: a failed chat signature does not open the native dialog and does not send.

In `SECURITY.md`, after the native-dialog layer, add:

```markdown
### Optional chat signature (hardened installs)

A hardened install can enroll a root-owned Ed25519 public key at
`/Library/Application Support/GrokBotIMessage/users/<uid>/config/chat_approval.json`.
When that file is enabled, a `send` request may include `chat_approval`
with a signature over the canonical statement for that nonce. The helper
skips the native dialog only after that signature verifies. Any other
request still shows the dialog. A bad, missing-for-this-attempt, expired,
revoked, or unknown signature does not send. The private key is not stored
by this bridge. No Grok platform endpoint is called.
```

In `SKILL.md`, replace the sending-flow step that tells the agent the helper will display the native dialog unconditionally with:

```markdown
5. Call `send` with the same `to`, `text`, `service`, and `send_nonce`. Omit `chat_approval` unless the owner’s external signer returned `key_id` and `signature` for this exact preview. Do not invent a signature from a chat sentence. If `status.chat_approval.mode` is `native`, omit `chat_approval`; the helper shows the macOS dialog. If a signature was attached and it fails, do not retry that nonce.
```

Add a `## Unreleased` section at the top of `CHANGELOG.md` (leave the `1.4.8` heading in place):

```markdown
## Unreleased

- Add an opt-in hardened chat-signature verifier for sends. Native confirmation remains the default. Protocol `1.3`.
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_chat_approval.PreviewStatusTests tests.test_list_chats.RoleGateTests.test_manager_status_reports_role tests.test_reliability_onboarding.SkillInstallTests.test_protocol_version_is_documented -v`

Expected: PASS. `test_protocol_version_is_documented` reads `Protocol version: \`1.3\`` from `docs/PROTOCOL.md`.

- [ ] **Step 5: Commit**

```bash
git add bin/helper.py docs/PROTOCOL.md SECURITY.md SKILL.md CHANGELOG.md tests/test_list_chats.py tests/test_chat_approval.py
git commit -m "Report chat-approval status and document protocol 1.3"
```

---

### Task 7: Enrollment tool

**Files:**
- Create: `tools/configure_chat_approval.py`
- Test: `tests/test_configure_chat_approval.py`

**Interfaces:**
- Consumes: the config schema from `chat_approval.load_config`
- Produces: `parse_public_key(raw: bytes) -> bytes`, `apply_action(config: dict, action: str, **kwargs) -> dict`, `install_argv(destination: Path, staged: Path) -> list[str]`

The tool's `main` uses `/usr/bin/sudo` and `/usr/bin/install` the way `tools/configure_allowlist.py` does. Tests do not run `sudo`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_configure_chat_approval.py`:

```python
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load():
    path = REPO_ROOT / "tools" / "configure_chat_approval.py"
    spec = importlib.util.spec_from_file_location("configure_chat_approval", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ConfigureChatApprovalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load()
        self.public = b"\x11" * 32

    def test_parse_public_key_accepts_raw_32_and_base64(self) -> None:
        self.assertEqual(self.tool.parse_public_key(self.public), self.public)
        text = __import__("base64").b64encode(self.public)
        self.assertEqual(self.tool.parse_public_key(text), self.public)

    def test_parse_public_key_rejects_private_material(self) -> None:
        for raw in (b"-----BEGIN PRIVATE KEY-----\n", b"\x22" * 64, b"ed25519-priv:" + self.public):
            with self.subTest(raw=raw[:24]):
                with self.assertRaises(ValueError):
                    self.tool.parse_public_key(raw)

    def test_enable_requires_an_active_key(self) -> None:
        empty = {
            "version": 1,
            "enabled": False,
            "audience": "grokbot-imessage-send",
            "installation_id": "ab" * 32,
            "keys": [],
        }
        with self.assertRaises(ValueError):
            self.tool.apply_action(empty, "enable")

    def test_enroll_revoke_disable_round_trip(self) -> None:
        config = self.tool.apply_action(None, "enroll", key_id="owner-2026-11", public_key=self.public)
        self.assertFalse(config["enabled"])
        self.assertEqual(len(config["installation_id"]), 64)
        armed = self.tool.apply_action(config, "enable")
        self.assertTrue(armed["enabled"])
        revoked = self.tool.apply_action(armed, "revoke", key_id="owner-2026-11")
        self.assertEqual(revoked["keys"][0]["status"], "revoked")
        self.assertFalse(self.tool.apply_action(revoked, "disable")["enabled"])

    def test_install_argv_targets_the_fixed_root_file(self) -> None:
        destination = self.tool.default_config_path(501)
        argv = self.tool.install_argv(destination, Path("/tmp/staged.json"))
        self.assertEqual(argv[:4], ["/usr/bin/sudo", "/usr/bin/install", "-o", "root"])
        self.assertIn("600", argv)
        self.assertTrue(str(argv[-1]).endswith("/users/501/config/chat_approval.json"))

    def test_refuses_unexpected_destination(self) -> None:
        with self.assertRaises(RuntimeError):
            self.tool.install_argv(Path("/tmp/chat_approval.json"), Path("/tmp/staged.json"))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_configure_chat_approval -v`

Expected: FAIL because the tool file does not exist.

- [ ] **Step 3: Write minimal implementation**

Create `tools/configure_chat_approval.py` with the functions below. `main` is not what the unit tests call. It parses `status|enroll|revoke|disable|enable`, writes the JSON to a mode `600` temp file, runs `subprocess.run(install_argv(...), check=True)`, then runs the same ACL commands as `configure_allowlist.py`: `/usr/bin/sudo /bin/chmod -N <path>` and `/usr/bin/sudo /bin/chmod +a user:<name> allow read <path>`.

```python
def parse_public_key(raw: bytes) -> bytes:
    if b"PRIVATE" in raw or b"ed25519-priv:" in raw:
        raise ValueError("refusing private key material")
    if len(raw) == 32:
        return bytes(raw)
    try:
        decoded = base64.b64decode(raw.decode("ascii").strip(), validate=True)
    except Exception as exc:
        raise ValueError("public key must be 32 raw bytes or base64") from exc
    if len(decoded) != 32:
        raise ValueError("public key must be 32 bytes")
    return decoded


def apply_action(config, action, **kwargs):
    if action == "enroll":
        public = parse_public_key(kwargs["public_key"])
        key_id = kwargs["key_id"]
        if re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", key_id) is None:
            raise ValueError("invalid key id")
        if config is None:
            config = {
                "version": 1,
                "enabled": False,
                "audience": "grokbot-imessage-send",
                "installation_id": secrets.token_hex(32),
                "keys": [],
            }
        if any(item["key_id"] == key_id for item in config["keys"]):
            raise ValueError("duplicate key id")
        config["keys"].append(
            {
                "key_id": key_id,
                "public_key": base64.b64encode(public).decode("ascii"),
                "status": "active",
            }
        )
        return config
    if action == "enable":
        if not any(item["status"] == "active" for item in config["keys"]):
            raise ValueError("no active key")
        config["enabled"] = True
        return config
    if action == "revoke":
        matches = [item for item in config["keys"] if item["key_id"] == kwargs["key_id"]]
        if not matches:
            raise ValueError("unknown key")
        matches[0]["status"] = "revoked"
        return config
    if action == "disable":
        config["enabled"] = False
        return config
    raise ValueError(f"unknown action {action}")
```

Use this `install_argv`:

```python
def default_config_path(uid: int) -> Path:
    return Path("/Library/Application Support/GrokBotIMessage") / "users" / str(uid) / "config" / "chat_approval.json"


def install_argv(destination: Path, staged: Path) -> list[str]:
    parts = destination.parts
    try:
        uid = int(parts[-3])
    except (ValueError, IndexError) as exc:
        raise RuntimeError("refusing an unexpected chat approval destination") from exc
    if parts[-1] != "chat_approval.json" or destination != default_config_path(uid):
        raise RuntimeError("refusing an unexpected chat approval destination")
    return [
        "/usr/bin/sudo",
        "/usr/bin/install",
        "-o",
        "root",
        "-g",
        "wheel",
        "-m",
        "600",
        str(staged),
        str(destination),
    ]
```

`parts[-3]` is the uid directory (`users/<uid>/config/chat_approval.json`).

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_configure_chat_approval -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tools/configure_chat_approval.py tests/test_configure_chat_approval.py
git commit -m "Add a root enrollment tool for chat-approval public keys"
```

---

### Task 8: Installer copy, compile list, shared-core hashes

**Files:**
- Modify: `install-hardened.sh` (three `install` lines next to the `send_gate.py` copy)
- Modify: `tools/test.sh` `py_compile` list
- Modify: `shared-core.json` hashes for `helper.py` and `send_gate.py` only
- Test: `tests/test_chat_approval.py`

**Interfaces:**
- Consumes: the new files from earlier tasks
- Produces: a hardened install that copies `bin/chat_approval.py`, `bin/ed25519_verify.py`, and `tools/configure_chat_approval.py` into the root-owned tree; local shared-core check passes

- [ ] **Step 1: Write the failing test**

Append to `tests/test_chat_approval.py`:

```python
class InstallerWiringTests(unittest.TestCase):
    def test_hardened_installer_copies_verifier_files(self) -> None:
        script = (REPO_ROOT / "install-hardened.sh").read_text(encoding="utf-8")
        for name in (
            "bin/chat_approval.py",
            "bin/ed25519_verify.py",
            "tools/configure_chat_approval.py",
        ):
            self.assertIn(name, script)
        compile_list = (REPO_ROOT / "tools" / "test.sh").read_text(encoding="utf-8")
        self.assertIn("bin/chat_approval.py", compile_list)
        self.assertIn("bin/ed25519_verify.py", compile_list)
        self.assertIn("tools/configure_chat_approval.py", compile_list)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_chat_approval.InstallerWiringTests -v`

Expected: FAIL because the installer and `tools/test.sh` do not name the new files.

- [ ] **Step 3: Write minimal implementation**

In `install-hardened.sh`, after the `send_gate.py` copy:

```bash
sudo /usr/bin/install -o root -g wheel -m 444 \
    "$SOURCE_ROOT/bin/chat_approval.py" "$CODE_ROOT/bin/chat_approval.py"
sudo /usr/bin/install -o root -g wheel -m 444 \
    "$SOURCE_ROOT/bin/ed25519_verify.py" "$CODE_ROOT/bin/ed25519_verify.py"
sudo /usr/bin/install -o root -g wheel -m 555 \
    "$SOURCE_ROOT/tools/configure_chat_approval.py" "$CODE_ROOT/tools/configure_chat_approval.py"
```

In the installer’s closing instructions, add one line:

```text
Chat signature enrollment, after a public key exists:
  "$PYTHON3_PATH" "$CODE_ROOT/tools/configure_chat_approval.py" status
```

In `tools/test.sh`, add `bin/chat_approval.py bin/ed25519_verify.py tools/configure_chat_approval.py` to the `py_compile` argument list.

Then refresh fingerprints:

```bash
python3 tools/check_shared_core.py --print
```

Copy the printed `helper.py` and `send_gate.py` digests into `shared-core.json`. Leave every other file entry unchanged. Do not add `chat_approval.py` or `ed25519_verify.py` to `files`.

- [ ] **Step 4: Run test to verify it passes**

Run: `./tools/test.sh v1.4.8`

Expected: `py_compile` succeeds, unittest PASS, `shared-core check` prints the grokbot-imessage hashes, and the command prints `release versions match v1.4.8`.

Also run the shell syntax check that CI runs:

```bash
bash -n install-hardened.sh tools/test.sh
```

Expected: no output and exit 0.

- [ ] **Step 5: Commit**

```bash
git add install-hardened.sh tools/test.sh shared-core.json tests/test_chat_approval.py
git commit -m "Install the chat verifier with the hardened code root"
```

---

## Spec coverage

- Canonical statement, Ed25519, RFC vectors: Task 1 and Task 2.
- Tampered recipient, body, service, pending id, expiry, installation id, audience: Task 2. Payload mismatch before verify: Task 4.
- Revoked and unknown keys, malformed approval: Task 2.
- Config mode, symlink, garbage, audience, string `enabled`, missing file, non-root owner: Task 3.
- Concurrent consume and one-use nonce: Task 4.
- Native dialog when `chat_approval` is absent, including `approval: true` and body `Send it`: Task 5.
- Valid signature skips the dialog and writes a hashed audit line: Task 5.
- Invalid signature does not confirm or send: Task 5.
- Blocklist, group id, send policy: Task 5.
- Preview and status fields, protocol `1.3`, security and skill text: Task 6.
- Enrollment tool refuses private keys and unexpected paths: Task 7.
- Hardened copy and shared-core self-check: Task 8.
- External Grok signer: not a task. The mode stays unusable until a real public key is enrolled outside this plan.

## Execution note

Do not start Task 1 until Andrew approves the spec and this plan. After approval, the two execution options are subagent-driven development (one fresh agent per task, review between tasks) or inline execution of these checkboxes in one session. Neither option merges, installs on a Mac, or sends a message.
