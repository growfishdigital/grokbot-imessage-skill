# Chat send approval design

Status: design approved in pull request 1, then held. A source review of the G2/Current glasses path is in `docs/superpowers/specs/2026-11-06-g2-approval-comparison.md`. Do not implement the Ed25519 bypass in this document until Andrew accepts or rejects the adjustment in that comparison. No send-path behavior is implemented by this document.

Repository inspected: `growfishdigital/grokbot-imessage-skill` at `ccd12b9c8cadeb8da27df16801bc1469c0883e9e` (`main`). Origin is this fork. The Mac install path and its ignored runtime files were not read or modified.

## Problem

Sending is already gated. `send_preview` mints a 60-second, one-use nonce bound to the exact validated `(to, text, service)` triple (`bin/send_gate.py`). `send` consumes that nonce and then requires the native macOS dialog (`bin/confirm_imessage_send.m`, launched from `action_send` in `bin/helper.py`). Cancel is the keyboard default. A 60-second timeout aborts the send.

Andrew wants an explicit approval of that same draft in Grok Bot chat to be able to stand in for the second, native confirmation. The owner must still consent to the exact message. The consent has to come from a signer the request-writing agent does not control.

## What the repository actually documents

Protocol version is `1.2` (`PROTOCOL_VERSION` in `bin/helper.py`). `docs/PROTOCOL.md`, `SKILL.md`, `README.md`, and `SECURITY.md` describe the same send sequence:

1. `send_preview` validates the recipient and body, checks the blocklist, and returns a nonce. It does not read `chat.db` and does not send.
2. The skill text tells the agent to wait for explicit approval in chat.
3. `send` replays the same recipient, body, service, and nonce.
4. The helper shows the native dialog. The owner must select Send.

`docs/SIGNING.md` is about ad hoc codesign of the local helper binaries. It is not a chat-approval or message-signing protocol.

Searched terms in this tree (`approval`, `signature`, `send_preview`, Grok, xAI) find no chat-approval endpoint, card schema, webhook, public-key delivery API, or signature format from the Grok Bot platform. A sentence in chat is not a signature. This design does not invent one.

## Threat model

Any local process that can write `control/requests/` can submit `send_preview` and `send`. The nonce stops a blind send, a replay, and a payload swap after preview. It is not owner consent: that same process can read the nonce out of the response and submit it. `SECURITY.md` already says this. The native dialog is the independent consent.

Replacing the dialog with `approval: true`, with the word "Send it", or with a key stored where the agent or the request writer can read it would remove that consent. A missing or invalid signature must not authorize a send.

Out of scope for the attacker: root, and a person who can replace the root-owned hardened code. Standard installs stay user-owned and remain inside the existing "same-user code replacement" limitation in `SECURITY.md`. Chat approval is therefore a hardened-install feature.

## Recommendation

Add an opt-in verification path on the bridge. The helper skips the native dialog only when all of the following are true:

- The install is the hardened one (`COWORK_IMESSAGE_REQUIRE_ROOT_POLICY=1`, set by the wrapper, not by the request).
- A root-owned verifier config is enrolled and `enabled` is JSON `true`.
- `send` carries a `chat_approval` object whose Ed25519 signature verifies under an **active** enrolled public key.
- The signed bytes are the canonical statement for this nonce's stored expiry, the fixed audience, the enrolled installation id, and the exact validated recipient, service, and body.
- The nonce claim succeeds once, atomically, with the same payload checks as today.

The private key never enters this repository, the bridge directory, the helper, or the agent. This repository verifies. It does not sign production approvals.

Until that config exists, behavior stays the current one: consume the nonce, show the native dialog, send only after the dialog returns Send. There is no unsigned shortcut and no standing approval.

### Why this is the smallest safe bridge change

The preview nonce is already a pending-send id bound to the exact payload and a short expiry. The new work is to authenticate owner consent over that id. Enrollment matches the existing root-owned allowlist pattern (`tools/configure_allowlist.py`, mode `600`, uid 0, user read ACL). The dialog code stays the default branch.

## Alternatives

### A. Leave the native dialog as the only send path

No new verifier. The skill can keep asking for a chat "yes", and the Mac dialog remains mandatory. This is the behavior at `ccd12b9`. It has no new attack surface. It does not let chat approval replace the dialog. It remains the default even if the recommended path is built.

### B. Trust a flag or a chat sentence

`params.approval = true`, or treating "Send it" as consent, is available to every request writer. This fails the threat model. It is not a fallback and it is not a temporary mode.

### C. HMAC or a signing key held by the agent or the bridge folder

The same principal that can write requests could mint approvals. That is the same failure as B, with extra ceremony.

### D. A second local UI that the agent launches

A broker the agent can start and drive is not independent of the request writer. It also does not move consent into Grok chat. A future external signer could be a device the owner uses, but that signer is outside this repository and must still meet the contract below. This repo will not ship that UI.

The recommended path is the one that can later accept a real platform signature without treating the agent as the owner.

## Major dependency

No supported Grok Bot chat-approval or signing API is documented here. Bridge code can verify a signature. It cannot produce one, and it cannot discover a platform endpoint that this tree does not describe.

Chat-only sending stays impossible until Andrew enrolls the public key of a signer he actually controls, and that signer starts producing signatures over the canonical statement. A unit-test key is not that signer. Enabling the config without a real signer makes every chat attempt fail closed. The native dialog continues to work when the request omits `chat_approval`.

## Split of work

### Achievable in this fork

- Canonical statement builder and Ed25519 **verify** (RFC 8032 pure Ed25519, no new Python dependency, Python 3.9+).
- Root-owned config loader: absent, disabled, malformed, wrong owner, wrong mode, symlink, unknown key, revoked key.
- `send` branch that verifies and then skips the dialog, with audit.
- Preview and `status` fields that report whether verification is armed.
- Enrollment tool that accepts a public key and refuses private-key material.
- Tests listed in the plan. Hardened installer copies the new modules into the root-owned code root.
- Protocol document update from `1.2` to `1.3` for the new optional fields.

### Not achievable here

- A Grok Bot control, card, or API that signs the statement when Andrew taps approve.
- Any network call from the helper. The helper stays offline; the signer is outside it.
- Installing, deploying, or sending. No message to David Bird, Aidan, or anyone else.
- Updating `jeffhuber/claudecowork-imessage-skill` or `jeffhuber/chatgpt-codex-imessage-plugin`.

## Approaches rejected inside the design

Custom per-install audiences, a longer nonce TTL, phone-number re-canonicalization, and an environment-variable path to the verifier config are left out. Each one either widens the window, lets the request writer aim the verifier at its own key, or changes which recipient string is bound. The signed recipient is the string `validate_send_recipient` already returns.

## Protocol additions

Protocol becomes `1.3`. Old clients that ignore unknown fields keep working. `HELPER_VERSION` stays `1.4.8` until a release is cut; CI checks that version against the `v1.4.8` tag argument.

### Canonical statement

UTF-8, exactly eight lines, each ending in `\n`, no spaces around the colons:

```text
grokbot-imessage-send-approval-v1
pending_id:<send nonce>
expires_at:<decimal unix seconds stored in the nonce record>
audience:grokbot-imessage-send
installation_id:<64 lowercase hex chars from the enrolled config>
service:<iMessage or SMS>
recipient:<validated to>
body_sha256:<sha256 hex of the exact UTF-8 body>
```

`body_sha256` is SHA-256 of the validated message bytes. The Ed25519 signature is over the raw statement bytes, not over `canonical_sha256`. `canonical_sha256` is SHA-256 of those statement bytes and is returned so an external signer can detect that it built different bytes. The helper recomputes the statement itself. The request cannot supply the statement, the expiry, the audience, or the installation id.

Worked example (not a live approval). Body `Confirmed for 3pm.` hashes to `7dc97dc29dc2ec4081b1d539b6985b6dcc6b5b4d4ecd0515968b42795b914cd2`. With `pending_id=pending-example`, `expires_at=1762400000`, `installation_id` of 64 `ab` characters, service `iMessage`, and recipient `+14155551234`, the statement's SHA-256 is `356c86b8941e291b185afaa11dd262c282c4a9887e3d6fdc748bb5a27014f515`.

### `send_preview`

Unchanged request. The response gains `send_nonce_expires_at` (the absolute expiry stored in the nonce file) and `approval`.

When chat verification is not armed, including when the config file is missing or malformed:

```json
"approval": {"mode": "native"}
```

A malformed config does not fail `send_preview`. When verification is armed, `approval.mode` is `chat_signature` and the object also carries `statement_version`, `audience`, `installation_id`, `pending_id` (the same nonce), `expires_at` (equal to `send_nonce_expires_at`), and `canonical_sha256`. Preview still does not send.

`mint_send_nonce` keeps returning the nonce string. A new `mint_send_nonce_record` returns `(nonce, expires_at)` so the preview reports the value that was stored.

### `send`

The nonce, recipient, body, and service rules are unchanged. Optional object:

```json
"chat_approval": {
  "key_id": "owner-2026-11",
  "signature": "<standard base64 of the 64-byte Ed25519 signature>"
}
```

Unknown keys inside `chat_approval` fail closed. `approval`, `approved`, and a bare string are not read as consent.

`consume_send_nonce` still claims the nonce by atomic rename, rejects payload mismatch and expiry, and deletes it on every outcome. On success it returns the stored `expires_at` integer. Callers that ignore the return value keep working.

Order in `action_send`:

1. Send-policy, recipient, body, service, and blocklist checks. Failures happen before the nonce is consumed, as they do today. Group ids still die in `validate_send_recipient`. Allowlist behavior of `send` is unchanged: `action_send` checks the blocklist and does not apply the read allowlist.
2. Consume the nonce.
3. If the params object contains `chat_approval`, verify. Any failure raises, writes a rejection audit line, and does not open the dialog and does not call Messages. The nonce stays consumed.
4. If `chat_approval` is absent, call `_run_send_confirmation` exactly as today.
5. Only then build the AppleScript from the same validated strings.

A chat attempt with a bad signature does not fall through to the dialog on that nonce. The owner can mint a new preview and send it without `chat_approval`; that request still shows the dialog. An absent signature is the native path. An invalid signature is a failed chat attempt, never a send.

### `status`

Add `chat_approval` with `enrolled`, `enabled`, and `mode` (`native` or `chat_signature`). Include active `key_id` strings only. Omit public keys, installation id, and message contents. A missing config is `enrolled: false`, `mode: native`. A present but unreadable or malformed config is `enrolled: false`, `mode: native`, `reason: invalid-config`, and it does not affect sends that omit `chat_approval`.

## Verifier config

Path, only this path:

`/Library/Application Support/GrokBotIMessage/users/<uid>/config/chat_approval.json`

Requirements: regular file, not a symlink, uid 0, mode `600`. The enrollment tool grants the console user a read ACL, same pattern as the hardened allowlist, so the user-launched helper can read the public keys. There is no `IMESSAGE_CHAT_APPROVAL_*` path override.

```json
{
  "version": 1,
  "enabled": false,
  "audience": "grokbot-imessage-send",
  "installation_id": "<64 lowercase hex characters>",
  "keys": [
    {
      "key_id": "owner-2026-11",
      "public_key": "<standard base64 of 32 raw public-key bytes>",
      "status": "active"
    }
  ]
}
```

- The object’s keys are exactly `version`, `enabled`, `audience`, `installation_id`, and `keys`. Any other top-level key makes the file malformed.
- `enabled` must be JSON `true` to arm chat verification. The tool writes `false` until `enable` is used.
- `audience` must equal `grokbot-imessage-send`. Any other value makes the file malformed.
- `installation_id` is generated at first enroll with `secrets.token_hex(32)`.
- `key_id` matches `^[a-z0-9][a-z0-9._-]{0,63}$` and is unique.
- At most 8 keys. `status` is `active` or `revoked`. Several active keys may overlap during rotation.
- `enable` refuses when zero keys are `active`.
- Public key material is 32 bytes after base64. 64-byte seeds, PEM private keys, and the substring `PRIVATE` are rejected.
- The helper reads this file on each chat attempt and each `status`. It does not cache it.

Standard and product-bundle installs that do not set root policy never consult a config in the bridge folder. A file dropped next to the requests cannot arm the mode.

## Module boundaries

| Unit | Responsibility |
| --- | --- |
| `bin/ed25519_verify.py` | `verify(public, message, signature) -> bool`. No sign function and no embedded key. |
| `bin/chat_approval.py` | Statement, config load, verify-against-statement, preview descriptor, status descriptor, audit append. |
| `bin/send_gate.py` | Existing nonce claim. Additionally return `expires_at` and expose `mint_send_nonce_record`. |
| `bin/helper.py` | Lazy-load the verifier only on a chat attempt. Native branch stays `_run_send_confirmation`. |
| `tools/configure_chat_approval.py` | `status`, `enroll`, `revoke`, `disable`, `enable`. Root via the same `sudo install` pattern as the allowlist tool. |
| `tests/ed25519_signer.py` | RFC 8032 test signer used by tests. Not installed. |

`chat_approval.py` is loaded from the same directory as the already validated `send_gate.py`, with a regular-file, not-group-writable, and (when root policy is on) uid-0 check. It loads `ed25519_verify.py` from that same directory and requires the sibling to be a regular file with the same owner and no group or world write bit. The chat branch fail-closes if that load fails: the error is `chat approval rejected: invalid-config`, Messages is not called, and no audit line is required when the module itself cannot be loaded. Read actions and native sends do not need the module to import at helper startup.

The C wrapper's file list is unchanged in this slice. The hardened code directory is root-owned and not user-writable, and the installer copies the new modules in next to `send_gate.py`. A later change can teach `bin/imessage_helper.c` to stat those siblings too. That wrapper change is deliberately deferred so this slice does not retune product-mode bundle validation.

## Audit

After a nonce has been consumed for a request that contains `chat_approval`, append one JSON object to `<bridge>/control/chat_approval_audit.jsonl` (mode `600`, current user, `O_NOFOLLOW`, atomic replace when compacted). Fields: `ts`, `result` (`accepted` or `rejected`), `reason`, `pending_id_sha256`, `recipient_sha256`, `body_sha256`, `service`, `key_id`. No raw recipient, body, signature, or public key. If the append fails, the chat attempt fails closed and does not send. The native path does not write this file. A nonce, blocklist, or validation failure that happens before consumption does not write it either.

When the file exceeds 256 KiB, keep the last 100 lines and replace atomically. A failed compaction fails the chat attempt.

## Enrollment

`tools/configure_chat_approval.py` is the only writer. It refuses to run the mutating commands unless it can `sudo install` the result to the fixed path as root, mode `600`, then apply the user read ACL. `enroll --public-key-file` reads raw 32 bytes or a one-line base64 file. It never asks for, stores, or prints a private key. `revoke --key-id` sets `status` to `revoked` and leaves the id in the file so later attempts audit as `revoked` rather than `unknown-key`. `disable` sets `enabled` to false immediately.

Operator key generation happens on a machine the agent cannot read, with a tool this repo does not ship. Example shape, not a bridge command and not the test signer:

```text
openssl genpkey -algorithm ED25519 -outform PEM -out owner.pem
openssl pkey -in owner.pem -pubout -outform DER | tail -c 32 > owner.pub
```

Ed25519 SubjectPublicKeyInfo is 44 bytes; the last 32 are the raw public key. Enroll `owner.pub`. Keep `owner.pem` off the Mac that runs the agent and the bridge.

## External signer contract

This is the interface a future platform signer must meet. Nothing in this fork calls it.

The signer:

1. Displays the exact recipient string, service, and full body to the owner, together with the pending id and expiry.
2. Builds the canonical statement from those displayed values plus `audience`, `installation_id`, and `expires_at` taken from that preview. It signs those bytes with Ed25519 and the owner's private key.
3. Returns only `key_id` and the standard-base64 signature.
4. Holds the private key where the agent and every process that can write `control/requests/` cannot read it.
5. Signs one statement per owner action. It has no bulk or standing approval.
6. Refuses expired previews, a different audience, and a different installation id.

The agent may attach that returned object as `chat_approval`. The agent must not fabricate it. If the platform did not return a signature, the agent omits `chat_approval` and the native dialog remains the consent.

## Failure behavior

Reason tokens on the chat path, after a successful nonce consume: `not-hardened`, `not-enrolled`, `disabled`, `invalid-config`, `malformed-approval`, `unknown-key`, `revoked`, `bad-signature`, `audit-failed`. A signature over a different pending id, expiry, audience, installation id, recipient, service, or body is `bad-signature`. The error string is `chat approval rejected: <reason>`.

| Condition | Result |
| --- | --- |
| No `chat_approval` field | Native dialog, current errors |
| Config missing, disabled, or malformed, and the field is present | Reject, nonce consumed, no dialog, no send |
| Tampered recipient, body, or service | Existing nonce error before verify; nonce consumed; no dialog |
| Signature for a different pending id, expiry, audience, or installation id | `bad-signature`, no send |
| Expired nonce | Existing expiry error |
| Reused nonce, including a second concurrent consumer | One claim wins; the rest get `nonce not recognized` |
| Revoked or unknown `key_id` | `revoked` or `unknown-key` |
| Blocked recipient or group id or send policy off | Existing error, nonce not consumed |
| `approval: true` or text "Send it" without a valid `chat_approval` | Ignored. Native dialog still required |
| Audit write failure on a chat attempt | `audit-failed`, no send |

## Shared-core effect

`bin/helper.py` and `bin/send_gate.py` are fingerprinted in `shared-core.json`. Implementing this design changes those fingerprints. This fork updates its own manifest. It does not update the jeffhuber sibling repositories. After merge to this fork's `main`, the scheduled cross-repo job in `.github/workflows/shared-core-parity.yml` will fail until those siblings carry the same helper and send-gate bytes or the schedule is changed. Pull-request CI only runs the local manifest check.

The new modules stay out of `shared-core.json` in this slice. Identity normalization requires every host identity string to appear in the file, and a raw hash would diverge from siblings that do not have the file. Extending the manifest format is a separate change.

## Tests the implementation must add first

Failing tests, then code, for:

- Tampered recipient, body, and service
- Expired nonce, reused nonce, wrong audience, wrong installation id, wrong pending id
- Revoked key, unknown key
- Concurrent double consume
- Blocklist, group id, and send-policy rejection even when a signature would have verified
- Malformed config and malformed `chat_approval`
- Wrong owner, mode, and symlink of the config
- Native path still calls the confirmation helper when `chat_approval` is absent, including when `approval` is true
- Invalid signature does not call the confirmation helper or `osascript`
- Audit line contains hashes and omits the raw recipient and body
- RFC 8032 test vectors 1 and 2 for `verify`
- Production modules do not define a signer

`./tools/test.sh v1.4.8` is the check. That runs `py_compile`, unittest, and `tools/check_shared_core.py`. The macOS CI compile of `confirm_imessage_send.m` and `imessage_helper.c` stays as it is because those sources are not part of this slice.

## Decisions required before implementation

1. Approve this spec and the companion plan, or mark the sections to change.
2. Accept that chat-only sending does not work until a real external signer is enrolled. This fork will not invent the Grok API.
3. Confirm chat approval is hardened-and-root-config only.
4. Confirm a failed chat signature consumes the nonce and does not open the dialog; a new preview without `chat_approval` still uses the dialog.
5. Confirm the nonce TTL stays 60 seconds.
6. Confirm Ed25519, the fixed audience `grokbot-imessage-send`, and the statement layout above.
7. Confirm this fork may diverge from the sibling shared-core fingerprints, and that jeffhuber repos are not to be edited.
8. Confirm the test signer under `tests/` is not to be installed or treated as the owner's key.

Implementation stops until those are accepted. Nothing in this change merges, installs, deploys, or sends.
