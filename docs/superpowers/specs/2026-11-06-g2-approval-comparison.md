# G2 glasses approval compared with this skill

Status: comparison only. No send-path code in this fork changes because of it. No GrokHUD source is copied here.

Reviewed artifact: a source-only working-tree snapshot collected November 6, 2026 from the GrokHUD tree Andrew named (`prototype/hold-to-speak-overlays`, named HEAD `a6bdb650d7a27a7cec62bc3c823fed279f4b033f`). The snapshot’s own readme says it is the working tree, not that git commit, and that `relay/`, `gateway/src/imessage.ts`, and `docs/imessage.md` were untracked locally. This agent’s GitHub credential received 404 for `growfishdigital/GrokHUD`, so the public commit was not reviewed. The Mac folder was not opened. The snapshot text was screened by its collector; this review did not execute it and did not send.

Andrew reports that approving on the glasses results in a send he sees from the phone. The snapshot’s own doc says physical G2 checks for this transport are still pending, and that a live gateway-to-Messages test was done through the dedicated Mac helper. Those are separate claims. This note follows the source.

## What actually sends

The phone does not submit the message to Messages. The path in the snapshot is:

1. The glasses UI, or the phone’s Send button, accepts one exact draft.
2. The phone app posts that text to the gateway with the owner’s gateway client token.
3. The gateway stores it as a queued outgoing message for five minutes.
4. A Mac relay, using a separate per-thread relay token, claims that queue item.
5. The relay signs a local command with a key that stays on the Mac and asks its own helper to send.
6. That helper runs AppleScript against Messages on the Mac.

The phone is the approval screen and the gateway client. The Mac is the Messages sender.

## How owner approval is authenticated

On the glasses, a long-press records the bot, draft revision, exact draft text, and the screen the owner is looking at. The release counts as Send only if that same draft is still on screen. The phone Send button submits the current draft the same way. That check is inside the app. It does not produce a signature the Mac can verify later.

The phone then calls the gateway’s message route with `Authorization: Bearer` set to the gateway client token stored in the app. For an iMessage thread, the gateway saves the text, a message id, and a five-minute queue expiry. It does not require a glasses signature.

The Mac relay polls with a different bearer token, issued for one thread at pairing. It refuses the poll unless the gateway’s thread id, recipient, and service match the Mac’s private `thread.json`. It claims the message id once. After a claim, the relay builds a JSON command containing that id, the text, the thread, and a timestamp, and HMAC-SHA256-signs it with `approvalKey`.

`approvalKey` is 32 random bytes created on the Mac at pairing. It is stored only in the Mac’s private thread file. The glasses and the phone do not have it. The dedicated helper checks the HMAC, requires the signed thread to match the local binding, and rejects a signature older than about 90 seconds. The recipient used in AppleScript is the local binding, not a recipient supplied by the gateway command. The body is the text inside the signed command, which the relay copied from the queue.

So there are three different controls:

| Step | What it proves |
| --- | --- |
| Glasses long-press or phone Send | The app that is showing the draft decided to submit that text |
| Gateway client token | The caller may enqueue a message for that connected bot |
| Mac HMAC | The Mac relay, which can read `approvalKey`, signed this command for the locally bound recipient |

The HMAC is not proof that the glasses were used. Any caller who can POST to the gateway with the client token can enqueue. The relay will then sign and the Mac helper will send, without the Grok Bot native dialog. The snapshot’s install note says a same-user process on the Mac is not isolated from these private files.

## Who can enqueue or approve

- Provisioning a thread uses the owner gateway client token. Pairing writes the relay token and the approval key on the Mac and does not keep the client token in the relay config.
- Enqueue uses that same owner client token, from the phone app’s `send` call. The glasses event only triggers the phone app.
- Poll, claim, and result use the per-thread relay token. That token cannot select another thread. It cannot change the Mac’s recipient binding.
- The dedicated helper accepts `approved_send` only with a valid local HMAC. It does not call this skill’s `send` action, so it does not show this skill’s native dialog.

## Grok Bot and those credentials

This skill’s bridge folder and LaunchAgent stay separate in the snapshot’s doc. The approval key, relay token, and gateway client token are not fields in this skill’s protocol. Nothing in the snapshot gives the Grok Bot agent an API that returns those secrets or a signature over a chat draft.

The Grok agent could use this path only if someone placed the gateway client token where the agent can call the gateway. That token is enough to enqueue without a glasses press. That would not be independent owner consent.

The Mac approval key would also be the wrong thing to copy into this skill. The agent, or any same-user process that can read the bridge, could HMAC a command and skip the dialog. The snapshot already uses that key to prove the relay signed its own command, not to prove a remote chat approved it.

## Reuse, without a second sender

This is not the same mechanism as “Grok chat signs an Ed25519 statement and this helper skips the dialog.”

G2 already has a working shape for glasses-to-Mac sends:

- The owner approves an exact draft in Current, on the glasses or the phone.
- The phone enqueues with a token the agent is not supposed to hold.
- The Mac relay checks the paired recipient and signs locally.
- Messages is driven on the Mac by a helper that is not this skill’s helper.

There is no request in this snapshot that lets Grok Bot ask the glasses for a signature and then present it to `bin/helper.py`. Adding that would be new GrokHUD work, not reuse. Treating a sentence in Grok chat as the glasses press would skip the only step the owner actually performs.

## Proposed adjustment (not implemented)

Leave `grokbot-imessage-skill` on the native dialog. Do not add the Ed25519 chat-approval bypass from the earlier plan until Andrew chooses otherwise. Do not copy GrokHUD sources, keys, or tokens into this public fork. Do not point this helper at `approved_send`.

If the desired product is “approve on the glasses, then Messages goes out,” that product is the GrokHUD relay, and the send already happens on the Mac. A Grok chat draft would need to be approved again inside Current by the owner. The chat agent must not be given the gateway client token, the relay token, or `approvalKey`.

The earlier plan’s pure-Python Ed25519 verifier should not be built as written. G2 uses HMAC-SHA256 with a Mac-local key. If a later change still adds a verifier to this skill, use PyCA `cryptography` (`Ed25519PublicKey.from_public_bytes` and `verify`) or the platform’s existing HMAC check, and keep the private key where the agent cannot read it. A missing verifier library must leave the native dialog in place.

Vendored `send_gate.py` in the snapshot matches this fork’s `shared-core.json` digest `4b813be2f18a0985d29aef1c34da8be4d10f2ae6a8c1bce300fb77abf3042cd1`. The dedicated worker does not use that gate’s nonce for `approved_send`. It calls AppleScript itself after the HMAC check.
