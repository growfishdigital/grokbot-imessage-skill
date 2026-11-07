"""Lock the current send gate while the G2 comparison is unresolved.

Unverified approval fields must not reach Messages unless the native
confirmation helper returns Send. AppleScript is mocked.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests._helper_loader import REPO_ROOT, helper


class NativeGateHoldTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="native-gate-hold-")
        self.addCleanup(self.tmp.cleanup)
        bridge = os.path.realpath(self.tmp.name)
        os.chmod(bridge, 0o700)
        self.old_bridge = os.environ.get("IMESSAGE_BRIDGE_DIR")
        self.old_alias = os.environ.get("COWORK_IMESSAGE_BRIDGE_DIR")
        os.environ["IMESSAGE_BRIDGE_DIR"] = bridge
        os.environ["COWORK_IMESSAGE_BRIDGE_DIR"] = bridge
        self.addCleanup(self._restore)

    def _restore(self) -> None:
        if self.old_bridge is None:
            os.environ.pop("IMESSAGE_BRIDGE_DIR", None)
        else:
            os.environ["IMESSAGE_BRIDGE_DIR"] = self.old_bridge
        if self.old_alias is None:
            os.environ.pop("COWORK_IMESSAGE_BRIDGE_DIR", None)
        else:
            os.environ["COWORK_IMESSAGE_BRIDGE_DIR"] = self.old_alias

    def test_declined_dialog_blocks_unverified_approval_fields(self) -> None:
        recipient = "+14155551234"
        text = "Send it"
        nonce = helper.mint_send_nonce(recipient, text, "iMessage")
        with mock.patch.object(helper, "_run_send_confirmation", return_value=False), \
             mock.patch.object(helper, "_run_osascript") as script:
            with self.assertRaisesRegex(RuntimeError, "cancelled"):
                helper.action_send(
                    {
                        "to": recipient,
                        "text": text,
                        "service": "iMessage",
                        "send_nonce": nonce,
                        "approval": True,
                        "chat_approval": {
                            "key_id": "agent",
                            "signature": "not-a-signature",
                        },
                    },
                    None,
                    {},
                    [],
                )
        script.assert_not_called()

    def test_unverified_approval_still_asks_native_dialog_before_send(self) -> None:
        recipient = "+14155551234"
        text = "Exact draft"
        nonce = helper.mint_send_nonce(recipient, text, "iMessage")
        with mock.patch.object(helper, "_run_send_confirmation", return_value=True) as confirm, \
             mock.patch.object(helper, "_run_osascript", return_value=(0, "", "")) as script:
            helper.action_send(
                {
                    "to": recipient,
                    "text": text,
                    "send_nonce": nonce,
                    "approval": True,
                },
                None,
                {},
                [],
            )
        confirm.assert_called_once()
        script.assert_called_once()

    def test_action_send_still_calls_native_confirmation(self) -> None:
        source = (REPO_ROOT / "bin" / "helper.py").read_text(encoding="utf-8")
        start = source.index("def action_send(")
        end = source.index("\ndef ", start + 1)
        body = source[start:end]
        self.assertIn("_run_send_confirmation(", body)
        self.assertNotIn("approved_send", body)
        self.assertNotIn("approvalKey", body)
