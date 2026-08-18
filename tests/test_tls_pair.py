from __future__ import annotations

import argparse
import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import tls_pair


class PairHelperTests(unittest.TestCase):
    def test_pair_writes_owner_only_config_without_printing_token(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            config = Path(root) / "config" / "agent.env"
            args = argparse.Namespace(
                url="https://api.xhqcode.com/tls-agent",
                code="PAIR-CODE",
                code_stdin=False,
                name="test-agent",
                hostname="test-host",
                config=str(config),
            )
            responses = [
                {
                    "ok": True,
                    "token": "tlsa-test-secret",
                    "user_id": "user-test",
                    "installation_id": "inst-test",
                },
                {
                    "ok": True,
                    "user_id": "user-test",
                    "installation_id": "inst-test",
                    "status": "active",
                },
            ]
            output = io.StringIO()
            with mock.patch.object(tls_pair, "_request", side_effect=responses), contextlib.redirect_stdout(output):
                self.assertEqual(tls_pair.pair(args), 0)
            self.assertNotIn("tlsa-test-secret", output.getvalue())
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
            saved = config.read_text(encoding="utf-8")
            self.assertIn("TLS_AGENT_USER_ID=user-test\n", saved)
            self.assertIn("TLS_AGENT_TOKEN=tlsa-test-secret\n", saved)

    def test_public_http_is_rejected(self) -> None:
        with self.assertRaises(tls_pair.PairingError):
            tls_pair._base_url("http://example.test")

    def test_local_http_is_allowed_for_isolated_tests(self) -> None:
        self.assertEqual(tls_pair._base_url("http://127.0.0.1:8766/"), "http://127.0.0.1:8766")


if __name__ == "__main__":
    unittest.main()
