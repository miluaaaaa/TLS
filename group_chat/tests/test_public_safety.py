from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from qyp_multi_gateway import GatewayHandler, main
from qyp_multi_registry import Registry
from qyp_multi_transport import TransportStore
from tls_multi_gateway import GatewayHandler as LegacyGatewayHandler
from tls_multi_gateway import main as legacy_main


class PublicSafetyTests(unittest.TestCase):
    def test_sqlite_files_are_private_even_without_explicit_init(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = Registry(root / "registry.sqlite3")
            with registry._connect():
                pass
            transport = TransportStore(registry.path, root / "agent.sqlite3")
            with transport._connect():
                pass
            self.assertEqual(registry.path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(transport.path.stat().st_mode & 0o777, 0o600)

    def test_gateway_rejects_non_loopback_bind(self) -> None:
        for entrypoint in (main, legacy_main):
            with self.subTest(entrypoint=entrypoint.__module__):
                with mock.patch("sys.argv", ["gateway", "--host", "0.0.0.0"]), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:
                        entrypoint()
                self.assertEqual(error.exception.code, 2)

    def test_gateway_access_log_does_not_write_request_target(self) -> None:
        for handler_type in (GatewayHandler, LegacyGatewayHandler):
            with self.subTest(handler=handler_type.__module__):
                handler = object.__new__(handler_type)
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    handler.log_message('GET /health?code=secret HTTP/1.1', 200)
                self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
