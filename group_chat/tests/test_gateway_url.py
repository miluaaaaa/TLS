from __future__ import annotations

import unittest

from gateway_url import gateway_base_url


class GatewayUrlTests(unittest.TestCase):
    def test_https_and_local_http(self) -> None:
        self.assertEqual(gateway_base_url("https://gateway.example.test/tls-agent/"), "https://gateway.example.test/tls-agent")
        self.assertEqual(gateway_base_url("http://127.0.0.1:8766"), "http://127.0.0.1:8766")

    def test_rejects_public_http_and_url_credentials(self) -> None:
        for url in (
            "http://gateway.example.test",
            "https://user:password@gateway.example.test",
            "https://gateway.example.test/?token=secret",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                gateway_base_url(url)
