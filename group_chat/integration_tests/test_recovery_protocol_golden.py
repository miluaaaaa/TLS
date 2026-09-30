from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import qyp_multi_agent as agent  # noqa: E402
from qyp_multi_gateway import GatewayServer  # noqa: E402
from qyp_multi_registry import Registry  # noqa: E402
from qyp_multi_transport import TransportStore  # noqa: E402


SESSION = "01a00558-3cd2-7690-a2ec-bcb3289f95b2"


class RecoveryProtocolGoldenTests(unittest.TestCase):
    def test_agent_http_and_gateway_sqlite_agree_with_golden_fixture(self) -> None:
        fixture = json.loads((ROOT / "tests/fixtures/recovery_protocol_v2.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            registry = Registry(root / "registry.sqlite3")
            registry.init()
            registry.add_user("ou_owner", "Owner", user_id="user-owner", role="owner", status="approved")
            registry.add_installation("user-owner", "Owner PC", installation_id="inst-owner")
            registry.add_session("inst-owner", SESSION, label="Owner", status="running")
            code = registry.create_pairing("user-owner", installation_id="inst-owner")
            store = TransportStore(registry.path, root / "agent.sqlite3")
            store.init()
            paired = store.pair(code)
            server = GatewayServer(("127.0.0.1", 0), store)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            config = {"TLS_AGENT_URL": f"http://127.0.0.1:{server.server_port}", "TLS_AGENT_TOKEN": paired["token"]}
            try:
                with mock.patch.object(agent, "discover_sessions", return_value=[{"session_id": SESSION, "status": "running"}]):
                    heartbeat = agent.heartbeat_once(config)
                self.assertEqual(heartbeat["protocol_version"], fixture["protocol_version"])
                with sqlite3.connect(registry.path) as connection:
                    connection.execute("UPDATE sessions SET last_seen_at = 1 WHERE session_id = ?", (SESSION,))
                store.session_availability(SESSION, max_age=1)
                with mock.patch.object(agent, "discover_sessions", return_value=[]):
                    heartbeat = agent.heartbeat_once(config)
                ticket = heartbeat["recovery_tickets"][0]
                self.assertTrue(set(fixture["ticket_fields"]).issubset(ticket))
                claim_payload = {"ticket_id": ticket["ticket_id"], "lease_owner": "golden:1", "lease_seconds": 30}
                self.assertEqual(set(claim_payload), set(fixture["claim_fields"]))
                claimed = agent.api_request(config, "/v1/agent/recovery/claim", payload=claim_payload)["ticket"]
                self.assertEqual(claimed["status"], "claimed")
                report_payload = {
                    "ticket_id": ticket["ticket_id"], "event": "launching", "lease_owner": "golden:1",
                    "writer_epoch": claimed["writer_epoch"], "evidence": {"fixture": True},
                }
                self.assertEqual(set(report_payload), set(fixture["report_fields"]))
                agent.api_request(config, "/v1/agent/recovery/report", payload=report_payload)
                with sqlite3.connect(store.path) as connection:
                    state = connection.execute("SELECT status FROM recovery_tickets WHERE ticket_id = ?", (ticket["ticket_id"],)).fetchone()[0]
                    attempts = connection.execute("SELECT count(*) FROM recovery_attempts WHERE ticket_id = ?", (ticket["ticket_id"],)).fetchone()[0]
                self.assertEqual(state, "launching")
                self.assertEqual(attempts, 2)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
