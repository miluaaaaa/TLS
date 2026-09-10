from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from tls_multi_registry import Registry
from tls_multi_transport import TransportError, TransportStore


SESSION = "01a00558-3cd2-7690-a2ec-bcb3289f95b2"


class TransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.registry = Registry(root / "registry.sqlite3")
        self.registry.init()
        self.registry.add_user("ou_owner", "Owner", user_id="user-owner", role="owner", status="approved")
        self.registry.add_installation("user-owner", "Owner PC", installation_id="inst-owner")
        self.registry.create_group("TLS 测试群", "user-owner", group_id="group-test", feishu_chat_id="oc_test")
        self.registry.add_session("inst-owner", SESSION, label="Owner session", status="offline")
        self.registry.share_session("group-test", SESSION, access="write")
        self.code = self.registry.create_pairing("user-owner", installation_id="inst-owner")
        self.store = TransportStore(self.registry.path, root / "agent.sqlite3")
        self.store.init()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_pair_heartbeat_queue_and_event(self) -> None:
        paired = self.store.pair(self.code, name="Owner PC")
        self.assertTrue(str(paired["token"]).startswith("tlsa_"))
        heartbeat = self.store.heartbeat(
            paired["token"],
            [{"session_id": SESSION, "label": "Owner session", "status": "idle"}],
        )
        self.assertEqual(heartbeat["sessions"][0]["status"], "idle")
        queued = self.store.enqueue(
            message_id="om_command",
            open_id="ou_owner",
            chat_id="oc_test",
            session_id=SESSION,
            text="测试命令",
        )
        self.assertTrue(queued["queued"])
        commands = self.store.poll(paired["token"])
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0]["payload"]["text"], "测试命令")
        self.store.complete(
            paired["token"],
            commands[0]["command_id"],
            status="completed",
            result={"answer": "已完成"},
        )
        event = self.store.next_event()
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["payload"]["result"]["answer"], "已完成")
        self.assertIsNotNone(self.store.claim_event(int(event["event_id"])))
        self.store.complete_event(int(event["event_id"]), status="sent")
        self.assertIsNone(self.store.next_event())

    def test_busy_command_can_be_released(self) -> None:
        paired = self.store.pair(self.code, name="Owner PC")
        queued = self.store.enqueue(
            message_id="om_release",
            open_id="ou_owner",
            chat_id="oc_test",
            session_id=SESSION,
            text="稍后执行",
        )
        self.store.poll(paired["token"])
        released = self.store.release(paired["token"], queued["command_id"], reason="session-busy")
        self.assertEqual(released["status"], "queued")
        self.assertEqual(len(self.store.poll(paired["token"])), 1)

    def test_authorized_retry_replaces_prior_failed_event_with_completion(self) -> None:
        paired = self.store.pair(self.code, name="Owner PC")
        queued = self.store.enqueue(
            message_id="om_retry",
            open_id="ou_owner",
            chat_id="oc_test",
            session_id=SESSION,
            text="重新执行",
        )
        first = self.store.poll(paired["token"])[0]
        self.store.complete(
            paired["token"], first["command_id"], attempts=1, status="failed", error="runtime-unavailable"
        )
        failed_event = self.store.next_event()
        assert failed_event is not None
        self.store.claim_event(int(failed_event["event_id"]))
        self.store.complete_event(int(failed_event["event_id"]), status="sent")
        with self.store._connect() as connection:
            connection.execute(
                "UPDATE agent_commands SET status = 'queued', lease_until = 0 WHERE command_id = ?",
                (queued["command_id"],),
            )
        second = self.store.poll(paired["token"])[0]
        self.assertEqual(second["attempts"], 2)
        self.store.complete(
            paired["token"], second["command_id"], attempts=2, status="completed", result={"answer": "完成"}
        )
        completion_event = self.store.next_event()
        assert completion_event is not None
        self.assertEqual(completion_event["event_type"], "command.completed")
        self.assertEqual(completion_event["payload"]["result"]["answer"], "完成")

    def test_fault_healer_can_retry_only_one_known_preturn_failure(self) -> None:
        paired = self.store.pair(self.code, name="Owner PC")
        queued = self.store.enqueue(
            message_id="om_auto_retry", open_id="ou_owner", chat_id="oc_test", session_id=SESSION, text="自动重投"
        )
        first = self.store.poll(paired["token"])[0]
        self.store.complete(
            paired["token"], first["command_id"], attempts=1, status="failed", error="turn-id-unavailable-cursor-runtime"
        )
        retried = self.store.retry_failed(paired["token"], queued["command_id"], reason="fault-healer")
        self.assertEqual(retried["status"], "queued")
        self.assertEqual(self.store.poll(paired["token"])[0]["attempts"], 2)
        with self.assertRaises(TransportError):
            self.store.retry_failed(paired["token"], queued["command_id"], reason="again")

    def test_command_lease_can_be_renewed_and_attempt_is_checked(self) -> None:
        paired = self.store.pair(self.code, name="Owner PC")
        queued = self.store.enqueue(
            message_id="om_renew",
            open_id="ou_owner",
            chat_id="oc_test",
            session_id=SESSION,
            text="长任务",
        )
        polled = self.store.poll(paired["token"])
        self.assertEqual(polled[0]["attempts"], 1)
        renewed = self.store.renew(
            paired["token"],
            queued["command_id"],
            attempts=1,
            lease_seconds=120,
        )
        self.assertGreaterEqual(int(renewed["lease_until"]), int(time.time()) + 100)
        with self.assertRaises(TransportError):
            self.store.renew(paired["token"], queued["command_id"], attempts=2)
        with self.assertRaises(TransportError):
            self.store.complete(
                paired["token"],
                queued["command_id"],
                attempts=2,
                status="completed",
                result={"answer": "错误尝试"},
            )
        self.store.complete(
            paired["token"],
            queued["command_id"],
            attempts=1,
            status="completed",
            result={"answer": "完成"},
        )

    def test_invalid_token_is_rejected(self) -> None:
        with self.assertRaises(TransportError):
            self.store.info("tlsa_invalid")

    def test_session_availability_requires_fresh_online_heartbeat(self) -> None:
        paired = self.store.pair(self.code, name="Owner PC")
        self.assertFalse(self.store.session_availability(SESSION)["online"])
        self.store.heartbeat(
            paired["token"],
            [{"session_id": SESSION, "label": "Owner session", "status": "idle"}],
        )
        self.assertTrue(self.store.session_availability(SESSION)["online"])
        self.store.heartbeat(
            paired["token"],
            [{"session_id": SESSION, "label": "Owner session", "status": "offline"}],
        )
        self.assertFalse(self.store.session_availability(SESSION)["online"])


if __name__ == "__main__":
    unittest.main()
