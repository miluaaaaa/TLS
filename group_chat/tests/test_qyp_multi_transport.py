from __future__ import annotations

import tempfile
import unittest
import sqlite3
from pathlib import Path

from qyp_multi_registry import Registry, RegistryError
from qyp_multi_transport import TransportError, TransportStore


SESSION = "01a00558-3cd2-7690-a2ec-bcb3289f95b2"
SESSION_BUILDER = "01a00558-3cd2-7690-a2ec-bcb3289f95c3"
SESSION_TESTER = "01a00558-3cd2-7690-a2ec-bcb3289f95c4"


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

    def test_completion_notification_is_idempotent_and_installation_scoped(self) -> None:
        token = self.store.pair(self.code)["token"]
        first = self.store.publish_completion_notification(
            token, event_key="turn-1", session_id=SESSION,
            conversation="Test", user_message="Question", answer="Answer",
        )
        repeated = self.store.publish_completion_notification(
            token, event_key="turn-1", session_id=SESSION,
            conversation="Test", user_message="Question", answer="Answer",
        )
        self.assertEqual(first["notification_id"], repeated["notification_id"])
        notification_id = first["notification_id"]
        self.assertEqual(self.store.next_completion_notification()["notification_id"], notification_id)
        self.assertIsNotNone(self.store.claim_completion_notification(notification_id))
        self.assertIsNone(self.store.claim_completion_notification(notification_id))
        self.store.complete_completion_notification(notification_id, status="sent")
        self.assertIsNone(self.store.next_completion_notification())

        self.registry.add_user("ou_other", "Other", user_id="user-other", status="approved")
        self.registry.add_installation("user-other", "Other PC", installation_id="inst-other")
        self.registry.add_session("inst-other", SESSION_BUILDER, label="Other session")
        with self.assertRaisesRegex(TransportError, "不属于当前 Agent"):
            self.store.publish_completion_notification(
                token, event_key="turn-other", session_id=SESSION_BUILDER,
                conversation="Other", user_message="Private", answer="Private",
            )

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

    def test_protocol_mismatch_keeps_recovery_awaiting_guardian(self) -> None:
        paired = self.store.pair(self.code, name="Owner PC")
        self.store.heartbeat(
            paired["token"],
            [{"session_id": SESSION, "label": "Owner session", "status": "running"}],
        )
        with sqlite3.connect(self.registry.path) as connection:
            connection.execute(
                "UPDATE sessions SET last_seen_at = 1 WHERE session_id = ?", (SESSION,)
            )
        availability = self.store.session_availability(SESSION, max_age=1)
        self.assertFalse(availability["online"])
        self.assertEqual(availability["recovery_ticket"]["status"], "awaiting_guardian")
        self.assertEqual(self.store.heartbeat(paired["token"], [], protocol_version="1")["recovery_tickets"], [])

    def test_recovery_claim_launch_and_explicit_report_are_fenced(self) -> None:
        paired = self.store.pair(self.code, name="Owner PC")
        self.store.heartbeat(
            paired["token"],
            [{"session_id": SESSION, "label": "Owner session", "status": "running"}],
            protocol_version="2",
            release_id="test-release",
        )
        with sqlite3.connect(self.registry.path) as connection:
            connection.execute("UPDATE sessions SET last_seen_at = 1 WHERE session_id = ?", (SESSION,))
        ticket = self.store.session_availability(SESSION, max_age=1)["recovery_ticket"]
        self.assertEqual(ticket["status"], "detected")
        claim = self.store.claim_recovery(paired["token"], ticket["ticket_id"], "owner:1")
        self.assertEqual(claim["status"], "claimed")
        self.assertEqual(claim["writer_epoch"], 1)
        with self.assertRaisesRegex(TransportError, "不可 claim"):
            self.store.claim_recovery(paired["token"], ticket["ticket_id"], "owner:2")
        launching = self.store.report_recovery(
            paired["token"], ticket["ticket_id"], "launching",
            lease_owner="owner:1", writer_epoch=1, evidence={"tmux": "test"},
        )
        self.assertEqual(launching["status"], "launching")
        heartbeat = self.store.heartbeat(
            paired["token"],
            [{"session_id": SESSION, "status": "idle", "recovery_ticket_id": ticket["ticket_id"], "writer_epoch": 1}],
            protocol_version="2",
        )
        self.assertEqual(heartbeat["recovery_heartbeats"], [ticket["ticket_id"]])
        recovered = self.store.report_recovery(
            paired["token"], ticket["ticket_id"], "recovered",
            lease_owner="owner:1", writer_epoch=1, evidence={"heartbeat_confirmed": True},
        )
        self.assertEqual(recovered["status"], "recovered")
        with sqlite3.connect(self.store.path) as connection:
            events = connection.execute(
                "SELECT event FROM recovery_attempts WHERE ticket_id = ? ORDER BY attempt_id", (ticket["ticket_id"],)
            ).fetchall()
        self.assertEqual([row[0] for row in events], ["claimed", "launching", "recovered"])

    def test_live_writer_cancels_without_epoch_increment(self) -> None:
        paired = self.store.pair(self.code, name="Owner PC")
        self.store.heartbeat(paired["token"], [{"session_id": SESSION, "status": "running"}], protocol_version="2")
        with sqlite3.connect(self.registry.path) as connection:
            connection.execute("UPDATE sessions SET last_seen_at = 1 WHERE session_id = ?", (SESSION,))
        ticket = self.store.session_availability(SESSION, max_age=1)["recovery_ticket"]
        cancelled = self.store.report_recovery(paired["token"], ticket["ticket_id"], "cancelled_live", evidence={"pid": 42})
        self.assertEqual(cancelled["status"], "cancelled_live")
        with sqlite3.connect(self.store.path) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM session_writers").fetchone()[0], 0)

    def test_stale_session_command_waits_and_keeps_identity(self) -> None:
        paired = self.store.pair(self.code, name="Owner PC")
        self.store.heartbeat(paired["token"], [{"session_id": SESSION, "status": "running"}], protocol_version="2")
        with sqlite3.connect(self.registry.path) as connection:
            connection.execute("UPDATE sessions SET last_seen_at = 1 WHERE session_id = ?", (SESSION,))
        queued = self.store.enqueue(
            message_id="om_waiting", open_id="ou_owner", chat_id="oc_test",
            session_id=SESSION, text="wait for recovery",
        )
        self.assertTrue(queued["waiting_recovery"])
        self.assertEqual(self.store.poll(paired["token"]), [])
        with sqlite3.connect(self.store.path) as connection:
            ticket_id = connection.execute("SELECT ticket_id FROM recovery_tickets WHERE session_id = ?", (SESSION,)).fetchone()[0]
        self.store.report_recovery(paired["token"], ticket_id, "cancelled_live", evidence={"pid": 42})
        command = self.store.poll(paired["token"])[0]
        self.assertEqual(command["command_id"], queued["command_id"])

    def test_epoch_rejects_old_command_completion_and_retry_needs_absence_proof(self) -> None:
        paired = self.store.pair(self.code, name="Owner PC")
        self.store.heartbeat(paired["token"], [{"session_id": SESSION, "status": "idle"}], protocol_version="2")
        queued = self.store.enqueue(
            message_id="om_fence", open_id="ou_owner", chat_id="oc_test", session_id=SESSION, text="once",
        )
        first = self.store.poll(paired["token"])[0]
        with sqlite3.connect(self.store.path) as connection:
            connection.execute("INSERT INTO session_writers(session_id,writer_epoch,updated_at) VALUES (?,?,1)", (SESSION, 1))
            connection.execute("UPDATE agent_commands SET writer_epoch=1 WHERE command_id=?", (queued["command_id"],))
        with self.assertRaisesRegex(TransportError, "lease lost"):
            self.store.complete(
                paired["token"], queued["command_id"], attempts=first["attempts"], writer_epoch=0,
                status="completed", result={"answer": "stale"},
            )
        self.store.complete(
            paired["token"], queued["command_id"], attempts=first["attempts"], writer_epoch=1,
            status="failed", error="runtime-unavailable", transcript_proof="unknown",
        )
        with self.assertRaisesRegex(TransportError, "自动重试"):
            self.store.retry_failed(paired["token"], queued["command_id"], reason="test")

    def test_three_launch_failures_end_in_explicit_failure(self) -> None:
        paired = self.store.pair(self.code, name="Owner PC")
        self.store.heartbeat(paired["token"], [{"session_id": SESSION, "status": "running"}], protocol_version="2")
        with sqlite3.connect(self.registry.path) as connection:
            connection.execute("UPDATE sessions SET last_seen_at = 1 WHERE session_id = ?", (SESSION,))
        ticket_id = self.store.session_availability(SESSION, max_age=1)["recovery_ticket"]["ticket_id"]
        states = []
        epochs = []
        for attempt in range(1, 4):
            with sqlite3.connect(self.store.path) as connection:
                connection.execute("UPDATE recovery_tickets SET next_attempt_at = 0 WHERE ticket_id = ?", (ticket_id,))
            claimed = self.store.claim_recovery(paired["token"], ticket_id, f"owner:{attempt}")
            epochs.append(claimed["writer_epoch"])
            reported = self.store.report_recovery(
                paired["token"], ticket_id, "launch_failed", lease_owner=f"owner:{attempt}",
                writer_epoch=claimed["writer_epoch"], error="boom",
            )
            states.append(reported["status"])
        self.assertEqual(states, ["detected", "detected", "failed"])
        self.assertEqual(epochs, [1, 2, 3])

    def test_legacy_active_ticket_gets_a_bounded_deadline(self) -> None:
        paired = self.store.pair(self.code, name="Owner PC")
        self.store.heartbeat(paired["token"], [{"session_id": SESSION, "status": "running"}], protocol_version="2")
        with sqlite3.connect(self.registry.path) as connection:
            connection.execute("UPDATE sessions SET last_seen_at = 1 WHERE session_id = ?", (SESSION,))
        ticket_id = self.store.session_availability(SESSION, max_age=1)["recovery_ticket"]["ticket_id"]
        with sqlite3.connect(self.store.path) as connection:
            connection.execute(
                "UPDATE recovery_tickets SET status='awaiting_guardian', deadline_at=0, next_attempt_at=0 "
                "WHERE ticket_id=?",
                (ticket_id,),
            )

        self.store.init()
        heartbeat = self.store.heartbeat(
            paired["token"], [{"session_id": SESSION, "status": "offline"}], protocol_version="2"
        )

        self.assertEqual(heartbeat["recovery_tickets"][0]["ticket_id"], ticket_id)
        self.assertGreater(heartbeat["recovery_tickets"][0]["deadline_at"], 0)

    def test_frontend_disappearance_creates_ticket_after_offline_threshold(self) -> None:
        paired = self.store.pair(self.code, name="Owner PC")
        self.store.heartbeat(paired["token"], [{"session_id": SESSION, "status": "running"}], protocol_version="2")
        self.store.heartbeat(paired["token"], [{"session_id": SESSION, "status": "offline"}], protocol_version="2")
        with sqlite3.connect(self.registry.path) as connection:
            connection.execute(
                "INSERT INTO session_slots(group_id,slot,session_id,assigned_by,created_at) VALUES ('group-test','q1',?,'user-owner',1)",
                (SESSION,),
            )
        with sqlite3.connect(self.store.path) as connection:
            connection.execute("UPDATE session_health SET offline_since = 1 WHERE session_id = ?", (SESSION,))
        tickets = self.store.scan_recovery_tickets(max_age=1)
        self.assertEqual(len(tickets), 1)
        self.assertEqual(tickets[0]["status"], "detected")

    def test_image_media_reference_survives_command_queue(self) -> None:
        paired = self.store.pair(self.code, name="Owner PC")
        self.store.heartbeat(
            paired["token"],
            [{"session_id": SESSION, "label": "Owner session", "status": "idle"}],
        )
        queued = self.store.enqueue(
            message_id="om_image_command",
            open_id="ou_owner",
            chat_id="oc_test",
            session_id=SESSION,
            text="请查看这张图片并直接回答。",
            extra={
                "message_type": "image",
                "image_media_id": "a" * 64,
                "image_instruction": "识别颜色",
            },
        )
        self.assertTrue(queued["queued"])
        command = self.store.poll(paired["token"])[0]
        self.assertEqual(command["payload"]["image_media_id"], "a" * 64)
        self.assertEqual(command["payload"]["image_instruction"], "识别颜色")

    def test_invalid_token_is_rejected(self) -> None:
        with self.assertRaises(TransportError):
            self.store.info("tlsa_invalid")

    def test_agent_tokens_use_broker_channel_without_shared_credentials(self) -> None:
        self.registry.add_user("ou_builder", "Builder", user_id="user-builder", status="approved")
        self.registry.add_user("ou_tester", "Tester", user_id="user-tester", status="approved")
        self.registry.add_installation("user-builder", "Builder PC", installation_id="inst-builder")
        self.registry.add_installation("user-tester", "Tester PC", installation_id="inst-tester")
        self.registry.add_session("inst-builder", SESSION_BUILDER, label="Builder", status="running")
        self.registry.add_session("inst-tester", SESSION_TESTER, label="Tester", status="running")
        self.registry.create_task("ou_owner", "Channel task", {"objective": "broker"}, task_id="task-channel")
        self.registry.attach_task_session("task-channel", SESSION_BUILDER, relation="worker")
        self.registry.attach_task_session("task-channel", SESSION_TESTER, relation="worker")
        builder_assignment = self.registry.create_task_assignment(
            "task-channel", "ou_builder", "implementer", session_id=SESSION_BUILDER, assignment_id="assignment-builder"
        )
        tester_assignment = self.registry.create_task_assignment(
            "task-channel", "ou_tester", "tester", session_id=SESSION_TESTER, assignment_id="assignment-tester"
        )
        self.registry.start_agent_run(
            "task-channel", SESSION_BUILDER, assignment_id=builder_assignment["assignment_id"], run_id="run-builder"
        )
        self.registry.start_agent_run(
            "task-channel", SESSION_TESTER, assignment_id=tester_assignment["assignment_id"], run_id="run-tester"
        )
        self.registry.grant_role(
            "ou_builder", "implementer", scope_type="task", scope_id="task-channel", granted_by="ou_owner"
        )
        builder_code = self.registry.create_pairing("user-builder", installation_id="inst-builder")
        tester_code = self.registry.create_pairing("user-tester", installation_id="inst-tester")
        builder = self.store.pair(builder_code, name="Builder PC")
        tester = self.store.pair(tester_code, name="Tester PC")

        requested = self.store.request_channel(
            builder["token"], "task-channel", "run-builder", "run-tester", ["agent.message"]
        )
        active = self.store.accept_channel(tester["token"], requested["channel_id"], "run-tester")
        sent = self.store.send_channel_message(
            builder["token"],
            active["channel_id"],
            "run-builder",
            "transport-message-1",
            {"kind": "evidence", "summary": "ready"},
        )
        self.assertEqual(sent["status"], "queued")
        polled = self.store.poll_channel_messages(
            tester["token"], active["channel_id"], "run-tester"
        )
        self.assertEqual(polled[0]["payload"]["summary"], "ready")
        self.assertEqual(
            self.store.ack_channel_message(tester["token"], "transport-message-1", "run-tester")["status"],
            "acknowledged",
        )
        with self.assertRaises(RegistryError):
            self.store.poll_channel_messages(builder["token"], active["channel_id"], "run-tester")
        with self.assertRaises(RegistryError):
            self.store.send_channel_message(
                builder["token"], active["channel_id"], "run-builder", "transport-secret", {"token": "x"}
            )

        for database in (self.registry.path, self.store.path):
            with sqlite3.connect(database) as connection:
                dump = " ".join(str(row) for row in connection.iterdump())
            self.assertNotIn(str(builder["token"]), dump)
            self.assertNotIn(str(tester["token"]), dump)


if __name__ == "__main__":
    unittest.main()
