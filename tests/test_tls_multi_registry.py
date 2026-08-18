from __future__ import annotations

import tempfile
import unittest
import sqlite3
from pathlib import Path

from tls_multi_adapter import claim_event, group_dashboard
from tls_multi_feishu import (
    authorize_group_event,
    claim_group_event,
    complete_group_event,
    group_is_member,
    member_dashboard,
    registered_group,
    shared_task,
    shared_session,
    task_dashboard,
)
from tls_multi_registry import AuthorizationDenied, Registry, RegistryError


SESSION_A = "019ffaf4-eccd-7203-b5b4-51d967ec128b"
SESSION_B = "019ffe42-5df3-76b1-95f8-f671fe1de4dc"
SESSION_C = "019ff92c-d8e3-7f20-b0d3-1b596bff1a91"
SESSION_D = "019ff92c-d8e3-7f20-b0d3-1b596bff1a92"


class MultiUserRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.registry = Registry(Path(self.tempdir.name) / "multi.sqlite3")
        self.registry.init()
        self.owner = self.registry.add_user("ou_owner", "负责人", user_id="user-owner", role="owner", status="approved")
        self.member = self.registry.add_user("ou_member", "成员", user_id="user-member", status="approved")
        self.other = self.registry.add_user("ou_other", "未共享成员", user_id="user-other", status="approved")
        self.installation = self.registry.add_installation("user-owner", "负责人电脑", installation_id="inst-owner", hostname="owner-host")
        self.registry.add_session(
            "inst-owner", SESSION_A, "ASR 零训练纠错", workspace="/workspace/a", status="running"
        )
        self.registry.add_session("inst-owner", SESSION_B, "整理实验结果", status="idle")
        self.group = self.registry.create_group("TLS 测试群", "user-owner", group_id="group-test", feishu_chat_id="oc_test")
        self.registry.add_group_member("group-test", "user-member")
        self.registry.add_group_member("group-test", "user-other")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_private_owner_can_access_only_own_session(self) -> None:
        result = self.registry.authorize("ou_owner", "", SESSION_A, "write")
        self.assertEqual(result["scope"], "private")
        with self.assertRaises(AuthorizationDenied):
            self.registry.authorize("ou_member", "", SESSION_A, "write")

    def test_group_requires_explicit_share(self) -> None:
        with self.assertRaises(AuthorizationDenied):
            self.registry.authorize("ou_member", "oc_test", SESSION_A, "write")
        self.registry.share_session("group-test", SESSION_A, access="write")
        result = self.registry.authorize("ou_member", "oc_test", SESSION_A, "write")
        self.assertEqual(result["scope"], "group")
        with self.assertRaises(AuthorizationDenied):
            self.registry.authorize("ou_other", "oc_test", SESSION_B, "read")

    def test_read_share_cannot_write(self) -> None:
        self.registry.share_session("group-test", SESSION_A, access="read")
        self.assertTrue(self.registry.authorize("ou_member", "oc_test", SESSION_A, "read")["allowed"])
        with self.assertRaises(AuthorizationDenied):
            self.registry.authorize("ou_member", "oc_test", SESSION_A, "write")

    def test_owner_must_be_group_member_before_share(self) -> None:
        self.registry.add_group_member("group-test", "user-owner")
        # The owner is already a member through group creation; sharing succeeds.
        self.assertEqual(self.registry.share_session("group-test", SESSION_B)["access"], "write")

    def test_command_claim_is_idempotent_and_authorized(self) -> None:
        self.registry.share_session("group-test", SESSION_A)
        self.assertTrue(self.registry.claim_command("om_1", "ou_member", "oc_test", SESSION_A))
        self.assertFalse(self.registry.claim_command("om_1", "ou_member", "oc_test", SESSION_A))
        self.registry.complete_command("om_1")
        self.assertFalse(self.registry.claim_command("om_1", "ou_member", "oc_test", SESSION_A))

    def test_pairing_code_is_single_use_and_not_stored_plaintext(self) -> None:
        code = self.registry.create_pairing("user-member", ttl=600)
        self.assertEqual(self.registry.consume_pairing(code)["user_id"], "user-member")
        with self.assertRaises(RegistryError):
            self.registry.consume_pairing(code)
        dump = self.registry.dump()
        self.assertNotIn(code, str(dump))

    def test_dashboard_contains_only_shared_sessions(self) -> None:
        self.registry.share_session("group-test", SESSION_A)
        dashboard = self.registry.group_dashboard("oc_test", "ou_member")
        self.assertEqual([item["session_id"] for item in dashboard["sessions"]], [SESSION_A])
        self.assertEqual(len(dashboard["members"]), 3)

    def test_member_add_assigns_dynamic_slot_and_is_idempotent(self) -> None:
        first = self.registry.add_session_to_group("oc_test", "ou_owner", SESSION_A)
        self.assertEqual(first["slot"], "q3")
        self.assertFalse(first["existing"])
        second = self.registry.add_session_to_group("oc_test", "ou_owner", SESSION_A, access="read")
        self.assertEqual(second["slot"], "q3")
        self.assertTrue(second["existing"])
        self.assertEqual(second["access"], "read")
        dashboard = self.registry.group_dashboard("oc_test", "ou_member")
        row = next(item for item in dashboard["sessions"] if item["session_id"] == SESSION_A)
        self.assertEqual(row["slot"], "q3")
        self.assertEqual(row["access"], "read")

    def test_member_can_add_only_their_own_session(self) -> None:
        member_installation = self.registry.add_installation(
            "user-member", "成员电脑", installation_id="inst-member-add", hostname="member-host"
        )
        self.registry.add_session("inst-member-add", SESSION_C, "成员窗口", status="idle")
        imported = self.registry.add_session_to_group("oc_test", "ou_member", SESSION_C, slot_alias="alice")
        self.assertEqual(imported["slot"], "alice")
        auto_session = SESSION_D
        self.registry.add_session("inst-member-add", auto_session, "成员第二窗口", status="idle")
        with self.assertRaises(RegistryError):
            self.registry.add_session_to_group("oc_test", "ou_member", auto_session, slot_alias="q3")
        auto = self.registry.add_session_to_group("oc_test", "ou_member", auto_session)
        self.assertTrue(auto["slot"].startswith("u-"))
        with self.assertRaises(AuthorizationDenied):
            self.registry.add_session_to_group("oc_test", "ou_member", SESSION_A)

    def test_subscription_recipients_are_scoped(self) -> None:
        self.registry.share_session("group-test", SESSION_A)
        self.registry.subscribe("group-test", "user-member", SESSION_A)
        self.registry.subscribe("group-test", "user-other")
        self.assertEqual(self.registry.notification_recipients("oc_test", SESSION_A), ["ou_member", "ou_other"])

    def test_unshare_revokes_access_and_removes_notifications(self) -> None:
        self.registry.subscribe("group-test", "user-other")
        self.assertEqual(self.registry.notification_recipients("oc_test", SESSION_A), [])
        self.registry.share_session("group-test", SESSION_A, access="write")
        self.registry.subscribe("group-test", "user-member", SESSION_A)
        self.assertEqual(self.registry.notification_recipients("oc_test", SESSION_A), ["ou_member", "ou_other"])

        result = self.registry.unshare_session("group-test", SESSION_A)
        self.assertEqual(result["previous_access"], "write")
        self.assertEqual(result["removed_subscriptions"], 1)
        self.assertTrue(result["unshared"])
        with self.assertRaises(AuthorizationDenied):
            self.registry.authorize("ou_member", "oc_test", SESSION_A, "read")
        self.assertEqual(self.registry.notification_recipients("oc_test", SESSION_A), [])
        self.assertEqual(self.registry.group_dashboard("oc_test", "ou_member")["sessions"], [])
        with self.assertRaises(RegistryError):
            self.registry.unshare_session("group-test", SESSION_A)

    def test_each_user_can_own_sessions_on_a_separate_installation(self) -> None:
        member_installation = self.registry.add_installation(
            "user-member", "成员电脑", installation_id="inst-member", hostname="member-host"
        )
        self.assertEqual(member_installation["user_id"], "user-member")
        session = self.registry.add_session("inst-member", SESSION_C, "成员自己的窗口", status="idle")
        self.assertEqual(session["installation_id"], "inst-member")
        self.assertTrue(self.registry.authorize("ou_member", "", SESSION_C, "write")["allowed"])
        with self.assertRaises(AuthorizationDenied):
            self.registry.authorize("ou_owner", "", SESSION_C, "read")

    def test_new_session_is_shared_to_existing_owner_groups(self) -> None:
        session = self.registry.add_session("inst-owner", SESSION_D, "后来打开的窗口", status="idle")
        self.assertEqual(session["session_id"], SESSION_D)
        dashboard = self.registry.group_dashboard("oc_test", "ou_member")
        self.assertEqual(
            [item["session_id"] for item in dashboard["sessions"]],
            [SESSION_D],
        )
        self.assertTrue(self.registry.authorize("ou_member", "oc_test", SESSION_D, "write")["allowed"])

    def test_member_enrollment_shares_that_members_existing_sessions(self) -> None:
        self.registry.add_installation(
            "user-member", "成员电脑", installation_id="inst-member-existing", hostname="member-host"
        )
        self.registry.add_session("inst-member-existing", SESSION_C, "成员已有窗口", status="idle")
        # The session is created before the member is enrolled in a fresh group.
        self.registry.create_group(
            "第二测试群", "user-owner", group_id="group-second", feishu_chat_id="oc_second"
        )
        self.registry.add_group_member("group-second", "user-member")
        dashboard = self.registry.group_dashboard("oc_second", "ou_member")
        self.assertEqual([item["session_id"] for item in dashboard["sessions"]], [SESSION_C])

    def test_duplicate_session_and_invalid_session_are_rejected(self) -> None:
        with self.assertRaises(RegistryError):
            self.registry.add_session("inst-owner", "not-a-uuid", "bad")
        with self.assertRaises(RegistryError):
            self.registry.add_session("inst-owner", SESSION_A, "duplicate")

    def test_feishu_adapter_requires_group_share_and_deduplicates_message(self) -> None:
        self.registry.share_session("group-test", SESSION_A)
        event = {"open_id": "ou_member", "chat_type": "group", "chat_id": "oc_test", "message_id": "om_group_1"}
        route, claimed = claim_event(self.registry, event, SESSION_A)
        self.assertTrue(claimed)
        self.assertEqual((route.scope, route.chat_id), ("group", "oc_test"))
        _, duplicate = claim_event(self.registry, event, SESSION_A)
        self.assertFalse(duplicate)
        dashboard = group_dashboard(self.registry, event)
        self.assertEqual(dashboard["group"]["group_id"], "group-test")

    def test_feishu_bridge_only_exposes_registered_shared_group_sessions(self) -> None:
        self.assertIsNotNone(registered_group("oc_test", path=self.registry.path))
        self.assertTrue(group_is_member("oc_test", "ou_member", path=self.registry.path))
        self.registry.share_session("group-test", SESSION_A, access="read")
        dashboard = member_dashboard("oc_test", "ou_member", path=self.registry.path)
        self.assertEqual([item["session_id"] for item in dashboard["sessions"]], [SESSION_A])
        self.assertEqual(dashboard["sessions"][0]["workspace"], "/workspace/a")
        self.assertEqual(dashboard["sessions"][0]["installation_id"], "inst-owner")
        self.assertEqual(shared_session("oc_test", "ou_member", path=self.registry.path)["session_id"], SESSION_A)
        event = {"open_id": "ou_member", "chat_type": "group", "chat_id": "oc_test", "message_id": "om_bridge_1"}
        route = authorize_group_event(event, SESSION_A, action="read", path=self.registry.path)
        self.assertEqual((route.scope, route.access), ("group", "read"))
        with self.assertRaises(AuthorizationDenied):
            authorize_group_event(event, SESSION_A, action="write", path=self.registry.path)

        self.registry.share_session("group-test", SESSION_A, access="write")
        route, claimed = claim_group_event(event, SESSION_A, path=self.registry.path)
        self.assertTrue(claimed)
        self.assertEqual(route.access, "write")
        self.assertEqual(complete_group_event("om_bridge_1", path=self.registry.path)["status"], "completed")
        _, duplicate = claim_group_event(event, SESSION_A, path=self.registry.path)
        self.assertFalse(duplicate)

    def test_registered_group_auto_enrolls_a_feishu_sender(self) -> None:
        self.registry.share_session("group-test", SESSION_A, access="write")
        self.assertTrue(group_is_member("oc_test", "ou_new", path=self.registry.path))
        dashboard = member_dashboard("oc_test", "ou_new", path=self.registry.path)
        self.assertEqual([item["session_id"] for item in dashboard["sessions"]], [SESSION_A])
        self.assertEqual(
            next(item for item in dashboard["members"] if item["feishu_open_id"] == "ou_new")["role"],
            "member",
        )

    def test_task_schema_migrates_and_preserves_existing_data(self) -> None:
        with sqlite3.connect(self.registry.path) as connection:
            connection.execute("DROP TABLE task_event_deliveries")
            connection.execute("DROP TABLE task_groups")
            connection.execute("DROP TABLE task_events")
            connection.execute("DROP TABLE task_sessions")
            connection.execute("DROP TABLE tasks")
            connection.execute("DROP TABLE commands")
            connection.execute(
                "CREATE TABLE commands ("
                "message_id TEXT PRIMARY KEY, open_id TEXT NOT NULL, chat_id TEXT NOT NULL DEFAULT '', "
                "session_id TEXT NOT NULL, action TEXT NOT NULL, status TEXT NOT NULL, lease_until INTEGER NOT NULL, "
                "created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)"
            )
            connection.execute("UPDATE meta SET value = '1' WHERE key = 'schema_version'")
        result = self.registry.init()
        self.assertEqual(result["schema_version"], 4)
        with sqlite3.connect(self.registry.path) as connection:
            version = connection.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0]
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
        self.assertEqual(version, "4")
        self.assertTrue({"tasks", "task_sessions", "task_groups", "task_events", "task_event_deliveries"}.issubset(tables))
        command_columns = {
            row[1] for row in sqlite3.connect(self.registry.path).execute("PRAGMA table_info(commands)")
        }
        self.assertIn("task_id", command_columns)
        self.assertEqual(len(self.registry.list_sessions("ou_owner")), 2)

    def test_task_contract_sessions_and_events_are_structured_and_idempotent(self) -> None:
        task = self.registry.create_task(
            "ou_owner",
            "TLS 多人控制面",
            {
                "objective": "验证任务事件链",
                "acceptance": ["事件可回放", "重复事件不重复写入"],
                "constraints": {"paths": ["tls_multi_person_fixture"]},
            },
            task_id="task-control-plane",
        )
        self.assertEqual(task["contract"]["objective"], "验证任务事件链")
        self.assertEqual(task["status"], "planned")

        primary = self.registry.attach_task_session("task-control-plane", SESSION_A, relation="primary")
        worker = self.registry.attach_task_session("task-control-plane", SESSION_B, relation="worker")
        self.assertEqual(primary["relation"], "primary")
        self.assertEqual(worker["relation"], "worker")
        self.assertEqual(
            self.registry.attach_task_session("task-control-plane", SESSION_B, relation="observer")["relation"],
            "observer",
        )

        first = self.registry.append_task_event(
            "task-control-plane",
            "task.started",
            {"summary": "开始", "progress": 0.1},
            session_id=SESSION_A,
            actor_open_id="ou_owner",
            idempotency_key="turn-1-started",
        )
        duplicate = self.registry.append_task_event(
            "task-control-plane",
            "task.started",
            {"summary": "重复投递"},
            session_id=SESSION_A,
            actor_open_id="ou_owner",
            idempotency_key="turn-1-started",
        )
        self.assertEqual(first["event_id"], duplicate["event_id"])
        self.assertEqual(duplicate["payload"]["progress"], 0.1)

        second = self.registry.append_task_event(
            "task-control-plane",
            "task.blocked",
            {"reason": "等待人工确认"},
            session_id=SESSION_B,
            idempotency_key="turn-1-blocked",
        )
        events = self.registry.list_task_events("task-control-plane")
        self.assertEqual([event["event_id"] for event in events], [first["event_id"], second["event_id"]])
        self.assertEqual(self.registry.list_task_events("task-control-plane", after_event_id=first["event_id"])[0]["event_type"], "task.blocked")
        self.assertEqual(self.registry.get_task("task-control-plane")["sessions"][1]["relation"], "observer")

        updated = self.registry.update_task("task-control-plane", status="running", name="TLS 控制面 MVP")
        self.assertEqual(updated["status"], "running")
        self.assertEqual(self.registry.list_tasks("ou_owner", status="running")[0]["task_id"], "task-control-plane")

    def test_task_event_requires_attached_session_and_valid_contract(self) -> None:
        with self.assertRaises(RegistryError):
            self.registry.create_task("ou_owner", "空合同", {})
        self.registry.create_task("ou_owner", "事件约束", {"objective": "x"}, task_id="task-constraints")
        with self.assertRaises(RegistryError):
            self.registry.append_task_event(
                "task-constraints",
                "task.started",
                {"ok": True},
                session_id=SESSION_A,
            )
        with self.assertRaises(RegistryError):
            self.registry.append_task_event("task-constraints", "task.started", {"bad": float("nan")})

    def test_task_session_detach_and_event_filters(self) -> None:
        self.registry.create_task("ou_owner", "筛选事件", {"objective": "x"}, task_id="task-filters")
        self.registry.attach_task_session("task-filters", SESSION_A)
        self.registry.append_task_event("task-filters", "session.running", {"state": "running"}, session_id=SESSION_A)
        self.registry.append_task_event("task-filters", "task.note", {"text": "观察"})
        self.assertEqual(len(self.registry.list_task_events("task-filters", session_id=SESSION_A)), 1)
        self.assertEqual(len(self.registry.list_task_events("task-filters", event_type="task.note")), 1)
        detached = self.registry.detach_task_session("task-filters", SESSION_A)
        self.assertTrue(detached["detached"])
        with self.assertRaises(RegistryError):
            self.registry.detach_task_session("task-filters", SESSION_A)

    def test_task_group_authorization_and_command_events(self) -> None:
        self.registry.share_session("group-test", SESSION_A, access="write")
        self.registry.create_task("ou_owner", "群任务", {"objective": "群内协作"}, task_id="task-group")
        self.registry.attach_task_session("task-group", SESSION_A, relation="primary")
        self.registry.share_task("group-test", "task-group", access="write")
        self.assertEqual(task_dashboard("oc_test", "ou_member", path=self.registry.path)["tasks"][0]["task_id"], "task-group")
        self.assertEqual(shared_task("oc_test", "ou_member", "task-group", path=self.registry.path)["sessions"][0]["session_id"], SESSION_A)
        decision = self.registry.authorize_task("ou_member", "oc_test", "task-group", SESSION_A, "write")
        self.assertEqual((decision["task_id"], decision["scope"], decision["task_relation"]), ("task-group", "group", "primary"))
        with self.assertRaises(AuthorizationDenied):
            self.registry.authorize_task("ou_member", "oc_test", "task-group", SESSION_B, "read")

        event = {"open_id": "ou_member", "chat_type": "group", "chat_id": "oc_test", "message_id": "om_task_1"}
        route, claimed = claim_event(self.registry, event, SESSION_A, task_id="task-group")
        self.assertTrue(claimed)
        self.assertEqual(route.task_id, "task-group")
        command = self.registry.complete_command("om_task_1")
        self.assertEqual(command["task_id"], "task-group")
        self.assertEqual(
            [item["event_type"] for item in self.registry.list_task_events("task-group")],
            ["command.claimed", "command.completed"],
        )

    def test_task_event_delivery_is_scoped_claimable_and_retryable(self) -> None:
        self.registry.share_session("group-test", SESSION_A, access="write")
        self.registry.subscribe("group-test", "user-member", SESSION_A)
        self.registry.create_task("ou_owner", "通知任务", {"objective": "通知"}, task_id="task-notify")
        self.registry.attach_task_session("task-notify", SESSION_A)
        self.registry.share_task("group-test", "task-notify", access="read")
        event = self.registry.append_task_event(
            "task-notify", "task.completed", {"summary": "完成"}, session_id=SESSION_A, idempotency_key="done-1"
        )
        deliveries = self.registry.list_task_event_deliveries(task_id="task-notify", status="pending")
        self.assertEqual(len(deliveries), 1)
        self.assertEqual(deliveries[0]["recipient_open_id"], "ou_member")
        self.assertEqual(deliveries[0]["event_id"], event["event_id"])

        claimed = self.registry.claim_task_event_delivery(deliveries[0]["delivery_id"], lease_seconds=30)
        self.assertEqual(claimed["status"], "claimed")
        self.assertIsNone(self.registry.claim_task_event_delivery(deliveries[0]["delivery_id"], lease_seconds=30))
        failed = self.registry.complete_task_event_delivery(
            deliveries[0]["delivery_id"], status="failed", error="Feishu 暂时不可用", retry_after=1
        )
        self.assertEqual(failed["status"], "failed")
        sent = self.registry.complete_task_event_delivery(deliveries[0]["delivery_id"], status="sent")
        self.assertEqual(sent["status"], "sent")

        self.registry.append_task_event(
            "task-notify", "task.failed", {"reason": "失败"}, session_id=SESSION_A, idempotency_key="failed-1"
        )
        second_delivery = self.registry.list_task_event_deliveries(task_id="task-notify", status="pending")[0]
        self.registry.set_user_status("user-member", "disabled")
        self.assertIsNone(self.registry.claim_task_event_delivery(second_delivery["delivery_id"]))
        self.assertEqual(self.registry.list_task_event_deliveries(task_id="task-notify", status="pending"), [])

    def test_task_share_requires_owner_membership_and_unshare_revokes_scope(self) -> None:
        self.registry.add_user("ou_outsider", "群外用户", user_id="user-outsider", status="approved")
        self.registry.add_installation("user-outsider", "群外电脑", installation_id="inst-outsider")
        self.registry.add_session("inst-outsider", SESSION_C, "群外窗口")
        self.registry.create_task("ou_outsider", "群外任务", {"objective": "授权"}, task_id="task-outsider")
        self.registry.attach_task_session("task-outsider", SESSION_C)
        with self.assertRaises(RegistryError):
            self.registry.share_task("group-test", "task-outsider")

        self.registry.create_task("ou_owner", "授权任务", {"objective": "授权"}, task_id="task-access")
        self.registry.attach_task_session("task-access", SESSION_A)
        self.registry.share_task("group-test", "task-access")
        self.assertTrue(self.registry.unshare_task("group-test", "task-access")["unshared"])
        with self.assertRaises(AuthorizationDenied):
            self.registry.authorize_task("ou_member", "oc_test", "task-access", SESSION_A, "read")


if __name__ == "__main__":
    unittest.main()
