from __future__ import annotations

import tempfile
import unittest
import sqlite3
from pathlib import Path

from qyp_multi_adapter import claim_event, group_dashboard
from qyp_multi_feishu import (
    authorize_group_event,
    claim_group_event,
    complete_group_event,
    group_is_member,
    member_dashboard,
    registered_group,
    bind_group_task_session,
    shared_task,
    shared_session,
    submit_agent_evidence,
    task_dashboard,
)
from qyp_multi_registry import AuthorizationDenied, Registry, RegistryError, SCHEMA_VERSION


SESSION_A = "019ffaf4-eccd-7203-b5b4-51d967ec128b"
SESSION_B = "019ffe42-5df3-76b1-95f8-f671fe1de4dc"
SESSION_C = "019ff92c-d8e3-7f20-b0d3-1b596bff1a91"


class MultiUserRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.registry = Registry(Path(self.tempdir.name) / "multi.sqlite3")
        self.registry.init()
        self.owner = self.registry.add_user("ou_owner", "负责人", user_id="user-owner", role="owner", status="approved")
        self.member = self.registry.add_user("ou_member", "成员", user_id="user-member", status="approved")
        self.other = self.registry.add_user("ou_other", "未共享成员", user_id="user-other", status="approved")
        self.installation = self.registry.add_installation("user-owner", "负责人电脑", installation_id="inst-owner", hostname="owner-host")
        self.registry.add_session("inst-owner", SESSION_A, "ASR 零训练纠错", status="running")
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

    def test_registration_and_membership_never_grant_or_restore_a_share(self) -> None:
        # Include a legacy group-eligible Session: its flag is not consent.
        self.registry.add_session("inst-owner", SESSION_C, share_with_groups=True)
        for enroll in (self.registry.add_group_member, self.registry.ensure_group_member):
            with self.subTest(enroll=enroll.__name__):
                enroll("group-test", "ou_owner")
                with self.assertRaises(AuthorizationDenied):
                    self.registry.authorize("ou_member", "oc_test", SESSION_C, "read")
        self.registry.share_session("group-test", SESSION_C)
        self.assertTrue(self.registry.authorize("ou_member", "oc_test", SESSION_C)["allowed"])
        self.registry.unshare_session("group-test", SESSION_C)
        self.registry.ensure_group_member("group-test", "ou_owner")
        self.registry.add_group_member("group-test", "ou_owner")
        with self.assertRaises(AuthorizationDenied):
            self.registry.authorize("ou_member", "oc_test", SESSION_C, "read")

    def test_joining_with_existing_sessions_requires_an_explicit_share(self) -> None:
        self.registry.create_group("Other team", "ou_member", group_id="group-other", feishu_chat_id="oc_other")
        self.registry.add_session("inst-owner", SESSION_C, share_with_groups=True)
        self.registry.add_group_member("group-other", "ou_owner")
        with self.assertRaises(AuthorizationDenied):
            self.registry.authorize("ou_member", "oc_other", SESSION_C, "read")
        self.registry.share_session("group-other", SESSION_C, access="read")
        self.assertTrue(self.registry.authorize("ou_member", "oc_other", SESSION_C, "read")["allowed"])
        with self.assertRaises(AuthorizationDenied):
            self.registry.authorize("ou_member", "oc_other", SESSION_C, "write")

    def test_upgrade_preserves_existing_access_but_does_not_restore_revocation(self) -> None:
        self.registry.share_session("group-test", SESSION_A, access="read")
        with self.registry._connect() as db:
            db.execute("UPDATE meta SET value='7' WHERE key='schema_version'")
            db.execute("UPDATE sessions SET private_only=0 WHERE session_id=?", (SESSION_A,))
        self.registry.init()
        self.assertTrue(self.registry.authorize("ou_member", "oc_test", SESSION_A, "read")["allowed"])
        with self.assertRaises(AuthorizationDenied):
            self.registry.authorize("ou_member", "oc_test", SESSION_A, "write")
        self.registry.unshare_session("group-test", SESSION_A)
        self.registry.ensure_group_member("group-test", "ou_owner")
        with self.assertRaises(AuthorizationDenied):
            self.registry.authorize("ou_member", "oc_test", SESSION_A, "read")

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

    def test_private_pairing_registration_is_idempotent_and_grants_no_group_access(self) -> None:
        first = self.registry.ensure_private_user("ou_new")
        second = self.registry.ensure_private_user("ou_new")
        self.assertEqual(first["user_id"], second["user_id"])
        self.assertEqual(first["status"], "approved")
        members = self.registry.group_dashboard("group-test")["members"]
        self.assertFalse(any(member["user_id"] == first["user_id"] for member in members))
        code = self.registry.create_pairing(first["user_id"], ttl=600)
        self.assertEqual(self.registry.consume_pairing(code)["user_id"], first["user_id"])

    def test_disabled_private_user_cannot_pair(self) -> None:
        user = self.registry.ensure_private_user("ou_disabled")
        self.registry.set_user_status(user["user_id"], "disabled")
        with self.assertRaises(AuthorizationDenied):
            self.registry.ensure_private_user("ou_disabled")

    def test_dashboard_contains_only_shared_sessions(self) -> None:
        self.registry.share_session("group-test", SESSION_A)
        dashboard = self.registry.group_dashboard("oc_test", "ou_member")
        self.assertEqual([item["session_id"] for item in dashboard["sessions"]], [SESSION_A])
        self.assertEqual(len(dashboard["members"]), 3)

    def test_session_slots_support_short_custom_and_owner_aliases(self) -> None:
        custom_one = self.registry.add_session_to_group(
            "group-test",
            "ou_owner",
            SESSION_A,
            slot_alias="h",
        )
        custom_two = self.registry.add_session_to_group(
            "group-test",
            "ou_owner",
            SESSION_B,
            slot_alias="hd",
        )
        self.assertEqual(custom_one["slot"], "h")
        self.assertEqual(custom_two["slot"], "hd")

        self.registry.add_session("inst-owner", SESSION_C, "第三个窗口", status="idle")
        automatic = self.registry.add_session_to_group("group-test", "ou_owner", SESSION_C)
        self.assertRegex(automatic["slot"], r"^[a-z]{1,2}$")
        self.assertNotIn(automatic["slot"], {"ad", "h", "hd"})

        with self.assertRaises(RegistryError):
            self.registry.add_session_to_group("group-test", "ou_owner", SESSION_C, slot_alias="h1")

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
        self.assertEqual(result["schema_version"], SCHEMA_VERSION)
        with sqlite3.connect(self.registry.path) as connection:
            version = connection.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0]
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
        self.assertEqual(version, str(SCHEMA_VERSION))
        self.assertTrue(
            {
                "tasks",
                "task_sessions",
                "task_groups",
                "task_events",
                "task_event_deliveries",
                "roles",
                "user_roles",
                "task_assignments",
                "agent_runs",
                "evidence",
                "handoffs",
                "agent_channels",
                "agent_channel_messages",
            }.issubset(tables)
        )
        roles = {
            row[0]
            for row in sqlite3.connect(self.registry.path).execute("SELECT role_id FROM roles")
        }
        self.assertIn("owner", roles)
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
                "constraints": {"paths": ["qyp_tls_multi_person_20260815"]},
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

    def test_task_progress_requires_verified_evidence_and_owner_approval_for_100(self) -> None:
        self.registry.create_task(
            "ou_owner",
            "证据进度",
            {"objective": "用证据验收", "acceptance": ["定向测试通过"]},
            task_id="task-evidence-progress",
            status="running",
        )
        self.registry.attach_task_session("task-evidence-progress", SESSION_A)
        self.registry.append_task_event(
            "task-evidence-progress",
            "command.completed",
            {"summary": "Agent 声称完成"},
            session_id=SESSION_A,
        )
        claimed = self.registry.task_progress("task-evidence-progress", session_id=SESSION_A)
        self.assertEqual((claimed["percent"], claimed["state"]), (75, "证据缺失"))

        evidence = self.registry.record_evidence(
            "task-evidence-progress",
            "test-report",
            "定向测试",
            session_id=SESSION_A,
            created_by="ou_owner",
        )
        pending = self.registry.task_progress("task-evidence-progress", session_id=SESSION_A)
        self.assertEqual((pending["percent"], pending["state"]), (75, "证据待验证"))

        self.registry.verify_evidence(evidence["evidence_id"], "ou_owner")
        verified = self.registry.task_progress("task-evidence-progress", session_id=SESSION_A)
        self.assertEqual((verified["percent"], verified["state"]), (90, "等待确认"))

        for actor in ("ou_member", "ou_owner"):
            with self.subTest(actor=actor), self.assertRaises(RegistryError):
                self.registry.append_task_event(
                    "task-evidence-progress", "task.approved", {"evidence_id": evidence["evidence_id"]},
                    session_id=SESSION_A, actor_open_id=actor,
                )
        for idem in ("queue-release:example", "task:task-evidence-progress:approved:all"):
            with self.subTest(idem=idem), self.assertRaises(RegistryError):
                self.registry.append_task_event(
                    "task-evidence-progress", "task.started", {}, idempotency_key=idem,
                )
        # A forged event already in an older database must not mean acceptance.
        with self.registry._connect() as db:
            db.execute(
                "INSERT INTO task_events(task_id, session_id, event_type, actor_open_id, payload_json, created_at) "
                "VALUES(?, ?, 'task.approved', 'ou_owner', '{}', 1)",
                ("task-evidence-progress", SESSION_A),
            )
        unauthorized = self.registry.task_progress("task-evidence-progress", session_id=SESSION_A)
        self.assertEqual((unauthorized["percent"], unauthorized["approved"]), (90, False))
        self.registry.approve_task("task-evidence-progress", "ou_owner", session_id=SESSION_A)
        approved = self.registry.task_progress("task-evidence-progress", session_id=SESSION_A)
        self.assertEqual((approved["percent"], approved["state"], approved["approved"]), (100, "已验收", True))

    def test_group_task_evidence_and_owner_approval_form_v1_state_machine(self) -> None:
        self.registry.share_session("group-test", SESSION_A, access="write")
        task = self.registry.create_group_task(
            "group-test",
            "ou_owner",
            SESSION_A,
            "证据闭环",
            {"objective": "验证 V1 闭环", "acceptance": ["证据已验证"]},
            task_id="task-v1-e2e",
        )
        self.assertEqual(task["task_id"], "task-v1-e2e")
        self.assertEqual(task["sessions"][0]["session_id"], SESSION_A)
        self.assertEqual(task_dashboard("oc_test", "ou_member", path=self.registry.path)["tasks"][0]["task_id"], "task-v1-e2e")
        self.assertEqual(self.registry.list_task_events("task-v1-e2e")[0]["event_type"], "task.created")

        self.registry.share_session("group-test", SESSION_B, access="read")
        with self.assertRaises(AuthorizationDenied):
            self.registry.create_group_task(
                "group-test", "ou_owner", SESSION_B, "只读不能创建", {"objective": "拒绝"}, task_id="task-v1-read"
            )
        evidence = self.registry.record_evidence(
            "task-v1-e2e", "test", "测试报告", session_id=SESSION_A, created_by="ou_member"
        )
        self.assertEqual(self.registry.list_task_events("task-v1-e2e")[-1]["event_type"], "evidence.attached")
        with self.assertRaises(AuthorizationDenied):
            self.registry.verify_evidence_as_task_owner("task-v1-e2e", evidence["evidence_id"], "ou_member")
        with self.assertRaises(RegistryError):
            self.registry.approve_task("task-v1-e2e", "ou_owner", session_id=SESSION_A)
        self.registry.verify_evidence_as_task_owner("task-v1-e2e", evidence["evidence_id"], "ou_owner")
        approved = self.registry.approve_task("task-v1-e2e", "ou_owner", session_id=SESSION_A)
        self.assertEqual(approved["status"], "completed")
        self.assertEqual(self.registry.task_progress("task-v1-e2e", session_id=SESSION_A)["percent"], 100)

    def test_existing_group_task_can_be_bound_and_agent_result_is_idempotent(self) -> None:
        self.registry.share_session("group-test", SESSION_A, access="write")
        self.registry.create_task(
            "ou_owner", "已有任务", {"objective": "补齐执行绑定"}, task_id="task-bind-v1"
        )
        self.registry.share_task("group-test", "task-bind-v1", access="write")
        bound = bind_group_task_session(
            "oc_test", "ou_owner", "task-bind-v1", SESSION_A, path=self.registry.path
        )
        self.assertEqual(bound["relation"], "primary")
        evidence = submit_agent_evidence(
            "task-bind-v1", SESSION_A, "测试退出码 0，Agent 已完成", "om-agent-1", created_by="ou_owner", path=self.registry.path
        )
        duplicate = submit_agent_evidence(
            "task-bind-v1", SESSION_A, "测试退出码 0，Agent 已完成", "om-agent-1", created_by="ou_owner", path=self.registry.path
        )
        self.assertEqual(evidence["evidence_id"], duplicate["evidence_id"])
        self.assertEqual(len(self.registry.list_evidence("task-bind-v1")), 1)
        self.assertEqual(
            [item["event_type"] for item in self.registry.list_task_events("task-bind-v1")],
            ["evidence.attached"],
        )

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
            ["task.started", "command.claimed", "command.completed"],
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
