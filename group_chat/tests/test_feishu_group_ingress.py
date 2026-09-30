from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from feishu_group_ingress import RouteStore, parse_message, process_message, publish_one, send_reply
from qyp_multi_registry import AuthorizationDenied, Registry
from qyp_multi_transport import TransportStore


SESSION = "01a00558-3cd2-7690-a2ec-bcb3289f95b2"


class FeishuIngressTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.registry = Registry(root / "registry.sqlite3")
        self.registry.init()
        self.registry.add_user("ou_owner", "Owner", user_id="owner", status="approved")
        self.registry.add_installation("owner", "Laptop", installation_id="laptop")
        self.registry.add_session("laptop", SESSION, label="Work", status="offline")
        self.registry.create_group("Team", "owner", group_id="team", feishu_chat_id="oc_team")
        self.registry.share_session("team", SESSION, access="write")
        self.transport = TransportStore(self.registry.path, root / "agent.sqlite3")
        self.transport.init()
        self.routes = RouteStore(root / "routes.sqlite3")
        self.pair = self.transport.pair(self.registry.create_pairing("owner", installation_id="laptop"))
        self.transport.heartbeat(self.pair["token"], [{"session_id": SESSION, "status": "idle", "label": "Work"}])
        self.env = mock.patch.dict(os.environ, {"QYP_TLS_MULTI_DB": str(self.registry.path), "FEISHU_BOT_OPEN_ID": "ou_bot"})
        self.env.start()

    def tearDown(self) -> None:
        self.env.stop()
        self.temp.cleanup()

    def event(self, message_id: str, text: str = "hello", **kwargs: str) -> dict[str, str]:
        return {
            "open_id": "ou_owner", "chat_id": "oc_team", "chat_type": "group",
            "message_id": message_id, "text": text, "mentioned": "1", **kwargs,
        }

    def test_parse_requires_bot_mention_or_reply_route(self) -> None:
        def message(mention_id: str):
            mention = SimpleNamespace(key="@_user_1", id=SimpleNamespace(open_id=mention_id))
            return SimpleNamespace(event=SimpleNamespace(
                sender=SimpleNamespace(sender_type="user", sender_id=SimpleNamespace(open_id="ou_owner")),
                message=SimpleNamespace(message_id="om_1", chat_id="oc_team", chat_type="group",
                                        message_type="text", content='{"text":"@_user_1 hello"}',
                                        mentions=[mention], parent_id="", root_id="")))
        self.assertEqual(parse_message(message("ou_bot"))["mentioned"], "1")
        self.assertEqual(parse_message(message("ou_other"))["mentioned"], "")

    def test_sdk_reply_request_has_stable_uuid(self) -> None:
        try:
            import lark_oapi  # noqa: F401
        except ImportError:
            self.skipTest("Feishu SDK not installed")
        reply = mock.Mock(return_value=SimpleNamespace(success=lambda: True, data=SimpleNamespace(message_id="om_bot")))
        client = SimpleNamespace(im=SimpleNamespace(v1=SimpleNamespace(message=SimpleNamespace(reply=reply))))
        self.assertEqual(send_reply(client, "om_source", "done", "event-1"), "om_bot")
        request = reply.call_args.args[0]
        self.assertEqual(request.message_id, "om_source")
        self.assertEqual(request.request_body.content, '{"text": "done"}')
        self.assertTrue(request.request_body.uuid)

    def test_duplicate_completion_reply_and_continuation(self) -> None:
        first = self.event("om_first")
        self.routes.receive(first)
        self.routes.receive(first)
        self.assertEqual(self.routes.next_message(), first)
        self.assertEqual(process_message(first, self.routes, self.transport), "queued")
        self.assertEqual(process_message(first, self.routes, self.transport), "duplicate")
        self.routes.finish("om_first")
        self.assertIsNone(self.routes.next_message())
        command = self.transport.poll(self.pair["token"])[0]
        self.transport.complete(self.pair["token"], command["command_id"], status="completed", result={"answer": "done"})
        with mock.patch("feishu_group_ingress.send_reply", return_value="om_bot") as send:
            self.assertTrue(publish_one(None, self.routes, self.transport))
        send.assert_called_once_with(None, "om_first", "done", mock.ANY)
        self.assertEqual(self.routes.route("om_bot", "oc_team"), SESSION)
        self.assertEqual(RouteStore(self.routes.path).route("om_bot", "oc_team"), SESSION)
        self.assertEqual(self.routes.route("om_bot", "oc_other"), "")
        followup = self.event("om_next", "continue", mentioned="", parent_id="om_bot")
        self.assertEqual(process_message(followup, self.routes, self.transport), "queued")
        self.assertEqual(self.transport.poll(self.pair["token"])[0]["session_id"], SESSION)

    def test_failed_send_retries_and_read_only_share_blocks_continuation(self) -> None:
        first = self.event("om_first")
        self.assertEqual(process_message(first, self.routes, self.transport), "queued")
        command = self.transport.poll(self.pair["token"])[0]
        self.transport.complete(self.pair["token"], command["command_id"], status="completed", result={"answer": "done"})
        with mock.patch("feishu_group_ingress.send_reply", side_effect=OSError("offline")):
            self.assertTrue(publish_one(None, self.routes, self.transport))
        self.assertEqual(self.routes.route("om_bot", "oc_team"), "")
        with self.transport._connect() as db:
            db.execute("UPDATE agent_events SET next_attempt_at=0 WHERE status='failed'")
        with mock.patch("feishu_group_ingress.send_reply", return_value="om_bot"):
            self.assertTrue(publish_one(None, self.routes, self.transport))
        self.registry.share_session("team", SESSION, access="read")
        with self.assertRaises(AuthorizationDenied):
            process_message(self.event("om_next", "continue", mentioned="", parent_id="om_bot"), self.routes, self.transport)

    def test_team_commands_create_claim_submit_verify_and_credit(self) -> None:
        self.registry.add_user("ou_builder", "Builder", user_id="builder", status="approved")
        self.registry.add_group_member("team", "ou_builder")
        create = self.event("om_task", f"/task task-demo {SESSION} Ship feature | Tests pass")
        self.assertEqual(process_message(create, self.routes, self.transport), "task-created")
        self.assertEqual(process_message(create, self.routes, self.transport), "task-created")
        with self.assertRaisesRegex(Exception, "领取者"):
            process_message(self.event("om_early", "/approve task-demo"), self.routes, self.transport)
        self.assertEqual(process_message(self.event("om_claim", "/claim task-demo", open_id="ou_builder"), self.routes, self.transport), "task-claimed")
        self.assertEqual(process_message(self.event("om_submit", "/submit task-demo commit:abc123", open_id="ou_builder"), self.routes, self.transport), "task-submitted")
        self.assertEqual(process_message(self.event("om_submit", "/submit task-demo commit:abc123", open_id="ou_builder"), self.routes, self.transport), "task-submitted")
        evidence = self.registry.list_evidence("task-demo")[0]
        self.assertEqual(len(self.registry.list_evidence("task-demo")), 1)
        self.assertEqual(process_message(self.event("om_verify", f"/verify task-demo {evidence['evidence_id']}"), self.routes, self.transport), "task-verified")
        self.assertEqual(process_message(self.event("om_approve", "/approve task-demo"), self.routes, self.transport), "task-approved")
        self.assertEqual(process_message(self.event("om_approve", "/approve task-demo"), self.routes, self.transport), "task-approved")
        self.assertEqual(self.registry.task_queue("oc_team", "ou_owner")[0]["credited_user_id"], "builder")

    def test_history_search_is_queued_only_with_consent_and_revocation_scrubs_result(self) -> None:
        self.registry.add_user("ou_builder", "Builder", user_id="builder", status="approved")
        self.registry.add_group_member("team", "ou_builder")
        request = self.event("om_history", f"/history {SESSION} architecture", open_id="ou_builder")
        with self.assertRaises(AuthorizationDenied):
            process_message(request, self.routes, self.transport)
        self.assertEqual(process_message(self.event("om_optin", f"/history-on {SESSION}"), self.routes, self.transport), "history-toggle")
        self.assertEqual(process_message(request, self.routes, self.transport), "queued")
        command = self.transport.poll(self.pair["token"])[0]
        self.assertEqual(command["action"], "history_search")
        self.assertEqual(command["payload"]["query"], "architecture")
        self.assertEqual(process_message(self.event("om_optout", f"/history-off {SESSION}"), self.routes, self.transport), "history-toggle")
        self.transport.complete(self.pair["token"], command["command_id"], status="completed", result={"answer": "private snippet"})
        event = self.transport.next_event()
        self.assertEqual(event["payload"]["result"], {})
        self.assertEqual(event["payload"]["status"], "failed")
        with mock.patch("feishu_group_ingress.send_reply", return_value="om_reply") as send:
            publish_one(None, self.routes, self.transport)
        self.assertNotIn("private snippet", send.call_args.args[2])


if __name__ == "__main__":
    unittest.main()
