from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from qyp_multi_registry import AuthorizationDenied, Registry, RegistryError


SESSION_A = "019ffaf4-eccd-7203-b5b4-51d967ec128b"
SESSION_B = "019ffe42-5df3-76b1-95f8-f671fe1de4dc"
SESSION_C = "019ff92c-d8e3-7f20-b0d3-1b596bff1a91"


class TeamModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.registry = Registry(Path(self.tempdir.name) / "multi.sqlite3")
        self.registry.init()
        self.registry.add_user("ou_owner", "Owner", user_id="user-owner", role="owner", status="approved")
        self.registry.add_user("ou_builder", "Builder", user_id="user-builder", status="approved")
        self.registry.add_user("ou_tester", "Tester", user_id="user-tester", status="approved")
        self.registry.add_installation(
            "user-owner",
            "Owner workstation",
            installation_id="inst-owner",
            hostname="owner-host",
        )
        self.registry.add_session("inst-owner", SESSION_A, "TLS Session", status="running")
        self.registry.create_task(
            "ou_owner",
            "TLS control-plane model",
            {"objective": "verify additive team entities", "acceptance": ["session remains usable"]},
            task_id="task-model",
        )
        self.registry.attach_task_session("task-model", SESSION_A, relation="primary")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_roles_are_seeded_and_can_be_scoped_to_a_task(self) -> None:
        role_ids = {item["role_id"] for item in self.registry.list_roles()}
        self.assertTrue({"owner", "implementer", "tester", "reviewer"}.issubset(role_ids))

        grant = self.registry.grant_role(
            "ou_builder",
            "implementer",
            scope_type="task",
            scope_id="task-model",
            granted_by="ou_owner",
        )
        self.assertEqual((grant["role_id"], grant["scope_type"], grant["scope_id"]), ("implementer", "task", "task-model"))
        self.assertEqual(self.registry.list_user_roles("ou_builder", scope_type="task")[0]["role_id"], "implementer")

    def test_assignment_and_run_do_not_mutate_existing_session_state(self) -> None:
        assignment = self.registry.create_task_assignment(
            "task-model",
            "ou_builder",
            "implementer",
            session_id=SESSION_A,
            assignment_id="assignment-builder",
            assigned_by="ou_owner",
        )
        self.assertEqual(assignment["status"], "assigned")

        run = self.registry.start_agent_run(
            "task-model",
            SESSION_A,
            assignment_id="assignment-builder",
            run_id="run-builder-1",
        )
        self.assertEqual(run["status"], "running")
        self.assertEqual(self.registry.list_sessions("ou_owner")[0]["status"], "running")

        finished = self.registry.finish_agent_run(
            "run-builder-1",
            summary="Implementation slice complete",
        )
        self.assertEqual(finished["status"], "completed")
        self.assertIsNotNone(finished["finished_at"])
        self.assertEqual(self.registry.list_sessions("ou_owner")[0]["status"], "running")

    def test_evidence_can_be_verified_and_handoff_can_be_accepted(self) -> None:
        assignment = self.registry.create_task_assignment(
            "task-model",
            "ou_builder",
            "implementer",
            session_id=SESSION_A,
            assignment_id="assignment-builder",
        )
        tester = self.registry.create_task_assignment(
            "task-model",
            "ou_tester",
            "tester",
            assignment_id="assignment-tester",
        )
        run = self.registry.start_agent_run(
            "task-model",
            SESSION_A,
            assignment_id=assignment["assignment_id"],
            run_id="run-builder-1",
        )
        evidence = self.registry.record_evidence(
            "task-model",
            "test",
            "Team model regression",
            uri="test://team-model",
            content_hash="sha256:test",
            summary="The additive model preserves the running Session.",
            assignment_id=assignment["assignment_id"],
            run_id=run["run_id"],
            created_by="ou_builder",
        )
        self.assertEqual(evidence["verification_status"], "unverified")
        verified = self.registry.verify_evidence(evidence["evidence_id"], "ou_tester")
        self.assertEqual(verified["verification_status"], "verified")
        self.assertEqual(verified["verifier_open_id"], "ou_tester")

        handoff = self.registry.create_handoff(
            "task-model",
            {
                "objective": "continue verification",
                "verified_facts": [evidence["evidence_id"]],
                "open_questions": ["Should the UI expose role capabilities?"],
                "next_actions": ["Review the group adapter"],
            },
            from_assignment_id=assignment["assignment_id"],
            to_assignment_id=tester["assignment_id"],
            from_run_id=run["run_id"],
            handoff_id="handoff-builder-tester",
            created_by="ou_builder",
        )
        self.assertEqual(handoff["status"], "ready")
        accepted = self.registry.accept_handoff("handoff-builder-tester", "ou_tester")
        self.assertEqual(accepted["status"], "accepted")
        self.assertEqual(accepted["accepted_by"], "ou_tester")

    def test_agent_channel_is_task_scoped_ordered_and_idempotent(self) -> None:
        self.registry.add_installation(
            "user-builder", "Builder workstation", installation_id="inst-builder"
        )
        self.registry.add_installation(
            "user-tester", "Tester workstation", installation_id="inst-tester"
        )
        self.registry.add_session("inst-builder", SESSION_B, "Builder Session", status="running")
        self.registry.add_session("inst-tester", SESSION_C, "Tester Session", status="running")
        self.registry.attach_task_session("task-model", SESSION_B, relation="worker")
        self.registry.attach_task_session("task-model", SESSION_C, relation="worker")
        builder_assignment = self.registry.create_task_assignment(
            "task-model",
            "ou_builder",
            "implementer",
            session_id=SESSION_B,
            assignment_id="assignment-channel-builder",
        )
        tester_assignment = self.registry.create_task_assignment(
            "task-model",
            "ou_tester",
            "tester",
            session_id=SESSION_C,
            assignment_id="assignment-channel-tester",
        )
        builder_run = self.registry.start_agent_run(
            "task-model",
            SESSION_B,
            assignment_id=builder_assignment["assignment_id"],
            run_id="run-channel-builder",
        )
        tester_run = self.registry.start_agent_run(
            "task-model",
            SESSION_C,
            assignment_id=tester_assignment["assignment_id"],
            run_id="run-channel-tester",
        )
        self.registry.grant_role(
            "ou_builder",
            "implementer",
            scope_type="task",
            scope_id="task-model",
            granted_by="ou_owner",
        )

        requested = self.registry.request_agent_channel(
            "task-model",
            builder_run["run_id"],
            tester_run["run_id"],
            ["agent.message"],
            requested_by="ou_builder",
        )
        self.assertEqual(requested["status"], "requested")
        active = self.registry.accept_agent_channel(
            requested["channel_id"], tester_run["run_id"], accepted_by="ou_tester"
        )
        self.assertEqual(active["status"], "active")

        sent = self.registry.send_agent_channel_message(
            active["channel_id"],
            builder_run["run_id"],
            "channel-message-1",
            {"kind": "handoff", "summary": "ready"},
            sent_by="ou_builder",
        )
        self.assertEqual(sent["sequence"], 1)
        duplicate = self.registry.send_agent_channel_message(
            active["channel_id"],
            builder_run["run_id"],
            "channel-message-1",
            {"kind": "handoff", "summary": "ready"},
            sent_by="ou_builder",
        )
        self.assertEqual(duplicate["sequence"], 1)
        with self.assertRaises(RegistryError):
            self.registry.send_agent_channel_message(
                active["channel_id"],
                builder_run["run_id"],
                "channel-message-1",
                {"token": "must-not-be-stored"},
                sent_by="ou_builder",
            )

        messages = self.registry.poll_agent_channel_messages(
            active["channel_id"], tester_run["run_id"], requested_by="ou_tester"
        )
        self.assertEqual(messages[0]["payload"]["summary"], "ready")
        self.assertEqual(
            self.registry.ack_agent_channel_message(
                "channel-message-1", tester_run["run_id"], acknowledged_by="ou_tester"
            )["status"],
            "acknowledged",
        )
        with self.assertRaises(AuthorizationDenied):
            self.registry.poll_agent_channel_messages(
                active["channel_id"], tester_run["run_id"], requested_by="ou_builder"
            )
        self.assertEqual(
            self.registry.revoke_agent_channel(active["channel_id"], revoked_by="ou_owner")["status"],
            "revoked",
        )


if __name__ == "__main__":
    unittest.main()
