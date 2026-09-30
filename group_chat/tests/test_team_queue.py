from __future__ import annotations

import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from qyp_multi_registry import AuthorizationDenied, Registry, RegistryError


SESSION = "019ffaf4-eccd-7203-b5b4-51d967ec128b"


class TeamQueueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "registry.sqlite3"
        self.registry = Registry(self.path)
        self.registry.init()
        for open_id, user_id in (("ou_owner", "owner"), ("ou_one", "one"), ("ou_two", "two"), ("ou_outside", "outside")):
            self.registry.add_user(open_id, user_id, user_id=user_id, status="approved")
        self.registry.add_installation("owner", "Laptop", installation_id="laptop")
        self.registry.add_session("laptop", SESSION, label="Work")
        self.registry.create_group("Team", "owner", group_id="team", feishu_chat_id="oc_team")
        self.registry.add_group_member("team", "ou_one")
        self.registry.add_group_member("team", "ou_two")
        self.registry.share_session("team", SESSION, access="write")
        self.registry.create_group_task(
            "team", "ou_owner", SESSION, "Ship feature",
            {"objective": "Ship feature", "acceptance": ["Tests pass", "Owner reviews result"], "team_queue": True},
            task_id="task-ship",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_atomic_claim_and_verified_finisher_credit(self) -> None:
        def claim(open_id: str) -> str:
            try:
                return Registry(self.path).claim_shared_task("oc_team", open_id, "task-ship")["user_id"]
            except RegistryError:
                return "lost"

        with ThreadPoolExecutor(max_workers=2) as pool:
            winners = list(pool.map(claim, ("ou_one", "ou_two")))
        self.assertEqual(sum(value != "lost" for value in winners), 1)
        winner = winners[0] if winners[0] != "lost" else winners[1]
        open_id = "ou_one" if winner == "one" else "ou_two"
        self.assertEqual(self.registry.claim_shared_task("oc_team", open_id, "task-ship")["user_id"], winner)
        evidence = self.registry.record_evidence("task-ship", "test", "Suite passed", created_by=open_id)
        self.registry.submit_shared_task("oc_team", open_id, "task-ship", evidence["evidence_id"])
        with self.assertRaises(RegistryError):
            self.registry.approve_task("task-ship", "ou_owner")
        self.registry.verify_evidence_as_task_owner("task-ship", evidence["evidence_id"], "ou_owner")
        approved = self.registry.approve_task("task-ship", "ou_owner")
        self.assertEqual(approved["credit"]["user_id"], winner)
        self.assertEqual(approved["credit"]["evidence_id"], evidence["evidence_id"])
        self.assertEqual(self.registry.approve_task("task-ship", "ou_owner")["credit"], approved["credit"])
        with self.assertRaises(RegistryError):
            self.registry.claim_shared_task("oc_team", "ou_two", "task-ship")

    def test_release_then_new_finisher_gets_credit(self) -> None:
        self.registry.claim_shared_task("oc_team", "ou_one", "task-ship")
        old = self.registry.record_evidence("task-ship", "test", "Old run", created_by="ou_one")
        self.registry.release_shared_task("oc_team", "ou_one", "task-ship")
        with self.assertRaises(AuthorizationDenied):
            self.registry.submit_shared_task("oc_team", "ou_one", "task-ship", old["evidence_id"])
        self.registry.claim_shared_task("oc_team", "ou_two", "task-ship")
        with self.assertRaises(AuthorizationDenied):
            self.registry.submit_shared_task("oc_team", "ou_two", "task-ship", old["evidence_id"])
        new = self.registry.record_evidence("task-ship", "test", "New run", created_by="ou_two")
        self.registry.submit_shared_task("oc_team", "ou_two", "task-ship", new["evidence_id"])
        self.registry.verify_evidence_as_task_owner("task-ship", old["evidence_id"], "ou_owner")
        with self.assertRaises(RegistryError):
            self.registry.approve_task("task-ship", "ou_owner")
        self.registry.verify_evidence_as_task_owner("task-ship", new["evidence_id"], "ou_owner")
        self.assertEqual(self.registry.approve_task("task-ship", "ou_owner")["credit"]["user_id"], "two")

    def test_queue_requires_membership_write_share_and_acceptance(self) -> None:
        self.assertEqual(self.registry.task_queue("oc_team", "ou_one")[0]["task_id"], "task-ship")
        with self.assertRaises(AuthorizationDenied):
            self.registry.task_queue("oc_team", "ou_outside")
        with self.assertRaises(AuthorizationDenied):
            self.registry.claim_shared_task("oc_team", "ou_outside", "task-ship")
        self.registry.share_task("team", "task-ship", access="read")
        with self.assertRaises(AuthorizationDenied):
            self.registry.claim_shared_task("oc_team", "ou_one", "task-ship")
        self.registry.share_task("team", "task-ship", access="write")
        self.registry.create_group_task("team", "ou_owner", SESSION, "No criteria", {"objective": "x"}, task_id="task-empty")
        with self.assertRaises(RegistryError):
            self.registry.claim_shared_task("oc_team", "ou_one", "task-empty")

    def test_history_search_requires_owner_opt_in_and_share(self) -> None:
        self.registry.share_session("team", SESSION, access="read")
        with self.assertRaises(AuthorizationDenied):
            self.registry.authorize_history_search("ou_one", "oc_team", SESSION)
        with self.assertRaises(AuthorizationDenied):
            self.registry.set_history_search("oc_team", "ou_one", SESSION, enabled=True)
        self.registry.set_history_search("oc_team", "ou_owner", SESSION, enabled=True)
        self.assertTrue(self.registry.authorize_history_search("ou_one", "oc_team", SESSION)["allowed"])
        with self.assertRaises(AuthorizationDenied):
            self.registry.authorize_history_search("ou_outside", "oc_team", SESSION)
        self.registry.set_history_search("oc_team", "ou_owner", SESSION, enabled=False)
        with self.assertRaises(AuthorizationDenied):
            self.registry.authorize_history_search("ou_one", "oc_team", SESSION)
        self.registry.set_history_search("oc_team", "ou_owner", SESSION, enabled=True)
        self.registry.unshare_session("team", SESSION)
        with self.assertRaises(AuthorizationDenied):
            self.registry.authorize_history_search("ou_one", "oc_team", SESSION)


if __name__ == "__main__":
    unittest.main()
