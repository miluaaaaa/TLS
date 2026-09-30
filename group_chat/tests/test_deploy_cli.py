from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "qyp_multi_registry.py"
SESSION = "019ffaf4-eccd-7203-b5b4-51d967ec128b"


class DeploymentCliTests(unittest.TestCase):
    def test_documented_registration_and_pairing_commands(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db = str(Path(directory) / "multi.sqlite3")

            def run(*args: str) -> dict:
                result = subprocess.run(
                    [sys.executable, str(SCRIPT), "--db", db, *args],
                    text=True, capture_output=True, check=True,
                )
                return json.loads(result.stdout)

            run("init")
            run("add-user", "--open-id", "ou_example", "--name", "Owner", "--user-id", "owner", "--status", "approved")
            run("add-installation", "--user", "owner", "--id", "laptop", "--name", "Laptop")
            run("add-session", "--installation", "laptop", "--session-id", SESSION, "--label", "Work")
            run("create-group", "--id", "team", "--chat-id", "oc_example", "--name", "Team", "--creator", "owner")
            run("share-session", "--group", "team", "--session", SESSION, "--access", "write")
            self.assertTrue(run("pair", "--user", "owner", "--installation", "laptop", "--ttl", "600")["code"])


if __name__ == "__main__":
    unittest.main()
