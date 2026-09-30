import sys
import os
import tempfile
import threading
import unittest
import json
from pathlib import Path
from unittest import mock


RUNTIME = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RUNTIME))

import qyp_multi_agent as agent  # noqa: E402


SESSION_ID = "019ffaf4-eccd-7203-b5b4-51d967ec128b"


class CompleteReportingTests(unittest.TestCase):
    def setUp(self):
        self.policy_dir = tempfile.TemporaryDirectory()
        allowed = Path(self.policy_dir.name) / "included-sessions"
        allowed.write_text(SESSION_ID + "\n", encoding="utf-8")
        self.policy_env = mock.patch.dict(os.environ, {
            "TLS_INCLUDED_SESSIONS_FILE": str(allowed),
            "TLS_EXCLUDED_SESSIONS_FILE": str(Path(self.policy_dir.name) / "excluded-sessions"),
            "TLS_MONITOR_ALL_SESSIONS": "0",
        })
        self.policy_env.start()

    def tearDown(self):
        self.policy_env.stop()
        self.policy_dir.cleanup()

    def command(self):
        return {
            "command_id": "cmd-test",
            "session_id": SESSION_ID,
            "payload": {"text": "hello"},
        }

    def process_patches(self, transcript):
        return (
            mock.patch.object(agent, "_find_transcript", return_value=transcript),
            mock.patch.object(agent, "_runtime_for", return_value={"socket": "/tmp/test.sock"}),
            mock.patch.object(agent, "deliver_turn", return_value="turn-target"),
            mock.patch.object(agent, "_wait_for_completion", return_value="done"),
            mock.patch.object(agent.time, "sleep"),
        )

    def test_heartbeat_retries_transient_gateway_failures(self):
        with (
            mock.patch.object(agent, "discover_sessions", return_value=[]),
            mock.patch.object(
                agent,
                "api_request",
                side_effect=[agent.AgentError("gateway-unreachable:URLError"), {"ok": True}],
            ) as request,
            mock.patch.object(agent.time, "sleep") as sleep,
        ):
            self.assertEqual(agent.heartbeat_once({}), {"ok": True})

        self.assertEqual(request.call_count, 2)
        sleep.assert_called_once_with(agent.HEARTBEAT_RETRY_DELAYS[0])

    def test_completed_callback_retries_without_reporting_failure(self):
        with tempfile.NamedTemporaryFile() as transcript:
            patches = self.process_patches(Path(transcript.name))
            with patches[0], patches[1], patches[2], patches[3], patches[4] as sleep:
                with mock.patch.object(
                    agent,
                    "api_request",
                    side_effect=[agent.AgentError("gateway-unreachable:URLError"), {"ok": True}],
                ) as request:
                    self.assertEqual(agent.process_command({}, self.command()), "completed")

        self.assertEqual(request.call_count, 2)
        self.assertTrue(all(call.kwargs["payload"]["status"] == "completed" for call in request.call_args_list))
        sleep.assert_called_once_with(agent.COMPLETE_RETRY_DELAYS[0])

    def test_completion_requires_the_bound_turn_id(self):
        with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8") as transcript:
            for turn_id, answer in (("turn-other", "wrong reply"), ("turn-target", "right reply")):
                transcript.write(
                    json.dumps(
                        {
                            "type": "event_msg",
                            "payload": {"type": "task_complete", "turn_id": turn_id, "last_agent_message": answer},
                        }
                    )
                    + "\n"
                )
            transcript.flush()
            self.assertEqual(agent._new_completion(Path(transcript.name), 0, "turn-target"), "right reply")

    def test_history_search_returns_bounded_local_matches_and_redacts_tokens(self):
        with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8") as transcript:
            for text in ("architecture first", "architecture bearer abcdefghijklmnop", "architecture last"):
                transcript.write(json.dumps({"type": "response_item", "payload": {
                    "type": "message", "role": "assistant", "content": [{"type": "output_text", "text": text}],
                }}) + "\n")
            transcript.flush()
            answer = agent.search_transcript(Path(transcript.name), "architecture", limit=2)
        self.assertIn("architecture last", answer)
        self.assertNotIn("architecture first", answer)
        self.assertNotIn("abcdefghijklmnop", answer)
        self.assertIn("[redacted]", answer)

    def test_completion_detects_abort_for_the_bound_turn(self):
        with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8") as transcript:
            transcript.write(
                json.dumps(
                    {
                        "type": "event_msg",
                        "payload": {"type": "turn_aborted", "turn_id": "turn-target", "reason": "interrupted"},
                    }
                )
                + "\n"
            )
            transcript.flush()
            with self.assertRaisesRegex(agent.AgentError, "turn-aborted"):
                agent._new_completion(Path(transcript.name), 0, "turn-target")

    def test_cursor_turn_binding_requires_exact_user_message(self):
        with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8") as transcript:
            for text, turn_id in (("另一条消息", "turn-other"), ("追加指令", "turn-target")):
                transcript.write(
                    json.dumps(
                        {
                            "type": "response_item",
                            "payload": {
                                "type": "message",
                                "role": "user",
                                "content": [{"type": "input_text", "text": text}],
                                "internal_chat_message_metadata_passthrough": {"turn_id": turn_id},
                            },
                        }
                    )
                    + "\n"
                )
            transcript.flush()
            self.assertEqual(agent._new_bound_turn_id(Path(transcript.name), 0, "追加指令"), "turn-target")

    def test_recovery_tmux_command_uses_exact_turn_binding(self):
        with tempfile.NamedTemporaryFile() as transcript:
            with (
                mock.patch.object(agent, "_find_transcript", return_value=Path(transcript.name)),
                mock.patch.object(agent, "_runtime_for", return_value={"tmux_target": "tls-recovery-1234abcd-019ffaf4:0.0"}),
                mock.patch.object(agent, "deliver_recovery_tmux_turn") as deliver,
                mock.patch.object(agent, "_wait_for_bound_turn", return_value="turn-target") as bind,
                mock.patch.object(agent, "_wait_for_completion", return_value="done"),
                mock.patch.object(agent, "api_request", return_value={"ok": True}),
                mock.patch.object(agent, "deliver_turn") as app_server_delivery,
            ):
                self.assertEqual(agent.process_command({}, self.command()), "completed")
        deliver.assert_called_once()
        bind.assert_called_once()
        app_server_delivery.assert_not_called()

    def test_visible_recovery_tmux_is_writable_without_recovery_state(self):
        with (
            mock.patch.object(agent, "resolve_runtime", return_value=None),
            mock.patch.object(agent, "_recovery_runtime", return_value=None),
            mock.patch.object(
                agent,
                "active_session_terminals",
                return_value={
                    SESSION_ID: {
                        "backend": "tmux",
                        "terminal_name": "tls-recovery-1234abcd-019ffaf4",
                    }
                },
            ),
        ):
            runtime = agent._runtime_for(SESSION_ID, Path("/tmp/transcript.jsonl"))

        self.assertEqual(runtime, {"tmux_target": "tls-recovery-1234abcd-019ffaf4:0.0"})

    def test_exhausted_completed_callback_is_not_reclassified_as_failed(self):
        with tempfile.NamedTemporaryFile() as transcript:
            patches = self.process_patches(Path(transcript.name))
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                with mock.patch.object(
                    agent,
                    "api_request",
                    side_effect=agent.AgentError("gateway-unreachable:URLError"),
                ) as request:
                    with self.assertRaisesRegex(agent.AgentError, "gateway-unreachable"):
                        agent.process_command({}, self.command())

        self.assertEqual(request.call_count, len(agent.COMPLETE_RETRY_DELAYS) + 1)
        self.assertTrue(all(call.kwargs["payload"]["status"] == "completed" for call in request.call_args_list))

    def test_failed_turn_requests_bounded_tls_repair(self):
        with tempfile.NamedTemporaryFile() as transcript:
            with (
                mock.patch.object(agent, "_find_transcript", return_value=Path(transcript.name)),
                mock.patch.object(agent, "_runtime_for", return_value={"socket": "/tmp/test.sock"}),
                mock.patch.object(agent, "deliver_turn", side_effect=agent.AgentError("turn-id-unavailable")),
                mock.patch.object(agent, "api_request", return_value={"ok": True}),
                mock.patch.object(agent, "_request_failure_repair") as repair,
            ):
                self.assertEqual(agent._process_command({"TLS_FAILURE_REPAIR_ENABLED": "1"}, self.command()), "failed")
        repair.assert_called_once_with({"TLS_FAILURE_REPAIR_ENABLED": "1"}, "turn-id-unavailable", SESSION_ID, "cmd-test")

    def test_turn_binding_stops_immediately_during_service_shutdown(self):
        stop_event = threading.Event()
        stop_event.set()
        with tempfile.NamedTemporaryFile() as transcript:
            with mock.patch.object(agent, "_new_bound_turn_id", return_value=""):
                with self.assertRaisesRegex(agent.AgentError, "agent-stopping"):
                    agent._wait_for_bound_turn(
                        Path(transcript.name), 0, "malformed command", 60.0, stop_event
                    )

    def test_bound_turn_is_handed_off_without_a_failed_callback(self):
        with tempfile.TemporaryDirectory() as state_dir, tempfile.NamedTemporaryFile() as transcript:
            command = self.command()
            with (
                mock.patch.object(agent, "STATE_DIR", Path(state_dir)),
                mock.patch.object(agent, "_find_transcript", return_value=Path(transcript.name)),
                mock.patch.object(agent, "_runtime_for", return_value={"socket": "/tmp/test.sock"}),
                mock.patch.object(agent, "deliver_turn", return_value="turn-target"),
                mock.patch.object(agent, "_wait_for_completion", side_effect=agent.AgentError("agent-stopping")),
                mock.patch.object(agent, "api_request") as request,
            ):
                self.assertEqual(agent._process_command({}, command), "interrupted")
                self.assertFalse(request.called)
                record = agent._load_inflight_command()
                self.assertEqual(record["command_id"], "cmd-test")
                self.assertEqual(record["turn_id"], "turn-target")

    def test_restarted_agent_completes_the_saved_turn_without_redelivery(self):
        with tempfile.TemporaryDirectory() as state_dir, tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8") as transcript:
            transcript.write(
                json.dumps(
                    {
                        "type": "event_msg",
                        "payload": {
                            "type": "task_complete",
                            "turn_id": "turn-target",
                            "last_agent_message": "recovered answer",
                        },
                    }
                )
                + "\n"
            )
            transcript.flush()
            with mock.patch.object(agent, "STATE_DIR", Path(state_dir)), mock.patch.object(
                agent, "api_request", return_value={"ok": True}
            ) as request:
                agent._save_inflight_command(
                    {
                        "attempts": 1,
                        "command_id": "cmd-test",
                        "deadline_at": agent.time.time() + 60,
                        "effort": "medium",
                        "model": "test-model",
                        "offset": 0,
                        "session_id": SESSION_ID,
                        "transcript": transcript.name,
                        "turn_id": "turn-target",
                    }
                )
                self.assertEqual(agent.recover_inflight_command({}), "completed")
                self.assertEqual(request.call_count, 1)
                self.assertEqual(request.call_args.kwargs["payload"]["status"], "completed")
                self.assertEqual(request.call_args.kwargs["payload"]["result"]["answer"], "recovered answer")
                self.assertIsNone(agent._load_inflight_command())

    def test_restarted_agent_fails_an_aborted_turn_and_requests_repair(self):
        with tempfile.TemporaryDirectory() as state_dir, tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8") as transcript:
            transcript.write(
                json.dumps(
                    {"type": "event_msg", "payload": {"type": "turn_aborted", "turn_id": "turn-target"}}
                )
                + "\n"
            )
            transcript.flush()
            with (
                mock.patch.object(agent, "STATE_DIR", Path(state_dir)),
                mock.patch.object(agent, "api_request", return_value={"ok": True}) as request,
                mock.patch.object(agent, "_request_failure_repair") as repair,
            ):
                agent._save_inflight_command(
                    {
                        "attempts": 1,
                        "command_id": "cmd-test",
                        "deadline_at": agent.time.time() + 60,
                        "offset": 0,
                        "session_id": SESSION_ID,
                        "transcript": transcript.name,
                        "turn_id": "turn-target",
                    }
                )
                self.assertEqual(agent.recover_inflight_command({}), "failed")

            self.assertEqual(request.call_args.kwargs["payload"]["status"], "failed")
            self.assertEqual(request.call_args.kwargs["payload"]["error"], "turn-aborted")
            repair.assert_called_once_with({}, "turn-aborted", SESSION_ID, "cmd-test")
            self.assertIsNone(agent._load_inflight_command())

    def test_restarted_agent_renews_the_original_command_lease(self):
        with tempfile.NamedTemporaryFile() as transcript, mock.patch.object(
            agent, "_wait_for_completion", return_value="answer"
        ), mock.patch.object(agent.threading, "Thread") as thread:
            self.assertEqual(
                agent._wait_for_recovered_completion(
                    {}, "cmd-recovery", 2, Path(transcript.name), 0, "turn-target", 30, None
                ),
                "answer",
            )

        thread.assert_called_once()
        self.assertEqual(thread.call_args.kwargs["target"], agent._lease_renew_loop)
        self.assertEqual(thread.call_args.kwargs["args"][:3], ({}, "cmd-recovery", 2))
        thread.return_value.start.assert_called_once()
        thread.return_value.join.assert_called_once_with(timeout=1.0)


class DaemonHeartbeatTests(unittest.TestCase):
    def test_recovery_config_source_and_emergency_override(self):
        with mock.patch.dict(agent.os.environ, {}, clear=True):
            self.assertEqual(agent.recovery_config_status({"TLS_AGENT_RECOVERY_ENABLED": "1"})["source"], "agent.env")
            self.assertTrue(agent.recovery_enabled({"TLS_AGENT_RECOVERY_ENABLED": "1"}))
            self.assertFalse(agent.recovery_enabled({
                "TLS_AGENT_RECOVERY_ENABLED": "1", "TLS_AGENT_RECOVERY_EMERGENCY_DISABLED": "1",
            }))

    def test_existing_recovery_session_is_discovered_when_launch_is_disabled(self):
        with tempfile.NamedTemporaryFile() as transcript:
            with (
                mock.patch.object(agent, "active_session_files", return_value={}),
                mock.patch.object(agent, "active_session_terminals", return_value={}),
                mock.patch.object(agent, "_active_recovery_sessions", return_value={SESSION_ID}),
                mock.patch.object(agent, "_transcript_for", return_value=Path(transcript.name)),
                mock.patch.object(agent, "latest_conversation_event", return_value="unknown"),
                mock.patch.object(agent, "session_label", return_value="Recovery"),
            ):
                records = agent.discover_sessions({"TLS_AGENT_RECOVERY_ENABLED": "0"})
        self.assertEqual(records[0]["session_id"], SESSION_ID)
        self.assertEqual(records[0]["status"], "idle")

    def test_explicit_session_with_live_terminal_remains_online(self):
        transcript = Path("/tmp/q2.jsonl")
        with (
            mock.patch.object(agent, "active_session_files", return_value={}),
            mock.patch.object(agent, "active_session_terminals", return_value={SESSION_ID: {"codex_pid": 42}}),
            mock.patch.object(agent, "_transcript_for", return_value=transcript),
            mock.patch.object(agent, "latest_conversation_event", return_value="idle"),
            mock.patch.object(agent, "_active_recovery_sessions", return_value=set()),
            mock.patch.object(agent, "session_label", return_value="用户端 q2"),
            mock.patch.object(agent, "_workspace", return_value="/tmp/workspace"),
        ):
            records = agent.discover_sessions({"TLS_AGENT_SESSION_IDS": SESSION_ID})

        self.assertEqual(records[0]["status"], "idle")

    def test_live_writer_cancels_ticket_without_launch(self):
        with (
            mock.patch.object(agent, "active_session_files", return_value={SESSION_ID: Path("/tmp/live.jsonl")}),
            mock.patch.object(agent, "active_session_terminals", return_value={}),
            mock.patch.object(agent, "api_request", return_value={"ok": True}) as request,
            mock.patch.object(agent.subprocess, "run") as run,
        ):
            agent.launch_recovery_tickets({}, {"recovery_compatible": True, "recovery_tickets": [{"ticket_id": "recovery_test", "session_id": SESSION_ID}]})
        run.assert_not_called()
        self.assertEqual(request.call_args.args[1], "/v1/agent/recovery/report")
        self.assertEqual(request.call_args.kwargs["payload"]["event"], "cancelled_live")

    def test_recovery_requires_claim_and_verified_heartbeat(self):
        completed = mock.Mock(returncode=0)
        with tempfile.NamedTemporaryFile() as transcript:
            with (
                mock.patch.object(agent, "_recovery_launches", return_value={}),
                mock.patch.object(agent, "active_session_files", return_value={}),
                mock.patch.object(agent, "active_session_terminals", return_value={}),
                mock.patch.object(agent, "_transcript_for", return_value=Path(transcript.name)),
                mock.patch.object(agent, "_runtime_for", return_value={"tmux_target": "test:0.0"}),
                mock.patch.object(agent, "discover_sessions", return_value=[{"session_id": SESSION_ID, "status": "idle"}]),
                mock.patch.object(agent, "_save_recovery_launches"),
                mock.patch.object(agent.subprocess, "run", return_value=completed) as run,
                mock.patch.object(agent, "api_request", side_effect=[
                    {"ticket": {"writer_epoch": 7}}, {"ok": True},
                    {"ok": True}, {"recovery_heartbeats": ["recovery_test"]}, {"ok": True},
                ]) as request,
            ):
                agent.launch_recovery_tickets({}, {"recovery_compatible": True, "recovery_tickets": [{"ticket_id": "recovery_test", "session_id": SESSION_ID}]})
        self.assertEqual([call.args[1] for call in request.call_args_list], [
            "/v1/agent/recovery/claim", "/v1/agent/recovery/report",
            "/v1/agent/recovery/renew", "/v1/agent/heartbeat", "/v1/agent/recovery/report",
        ])
        self.assertTrue(any("new-session" in call.args[0] for call in run.call_args_list))

    def test_recovery_launches_can_be_explicitly_disabled(self):
        with mock.patch.object(agent, "_recovery_launches") as launches:
            agent.launch_recovery_tickets(
                {"TLS_AGENT_RECOVERY_ENABLED": "0"},
                {"recovery_tickets": [{"ticket_id": "recovery_test", "session_id": SESSION_ID}]},
            )
        launches.assert_not_called()

    def test_heartbeat_continues_while_poll_is_blocked(self):
        poll_started = threading.Event()
        release_poll = threading.Event()
        handlers = {}
        heartbeat_count = 0

        def register_handler(signum, handler):
            handlers[signum] = handler

        def heartbeat(_config):
            nonlocal heartbeat_count
            heartbeat_count += 1
            if heartbeat_count >= 2:
                self.assertTrue(poll_started.wait(1.0))
                handlers[agent.signal.SIGTERM](agent.signal.SIGTERM, None)
                release_poll.set()

        def blocked_poll(_config, _stop_event):
            poll_started.set()
            self.assertTrue(release_poll.wait(1.0))
            return 0

        with tempfile.TemporaryDirectory() as state_dir:
            with (
                mock.patch.object(agent, "STATE_DIR", Path(state_dir)),
                mock.patch.object(agent, "MIN_HEARTBEAT_INTERVAL", 0.01),
                mock.patch.object(agent.signal, "signal", side_effect=register_handler),
                mock.patch.object(agent, "heartbeat_once", side_effect=heartbeat),
                mock.patch.object(agent, "poll_once", side_effect=blocked_poll) as poll,
            ):
                self.assertEqual(agent.daemon({}, 0.01, 0.01), 0)

        self.assertGreaterEqual(heartbeat_count, 2)
        poll.assert_called_once()
        self.assertEqual(poll.call_args.args[0], {})


if __name__ == "__main__":
    unittest.main()
