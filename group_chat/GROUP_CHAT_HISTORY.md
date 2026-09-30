# TLS group chat: development and verification history

This is a sanitized development record for the group-chat control path. It is
not a claim that every group workflow has passed an end-to-end acceptance test.
Times below are China Standard Time (UTC+08:00).

## Scope and design

- A Feishu group can route commands only to sessions explicitly shared with
  that group. Membership and the share's read/write level are checked before
  command creation. Ordinary group messages are ignored; explicit commands
  select a target session.
- An installation-side Agent sends heartbeats, polls a durable command queue,
  binds a delivered message to a Codex turn, and returns a result. Message IDs
  provide an idempotency key for event claims.
- Queue acceptance, Agent delivery, Codex turn binding, completion, and Feishu
  reply are distinct states. An acknowledgement must not claim a later state
  before it is observed.

## Timeline

| Date | Observation and change | Evidence boundary |
| --- | --- | --- |
| 2026-09-08, 19:58-20:00 | A long command blocked the Agent's heartbeat loop. Other routed sessions were reported offline while their Codex processes were still alive. | Confirmed incident, not a Codex process outage. |
| 2026-09-08, 20:12-20:16 | After service recovery, three separately routed group commands completed and returned distinct probe markers. | Real Feishu-routed probes established routing at that point in time. |
| 2026-09-08, 20:35-20:44 | Heartbeats moved to an independent Agent thread while command execution remained serial. A long-running command and a second queued command were exercised together. | Focused Agent tests passed; live heartbeats stayed fresh beyond the 30-second online TTL. This did not prove group reply threading or reply-based continuation. |
| 2026-09-08, 20:43-21:07 | A queued command failed to create a Codex turn and held the serial queue. A separate 20-second turn-binding timeout and stop-aware waits were added; queue acknowledgements were changed to say delivery was not yet confirmed. | Focused Agent tests passed. A queue receipt alone remains insufficient evidence of Codex delivery. |
| 2026-09-09, 13:06-13:18 | Restarting the Agent during a bound turn incorrectly reported failure. The Agent began persisting the exact turn and resuming its wait without resending the user message. | Eight focused tests passed. |
| 2026-09-09, 14:56-16:12 | Session discovery and command-lease recovery were corrected after false-offline and post-restart failures. | Focused suites passed; historical failed commands were not replayed automatically. |
| 2026-09-09 | A recovery trial widened from one target to multiple historical sessions, disrupting the user's routed sessions. | High-severity incident. Future fault injection requires a single target and preservation of all non-target sessions. |
| 2026-09-09 onward | Proxy egress failures intermittently caused stale Agent heartbeats despite live Codex processes. An independent heartbeat timer and clearer transport failure logging were added. | Transport reachability must be checked separately from process and session liveness. |

## What is verified, and what remains open

The record supports group command routing, explicit sharing and authorization,
idempotent event claims, and the focused heartbeat, binding, and restart
regressions above. The group modules' local regression suite passed 60 tests on
2026-09-30.

The historical log explicitly did **not** accept the complete group reply and
continuation workflow. A release claim for that workflow needs a fresh group
probe that verifies one command claim, heartbeat and lease renewal during a
turn longer than the lease interval, exactly one completion reply attached to
the original group message, and a reply to that TLS message that continues the
same session exactly once. Unit tests and service health do not replace this
probe.

## Provenance

This account was reconstructed from the operator's 2026-09-08 to 2026-09-09
development log and the group module tests. Raw operational logs contain
message IDs, session IDs, local paths, and infrastructure details and are not
part of this publication draft.
