# Group-chat control plane

This directory contains the TLS multi-user registry, Feishu-neutral adapter,
durable Agent transport, loopback HTTP gateway, and optional user-side Agent.
It is a source release, not a copy of an operator's running state or Feishu
event consumer.

## Components

| File | Responsibility |
| --- | --- |
| `qyp_multi_registry.py` | Users, installations, sessions, groups, explicit shares, task permissions, and message claims. |
| `qyp_multi_adapter.py`, `qyp_multi_feishu.py` | Authorization and group-event bridge without a Feishu SDK dependency. |
| `qyp_multi_transport.py` | Pairing, heartbeats, command leases, completion events, and recovery records in SQLite. |
| `qyp_multi_gateway.py` | Agent HTTP API bound to loopback; put an HTTPS reverse proxy in front for remote Agents. |
| `qyp_multi_agent.py` | Optional user-side Agent. It requires the local Codex bridge modules listed in `INTEGRATION.md`. |

The executable registry schema is embedded in `qyp_multi_registry.py`
(`SCHEMA_VERSION = 7`). `schema.sql` is only a human-readable marker. The
transport schema is version 2 and the Agent wire protocol is version 2.

## Local control-plane setup

Use Python 3.10 or later. Keep the two SQLite databases in a private directory
on the gateway host. These are example identifiers, not real Feishu IDs:

```bash
export PYTHONPATH="$PWD/group_chat"
export QYP_TLS_MULTI_DB="$HOME/.local/state/tls-group-chat/multi.sqlite3"
export QYP_TLS_MULTI_TRANSPORT_DB="$HOME/.local/state/tls-group-chat/agent.sqlite3"
python3 group_chat/qyp_multi_registry.py --db "$QYP_TLS_MULTI_DB" init
python3 group_chat/qyp_multi_registry.py --db "$QYP_TLS_MULTI_DB" \
  add-user --open-id ou_example --name Owner --user-id owner --status approved
python3 group_chat/qyp_multi_registry.py --db "$QYP_TLS_MULTI_DB" \
  add-installation --user owner --id laptop --name Laptop
python3 group_chat/qyp_multi_registry.py --db "$QYP_TLS_MULTI_DB" \
  add-session --installation laptop \
  --session-id 019ffaf4-eccd-7203-b5b4-51d967ec128b --label "Research"
python3 group_chat/qyp_multi_registry.py --db "$QYP_TLS_MULTI_DB" \
  create-group --id group-example --chat-id oc_example --name "TLS Example" --creator owner
python3 group_chat/qyp_multi_registry.py --db "$QYP_TLS_MULTI_DB" \
  share-session --group group-example \
  --session 019ffaf4-eccd-7203-b5b4-51d967ec128b --access write
python3 group_chat/qyp_multi_gateway.py --host 127.0.0.1 --port 8766
```

Both gateway and event consumer must use the same registry and transport
files. The gateway deliberately refuses a non-loopback bind. Expose it only
behind a TLS reverse proxy with access controls, then give the Agent the
HTTPS URL.

## Authorization and message lifecycle

The Feishu ingress must supply a real `open_id`, `chat_id`, `message_id`, and
`chat_type=group` from a verified event. The group must already be registered.
The bridge can enroll a sender from that group event, but a session becomes
accessible only after explicit sharing. `read` shares cannot issue commands.
Revoking a share removes group access and associated subscriptions.

For each command, authorize first and then call `TransportStore.enqueue()`.
That method performs the atomic message-ID claim; do not claim the same message
separately. A duplicate Feishu delivery returns `duplicate=True`. The Agent
polls, renews its lease, and reports completion. The ingress then claims the
durable completion event, sends one reply, and marks the event sent only after
Feishu accepts the reply. The [integration contract](INTEGRATION.md) gives the
required call sequence and failure handling.

Queue receipt means only that a command was accepted, not that Codex saw it.
The complete reply-to-original-message and reply-to-continue loop has not yet
been revalidated end to end in this public package. Do not advertise it as an
accepted feature on service health or unit tests alone.

## Validation

```bash
PYTHONPATH=group_chat python3 -m unittest discover -s group_chat/tests -q
```

The Agent integration tests require `codex_session_watch`,
`codex_completion_watch`, `mobile_reply`, and `session_policy` from the local
Codex bridge. They are intentionally separate from the dependency-free CI
suite. See [development history](GROUP_CHAT_HISTORY.md) for the original
routing and incident evidence.
