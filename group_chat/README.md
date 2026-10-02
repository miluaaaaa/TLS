# Group-chat control plane

This directory contains the TLS multi-user registry, Feishu WebSocket ingress,
durable Agent transport, loopback HTTP gateway, and user-side Codex Agent.
No operator credentials or running state are included.

## Components

| File | Responsibility |
| --- | --- |
| `qyp_multi_registry.py` | Users, installations, sessions, groups, explicit shares, task permissions, and message claims. |
| `qyp_multi_adapter.py`, `qyp_multi_feishu.py` | Authorization and group-event bridge without a Feishu SDK dependency. |
| `qyp_multi_transport.py` | Pairing, heartbeats, command leases, completion events, and recovery records in SQLite. |
| `qyp_multi_gateway.py` | Agent HTTP API bound to loopback; put an HTTPS reverse proxy in front for remote Agents. |
| `feishu_group_ingress.py` | Feishu long-connection event consumer, reply sender, and durable reply-to-continue bindings. |
| `qyp_multi_agent.py` | User-side Agent; its Codex bridge modules are included here. |

The executable registry schema is embedded in `qyp_multi_registry.py`
(`SCHEMA_VERSION = 8`). `schema.sql` is only a human-readable marker. The
transport schema is version 2 and the Agent wire protocol is version 2.

## Setup

Use Python 3.10 or later on Linux. The Agent additionally needs Codex CLI and
an active Codex app-server runtime or a supported tmux session. The server
needs the pinned Feishu SDK dependencies in `requirements.txt`. See the complete
[deployment guide](DEPLOY.md) for Feishu app permissions, TLS proxy, pairing,
services, and acceptance. Keep all three SQLite databases in a private
directory on the gateway host. These are example identifiers:

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
files. The gateway deliberately refuses a non-loopback bind. Expose it behind
a TLS reverse proxy, then give the Agent its HTTPS URL.

## Authorization and message lifecycle

The Feishu ingress obtains `open_id`, `chat_id`, `message_id`, and `chat_type`
from the SDK long connection. The group must already be registered.
The bridge can enroll a sender from that group event, but a session becomes
accessible only after explicit sharing. `read` shares cannot issue commands.
Revoking a share removes group access and associated subscriptions.
Registering a Session, enrolling its owner, or receiving another group event
never creates or restores a Session share. Results recheck current access
both when the Agent completes and before Feishu delivery.

## Shared work queue

Group members can create tasks with explicit acceptance criteria, claim one
available task, submit evidence, and release a task for another member. Only
the task owner can verify evidence and approve completion. Approval records
one credit for the current submitted claimant; it is attribution metadata,
not a billing or payment mechanism. A task can have only one open claim, and
claiming does not grant access to any unshared Codex session.
Use `/help` to see group commands and `/task <task-id>` to inspect acceptance
criteria, the current claimant, recent evidence, and completion credit.
Release retries are tied to the original message and claim, so a lost reply
cannot release a later claimant's work. Malformed management commands return
usage help rather than becoming instructions to Codex.

New evidence must start unverified. The registry permits verification only
by an approved task owner or an explicitly authorized reviewer; the Feishu
`/verify` and `/approve` commands remain owner-only and require a writable
task share. Accepted progress requires the completed task and its approved
evidence to remain verified.

Session owners may separately enable history search for a group. An ordinary
session share does not enable it. Searches execute on the owner's Agent and
return at most five short matches; the raw transcript stays local. Search
queries and returned snippets are stored in the durable transport database
and sent to the group, so enable this only for sessions suitable for sharing.
See the command examples in [DEPLOY.md](DEPLOY.md).
The Agent redacts common credential assignments, authorization headers,
private keys, and token formats before cutting short history snippets.

For each command, authorize first and then call `TransportStore.enqueue()`.
That method performs the atomic message-ID claim; do not claim the same message
separately. A duplicate Feishu delivery returns `duplicate=True`. The Agent
polls, renews its lease, and reports completion. The ingress then claims the
durable completion event, sends one reply, and marks the event sent only after
Feishu accepts the reply. The [integration contract](INTEGRATION.md) gives the
required call sequence and failure handling.

Queue receipt means only that a command was accepted, not that Codex saw it.
The full path is covered by local fake-Feishu integration tests. A real tenant
end-to-end acceptance is still required for a production deployment.

## Validation

```bash
PYTHONPATH=group_chat python3 -m unittest discover -s group_chat/tests -q
```

The Agent integration suite runs in CI from published source. See
[development history](GROUP_CHAT_HISTORY.md) for the original routing and
incident evidence.
