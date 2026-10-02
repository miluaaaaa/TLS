# TLS

TLS connects Feishu conversations to explicitly authorized Codex sessions.
The repository contains a legacy single-user pairing protocol and a newer
[group-chat implementation](group_chat/README.md). The group-chat source now
includes the Feishu long-connection consumer, durable reply bindings, and
local Codex bridge. It also supports shared task claims, evidence-based
approval, group help and task details, and owner-enabled session history
search. Follow the [deployment guide](group_chat/DEPLOY.md) and check the
[implemented scope and remaining work](group_chat/STATUS.md).

## Group chat

The group implementation keeps users, installations, sessions, group
memberships, and session shares in a SQLite registry. A group message never
falls back to a private session. A writable, explicitly shared session is
required before a command can be queued. The gateway stores commands and
results durably; an installation-side Agent polls it over HTTPS.

Start with the [group-chat setup](group_chat/README.md). The
[development history](group_chat/GROUP_CHAT_HISTORY.md) separates verified
routing and regression tests from the group reply/continuation workflow that
still needs a fresh end-to-end acceptance run.

## Legacy pairing

The root-level `tls_multi_*`, `tls_pair.py`, and `tls_fault_healer.py` files are
the earlier protocol. An existing Feishu bot may issue a one-time code in a
private chat. On a user's computer, the legacy helper can exchange it for an
Agent credential:

```bash
python3 tls_pair.py pair --code '<ONE_TIME_CODE>' --url 'https://your-gateway.example/tls-agent'
```

The credential is stored under `~/.config/tls/agent.env` and must remain local.
The optional Fault Healer only acts when a local bridge explicitly reports a
hard failure; installation alone does not retrofit another bridge.

## Feishu app

The operator must create and publish a Feishu app, grant the required message
permissions, and make the bot visible to the intended users or groups.
Adding a bot to a group does not grant access to any Codex session. Register
the group and explicitly share sessions through the registry first.

No real app ID, bot name, tenant address, session ID, or production log is
included in this repository. See [security guidance](SECURITY.md).

## Development

The group core uses Python 3.10 or later and the standard library. Run its
dependency-free tests with:

```bash
PYTHONPATH=group_chat python3 -m unittest discover -s group_chat/tests -q
```

Agent integration tests in `group_chat/integration_tests` run from the same
source checkout. The root-level legacy modules retain their tests under
`tests/`. This repository is licensed under [MIT](LICENSE).
