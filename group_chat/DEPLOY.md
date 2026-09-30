# Deploy the group-chat bot

This deployment uses one gateway host, one Feishu long-connection consumer,
and one Linux machine running Codex and the Agent. Use Python 3.10+. Keep the
three SQLite databases on persistent, private storage. Local tests need no
Feishu account; a live bot needs your own app credentials. On Debian/Ubuntu,
install `python3-venv` before creating the environment if `ensurepip` is absent.

## Feishu app

Create and publish a custom app with bot capability. Grant `im:message` (or
the bot-send permission shown for your app), `im:message.group_at_msg`, and
`im:message.group_msg`. The last scope is needed for an unmentioned reply to
a TLS result. Subscribe to `im.message.receive_v1` through a long connection.
Add the bot to the group and make the app visible to its users. Set
`FEISHU_BOT_OPEN_ID` to the bot's actual `open_id`; mentioning another user
must not trigger a command. No public event callback URL is needed for the
long connection. See [Feishu permissions](https://open.feishu.cn/solutions/detail/ticket?lang=en-US)
and the [official Python SDK](https://github.com/larksuite/oapi-sdk-python).

## Gateway host

From this checkout:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r group_chat/requirements.txt
install -d -m 700 "$HOME/.local/state/tls-group-chat"
export PYTHONPATH="$PWD/group_chat"
export QYP_TLS_MULTI_DB="$HOME/.local/state/tls-group-chat/multi.sqlite3"
export QYP_TLS_MULTI_TRANSPORT_DB="$HOME/.local/state/tls-group-chat/agent.sqlite3"
export TLS_FEISHU_ROUTES_DB="$HOME/.local/state/tls-group-chat/routes.sqlite3"
.venv/bin/python group_chat/qyp_multi_registry.py --db "$QYP_TLS_MULTI_DB" init
```

Register an approved owner, installation, real Codex session UUID, and actual
Feishu group chat ID. Replace every example identifier:

```bash
.venv/bin/python group_chat/qyp_multi_registry.py --db "$QYP_TLS_MULTI_DB" add-user \
  --open-id ou_example --name Owner --user-id owner --status approved
.venv/bin/python group_chat/qyp_multi_registry.py --db "$QYP_TLS_MULTI_DB" add-installation \
  --user owner --id laptop --name Laptop
.venv/bin/python group_chat/qyp_multi_registry.py --db "$QYP_TLS_MULTI_DB" add-session \
  --installation laptop --session-id 019ffaf4-eccd-7203-b5b4-51d967ec128b --label Work
.venv/bin/python group_chat/qyp_multi_registry.py --db "$QYP_TLS_MULTI_DB" create-group \
  --id team --chat-id oc_example --name Team --creator owner
.venv/bin/python group_chat/qyp_multi_registry.py --db "$QYP_TLS_MULTI_DB" share-session \
  --group team --session 019ffaf4-eccd-7203-b5b4-51d967ec128b --access write
```

Use [`config.example`](config.example) as the list of required variables.
Store `FEISHU_APP_ID`, `FEISHU_APP_SECRET`, `FEISHU_BOT_OPEN_ID`, and the
three database variables in a mode-600 environment file used by both
services. Run the gateway on loopback and the ingress as separate processes:

```bash
.venv/bin/python group_chat/qyp_multi_gateway.py --host 127.0.0.1 --port 8766
.venv/bin/python group_chat/feishu_group_ingress.py
```

Expose only the Agent API through a TLS reverse proxy. Example Caddy config
for a domain you control:

```caddyfile
agent.example.org {
    reverse_proxy 127.0.0.1:8766
}
```

Run the gateway and ingress with your service manager using the same
`PYTHONPATH` and database paths. Pairing uses a one-time code, then a bearer
token. Do not publish the SQLite files, token, or app secret. Back up all
three databases using SQLite's backup API or while both services are stopped.

## Pair a Codex machine

Create a one-time code on the gateway host and convey it privately to the
owner:

```bash
.venv/bin/python group_chat/qyp_multi_registry.py --db "$QYP_TLS_MULTI_DB" \
  pair --user owner --installation laptop --ttl 600
```

On the Linux Codex machine, use the same checkout. `codex` and `tmux` must be
on `PATH`; session JSONL files must be readable by the Agent user. Pair once
and run the long-lived Agent:

```bash
python3 group_chat/qyp_multi_agent.py pair \
  --url https://agent.example.org --code '<ONE_TIME_CODE>' --name Laptop \
  --hostname laptop --session-id 019ffaf4-eccd-7203-b5b4-51d967ec128b
python3 group_chat/qyp_multi_agent.py daemon
```

Pairing writes a mode-600 `~/.config/tls/agent.env`. Set `TLS_CODEX_HOME`,
`TLS_CODEX_RUNTIME_ROOTS`, or `TLS_AGENT_SESSION_IDS` when Codex uses
non-default paths. The session policy is fail-closed: list each allowed
session UUID in `~/.config/tls/included-sessions` (one per line, mode 600)
before starting the Agent. For the example session:

```bash
install -d -m 700 "$HOME/.config/tls"
printf '%s\n' '019ffaf4-eccd-7203-b5b4-51d967ec128b' > "$HOME/.config/tls/included-sessions"
chmod 600 "$HOME/.config/tls/included-sessions"
python3 group_chat/session_policy.py validate
```

Run the Agent as the same OS user as Codex.

## Verify

```bash
PYTHONPATH=group_chat:. python3 -m unittest discover -s group_chat/tests -q
PYTHONPATH=group_chat:. python3 -m unittest discover -s group_chat/integration_tests -q
```

In the registered group, mention the bot with a unique command. Verify one
queued command, one bound Codex turn, and one reply to the original message.
Reply to that TLS message without mentioning the bot and verify the next
turn uses the same session once. Revoke the share; the next write must fail.
Simulate a transient Feishu send failure and restart the Agent during a long
turn; confirm the reply appears once and the lease is renewed. Keep actual
IDs and timestamps in a private log. Local tests do not replace this probe.
