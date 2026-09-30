# Integration contract

`feishu_group_ingress.py` receives Feishu events through the official SDK
WebSocket client. Only text in registered groups is considered. A command
must mention this bot or reply to a TLS result. `/session <UUID> <command>`
selects a writable shared session explicitly; without it, the group must
have exactly one shared session. An unauthorized message cannot fall back
to a private session.

The ingress persists the incoming message before acknowledging the WebSocket
callback. It rechecks group membership and write access, then uses
`TransportStore.enqueue()` for the atomic message-ID claim. The Agent polls,
binds a real Codex turn, renews the command lease, and reports completion.
The ingress claims the durable completion event, sends one Feishu reply using
a stable deduplication UUID, stores that reply's message ID and session route,
then marks the event sent. On send failure it retries later. A reply to the
stored TLS message resolves the same session and repeats authorization before
enqueueing the next command.

The local Agent loads the bridge modules included in this directory. It
requires a local Codex transcript and a supported app-server socket or tmux
target. `TLS_AGENT_LOCAL_LIB` may override their location, but is not needed
for a source checkout. `TLS_FAILURE_REPAIR_SCRIPT` is optional; do not enable
automatic recovery until that separate handler has been validated locally.

The included tests cover authorization, duplicate events, completion sending,
send retry, reply continuation, bound turns, and Agent restart behavior. Before
claiming a deployment is accepted, perform the real-group probe in
[DEPLOY.md](DEPLOY.md) and record private IDs/timestamps outside the repository.
