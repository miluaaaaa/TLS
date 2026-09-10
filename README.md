# TLS Pairing

Give this repository URL to an existing Codex Agent.

## Pair

1. Open the published TLS bot in Feishu and send `/pair` in a private chat.
2. Copy the one-time pairing code returned by the bot to the Agent.
3. The Agent runs this command on the user's computer:

   ```bash
   python3 tls_pair.py pair --code '<ONE_TIME_PAIRING_CODE>'
   ```

The helper exchanges the code for a local Agent credential and stores it in
`~/.config/tls/agent.env`. It also installs and enables the local TLS Fault
Healer protocol. The credential must stay on the user's computer.

## Fault Healer Protocol

Each successful pairing accepts the TLS Fault Healer protocol for that machine.
The helper installs `~/.config/tls/runtime/tls_fault_healer.py`, writes its
enabled state into `agent.env`, and enables a user-level retry timer when
systemd is available. The component creates one bounded local Codex diagnosis
only after the local TLS bridge reports a hard delivery failure. It may repair
the local bridge, heartbeat, or managed proxy; it never changes the gateway or
Feishu, rebinds a Codex session, or replays a user message.

A TLS bridge integrates it by invoking the configured
`TLS_FAULT_HEALER_SCRIPT trigger --reason ... --session-id ... --command-id ...`
when it reports a hard command/heartbeat failure. Pairing installs this
protocol but does not retrofit an unrelated pre-existing bridge: that bridge
must make this explicit trigger call to report its failures.

## Finding the TLS Bot

The TLS bot must be published as a Feishu application before new users can find it.

- In the same Feishu tenant, publish the app and include the intended users in its visibility
  scope. Users can then search the published bot name in Feishu and open a private chat.
- To use TLS in a group, a group administrator adds the bot to the group.
- For users or groups outside the tenant, enable the app's external sharing capability and
  publish the required version.

GitHub cannot automatically add a Feishu bot to a user's tenant. The final README should include
the published TLS bot name or a direct Feishu entry link.

## Protocol Note

The current server issues the pairing code after the user sends `/pair`. An Agent-generated code
followed by `/pair <code>` requires a separate challenge endpoint and a Feishu ingress update; it
is not enabled by the current server.
