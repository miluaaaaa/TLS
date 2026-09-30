# Security and privacy

TLS stores Feishu IDs, session IDs, command payloads, results, and delivery
metadata in SQLite. Keep all three group-chat databases in a service-owned private
directory. The group modules set directories to `0700` and database files to
`0600`; verify the permissions after migrating an older installation.

The HTTP gateway has no built-in TLS and refuses to listen outside loopback.
Use an HTTPS reverse proxy for remote Agents. Do not put pairing codes or Agent
tokens in URLs or logs. The gateway does not write raw request targets to its
access log. Rotate credentials if a log, backup, or support bundle exposed one.

Do not commit `.env` files, SQLite databases, journals, Feishu event payloads,
real session/message IDs, transcripts, or repair records. The group-chat
history in this repository is redacted; the raw development log remains
private. Feishu group membership alone never grants a Codex session: an
operator must explicitly share it, and write access is separate from read.

Report security issues privately to the repository owner through GitHub's
private vulnerability reporting mechanism rather than opening a public issue
with credentials or message content.
