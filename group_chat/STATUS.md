# Implemented scope and remaining work

## Available in source

- Explicit Session sharing, read/write separation, private ownership, and
  revocation. Registration, member enrollment, and later messages never
  grant or restore a Session share.
- Durable command delivery, turn binding, completion retry, and reply
  continuation. Current access is checked when a result arrives and before
  it is sent to Feishu.
- Shared task creation with acceptance criteria, one active claim, release
  and takeover, evidence submission, owner verification and approval, and
  one credit for the final accepted claimant.
- `/help`, `/tasks`, and `/task <task-id>` for discovering commands and
  inspecting criteria, claimants, evidence, and credit. Malformed recognized
  commands do not reach Codex. Release retries cannot affect a later claim.
- Owner-enabled, bounded keyword history search. Common credentials are
  redacted before slicing; raw transcripts remain local, while queries and
  returned snippets are retained by the transport and visible to the group.
- Registry verification requires an approved owner or a reviewer with an
  explicit task/global capability. Evidence starts unverified; generic
  events cannot replace the approval operation. Progress reaches 100% only
  for a completed task whose accepted evidence is still verified.

These behaviors have local regression coverage. They are not evidence that
a particular operator's live deployment has passed acceptance.

## Remaining before a production deployment can be accepted

Run the [real-group acceptance probe](DEPLOY.md#verify) in the operator's
Feishu tenant, recording results privately. It must cover two-member claim
races, release/takeover, evidence approval and credit, duplicate events,
send failures, Agent restarts during a long turn, reply continuation, and
revocation both before completion and before delivery. Review pre-existing
Session shares when upgrading; old automatic shares cannot be reliably
distinguished from intentional ones.

## Further capabilities not implemented

- Automatic synchronization of Feishu member departures and a persistent
  per-group exclusion workflow. Group-event enrollment remains enabled;
  globally disabling a user is the existing operator-level denial path.
- Personal queue filters, pagination beyond the first 20 listed tasks, and
  automatic assignment or prioritization. Members explicitly claim shared
  tasks rather than receiving a fixed-size personal queue.
- Semantic retrieval across sessions. Current history search is bounded
  keyword matching within one explicitly authorized Session.
- Project/file synchronization. Sharing a Session and its workspace label
  does not publish a filesystem, clone a project, or transfer credentials.

The implementation was motivated by the first supplied screenshot. It does
not claim to reproduce every rule of the original post or an organization's
internal workflow.
