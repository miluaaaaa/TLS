# Integration contract

The group modules do not open a Feishu WebSocket or read Codex transcripts on
the gateway. The deployment supplies two adapters: a verified Feishu event
consumer on the control-plane host and a local Codex bridge beside each Agent.

## Feishu ingress

The event consumer must authenticate the Feishu event before using its IDs.
For a group command, construct an event with `open_id`, `chat_id`,
`chat_type="group"`, and a stable `message_id` from Feishu. Resolve the target
from an explicit command slot or a reply-card binding; never guess a private
session. The following is the call order after parsing and target resolution:

```python
from qyp_multi_feishu import ensure_group_member, authorize_group_event, registered_group
from qyp_multi_transport import TransportStore

if registered_group(event["chat_id"]) is not None:
    ensure_group_member(event["chat_id"], event["open_id"])
    route = authorize_group_event(event, session_id, action="write")
    queued = TransportStore().enqueue(
        message_id=event["message_id"], open_id=route.open_id,
        chat_id=route.chat_id, session_id=route.session_id, text=command_text,
    )
```

`enqueue()` owns the atomic message claim. Calling `claim_group_event()` first
would make the subsequent enqueue appear duplicate. Check `duplicate`,
`queued`, and `waiting_recovery` in its result; acknowledge only the observed
state. Keep the Feishu message ID on the command and reply so retries can be
deduplicated. Recheck membership and share permissions for a reply or card
action before queuing another command.

To publish Agent results, use `TransportStore.next_event()`,
`claim_event(event_id)`, and `complete_event(event_id, status="sent")` after a
successful Feishu send. On a failed send, complete with `status="failed"` and
a bounded retry delay. A claimed event must not be reported sent before Feishu
accepts the reply. Store the returned Feishu message ID for any reply-based
continuation. This package does not include that message-binding store or a
running Feishu consumer; an operator must implement and test them.

## Local Agent bridge

`qyp_multi_agent.py` imports four local bridge modules: `codex_session_watch`,
`codex_completion_watch`, `mobile_reply`, and `session_policy`. Set
`TLS_AGENT_LOCAL_LIB` to the directory containing them. The bridge must report
the exact submitted turn, preserve a bound turn across Agent restarts, and
prove absence of delivery before retrying a pre-turn failure. These modules
are installation-specific and are not bundled here.

Set `TLS_FAILURE_REPAIR_SCRIPT` only if an installed, trusted local repair
handler implements the `trigger` command. The repository's legacy
`tls_fault_healer.py` is the default path when this variable is unset. Do not
enable automatic recovery solely because the gateway process is healthy.

## Acceptance before a production claim

In a registered test group, send one unique command and verify its single
claim, Agent delivery, exact Codex turn, and one reply attached to the
original group message. Then reply to that TLS message and verify the next
command reaches the same session exactly once. During a turn longer than the
lease interval, verify fresh heartbeats and lease renewal. Finally, exercise
a Feishu send failure and Agent restart while checking that non-target
sessions remain routable. Record IDs and timestamps in a private test log;
publish only a redacted summary.
