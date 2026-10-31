# Read the audit log

Audit events are an append-only, tenant-scoped hash chain. The authenticated
REST endpoint `GET /api/v1/audit/events` and MCP tool `get_audit_events` return
bounded pages from a fixed snapshot, so additional events do not invalidate an
ongoing read or force the entire result into one response.

## Snapshot pages

Start with a page limit, optionally filtering to events after a sequence. The
default limit is 50 and the maximum is 100; a byte budget may produce a smaller
page. Events are ordered by ascending sequence. REST accepts `limit`, canonical
decimal `after_sequence` and `cursor`; MCP `get_audit_events` uses the same fields
with `after_sequence` represented as a decimal string. A non-null `next_cursor`
means that the snapshot has more events. On continuation, omit filter/limit to
inherit them or repeat their original values; changed values are rejected.
Continue until `next_cursor` is null. Start a new read to include events appended
after the snapshot was captured.

Each opaque cursor is authenticated with HMAC-SHA256. It binds the organization,
project, principal, current session, REST-versus-MCP route, original sequence
filter, page limit, snapshot head and last returned sequence. The first page's
15-minute lifetime is retained throughout pagination. Editing a cursor, moving
it to another session/route, or changing its bound filters cannot authorize a
read. The server still checks current session and credential authorization on
every request. Invalid or mismatched cursors return HTTP 400; expired cursors
return HTTP 410 `CURSOR_EXPIRED`. Cursors are one base64url value with at most
2,048 characters and must be treated as opaque.

The HMAC key exists only in the running controller process. Restart, logout or
session replacement requires a new authenticated read; old cursors are not
portable export credentials. This mechanism covers audit events. Other catalogue
and request endpoints now have their own [collection snapshot contract](catalogue-pagination.md).

## Repeated authentication failures

The controller distinguishes normal unauthenticated session discovery from
explicit failed authentication. Credential-free anonymous protected GET probes
are not persisted as denials. Failures involving an explicit session cookie,
authorization header or write request are sampled instead.

There are at most 16 fixed server-reason buckets per process. The first sample
is written immediately; follow-up counts are coalesced at most once per minute
per bucket, on a background timer or later denial. Failed writes retain the
buffered counts and retry at most once per minute. A persisted summary links
those suppressed counts to the immutable audit chain without adding arbitrary
fields to the original `f.audit-event/v1` contract.

An event's `evidence_hashes` can reference a summary at:

```text
GET /api/v1/audit/denial-summaries/sha256:CONTENT_HASH
```

This authenticated development extension returns a tenant-scoped object with
schema `fw.authentication-denial-summary/v1`, the reason code, optional verified
actor, decimal-string count, UTC window boundaries and
`scope: suppressed_followup_denials`. The count excludes the separately recorded
initial sample. No supplied cookie, token, credential or raw attacker-controlled
message is used as the summary's content.

Migration 5 stores each canonical summary and its audit reference atomically.
Reads verify its content hash; exact repeated summary content is idempotent, and
stored summaries cannot be updated or deleted through these APIs.

The counts are operational evidence, not a complete access log. Buffered counts
can be lost on process crash or before a successful flush. Sampling, suppression
and missing intervals must not be described as durable per-request recording or
proof that no other authentication attempts occurred. The regular audit chain
and persisted evidence remain independently verifiable.

## Reproduce the integration check

After building the controller and static client, install the browser test
prerequisites from the [passkey guide](passkey-login.md#reproduce-the-browser-check)
and run:

```sh
python scripts/smoke_audit.py
```

The suite starts private disposable controller state, sends bounded bursts of
unauthenticated and invalid-session requests, follows REST/MCP snapshot pages,
and checks the shipped browser's pagination. The generated
`reports/audit-smoke.json` stays ignored locally or in the selected seven-day CI
artifact. Test results do not imply complete event retention across crashes.

See the [local authentication guide](passkey-login.md),
[implementation boundaries](implementation.md) and
[verification summary](../reports/README.md).
