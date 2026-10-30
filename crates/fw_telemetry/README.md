# Optional telemetry consent core

This crate is a network-free state machine. It defaults to disabled with no
collector endpoint. It has no policy, packet, signer, executor, or network client
dependency. Protected administrator endpoint configuration and explicit,
revision-matched category consent are required before reports can be prepared.
A changed endpoint or privacy-policy digest revokes consent.

Only fixed adoption fields and five diagnostic event counters can enter reports.
Counts saturate at 9999; loss is marked. Reports exclude raw deletion tokens and
use CSPRNG-generated, consent/month-scoped identifiers. Repeated preparation
returns the same report ID and body. Completed reports cannot be repeated for the
same day/category; dates must be completed UTC days from the last three days,
and may not precede consent. Queue bounds are six reports, 64 KiB, and three days.

Disabling clears queued reports/counters, erases the active seed, and invalidates
previously issued send permits. Reconsent creates unrelated identities. Stored
monthly deletion secrets are retained in memory for up to 35 days and zeroized on
drop. They are not exposed through configuration serialization.

This is not a deployed telemetry system. Durable encrypted state, operating-system
account isolation, HTTP sender/scheduler with cancellation/backoff, secure remote
deletion, collector storage/retention, and API integration are not implemented.
There is no transmission or automatic collector installation. A future sender
must recheck a permit under config synchronization immediately before sending,
cancel in-flight HTTP on disable, and enforce the F-2.0 HTTP/resource limits.
Calling code must authenticate installation-wide telemetry-management authority;
`record_consent` is the pure transaction core, not an authentication endpoint.
