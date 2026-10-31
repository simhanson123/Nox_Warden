# Independent local authority review

`fw_authority_service` runs a bounded review process on its own configured
loopback origin, for example `http://localhost:8790`. It serves an independently
built authority UI and reads immutable plans from `AuthorityStore`. Controller
login credentials, cookies, role claims and draft plans confer no authority here.
It has no signer, deployment endpoint or privileged firewall operation.

This is a local development profile. Separate protected OS accounts, directory
ownership/ACLs, authenticated IPC, production authority bootstrap, trustworthy
artifact admission and installed-platform qualification remain deployment gates.
A second process and database under the same writable account do not establish
that protection. Automated P-256 and virtual-authenticator tests verify protocol
behavior, not a person's comprehension or physical authenticator assurance.

## Explicit startup and trust

Startup requires an existing nonempty private authority database, an explicit
private configuration file, a separate private 32-byte random session-key file,
and a built authority UI directory. It does not create an owner, import a
controller credential, enroll a browser key or automatically migrate an old
store. Perform any required store migration through the trusted local authority
maintenance procedure before starting this service.

```sh
source scripts/dev-env.sh
cargo build --locked -p fw_authority_service
./target/debug/fw_authority_service \
  --config /private/authority/config.json \
  --session-key-file /private/authority/session.key
```

Configuration is closed JSON. All fields are required:

```json
{
  "origin": "http://localhost:8790",
  "controller_origin": "http://localhost:8787",
  "database": "/private/authority/authority.sqlite3",
  "ui_directory": "/private/authority/ui",
  "profiles": {
    "reviewer": {
      "org_id": "22222222-2222-4222-8222-222222222222",
      "project_id": "33333333-3333-4333-8333-333333333333",
      "principal_id": "11111111-1111-4111-8111-111111111111",
      "credential_id": "the-explicitly-pinned-credential-id"
    }
  },
  "review_evidence": {
    "44444444-4444-4444-8444-444444444444": "/private/authority/review.json"
  }
}
```

The authority origin must be canonical `http://localhost:<nonzero-port>` and
must differ from the configured controller origin. It binds IPv4 loopback only.
The supplied authority UI build currently supports `http://localhost:8790` only;
other explicit server origins require a separately matched UI build and are not
claimed as a working bundled UI configuration. Both origins are checked by the
existing WebAuthn origin validator. The shared
`localhost` RP ID does not make the origins interchangeable.

A profile is a local alias selecting already provisioned authority records. The
service resolves the pinned credential and current principal/project roles from
the authority database; configuration cannot grant roles or replace a key. The
profile list is not publicly enumerable. This bounded local profile uses an
explicit alias and credential allow-list, not discoverable multi-tenant login.
An existing pending key can complete a distinct possession ceremony; an active
key completes a fresh authentication ceremony. Public option issuance reserves
no durable activation slots. Only a verified pending-key proof creates and
consumes a retained activation-state row, updates the credential, advances the
security revision and appends audit in one transaction. Active login similarly
updates the durable credential revision and audit atomically. Neither route
provisions a new credential. Invalid/revoked/expired or
roleless configured profiles cause startup to fail closed.

Quorum completion additionally requires a current independently pinned authority
epoch/role-policy basis and explicit canonical human-identity mappings in the
authority database. Runtime startup and HTTP routes never create these records
or infer them from a plan. A service with valid login records but missing quorum
trust can retain signed decisions; it reports `authority_unavailable` and never
returns a completed set. Use the trusted local authority administrator to pin
that basis and bind independently established human identities.

On Unix, private files must be regular, single-link, without group/other access;
UI files may be publicly readable but not group/other writable. Immediate
containing directories must not be group/other writable or symlinks. These
checks do not establish protected ownership, ancestor ACL correctness or
resistance to a same-account attacker replacing files. Windows ACL enforcement
is not implemented; this local service refuses non-Unix startup until that
private-file adapter exists. Native Windows/macOS production qualification is
not established by the Unix development profile.

## File modes, inherited ACLs and startup diagnostics

The authority build output is an input to protected installation. Vite's output
can inherit a default ACL from a developer checkout; `umask 022` alone does not
remove inherited ACL entries. In particular, an output file with mode `0646`
(other-writable) is refused. The service does not change file modes or ACLs to
make an existing input acceptable.

| Input | Suggested Unix mode | Required checks |
| --- | --- | --- |
| Configuration, session key, database, review bundles | `0600` | Regular single-link file; no group/other access |
| Authority private state directory | `0700` | Protected ownership/ancestors; immediate parent is not a symlink or group/other writable |
| Installed UI files (`index.html`, hashed assets) | `0644` or `0600` | Regular single-link file; no group/other write |
| Installed UI directory and `assets/` | `0755` or `0700` | No group/other write; no symlink immediate parent |

Use the deployment account to inspect `stat` and `getfacl` output on the selected
inputs and their ancestors. Named ACL entries and directory defaults need an
operator review as well as the numeric mode; the startup checks do not prove
ownership or a complete protected ancestor chain. On systems with POSIX ACLs,
install the `getfacl`/`setfacl` tools before following this example. This recipe
creates a **new**, authority-owned release directory below an already protected
parent; `mkdir` deliberately fails if the destination exists. It removes ACLs
only from the new directories that this command just created. It never repairs
or recursively changes an existing untrusted path.

```sh
set -eu
# Set these to an independently verified release and protected authority parent.
release=/verified/release/web/dist-authority
new_ui=/protected/authority/ui-release-unique
umask 022
mkdir -m 0755 -- "$new_ui"
setfacl -b -k -- "$new_ui"
mkdir -m 0755 -- "$new_ui/assets"
setfacl -b -k -- "$new_ui/assets"
test -f "$release/index.html" && test ! -L "$release/index.html"
install -m 0644 -- "$release/index.html" "$new_ui/index.html"
for asset in "$release"/assets/*; do
  test -f "$asset" && test ! -L "$asset"
  case "$asset" in *.js|*.css|*.svg) ;; *) exit 1 ;; esac
  install -m 0644 -- "$asset" "$new_ui/assets/"
done
stat -c '%a %n' -- "$new_ui" "$new_ui/assets" "$new_ui/index.html" "$new_ui"/assets/*
getfacl -p -- "$new_ui" "$new_ui/assets" "$new_ui/index.html" "$new_ui"/assets/*
```

Point the private configuration's `ui_directory` at the reviewed installation,
then start the service. Artifact provenance and protected OS account deployment
are separate requirements; copying files and clearing inherited ACLs does not
establish either.

Refused startup emits one bounded line to stderr, for example
`AUTHORITY_STARTUP stage=ui_assets code=AUTHORITY_UI_ASSETS_REJECTED`.
Stages distinguish `arguments`, `config`, `session_key`, `origin`, `database`,
`trust`, `ui_assets`, `review_evidence`, `runtime_key`, and `bind`. A stopped
listener reports `listener`. Only fixed stage/code pairs are printed: no raw
OS, JSON, database or cryptographic error, input value, key, assertion or private
path is included. For `ui_assets`, inspect the chosen installation's existence,
modes/ACLs, regular-file/link policy and documented asset count/size/type limits.
A `database` failure may require trusted migration or permissions repair; a
`trust` failure requires reviewing the preprovisioned profile, key and role
records. A `bind` failure means the configured loopback listener could not be
opened, including an occupied port. These diagnostics identify a stage, not the
specific private cause. They do not log configuration or weaken the refusal.

## Authoritative review content

A review bundle is closed JSON containing `before` and `after`, both complete
`fw_planner::StateIr` objects. It comes from an explicitly selected private local
file, never a browser request or controller response. The service snapshots it
at startup. Restart is required to load an operator's changed file.

For `policy_change`, each display and approve request checks normalization,
canonical baseline/candidate hashes, candidate reference hash and byte length,
target/tenant bindings, and source/capability references. It independently applies
the stored operations with `compose_policy_change` and compares the resulting
candidate, patch hash, complete relation and semantic region hashes. Before/after
policies include the actual affected address/port/interface/lifetime scope.
The combined full plan/before/after review payload is conservatively limited to
128 KiB, reserving response space for requirements and decision metadata.
Oversized review content is unavailable and cannot authorize approve; it is
never truncated into an apparently complete review. All JSON responses have a
256 KiB hard cap and return a bounded unavailable error when exceeded.
Missing, inconsistent, unsupported or incomplete evidence produces
`review.available=false`; the server refuses approve challenge issuance and
approve assertion admission, including a challenge created by another trusted
library caller. Rejection remains available. `add_access_lease` approval evidence
is not implemented by this profile and therefore remains gated.

These checks do not authenticate the original baseline observation, compiler
artifact, target capability or referenced gate evidence. Those sources and a
future signer must be independently qualified before any dispatch. Trusted
provisioning and a JSON `PASS` string are not substitutes for that qualification.

## HTTP contract

All API paths start with `/authority/v1`. Exact configured Host is required for
API and static files. Unsafe methods require exact Origin; any supplied Origin
must match on reads too. Protected reads and writes additionally require the
HttpOnly session cookie **and** `X-Authority-CSRF`, held only in browser memory.
Duplicate cookie credentials/headers, duplicate or unknown JSON fields, URL
queries and forwarded identity headers are rejected. No CORS permission is
emitted. Responses are `no-store`, cannot be framed, and use a restrictive CSP.
The cookie is Secure, HttpOnly, host-only, `Path=/`, SameSite=Strict. Secure
localhost behavior is exercised by the Chromium smoke; remote HTTP is unsupported.

| Method/path | Request | Response |
| --- | --- | --- |
| `GET /session` | Fresh page: no proof | `{authenticated:false,csrf_token}` and a new anonymous cookie; never reveals an earlier session's CSRF |
| `GET /session` | Existing cookie and CSRF | Current session, with authenticated principal/tenant/roles and RFC3339 `expires_at` |
| `POST /auth/options` | `{profile}` | `{ceremony_id,kind:"login"\|"activation",options}` |
| `POST /auth/verify` | `{ceremony_id,assertion}` | Rotated cookie/CSRF and authenticated session |
| `POST /logout` | `{}` | Invalidates old session and returns a new anonymous binding |
| `GET /plans` | Cookie and CSRF | At most 100 live tenant plans, newest first |
| `GET /plans/{id}` | Cookie and CSRF | Exact `plan`, `requirements`, hashes, eligible `roles`, `review`, current principal's retained decisions, live `aggregation` and `current_approval_set` |
| `POST /approvals/challenges` | `{plan_id,plan_hash,requirements_hash,decision,role}` | `{challenge,options}` from the authority's immutable plan |
| `POST /approvals/assertions` | `{challenge_id,idempotency_key,assertion}` | `{approval,replayed,aggregation}` from atomic cryptographic admission |

`assertion` is the standard JSON WebAuthn authentication response, not an approval
boolean. `challenge.subject.plan_ref` identifies the exact plan; the challenge
also binds principal/tenant, decision, role, requirements, RP, origin and expiry.
The idempotency key is a canonical UUID. Exact successful retries return the
original decision and never renew its validity. A lost login response requires
a fresh login; login verification is deliberately one-use.

Plan detail returns
`current_principal_decisions:[{approval:<HumanApproval>,current_valid:boolean}]`.
Historical evidence stays immutable; current validity is independently checked
at read time. Individual decisions are not a quorum result.

Plan detail also returns `aggregation:{state,...}` and
`current_approval_set:null|{content,hash,valid_until}` from one consistent,
read-only authority snapshot. `content` is the exact `f.approval-set/v1` object;
`hash` is its canonical content hash and `valid_until` is RFC3339 UTC. A non-null
set is returned only after the store revalidates the original proofs, current
credentials/roles, independent authority basis, canonical human identities,
requirements and dissent. GET never assembles or refreshes an approval set.

Current states are `authority_unavailable`, `pending`, `blocked_by_dissent`,
`approved` (with `approval_set_id` and `approval_set_hash`), and `stale`.
Missing trust is explicitly unavailable, not pending or approved. A terminal
rejection blocks that plan even if a later signed decision says approve. An
expired or changed authority basis makes an old set stale and removes it from
this current projection, preserving its immutable stored content. Expired or
retired plans still fail the earlier live-plan detail check with a conflict.

The `aggregation` returned by POST `/approvals/assertions` is the original
admission result. An exact replay repeats that historical result even when the
set is now stale; legacy receipts may say `not_evaluated`. Clients must refetch
plan detail to display current quorum status. Neither an admission receipt nor
a current read snapshot reserves signing authority or creates a grant; a future
signing transaction must independently recheck its current authorization.

All protected requests recheck active credential, current scoped roles and the
session's project security revision. Role/key changes invalidate existing
sessions. Authenticated session state remains server memory. Anonymous bindings and login
ceremonies use opaque AES-256-GCM envelopes with independent purpose/origin AAD,
unique nonces and a runtime-key-derived boot master. The browser receives no plaintext
private verification state and persists no ticket or session proof. Restart
invalidates old anonymous envelopes, login tickets and authenticated sessions. Approval challenges, decisions and original proofs
remain durable in `AuthorityStore`. A browser reload starts a fresh passkey login.

A non-clonable checked 64-bit sequence supplies the nonce. Separate HMAC-SHA256
domains derive anonymous and login AES keys, changing them every 65,536 sequence
values. Payload/context limits keep each derived key below 2^27 GHASH input
blocks. Old epochs remain derivable without a key cache, so further issuance
never evicts unexpired tickets. Exhaustion stops new issuance while preserving
old decryption; restart replaces the boot master. This bounds encryption use,
not failed verification attempts or sustained request saturation.

Errors contain only `{error,reason}` with stable codes. `AUTHORITY_STATE_CHANGED`
is a conservative conflict response for a stale, expired or ineligible store
operation; it does not disclose another tenant's state. No assertion, private
state, session secret or configuration path is logged or placed in a URL.

The executable serves at most 64 connection tasks plus one just-accepted socket.
When full, it can evict the oldest unverified connection still reading headers
or sending a completed response. It does not evict in-progress request work or
connections promoted after current session verification. Atomic phase transitions
prevent an evicted connection from beginning or promoting a request; a completed
task is joined before a replacement starts. Headers remain limited to 48 and a
16 KiB parsing buffer, API header content to 8 KiB, JSON bodies to 64 KiB, body
reads to three seconds, initial header reads to one second and connection
lifetime to 30 seconds. Dripping bytes does not renew these deadlines.

Request admission reserves eight work slots for public requests and eight for
verified authenticated requests, before reading bodies. A bounded mirror of the
existing 128-session registry checks the exact cookie, memory-only CSRF proof
and expiry. Only a matching proof can enter a separate eight-slot current-state
checking lane. One additional authority database connection rechecks the active
key, scoped roles and project security revision, followed by fresh expiry and
mirror checks, before authenticated capacity is granted. Missing, forged,
revoked, removed or revision-stale sessions cannot borrow that capacity. The
mirror is published after dispatch on both success and error, including logout;
it is routing evidence only. Runtime dispatch still independently rechecks the
actual session and current authorization. Blocking jobs retain their permits
until completion even when a client disconnects or its response times out.

These bounds mitigate the reproduced 64-idle-connection and public slow-body
starvation cases. They reserve admission capacity, not CPU priority or a latency
guarantee: public and authenticated dispatch still serialize on the runtime lock.
Fresh sign-in remains public work. Sustained TCP, public-work, authenticated,
CPU or database saturation can still deny service; protected OS accounts,
authenticated IPC and deployment resource controls remain required. SQLite has
its existing five-second busy bound. A timed-out/disconnected response does not
imply a rolled-back admission; use the same assertion/idempotency key to reconcile.
Sessions last 15 minutes and login ceremonies five minutes. Public anonymous
bindings and login options allocate no session slots or durable credential
reservations. At most four proven sessions per configured key and 128 total are
retained; a fresh valid proof evicts the oldest session for that same key only.
Protected API limits are scoped to the authenticated session (120/minute), so
anonymous calls cannot consume an owner's persistent admission budget. Invalid
login proofs retain at most one sampled audit event per configured key per minute;
this bounded sampling is observation only and never locks a key or prevents a
valid proof. Sample history is memory-only and is not complete failure retention.
Process restart resets it and sessions, not persisted approval attempt bounds.

Login tickets capture the durable credential and security revisions. Success
always increments the credential revision inside `BEGIN IMMEDIATE`, including
zero-counter authenticators, so exact replay cannot mint another session even
across database reopen or concurrent service connections. Audit failure rolls
back counter/revision/activation changes. Login/activation does not retain the
original raw assertion for later cryptographic evidence review; full original
signature retention applies to the separate HumanApproval decision transaction.

## Isolated reproduction

The explicit example provisioner creates a **new** private fixture directory,
actual synthetic policy plans, reviewed before/after states and a test-only
software key. It explicitly pins the fixture's independently configured epoch-1
role-policy basis and canonical owner-human mapping through trusted local store
methods; it does not derive those trusted values from the submitted plan. It performs no controller import or network enforcement. Never
use this software key for production authority.

```sh
cargo build --locked -p fw_authority_service --examples --bin fw_authority_service
./target/debug/examples/review_fixture \
  /tmp/new-authority-review-fixture /absolute/path/to/web/dist-authority
./target/debug/fw_authority_service \
  --config /tmp/new-authority-review-fixture/config.json \
  --session-key-file /tmp/new-authority-review-fixture/session.key
cargo test --locked -p fw_authority_service -p fw_authority
cargo clippy --locked -p fw_authority_service -p fw_authority --all-targets -- -D warnings
```

The fixture outputs private `virtual_authenticator.json` for Chromium CDP and
`fixture.json` with the local `owner` alias and four plan IDs: reviewed approval,
reviewed rejection, deliberately missing review evidence and a plan whose epoch
does not match the fixture's trusted basis (`stale_plan_id`). The reviewed plans
start pending; real signed decisions exercise completed and dissent-blocked
quorums. The mismatched plan remains stale. Keep all generated
keys, credentials, databases and browser artifacts out of source control.

The tests use real HTTP/TCP and actual P-256 signatures for login, activation,
review, approval/rejection, immutable replay, restart, expired ceremonies,
revocation, cross-tenant denial and evidence tampering. Native OS account
isolation, remote deployment and physical authenticators are not qualified.
