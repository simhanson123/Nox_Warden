# WebAuthn challenge extension

These two directories contain the published `webauthn-rs` and
`webauthn-rs-core` **0.5.4** sources, with a small local patch. The original
archive SHA-256 values were verified against the registry checksums in the
pre-patch `Cargo.lock` before extraction. The registry cache was not modified.

[Provenance](webauthn-challenge-provenance.json) records both archive hashes,
the exact upstream Git revision, every published source file hash, the local
modified-file hashes and the license-copy hash.
[The patch](webauthn-challenge.patch) is the complete delta from the two
published archives, excluding the added, unchanged license copies.

The patch adds an optional 32-byte challenge to the core authentication builder
and `Webauthn::start_passkey_authentication_with_challenge`. Ordinary passkey
authentication continues to generate a random challenge using the existing
library CSPRNG. Both entry points use the same required user verification,
backup eligibility policy, counter checks and assertion verifier. The supplied
challenge is copied into both the browser options and private verifier state.
No serialized opaque verifier state is edited.

Applications using the new method must derive the digest from a validated,
domain-separated immutable payload containing a fresh random nonce of at least
32 bytes. They must protect and atomically consume server-side ceremony state.
The method proves a WebAuthn assertion, not consent to a policy or authorization
to modify a host. `fw_webauthn` keeps its ordinary-login and bound-challenge
state types separate and rechecks the freshly derived digest at completion.

One build-only fix conditionally imports the attestation-only types in
`interface.rs`. Path dependencies expose the upstream unused imports under
`#![deny(warnings)]` with default features disabled; registry dependencies had
capped those lints. This fix does not enable new features or relax warnings.

The covered upstream files and modifications remain **MPL-2.0**. Both published
archives omitted the license text, so each directory includes an unchanged
`LICENSE.md` copied from the exact upstream Git revision recorded in provenance.
Existing copyright and source notices are preserved. Distributions containing
these components must retain applicable notices and make the modified covered
source available under MPL-2.0; original application files remain Apache-2.0.
This inventory is not a legal opinion or an upstream endorsement of the patch.

To verify the checked-in files without network access:

```sh
python3 scripts/check_vendor.py
```

To additionally verify both published archives and reconstruct the exact patch
from them, pass the Cargo archive cache (or a directory containing freshly
downloaded archives from the recorded URLs):

```sh
python3 scripts/check_vendor.py --archive-dir "$CARGO_HOME/registry/cache"
```

The patch applies with `patch -p1` from a directory containing the two pristine
published crate directories. The license copies are added separately. Future
dependency upgrades must revalidate provenance, rebase or remove this patch,
and rerun the real-signature tests in `fw_webauthn`; RustSec coverage alone does
not review the local modifications. This change has not been submitted or
accepted upstream.
