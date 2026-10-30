# PBOM integrity core

`verify_graph` verifies the F-2.0 PBOM node content hashes and byte counts,
allowlisted store identifiers, authenticated tenant and classification boundaries,
DAG shape, stable node/edge order, and the exact odd-leaf-promotion Merkle tree.
The verifier supplies the required lifecycle stage set independently; an empty
stage set cannot establish a `complete` manifest. Missing evidence must be
explicitly declared and prevents a complete result.

`verify_signed_manifest` additionally checks Ed25519 DSSE payload bytes, domain,
key identity, tenant, time window, and revocation status. The calling trusted
registry must authorize the audit key. Signature validity establishes signer
provenance and byte integrity; it does not prove device observations or successful
firewall application. `sign_manifest` is an audit-only cryptographic primitive;
it grants no approval or execution authority. Callers must verify the graph and
select the correct signing key before signing.

`redact` creates a derivative retaining the original hash, changed JSON pointers,
and reasons. It explicitly marks original-signature verification unavailable.
`csv_field` escapes cells and neutralizes spreadsheet formula prefixes.

This crate does not implement protected evidence storage, archive streaming,
retention/backup/restore, independent checkpoint publication, or REST integration.
Evidence record metadata must come from a trusted store, never client assertions.
