# Deterministic policy composition and semantic proof

`compose_access_patch` adds only new lease policies to the entire baseline.
`compose_policy_change` adds deny, replaces a revision with exact old hash binding,
or removes an exact revision. It preserves unrelated policies and associations,
rejects repeated/tombstoned IDs, and prohibits allow scope/expiry expansion or
owner/action/lease replacement through the general change route.

`semantic_diff` computes the allowed business-traffic set before and after a
change with the pure domain evaluator. It partitions each family/direction/
protocol into the complete Cartesian product of address intervals, port ranges,
interface aliases, and absolute lifetime intervals. Every predicate is constant
inside a cell, so a representative at the lower boundary is sufficient; this is
an exhaustive proof, not packet sampling. Interfaces absent from every policy
and traffic outside every supported protocol partition default-drop on both
sides. IPv4-mapped IPv6 addresses are outside the accepted domain. Deny review
dates do not terminate deny policies.

A completed proof reports equivalent/restricting/expanding/mixed, evaluated-cell
count, and deterministic hashes of added/removed region-cell lists. Default proof
budget is 4096 cells and 128 combined policy revisions. ICMP, changed context or
management-baseline hashes, and a resource-bound excess return incomplete UNKNOWN.
No partial result can pass `ensure_dispatchable`.

This proof concerns the normalized business-traffic predicate only. The protected
management baseline must remain unchanged; independent baseline/scope gates must
verify management constraints. Identity provenance, quota, approvals, kernel
installation, original-flow/conntrack association, packet-time expiry, capability
and readback remain separate mandatory checks. This crate alone never authorizes
or performs a firewall write. ICMP proof, full plan wire generation and persisted
proof-evidence integration remain outstanding.
