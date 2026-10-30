# Isolated Linux execution driver

This executable verifies signed fixture grants and connects the durable executor
journal to actual nftables apply/readback, packet probes, confirmation and
restrictive recovery. It refuses execution outside the guarded, loopback-only
disposable lab. It is not a host installer or the controller's production executor.

Use the supported runner from the repository root:

```sh
source scripts/dev-env.sh
python scripts/signed-linux-lab.py --report reports/signed-linux-lab.json
```

The runner supplies a private fixture bundle and a separately pinned public-key
registry. Signing keys stay with the test-only fixture generator; the driver has
no signing or human-approval command. `LabApproval` is explicitly synthetic and
cannot be treated as a WebAuthn proof.

The internal fixture CLI consists of `init` and `apply` with `--state-dir`,
`--bundle` and `--trust`; `observe`, `recover` and `status` use `--state-dir`,
`--operation-id` and `--trust`. `probe` also takes `--output`; `confirm` takes
`--confirmation`. All state and evidence paths are private lab files. The runner
owns their lifecycle; do not copy fixture keys or bundles into production state.

The complete [signed execution guide](../../docs/signed-linux-execution.md)
describes immutable artifacts, runtime expiry binding, journal/CAS behavior,
actual probe evidence and the limits of the separate recovery process. Unknown
state, expired recovery authority and unsupported bootstrap/clock cases do not
acquire new write authority. The product remains observe-only.
