# Isolated Linux packet and execution suites

The Rust compiler and signed execution driver have separate nftables kernel
suites. Both run in disposable Docker network namespaces using loopback only.
Neither uses host networking, published ports, privileged containers, host mounts,
devices or an external network target. The container receives **only CAP_NET_ADMIN**, has
a read-only root filesystem, and is removed in a `finally` cleanup path. The suite
checks that its namespace differs from the caller's before changing any rules.
The fixed Docker-local socket cannot be redirected by inherited Docker endpoint,
context or TLS selector variables. Existing registry configuration is retained.

From the repository root, with the pinned Rust toolchain/Cargo active:

```sh
cargo run -p fw_testlab --locked --offline -- smoke --backend nftables --report reports/linux-lab.json
```

Standalone compiler and signed-execution commands:

```sh
python scripts/linux-lab.py --report reports/linux-lab.json
python scripts/signed-linux-lab.py --report reports/signed-linux-lab.json
```

Use `--skip-image-build` with the Python entry point only to reuse an image built
by this workflow. Its exact content ID is always recorded. The default build uses
the official Debian digest in `Dockerfile.lab`, exact nftables/iproute2/Python
package versions, signed apt repository metadata, HTTPS verification, and the
managed combined CA bundle mounted as a BuildKit secret. The CA mount is mode 0444
because apt validates downloads as its unprivileged `_apt` user. No session CA is
copied into an image layer. Debian can retire security package versions; a missing
pin must fail installation and be deliberately updated, never silently substituted.

The report includes image/base digests, all resolved Debian package versions,
source and executable hashes, current commit/dirty state, actual nft readbacks,
Unix observation times, kernel version, conntrack settings, packet outcomes and
container cleanup. Startup failures return 2/NOT_RUN; failed packet/assertion or
cleanup checks return nonzero. Only completed smoke assertions return 0/PASS.
This does **not** make `fw_testlab qualify` pass the full platform gate. Generated
reports are ignored local outputs. CI keeps its selected smoke report as an
artifact for seven days; see the [verification summary](../../reports/README.md)
for scope and CI links.

## Compiler packet coverage

The suite starts real TCP and UDP echo listeners on IPv4 and IPv6. Baseline probes
prove the destination listeners work before rules are applied. It then verifies:

- Native nft JSON syntax check, atomic own-table replacement and semantic readback.
- Actual kernel rule tampering and restoration, unknown expressions, scope changes
  and altered timeout/cutoff bounds.
- TCP/UDP allow and default deny on IPv4/IPv6, with actual returned random payloads.
- Existing/new TCP blocked by a deny whose review deadline has already passed.
- UDP unaffected by that TCP-only deny.
- Existing TCP/UDP flows continue while a second overlapping allow remains valid.
- The first lease's kernel tokens expire while the second lease's tokens remain.
- Existing and new TCP/UDP flows stop after all authorizing leases expire.
- Kernel token disappearance without refresh, independent of the absolute guard.
- An unrelated nft table/counter survives each update.
- Removing only the managed table restores the baseline listeners' reachability.

The container's namespaced `nf_conntrack_tcp_loose` is explicitly 0. Checksum
verification and liberal-mode values are observed and reported. The smoke is a
loopback topology on the actual reported kernel, not physical NIC, routed,
fragment/ICMP/PMTU, installer, crash/reboot or full `common-host-v1` qualification.
Those release gates remain incomplete, and `production_supported` stays false.

## Signed execution coverage

The additional `signed-linux-lab.py` suite exercises the real
`fw_linux_executor` process. It resolves full `StateIr` artifacts and independently
pinned signature keys, persists complete candidate/recovery material, applies an
atomic native batch, and uses actual readback and collected packet probes before
signed confirmation. It also exercises replay without timeout refresh and
restrictive timeout/crash recovery with generation and authority bounds.

This suite creates ephemeral signing keys and clearly marked synthetic plan and
approval fixtures. It does not claim that a human approved the change or that a
registered product target has qualified capabilities. Its default-deny baseline
has no network management path; management-channel survival is not tested.
The separate recovery child can acquire the writer fence after normal command
exit or a crash, but can be blocked by a permanently hung lock owner. It is not a
qualified production watchdog. The [execution guide](../../docs/signed-linux-execution.md)
describes the exact trust and recovery boundaries.

## Timer units and runner regressions

The compiler emits JSON timeout values in seconds for the pinned
nft/libnftables 1.0.6, while lower-level kernel/netlink timer representations use
milliseconds. Regression checks inspect token disappearance as well as packet
expiry; a working absolute-time guard alone would hide an excessively long token.
The optional `timer_units.py` diagnostic requires its explicit lab marker,
exactly NET_ADMIN and a loopback-only namespace.

Runner error classification has standalone regressions:

```sh
python -m unittest discover -s native/linux -p 'test_*runner.py' -v
```

These tests simulate startup failures, transport timeouts, malformed reports,
exit/status mismatches and cleanup failure. They do not count as native packet
probes. Consult the [verification summary](../../reports/README.md) for confirmed
suite counts and CI results.
