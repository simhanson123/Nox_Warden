# Isolated Linux packet smoke

The real Rust compiler now has an executable nftables kernel smoke suite. It runs
in a disposable Docker container network namespace, using loopback only. It never
uses host networking, published ports, privileged containers, host mounts, devices,
or an external network target. The container receives **only CAP_NET_ADMIN**, has
a read-only root filesystem, and is removed in a `finally` cleanup path. The suite
checks that its namespace differs from the caller's before changing any rules.
The fixed Docker-local socket cannot be redirected by inherited Docker endpoint,
context or TLS selector variables. Existing registry configuration is retained.

From the repository root, with the pinned Rust toolchain/Cargo active:

```sh
cargo run -p fw_testlab --locked --offline -- smoke --backend nftables --report reports/linux-lab.json
```

Equivalent standalone command:

```sh
python scripts/linux-lab.py --report reports/linux-lab.json
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

## Actual coverage

The suite starts real TCP and UDP echo listeners on IPv4 and IPv6. Baseline probes
prove the destination listeners work before rules are applied. It then verifies:

- Native nft JSON syntax check, atomic own-table replacement and structural readback.
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

## Native defect found and fixed

The initial compiler multiplied lease seconds by 1000 for the JSON `timeout`.
Actual nft/libnftables 1.0.6 JSON values use **seconds**, even though lower-level
kernel/netlink timer representations use milliseconds. Ordinary packet-expiry
probes initially passed because the independent absolute deadline still blocked
traffic. A stronger check found live timeout tokens after the deadline.

Historical failure and timing reports remain in Git history. The timing
experiment observed a token with `timeout: 3` disappear after 4.0047 monotonic
seconds while `timeout: 3000` remained with 2995 seconds. `timer_units.py`
reproduces that experiment when piped to Python in
a similarly isolated NET_ADMIN-only container with `NOX_TIMER_LAB=1`.
The diagnostic refuses execution without that explicit marker, exactly NET_ADMIN,
and a loopback-only namespace. The compiler now emits seconds,
has a regression unit test, and the smoke checks both partial and full token
expiry. Readback equality alone is not accepted as evidence of timer units.

Runner error classification has standalone regressions: `python -m unittest discover -s native/linux -p test_runner.py -v`. These tests simulate startup failures, transport timeouts, malformed reports and mismatched exit/status pairs; they do not count as native packet probes.
