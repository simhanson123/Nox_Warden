# Native platform implementation and qualification

The F-2.0 specification requires native Linux, Windows and macOS enforcement.
The current application runs in **observe mode** and provides no host protection.
No supported production platform or signed installer is declared.

| Platform | Implemented locally | Missing release gates | Qualification |
| --- | --- | --- | --- |
| Linux nftables | Transport enrollment and conservative mTLS metadata reports; experimental host TCP/UDP compiler and bounded semantic readback; isolated IPv4/IPv6 packet and rule-tamper tests; durable executor journal | Native apply/readback integration, authenticated policy IPC and independent watchdog, collision registry, baseline/anti-spoof/ICMP/PMTU, physical NIC/fragment/crash/boot/coexistence tests, signed packages | Unverified |
| Windows WFP | Common pure evaluator and authority/journal model | Native service, packet-time WDK callout, persistent/boot-time guards, ACL IPC, signed MSI, Windows packet/crash/reboot fixtures | Unimplemented |
| macOS Network Extension | Common pure evaluator and authority/journal model | Swift host app/system extension, authenticated XPC, packet callback integration, entitlements/signing/notarization, actual-device fail-closed proof | Unimplemented |

The real isolated Linux smoke and its limits are documented in
[native/linux/README.md](../native/linux/README.md). Run
`cargo run -p fw_testlab --locked --offline -- smoke --backend nftables --report reports/linux-lab.json`.
This separately scoped smoke exercises actual nftables and packets; its success
does not complete the full native qualification commands below.

The Linux artifact uses the deliberately separate experimental identifier
`fw.experimental-nft/v1`, profile `host-tcp-udp-lab`, and
`production_qualified: false`. It is not an implementation of all
`common-host-v1` features. The crate never runs `nft` or changes sysctls. It rejects
routed and ICMP policies rather than expanding authority. A future native adapter
must independently verify the deployment kernel and complete family/direction,
conntrack, baseline, ICMP/fragment and capability coverage before production use.
The readback verifier compares the expected owned table, chains, ordered rules,
flow predicates, absolute expiry and token timeout bounds with nft JSON. It
accepts only explicit known nft normalizations; unknown expressions or mismatches
produce no observed semantic hash. It requires the trusted, unaltered compiler
artifact, a trusted observation time and a UTC nft capture. It does not
authenticate the artifact or independently recompute its policy state hash.
A successful comparison propagates the trusted expected hash.

The isolated suite passes 66 checks, including 40 real packet probes and 13
readback checks. It detects actual kernel rule mutation and verifies restored
state without refreshing tokens. One snapshot cannot prove historical token
refreshes, other managers' rules, authority provenance or authenticated dispatch.
This verifier is not yet wired into the application's native apply lifecycle.

`fw_executor` provides one-owner SQLite FULL durability, signed grant acceptance,
high-water replay fencing, conservative UNKNOWN restart, exact readback hash
matching, and signed-confirm versus recovery CAS. Signed issue/dispatch bounds
are persisted and checked again at submission. Confirmation expires at the earlier
of submission + 60 seconds and the signed absolute cap; restart/readback never
extend that stored deadline. Journals without these bounds are rejected rather
than assigned fabricated timestamps. It does not contain a native
adapter, policy rollback projection, authenticated policy-dispatch transport, probe collector, or
independent watchdog process. Confirm signatures currently use the explicit
experimental type `application/vnd.fw.experimental-confirm.v1+json`, because the
supplied public schema does not define a signed confirm envelope. Registry role
resolution remains the caller's trust boundary. This profile must be standardized
before production interoperability is claimed.

Device transport registration is separately implemented for the Linux client.
Its certificate and capability report do not change platform qualification:
every reported enforcement feature is unverified, and the controller remains
observe-only. Remote enrollment, certificate renewal and Windows/macOS device
clients remain unavailable. See the [device guide](device-enrollment.md).

Run qualification preflight from the repository root:

```sh
cargo run -p fw_testlab -- qualify --backend nftables --report reports/linux.json
cargo run -p fw_testlab -- qualify --backend windows_wfp --report reports/windows.json
cargo run -p fw_testlab -- qualify --backend macos_network_extension --report reports/macos.json
```

Each currently exits **2** with **NOT_RUN**, identifies missing prerequisites, and
records zero executed packet tests. These are genuine preflight reports, not a
passing native test suite. Unit tests, compilation and JSON validation do not
substitute for F_07 K/F and F_09 OS01–OS10 evidence.

Generated reports are ignored local outputs; consult the
[verification summary](../reports/README.md) for reproducible commands and CI links.

No active host firewall, Defender Firewall, PF rules, cloud security groups or
host network sysctls are changed by these development commands. The Linux smoke
changes rules and sysctls only inside its disposable network namespace.
Production protection stays unavailable until the complete platform-specific
acceptance gate passes.
