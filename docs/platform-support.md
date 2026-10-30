# Native platform implementation and qualification

The F-2.0 specification requires native Linux, Windows and macOS enforcement.
The current application runs in **observe mode** and provides no host protection.
No supported production platform or signed installer is declared.

| Platform | Implemented locally | Missing release gates | Qualification |
| --- | --- | --- | --- |
| Linux nftables | Experimental deterministic host TCP/UDP JSON compiler; durable executor journal | Authenticated independent IPC and watchdog, native apply/readback, collision registry, baseline/anti-spoof/ICMP/PMTU, isolated packet/crash/boot/coexistence tests, signed packages | Unverified |
| Windows WFP | Common pure evaluator and authority/journal model | Native service, packet-time WDK callout, persistent/boot-time guards, ACL IPC, signed MSI, Windows packet/crash/reboot fixtures | Unimplemented |
| macOS Network Extension | Common pure evaluator and authority/journal model | Swift host app/system extension, authenticated XPC, packet callback integration, entitlements/signing/notarization, actual-device fail-closed proof | Unimplemented |

The Linux artifact uses the deliberately separate experimental identifier
`fw.experimental-nft/v1`, profile `host-tcp-udp-lab`, and
`production_qualified: false`. It is not an implementation of all
`common-host-v1` features. The crate never runs `nft` or changes sysctls. It rejects
routed and ICMP policies rather than expanding authority. A future native adapter
must independently verify actual nft JSON syntax and timer units, family/direction
handling, conntrack assumptions and native capability fingerprints before use.

`fw_executor` provides one-owner SQLite FULL durability, signed grant acceptance,
high-water replay fencing, conservative UNKNOWN restart, exact readback hash
matching, and signed-confirm versus recovery CAS. Signed issue/dispatch bounds
are persisted and checked again at submission. Confirmation expires at the earlier
of submission + 60 seconds and the signed absolute cap; restart/readback never
extend that stored deadline. Journals without these bounds are rejected rather
than assigned fabricated timestamps. It does not contain a native
adapter, policy rollback projection, authenticated transport, probe collector, or
independent watchdog process. Confirm signatures currently use the explicit
experimental type `application/vnd.fw.experimental-confirm.v1+json`, because the
supplied public schema does not define a signed confirm envelope. Registry role
resolution remains the caller's trust boundary. This profile must be standardized
before production interoperability is claimed.

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

No active host firewall, Defender Firewall, PF rules, cloud security groups or
network sysctls are changed by development commands. Production protection stays
unavailable until the complete platform-specific acceptance gate passes.
