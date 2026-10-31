# Native platform implementation and qualification

The specification requires native Linux, Windows and macOS enforcement.
The management application remains **observe-only** and provides no host
protection. No supported production platform or signed installer is declared.

| Platform | Implemented locally | Missing release gates | Qualification |
| --- | --- | --- | --- |
| Linux nftables | Transport enrollment and conservative mTLS metadata; experimental host TCP/UDP compiler, immutable full-state portable artifacts, bounded semantic readback, guarded signed apply/probe/confirm and restrictive timeout/crash recovery in a disposable lab | Real approval/bootstrap and authenticated production dispatch; qualified independent watchdog; baseline/anti-spoof/ICMP/PMTU; physical NIC, full clock/crash/reboot/coexistence and installer acceptance | Unverified |
| Windows WFP | Common pure evaluator and authority/journal model | Native service, packet-time WDK callout, persistent/boot guards, ACL IPC, signed MSI and native packet/crash/reboot fixtures | Unimplemented |
| macOS Network Extension | Common pure evaluator and authority/journal model | Swift host app/system extension, authenticated XPC, packet callbacks, entitlements/signing/notarization and actual-device failure tests | Unimplemented |

## Isolated Linux profiles

The [Linux suites](../native/linux/README.md) run real nftables and packet probes
inside disposable loopback network namespaces. The original compiler suite uses
`fw.experimental-nft/v1`, profile `host-tcp-udp-lab`, and
`production_qualified: false`. The separate portable profile binds a full
normalized `StateIr` to resolved lab references and absolute policy deadlines;
relative token timeouts live in an installation manifest. Neither profile is a
complete implementation of `common-host-v1`.

The pure compiler never executes an OS command. `fw_linux_executor` supplies a
separate guarded native driver for the signed suite, with a fixed nft executable,
bounded I/O and one atomic owned-table update. It refuses the outer namespace or
non-loopback topology. Existing rules from unrelated tables are not flushed.
The controller and registered device client cannot invoke this driver.

The readback verifier checks chains, ordered rules, scope, absolute expiry and
token lifetime bounds. Unknown expressions or mismatches yield no semantic state
hash. Its portable wrapper rebuilds the artifact from the complete normalized
state and resolved references, validates the persisted installation, and checks
boot/monotonic context. A single snapshot still cannot prove historical absence
of shorter token refreshes or other managers' activity.

The executor journal persists exact signed and native recovery material before
submission, consumes the generation durably, and keeps uncertain writes UNKNOWN.
Confirmation needs matching actual readback, the locally collected packet report,
a separate signature and a deadline/generation CAS. The confirmation payload type
remains the explicit experimental
`application/vnd.fw.experimental-confirm.v1+json`; production interoperability is
not claimed. Retried and same-boot operations observe the saved installation
without reissuing its timeout tokens.

A separate recovery child is armed before submission. After normal command exit
or a crash, it can take the same writer lock and apply only the exact signed,
restrictive recovery artifact while its authority remains valid at submission. This projection removes business allows,
preserves deny restrictions and does not reduce the generation high-water mark.
There is no unsigned fallback after recovery authority expires. A hung or paused
owner can block the process-lifetime journal lock, so this is not the independent
watchdog required for production qualification.

The [signed execution guide](signed-linux-execution.md) explains the fixture
trust registry, synthetic approvals and remaining limitations. Local-owner
[WebAuthn login](passkey-login.md) is implemented. Plan-bound human approval,
independent signer/quota jobs, approved authority bootstrap, workload identity and
production capability admission remain incomplete. Lab fixtures cannot promote
an `unverified` enrollment to supported enforcement.

## Device enrollment and release preflight

[Device transport registration](device-enrollment.md) remains separate. Its
certificate and authenticated metadata report do not alter OS qualification or
enable native dispatch. Remote enrollment, certificate renewal and Windows/macOS
device clients remain unavailable.

Run the full-platform qualification preflight from the repository root:

```sh
cargo run -p fw_testlab -- qualify --backend nftables --report reports/linux.json
cargo run -p fw_testlab -- qualify --backend windows_wfp --report reports/windows.json
cargo run -p fw_testlab -- qualify --backend macos_network_extension --report reports/macos.json
```

These commands return **2 / NOT_RUN**, identify missing prerequisites and record
zero executed qualification packet tests. Passing the separate Linux suites does
not make this full-platform gate pass. Unit, schema, HTTP and browser checks do
not replace required native acceptance evidence.

Generated reports are ignored local outputs. The [verification summary](../reports/README.md)
links reproducible commands and CI results. No active host firewall, Windows
Defender Firewall, macOS PF rules, cloud security group or host network sysctl is
changed by these development commands. Rule and sysctl changes occur only inside
the disposable Linux namespace.
