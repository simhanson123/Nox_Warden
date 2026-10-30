# Windows packet enforcement gate

The WDK callout driver is not implemented or signed. The Rust evaluator is not a
substitute for WFP packet-time enforcement. Before adding a native implementation,
follow F_09 sections 5 and 7: immutable decision image publication, exact metadata
coverage, persistent/boot guards, no `PERMIT_IF_CALLOUT_UNREGISTERED`, bounded IOCTL
parsing, Service SID/ACL isolation, coexistence and actual signed-VM tests.

No unsigned driver download or Secure Boot change is provided as an installation
shortcut. Windows remains unverified and enforcement must be rejected.
