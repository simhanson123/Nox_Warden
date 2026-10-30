# macOS native enforcement gate

The Swift host app and Network Extension system extension are not implemented.
The common Rust evaluator is not a packet provider. Implementation requires an
approved Network Extension entitlement, authenticated XPC, signed distribution,
notarization and actual-device crash/boot/suspend/upgrade evidence.

F_09 section 6 explicitly requires proof of strict failure behavior. PF is not a
production fallback. Until that evidence exists the strict profile is unavailable.
