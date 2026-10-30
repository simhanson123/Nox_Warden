# Release packaging gate

No production installer exists. Development builds run observe-only and must not
be packaged as a host-protection release. Release packaging requires the native
platform suite, dependency notices/SBOM, artifact hashes and provenance, signature
verification, permission separation, backup/recovery, interrupted upgrades,
coexistence, and retain-data uninstall qualification described in F_08/F_09.

Future packages must install controller and privileged executor as distinct OS
accounts/processes, retain existing firewall managers, validate management
recovery, and begin observe-only. No script in this directory changes host rules.
