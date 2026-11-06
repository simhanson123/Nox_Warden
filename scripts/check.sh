#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/dev-env.sh
python scripts/validate_spec.py --root docs/specs
python scripts/check_contracts.py
python scripts/check_vendor.py
python scripts/check_locales.py
python -m unittest discover -s native/linux -p 'test_*runner.py'
python -m unittest discover -s scripts -p 'test_catalogue_smoke_diagnostics.py'
python -m unittest discover -s scripts -p 'test_authority_smoke_diagnostics.py'
python -m unittest discover -s scripts -p 'test_native_evidence_diagnostics.py'
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
# The successful cancellation process fixture exists only in cfg(test), while
# the administrator executable retains the normal closed production resolver.
cargo build --locked -p fw_authority --bin fw_authority_admin
NOX_TEST_AUTHORITY_ADMIN="$PWD/target/debug/fw_authority_admin" \
  cargo test --locked -p fw_authority --lib \
  cancellation_cli_preserves_commits_retries_tenants_and_issued_unknown -- --ignored
# Verify the reduced authority profile without approval ceremony dependencies.
cargo test -p fw_authority --no-default-features --locked
npm run check --prefix web
npm test --prefix web -- --run
npm run build --prefix web
npm run build:authority --prefix web
