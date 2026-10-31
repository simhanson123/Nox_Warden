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
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
# Native executors consume grant verification without approval ceremony code.
cargo test -p fw_authority --no-default-features --locked
npm run check --prefix web
npm test --prefix web -- --run
npm run build --prefix web
npm run build:authority --prefix web
