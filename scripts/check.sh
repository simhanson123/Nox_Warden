#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/dev-env.sh
python scripts/validate_spec.py --root docs/specs
python scripts/check_contracts.py
python scripts/check_locales.py
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
npm run check --prefix web
npm test --prefix web -- --run
npm run build --prefix web
