#!/usr/bin/env bash
set -euo pipefail
# Linux x86_64 cloud toolchain; other hosts use rust-toolchain.toml with rustup.
[[ "$(uname -sm)" == 'Linux x86_64' ]] || { echo 'Use rustup with rust-toolchain.toml on this platform' >&2; exit 2; }
FW_TOOLCHAIN_ROOT="${FW_TOOLCHAIN_ROOT:-/workspace/toolchains/rust-1.99.1}"
if [[ -x "$FW_TOOLCHAIN_ROOT/bin/rustc" ]] && "$FW_TOOLCHAIN_ROOT/bin/rustc" --version | rg -q '^rustc 1\.99\.1 '; then
  exit 0
fi
FW_INSTALL_TMP=$(mktemp -d)
trap 'rm -rf "$FW_INSTALL_TMP"' EXIT
curl --fail --show-error --location https://static.rust-lang.org/dist/2026-10-15/rust-1.99.1-x86_64-unknown-linux-gnu.tar.xz -o "$FW_INSTALL_TMP/rust.tar.xz"
printf '%s  %s\n' 231fcae47ee950621374725b5fc3b5441d2fbda2955ac45dd7dc816d8876cfe7 "$FW_INSTALL_TMP/rust.tar.xz" | sha256sum --check
 tar -xf "$FW_INSTALL_TMP/rust.tar.xz" -C "$FW_INSTALL_TMP"
"$FW_INSTALL_TMP/rust-1.99.1-x86_64-unknown-linux-gnu/install.sh" --prefix="$FW_TOOLCHAIN_ROOT" --without=rust-docs --disable-ldconfig
