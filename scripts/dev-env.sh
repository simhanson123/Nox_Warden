# Source this file from the repository root when using the prepared cloud image.
if [ -d /workspace/toolchains/rust-1.99.1/bin ]; then
  export PATH="/workspace/toolchains/rust-1.99.1/bin:$PATH"
fi
if [ -d /workspace ]; then
  export CARGO_HOME=/workspace/.cargo
fi
