#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
bash scripts/cargo.sh build --manifest-path check-runner/Cargo.toml --release
if [ -x .tools/cargo/bin/rustc ]; then
  runner_target=$(CARGO_HOME="$PWD/.tools/cargo" RUSTUP_HOME="$PWD/.tools/rustup" .tools/cargo/bin/rustc --print host-tuple)
else
  runner_target=$(rustc --print host-tuple)
fi
mkdir -p src-tauri/binaries src-tauri/target/debug src-tauri/target/release
cp check-runner/target/release/cyberbot-check-runner "src-tauri/binaries/cyberbot-check-runner-$runner_target"
cp check-runner/target/release/cyberbot-check-runner src-tauri/target/debug/cyberbot-check-runner
cp check-runner/target/release/cyberbot-check-runner src-tauri/target/release/cyberbot-check-runner
