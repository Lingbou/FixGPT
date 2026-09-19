#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

cargo build --release -p fixgpt-cpa-plugin

# CPA 按 <os>/<goarch> 目录找插件：plugins/linux/amd64/fixgpt.so
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) suffix=".so"; directory="linux/amd64" ;;
  Linux/aarch64 | Linux/arm64) suffix=".so"; directory="linux/arm64" ;;
  Darwin/x86_64) suffix=".dylib"; directory="darwin/amd64" ;;
  Darwin/arm64) suffix=".dylib"; directory="darwin/arm64" ;;
  *) echo "unsupported host: $(uname -s)/$(uname -m)" >&2; exit 1 ;;
esac

mkdir -p "plugins/$directory"
cp "target/release/libfixgpt$suffix" "plugins/$directory/fixgpt$suffix"
echo "built plugins/$directory/fixgpt$suffix"