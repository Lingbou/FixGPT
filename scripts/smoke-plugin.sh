#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

cargo build -p fixgpt-cpa-plugin
cc -O2 -Wall -Wextra -o /tmp/fixgpt-plugin-smoke scripts/plugin-smoke.c -ldl
/tmp/fixgpt-plugin-smoke target/debug/libfixgpt.so