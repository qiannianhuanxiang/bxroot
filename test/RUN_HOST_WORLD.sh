#!/bin/sh
# Focused host-world regression. Only builds and runs the host-world unit.
# No device, network, credentials, or Android program is used.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-host-world.XXXXXX")
trap 'rm -rf "$W"' EXIT HUP INT TERM

if [ -n "${HOST_WORLD_CC:-}" ]; then
    CC=$HOST_WORLD_CC
elif command -v gcc >/dev/null 2>&1; then
    CC=gcc
elif command -v cc >/dev/null 2>&1; then
    CC=cc
else
    echo "❌ host-world: no C compiler" >&2
    exit 1
fi

# Compile host-world.c itself into the executable. The classifier tests use an
# in-memory pread callback; build-env tests exercise the real backend policy.
"$CC" -std=c11 -O2 -Wall -Wextra -Werror -D_GNU_SOURCE \
    -I"$ROOT/src/host" \
    "$ROOT/test/host/test_host_world.c" \
    "$ROOT/src/host/host-world.c" \
    -o "$W/test_host_world"

# This is intentionally an actual execution, not just a compile/link check.
"$W/test_host_world"

case "$(uname -m)" in
    aarch64|arm64)
        echo "host-world: aarch64; no Android target launched, classifier/env ran"
        ;;
    *)
        echo "host-world: non-aarch64; rawexec behavior skipped, classifier/env ran"
        ;;
esac
