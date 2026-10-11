#!/bin/sh
# Independent opt-in probe; does not alter runtime or seccomp policy.
# Default: raw AArch64 syscall 271. --ipc-stat: exercise current shmctl runtime.
# Exit 0=all cases pass, 1=regression/build error, 2=target/capability unavailable.
# To run inside bxroot, compile-only here then invoke the binary in that session.
set -u
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd) || exit 1
MODE=${1:-capability}
case "$MODE" in capability|--ipc-stat|--compile-only|--safe-copyout|--gate-disabled) ;; *) echo "usage: $0 [capability|--ipc-stat|--compile-only|--safe-copyout|--gate-disabled]" >&2; exit 1 ;; esac
command -v "${CC:-gcc}" >/dev/null 2>&1 || { echo 'SKIP: compiler unavailable'; exit 2; }
command -v timeout >/dev/null 2>&1 || { echo 'SKIP: timeout unavailable'; exit 2; }
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-copyout-XXXXXX") || exit 1
cleanup() {
    # Delete only the literal, verified mktemp directory owned by this invocation.
    case "$W" in /*/bxroot-copyout-*) [ -d "$W" ] && rm -rf -- "$W" ;; esac
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for GATE in 0 1; do
    "${CC:-gcc}" -std=c11 -O1 -Wall -Wextra -Werror \
        -DBXROOT_SHM_COPYOUT_VERIFIED="$GATE" \
        -o "$W/unit-$GATE" "$ROOT/test/shm/test_copyout_gate.c" || exit 1
    "$W/unit-$GATE" || exit 1
done
VERIFIED=0
[ "$MODE" = --safe-copyout ] && VERIFIED=1
"${CC:-gcc}" -std=c11 -O1 -Wall -Wextra -Werror \
    -DBXROOT_SHM_COPYOUT_VERIFIED="$VERIFIED" \
    -o "$W/probe" "$ROOT/test/shm/probe_copyout_fault.c" || exit 1
if [ "$MODE" = --compile-only ]; then
    echo 'RESULT: compile PASS'; exit 0
fi
rc=0
if [ "$MODE" = --ipc-stat ]; then
    timeout --kill-after=5 60 "$W/probe" --ipc-stat >"$W/output" 2>&1 || rc=$?
elif [ "$MODE" = --safe-copyout ] || [ "$MODE" = --gate-disabled ]; then
    timeout --kill-after=5 60 "$W/probe" --safe-copyout >"$W/output" 2>&1 || rc=$?
else
    timeout --kill-after=5 60 "$W/probe" >"$W/output" 2>&1 || rc=$?
fi
cat "$W/output"
case "$rc" in
0) grep -qx 'FAULT_PROBE_DONE' "$W/output" || { echo 'FAIL: missing completion marker'; exit 1; } ;;
2) echo 'RESULT: capability/architecture unavailable (see individual cases)'; exit 2 ;;
*) echo "FAIL: probe rc=$rc (timeout, signal or regression)"; exit 1 ;;
esac
