#!/bin/sh
# Focused local regression for proc fd leaf handling in the real resolvers.
# Scope is the Linux source-level runtime only; this does not claim Android
# loader/interposition coverage.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CC="${CC:-gcc}"
OUT="/tmp/bxroot-proc-fd-probe.$$"
ERR="${OUT}.err"
OPT="-O2"
COMPILED=0

# Remove only the exact absolute files created by this invocation.  Resolve
# before rm so an unexpected symlink cannot redirect cleanup elsewhere.
cleanup() {
    rc=$?
    for f in "$OUT" "$ERR"; do
        case "$f" in
            /tmp/bxroot-proc-fd-probe.[0-9]*) ;;
            *)
                echo "   REFUSE cleanup of unexpected target: $f" >&2
                continue
                ;;
        esac
        if [ -e "$f" ] || [ -L "$f" ]; then
            resolved="$(readlink -f -- "$f" 2>/dev/null || true)"
            if [ "$resolved" = "$f" ]; then
                rm -f -- "$f"
            else
                echo "   REFUSE cleanup: $f resolves to $resolved" >&2
            fi
        fi
    done
    exit "$rc"
}
trap cleanup EXIT

echo "▶️  proc fd runtime 回归（源码级 Linux probe）"

# Match the existing D3/realpath source probes: use the complete minimal
# runtime dependency set and retry only compiler ICEs with lower optimization.
for i in 1 2 3 4; do
    if "$CC" $OPT -Wall -Wextra -Wformat=2 \
        -Wno-nonnull-compare -Wno-unused-parameter \
        -Wno-format-truncation \
        -I"$ROOT/src/l2s" -I"$ROOT/src/proc" \
        -DFAKEROOT_PURE_LOGIC -DPX_PURE_LOGIC=0 \
        -Wl,--allow-multiple-definition \
        -o "$OUT" "$ROOT/test/probe_proc_fd.c" \
        "$ROOT/src/l2s/l2s.c" "$ROOT/src/l2s/l2s-runtime.c" \
        "$ROOT/src/runtime/fakeroot.c" "$ROOT/src/runtime/crash.c" \
        "$ROOT/src/runtime/sigsys.c" "$ROOT/src/runtime/syscall_guard.c" \
        "$ROOT/src/runtime/livepatch.c" "$ROOT/src/proc/proc.c" \
        -ldl -lpthread 2>"$ERR"; then
        COMPILED=1
        break
    fi
    if grep -q "internal compiler error" "$ERR" && [ "$OPT" = "-O2" ]; then
        OPT="-O1"
        continue
    fi
    if grep -q "internal compiler error" "$ERR" && [ "$OPT" = "-O1" ]; then
        OPT="-O0"
        continue
    fi
    echo "   ❌ 编译失败（不是 compiler ICE，未执行 probe）："
    head -40 "$ERR"
    exit 1
done

if [ "$COMPILED" -ne 1 ] || [ ! -x "$OUT" ]; then
    echo "   ❌ probe 未产出可执行文件，未执行 runtime 回归"
    exit 1
fi

# Runtime execution is mandatory: compile-only is never reported as PASS.
BXROOT_NO_AUTORUN=1 "$OUT"
rc=$?
if [ "$rc" -eq 0 ]; then
    echo "   RESULT: PASS"
else
    echo "   RESULT: FAIL (probe rc=$rc)"
fi
exit "$rc"
