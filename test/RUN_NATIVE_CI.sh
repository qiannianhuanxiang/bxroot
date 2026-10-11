#!/bin/sh
# Compile locally; execution requires a native, untraced external AArch64 runner.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
MODE=${1:-run}
case "$MODE" in run|--compile-only) ;; *) echo 'usage: RUN_NATIVE_CI.sh [run|--compile-only]' >&2; exit 1;; esac
[ "${CI:-}" = true ] || { echo 'REFUSED: CI=true required'; exit 2; }
[ "$(uname -m)" = aarch64 ] || { echo 'REFUSED: native AArch64 required'; exit 2; }
if [ "$MODE" = run ]; then
    python3 - <<'PY'
import os,pathlib,re,sys
for key in ('DSH_HOME','DSH_PERMISSION_MODE','DSHA_WORKSPACE_DOCUMENTS','PROROOT_ROOTFS','BXROOT_ROOTFS'):
    if key in os.environ:sys.exit('REFUSED: device/guest marker '+key)
if pathlib.Path('/root/.dsh/.bridge_headers').exists() or pathlib.Path('/apex').exists():
    sys.exit('REFUSED: DSHA/Android filesystem detected')
pid=os.getpid(); seen=set()
while pid>0 and pid not in seen:
    seen.add(pid); base=pathlib.Path('/proc')/str(pid)
    try:
        status=(base/'status').read_text(); cmd=(base/'cmdline').read_bytes()
        parent=int(re.search(r'^PPid:\s*(\d+)',status,re.M).group(1))
        tracer=int(re.search(r'^TracerPid:\s*(\d+)',status,re.M).group(1))
    except (OSError,ValueError,AttributeError) as exc:
        sys.exit('REFUSED: cannot validate process ancestry: '+str(exc))
    if tracer or re.search(rb'libproot|libproroot|proroot|deepseek-ai/dsh|/system/bin|/data/app/',cmd):
        sys.exit('REFUSED: traced/PRoot/Android ancestor')
    pid=parent
PY
fi
BASE=${BXROOT_NATIVE_CI_OUTPUT:-${TMPDIR:-/tmp}/bxroot-native-ci-results}
mkdir -p "$BASE"
W=$(mktemp -d "$BASE/run-XXXXXX") || exit 1
# Keep logs on both failure and success. CI uploads only logs/results, not binaries.
printf 'mode=%s\narch=%s\nsource_commit=%s\n' "$MODE" "$(uname -m)" "$(git rev-parse HEAD)" >"$W/metadata.txt"
FAILED=0
run() {
    name=$1; marker=$2; shift 2
    rc=0
    timeout --kill-after=5 600 "$@" >"$W/$name.log" 2>&1 || rc=$?
    cat "$W/$name.log"
    printf '%s|rc=%s|log=%s\n' "$name" "$rc" "$W/$name.log" >>"$W/results.txt"
    if [ "$rc" -ne 0 ]; then
        echo "FAIL: $name rc=$rc evidence=$W"; FAILED=$((FAILED+1)); return 0
    fi
    if ! grep -Fxq "$marker" "$W/$name.log"; then
        echo "FAIL: $name missing exact marker $marker evidence=$W"; FAILED=$((FAILED+1))
    fi
}
if [ "$MODE" = --compile-only ]; then
    gcc -std=c11 -O1 -Wall -Wextra -Werror -D_GNU_SOURCE -Isrc/l2s \
        -fsyntax-only test/test_l2s_rt.c src/l2s/l2s.c src/l2s/l2s-runtime.c
    gcc -std=c11 -O1 -Wall -Wextra -Werror -D_GNU_SOURCE -DFAKEROOT_PURE_LOGIC \
        -Itest -Isrc/l2s -Isrc/runtime -fsyntax-only \
        test/test_integration.c src/l2s/l2s-runtime.c src/l2s/l2s.c src/runtime/fakeroot.c
    gcc -std=c11 -O1 -Wall -Wextra -Werror -pthread -o "$W/runtime-stat" test/shm/probe_runtime_stat.c
    gcc -std=c11 -O1 -Wall -Wextra -Werror -DPX_PURE_LOGIC=0 -Isrc/proc -o "$W/native-fork" test/host/probe_native_fork_wait.c
    echo NATIVE_CI_COMPILE_PASS
    exit 0
fi
run l2s_mock 'RESULT: L2S mock closure PASS' sh test/RUN_L2S_MOCK.sh
run l2s_runtime 'RESULT: PASS' sh -c 'gcc -std=c11 -O1 -Wall -Wextra -Werror -D_GNU_SOURCE -Isrc/l2s -o "$1" test/test_l2s_rt.c src/l2s/l2s.c src/l2s/l2s-runtime.c && "$1"' sh "$W/l2s"
run integration 'RESULT: PASS' sh test/RUN_INTEGRATION.sh
run shm_backend 'RUNTIME_IPC_STAT_PASS' sh test/RUN_RUNTIME_STAT.sh
run shm_claim 'RESULT: SHM claim PASS' sh test/RUN_SHM_CLAIM.sh
run shm_id_aba 'SHM_ID_ABA_PASS' sh test/RUN_SHM_ID_ABA.sh
run shm_fork_gate 'SHM_FORK_GATE_PASS' sh test/RUN_SHM_FORK_GATE.sh
run static_fd 'STATIC_SHM_FD_PASS' sh test/RUN_STATIC_SHM_FD.sh
run static_syscall 'RESULT: static SHM syscall PASS' sh test/RUN_STATIC_SHM_SYSCALL.sh
run runtime_build 'NATIVE_RUNTIME_BUILD_PASS' sh -c 'BXROOT_BUILD_PROFILE=verified BXROOT_BUILD_SHM_COPYOUT_VERIFIED=1 BXROOT_BUILD_SHM_CLAIM_VERIFIED=1 sh BUILD_RUNTIME.sh -O1 && echo NATIVE_RUNTIME_BUILD_PASS'
run native_fork_compile 'NATIVE_FORK_COMPILE_PASS' sh -c 'gcc -std=c11 -O1 -Wall -Wextra -Werror -DPX_PURE_LOGIC=0 -Isrc/proc -o "$1" test/host/probe_native_fork_wait.c && echo NATIVE_FORK_COMPILE_PASS' sh "$W/native-fork"
# Native Linux resolves LD_PRELOAD normally; no Android bridge is required here.
run native_fork_wait 'NATIVE_CHAIN_FORK_WAIT_PASS' env BXROOT_ROOTFS=/ \
    LD_PRELOAD="$ROOT/build/verified/libbxroot-runtime.so" "$W/native-fork"
if [ "$FAILED" -ne 0 ]; then
    printf 'NATIVE_CI_FAIL failures=%s evidence=%s\n' "$FAILED" "$W"
    exit 1
fi
printf 'NATIVE_CI_PASS evidence=%s\n' "$W"
