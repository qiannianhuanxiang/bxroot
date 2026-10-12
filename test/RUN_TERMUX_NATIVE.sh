#!/bin/sh
# Run manually from native Termux; do not run inside proot-distro.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
[ "$(uname -m)" = aarch64 ] || { echo 'REFUSED: AArch64 required'; exit 1; }
[ -n "${PREFIX:-}" ] && [ -x "$PREFIX/bin/clang" ] || { echo 'REFUSED: native Termux clang required'; exit 1; }
python - <<'PY'
import pathlib,re,os,sys
pid=os.getpid();seen=set();chain=[];me=None
while pid>0 and pid not in seen:
 seen.add(pid);root=pathlib.Path('/proc')/str(pid)
 try:
  s=(root/'status').read_text();cmd=(root/'cmdline').read_bytes()
 except OSError as e:
  # /proc is mounted hidepid=invisible: other UIDs' processes (zygote, init)
  # do not exist for us. A PRoot/ptrace parent is the SAME uid and stays
  # visible, so an invisible ancestor is the Android UID boundary only when
  # we have already walked at least one readable same-uid ancestor.
  if chain and getattr(e,'errno',None) in (2,13):
   print('ANCESTRY_BOUNDARY pid=%d (%s); readable same-uid chain=%s'%(pid,e.strerror,chain),file=sys.stderr);break
  raise SystemExit('REFUSED: process ancestry unreadable '+str(e))
 uid=int(re.search(r'^Uid:\s*(\d+)',s,re.M).group(1))
 if me is None:me=uid
 if uid!=me:raise SystemExit('REFUSED: ancestor pid %d has different uid %d'%(pid,uid))
 tracer=int(re.search(r'^TracerPid:\s*(\d+)',s,re.M).group(1))
 if tracer or b'proot' in cmd:raise SystemExit('REFUSED: traced/PRoot process')
 chain.append(pid)
 parent=int(re.search(r'^PPid:\s*(\d+)',s,re.M).group(1))
 if parent==1:break
 pid=parent
PY
export CC=clang
W=$(mktemp -d "$ROOT/termux-results-XXXXXX")
FAIL=0
printf 'uid=%s\nprefix=%s\n' "$(id -u)" "$PREFIX" >"$W/environment.txt"
run() {
 name=$1;marker=$2;shift 2
 rc=0;timeout --kill-after=5 120 "$@" >"$W/$name.log" 2>&1 || rc=$?
 cat "$W/$name.log"
 printf '%s|rc=%s|log=%s\n' "$name" "$rc" "$W/$name.log" >>"$W/results.txt"
 if [ "$rc" -ne 0 ] || ! grep -Fxq "$marker" "$W/$name.log"; then
  echo "FAIL: $name rc=$rc (rc2 is unverified, never PASS)";FAIL=$((FAIL+1))
 fi
}
run copyout 'RUNTIME_IPC_STAT_PASS' sh test/RUN_RUNTIME_STAT.sh
run claim 'RESULT: SHM claim PASS' sh test/RUN_SHM_CLAIM.sh
run id_aba 'SHM_ID_ABA_PASS' sh test/RUN_SHM_ID_ABA.sh
run fork_gate 'SHM_FORK_GATE_PASS' sh test/RUN_SHM_FORK_GATE.sh
run static_reset 'STATIC_SHM_FD_PASS' sh test/RUN_STATIC_SHM_FD.sh
run static_trap 'RESULT: static SHM syscall PASS' sh test/RUN_STATIC_SHM_SYSCALL.sh
run l2s_mock 'RESULT: L2S mock closure PASS' sh test/RUN_L2S_MOCK.sh
run l2s_native 'RESULT: PASS' sh -c 'clang -std=c11 -O1 -Wall -Wextra -Werror -D_GNU_SOURCE -Isrc/l2s -o "$1/l2s-native" test/test_l2s_rt.c src/l2s/l2s.c src/l2s/l2s-runtime.c && "$1/l2s-native"' sh "$W"
run integration 'RESULT: PASS' sh -c 'clang -std=c11 -O1 -Wall -Wextra -Werror -D_GNU_SOURCE -DFAKEROOT_PURE_LOGIC -Itest -Isrc/l2s -Isrc/runtime -o "$1/integration" test/test_integration.c src/l2s/l2s-runtime.c src/l2s/l2s.c src/runtime/fakeroot.c && "$1/integration"' sh "$W"
printf 'TERMUX_NATIVE_RESULT failures=%s directory=%s\n' "$FAIL" "$W"
[ "$FAIL" -eq 0 ]
