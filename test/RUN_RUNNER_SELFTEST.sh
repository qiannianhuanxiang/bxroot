#!/bin/sh
# Exercise result classification and health failure without touching system paths.
set -u
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd) || exit 1
BASE=$(mktemp -d /root/work/bxroot-runner-selftest-XXXXXX) || exit 1
rc=0
BXROOT_RESULT_BASE="$BASE" sh "$ROOT/test/RUN_ALL.sh" --runner-selftest >"$BASE/output.log" 2>&1 || rc=$?
python3 - "$BASE" "$rc" <<'PY'
import pathlib, sys
base=pathlib.Path(sys.argv[1]); rc=int(sys.argv[2])
files=list(base.glob('quick-*/results.txt'))
assert rc==1, ('expected infra failure',rc)
assert len(files)==1,files
rows=[r.split('|',2) for r in files[0].read_text().splitlines()]
assert [r[0] for r in rows]==['PASS','SKIP','FAIL','FAIL','ERROR'],rows
assert len(list(files[0].parent.glob('step-*.log')))==5
out=(base/'output.log').read_text()
assert 'stop, log=' in out,out
print('RUNNER_SELFTEST_PASS evidence='+str(base))
PY
