#!/bin/sh
# ---------------------------------------------------------------------
# SysV 共享内存模拟（src/runtime/sysvshm.c，行动清单 #12）
#
# 三组判据，全部以官方 proroot 为对照：
#   A. 语义对照：probe_shm_spec 在官方与 bxroot 下逐行输出一致
#      （id 数值归一；唯一允许的差异是 IPC_STAT 的 nattch —— 官方恒 0，
#       bxroot 报本进程 attach 数，更接近内核，见 sysvshm.c 头注释）
#   B. 互通：官方写/bxroot 读、bxroot 写/官方读、bxroot 删后官方查不到
#      （共用 /tmp/.proroot-shm 目录与格式；RMID 必须连 key 一起删）
#   C. 并发：16 进程同时 shmget(同 key, CREAT) 只得到 1 个 id；
#      8 线程 × 200 次 attach/detach 计数正确、attach 表无泄漏
# 不在官方 proroot 下 → 无对照，rc=2。
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BX="$ROOT/tools/bxroot-run"
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-shm-XXXXXX")
trap 'rm -rf "$W"' EXIT

grep -q 'libproroot-runtime\.so' /proc/self/maps 2>/dev/null || {
    echo "⏭️  跳过：不在官方 proroot 下，没有对照组"; exit 2; }
[ -f "$ROOT/build/libbxroot-runtime.so" ] || { echo "⏭️  跳过：没有 runtime"; exit 2; }

for p in spec xproc race; do
    ok=0; i=1
    while [ $i -le 10 ]; do
        gcc -O0 -w -pthread -o "$W/$p" "$ROOT/test/shm/probe_shm_$p.c" 2>"$W/cc" && { ok=1; break; }
        grep -q 'internal compiler error' "$W/cc" || break
        i=$((i + 1))
    done
    [ $ok = 1 ] || { echo "❌ 探针 $p 编译失败"; cat "$W/cc"; exit 1; }
done

FAIL=0
bad() { FAIL=$((FAIL + 1)); echo "  ❌ $*"; }
good() { echo "  ✅ $*"; }
norm() { sed -E 's/= [0-9]{5,}/= ID/; s/id=[0-9]+/id=ID/; s/nattch=[0-9]+/nattch=N/' "$1"; }

echo "--- A) 语义对照 ---"
timeout 60 "$W/spec" > "$W/off.txt" 2>&1
timeout 120 "$BX" -- "$W/spec" > "$W/bx.txt" 2>&1
if grep -q 'errno=38' "$W/bx.txt"; then
    bad "bxroot 下仍有 ENOSYS：$(grep 'errno=38' "$W/bx.txt" | head -1)"
elif norm "$W/off.txt" > "$W/o" && norm "$W/bx.txt" > "$W/b" && cmp -s "$W/o" "$W/b"; then
    good "$(wc -l < "$W/b") 行输出与官方一致（id/nattch 归一）"
else
    bad "与官方输出不一致："; diff "$W/o" "$W/b" | head -10
fi

echo "--- B) 与官方互通 ---"
X="$W/xproc"
"$X" rm >/dev/null 2>&1
"$X" put from-off >/dev/null
out=$(timeout 30 "$BX" -- "$X" get); "$X" rm >/dev/null
case "$out" in *"'from-off'"*) good "官方写 → bxroot 读" ;; *) bad "官方写 → bxroot 读：$out" ;; esac
timeout 30 "$BX" -- "$X" put from-bx >/dev/null
out=$("$X" get)
case "$out" in *"'from-bx'"*) good "bxroot 写 → 官方读" ;; *) bad "bxroot 写 → 官方读：$out" ;; esac
timeout 30 "$BX" -- "$X" rm >/dev/null
out=$("$X" get)
case "$out" in *"no key"*) good "bxroot RMID → 官方查不到（key 同步删除）" ;; *) bad "bxroot RMID 后官方仍查到：$out" ;; esac

echo "--- C) 并发 ---"
timeout 120 "$BX" -- "$W/race" > "$W/r.txt" 2>&1
n=$(grep -c '^[0-9][0-9]*$' "$W/r.txt"); u=$(grep '^[0-9][0-9]*$' "$W/r.txt" | sort -u | wc -l)
[ "$n" = 16 ] && [ "$u" = 1 ] && good "16 进程抢同一 key → 1 个 id" || bad "抢 key：$n 个进程得到 $u 个 id"
grep -q 'counter=1600 (expect 1600) bad=0' "$W/r.txt" && good "8 线程 × 200 次 attach/detach 计数正确" \
    || bad "多线程：$(grep counter "$W/r.txt")"
grep -q 'nattch after threads=1 ' "$W/r.txt" && good "attach 表无泄漏（nattch=1）" \
    || bad "attach 表：$(grep nattch "$W/r.txt")"

echo
if [ "$FAIL" -gt 0 ]; then echo "RESULT: FAIL（$FAIL 项）"; exit 1; fi
echo "RESULT: PASS"
