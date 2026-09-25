#!/bin/sh
# ---------------------------------------------------------------------
# --kill-on-exit 监督进程（launcher.c supervise_or_return_in_child，行动清单 #3）
#
# 【缺口】runtime 侧只有 atexit 清理，_exit/exit_group/信号致死全部留孤儿。
# 现由 launcher 留作 subreaper 监督者：guest 退出后清光整棵后代树。
#
# 【判据】
#   A. 六种退出方式（exit/_exit/exit_group/segv/kill9/abort）× guest 的
#      3 个后代（2 子 + 1 个 setsid 脱离的孙进程）：
#        无 --kill-on-exit → 3/3 存活（对照：证明探针真的留下了孤儿）
#        有 --kill-on-exit → 0/3 存活；且退出码与对照组逐一相同
#   B. 信号：SIGTERM 发给 launcher → guest 收到 1 次；SIGINT 发给进程组 →
#      guest 只收到 1 次（监督者不重复转发）；launcher 以 guest 退出码退出
#   C. 监督者被 SIGKILL → guest 主进程随之结束（PDEATHSIG）
#   D. 不带 --kill-on-exit 时 launcher 仍 exec 成 guest（pid 不变）
#
# 探针全部静态链接：本容器里 launcher 的 LD_PRELOAD 注入会被外层
# proroot 拦掉（见 RUN_UPSTREAM_CLI.sh），但监督逻辑全在 launcher 自身，
# 用静态 guest 可以完整测到。杀进程只按探针自己写下的精确 pid。
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-kox-XXXXXX")
PIDS=""
cleanup() {
    for p in $PIDS $(cat "$W"/*.pids 2>/dev/null); do
        [ -d "/proc/$p" ] && grep -q bxroot-kox "/proc/$p/cmdline" 2>/dev/null && kill -9 "$p" 2>/dev/null
    done
    rm -rf "$W"
}
trap cleanup EXIT

build() {   # $1 输出  $2.. gcc 参数；带 ICE 重试
    i=1
    while [ $i -le 10 ]; do
        gcc "$@" 2>"$W/cc" && return 0
        grep -q 'internal compiler error' "$W/cc" || { cat "$W/cc"; return 1; }
        i=$((i + 1))
    done
    return 1
}
build -static -O1 -w -o "$W/L" "$ROOT/src/launcher/launcher.c" || { echo "❌ launcher 编译失败"; exit 1; }
for p in tree signal hang pid; do
    build -static -O0 -w -o "$W/$p" "$ROOT/test/kox/probe_kox_$p.c" || {
        echo "⏭️  跳过：静态探针编不出来（缺 libc 静态库？）"; exit 2; }
done

FAIL=0
bad()  { FAIL=$((FAIL + 1)); echo "  ❌ $*"; }
good() { echo "  ✅ $*"; }

# 存活计数：只数 pidfile 里、且 cmdline 仍是本探针的 pid
alive_of() {
    n=0
    for p in $(cat "$1"); do
        if [ -d "/proc/$p" ] && grep -q bxroot-kox "/proc/$p/cmdline" 2>/dev/null; then
            n=$((n + 1)); kill -9 "$p" 2>/dev/null
        fi
    done
    echo $n
}

echo "--- A) 六种退出方式 ---"
for m in exit _exit exit_group segv kill9 abort; do
    f0="$W/$m.0.pids"; f1="$W/$m.1.pids"
    ( BXROOT_NO_CRASH=1 timeout 20 "$W/L" -r / -w /tmp "$W/tree" "$m" "$f0" >/dev/null 2>&1 ); rc0=$?
    sleep 0.3; a0=$(alive_of "$f0")
    ( BXROOT_NO_CRASH=1 timeout 20 "$W/L" --kill-on-exit -r / -w /tmp "$W/tree" "$m" "$f1" >/dev/null 2>&1 ); rc1=$?
    sleep 0.3; a1=$(alive_of "$f1")
    if [ "$a0" != 3 ]; then
        bad "$m：对照组存活 $a0/3（探针没留下孤儿，本项无判别力）"
    elif [ "$a1" != 0 ]; then
        bad "$m：--kill-on-exit 后仍存活 $a1/3"
    elif [ "$rc0" != "$rc1" ]; then
        bad "$m：退出码变了（对照 $rc0，监督 $rc1）"
    else
        good "$m：对照 3/3 存活 → 监督 0/3，退出码同为 $rc1"
    fi
done

echo "--- B) 信号转发 ---"
cat > "$W/st.sh" <<EOF
trap '' INT
"$W/L" --kill-on-exit -r / -w /tmp "$W/signal" > "$W/sig.out" 2>/dev/null &
L=\$!; sleep 0.5; kill -TERM \$L; kill -INT -\$\$; wait \$L; echo "rc=\$?" >> "$W/sig.out"
EOF
setsid sh "$W/st.sh"
if grep -q 'TERM=1 INT=1' "$W/sig.out" && grep -q '^rc=11$' "$W/sig.out"; then
    good "SIGTERM 转发 1 次、SIGINT 不重复、退出码透传（rc=11）"
else
    bad "信号语义：$(tr '\n' ' ' < "$W/sig.out")"
fi

echo "--- C) 监督者被 SIGKILL ---"
"$W/L" --kill-on-exit -r / -w /tmp "$W/hang" > "$W/hang.out" 2>/dev/null &
L=$!; PIDS="$L"; sleep 0.5; G=$(head -1 "$W/hang.out"); PIDS="$PIDS $G"
kill -9 "$L" 2>/dev/null; wait "$L" 2>/dev/null; sleep 0.3
if [ -n "$G" ] && [ ! -d "/proc/$G" ]; then
    good "guest 随监督者结束（PDEATHSIG）"
else
    bad "监督者被杀后 guest($G) 仍存活"
fi

echo "--- D) 默认路径不变 ---"
out=$(sh -c 'echo $$; exec "$0" -r / -w /tmp "$1"' "$W/L" "$W/pid" 2>/dev/null)
sh_pid=$(echo "$out" | sed -n 1p); g_pid=$(echo "$out" | sed -n 2p | cut -d' ' -f1)
[ -n "$sh_pid" ] && [ "$sh_pid" = "$g_pid" ] && good "无 --kill-on-exit 时 launcher exec 成 guest（pid 相同）" \
    || bad "默认路径 pid 变了（shell=$sh_pid guest=$g_pid）"

echo
[ "$FAIL" -gt 0 ] && { echo "RESULT: FAIL（$FAIL 项）"; exit 1; }
echo "RESULT: PASS"
