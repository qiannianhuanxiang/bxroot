#!/bin/sh
# ---------------------------------------------------------------------
# exec 家族与失败诊断（行动清单 #8，上游 #402/#21）
#
# A. fd/dirfd 形态的 exec（runtime，proc.c）
#    guest 可执行文件在 app 数据目录，内核禁止直接 exec，只能走 trampoline。
#    execveat/fexecve 原先绕过 trampoline 直接交内核 → 全部 EACCES。
#    判据：五种形态全部成功执行（含 fexecve 执行 #! 脚本），且错误形态
#    给出内核语义的 errno（NOFOLLOW 链接 → ELOOP，不存在 → ENOENT，
#    fexecve(-1) → EBADF）。带官方对照：官方下 4 种 fd 形态失败 —— 证明
#    探针在本环境有判别力。
#
# B. launcher 的失败诊断：exec 失败时按文件内容指出**具体**原因
#    （缺解释器 / 无 #! 文本 / 无执行位 / CRLF / 空文件 / 外部架构），
#    而不是只报 "Permission denied"。-v -1（quiet）时不打印。
#
# C. 退出码：命令不存在 127、存在但不能执行 126（原先一律 1）。
# D. 默认静默：不带 -v 时 stderr 不应有 "[bxroot-launcher] stat(...)" 行。
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-exec-XXXXXX")
trap 'rm -rf "$W"' EXIT
FAIL=0
bad()  { FAIL=$((FAIL + 1)); echo "  ❌ $*"; }
good() { echo "  ✅ $*"; }

build() {
    i=1
    while [ $i -le 10 ]; do
        gcc "$@" 2>"$W/cc" && return 0
        grep -q 'internal compiler error' "$W/cc" || { cat "$W/cc"; return 1; }
        i=$((i + 1))
    done
    return 1
}

echo "--- A) execveat / fexecve 形态 ---"
if [ ! -f "$ROOT/build/libbxroot-runtime.so" ] || \
   ! grep -q 'libproroot-runtime\.so' /proc/self/maps 2>/dev/null; then
    echo "  ⏭️  跳过 A：需要 runtime 与外层 proroot 注入链路"
else
    build -O0 -w -o "$W/pe" "$ROOT/test/exec/probe_execveat.c" || { echo "❌ 探针编译失败"; exit 1; }
    "$W/pe" > "$W/off.txt" 2>&1
    timeout 60 "$ROOT/tools/bxroot-run" -- "$W/pe" > "$W/bx.txt" 2>&1
    offok=$(grep -c ' OK ' "$W/off.txt")
    [ "$offok" -lt 5 ] || bad "对照组 fd 形态也全部成功 —— 本环境下缺口不可观测"
    for k in 'execveat(AT_FDCWD,/usr/bin/echo,0)' 'execveat(dirfd(/usr/bin),"echo",0)' \
             'execveat(fd,"",AT_EMPTY_PATH)' 'fexecve(fd) ' ; do
        grep -F "$k" "$W/bx.txt" | grep -q 'OK out=hi' && good "$k 执行成功" \
            || bad "$k：$(grep -F "$k" "$W/bx.txt" | head -1)"
    done
    grep 'fexecve(script fd)' "$W/bx.txt" | grep -q 'OK out=script:' && good "fexecve 执行 #! 脚本" \
        || bad "fexecve 脚本：$(grep 'fexecve(script' "$W/bx.txt")"
    grep 'NOFOLLOW' "$W/bx.txt" | grep -q 'errno=40' && good "AT_SYMLINK_NOFOLLOW 链接 → ELOOP" \
        || bad "NOFOLLOW：$(grep NOFOLLOW "$W/bx.txt")"
    grep '/nonexist' "$W/bx.txt" | grep -q 'errno=2 ' && good "不存在 → ENOENT" \
        || bad "不存在：$(grep nonexist "$W/bx.txt")"
    grep 'fexecve(-1)' "$W/bx.txt" | grep -q 'errno=9 ' && good "fexecve(-1) → EBADF" \
        || bad "fexecve(-1)：$(grep 'fexecve(-1)' "$W/bx.txt")"
fi

echo "--- B) launcher 失败诊断 ---"
build -static -O1 -w -o "$W/L" "$ROOT/src/launcher/launcher.c" || { echo "❌ launcher 编译失败"; exit 1; }
D="$W/d"; mkdir -p "$D"
printf '#!/nonexistent/interp\necho x\n' > "$D/badinterp"; chmod +x "$D/badinterp"
printf 'plain text\n' > "$D/plain";                         chmod +x "$D/plain"
printf 'echo hi\n' > "$D/noexec";                           chmod 600 "$D/noexec"
printf '#!/bin/sh\r\necho x\r\n' > "$D/crlf";               chmod +x "$D/crlf"
: > "$D/empty";                                              chmod +x "$D/empty"
printf '\177ELF\002\001\001\000\000\000\000\000\000\000\000\000\002\000\076\000' > "$D/x86"
head -c 200 /dev/zero >> "$D/x86"; chmod +x "$D/x86"
chk() {   # $1 文件  $2 期望诊断片段  $3 期望 rc
    out=$("$W/L" -r / -w /tmp "$D/$1" 2>&1); rc=$?
    if printf '%s' "$out" | grep -qF "$2" && [ "$rc" = "$3" ]; then
        good "$1：诊断含「$2」，rc=$rc"
    else
        bad "$1：rc=$rc（期望 $3），输出：$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-160)"
    fi
}
chk badinterp '解释器 /nonexistent/interp 在 rootfs 内不存在' 126
chk plain     '没有 #! 行的文本文件' 126
chk noexec    '没有执行权限' 126
chk crlf      'Windows 换行' 126
chk empty     '文件是空的' 126
# x86：外层 stub-loader 可能先于内核报错，诊断不一定能走到；只要求不是 0
out=$("$W/L" -r / -w /tmp "$D/x86" 2>&1); rc=$?
if printf '%s' "$out" | grep -qF 'x86_64 架构'; then good "x86：诊断指出外部架构，rc=$rc"
elif [ "$rc" != 0 ]; then good "x86：rc=$rc（本环境由外层 stub-loader 先拒绝，诊断未触达）"
else bad "x86：rc=0"; fi
q=$("$W/L" -v -1 -r / -w /tmp "$D/plain" 2>&1)
printf '%s' "$q" | grep -q '可能原因' && bad "quiet 下仍打印诊断" || good "quiet（-v -1）不打印诊断"

echo "--- C) 退出码 ---"
"$W/L" -r / -w /tmp "$D/missing" >/dev/null 2>&1; rc=$?
[ "$rc" = 127 ] && good "命令不存在 → 127" || bad "命令不存在 rc=$rc（期望 127）"
"$W/L" -r / -w /tmp nosuchcmd_bxroot >/dev/null 2>&1; rc=$?
[ "$rc" = 127 ] && good "PATH 里找不到 → 127" || bad "PATH 找不到 rc=$rc（期望 127）"

echo "--- D) 默认静默 ---"
e=$("$W/L" -r / -w /tmp "$D/plain" 2>&1 >/dev/null)
printf '%s' "$e" | grep -q '\[bxroot-launcher\] stat(' && bad "默认模式仍打印 stat 诊断行" \
    || good "默认模式无 [bxroot-launcher] stat 行"
e=$("$W/L" -v 1 -r / -w /tmp "$D/plain" 2>&1 >/dev/null)
printf '%s' "$e" | grep -q '\[bxroot-launcher\] stat(' && good "-v 1 时打印 stat 诊断行" \
    || bad "-v 1 时缺 stat 诊断行"

echo
[ "$FAIL" -gt 0 ] && { echo "RESULT: FAIL（$FAIL 项）"; exit 1; }
echo "RESULT: PASS"
