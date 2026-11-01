#!/bin/sh
# 原生调用真机验收（bxroot 引擎，DSHA bxroot.8+）。
# 在 DSHA 的 bxroot 终端里执行：  sh run-native-calls.sh
# 只读：不安装、不改设置、不写设备目录；临时文件只放 $TMPDIR。
# 每项打印 PASS/FAIL/SKIP；最后一行是汇总。把全部输出贴回即可。
set -u
pass=0; fail=0; skip=0
ok()   { pass=$((pass+1)); printf 'PASS %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf 'FAIL %s :: %s\n' "$1" "$2"; }
na()   { skip=$((skip+1)); printf 'SKIP %s :: %s\n' "$1" "$2"; }
cut200() { s=$1; [ ${#s} -gt 200 ] && s=$(printf %.200s "$s"); printf %s "$s"; }
# 回入口在真机由 Android linker 按 PT_INTERP 装载；内核拒绝直接执行（rc=126）时
# 退回显式 /system/bin/linker64 装载（见三、的 e() 函数）。
check() { # name expected-substring command...
    name=$1; want=$2; shift 2
    out=$("$@" 2>&1); rc=$?
    case "$out" in *"$want"*) ok "$name (rc=$rc)";; *) bad "$name" "rc=$rc out=$(cut200 "$out")";; esac
}

echo "== 环境"
echo "engine-auto=${BXROOT_AUTO_HOST:-unset} reentry=${BXROOT_REENTRY:-unset}"
echo "enter=${BXROOT_ENTER:-unset} session_fd=${BXROOT_SESSION_FD:-unset}"
command -v bx-host >/dev/null 2>&1 && ok "bx-host 在 PATH ($(command -v bx-host))" || bad "bx-host 在 PATH" "not found"
[ "${BXROOT_AUTO_HOST:-}" = 1 ] && ok "自动分流已开启" || bad "自动分流已开启" "BXROOT_AUTO_HOST=${BXROOT_AUTO_HOST:-unset}"

echo "== 一、bx-host 显式调用"
check "bx-host --version" "bx-host" bx-host --version
check "bx-host getprop" "" bx-host getprop ro.product.model
m=$(bx-host getprop ro.product.model 2>/dev/null); [ -n "$m" ] && ok "getprop 有输出: $m" || bad "getprop 有输出" "empty"
check "bx-host toybox uname" "aarch64" bx-host toybox uname -m
out=$(bx-host /system/bin/sh -c 'echo LD=[$LD_PRELOAD]; exit 7' 2>&1); rc=$?
[ "$rc" = 7 ] && ok "退出码透传 rc=7" || bad "退出码透传" "rc=$rc $out"
case "$out" in *"LD=[]"*) ok "宿主侧无 glibc LD_PRELOAD";; *) bad "宿主侧无 glibc LD_PRELOAD" "$out";; esac
bx-host /usr/bin/true >/dev/null 2>&1; rc=$?
[ "$rc" = 126 ] && ok "拒绝把 glibc 程序交给 Android (rc=126)" || bad "拒绝 glibc 程序" "rc=$rc"
bx-host no-such-cmd-xyz >/dev/null 2>&1; rc=$?
[ "$rc" = 127 ] && ok "不存在的命令 rc=127" || bad "不存在的命令" "rc=$rc"

echo "== 二、自动分流（guest 没有同名程序时落到 Android）"
check "getprop（无前缀）" "" getprop ro.build.version.release
v=$(getprop ro.build.version.release 2>/dev/null); [ -n "$v" ] && ok "Android 版本: $v" || bad "getprop 无前缀" "empty"
check "/system/bin/getprop 绝对路径" "" /system/bin/getprop ro.product.brand
check "toybox（无前缀）" "aarch64" toybox uname -m
check "Ubuntu 的 uname 仍是 guest 程序" "Linux" uname -s
if command -v python3 >/dev/null 2>&1; then
    out=$(python3 -c 'import subprocess;print(subprocess.run(["getprop","ro.product.model"],capture_output=True,text=True).stdout.strip())' 2>&1)
    [ -n "$out" ] && ok "python subprocess 调 getprop: $out" || bad "python subprocess 调 getprop" "empty"
else na "python subprocess" "python3 未安装"; fi
if command -v node >/dev/null 2>&1; then
    out=$(node -e 'console.log(require("child_process").execFileSync("getprop",["ro.product.model"]).toString().trim())' 2>&1)
    [ -n "$out" ] && ok "node execFileSync 调 getprop: $out" || bad "node execFileSync 调 getprop" "empty"
else na "node execFileSync" "node 未安装"; fi
out=$(pm list packages 2>&1); rc=$?
case "$out" in package:*) ok "pm list packages 可用";; *) na "pm list packages" "受 Android 权限限制属正常: $(cut200 "$out")";; esac

echo "== 三、回入口（Android 原生 → 同一 Ubuntu 会话）"
if [ -z "${BXROOT_ENTER:-}" ] || [ -z "${BXROOT_SESSION_FD:-}" ]; then
    na "回入口" "BXROOT_ENTER/BXROOT_SESSION_FD 未设置"
else
    E='e(){ "$BXROOT_ENTER" "$@" 2>/dev/null && return 0; r=$?; [ $r = 126 ] || return $r; /system/bin/linker64 "$BXROOT_ENTER" "$@"; }; '
    out=$(bx-host /system/bin/sh -c "$E"'e --cwd /root -- /usr/bin/printf back-to-guest' 2>&1); rc=$?
    case "$out" in *back-to-guest*) ok "原生 sh → guest printf (rc=$rc)";; *) bad "原生 sh → guest printf" "rc=$rc $out";; esac
    out=$(bx-host /system/bin/sh -c "$E"'e --cwd /root -- /bin/sh -c ". /etc/os-release; echo \$ID; exit 5"' 2>&1); rc=$?
    case "$out" in *ubuntu*) [ "$rc" = 5 ] && ok "回入 guest shell，rc=5 透传" || bad "回入 rc" "rc=$rc";; *) bad "回入 guest shell" "rc=$rc $out";; esac
    out=$(bx-host /system/bin/sh -c "$E"'e --to-host /etc/os-release' 2>/dev/null)
    case "$out" in /*os-release) ok "路径转换 --to-host: $out";; *) bad "路径转换 --to-host" "$out";; esac
    out=$(bx-host /system/bin/sh -c "$E"'e --cwd /root -- /usr/bin/bash -c "getprop ro.product.model"' 2>/dev/null); rc=$?
    [ -n "$out" ] && [ "$rc" = 0 ] && ok "guest→host→guest→host 链: $out" || bad "多层链" "rc=$rc $out"
fi

echo "== 汇总"
echo "RESULT: pass=$pass fail=$fail skip=$skip"
[ "$fail" = 0 ]
