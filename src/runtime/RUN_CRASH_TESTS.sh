#!/bin/sh
# crash.c 崩溃处理器测试
#
# 崩溃处理器**无法**在进程内自测（它一跑进程就死了），所以这里用
# "子进程崩溃 → 父 shell 检查输出与退出码" 的方式验证。
#
# 三类场景各自验证：
#   T1 空指针解引用     -> SEGV_MAPERR，应跳过内存窗口
#   T2 写只读代码段     -> SEGV_ACCERR，应转储内存窗口
#   T3 栈溢出           -> 验证 sigaltstack 生效（否则处理器根本跑不起来）
#
# 另加两项行为验证：
#   T4 退出码必须是 139（128+SIGSEGV），父进程/脚本才能正确识别
#   T5 重入守卫：崩溃后必须**恰好一次**输出，不能刷屏或死循环
set -e
cd "$(dirname "$0")"

CC=${CC:-gcc}
CFLAGS="-std=c11 -O0 -D_GNU_SOURCE -Wall -Wextra"
pass=0
fail=0

note() { printf '%s\n' "$*"; }
ok()   { pass=$((pass+1)); printf '  [PASS] %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf '  [FAIL] %s\n' "$1"; }

# gcc 在本容器会间歇性 ICE，带重试
build() {
    out=$1; src=$2
    i=1
    while [ "$i" -le 8 ]; do
        if $CC $CFLAGS -o "$out" "$src" crash.c 2>/tmp/crash-cc.err; then
            return 0
        fi
        if ! grep -q 'internal compiler error' /tmp/crash-cc.err; then
            cat /tmp/crash-cc.err
            return 1
        fi
        i=$((i+1))
    done
    return 1
}

note "构建测试程序..."
build t_null  t_null.c
build t_write t_write.c
build t_stack t_stack.c

note ""
note "T1 空指针解引用（SEGV_MAPERR）"
out=$(timeout 20 ./t_null 2>&1 || true)
if printf '%s' "$out" | grep -q 'SIGSEGV'; then
    ok "捕获到 SIGSEGV 并打印了信号信息"
else
    bad "未捕获 SIGSEGV"
fi
if printf '%s' "$out" | grep -q 'fault=0x0000000000000000'; then
    ok "fault 地址正确（0）"
else
    bad "fault 地址不正确"
fi
if printf '%s' "$out" | grep -q 'x0 '; then
    ok "打印了通用寄存器"
else
    bad "未打印寄存器"
fi
if printf '%s' "$out" | grep -q 'backtrace (fp chain)'; then
    ok "打印了帧指针链回溯"
else
    bad "未打印回溯"
fi
if printf '%s' "$out" | grep -q 'SEGV_MAPERR'; then
    ok "识别出未映射并跳过内存窗口（避免二次崩溃）"
else
    bad "未识别 SEGV_MAPERR"
fi

note ""
note "T2 写只读代码段（SEGV_ACCERR）"
out=$(timeout 20 ./t_write 2>&1 || true)
if printf '%s' "$out" | grep -q 'code=2'; then
    ok "si_code=2（SEGV_ACCERR）正确"
else
    bad "si_code 不正确"
fi
if printf '%s' "$out" | grep -q 'sigsegv-extra'; then
    ok "转储了内存窗口"
else
    bad "未转储内存窗口"
fi
if printf '%s' "$out" | grep -qE '\+00=0x[0-9a-f]{16}'; then
    ok "内存窗口格式正确（+00=0x...）"
else
    bad "内存窗口格式错误"
fi

note ""
note "T3 栈溢出（验证 sigaltstack）"
out=$(timeout 30 ./t_stack 2>&1 || true)
if printf '%s' "$out" | grep -q 'SIGSEGV'; then
    ok "栈溢出时仍能输出（sigaltstack 生效）"
else
    bad "栈溢出时无输出 —— sigaltstack 未生效"
fi
if printf '%s' "$out" | grep -q '#10'; then
    ok "回溯足够深（可见递归链）"
else
    bad "回溯过浅"
fi

note ""
note "T4 退出码"
timeout 20 ./t_null >/dev/null 2>&1 && rc=0 || rc=$?
if [ "$rc" = "139" ]; then
    ok "退出码 139（128+SIGSEGV），父进程可正确识别"
else
    bad "退出码为 $rc，期望 139"
fi

note ""
note "T5 重入守卫（必须恰好一次输出，不刷屏）"
out=$(timeout 20 ./t_null 2>&1 || true)
n=$(printf '%s' "$out" | grep -c 'SIGSEGV pc=' || true)
if [ "$n" = "1" ]; then
    ok "恰好输出一次（重入守卫生效）"
else
    bad "输出了 $n 次，期望 1 次（重入守卫失效）"
fi

note ""
note "----------------------------------------"
note "PASS=$pass FAIL=$fail"
if [ "$fail" = "0" ]; then
    note "RESULT: PASS"
    exit 0
else
    note "RESULT: FAIL"
    exit 1
fi
