#!/bin/sh
# =====================================================================
# 钉住 sigsys.c 的裸系统调用号与 sigsetsize
# =====================================================================
#
# 由来
# ----
# src/runtime/sigsys.c 里"主线程解除 SIGSYS 屏蔽"那句裸调用曾同时错三处：
#   1. 调用号写 175 —— aarch64 上 175 是 **geteuid**，rt_sigprocmask 是 135
#   2. sigsetsize 传 sizeof(sigset_t)=128 —— 内核只接受 8，传 128 报 EINVAL
#   3. 注释断言"sigset_t 内核与 glibc 都是 128 字节布局一致"—— 事实相反
#
# 后果：这句"解除屏蔽"实际只查了一次 euid，返回 0（**所以从不报错**），
# SIGSYS 屏蔽位原封不动 → 处理器装了却收不到信号 → 进程被 159 杀掉。
#
# 这类缺陷没有任何静态手段能发现（编译通过、返回值正常、没有类型检查），
# 只有在真实内核上实测**副作用**才看得见。本脚本就是那个实测。
#
# 判别力
# ------
# 探针里同时跑正确号(135)与错误号(175)：
#   - 135 → 屏蔽位必须变 0
#   - 175 → 屏蔽位必须**保持 1**
# 两个方向都断言，才能排除"探针本身恒真"的假阳性（例如恒返回 PASS 的
# 空断言）。若有人把号改回去，T1 第一条立即 FAIL。
#
# 用法：sh test/RUN_SIGSYS_NUM.sh
# =====================================================================
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CC="${CC:-gcc}"
OUT="/tmp/sigsys-num-probe.$$"

echo "▶️  sigsys 裸系统调用号 / sigsetsize"

# gcc13 间歇 ICE：重试 + 降优化级（与其余 runner 同策略）
OPT="-O2"
for i in 1 2 3 4; do
    if $CC $OPT -Wall -Wextra -o "$OUT" "$ROOT/test/probe_sigprocmask_num.c" 2>"$OUT.err"; then
        break
    fi
    if grep -q "internal compiler error" "$OUT.err" && [ "$OPT" = "-O2" ]; then
        OPT="-O1"; continue
    fi
    if grep -q "internal compiler error" "$OUT.err" && [ "$OPT" = "-O1" ]; then
        OPT="-O0"; continue
    fi
    echo "   ❌ 编译失败（非 ICE）："
    head -20 "$OUT.err"
    rm -f "$OUT" "$OUT.err"
    exit 1
done

# 判成功看产物是否存在，不要 grep 日志
if [ ! -f "$OUT" ]; then
    echo "   ❌ 探针未产出（检查 $OUT.err）"
    rm -f "$OUT.err"
    exit 1
fi

"$OUT"
rc=$?
rm -f "$OUT" "$OUT.err"

if [ $rc -eq 0 ]; then
    echo "   RESULT: PASS"
else
    echo "   RESULT: FAIL"
fi
exit $rc
