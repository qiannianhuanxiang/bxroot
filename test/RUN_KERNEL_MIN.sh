#!/bin/sh
# ---------------------------------------------------------------------
# 最低内核版本依据检查（行动清单 #10，上游 #417）
#
# 【为什么要这个】清单原写 "kernel 4.19 最低版本未验证/未声明" —— 那个
# 数字是从上游 issue 的**症状描述**里抄来的，不是对 bxroot 自身依赖的
# 分析结果。本脚本把依赖逐项实测出来，让声明有依据（可复跑、可反驳）。
#
# 【实测得出的门槛】运行时真正**无回退**依赖的最新调用：
#     statx      (291)  内核 4.11   —— 裸 syscall 路径翻译 + 结果补丁
#     execveat   (281)  内核 3.19   —— fd/dirfd 形态的 exec
#   以下都是**有回退**的，不构成门槛（见各自源码注释）：
#     faccessat2 (439)  内核 5.8    —— 拿不到就用 faccessat(48) 重放
#     accept     (202)  始终可用    —— Android 白名单外时用 accept4 重放
#     clone3     (435)  内核 5.3    —— 被拦时 glibc 自动回退 clone(2)
#     rseq       (293)  内核 4.18   —— livepatch 站点中和
#   所以门槛由 statx 决定 = **4.11**。
#
# 【判据】
#   A. 本机内核能跑通这两个关键调用（在当前内核上就是"可用"的实证）
#   B. 源码里对它们的使用与回退策略仍然成立（防止将来改成硬依赖）
#   C. README 里的声明与实测门槛一致（防止文档再次漂移）
# 不需要外层 proroot（纯本地 + 源码扫描）。
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-kmin-XXXXXX")
trap 'rm -rf "$W"' EXIT
FAIL=0
bad()  { FAIL=$((FAIL + 1)); echo "  ❌ $*"; }
good() { echo "  ✅ $*"; }

bld() {
    i=1
    while [ $i -le 10 ]; do
        gcc "$@" 2>"$W/cc" && return 0
        grep -q 'internal compiler error' "$W/cc" || { cat "$W/cc"; return 1; }
        i=$((i + 1))
    done
    return 1
}

echo "--- A) 关键调用的本机可用性 ---"
cat > "$W/k.c" <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
/*
 * ★ 必须用系统头的 struct statx ★
 *
 * 首版手写了一个 "struct stx"，字段宽度算错（statx 的结构体是 256 字节，
 * 我只写了约 160），于是内核按 256 字节写入时越过了栈上的缓冲 ——
 * 实测 "*** stack smashing detected ***" 后被 SIGABRT 杀掉，输出全空，
 * 探针看起来像"statx 不可用"。那是**探针自身的缺陷**，不是内核的。
 */
#include <linux/stat.h>
int main(void)
{
    struct statx x;
    long r;

    /* 必须无缓冲：崩溃/失败时也要看到已经打出来的那几行 */
    setvbuf(stdout, NULL, _IONBF, 0);

    errno = 0;
    r = syscall(291 /* statx */, -100, "/", 0, 0xfffU, &x);
    printf("statx(291) rc=%ld errno=%d\n", r, errno);
    if (r != 0)
        return 1;

    errno = 0;
    r = syscall(281 /* execveat */, -100, "/nonexistent-kmin",
                (char *[]){ "x", NULL }, NULL, 0);
    printf("execveat(281) rc=%ld errno=%d\n", r, errno);
    /* ENOENT = 内核理解并执行了这个号；ENOSYS = 内核不认识它 */
    return (errno == ENOSYS) ? 2 : 0;
}
EOF

bld -O0 -w -o "$W/k" "$W/k.c" || { echo "❌ 探针编译失败"; exit 1; }
out=$("$W/k"); rc=$?
printf '%s\n' "$out" | sed 's/^/     /'
case "$rc" in
    0) good "statx 与 execveat 在本机内核可用（门槛满足）" ;;
    2) bad "execveat 返回 ENOSYS —— 本机内核低于 3.19？" ;;
    *) bad "statx 不可用 —— 本机内核低于 4.11？（本机 $(uname -r)）" ;;
esac

echo "--- B) 源码依赖与回退策略 ---"
SG="$ROOT/src/runtime/syscall_guard.c"
grep -q 'case 291:.*statx' "$SG" && good "statx(291) 在路径参数表内" || bad "statx 不在路径参数表内"
grep -q 'case 281:.*execveat' "$SG" && good "execveat(281) 在路径参数表内" || bad "execveat 不在路径参数表内"
if grep -q 'replay_faccessat2' "$ROOT/src/runtime/sigsys.c"; then
    good "faccessat2(439) 有重放回退（不构成门槛）"
else
    bad "faccessat2 的回退实现不见了 —— 它可能变成硬依赖"
fi
if grep -q 'replay_accept' "$ROOT/src/runtime/sigsys.c"; then
    good "accept(202) 有 accept4 重放（不构成门槛）"
else
    bad "accept 的重放实现不见了"
fi

echo "--- C) README 声明与实测门槛一致 ---"
#
# 匹配标题行 `### 最低内核要求：**4.11**…` —— 用宽松模式（允许加粗标记
# 与冒号），否则检查条件比文档本身还苛刻（首版找的是无冒号无加粗的
# "最低内核 4.11"，而 README 写的是带加粗的标题，于是误报）。
# 同时**禁止**出现旧的无依据数字 4.19 作为门槛。
if grep -qE '最低内核要求.*4\.11' "$ROOT/README.md"; then
    good "README 声明最低内核 4.11（与 statx 门槛一致）"
else
    bad "README 未声明最低内核 4.11（或声明了别的数字）"
fi
if grep -qE '最低内核.*4\.19|要求.*4\.19' "$ROOT/README.md"; then
    bad "README 仍把 4.19 当作最低内核（那是照搬上游 issue 的数字，无依据）"
else
    good "README 未把无依据的 4.19 写成门槛"
fi

echo
[ "$FAIL" -gt 0 ] && { echo "RESULT: FAIL（$FAIL 项）"; exit 1; }
echo "RESULT: PASS"
