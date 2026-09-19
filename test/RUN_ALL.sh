#!/bin/sh
# =====================================================================
# bxroot 全量回归入口
# =====================================================================
#
# 由来
# ----
# Makefile 里的 `make test` 一直指向 `test/full_test.sh` —— 而那个文件
# **从来不存在**。也就是说"跑测试"这个动作在过去是空转的：谁执行
# `make test` 都会拿到 "No such file or directory"，于是没人真的跑过
# 全量回归。本脚本把它补成一个真实可跑的总入口。
#
# 覆盖范围
# --------
#   1. 编译告警门禁        test/RUN_WARN_GATE.sh
#   2. l2s 运行时          test/test_l2s_rt.c
#   3. l2s × fakeroot 协同 test/RUN_INTEGRATION.sh
#   4. fakeroot 纯逻辑     test/RUN_TESTS.sh
#   5. 系统调用参数位置    test/test_syscall_argpos.c
#   5b. rename/link 双路径 test/test_rename_link_argpos.c（含 syscall_guard.c）
#   5c. 身份 syscall 伪装  test/test_id_syscall_guard.c（含 syscall_guard.c）
#   6. crash 崩溃处理器    src/runtime/RUN_CRASH_TESTS.sh
#   7. D4 进程管理         src/proc/RUN_TESTS.sh
#   8. wait 家族钩子       test/RUN_WAIT_TESTS.sh
#   9. 运行时构建 + 符号导出  BUILD_RUNTIME.sh
#
# 为什么第 9 项也算回归
# --------------------
# 构建脚本结尾会核对 D4 的 19 个符号是否在**动态符号表**里。LD_PRELOAD
# 靠动态符号表插入，符号漏导出 = 钩子静默失效，而进程照样能跑 ——
# 这类缺陷只有构建期检查能拦住。
#
# 可选：端到端（默认**不跑**）
# ---------------------------
#   sh test/RUN_ALL.sh --e2e
# 会额外尝试在真机容器里用 bxroot 启动 dsh。它需要真实 rootfs 与
# Android 环境，在纯 Ubuntu 容器里会跳过。
#
# 用法
# ----
#   sh test/RUN_ALL.sh             # 全量回归
#   sh test/RUN_ALL.sh --quick     # 跳过构建（只跑测试）
#   sh test/RUN_ALL.sh --e2e       # 追加端到端
#
# 退出码
# ------
#   0 = 全部通过     1 = 有失败
# =====================================================================

set -u

SELF_DIR=$(dirname "$0")
ROOT=$(cd "$SELF_DIR/.." && pwd)
cd "$ROOT" || { echo "❌ 无法进入仓库根目录"; exit 1; }

QUICK=0
DO_E2E=0
for a in "$@"; do
    case "$a" in
    --quick) QUICK=1 ;;
    --e2e)   DO_E2E=1 ;;
    esac
done

# ---------------------------------------------------------------------
# 结果收集。用文件暂存，因为各测试跑在子 shell 里。
#
# ★ /tmp 在这里并不总是可用 ★ 实测：一次回归跑到一半，/tmp 的权限被
# 清成了 000（本容器里有别的进程会动它），于是 `: > /tmp/...` 直接
# "Permission denied"，整轮汇总崩掉 —— 而**各个测试其实是跑完了的**，
# 只是结果记不下来。所以这里做两件事：
#   ① 优先 mktemp（拿到一个已存在且可写的名字）；
#   ② 拿不到就退回仓库内的临时目录，保证回归不因外部环境崩掉。
# 注意不能简单用 `$$` 拼 /tmp 下的固定名 —— 那正是失败的那条路径。
# ---------------------------------------------------------------------
TMPDIR_BX="${TMPDIR:-/tmp}"
RESULT_FILE=""

if command -v mktemp >/dev/null 2>&1; then
    RESULT_FILE=$(mktemp "$TMPDIR_BX/bxroot-all-XXXXXX" 2>/dev/null) || RESULT_FILE=""
fi
if [ -z "$RESULT_FILE" ]; then
    # 回退：仓库内的临时目录（随仓库可写性走，不受 /tmp 影响）
    mkdir -p "$ROOT/.tmp-regress" 2>/dev/null
    RESULT_FILE="$ROOT/.tmp-regress/all-$$.txt"
    : > "$RESULT_FILE" 2>/dev/null || {
        echo "❌ 无法创建结果文件（/tmp 与仓库内都不可写）"
        exit 1
    }
fi
: > "$RESULT_FILE" 2>/dev/null

# 各测试的日志也走同一个可写目录，避免 /tmp 不可写时日志写入失败
WORK_DIR=$(dirname "$RESULT_FILE")

PASS=0
FAIL=0
SKIP=0
KNOWN=0

# 已知缺陷登记表：这些项当前**预期失败**，失败记为 KNOWN 而不是 FAIL，
# 免得整轮回归长期红着、把别的新问题掩盖掉。
# 修复后把对应条目删掉即可（那时它应当 PASS，也就不会再走这条分支）。
#
# ★ 2026-09-16：`l2s 端到端契约` 已修复并移除 ★
#
# 它曾在这里登记过一段时间（三个独立缺陷叠加：scheme 自相矛盾 /
# fstatat 漏接 l2s / node 走裸 syscall(291) 而补丁接在 statx() 符号上）。
# 修复后实测与官方逐项一致：
#     bxroot: nlink=2 islink=false content="hello"
#     官方  : nlink=2 islink=false content="hello"
# 完整分析见 docs/l2s-stat伪装三缺陷分析.md。
#
# 保留这行注释而不是直接删干净，是为了让后来者知道：这张表**是可以清空的** ——
# 登记不是"把测试关掉"，而是"承认缺陷存在、让它可见但不污染回归信号"。
#
# ★ 2026-09-16（第二次登记）→ 已修复，第三次清空 ★
#
# 这一轮修的是 `size` 与 `ino`/`blocks` 的回填：
#   - `l2s_rt_patch_stat` 现在会 lstat 最终数据文件并回填真实元数据
#   - 新增 `l2s_rt_patch_statx_buf`（传整个结构体），覆盖 statx 路
#     （`stat` 命令与 node 走这条）
#
# 实测与官方逐项一致：
#     bxroot: nlink=2 islink=false size=5 stsize=5 reallink=true content="hello"
#     官方  : nlink=2 islink=false size=5 stsize=5 reallink=true content="hello"
#
# ⚠️ 但 `readlink` 那一项**仍待修**（另一个子代理在做）——
# 它不影响本回归项（本项测的是 stat 的字段），但会让 `tar` / `cp -a` 仍失败。
# 见 docs/l2s-真实工具链缺陷-tar与lstat-size.md
KNOWN_FAIL=""

# 记录一条结果：$1=状态(PASS/FAIL/SKIP) $2=名称 $3=摘要
note() {
    printf '%s|%s|%s\n' "$1" "$2" "$3" >> "$RESULT_FILE"
}

echo "======================================================"
echo " bxroot 全量回归"
echo " 仓库: $ROOT"
echo "======================================================"
echo

# ---------------------------------------------------------------------
# 通用执行器：跑一条命令，捕获退出码与输出尾部
#
# 之所以不直接 `set -e`：需要跑完所有测试再统一汇报，
# 第一个失败就退出会掩盖后面测试的状态。
# ---------------------------------------------------------------------
run_step() {
    name="$1"; shift
    logf="$WORK_DIR/step-$$.log"

    if [ "$#" -eq 0 ]; then
        note SKIP "$name" "无命令"
        SKIP=$((SKIP + 1))
        printf '⏭️  %-26s 跳过\n' "$name"
        return 0
    fi

    printf '▶️  %-26s ' "$name"
    # shellcheck disable=SC2068
    if "$@" >"$logf" 2>&1; then
        rc=0
    else
        rc=$?
    fi

    # 摘要：优先取输出里的"通过/失败"统计行，否则取末行
    summary=$(grep -aoE '[0-9]+ *(用例|个用例|passed|通过)[^,，]*' "$logf" 2>/dev/null | tail -1)
    [ -z "$summary" ] && summary=$(tail -1 "$logf" 2>/dev/null | cut -c1-48)
    [ -z "$summary" ] && summary="(无输出)"

    if [ "$rc" -eq 0 ]; then
        note PASS "$name" "$summary"
        PASS=$((PASS + 1))
        printf '✅ rc=0  %s\n' "$summary"
    elif [ "$rc" -eq 2 ]; then
        # ★ rc=2 = "环境不满足，无法测"，不是失败 ★
        #
        # 本项目的子测试脚本用三种退出码表达三件事，这是既定约定
        # （见各脚本头部的"退出码"一节）：
        #     0 = 通过      1 = 契约被破坏      2 = 环境不满足（无法测）
        #
        # 但本函数原先**只认 0 为通过**，把 rc=2 也记成失败。实测后果：
        # 在干净克隆（无 build/ 产物、无真机 rootfs）里跑：
        #
        #     ✅ 编译告警门禁 ... ✅ dl 家族契约   ← dl 脚本自己 exit 0
        #     ❌ l2s 端到端契约  rc=2 跳过：没有 build/libbxroot-runtime.so
        #     通过 11 / 失败 1        ← ★ 一个"环境不满足"被报成缺陷 ★
        #
        # 两个脚本对同一件事用了**不同**的退出码（l2s 用 2、dl 用 0），
        # 于是同一个环境限制只有其中一个被误报 —— 典型的约定漂移。
        #
        # 处置：rc=2 归入 SKIP，但**明确显示原因**（不能静默 —— 静默跳过
        # 是本项目反复出现的缺陷模式，见 docs/测试基础设施红队报告.md）。
        # 真正的契约破坏走 exit 1，仍归 FAIL。
        note SKIP "$name" "rc=2 环境不满足（无法测）"
        SKIP=$((SKIP + 1))
        printf '⏭️  rc=2  %s\n' "$summary"
        # 打印末几行，让"为什么跳过"可见（例如缺哪个产物）
        tail -3 "$logf" 2>/dev/null | sed 's/^/   /'
    else
        # 已知缺陷：记 KNOWN，不计入失败总数（但仍醒目显示）
        case " $KNOWN_FAIL " in
            *" $name "*)
                note KNOWN "$name" "rc=$rc $summary"
                KNOWN=$((KNOWN + 1))
                printf '⚠️  rc=%s （已知缺陷）%s\n' "$rc" "$summary"
                echo "   --- 末尾 5 行 ---"
                tail -5 "$logf" 2>/dev/null | sed 's/^/   /'
                echo "   ----------------"
                rm -f "$logf"
                return 0
                ;;
        esac
        note FAIL "$name" "rc=$rc $summary"
        FAIL=$((FAIL + 1))
        printf '❌ rc=%s  %s\n' "$rc" "$summary"
        echo "   --- 末尾 15 行 ---"
        tail -15 "$logf" 2>/dev/null | sed 's/^/   /'
        echo "   ------------------"
    fi
    rm -f "$logf"
    return 0
}

# =====================================================================
# 1. 编译告警门禁 —— 放第一位：编译不过后面都没意义
# =====================================================================
run_step "编译告警门禁" sh test/RUN_WARN_GATE.sh

# ---------------------------------------------------------------------
# 带 ICE 重试的「编译 + 运行」。
#
# ★ 不能用 exec ★ run_step 是在**当前 shell**里调用命令的，一旦 exec
# 就会把整个回归进程替换成被测程序，后面的测试全部消失、汇总也打不出来。
# 所以这里只运行并返回它的退出码。
#
# 输出路径统一放 $WORK_DIR（/tmp 不可写时已自动回退），不再散落 /tmp。
# ---------------------------------------------------------------------
retry_gcc_run() {
    out="$WORK_DIR/$1"; shift
    i=1
    while [ "$i" -le 8 ]; do
        if gcc "$@" -o "$out" 2>"$WORK_DIR/cc.err"; then
            "$out"
            return $?
        fi
        if ! grep -q 'internal compiler error' "$WORK_DIR/cc.err" 2>/dev/null; then
            cat "$WORK_DIR/cc.err" 2>/dev/null
            return 1
        fi
        i=$((i + 1))
    done
    echo "gcc 持续 ICE，退回 -O0"
    gcc "$@" -O0 -o "$out" && "$out"
    return $?
}

# =====================================================================
# 2. l2s 运行时（15 用例）
# =====================================================================
if [ -f test/test_l2s_rt.c ]; then
    run_step "l2s 运行时" retry_gcc_run t-l2s \
        -std=c11 -O1 -Wall -Wextra -D_GNU_SOURCE -Isrc/l2s \
        test/test_l2s_rt.c src/l2s/l2s.c src/l2s/l2s-runtime.c
else
    run_step "l2s 运行时"
fi

# =====================================================================
# 3. 协同（l2s × fakeroot）
# =====================================================================
[ -f test/RUN_INTEGRATION.sh ] && run_step "l2s×fakeroot 协同" sh test/RUN_INTEGRATION.sh \
    || run_step "l2s×fakeroot 协同"

# =====================================================================
# 4. fakeroot 纯逻辑
# =====================================================================
[ -f test/RUN_TESTS.sh ] && run_step "fakeroot 纯逻辑" sh test/RUN_TESTS.sh \
    || run_step "fakeroot 纯逻辑"

# =====================================================================
# 4b. fakeroot 账本多线程并发（评估报告 8.7）
#
# 无锁版实测稳定堆破坏（double free / unaligned tcache chunk）；
# 本项钉住加锁后的并发正确性（不变量 + 计数精确）。
# =====================================================================
if [ -f test/RUN_CONCUR.sh ]; then
    run_step "fakeroot 账本并发" sh test/RUN_CONCUR.sh
fi

# =====================================================================
# 5. 系统调用参数位置（防回归：symlinkat 的 a1 不是路径）
# =====================================================================
if [ -f test/test_syscall_argpos.c ]; then
    # ★ 必须链接 src/runtime/syscall_guard.c ★
    #
    # 这是一处**实测出来的漏洞**（红队复核发现）：本项原先只编测试自己，
    # 从不链接 syscall_guard.c（`nm` 里 0 个 guard 符号），于是它测的全是
    # **内核 ABI** —— 而那部分永远稳定，不会因为我们改坏"路径参数表"而变红。
    #
    # 后果：把 path_arg_index() 改回 `return 1`（历史缺陷本体），本项仍然
    # PASS、门禁 0 条、全回归绿。**这套回归声称能防的那个具体缺陷，它防不住。**
    #
    # 现在链接真实源文件，并通过 syscall_guard.h 里的测试钩子
    # bxroot_test_path_arg_mask() 直接断言表内容 —— 那才是主证据。
    run_step "系统调用参数位置" retry_gcc_run t-argpos \
        -std=c11 -O1 -Wall -Wextra -Wno-nonnull-compare -Wno-unused-parameter \
        -D_GNU_SOURCE= -Isrc/runtime -Isrc/l2s \
        test/test_syscall_argpos.c src/runtime/syscall_guard.c
else
    run_step "系统调用参数位置"
fi

# =====================================================================
# 5c. 路径参数表实测审计（评估报告 8.6）
#
# 与 5/5b 的分工：那两项断言表内容（快，但只覆盖已知编号）；
# 本项用**裸 svc** 对内核逐号实测，能发现"表里完全没有的路径型调用"
# —— 2026-09-18 正是它报出 25 个遗漏（xattr 族/chdir/truncate/openat2 等
# 走裸 syscall 时绕过翻译），补齐后遗漏归零。
# 判据：遗漏 0 且不一致 0。存疑项（seccomp 遮挡）不判失败。
# =====================================================================
if [ -f test/RUN_SYSCALL_TABLE_AUDIT.sh ]; then
    run_step "路径参数表实测审计" sh test/RUN_SYSCALL_TABLE_AUDIT.sh
fi

# =====================================================================
# 5b. rename/link 第二路径参数（防回归：a3 必须被翻译；260 不是 linkat）
#
# 与上一项的分工：上一项验 symlinkat 的 a1 是 dirfd；本项验
# renameat/renameat2/linkat 的 **两个** 路径参数（a1 与 a3）位置正确，
# 且 260（真身 wait4）不被误当 linkat 翻译。
#
# ★ 必须与被测模块 syscall_guard.c 一起编译 ★ —— 本测试自带一个翻译桩，
#   借此在**同一个进程内**观察并驱动 guard 的翻译层，从而真正区分
#   "翻译了" 与 "没翻译"（而不是只看返回值）。
# =====================================================================
if [ -f test/test_rename_link_argpos.c ]; then
    run_step "rename/link 双路径" retry_gcc_run t-rename-link \
        -std=c11 -O1 -Wall -Wextra -D_GNU_SOURCE= -Isrc/runtime \
        test/test_rename_link_argpos.c src/runtime/syscall_guard.c
else
    run_step "rename/link 双路径"
fi

# =====================================================================
# 5c. 裸 syscall 层身份伪装（fakeroot 的 uid/gid）
#
# 与 5/5b 是**同一个文件**（syscall_guard.c）的另一半契约：前两项钉住
# "哪些参数寄存器是路径"，本项钉住"哪些**返回值**要被改写"。
#
# 为什么也必须与 syscall_guard.c 一起编译：被测的就是那个文件里的
# syscall() 接管层。它有两次明确记录的事故都在"号码/位置"上
# （case 36 把 dirfd 当路径、case 260 把 wait4 当 linkat），所以本项
# 除正向判据外还带**负向判据**（172 getpid / 178 gettid / 148 / 150
# 不得被波及），防止"为了加身份把别的调用卷进来"。
#
# 编译参数收在 test/RUN_ID_SYSCALL.sh 里（只有一份，避免与别处漂移）。
# =====================================================================
run_step "身份 syscall 伪装" sh test/RUN_ID_SYSCALL.sh

# =====================================================================
# 6. crash 崩溃处理器
# =====================================================================
[ -f src/runtime/RUN_CRASH_TESTS.sh ] \
    && run_step "crash 崩溃处理器" sh src/runtime/RUN_CRASH_TESTS.sh \
    || run_step "crash 崩溃处理器"

# =====================================================================
# 7. D4 进程管理
# =====================================================================
if [ -f src/proc/RUN_TESTS.sh ]; then
    run_step "D4 进程管理" sh -c 'cd src/proc && sh RUN_TESTS.sh'
else
    run_step "D4 进程管理"
fi

# =====================================================================
# 8. 运行时构建 + 符号导出核对
# =====================================================================
#
# ★ 顺序很关键 ★ 构建必须排在第 9 项（wait 家族钩子）**之前** ——
# 那个测试用 dlopen 打开 build/libbxroot-runtime.so，没有产物就直接
# "找不到被测库"失败。这一点是在干净克隆里跑出来的：建库放在最后时，
# `--quick` 跳过构建 → wait 测试必然红。
#
# 另外 `--quick` 不再"静默跳过"：若产物已存在就照跑（不重新编译，
# 但符号导出核对仍然有效）；确实没有产物才跳过，且明确标注原因。
if [ "$QUICK" = 0 ]; then
    run_step "运行时构建" sh BUILD_RUNTIME.sh
elif [ -f build/libbxroot-runtime.so ]; then
    run_step "运行时构建" sh -c '
        SZ=$(wc -c < build/libbxroot-runtime.so)
        NSYM=$(nm -D --defined-only build/libbxroot-runtime.so 2>/dev/null | wc -l)
        echo "跳过重编译（--quick）；复用现有产物"
        echo "大小: $SZ 字节 / 导出符号: $NSYM"
        [ "$NSYM" -ge 300 ] || { echo "❌ 导出符号过少（$NSYM），产物可疑"; exit 1; }
        MISSING=""
        for s in fork vfork posix_spawn kill tgkill tkill system popen \
                 execve execvp execl waitpid wait4 wait3 waitid; do
            nm -D --defined-only build/libbxroot-runtime.so 2>/dev/null \
                | awk "{print \$3}" | grep -qx "$s" || MISSING="$MISSING $s"
        done
        if [ -n "$MISSING" ]; then
            echo "❌ 未导出的 D4 符号:$MISSING"; exit 1
        fi
        echo "✅ D4 进程管理符号全部导出（复用产物核对）"
    '
else
    note SKIP "运行时构建" "--quick 且无产物，wait 测试将跳过"
    printf '⏭️  %-26s 跳过（--quick 且无产物）\n' "运行时构建"
fi

# =====================================================================
# 8b. proot CLI 兼容性
# =====================================================================
#
# 独立于运行时构建（只编 launcher），所以放在构建之前也行。
# 它钉住「proot 的每个选项都有明确行为」这条契约 —— 这类东西最容易
# 在重构参数解析时悄悄退化（删掉一个不常用的别名，没有任何测试会红）。
if [ -f test/RUN_CLI_COMPAT.sh ]; then
    run_step "proot CLI 兼容" sh test/RUN_CLI_COMPAT.sh
else
    run_step "proot CLI 兼容"
fi

# ---------------------------------------------------------------------
# 8b-2. 上游 proot 选项表全覆盖（35 个选项名逐一对照）
# ---------------------------------------------------------------------
#
# 与上一项的分工：
#   RUN_CLI_COMPAT.sh  钉「每个已识别选项的**语义**对不对」（看输出内容）
#   本项                钉「上游选项表里的名字**一个都没漏**」（看识别与否）
#
# 为什么必须分开：`-l` 曾经就是被漏掉的那一个 —— 只认长名
# `--link2symlink`。漏别名的后果是**静默不生效**（不是报错）：用户的
# 启动脚本写 `-l`，l2s 全程没开，硬链接在 f2fs 上失败，错误现象
# （tar 解包 EPERM、pnpm 崩在无关步骤）离原因很远。
# 语义测试测不出"名字都没被认下"这种情况。
#
# 判据来源是**上游源码的选项表**（`cli/proot.h` 的 arguments[]），
# 不是 `--help` 文本 —— 因为一个 arguments[] 组里的多个名字共用
# 同一个 handler，只读 --help 必然漏别名。
# 有真实源码时用 `UPSTREAM_PROOT_H=/path/to/proot.h` 覆盖内置抄录表。
if [ -f test/RUN_UPSTREAM_CLI.sh ]; then
    run_step "上游 proot 选项表覆盖" sh test/RUN_UPSTREAM_CLI.sh
else
    run_step "上游 proot 选项表覆盖"
fi

# ---------------------------------------------------------------------
# 8b-3. 路径形态回归（裸相对名 / ./ 前缀 / 绝对 / dirfd+相对）
# ---------------------------------------------------------------------
#
# 动机来自一个**踩在 proroot 上的实际缺陷**（见
# `docs/proroot容器裸文件名堆溢出缺陷.md`）：proroot 容器内对"裸相对
# 文件名"做原地改写的工具 100% 堆溢出，加 `./` 就正常。那条缺陷最终
# 判定不是 bxroot 的，但它暴露了我们自己的盲区 ——
#
# ★ 既有测试全部在用「绝对 guest 路径」调用 ★
# `/bin/true`、`/etc/passwd`、`$ROOTFS/tmp/x`……
# 而"相对路径"恰恰是用户在容器里最常用的方式（`cat foo.txt`）。
# 绝对路径全绿**推不出**相对路径也对：裸名要走 getcwd 拼接、
# dirfd+相对要走 /proc/self/fd 解析，是完全不同的代码入口。
#
# 已记录在案的同型缺陷：`utimensat` 先只处理绝对路径，补了
# AT_FDCWD+相对后又漏了 dirfd+相对（dpkg 崩在第三种）。三种形态
# 三个入口，覆盖不全等于没覆盖。
if [ -f test/RUN_PATH_FORMS.sh ]; then
    run_step "路径形态回归" sh test/RUN_PATH_FORMS.sh
else
    run_step "路径形态回归"
fi

# =====================================================================
# D3 /proc 泄漏反向翻译（源码级单元，见 probe_d3_fixup.c 头注）
# =====================================================================
if [ -f test/RUN_D3_FIXUP.sh ]; then
    run_step "D3 /proc 泄漏反向翻译" sh test/RUN_D3_FIXUP.sh
fi

# =====================================================================
# D3 同族：realpath 返回值反向翻译（源码级单元，见 probe_realpath_fixup.c 头注）
# =====================================================================
#
# 与上一项的分工：上一项钉「readlink 系返回值」（/proc/fd、/proc/cwd），
# 本项钉「realpath 系返回值」（realpath / __realpath_chk /
# canonicalize_file_name 三个入口）。修前返回的是宿主绝对路径，
# tar/git 的绝对路径与路径相等性判断全错（评估报告 8.2）。
# 两者共用 strip_rootfs_prefix_inplace + detranslate_binds 反向核心。
if [ -f test/RUN_REALPATH_FIXUP.sh ]; then
    run_step "realpath 返回值反向翻译" sh test/RUN_REALPATH_FIXUP.sh
fi

# =====================================================================
# RAW_SYSCALL 透传开关（源码级单元，见 probe_raw_syscall.c 头注）
# =====================================================================
if [ -f test/RUN_RAW_SYSCALL.sh ]; then
    run_step "RAW_SYSCALL 透传开关" sh test/RUN_RAW_SYSCALL.sh
fi

# =====================================================================
# sigsys 裸系统调用号 / sigsetsize（源码级单元，见 probe_sigprocmask_num.c 头注）
# =====================================================================
#
# 为什么必须有这一项：src/runtime/sigsys.c 里"主线程解除 SIGSYS 屏蔽"
# 的裸调用曾同时错三处 —— 号写成 175（aarch64 上是 geteuid，正确是 135）、
# sigsetsize 传 128（内核只接受 8）、注释断言内核与 glibc 的 sigset_t 都是
# 128 字节（事实相反）。
#
# 后果是**完全静默**的：调用返回 0（因为 geteuid 本来就会成功），从不报错，
# 但 SIGSYS 屏蔽位原封不动 → 处理器装了收不到信号 → 进程被 159 杀掉。
# 编译、返回值、静态检查全都看不出问题，只有实测**副作用**才暴露。
if [ -f test/RUN_SIGSYS_NUM.sh ]; then
    run_step "sigsys 裸系统调用号/sigsetsize" sh test/RUN_SIGSYS_NUM.sh
fi

# =====================================================================
# 8c. l2s 端到端契约（依赖真机 rootfs；不在真机上会自行跳过）
# =====================================================================
#
# 为什么这个必须端到端：`test_l2s_rt.c` 是纯逻辑测试（全过），但
# **库正确 ≠ 接线正确**。实测缺口：bxroot 下 l2s 的"创建"那半正常
# （目录里有 .l2s.* 中间文件），"伪装"那半没生效 ——
#   官方: nlink=2 islink=false     bxroot: nlink=1 islink=true
# 纯逻辑测试注入的是 l2s 自己的 ops 表，走的路径与真实 stat 钩子不同，
# 所以永远测不出来。
#
# ★ 这是一项**已知缺陷**，当前预期就是 FAIL ★
# 用 BXROOT_KNOWN_FAIL 标记：失败时记为"已知缺陷"而不是"回归失败"，
# 免得整轮回归长期红着、掩盖别的新问题。修复后把该变量去掉即可。
if [ -f test/RUN_L2S_E2E.sh ]; then
    run_step "l2s 端到端契约" sh test/RUN_L2S_E2E.sh
else
    run_step "l2s 端到端契约"
fi

# =====================================================================
# 9. wait 家族钩子（依赖上一步的构建产物）
# =====================================================================
if [ -f test/RUN_WAIT_TESTS.sh ] && [ -f build/libbxroot-runtime.so ]; then
    run_step "wait 家族钩子" sh test/RUN_WAIT_TESTS.sh
elif [ -f test/RUN_WAIT_TESTS.sh ]; then
    note SKIP "wait 家族钩子" "无 build/libbxroot-runtime.so"
    printf '⏭️  %-26s 跳过（缺构建产物）\n' "wait 家族钩子"
else
    run_step "wait 家族钩子"
fi

# =====================================================================
# 9b. dl 家族契约（dlerror / dlsym 同源 + dl_iterate_phdr 模块视图）
# =====================================================================
#
# ★ 本项**只新增判据，不改动上面任何一项的判据** ★
#
# 为什么必须单列一项：这两个符号的缺陷**编译期完全看不出来**，
# 只有真的挂在 proroot linker 下跑才有判据 ——
#   - dlerror 恒 NULL（本库 dlsym 走 linker 服务，不写 glibc 的
#     __libc_dlerror_result），症状是"失败原因被静默吞掉"；
#   - dl_iterate_phdr 模块视图从 N 个塌成 1 个。
# 而且二者互为前提：修 dlerror 若做"薄转发"会解析回本库自己 →
# 无限自递归 → SIGSEGV；能拦住它的自递归检测垫片又依赖
# dl_iterate_phdr 的完整视图（详见 docs/dl家族符号修复.md）。
#
# 依赖构建产物；构建在非 --quick 时已由第 8 项完成。
# 在非真机/无 proroot linker 的环境里，脚本自己会明确 SKIP 并 exit 0。
if [ -f test/RUN_DL_TESTS.sh ]; then
    run_step "dl 家族契约" sh test/RUN_DL_TESTS.sh
else
    run_step "dl 家族契约"
fi

# ---------------------------------------------------------------------
# 9c. system()/popen() 子进程契约
# ---------------------------------------------------------------------
# 这两个符号**曾经长期是坏的**（所有 exec 出来的子进程都起不来），
# 而当时的回归**完全没发现** —— 因为旧检查只 grep `nm -D` 的符号表，
# 看 `system`/`popen` 是否导出。符号导出是**必要**条件，不是充分条件。
#
# 这个脚本真的去调 system()/popen()，并验证子进程里**路径翻译仍生效**
# （防止用"关掉功能"换"不报错"——只清 environ 会让 system() 返回 0，
# 但子进程实际跑在宿主 Android 的 /system/bin/sh 上，即"静默越狱"）。
#
# 详见 docs/子进程全部失败-LD_PRELOAD注入缺陷.md
if [ -f test/RUN_SYSTEM_POPEN.sh ]; then
    run_step "system/popen 子进程" sh test/RUN_SYSTEM_POPEN.sh
else
    run_step "system/popen 子进程"
fi

# ---------------------------------------------------------------------
# 9d. pthread_create 栈下限契约
# ---------------------------------------------------------------------
# 与官方逐档对照"真实栈大小"（不只是返回码 —— 旧现象正是 rc=0 但栈太小、
# 随后 SIGSEGV）。详见 docs/pthread_create栈哨兵修复.md
if [ -f test/RUN_PTHREAD_CREATE.sh ]; then
    run_step "pthread_create 栈" sh test/RUN_PTHREAD_CREATE.sh
else
    run_step "pthread_create 栈"
fi

# ---------------------------------------------------------------------
# 9e. shebang 脚本直接 exec 契约
# ---------------------------------------------------------------------
# `sh script.sh` 两侧本来就是好的，所以这个缺陷**只有测"直接 exec 脚本文件"
# 才抓得到**。修前 bxroot 报 `bad read`（linker 只认 ELF）；修法是按内核语义
# 改写 argv 后 exec 解释器。详见 docs/shebang脚本无法执行修复.md
if [ -f test/RUN_SHEBANG.sh ]; then
    run_step "shebang 脚本 exec" sh test/RUN_SHEBANG.sh
else
    run_step "shebang 脚本 exec"
fi

# ---------------------------------------------------------------------
# 9f. 降权族（缺口 C）—— 真实程序 chage 验收
# ---------------------------------------------------------------------
# 修前 `chage -l root` 报 `failed to drop privileges (Function not
# implemented)`（官方 rc=0 正常输出）。根因是符号层与 syscall 层**两条**
# 路径都没覆盖降权族，而真实程序走的是符号层那条（`readelf` 证实 chage
# 引用 `setreuid` 符号、零处 svc）。
#
# 判据含"账本自洽"一条 —— 那是"假装返回 0"与"真账本"的分水岭：
# 只返回 0 而回读没变，程序会看到自相矛盾的世界（比报错更难查）。
# 详见 docs/缺口B-身份查询族修复.md 与 docs/身份查询与降权族-原始数据.md
if [ -f test/RUN_PRIVDROP.sh ]; then
    run_step "降权族 chage" sh test/RUN_PRIVDROP.sh
else
    run_step "降权族 chage"
fi

# =====================================================================
# 10. 可选端到端
# =====================================================================
if [ "$DO_E2E" = 1 ]; then
    if [ -f test/RUN_E2E.sh ] && [ -d /data/data/com.dsh.client ]; then
        run_step "端到端 dsh" sh test/RUN_E2E.sh --version
    else
        note SKIP "端到端 dsh" "非真机环境"
        printf '⏭️  %-26s 跳过（需真机 rootfs）\n' "端到端 dsh"
    fi
fi

# =====================================================================
# 汇总
# =====================================================================
echo
echo "======================================================"
echo " 回归汇总"
echo "======================================================"
while IFS='|' read -r st nm sm; do
    case "$st" in
    PASS) printf '  ✅ %-24s %s\n' "$nm" "$sm" ;;
    FAIL) printf '  ❌ %-24s %s\n' "$nm" "$sm" ;;
    SKIP) printf '  ⏭️  %-24s %s\n' "$nm" "$sm" ;;
    KNOWN) printf '  ⚠️  %-24s %s\n' "$nm" "$sm" ;;
    esac
done < "$RESULT_FILE"
echo "------------------------------------------------------"
echo "  通过 $PASS / 失败 $FAIL$([ "$KNOWN" -gt 0 ] && echo " / 已知缺陷 $KNOWN")"
rm -f "$RESULT_FILE"

if [ "$FAIL" -gt 0 ]; then
    echo "  ❌ 回归未通过"
    exit 1
fi
echo "  ✅ 全部通过"
exit 0
