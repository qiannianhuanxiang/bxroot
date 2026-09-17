#!/bin/sh
# =====================================================================
# 降级路径回归 —— 「无 ldso 服务」环境下的 dl 家族
# =====================================================================
#
# 由来（这一项是被用户报告逼出来的）
# ---------------------------------
# 一位用户在**纯 Linux（Ubuntu 24.04 / aarch64 / 外层 proot 沙箱）**
# 环境下评估 bxroot 0.1.0，报出三个 P0，其中两个都在**降级路径**上：
#
#   1. `LD_PRELOAD=libbxroot-runtime.so /bin/true`
#      → `symbol lookup error: undefined symbol: ldso_service_dlsym_global`
#      （加载即崩，构造函数都没机会跑）
#   2. 修掉 1 之后，`bash` 启动即 `SEGV pc=0x0`
#      （自研 `dlsym` 的无服务分支直接 `return NULL`，客户程序 call NULL）
#
# 而报告里最有价值的一句是这个**元问题**：
#
#   「降级路径零测试覆盖。这就是三个 P0 都能活过仓库的原因：
#     它们全在降级路径上。」
#
# 这个判断是对的。本库的降级路径在开发环境里**根本走不到** ——
# Android 真机有 linker 服务，本容器也有（官方 proroot 的 linker 就在
# 进程里），所以所有既有测试跑的都是"有服务"那条路。
#
# ★ 本测试解决的就是"走不到"这件事 ★
# `BXROOT_FORCE_NO_LDSO_SERVICE=1` 让服务判断强制返回"无服务"，
# 从而让降级路径**在当前环境里被真实执行**。这个开关只影响走哪条分支，
# 不改业务语义；生产不设它，行为与从前一致。
#
# 为什么不能只靠"改弱符号 + 肉眼看代码"
# ------------------------------------
# 本次修复过程中我自己就踩了一次：先用裸跑 `/tmp/fbtest` 验证降级
# 路径"成功"，后来查 `/proc/<pid>/maps` 才发现**探针压根没加载 runtime**
# —— 那次"验证通过"测的是 libc 自己的 dlsym，与我们的代码无关。
# 所以本测试有一条硬判据：**必须先证明 runtime 真的被加载了**，
# 否则整项 SKIP（而不是 PASS）。
#
# 用法
# ----
#   sh test/RUN_FALLBACK.sh
#
# 退出码
# ------
#   0 = 全过（允许 SKIP）   1 = 有回归   2 = 环境不满足（整项 SKIP）
# =====================================================================

set -u

SELF_DIR=$(dirname "$0")
ROOT=$(cd "$SELF_DIR/.." && pwd)
cd "$ROOT" || { echo "❌ 无法进入仓库根目录"; exit 2; }

CC="${CC:-gcc}"
command -v "$CC" >/dev/null 2>&1 || { echo "❌ 找不到编译器 $CC"; exit 2; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-fallback-XXXXXX" 2>/dev/null) || exit 2
trap 'rm -rf "$WORK"' EXIT INT TERM

[ -f build/libbxroot-runtime.so ] || {
    echo "⏭  build/libbxroot-runtime.so 不存在 —— 先跑 BUILD_RUNTIME.sh"
    exit 2
}

PASS=0; FAIL=0; FAILED_LIST=""
ok()  { PASS=$((PASS+1)); printf '  ✅ %-42s %s\n' "$1" "$2"; }
bad() { FAIL=$((FAIL+1)); FAILED_LIST="$FAILED_LIST $1"; printf '  ❌ %-42s %s\n' "$1" "$2"; }

# ---------------------------------------------------------------------
# 编译（带 ICE 重试；以产物存在为准）
# ---------------------------------------------------------------------
build_c() {
    _src="$1"; _out="$2"; shift 2; _i=1
    while [ "$_i" -le 10 ]; do
        if "$CC" -O0 "$@" -o "$_out" "$_src" 2>"$WORK/cc.err"; then
            [ -f "$_out" ] && return 0
        fi
        grep -q 'internal compiler error' "$WORK/cc.err" || {
            echo "❌ 编译失败（非 ICE）: $_src"; cat "$WORK/cc.err"; return 1
        }
        _i=$((_i + 1))
    done
    echo "❌ 编译 10 次均撞 ICE: $_src"; return 1
}

# launcher：静态二进制，**名字不能以 .so 结尾**（否则 glibc _dl_get_origin 断言崩）
LAUNCHER="$WORK/bxroot-bin"
_i=1
while [ "$_i" -le 10 ]; do
    if "$CC" -static -O1 -Wall -Wextra -Wno-nonnull-compare \
        -o "$LAUNCHER" src/launcher/launcher.c 2>"$WORK/lcc.err"; then
        break
    fi
    grep -q 'internal compiler error' "$WORK/lcc.err" || {
        echo "❌ launcher 编译失败"; cat "$WORK/lcc.err"; exit 2
    }
    _i=$((_i + 1))
done
[ -x "$LAUNCHER" ] || { echo "❌ launcher 编译 10 次均撞 ICE"; exit 2; }

# ---------------------------------------------------------------------
# 探针 1：dl 家族 —— 别名（symbol alias）与句柄查找都要能拿到真身
# ---------------------------------------------------------------------
cat > "$WORK/dlprobe.c" <<'EOF'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

static int fails;
static void chk(const char *what, void *p) {
    printf("  %-34s = %p  %s\n", what, p, p ? "非空" : "NULL");
    if (p == NULL) fails++;
}

int main(void) {
    void *h;
    printf("[dl 家族 · 降级路径]\n");

    /* 1) dlsym(RTLD_DEFAULT, ...) —— 最高频入口，就是原来 return NULL 的那个 */
    chk("dlsym(RTLD_DEFAULT,malloc)", dlsym(RTLD_DEFAULT, "malloc"));
    chk("dlsym(NULL,malloc)",         dlsym(NULL, "malloc"));

    /* 2) 带句柄 */
    h = dlopen("libm.so.6", RTLD_NOW);
    if (h == NULL) {
        printf("  dlopen(libm.so.6) 失败: %s\n", dlerror());
        /* 不是本测试的关注点，不判失败；但后面依赖句柄的用例要跳过 */
    }
    chk("dlsym(handle,cos)", h ? dlsym(h, "cos") : (void *)1);

    /* 3) dlsym(RTLD_NEXT, ...) —— 依赖调用方返回地址，最易错 */
    {
        void *p = dlsym(RTLD_NEXT, "malloc");
        printf("  %-34s = %p  %s\n", "dlsym(RTLD_NEXT,malloc)", p,
               p ? "非空" : "(NULL 可接受：本库之后可能真没有)");
    }

    /* 4) dl_iterate_phdr 降级：必须能枚举出至少主程序自身 */
    {
        extern int dl_iterate_phdr(int (*)(struct dl_phdr_info *, size_t, void *), void *);
        printf("  （dl_iterate_phdr 单独在 dliterprobe 里测）\n");
    }

    printf("dlprobe: fails=%d\n", fails);
    return fails ? 1 : 0;
}
EOF

# ---------------------------------------------------------------------
# 探针 2：dl_iterate_phdr / dladdr 降级
# ---------------------------------------------------------------------
cat > "$WORK/dliterprobe.c" <<'EOF'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <string.h>

static int n_mod;
static int cb(struct dl_phdr_info *info, size_t sz, void *data) {
    (void)sz; (void)data;
    n_mod++;
    return 0;
}

int main(void) {
    int rc;
    printf("[dl_iterate_phdr / dladdr · 降级路径]\n");

    rc = dl_iterate_phdr(cb, NULL);
    printf("  dl_iterate_phdr rc=%d 枚举到 %d 个模块\n", rc, n_mod);

    /* 判据：至少要枚举出主程序自己（1 个）。0 个说明降级实现没接上。 */
    if (n_mod < 1) { printf("dliterprobe: FAIL(模块数=0)\n"); return 1; }

    /* dladdr 对主程序内的一个地址应当命中 */
    {
        Dl_info di;
        memset(&di, 0, sizeof di);
        rc = dladdr((void *)&main, &di);
        printf("  dladdr(&main) rc=%d fname=%s\n", rc, di.dli_fname ? di.dli_fname : "(null)");
        /* dladdr 在降级路径下允许失败（glibc 版未必给 fbase）——
         * 只要求"不崩"，不要求必成功。 */
    }

    printf("dliterprobe: ok 模块数=%d\n", n_mod);
    return 0;
}
EOF

# ---------------------------------------------------------------------
# 探针 3：加载期可用性 —— 这是 P0-2.1 的直接判据
# ---------------------------------------------------------------------
cat > "$WORK/loadprobe.c" <<'EOF'
/* 只做一件最小的事：证明"加载了 runtime 之后程序还能正常跑"。
 * 原先这里连构造函数都跑不到就 symbol lookup error。 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
    /* `-s <秒>`：睡一会儿，供外部查 /proc/<pid>/maps 确认库真的加载了。
     * ★ 这个模式是必要的 ★ 程序瞬间退出时 maps 根本来不及读，
     * 会让"前提检查"永远 SKIP（实测踩过）。 */
    if (argc >= 3 && argv[1][0] == '-' && argv[1][1] == 's')
        sleep((unsigned)atoi(argv[2]));
    printf("loadprobe: alive\n");
    return 0;
}
EOF

build_c "$WORK/dlprobe.c"     "$WORK/dlprobe"     || exit 2
build_c "$WORK/dliterprobe.c" "$WORK/dliterprobe" || exit 2
build_c "$WORK/loadprobe.c"   "$WORK/loadprobe"   || exit 2

# ---------------------------------------------------------------------
# ★ 硬前提：证明 runtime 真的被加载了 ★
# ---------------------------------------------------------------------
# 没有这一步，本测试可能测的是 libc 自己 —— 那就完全没意义。
# 实测教训：本次修复过程中用裸跑验证过一次，结论是"通过"，
# 后来查 maps 才发现探针根本没加载 runtime。
#
# ★ 为什么要显式指定 BXROOT_RUNTIME ★
# launcher 会自己推导 runtime 路径（默认往 /tmp/libbxroot-runtime.so 找），
# 而本测试的产物在 `build/` 下、且当前 shell 可能带着别人的环境变量。
# 不显式指定就会出现"launcher 报 stat OK、程序也跑了，但 maps 里
# **没有我们的库**"这种假绿 —— 正是本测试要防的那类错误。
#
# 路径要用 `/proc/self/root` 前缀：本容器在 proroot 内，launcher 把路径
# 交给内核时不做翻译，而 `/proc/self/root/...` 是"翻译前"的可靠写法。
RT_SO="/proc/self/root$ROOT/build/libbxroot-runtime.so"

echo "== 前提检查：runtime 是否真的被加载 =="
echo "  runtime: $RT_SO"
BXROOT_RUNTIME="$RT_SO" "$LAUNCHER" -r / -w / "$WORK/loadprobe" -s 3 >"$WORK/load.out" 2>&1 &
LP=$!
sleep 1.0
LOADED=0
if grep -q "libbxroot-runtime" "/proc/$LP/maps" 2>/dev/null; then LOADED=1; fi
wait "$LP" 2>/dev/null

if [ "$LOADED" -ne 1 ]; then
    echo "⏭  无法确认 runtime 被加载 —— 本项 SKIP"
    echo "    输出：$(head -3 "$WORK/load.out")"
    echo "    ★ 宁可不测，也不要测一个假的东西 ★"
    exit 2
fi
echo "  ✅ runtime 已在目标进程的 maps 里"
echo

# ---------------------------------------------------------------------
# 判据 A：加载期不崩（对应 P0-2.1）
# ---------------------------------------------------------------------
echo "== A) 加载期可用性（P0-2.1 判据）=="
BXROOT_RUNTIME="$RT_SO" "$LAUNCHER" -r / -w / "$WORK/loadprobe" >"$WORK/a.out" 2>&1
A_RC=$?
if [ "$A_RC" -eq 0 ] && grep -q "loadprobe: alive" "$WORK/a.out"; then
    ok "加载后程序存活" "rc=0"
else
    bad "加载后程序存活" "rc=$A_RC $(head -1 "$WORK/a.out")"
fi
# 明确覆盖"symbol lookup error"这个具体现象
if grep -q "symbol lookup error" "$WORK/a.out"; then
    bad "无 symbol lookup error" "$(grep -m1 'symbol lookup error' "$WORK/a.out")"
else
    ok "无 symbol lookup error" "（P0-2.1 的直接判据）"
fi
echo

# ---------------------------------------------------------------------
# 判据 B：强制降级路径下的 dl 家族（对应 P0-2.2）
# ---------------------------------------------------------------------
echo "== B) 强制降级路径：dl 家族 =="
BXROOT_RUNTIME="$RT_SO" BXROOT_FORCE_NO_LDSO_SERVICE=1 "$LAUNCHER" -r / -w / "$WORK/dlprobe" >"$WORK/b.out" 2>&1
B_RC=$?
sed 's/^/   /' "$WORK/b.out"
if [ "$B_RC" -eq 0 ]; then
    ok "降级路径 dlsym 转发" "rc=0（P0-2.2 的直接判据）"
else
    bad "降级路径 dlsym 转发" "rc=$B_RC"
fi
# 崩在 0x0 是 call NULL 的特征 —— 单独判一次，便于一眼识别回归
if grep -qE "SEGV pc=0x0|pc=0x0000000000000000" "$WORK/b.out"; then
    bad "无 call NULL" "出现 pc=0x0（dlsym 又返回 NULL 了）"
else
    ok "无 call NULL" "（P0-2.2 的特征现象未出现）"
fi
echo

# ---------------------------------------------------------------------
# 判据 C：强制降级路径下的 dl_iterate_phdr / dladdr
# ---------------------------------------------------------------------
echo "== C) 强制降级路径：dl_iterate_phdr / dladdr =="
BXROOT_RUNTIME="$RT_SO" BXROOT_FORCE_NO_LDSO_SERVICE=1 "$LAUNCHER" -r / -w / "$WORK/dliterprobe" >"$WORK/c.out" 2>&1
C_RC=$?
sed 's/^/   /' "$WORK/c.out"
if [ "$C_RC" -eq 0 ]; then
    ok "降级路径模块枚举" "rc=0"
else
    bad "降级路径模块枚举" "rc=$C_RC"
fi
echo

# ---------------------------------------------------------------------
# 判据 D：有服务路径未被破坏（回归保护）
# ---------------------------------------------------------------------
# ★ 这一条很重要 ★ 修降级路径时最容易顺手把正常路径改坏，
# 而正常路径才是 Android 真机上的主战场。
echo "== D) 有服务路径未回归（Android 主战场）=="
BXROOT_RUNTIME="$RT_SO" "$LAUNCHER" -r / -w / "$WORK/dlprobe" >"$WORK/d.out" 2>&1
D_RC=$?
sed 's/^/   /' "$WORK/d.out"
if [ "$D_RC" -eq 0 ]; then
    ok "有服务路径 dl 家族" "rc=0"
else
    bad "有服务路径 dl 家族" "rc=$D_RC（正常路径被改坏了！）"
fi
echo

echo "======================================================"
echo " 通过 $PASS / 失败 $FAIL"
if [ "$FAIL" -gt 0 ]; then
    echo " 失败项:$FAILED_LIST"
    echo "RESULT: FAIL"
    exit 1
fi
echo "RESULT: PASS"
exit 0
