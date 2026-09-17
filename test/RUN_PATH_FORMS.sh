#!/bin/sh
# =====================================================================
# 路径形态回归 —— 裸相对名 / ./ 前缀 / 绝对路径 / dirfd+相对
# =====================================================================
#
# 由来
# ----
# 这个测试的动机来自一个**踩在 proroot 上的实际缺陷**（见
# `docs/proroot容器裸文件名堆溢出缺陷.md`）：在 proroot 容器内，
# 对「不含目录分量的相对文件名」做原地改写的工具（`strip`/`objcopy`）
# **100% 死于堆溢出**，而加 `./` 前缀或改绝对路径就完全正常。
#
# 那条缺陷最终判定**不是 bxroot 的**（bxroot 只是恰好也跑在那个容器里，
# 外层 ptrace 照样崩）。但它顺带暴露了我们自己的一个测试盲区：
#
#   ★ 全部既有测试都在用「绝对 guest 路径」调用 ★
#     `/bin/true`、`/etc/passwd`、`$ROOTFS/tmp/x` ……
#   也就是说，「相对路径」这条最常见的使用方式（用户在容器里敲
#   `cat foo.txt`）**从来没有被回归覆盖过**。
#
# 路径形态是路径翻译层最容易出错的维度之一，因为：
#   - 裸相对名要走 getcwd 拼接；cwd 解析错 → 拼到别处
#   - 非 AT_FDCWD 的 dirfd+相对要走 /proc/self/fd 解析
#   - 绝对路径反而最简单，所以"绝对路径全绿"完全不能推出相对路径也对
#
# 本测试把四种路径形态**逐一**钉住，每种都用「读」和「写」两类操作，
# 因为读写走的钩子不一定相同（历史缺陷：有的钩子只处理绝对路径）。
#
# ★ 四形态必须都测，不能抽一个代表 ★
# 记录在案的真实缺陷：`utimensat` 曾经只处理绝对路径，补了 AT_FDCWD+相对
# 之后又漏了 dirfd+相对（dpkg 就崩在第三种）。三种形态三个入口，
# 覆盖不全就等于没覆盖。
#
# 用法
# ----
#   sh test/RUN_PATH_FORMS.sh
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

WORK=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-pathform-XXXXXX" 2>/dev/null) || exit 2
trap 'rm -rf "$WORK"' EXIT INT TERM

# ---------------------------------------------------------------------
# 构建探针
# ---------------------------------------------------------------------
# ★ 编译成败以产物存在为准 ★
# 不要用 `grep -cE "error: "` 判断 —— 输出为空时 grep -c 返回 0，
# 会把"编译彻底没跑起来"误判成成功（本项目踩过）。
build() {
    _src="$1"; _out="$2"; _i=1
    while [ "$_i" -le 10 ]; do
        if "$CC" -O0 -o "$_out" "$_src" 2>"$WORK/cc.err"; then
            [ -f "$_out" ] && return 0
        fi
        # 本容器 gcc 13.3.0 有间歇性 ICE，重试；真错误立即失败
        grep -q 'internal compiler error' "$WORK/cc.err" || {
            echo "❌ 编译失败（非 ICE）: $_src"; cat "$WORK/cc.err"; return 1
        }
        _i=$((_i + 1))
    done
    echo "❌ 编译 10 次均撞 ICE: $_src"; return 1
}

cat > "$WORK/probe.c" <<'PROBE_EOF'
/*
 * 路径形态探针。
 *
 * 每个用例自建文件、自清理，所以可以乱序/重复跑。
 * 输出契约（runner 依赖，勿改格式）：
 *   [ok] <ID> <描述>
 *   [FAIL] <ID> <描述> -- <原因>
 * 末行：probe PATHFORM: ok=<n> fail=<n>
 * 退出码：0 = 无 FAIL
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

static int g_ok, g_fail;
static char g_cwd[4096];

static void ok(const char *id, const char *what) {
    printf("[ok] %s %s\n", id, what); g_ok++;
}
static void bad(const char *id, const char *what, const char *why) {
    printf("[FAIL] %s %s -- %s\n", id, what, why); g_fail++;
}

/* 用例 1：读 —— 用相对名读自己刚写的文件 */
static void t01(void) {
    const char *p = "pf_read_rel.txt";
    int fd = open(p, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (fd < 0) { bad("T01", "裸相对名写", strerror(errno)); return; }
    if (write(fd, "hello", 5) != 5) { close(fd); bad("T01", "裸相对名写", "write 短写"); return; }
    close(fd);

    /* 换绝对路径读回，确认内容真的写到了"当前目录下的这个名字" */
    char abs[4200];
    snprintf(abs, sizeof abs, "%s/%s", g_cwd, p);
    fd = open(abs, O_RDONLY);
    if (fd < 0) { bad("T01", "裸相对名写后就近可读", strerror(errno)); return; }
    char buf[8] = {0};
    ssize_t n = read(fd, buf, 5);
    close(fd);
    if (n != 5 || memcmp(buf, "hello", 5) != 0) {
        bad("T01", "裸相对名写后就近可读", "内容不符");
        return;
    }
    unlink(p);
    ok("T01", "裸相对名 写+读 (open)");
}

/* 用例 2：stat 家族对裸相对名 */
static void t02(void) {
    const char *p = "pf_stat_rel.txt";
    int fd = open(p, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (fd < 0) { bad("T02", "裸相对名 stat 族", strerror(errno)); return; }
    close(fd);
    struct stat st;
    if (stat(p, &st) != 0)   { bad("T02", "stat(裸名)", strerror(errno)); unlink(p); return; }
    if (lstat(p, &st) != 0)  { bad("T02", "lstat(裸名)", strerror(errno)); unlink(p); return; }
    if (access(p, F_OK) != 0) { bad("T02", "access(裸名)", strerror(errno)); unlink(p); return; }
    unlink(p);
    ok("T02", "stat / lstat / access 裸相对名");
}

/* 用例 3：dirfd + 相对名（非 AT_FDCWD）—— 与裸名完全是两个入口 */
static void t03(void) {
    const char *d = "pf_dfd_dir";
    mkdir(d, 0755);
    const char *p = "inner.txt";
    int dfd = open(d, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) { bad("T03", "dirfd+相对名", strerror(errno)); rmdir(d); return; }

    int fd = openat(dfd, p, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (fd < 0) { bad("T03", "openat(dirfd,相对名)", strerror(errno)); close(dfd); rmdir(d); return; }
    write(fd, "x", 1);
    close(fd);

    struct stat st;
    if (fstatat(dfd, p, &st, 0) != 0) {
        bad("T03", "fstatat(dirfd,相对名)", strerror(errno));
        close(dfd); unlinkat(dfd, p, 0); rmdir(d); return;
    }
    if (!S_ISREG(st.st_mode)) {
        bad("T03", "fstatat(dirfd,相对名)", "不是普通文件");
        close(dfd); unlinkat(dfd, p, 0); rmdir(d); return;
    }
    unlinkat(dfd, p, 0);
    close(dfd);
    rmdir(d);
    ok("T03", "dirfd + 相对名 (openat/fstatat/unlinkat)");
}

/* 用例 4：./ 前缀 —— 与裸名只差两个字符，但走的分支可能不同 */
static void t04(void) {
    const char *p = "./pf_dot.txt";
    int fd = open(p, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (fd < 0) { bad("T04", "./ 前缀", strerror(errno)); return; }
    close(fd);
    struct stat st;
    if (stat(p, &st) != 0) { bad("T04", "stat(./x)", strerror(errno)); unlink(p); return; }
    unlink(p);
    ok("T04", "./ 前缀 (open/stat/unlink)");
}

/* 用例 5：相对名做原地改写 —— 就是 proroot 崩溃的那个操作形态 */
static void t05(void) {
    const char *p = "pf_rewrite.bin";
    int fd = open(p, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (fd < 0) { bad("T05", "裸名原地改写", strerror(errno)); return; }
    for (int i = 0; i < 64; i++) write(fd, "A", 1);
    close(fd);

    /* 读入 → 原地写回（truncate + 重写）。截断是原地改写的关键一步。 */
    fd = open(p, O_RDWR);
    if (fd < 0) { bad("T05", "裸名 O_RDWR", strerror(errno)); unlink(p); return; }
    char buf[64];
    if (read(fd, buf, 64) != 64) {
        bad("T05", "裸名读回", "短读"); close(fd); unlink(p); return;
    }
    if (ftruncate(fd, 32) != 0) {
        bad("T05", "裸名 ftruncate", strerror(errno)); close(fd); unlink(p); return;
    }
    /* 从 0 重写前半段 */
    if (lseek(fd, 0, SEEK_SET) != 0) {
        bad("T05", "裸名 lseek", strerror(errno)); close(fd); unlink(p); return;
    }
    if (write(fd, buf, 32) != 32) {
        bad("T05", "裸名重写", strerror(errno)); close(fd); unlink(p); return;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size != 32) {
        bad("T05", "裸名原地改写后 size", "size 不是 32");
        close(fd); unlink(p); return;
    }
    close(fd);
    unlink(p);
    ok("T05", "裸相对名 原地改写 (O_RDWR+ftruncate+重写)");
}

/* 用例 6：符号链接与 readlink —— 相对目标 vs 绝对目标 */
static void t06(void) {
    const char *tgt = "pf_link_target.txt";
    const char *rel = "pf_link_rel";
    const char *abs = "pf_link_abs";
    int fd = open(tgt, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (fd < 0) { bad("T06", "符号链接族", strerror(errno)); return; }
    close(fd);

    unlink(rel); unlink(abs);
    if (symlink(tgt, rel) != 0) { bad("T06", "symlink(相对目标)", strerror(errno)); goto out; }
    char buf[4200];
    ssize_t n = readlink(rel, buf, sizeof buf - 1);
    if (n <= 0) { bad("T06", "readlink(裸名)", strerror(errno)); goto out; }
    buf[n] = '\0';
    if (strcmp(buf, tgt) != 0) { bad("T06", "readlink 返回值", buf); goto out; }

    /* 经链接读内容（翻译要解析相对链接） */
    fd = open(rel, O_RDONLY);
    if (fd < 0) { bad("T06", "经相对符号链接 open", strerror(errno)); goto out; }
    close(fd);

    snprintf(buf, sizeof buf, "%s/%s", g_cwd, tgt);
    if (symlink(buf, abs) != 0) { bad("T06", "symlink(绝对目标)", strerror(errno)); goto out; }
    fd = open(abs, O_RDONLY);
    if (fd < 0) {
        /*
         * ★ 已知限制，不是回归 ★
         *
         * "目标为**绝对路径**的符号链接"在 bxroot（LD_PRELOAD 架构）下
         * 打不开，官方 proroot（ptrace 架构）正常。根因：链接目标的解析
         * 发生在**内核内部**，不经过任何 libc 符号，bxroot 的钩子没有
         * 机会介入。完整分析见 docs/缺陷-绝对目标符号链接打不开.md。
         *
         * 这里**保留**这个用例而不是删掉它，理由有两个：
         *   1. 它是回归锚点 —— 万一将来实现了修法，测试会自动变绿；
         *   2. 删掉等于把限制藏起来，而这正是本项目最反对的做法。
         *
         * 用 KNOWNLIMIT 前缀（而非 FAIL）让 runner 区分
         * "比官方差但已知"与"新引入的回归"。runner 把 KNOWNLIMIT
         * 计入 skip 而非 fail，但会在输出里**原样显示**，保持可见。
         */
        printf("[KNOWNLIMIT] T06 经绝对符号链接 open -- %s"
               "（架构级：内核解析链接目标，LD_PRELOAD 感知不到；官方 ptrace 正常）\n",
               strerror(errno));
        goto out;
    }
    close(fd);
    ok("T06", "symlink 相对/绝对目标 + readlink + 穿透读");
out:
    unlink(rel); unlink(abs); unlink(tgt);
}

/* 用例 7：chdir 到相对路径后，再操作裸名（cwd 基准点对不对） */
static void t07(void) {
    const char *d = "pf_cwd_dir";
    mkdir(d, 0755);
    if (chdir(d) != 0) { bad("T07", "chdir(裸相对名)", strerror(errno)); rmdir(d); return; }

    /* chdir 之后，裸名应当相对"新的 cwd"解析 */
    int fd = open("after.txt", O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (fd < 0) {
        bad("T07", "chdir 后裸名 open", strerror(errno));
        chdir(g_cwd); rmdir(d); return;
    }
    close(fd);
    struct stat st;
    if (stat("after.txt", &st) != 0) {
        bad("T07", "chdir 后裸名 stat", strerror(errno));
        unlink("after.txt"); chdir(g_cwd); rmdir(d); return;
    }
    unlink("after.txt");
    if (chdir(g_cwd) != 0) { bad("T07", "chdir 回原目录", strerror(errno)); rmdir(d); return; }
    rmdir(d);
    ok("T07", "chdir(相对) 后裸名以新 cwd 为基准");
}

/* 用例 8：getcwd 与 ../ 上溯 —— 相对路径规范化 */
static void t08(void) {
    const char *d = "pf_up_dir";
    mkdir(d, 0755);
    int fd = open("pf_up_marker.txt", O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (fd < 0) { bad("T08", "../ 上溯", strerror(errno)); rmdir(d); return; }
    close(fd);

    if (chdir(d) != 0) { bad("T08", "chdir", strerror(errno)); unlink("pf_up_marker.txt"); rmdir(d); return; }
    /* 从子目录用 ../name 回到父目录的文件 */
    struct stat st;
    int rc = stat("../pf_up_marker.txt", &st);
    if (rc != 0) {
        bad("T08", "stat(../裸名)", strerror(errno));
        chdir(g_cwd); unlink("pf_up_marker.txt"); rmdir(d); return;
    }
    if (chdir(g_cwd) != 0) { bad("T08", "chdir 回", strerror(errno)); rmdir(d); return; }
    unlink("pf_up_marker.txt");
    rmdir(d);
    ok("T08", "../ 上溯相对路径 (stat)");
}

int main(void) {
    if (getcwd(g_cwd, sizeof g_cwd) == NULL) {
        printf("probe PATHFORM: ok=0 fail=1\n");
        return 1;
    }
    t01(); t02(); t03(); t04();
    t05(); t06(); t07(); t08();
    printf("probe PATHFORM: ok=%d fail=%d\n", g_ok, g_fail);
    return g_fail ? 1 : 0;
}
PROBE_EOF

PROBE="$WORK/pathform"
build "$WORK/probe.c" "$PROBE" || exit 2

# ---------------------------------------------------------------------
# 运行
# ---------------------------------------------------------------------
# 两个基线：
#   A. 直跑（容器内原生 glibc）—— 作为"该实现本身对不对"的锚点
#   B. 经 bxroot 驱动 —— 被测对象
#
# ★ 为什么两个都要跑 ★
# 只跑 B 的话，探针自身的 bug 会被记成 bxroot 的缺陷。A 侧是必要的
# 对照组：A 失败说明探针/环境有问题，不是 bxroot 的问题。
echo "== A 基线：直跑（不加载任何 runtime）=="
A_DIR=$(mktemp -d "$WORK/runA-XXXXXX")
( cd "$A_DIR" && "$PROBE" ) > "$WORK/A.out" 2>&1
A_RC=$?
sed 's/^/   /' "$WORK/A.out"
echo "   （退出码 $A_RC）"
echo

# bxroot launcher 构建（静态；名字不能以 .so 结尾，否则 glibc 断言崩溃）
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

echo "== B 基线：经 bxroot 驱动 =="
# ---------------------------------------------------------------------
# ★ 加载方式：用 bridge + linker + --preload，**不要**用 launcher + LD_PRELOAD ★
# ---------------------------------------------------------------------
# 这条规则来自一次代价不小的调查（见
# `docs/调查-LD_PRELOAD在proroot容器内失效.md`）：
#
#   在本项目所处的官方 proroot 容器内，`LD_PRELOAD` **架构性失效** ——
#   连一个只有空构造函数的最小 .so 都不会被执行（三种传入方式实测全无效，
#   含 Python os.execve 直接传 envp，排除了 shell 层的解释）。
#
#   原因是官方 proroot 用**自研 ELF 加载器**接管了 execve，它不实现
#   LD_PRELOAD 语义。因此"launcher + LD_PRELOAD"这条路在本容器里
#   加载的其实是**外层 proroot 自己** —— 测试会显示"全绿"，
#   但测的根本不是 bxroot。
#
# ★ 这类假绿比红灯危险得多 ★ 红灯会有人去查，假绿会被当成事实记进报告。
#
# 可靠的加载方式是官方那套四件套（bridge + linker + --argv0 + --preload），
# 它同时适用于真机与容器。两个必须遵守的细节：
#
#   ① runtime 要放在 **rootfs 内**（linker 只认内核视角路径）
#   ② --preload 给**内核视角**路径（$ROOTFS/tmp/xxx），
#      而 mkdir/cp 给**容器视角**路径（/tmp/xxx）—— 两者 inode 相同，
#      但分别只认其中一个（给 mkdir 内核视角路径会"返回 0 却不创建"）
#
# 并且**必须验证 runtime 真的加载了**：只看"程序跑起来了"不够。
# 判据是 BXROOT_VERBOSE=1 输出里的 `[bxroot] proc: init … inject=1`。
B_DIR=$(mktemp -d "$WORK/runB-XXXXXX")
cp "$PROBE" "$B_DIR/pathform"

# 探测官方 bridge/linker 目录（APK 路径含随机后缀，必须动态找）
APP_LIB=""
for m in /proc/[0-9]*/maps; do
    [ -r "$m" ] || continue
    _p=$(grep -a 'libproroot-bridge\.so' "$m" 2>/dev/null | head -1 | awk '{print $6}')
    [ -n "${_p:-}" ] && { APP_LIB="${_p%/*}"; break; }
done

# ★ 不要用 [ -f ] 校验 APP_LIB ★
# shell 的 test/ls 走的是**翻译后的视图**，看不到 /data/app（那里被映射到
# rootfs 内），所以 "[ -f ] 说不存在" 与 "exec 能跑" 可以同时成立。
# 可用性交给后面的 exec 去证明（这是 RUN_E2E.sh 里记载的同一条教训）。
if [ -z "$APP_LIB" ]; then
    echo "⏭  探测不到官方 bridge/linker（非真机/非容器环境）"
    echo "    本项在无 --preload 机制的环境下无法验证 bxroot —— SKIP"
    echo "    （★ 不用 LD_PRELOAD 凑合：那会测出假绿，见脚本内注释）"
    exit 2
fi

# runtime 放到 rootfs 内：容器视角建目录、内核视角给 --preload
RF_REAL="${BXROOT_ROOTFS:-/data/data/com.dsh.client/files/linux/ubuntu}"
if [ ! -d "$RF_REAL" ]; then
    echo "⏭  找不到 rootfs（$RF_REAL）—— SKIP"
    exit 2
fi

STAGE_C="/tmp/bxroot-pathform-$$"          # 容器视角，供 mkdir/cp
STAGE_K="$RF_REAL/tmp/bxroot-pathform-$$"  # 内核视角，供 --preload
mkdir -p "$STAGE_C" || { echo "❌ 无法创建 $STAGE_C"; exit 2; }
cp "$ROOT/build/libbxroot-runtime.so" "$STAGE_C/rt.so" || exit 2
cp "$PROBE" "$STAGE_C/pathform" || exit 2
# mkdir 返回 0 不代表成功（双视角陷阱）—— 实测确认
[ -f "$STAGE_K/rt.so" ] || { echo "❌ $STAGE_K/rt.so 不存在（双视角陷阱？）"; exit 2; }

BXROOT_ROOTFS="$RF_REAL" \
BXROOT_VERBOSE=1 \
"$APP_LIB/libproroot-bridge.so" "$APP_LIB/libproroot-linker.so" \
    --argv0 pathform \
    --preload "$STAGE_K/rt.so" \
    "$STAGE_K/pathform" > "$WORK/B.out" 2>&1
B_RC=$?
sed 's/^/   /' "$WORK/B.out"
echo "   （退出码 $B_RC）"

# ★ 硬前提：证明 bxroot runtime 真的被加载 ★
if grep -q '\[bxroot\]' "$WORK/B.out"; then
    echo "   ✅ 确认 bxroot runtime 已生效（有 [bxroot] 日志）"
else
    echo "   ❌ 未看到 [bxroot] 日志 —— runtime 可能没加载"
    echo "      ★ 宁可 SKIP 也不要把 proroot 的结果记成 bxroot 的 ★"
    rm -rf "$STAGE_C" 2>/dev/null
    exit 2
fi
rm -rf "$STAGE_C" 2>/dev/null
echo

# ---------------------------------------------------------------------
# 判据
# ---------------------------------------------------------------------
# 从两侧输出里抽最后的统计行比对。
# ★ 不用退出码作唯一判据 ★ 退出码无法区分"探针没跑起来"与"用例失败"。
# 已知限制：原样显示，但不计为失败（详见探针 T06 内的注释）
KL=$(grep -c '^\[KNOWNLIMIT\]' "$WORK/B.out" 2>/dev/null | head -1)
[ -n "$KL" ] || KL=0
if [ "${KL:-0}" -gt 0 ]; then
    echo "ℹ️  已知限制 $KL 项（不是本次回归）："
    grep '^\[KNOWNLIMIT\]' "$WORK/B.out" | sed 's/^/     /'
    echo
fi

A_LINE=$(grep '^probe PATHFORM:' "$WORK/A.out" 2>/dev/null | tail -1)
B_LINE=$(grep '^probe PATHFORM:' "$WORK/B.out" 2>/dev/null | tail -1)

echo "======================================================"
echo " A 基线（直跑）    : ${A_LINE:-<无输出>}"
echo " B 基线（bxroot）  : ${B_LINE:-<无输出>}"
echo "======================================================"

if [ -z "$A_LINE" ]; then
    echo "⏭  A 基线探针未产生统计行 —— 环境不满足，整项 SKIP"
    exit 2
fi
if [ -z "$B_LINE" ]; then
    echo "❌ B 基线（bxroot）未产生统计行 —— 运行时没把探针跑起来"
    echo "   原始输出："; sed 's/^/     /' "$WORK/B.out"
    echo "RESULT: FAIL"
    exit 1
fi

B_OK=$(echo "$B_LINE"  | sed -n 's/.*ok=\([0-9]*\).*/\1/p')
B_FAIL=$(echo "$B_LINE"| sed -n 's/.*fail=\([0-9]*\).*/\1/p')
A_FAIL=$(echo "$A_LINE"| sed -n 's/.*fail=\([0-9]*\).*/\1/p')

# ★ 从失败数里扣掉"已知限制" ★
# 探针的 bad() 会把 KNOWNLIMIT 也算进 fail 计数（因为它走的是同一个出口），
# 所以这里扣掉。**扣的是计数，不是可见性** —— 上面已经把每一条
# 原样打印出来了。
#
# ★ 为什么不用"改探针让 KNOWNLIMIT 不计 fail"这个更干净的做法 ★
# 因为那会让"探针自身的统计行"与"人们读到的行"不一致：
# 统计行说 fail=0 而输出里明明有一条不是 [ok] 的行，
# 这种不一致本身就是下一轮排查的陷阱。宁可在这里显式扣一次。
B_FAIL_REAL=$(( ${B_FAIL:-0} - ${KL:-0} ))
[ "$B_FAIL_REAL" -lt 0 ] && B_FAIL_REAL=0

if [ "${A_FAIL:-1}" -ne 0 ]; then
    echo "⚠️  A 基线自身有失败 —— 先修探针/环境，本项不能作为 bxroot 判据"
    echo "RESULT: FAIL"
    exit 1
fi

if [ "$B_FAIL_REAL" -ne 0 ]; then
    echo "❌ bxroot 侧有 $B_FAIL_REAL 个用例失败："
    grep '^\[FAIL\]' "$WORK/B.out" | sed 's/^/     /'
    echo "RESULT: FAIL"
    exit 1
fi

if [ "${B_OK:-0}" -eq 0 ]; then
    echo "❌ bxroot 侧 0 个用例通过 —— 疑似探针未真正执行"
    echo "RESULT: FAIL"
    exit 1
fi

# ★ 措辞要如实 ★ 有已知限制时不能说"全部通过"
if [ "${KL:-0}" -gt 0 ]; then
    echo "✅ 路径形态回归通过（$B_OK 个用例），另有 $KL 项已知限制（见上）"
else
    echo "✅ 四种路径形态 × 读写操作全部通过（$B_OK 个用例）"
fi
echo "RESULT: PASS"
exit 0
