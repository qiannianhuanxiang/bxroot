#!/system/bin/sh
# =====================================================================
# system() / popen() / pclose() 真机 A/B 端到端测试
# =====================================================================
#
# 由来
# ----
# `docs/LD_PRELOAD注入致子进程失败.md` 记录的缺陷：bxroot 的
# `system()` / `popen()` 子进程**全部起不来**，报
#
#     CANNOT LINK EXECUTABLE "sh": library "libc.so.6" not found:
#       needed by <rootfs>/.../libbxroot-runtime.so in namespace (default)
#
# 而这个缺陷此前**在所有回归里都是绿的** —— 因为回归只检查
# `nm -D` 里 `system`/`popen` **符号是否导出**（`test/RUN_ALL.sh` 的
# 「运行时构建」一项）。符号导出是必要条件，不是充分条件。
#
# 本脚本补上那条缺失的判据：**真的调用它们，并检查行为**。
#
# 判据（三条，缺一不可）
# ----------------------
#   1. `system()` 的 rc 与 stdout 与官方一致；
#   2. `popen()`/`pclose()` 的 rc 与读到的内容与官方一致；
#   3. **子进程仍然带上了运行时** —— 否则「修好」只是把功能关掉：
#      - 子进程里 `LD_PRELOAD` 指向我们的库（容器视角）；
#      - 子进程 `/proc/self/maps` 里能看到我们的 runtime；
#      - 子进程里的路径翻译仍然生效（`/etc/os-release` 是容器的
#        Ubuntu，而不是宿主的 Android）。
#
# 为什么必须真机
# --------------
# 本容器外层 proot 会吞掉注入（`_shared/容器内测试不可信.md`），纯
# Ubuntu 环境里没有 SELinux 的 `app_data_file` 限制，也没有官方
# bridge/linker 三件套 —— 失败的那条路径（直接 execve 翻译后的宿主
# 路径 → EACCES）在那里根本不会出现，测试会**假绿**。
#
# 用法
# ----
#   sh test/RUN_SYSTEM_POPEN.sh              跑 A/B 对照
#   sh test/RUN_SYSTEM_POPEN.sh --keep       保留现场（不删暂存目录）
#
# 退出码：0 = 通过 / 1 = 失败 / 2 = 环境不具备（跳过）
# =====================================================================

set -u

SELF_DIR=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
ROOT=$(cd "$SELF_DIR/.." && pwd)
ROOTFS="${ROOTFS:-/data/data/com.dsh.client/files/linux/ubuntu}"
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

die() { echo "错误: $*" >&2; exit 1; }
skip() { echo "⏭️  跳过: $*"; exit 2; }

# ---------------------------------------------------------------------
# 官方库目录探测
#
# ★ 容器视角看不到 /data/app ★
# proroot 是纯用户态路径翻译，`/proc/self/maps` 里写的是内核视角
# `/data/app/~~…/lib/arm64/…`，而 shell 的 `ls` 走翻译后的视图，会说不
# 存在。所以只能从 maps 里读，且**不能**用 `[ -f ]` 校验。
detect_app_lib() {
    for m in /proc/[0-9]*/maps; do
        [ -r "$m" ] || continue
        p=$(grep -a 'libproroot-bridge\.so' "$m" 2>/dev/null | head -1 | awk '{print $6}')
        [ -n "${p:-}" ] && { echo "${p%/*}"; return 0; }
    done
    return 1
}
APP_LIB="${APP_LIB:-$(detect_app_lib)}"
[ -n "$APP_LIB" ] || skip "探测不到官方库目录（本机可能不在 proroot 容器里）"
case "$APP_LIB" in
    */lib/arm64) ;;
    *) skip "探测到的官方库目录形状异常: $APP_LIB" ;;
esac
[ -f "$ROOTFS/usr/bin/dash" ] || skip "找不到 $ROOTFS/usr/bin/dash"

BXROOT_SO="${BXROOT_SO:-$ROOT/build/libbxroot-runtime.so}"
OFFICIAL_SO="${OFFICIAL_SO:-$ROOT/work/parity/off/libproroot-runtime.so}"
[ -f "$BXROOT_SO" ] || die "找不到 bxroot 运行时: $BXROOT_SO（先跑 BUILD_RUNTIME.sh）"
[ -f "$OFFICIAL_SO" ] || die "找不到官方运行时: $OFFICIAL_SO"

# ---------------------------------------------------------------------
# 暂存目录
#
# ★ 双视角：mkdir/cp 认容器视角，--preload 认内核视角 ★
# 且目录名带 $$，避免并发跑时互相删（本项目的协作陷阱，已踩过）。
# 落地在 $ROOTFS/root/… 内 ⇒ 容器视角 /root/… 与内核视角自动同 inode。
# ---------------------------------------------------------------------
STAGE_MK="/root/bxroot-syspopen-$$"
STAGE_LD="$ROOTFS$STAGE_MK"

# 清理护栏：只删自己那个带 $$ 的目录
cleanup() {
    if [ "$KEEP" = "1" ]; then
        echo "（--keep）保留现场: $STAGE_MK = $STAGE_LD"
        return
    fi
    case "$STAGE_MK" in
        /root/bxroot-syspopen-*) rm -rf "$STAGE_MK" 2>/dev/null ;;
    esac
}
trap cleanup EXIT INT TERM

# ★ 在 ROOTFS 内建目录/复制一律用 python3 ★
# 实测：shell 的 mkdir/cp 在这个文件系统上会「返回 0 但看不见」。
python3 - "$STAGE_MK" "$BXROOT_SO" "$OFFICIAL_SO" <<'PY' || die "暂存目录准备失败"
import os, shutil, sys
stage, bx, off = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(stage, exist_ok=True)
os.makedirs(os.path.join(stage, "tmp"), exist_ok=True)
shutil.copy(bx, os.path.join(stage, "libbxroot-runtime.so"))
shutil.copy(off, os.path.join(stage, "libproroot-runtime.so"))
print("   暂存目录就绪:", stage)
PY

# ---------------------------------------------------------------------
# 探针
#
# 一个探针同时覆盖三条判据：system / popen / 子进程内的身份与翻译。
# 子壳里打印的是**子壳自己**的信息（`$$`），不是 `$()` 子壳的 ——
# 后者会多套一层，读到的 pid 不是我们关心的那个。
# ---------------------------------------------------------------------
PROBE_SRC="$STAGE_MK/probe.c"
cat > "$PROBE_SRC" <<'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>

extern char **environ;

/* 在 system() 派生的 shell 里跑，打印 shell 自身的身份与视角 */
#define CHILD_CMD \
    "echo  CHILD_LD_PRELOAD=[$LD_PRELOAD];" \
    "echo -n '  CHILD_RT_MAPS='; grep -cE 'bxroot-runtime|proroot-runtime' /proc/$$/maps;" \
    "echo -n '  CHILD_OS='; head -1 /etc/os-release 2>/dev/null;" \
    "echo  CHILD_ROOT_ITEMS=$(ls / | wc -l)"

/*
 * 判据 5 的探针：**宿主视角**的裸 exec。
 *
 * `environ` 里若留着**容器视角**的 LD_PRELOAD，任何不经我们 hook 的
 * 宿主 exec（glibc 硬编码的宿主 /bin/sh、原生 dlopen、宿主侧工具链）
 * 都会拿这条路径去解析，然后 `CANNOT LINK EXECUTABLE`。
 *
 * 这里用**裸 syscall** 走一遍，正是为了**绕开我们自己的钩子** ——
 * 否则测到的只是「我们的 hook 修好了没」，而不是「environ 干净没」。
 * 宿主 `/system/bin/sh` 在容器视角下不可见，所以必须经 `/proc/self/root`
 * 前缀访问（那是内核对本进程而言的真 `/`）。
 */
static void host_exec_probe(void)
{
    const char *pl = getenv("LD_PRELOAD");
    pid_t p;
    int st = 0;

    printf("HOSTENV_LD_PRELOAD=[%s]\n", pl ? pl : "(unset)");
    fflush(stdout);

    p = fork();
    if (p == 0) {
        char *av[] = { (char *)"sh", (char *)"-c",
                       (char *)"echo HOST-SH-OK", NULL };
        syscall(SYS_execve, "/proc/self/root/system/bin/sh", av, environ);
        _exit(errno ? errno : 127);
    }
    waitpid(p, &st, 0);
    printf("host_exec status=%d\n", st);
}

int main(void)
{
    int rc;

    errno = 0;
    rc = system("echo SYSCALL-OK;" CHILD_CMD);
    printf("system rc=%d errno=%d\n", rc, errno);

    errno = 0;
    {
        FILE *f = popen("echo POPEN-OK;" CHILD_CMD, "r");
        if (f == NULL) {
            printf("popen NULL errno=%d\n", errno);
            return 0;
        }
        {
            char buf[1024];
            while (fgets(buf, sizeof(buf), f) != NULL) {
                fputs(buf, stdout);
            }
        }
        printf("pclose rc=%d\n", pclose(f));
    }

    host_exec_probe();
    return 0;
}
CEOF

PROBE_BIN="$STAGE_MK/probe"
gcc -O1 -o "$PROBE_BIN" "$PROBE_SRC" 2>&1 | head -5
[ -f "$PROBE_BIN" ] || die "探针编译失败"

# ---------------------------------------------------------------------
# 运行
#
# ★ 两侧各用各的环境变量前缀 ★
# 官方只认 PROROOT_*，bxroot 只认 BXROOT_*（官方产物里 "BXROOT" 出现
# **0 次**，传了会被静默忽略）—— 不分开设就不是对照实验。
# ---------------------------------------------------------------------
run_side() {
    who="$1"; rt="$2"
    env \
        PROROOT_ROOTFS="$ROOTFS" PROROOT_TMP_DIR="$STAGE_LD/tmp" \
        PROROOT_GUEST_EXE="$STAGE_LD/probe" \
        PROROOT_TRAMPOLINE_PATH="$APP_LIB/libproroot-bridge.so" \
        PROROOT_LINKER_PATH="$APP_LIB/libproroot-linker.so" \
        BXROOT_ROOTFS="$ROOTFS" BXROOT_TMP_DIR="$STAGE_LD/tmp" \
        BXROOT_WORKDIR="/" BXROOT_FAKEROOT=1 BXROOT_LINK2SYMLINK=1 \
        BXROOT_GUEST_EXE="$STAGE_LD/probe" \
        BXROOT_TRAMPOLINE_PATH="$APP_LIB/libproroot-bridge.so" \
        BXROOT_LINKER_PATH="$APP_LIB/libproroot-linker.so" \
        timeout 120 "$APP_LIB/libproroot-bridge.so" \
            "$APP_LIB/libproroot-linker.so" \
            --argv0 probe --preload "$STAGE_LD/$rt" \
            "$STAGE_LD/probe" 2>&1
}

echo "== 官方（对照组）=="
OFF_OUT=$(run_side off libproroot-runtime.so)
echo "$OFF_OUT"

echo
echo "== bxroot（被测组）=="
BX_OUT=$(run_side bx libbxroot-runtime.so)
echo "$BX_OUT"

# ---------------------------------------------------------------------
# 判据
# ---------------------------------------------------------------------
echo
echo "== 判据 =="
FAIL=0

# 判据 1：system/popen 的 rc 与关键输出两侧一致
for pat in 'system rc=' 'pclose rc=' 'SYSCALL-OK' 'POPEN-OK'; do
    o=$(printf '%s\n' "$OFF_OUT" | grep -F "$pat" | head -1)
    b=$(printf '%s\n' "$BX_OUT"  | grep -F "$pat" | head -1)
    if [ -z "$b" ]; then
        echo "   ❌ bxroot 缺少 '$pat'（官方: $o）"; FAIL=1
    elif [ "$o" != "$b" ]; then
        echo "   ❌ '$pat' 不一致"; echo "      官方  : $o"; echo "      bxroot: $b"; FAIL=1
    else
        echo "   ✅ $pat 一致: $b"
    fi
done

# 判据 2：子进程仍然带上运行时（maps 计数 > 0）
rtmaps=$(printf '%s\n' "$BX_OUT" | grep -F 'CHILD_RT_MAPS=' | head -1 | sed 's/.*=//')
case "${rtmaps:-0}" in
    ''|0) echo "   ❌ 子进程里没有 runtime 映射（CHILD_RT_MAPS=${rtmaps:-空}）"; FAIL=1 ;;
    *)    echo "   ✅ 子进程带上了 runtime（CHILD_RT_MAPS=$rtmaps）" ;;
esac

# 判据 3：子进程里的路径翻译仍生效（看到的必须是容器的 Ubuntu）
osline=$(printf '%s\n' "$BX_OUT" | grep -F 'CHILD_OS=' | head -1 | sed 's/.*CHILD_OS=//')
case "${osline:-}" in
    *Ubuntu*) echo "   ✅ 子进程里的路径翻译生效: $osline" ;;
    *)        echo "   ❌ 子进程里看到的不是容器内容: ${osline:-（空）}"; FAIL=1 ;;
esac

# 判据 4：不得再出现连接器失败
if printf '%s\n' "$BX_OUT" | grep -q 'CANNOT LINK EXECUTABLE'; then
    echo "   ❌ 仍有 CANNOT LINK EXECUTABLE（本缺陷未修好）"; FAIL=1
else
    echo "   ✅ 无 CANNOT LINK EXECUTABLE"
fi

# 判据 5：environ 里不得留**容器视角**的 LD_PRELOAD
#
# ★ 这是本缺陷的**第二半**，与判据 1-4 独立 ★
# 光把 system/popen 接管只能保证「我们自己发起的子进程」正常；而
# environ 是**进程级**状态，任何不经我们 hook 的宿主 exec（glibc 硬编码
# 的宿主 /bin/sh、原生 dlopen、宿主侧工具链）都会继承它。留一条容器视角
# 的路径在里面 ⇒ 那些 exec 全部 `CANNOT LINK EXECUTABLE`。
#
# 负对照实测（源码级回退 environ 这一处，保留接管）：
#     ENV LD_PRELOAD=[<rootfs>/.../libnegA2.so]
#     裸 syscall execve("/proc/self/root/system/bin/sh")
#     → CANNOT LINK EXECUTABLE "sh": library "libc.so.6" not found
#     → 宿主 sh 结束 status=256 WEXIT=1   ← 起不来
# 修复后同一条命令：HOST-SH-OK / status=0。
#
# 判据用「宿主 exec 成功」而不是「LD_PRELOAD 是否为空」：后者是**实现
# 细节**（guest 自己设的 preload 我们刻意保留），前者才是**行为契约**。
hostst=$(printf '%s\n' "$BX_OUT" | grep -F 'host_exec status=' | head -1 | sed 's/.*=//')
hostpl=$(printf '%s\n' "$BX_OUT" | grep -F 'HOSTENV_LD_PRELOAD=' | head -1 | sed 's/.*=\[//;s/\]$//')
case "${hostst:-}" in
    0) echo "   ✅ environ 干净：宿主视角裸 exec 正常（HOSTENV_LD_PRELOAD=$hostpl）" ;;
    *) echo "   ❌ 宿主视角裸 exec 失败（status=${hostst:-空}，HOSTENV_LD_PRELOAD=$hostpl）"
       echo "      ⇒ environ 里留着容器视角的 LD_PRELOAD，宿主 linker 解析不了"
       FAIL=1 ;;
esac

echo
if [ "$FAIL" -eq 0 ]; then
    echo "RESULT: PASS"
    exit 0
fi
echo "RESULT: FAIL"
exit 1
