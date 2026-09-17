#!/bin/sh
# =====================================================================
# 缺口 C 的真实程序验收：降权族（setuid/setgid/setgroups/...）
# =====================================================================
#
# 由来
# ----
# 实测缺陷（2026-09-17）：
#
#     ########## 官方 ##########          ########## bxroot（修前）##########
#     $ chage -l root                     $ chage -l root
#     Last password change : Aug 05, 2025 chage: failed to drop privileges
#     ...（正常输出）                      (Function not implemented)
#     rc=0                                rc=1
#
# 根因是**两条**路径都没覆盖，而修一条不够：
#   ① 符号层：`chage` 引用 `setreuid` **符号**（readelf 证实；
#      `objdump -d chage | grep -c svc` = 0），glibc 的包装函数自己发 svc；
#   ② syscall 层：程序若调 `syscall(143,...)` 也要覆盖。
# 而两者最终都撞 proroot-ldso 的 seccomp 过滤器（bxroot 的 sigsys.c 统一回 ENOSYS）。
#
# 官方用**用户态身份账本**（setter 写、getter 读，回读自洽），
# bxroot 现在复用 fakeroot 的纯逻辑账本做同样的事。
#
# 为什么必须是**真实程序**验收
# ---------------------------
# 单测只能证明"接线对了"，证明不了"真实工具因此可用了"。而这个缺陷
# 最初的发现方式就是"跑 `chage` 失败" —— 判据必须回到同一个高度。
#
# 用法
# ----
#   sh test/RUN_PRIVDROP.sh
#
# 退出码
# ------
#   0 = 契约成立     1 = 契约被破坏     2 = 环境不满足（无法测）
# =====================================================================

set -u

SELF_DIR=$(dirname "$0")
ROOT=$(cd "$SELF_DIR/.." && pwd)
cd "$ROOT" || exit 2

detect_app_lib() {
    for m in /proc/[0-9]*/maps; do
        [ -r "$m" ] || continue
        p=$(grep -a 'libproroot-bridge\.so' "$m" 2>/dev/null | head -1 | awk '{print $6}')
        [ -n "${p:-}" ] && { echo "${p%/*}"; return 0; }
    done
    return 1
}

APP_LIB="${APP_LIB:-$(detect_app_lib)}"
ROOTFS="${ROOTFS:-/data/data/com.dsh.client/files/linux/ubuntu}"
OFFICIAL_SO="${OFFICIAL_SO:-$ROOT/work/parity/off/libproroot-runtime.so}"

[ -n "$APP_LIB" ] || { echo "⏭️  跳过：探测不到官方库目录（需要真机容器）"; exit 2; }
case "$APP_LIB" in
    */lib/arm64) ;;
    *) echo "⏭️  跳过：库目录形状异常（$APP_LIB）"; exit 2 ;;
esac

BXROOT_SO="$ROOT/build/libbxroot-runtime.so"
[ -f "$BXROOT_SO" ] || { echo "⏭️  跳过：缺 bxroot 产物（先跑 sh BUILD_RUNTIME.sh）"; exit 2; }
HAVE_OFFICIAL=0
[ -f "$OFFICIAL_SO" ] && HAVE_OFFICIAL=1

# 被测程序：chage（最直接的受害者，官方/我们的差异原先就在这里）
CHAGE="$ROOTFS/usr/bin/chage"
[ -f "$CHAGE" ] || { echo "⏭️  跳过：rootfs 里没有 $CHAGE"; exit 2; }

STAGE_MK="${BXROOT_STAGE:-/tmp/bxroot-privdrop-$$}"
STAGE_LD="$ROOTFS$STAGE_MK"

cleanup() { rm -rf "$STAGE_MK" 2>/dev/null; }
trap cleanup EXIT INT TERM

python3 - "$STAGE_MK" "$BXROOT_SO" "$OFFICIAL_SO" "$HAVE_OFFICIAL" <<'PY'
import os, shutil, sys
stage, bx, off, have_off = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
os.makedirs(stage, exist_ok=True)
os.makedirs(os.path.join(stage, "tmp"), exist_ok=True)
shutil.copy(bx, os.path.join(stage, "libbxroot-runtime.so"))
if have_off == "1":
    shutil.copy(off, os.path.join(stage, "libproroot-runtime.so"))
PY
[ $? -eq 0 ] || { echo "❌ 暂存目录准备失败"; exit 2; }

# ---------------------------------------------------------------------
# 探针：直接用 syscall() 走降权族 + 回读账本
# ---------------------------------------------------------------------
cat > "$STAGE_MK/probe.c" <<'CEOF'
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>

static void bid(const char *tag, unsigned r, unsigned e, unsigned s)
{
    printf("   %s r=%u e=%u s=%u\n", tag, r, e, s);
}

int main(void)
{
    unsigned r, e, s;

    syscall(148, &r, &e, &s);
    bid("before   ", r, e, s);

    errno = 0;
    long a = syscall(144, 999);          /* setgid */
    printf("   setgid(144)  rc=%ld errno=%d\n", a, errno);

    errno = 0;
    long b = syscall(146, 999);          /* setuid */
    printf("   setuid(146)  rc=%ld errno=%d\n", b, errno);

    syscall(148, &r, &e, &s);
    bid("after    ", r, e, s);

    /* 降权后 setgroups：官方允许（无条件假装成功），我们也应该允许 */
    errno = 0;
    long c = syscall(159, 0, 0);         /* setgroups(0,NULL) */
    printf("   setgroups   rc=%ld errno=%d\n", c, errno);
    return 0;
}
CEOF

CC="${CC:-gcc}"
$CC -O1 -o "$STAGE_MK/probe" "$STAGE_MK/probe.c" 2>/dev/null

run_side() {
    # $1 = runtime 文件名；$2 = "prog" 则跑 chage，否则跑 probe
    if [ "${2:-probe}" = "prog" ]; then
        BXROOT_ROOTFS="$ROOTFS" BXROOT_TMP_DIR="$STAGE_LD/tmp" \
        BXROOT_WORKDIR="/" BXROOT_FAKEROOT=1 \
        PROROOT_ROOTFS="$ROOTFS" PROROOT_TMP_DIR="$STAGE_LD/tmp" \
        timeout 150 "$APP_LIB/libproroot-bridge.so" \
            "$APP_LIB/libproroot-linker.so" \
            --argv0 chage --preload "$STAGE_LD/$1" \
            "$CHAGE" -l root 2>&1
    else
        BXROOT_ROOTFS="$ROOTFS" BXROOT_TMP_DIR="$STAGE_LD/tmp" \
        BXROOT_WORKDIR="/" BXROOT_FAKEROOT=1 \
        PROROOT_ROOTFS="$ROOTFS" PROROOT_TMP_DIR="$STAGE_LD/tmp" \
        timeout 150 "$APP_LIB/libproroot-bridge.so" \
            "$APP_LIB/libproroot-linker.so" \
            --argv0 probe --preload "$STAGE_LD/$1" \
            "$STAGE_LD/probe" 2>&1
    fi
}

echo "== 缺口 C：降权族（真实程序 chage + syscall 探针）=="
echo

echo "########## syscall 探针：bxroot ##########"
BX_PROBE=$(run_side libbxroot-runtime.so probe | grep -vE '^\[NEXT\]|^\[bxroot\]')
echo "$BX_PROBE"
echo

if [ "$HAVE_OFFICIAL" = 1 ]; then
    echo "########## syscall 探针：官方 ##########"
    OFF_PROBE=$(run_side libproroot-runtime.so probe | grep -vE '^\[NEXT\]|^\[bxroot\]')
    echo "$OFF_PROBE"
    echo
fi

echo "########## 真实程序：bxroot ##########"
BX_OUT=$(run_side libbxroot-runtime.so prog | grep -vE '^\[NEXT\]|^\[bxroot\]')
BX_RC=$?
echo "$BX_OUT" | head -4
echo

FAIL=0

# --- 判据 1：setgid/setuid 必须成功（rc=0）---
case "$BX_PROBE" in
    *"setgid(144)  rc=0"*) echo "   ✅ setgid(144) rc=0" ;;
    *) echo "   ❌ setgid(144) 未成功"; FAIL=1 ;;
esac
case "$BX_PROBE" in
    *"setuid(146)  rc=0"*) echo "   ✅ setuid(146) rc=0" ;;
    *) echo "   ❌ setuid(146) 未成功"; FAIL=1 ;;
esac

# --- 判据 2：★ 账本必须自洽（回读等于新值）★
# 这是"假装成功"与"真账本"的分水岭：只返回 0 而回读没变，
# 程序会看到自相矛盾的世界（比报错更难查）。
case "$BX_PROBE" in
    *"after     r=999 e=999 s=999"*) echo "   ✅ 账本自洽：setuid(999) 后回读 r=e=s=999" ;;
    *) echo "   ❌ 账本不自洽 —— 回读与 setter 不一致"
       echo "$BX_PROBE" | grep "after" | sed 's/^/      /'; FAIL=1 ;;
esac

# --- 判据 3：降权后 setgroups 仍成功（官方语义，见 preload.c case 7）---
case "$BX_PROBE" in
    *"setgroups   rc=0"*) echo "   ✅ 降权后 setgroups rc=0" ;;
    *) echo "   ❌ 降权后 setgroups 未成功"; FAIL=1 ;;
esac

# --- 判据 4：★ 真实程序 chage 必须正常输出 ★
if printf '%s\n' "$BX_OUT" | grep -q 'failed to drop privileges'; then
    echo "   ❌ chage 仍报 'failed to drop privileges'"
    FAIL=1
elif printf '%s\n' "$BX_OUT" | grep -q 'Last password change'; then
    echo "   ✅ chage 正常输出账号信息"
else
    echo "   ❌ chage 输出既不是成功也不是已知失败形态："
    printf '%s\n' "$BX_OUT" | head -3 | sed 's/^/      /'
    FAIL=1
fi

# --- 判据 5：有官方对照时，逐行比对 probe ---
if [ "$HAVE_OFFICIAL" = 1 ]; then
    if [ "$BX_PROBE" = "$OFF_PROBE" ]; then
        echo "   ✅ syscall 探针与官方逐行一致"
    else
        echo "   ❌ syscall 探针与官方不一致："
        # ★ 不用进程替换 `<(...)` ★ —— /bin/sh 是 dash，不支持它
        #（实测报 `Syntax error: "(" unexpected`）。写成临时文件最稳。
        printf '%s\n' "$OFF_PROBE" > "$STAGE_MK/off.txt"
        printf '%s\n' "$BX_PROBE"  > "$STAGE_MK/bx.txt"
        diff "$STAGE_MK/off.txt" "$STAGE_MK/bx.txt" | sed 's/^/      /'
        FAIL=1
    fi
else
    echo "   ⏭️  无官方 runtime 副本 —— 只做绝对判据（上面 4 条）"
fi

echo
echo "----------------------------------------"
if [ "$FAIL" -eq 0 ]; then
    echo "RESULT: PASS"
    exit 0
fi
echo "RESULT: FAIL"
exit 1
