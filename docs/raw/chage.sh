#!/bin/sh
# chage -l root 两侧对照（官方 vs bxroot）
# 退出码必须单独取，不经管道（管道拿到的是 head 的退出码）
#
# 两个视角的坑（RUN_E2E.sh 已记录）：--preload 只认**内核视角**路径，
# 所以运行时必须先复制到容器可见目录，再用 $ROOTFS/<容器路径> 引用。
set -u

RFS=/data/data/com.dsh.client/files/linux/ubuntu

detect_app_lib() {
    for m in /proc/[0-9]*/maps; do
        [ -r "$m" ] || continue
        p=$(grep -a 'libproroot-bridge\.so' "$m" 2>/dev/null | head -1 | awk '{print $6}')
        [ -n "${p:-}" ] && { echo "${p%/*}"; return 0; }
    done
    return 1
}
APP_LIB="${APP_LIB:-$(detect_app_lib)}"
BR="$APP_LIB/libproroot-bridge.so"
LK="$APP_LIB/libproroot-linker.so"

# 容器可见的落地目录 + 内核视角的引用路径
STAGE_MK=/root/gapfix/chage
STAGE_LOAD="$RFS/root/gapfix/chage"
mkdir -p "$STAGE_MK/tmp" 2>/dev/null

OFF_SRC=${OFF:-/root/gapfix/libofficial-runtime.so}
BX_SRC=${BX:-/root/proroot-work/agents/rename-bxroot/build/libbxroot-runtime.so}
cp -f "$OFF_SRC" "$STAGE_MK/libofficial-runtime.so"
cp -f "$BX_SRC"  "$STAGE_MK/libbxroot-runtime.so"

echo "官方库目录 = $APP_LIB"

run_off() {
    PROROOT_ROOTFS="$RFS" PROROOT_TMP_DIR="$STAGE_LOAD/tmp" \
    "$BR" "$LK" \
      --argv0 chage --preload "$STAGE_LOAD/libofficial-runtime.so" \
      "$RFS/usr/bin/chage" -l root
}
run_bx() {
    BXROOT_ROOTFS="$RFS" BXROOT_TMP_DIR="$STAGE_LOAD/tmp" BXROOT_FAKEROOT=1 \
    "$BR" "$LK" \
      --argv0 chage --preload "$STAGE_LOAD/libbxroot-runtime.so" \
      "$RFS/usr/bin/chage" -l root
}

echo "##### 官方 #####"
run_off > "$STAGE_MK/out_off.txt" 2>&1
RC_OFF=$?
cat "$STAGE_MK/out_off.txt"
echo "chage 官方真实退出码 = $RC_OFF"

echo
echo "##### bxroot #####"
run_bx > "$STAGE_MK/out_bx.txt" 2>&1
RC_BX=$?
cat "$STAGE_MK/out_bx.txt"
echo "chage bxroot 真实退出码 = $RC_BX"

echo
echo "##### 逐字对照 #####"
if diff "$STAGE_MK/out_off.txt" "$STAGE_MK/out_bx.txt" > "$STAGE_MK/diff.txt" 2>&1; then
    echo "✅ 输出逐字一致"
else
    echo "❌ 输出不同："
    cat "$STAGE_MK/diff.txt"
fi
if [ "$RC_OFF" = "$RC_BX" ]; then
    echo "✅ 退出码一致（$RC_OFF）"
else
    echo "❌ 退出码不同：官方=$RC_OFF bxroot=$RC_BX"
fi
