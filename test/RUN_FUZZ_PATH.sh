#!/bin/sh
# ---------------------------------------------------------------------
# 路径翻译层「更狠的」沙箱边界爆破 / 回归（BXR-ESC-4，2026-09-28）
#
# 在 9a2d539（ESC-1/2/3：绝对 `..`、叶子链接回退、*at 只加前缀不跟随）
# 之上，覆盖那一轮**没测到**的入口与组合：
#   ESC-4a 普通**相对** `..`：chdir 到 guest 根后 open/access/stat/chmod/
#          chown/truncate/unlink/rmdir/readlink/realpath("../x")。修前
#          translate_path 对相对名直接透传，内核按**宿主 cwd** 解析 `..`
#          → 走出 rootfs（实测 access/chmod/chown/unlink/mkdir/rmdir/
#          truncate/fchownat 8 项逃逸）。
#   ESC-4b *at 家族 + dirfd 指向 rootfs 根 + 相对 `..`：faccessat/
#          fchmodat/fchownat/utimensat/unlinkat/mkdirat/symlinkat/
#          renameat/renameat2/linkat/openat(O_CREAT)。修前只
#          translate_path(相对名)=透传，内核按 dirfd 解析 `../x` 逃逸
#          （实测读/元数据 3 项 + 写/改名/链接多项）。
#   ESC-4c AT_FDCWD + 相对 `..`：同 4b，cwd=guest 根时也必须夹紧。
#
# 修法（src/runtime/preload.c）：
#   ① translate_path 对**含 `..` 的相对名**先按 guest cwd 绝对化再夹紧；
#   ② translate_follow 对相对名先 bxroot_absolutize（access/chmod/chown/
#      lchown/creat/statfs/statvfs/truncate/canonicalize_file_name/
#      mkdir/rmdir 受益）；
#   ③ *at 写侧钩子（faccessat/fchmodat/unlinkat/mkdirat/symlinkat/
#      renameat/renameat2/linkat）统一走 resolve_host_path 按 dirfd 拼
#      绝对再翻译，绝对后把 dirfd 归零为 AT_FDCWD。
#
# 【判据 —— 被测对象自己的痕迹】rootfs 是宿主某目录的**子目录**，
# canary/decoy 放 rootfs **上一层**（宿主视角）。正确沙箱把 `..` 在
# guest 根夹紧：`../canary` → guest `/canary`（不存在），绝不碰父目录。
#   读类：读到 CANARY 字节 = 逃逸；元数据/删除类：对 ../x 返回 0 = 逃逸；
#   写/改名/链接类：审计宿主父目录是否多出 EPWN_* 文件（应落在 rootfs 内）。
#
# 与官方 proroot（/tmp/off-rt.so，若存在）对照：官方对这些构造全部夹紧。
# 判别力：撤掉 preload.c 的修复重建，本测试立即变红（见 docs 与提交说明）。
# 退出：0 通过 / 1 失败 / 2 环境不满足
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BX="$ROOT/tools/bxroot-run"

grep -q 'libproroot-runtime\.so' /proc/self/maps 2>/dev/null || {
    echo "⏭️  跳过：需要外层 proroot 注入链路"; exit 2; }
[ -f "$ROOT/build/libbxroot-runtime.so" ] || {
    echo "⏭️  跳过：没有 build/libbxroot-runtime.so"; exit 2; }

W=$(mktemp -d /tmp/bxroot-fuzzpath-XXXXXX)
trap 'rm -rf "$W"' EXIT
F=0
bad()  { F=$((F + 1)); echo "  ❌ $*"; }
good() { echo "  ✅ $*"; }

# rootfs = W/rf（宿主子目录）；canary/decoy 在 W/（rootfs 上一层）
RF="$W/rf"
mkdir -p "$RF/etc" "$RF/tmp"
ln -s ../../../usr "$RF/usr"
ln -s usr/bin "$RF/bin"; ln -s usr/lib "$RF/lib"
echo "FUZZ-GUEST" > "$RF/etc/hostname"

reset_state() {
    find "$W" -maxdepth 1 \( -name 'EPWN_*' \) -exec rm -rf {} + 2>/dev/null
    rm -rf "$RF"/EPWN_* "$RF"/tmp/src_* 2>/dev/null
    echo CANARY > "$W/canary"
    echo DECOY  > "$W/decoy"
    rm -rf "$W/rmtgt"; mkdir -p "$W/rmtgt"
    ln -sf /etc/hostname "$W/slk" 2>/dev/null
}

bld() {
    i=1
    while [ $i -le 12 ]; do
        gcc "$@" 2>"$W/cc" && return 0
        grep -q 'internal compiler error' "$W/cc" || { cat "$W/cc"; return 1; }
        i=$((i + 1))
    done
    return 1
}
bld -O1 -w -o "$RF/tmp/pf"  "$ROOT/test/probe_fuzz_path.c"       || exit 1
bld -O1 -w -o "$RF/tmp/pfw" "$ROOT/test/probe_fuzz_path_write.c" || exit 1

# runtime 选择：$1=off 用官方基线
run() {
    _rt=$1; shift
    if [ "$_rt" = off ]; then
        [ -f /tmp/off-rt.so ] || return 111
        (cd / && BXROOT_RUN_RUNTIME=/tmp/off-rt.so timeout 60 \
            "$BX" --no-check --rootfs "$RF" -- "$@") 2>&1
    else
        (cd / && timeout 60 "$BX" --rootfs "$RF" -- "$@") 2>&1
    fi
}

# 审计宿主父目录里是否出现 EPWN_* / decoy 被删 —— 返回逃逸计数
audit_write() {
    n=0
    for f in "$W"/EPWN_*; do [ -e "$f" ] && { echo "      泄漏到父目录: ${f##*/}"; n=$((n + 1)); }; done
    return $n
}

echo "======================================================"
echo " bxroot：ESC-4 相对 '..' / *at dirfd '..' 夹紧"
echo "======================================================"

reset_state
o=$(run bx /tmp/pf "$W")
esc=$(printf '%s\n' "$o" | sed -n 's/^DONE escapes=//p')
if [ "${esc:-x}" = 0 ]; then
    good "读/元数据/删除类相对 '..' 全部夹紧（0 逃逸）"
else
    bad "读/元数据/删除类逃逸：$(printf '%s\n' "$o" | grep '^ESCAPE' | tr '\n' ' ')"
fi

reset_state
run bx /tmp/pfw >/dev/null 2>&1
audit_write; wn=$?
[ "$wn" = 0 ] && good "写/改名/符号链接/硬链接类未泄漏到宿主父目录" \
             || bad "写侧逃逸：$wn 个 EPWN_ 落到父目录"
# 且 decoy 未被删、rmtgt 未被删（相对 '..' 删除夹紧）
[ -e "$W/decoy" ] && good "decoy 未被 ../decoy 删除" || bad "decoy 被删（unlink 逃逸）"
[ -e "$W/rmtgt" ] && good "rmtgt 未被 ../rmtgt 删除" || bad "rmtgt 被删（rmdir 逃逸）"

echo "== 语义不倒退：相对 '..' 仍能在 rootfs 内正常工作 =="
o=$(run bx /bin/sh -c 'cd /tmp && mkdir -p a/b && cd a/b && cat ../../../etc/hostname')
[ "$o" = "FUZZ-GUEST" ] && good "相对 ../../../etc/hostname（rootfs 内）" \
                        || bad "相对 .. 读 rootfs 内文件失败 → [$o]"
o=$(run bx /bin/sh -c 'cd /etc && cat ../etc/hostname')
[ "$o" = "FUZZ-GUEST" ] && good "cd /etc; cat ../etc/hostname" \
                        || bad "相对 ../etc/hostname → [$o]"
# ../ 越界仍夹紧到根、可继续读根下文件
o=$(run bx /bin/sh -c 'cd /tmp && cat ../../../../../../etc/hostname')
[ "$o" = "FUZZ-GUEST" ] && good "相对 ../ 越界夹紧到根" || bad "越界夹紧 → [$o]"

# ---- 官方对照（可选）----
if [ -f /tmp/off-rt.so ]; then
    echo "======================================================"
    echo " 官方 proroot 对照（/tmp/off-rt.so）"
    echo "======================================================"
    reset_state
    oo=$(run off /tmp/pf "$W")
    oesc=$(printf '%s\n' "$oo" | sed -n 's/^DONE escapes=//p')
    if [ "${oesc:-x}" = 0 ]; then
        good "官方：读/元数据/删除类相对 '..' 同样 0 逃逸（语义一致）"
    else
        echo "  ℹ️  官方读/元数据类逃逸计数=$oesc（对照记录，不计入本测试判定）"
    fi
    reset_state
    run off /tmp/pfw >/dev/null 2>&1
    audit_write; own=$?
    [ "$own" = 0 ] && good "官方：写侧同样未泄漏（语义一致）" \
                   || echo "  ℹ️  官方写侧泄漏=$own（对照记录）"
else
    echo "ℹ️  未提供 /tmp/off-rt.so，跳过官方对照（不影响回归判定）"
fi

echo "------------------------------------------------------"
[ $F -eq 0 ] && { echo "RESULT: PASS"; exit 0; }
echo "RESULT: FAIL（$F 项）"; exit 1
