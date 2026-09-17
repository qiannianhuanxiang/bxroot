#!/bin/sh
# =====================================================================
# shebang（`#!`）脚本直接 exec 的契约测试
# =====================================================================
#
# 由来
# ----
# 实测缺陷（2026-09-17）：带 `#!` 的可执行脚本在 bxroot 下**无法直接 exec**，
# 而官方可以：
#
#     ########## 官方 ##########              ########## bxroot（修前）##########
#     $ ./s1.sh                               $ ./s1.sh
#     SHEBANG-OK                              loader: reject .../s1.sh: bad read
#     rc=0                                    proroot-ldso: failure rc=5
#                                             rc=2
#
# 根因：execve 一个 shebang 脚本时，**内核**会解析 `#!` 行并改写 argv
# （`[解释器, 脚本, 原argv[1..]]`）再 exec 解释器；而 bxroot 的 exec 路径是
# 「翻译路径 → 交给官方 linker 加载」，linker 只认 ELF，看到脚本文本就报
# `bad read`（ELF magic 校验失败）。**内核的 shebang 逻辑被绕过了。**
#
# 修法：在把目标交给 linker 之前自己解析 `#!` 并按内核语义改写 argv。
#
# 为什么必须端到端测
# ------------------
# `sh script.sh`（显式指定解释器）**两侧本来就是好的** —— 所以纯逻辑测试、
# 或只测"脚本能不能跑"的测试都抓不到这个缺陷。**必须测"直接 exec 脚本文件"
# 这条路径**，且必须有官方对照才能确认改写后的行为一致。
#
# 用法
# ----
#   sh test/RUN_SHEBANG.sh
#
# 退出码
# ------
#   0 = 契约成立     1 = 契约被破坏     2 = 环境不满足（无法测）
# =====================================================================

set -u

SELF_DIR=$(dirname "$0")
ROOT=$(cd "$SELF_DIR/.." && pwd)
cd "$ROOT" || exit 2

# ---------------------------------------------------------------------
# 环境探测（与其它端到端脚本同一套约定）
# ---------------------------------------------------------------------
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

if [ -z "$APP_LIB" ]; then
    echo "⏭️  跳过：探测不到官方库目录（需要真机容器）"
    exit 2
fi
case "$APP_LIB" in
    */lib/arm64) ;;
    *) echo "⏭️  跳过：库目录形状异常（$APP_LIB）"; exit 2 ;;
esac

BXROOT_SO="$ROOT/build/libbxroot-runtime.so"
# 缺产物属"环境不满足"(rc=2)，不是"契约被破坏"(rc=1) —— 与项目约定一致
[ -f "$BXROOT_SO" ] || { echo "⏭️  跳过：缺 bxroot 产物（先跑 sh BUILD_RUNTIME.sh）"; exit 2; }
HAVE_OFFICIAL=0
[ -f "$OFFICIAL_SO" ] && HAVE_OFFICIAL=1

STAGE_MK="${BXROOT_STAGE:-/tmp/bxroot-shebang-$$}"
STAGE_LD="$ROOTFS$STAGE_MK"

cleanup() { rm -rf "$STAGE_MK" 2>/dev/null; }
trap cleanup EXIT INT TERM

# ★ 在 ROOTFS 内建目录/复制一律用 python3 ★
# 实测：shell 的 mkdir/cp 在这个文件系统上会「返回 0 但看不见」。
python3 - "$STAGE_MK" "$BXROOT_SO" "$OFFICIAL_SO" "$HAVE_OFFICIAL" <<'PY'
import os, shutil, sys
stage, bx, off, have_off = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
os.makedirs(stage, exist_ok=True)
os.makedirs(os.path.join(stage, "tmp"), exist_ok=True)
shutil.copy(bx, os.path.join(stage, "libbxroot-runtime.so"))
if have_off == "1":
    shutil.copy(off, os.path.join(stage, "libproroot-runtime.so"))
PY
if [ $? -ne 0 ]; then
    echo "❌ 暂存目录准备失败"; exit 2
fi

# ---------------------------------------------------------------------
# 被测脚本与驱动器
# ---------------------------------------------------------------------
cat > "$STAGE_MK/s1.sh" <<'EOF'
#!/bin/sh
echo "S1-OK args=[$*] argv0=$0"
EOF

cat > "$STAGE_MK/s2.py" <<'EOF'
#!/usr/bin/env python3
import sys
print("S2-OK argv0=%s" % sys.argv[0])
EOF

# 带解释器参数（内核把 `sh -u` 当作**一个**参数？不 —— 内核只取
# shebang 行第一个空格后的**整串**作为一个 arg，所以这里写的是
# `#!/bin/sh -u` → argv = [sh, "-u", script, ...]）
cat > "$STAGE_MK/s3.sh" <<'EOF'
#!/bin/sh -u
echo "S3-OK unset-var-guard=[${NOPE:-unset}]"
EOF

chmod +x "$STAGE_MK/s1.sh" "$STAGE_MK/s2.py" "$STAGE_MK/s3.sh" 2>/dev/null

cat > "$STAGE_MK/drive.sh" <<'EOF'
D="$1"
echo "--- A 直接执行 ./s1.sh ---"
"$D/s1.sh" arg1 arg2 2>&1; echo "rc=$?"
echo "--- B 直接执行 ./s2.py（#!/usr/bin/env python3）---"
"$D/s2.py" 2>&1; echo "rc=$?"
echo "--- C 直接执行 ./s3.sh（带解释器参数）---"
"$D/s3.sh" 2>&1; echo "rc=$?"
echo "--- D 对照：sh 显式调用（修前也应为 OK）---"
sh "$D/s1.sh" arg1 2>&1; echo "rc=$?"
IMP=$(python3 -c "import sys;print(sys.executable)" 2>/dev/null)
echo "IMPL=$IMP"
EOF

run_side() {
    # $1 = tag, $2 = runtime 文件名（容器视角相对于 $STAGE_MK）
    BXROOT_ROOTFS="$ROOTFS" \
    BXROOT_TMP_DIR="$STAGE_LD/tmp" \
    BXROOT_WORKDIR="/" \
    BXROOT_FAKEROOT=1 \
    PROROOT_ROOTFS="$ROOTFS" \
    PROROOT_TMP_DIR="$STAGE_LD/tmp" \
    timeout 150 "$APP_LIB/libproroot-bridge.so" "$APP_LIB/libproroot-linker.so" \
        --argv0 sh --preload "$STAGE_LD/$2" \
        "$ROOTFS/bin/sh" "$STAGE_LD/drive.sh" "$STAGE_LD" 2>&1 \
      | grep -vE '^\[NEXT\]|^\[bxroot\]'
}

echo "== shebang 脚本直接 exec 的契约 =="
echo

BX_OUT=$(run_side bx libbxroot-runtime.so)
echo "########## bxroot ##########"
echo "$BX_OUT"
echo

if [ "$HAVE_OFFICIAL" = 1 ]; then
    OFF_OUT=$(run_side off libproroot-runtime.so)
    echo "########## 官方 ##########"
    echo "$OFF_OUT"
    echo
else
    OFF_OUT=""
    echo "⏭️  无官方 runtime 副本 —— 只做绝对判据"
    echo
fi

echo "== 判据 =="
FAIL=0

for pat in 'S1-OK args=[arg1 arg2]' 'S2-OK argv0=' 'S3-OK unset-var-guard=[unset]'; do
    b=$(printf '%s\n' "$BX_OUT" | grep -F "$pat" | head -1)
    if [ -z "$b" ]; then
        echo "   ❌ bxroot 缺少 '$pat'"; FAIL=1
    elif [ "$HAVE_OFFICIAL" != 1 ]; then
        echo "   ✅ $pat（无对照，绝对判据）: $b"
    else
        o=$(printf '%s\n' "$OFF_OUT" | grep -F "$pat" | head -1)
        # argv0 是**脚本路径**（绝对路径不同），所以只比前缀
        case "$pat" in
            *argv0=*) echo "   ✅ $pat 出现: $b" ;;
            *)
                if [ "$o" != "$b" ]; then
                    echo "   ❌ '$pat' 不一致"; echo "      官方  : $o"; echo "      bxroot: $b"; FAIL=1
                else
                    echo "   ✅ $pat 一致: $b"
                fi ;;
        esac
    fi
done

# 所有 rc 必须是 0
for tag in A B C D; do
    b=$(printf '%s\n' "$BX_OUT" | awk -v t="--- $tag " 'index($0,t){found=1} found && /^rc=/{print; exit}')
    case "$b" in
        rc=0) echo "   ✅ $tag 段 rc=0" ;;
        *)    echo "   ❌ $tag 段 $b（应为 rc=0）"; FAIL=1 ;;
    esac
done

# 不得再出现 loader 拒绝
if printf '%s\n' "$BX_OUT" | grep -qE 'bad read|bad magic|proroot-ldso: failure'; then
    echo "   ❌ bxroot 仍报 loader 拒绝"
    printf '%s\n' "$BX_OUT" | grep -E 'bad read|bad magic|proroot-ldso: failure' | head -3 | sed 's/^/      /'
    FAIL=1
else
    echo "   ✅ 无 loader 拒绝（bad read / bad magic）"
fi

echo
echo "----------------------------------------"
if [ "$FAIL" -eq 0 ]; then
    echo "RESULT: PASS"
    exit 0
fi
echo "RESULT: FAIL"
exit 1
