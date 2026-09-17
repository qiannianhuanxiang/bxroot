#!/bin/sh
# =====================================================================
# NSS 直解回退 · 边界回归（getpwnam / getpwnam_r / getgrnam / getgrnam_r）
# =====================================================================
#
# 被测特性
# --------
# 缺口 D 的修法（见 docs/缺口D-NSS用户库查询失败.md）：真实 NSS 调用失败时，
# hook **自己** fopen("/etc/passwd")、("/etc/group") 逐行解析。
# 实现在 src/runtime/preload.c（grep 直解）。本 runner 把这条回退路径的
# **边界行为**钉住。探针：test/probe_nss_edge.c（T01..T10）。
#
# ★ 为什么要按「文件组」分批 ★
# ---------------------------
# 探针的 10 个用例需要 **5 种互不相同的 /etc/passwd + /etc/group 内容**
# （正常行 / 缺字段 / 空行 / 超长行 / 文件缺失）。一个进程只能看到一套文件，
# 所以必须分批换文件、每批只跑属于该批的用例（探针的 EDGE_CASES 就是为此）。
#
# 不这么做的后果是**血淋淋的**：把 10 个用例对着「真实 rootfs 的 passwd」
# 一次跑完，会得到 T01「pw_shell 不符」（真实 root 的 shell 是 /bin/bash
# 而探针期望 /bin/sh）、T08「直解路径错误地命中了非法行」（其实 passwd
# 存在、root 本来就能查到）——**四个 FAIL 全是分组错，不是代码缺陷**。
# 本 runner 的分组表就是为消除这类假阳性而存在的。
#
# 两个基线
# --------
#   bxroot 侧：libbxroot-runtime.so（BXROOT_BINDS/--preload 驱动，
#              设 EDGE_EXPECT_DIRECT=1 声明「直解路径预期生效」）
#   对照 侧：**不加任何 runtime**，直接在容器里跑同一个探针（不设
#              EDGE_EXPECT_DIRECT）—— 容器内就是完整 glibc + NSS。
#              这是可用的真实 NSS 基线（上游 ptrace 版 proot 在本容器
#              是双重翻译死胡同，别花时间）。
#
# ★ 对照侧的「同一份合成文件」怎么给 ★
# ---------------------------------
# 容器内 NSS 只认 /etc/passwd（= $ROOTFS/etc/passwd，同一 inode）。
# 所以对照侧必须在**同一个 trap 保护窗口**内把真实 /etc/passwd、
# /etc/group 换成与 bxroot 侧**逐字节相同**的合成内容，跑完立即恢复。
# 备份到 mktemp -d 私有目录，恢复后**校验 md5**；trap EXIT/INT/TERM 兜底。
# 恢复用 `cat 备份 > 目标`（就地覆写，保留 inode 与权限），不用 cp -a
# （那会换 inode —— 本项目的双视角陷阱里，inode 变化会让别的进程看到
# 不一样的 /etc/passwd）。
#
# ★ bxroot 侧为什么不是 launcher 而是 bridge ★
# -------------------------------------------
# 本容器**已经在官方 proroot 容器内**。实测：用 launcher（静态二进制）
# 直接跑，即使 env -i 清空环境、即使 LD_PRELOAD 明确指向 bxroot，
# guest 里映射进来的仍是官方 libproroot-runtime.so（`/proc/self/maps`
# 实证），`-b` 完全无效、`-r` 被忽略。也就是说 launcher 那条路在本容器
# 内**测不到 bxroot**（见报告「缺陷 0/环境事实」）。本仓库其余测试
# （RUN_PRIVDROP / RUN_PTHREAD_CREATE / RUN_SHEBANG / RUN_E2E …）走的都是
# `libproroot-bridge.so <linker> --preload <rt>` 这条路 —— 本 runner 照做。
# 脚本仍会编译 launcher 并跑一次**诊断**（不做判据），把上述事实留证。
#
# ★ 探针必须**动态链接** ★
# ----------------------
# LD_PRELOAD 对静态链接的 ELF 无效。静态编译探针 → 直解钩子根本没被加载，
# 测出来的是容器 glibc，两侧结果会"意外一致"，得出完全错误的结论。
# 本脚本编译后**显式校验产物是动态链接**（readelf 找 INTERP），不是就报错。
#
# 用法
# ----
#   sh test/RUN_NSS_EDGE.sh              # 完整跑（bxroot + 对照 + 缺陷钉桩）
#   sh test/RUN_NSS_EDGE.sh --bxroot-only   # 只跑 bxroot 侧（不碰真实 /etc）
#   sh test/RUN_NSS_EDGE.sh --keep          # 保留暂存目录（排障）
#   sh test/RUN_NSS_EDGE.sh --restore       # 从上次被 SIGKILL 打断的备份里恢复 /etc
#
# 环境变量
# --------
#   BXROOT_SO=<path>   指定被测的 libbxroot-runtime.so（默认 build/ 下的共享产物）。
#                      本项目并行跑多个 agent 时 build/ 可能对应**别人**的代码状态，
#                      要得到可归因的结论就自己 BUILD_RUNTIME.sh 到别处再指定。
#   ROOTFS=<path>      覆盖 rootfs 路径
#   CC=<compiler>      覆盖编译器
#
# 退出码
# ------
#   0 = 无 FAIL（允许 skip）   1 = 有 FAIL   2 = 环境不满足（SKIP）
# =====================================================================

set -u

SELF_DIR=$(dirname "$0")
ROOT=$(cd "$SELF_DIR/.." && pwd)
cd "$ROOT" || exit 2

CC="${CC:-gcc}"
ROOTFS="${ROOTFS:-/data/data/com.dsh.client/files/linux/ubuntu}"
# ★ 可用 BXROOT_SO=<path> 指向自建的运行时 ★
# 本项目经常**并行跑多个 agent**。build/libbxroot-runtime.so 是共享产物：
# 别的 agent 改完 src/ 重新构建之后，这个文件代表的是**别人的**代码状态。
# 实测踩到过：测试跑到一半 src/runtime/preload.c 的 mtime 超过了 build/ 里的
# .so（源比产物新），此时若直接用它，报告里的结论就对应不上任何一份源码。
# 所以：既允许覆盖，也在"源比产物新"时**显式警告**（不静默）。
BXROOT_SO="${BXROOT_SO:-$ROOT/build/libbxroot-runtime.so}"
PROBE_SRC="$ROOT/test/probe_nss_edge.c"
LAUNCHER_SRC="$ROOT/src/launcher/launcher.c"

BXROOT_ONLY=0
KEEP=0
RESTORE_ONLY=0
for a in "$@"; do
    case "$a" in
        --bxroot-only) BXROOT_ONLY=1 ;;
        --keep)        KEEP=1 ;;
        --restore)     RESTORE_ONLY=1 ;;
        *) echo "❌ 未知参数: $a"; exit 2 ;;
    esac
done

# ---------------------------------------------------------------------
# --restore：从「上一次被 SIGKILL 打断」留下的备份里恢复真实 /etc
# ---------------------------------------------------------------------
# ★ 为什么需要这个模式 ★
#
# 对照侧必须在窗口内把真实 /etc/passwd、/etc/group 换成合成内容。脚本对
# INT/TERM/HUP/PIPE/EXIT 都装了 trap，实测这些信号下都能完整恢复。
# 但 **SIGKILL 不可捕获** —— 进程被 `kill -9`（或 OOM killer 杀掉）时
# trap 来不及跑，/etc 会**停在合成内容上**。这是本方案唯一的硬缺口，
# 无法用 shell 消除（要根治只能用 mount namespace，而本容器 CapEff=0，
# unshare -m 直接 EPERM，实测过）。
#
# 缓解措施有两层（都已实现）：
#   ① 进入窗口前先写状态文件，SIGKILL 后它仍然在 —— 下次运行会**警告**；
#   ② 本 `--restore` 模式：读状态文件 → 用备份目录里的**硬链接**还原
#      （inode 与内容都能回去）。这样"被 -9 之后怎么办"有明确答案。
STAGE_STATE="${TMPDIR:-/tmp}/.bxroot-nss-edge-state"
if [ "$RESTORE_ONLY" = 1 ]; then
    echo "== NSS 边界测试 · 恢复模式 =="
    if [ ! -f "$STAGE_STATE" ]; then
        echo "   ℹ️  没有残留状态文件（$STAGE_STATE）—— 无需恢复"; exit 0
    fi
    BK=$(cat "$STAGE_STATE" 2>/dev/null)
    echo "   上次备份目录: $BK"
    [ -d "$BK" ] || { echo "   ❌ 备份目录不存在，无法自动恢复；请人工核对 /etc/passwd、/etc/group"; exit 2; }
    bad=0
    for f in passwd group; do
        st=$(cat "$BK/$f.state" 2>/dev/null || echo unknown)
        case "$st" in
            inode)
                rm -f "/etc/$f"
                ln "$BK/$f.inode" "/etc/$f" 2>/dev/null || { echo "   ❌ 恢复 /etc/$f 失败"; bad=1; continue; }
                [ -f "$BK/$f.mode" ] && chmod "$(cat "$BK/$f.mode")" "/etc/$f" 2>/dev/null
                ;;
            copy)
                cat "$BK/$f" > "/etc/$f" 2>/dev/null || { echo "   ❌ 恢复 /etc/$f 失败"; bad=1; continue; }
                ;;
            absent) rm -f "/etc/$f" ;;
            *) echo "   ⚠️  /etc/$f 状态未知，跳过"; continue ;;
        esac
        want=$(cat "$BK/$f.md5" 2>/dev/null || echo none)
        got=$(md5sum "/etc/$f" 2>/dev/null | awk '{print $1}')
        if [ "$want" = "$got" ]; then
            echo "   ✅ /etc/$f 已恢复（md5=$got）"
        else
            echo "   ❌ /etc/$f 恢复后 md5 不符: want=$want got=$got"; bad=1
        fi
    done
    if [ "$bad" = 0 ]; then
        rm -f "$STAGE_STATE"
        echo "   ✅ 恢复完成，状态文件已清除"
        echo "RESULT: PASS"; exit 0
    fi
    echo "RESULT: FAIL"; exit 1
fi

# ---------------------------------------------------------------------
# 环境探测
# ---------------------------------------------------------------------
# ★ 不要对 $APP_LIB 做任何存在性探测 ★
# 那是本项目的经典双视角陷阱（实测 [ -f ] [ -d ] ls cat test -x 全部为假，
# 而 exec 却能正常工作）。唯一可靠的办法是**真跑一次**。
detect_app_lib() {
    for m in /proc/[0-9]*/maps; do
        [ -r "$m" ] || continue
        p=$(grep -a 'libproroot-bridge\.so' "$m" 2>/dev/null | head -1 | awk '{print $6}')
        [ -n "${p:-}" ] && { echo "${p%/*}"; return 0; }
    done
    return 1
}

APP_LIB="${APP_LIB:-$(detect_app_lib || true)}"
[ -n "${APP_LIB:-}" ] || { echo "⏭️  跳过：探测不到官方库目录（需要真机容器）"; exit 2; }
case "$APP_LIB" in
    */lib/arm64) ;;
    *) echo "⏭️  跳过：库目录形状异常（$APP_LIB）"; exit 2 ;;
esac
BRIDGE="$APP_LIB/libproroot-bridge.so"
LINKER="$APP_LIB/libproroot-linker.so"

# bridge 可用性：真跑一次，看 usage 里有没有 trampoline
bridge_ok() {
    out=$(timeout 20 "$BRIDGE" 2>&1)
    case "$out" in
        *trampoline*) return 0 ;;
        *) return 1 ;;
    esac
}
bridge_ok || { echo "⏭️  跳过：proroot bridge 不可用（$APP_LIB）"; exit 2; }

[ -d "$ROOTFS" ]     || { echo "⏭️  跳过：找不到 ROOTFS（$ROOTFS）"; exit 2; }
[ -f "$BXROOT_SO" ]  || { echo "⏭️  跳过：缺 bxroot 产物（先跑 sh BUILD_RUNTIME.sh）"; exit 2; }
[ -f "$PROBE_SRC" ]  || { echo "❌ 缺探针源码 $PROBE_SRC"; exit 2; }
command -v "$CC" >/dev/null 2>&1 || { echo "❌ 找不到编译器 $CC"; exit 2; }

# ---------------------------------------------------------------------
# 暂存目录
# ---------------------------------------------------------------------
# ★ 双视角 ★：$STAGE_K 是容器视角，$STAGE_LD 是它的内核视角。
#   传给 --preload / BXROOT_ROOTFS 的必须是**内核视角**（那些值直达内核，
#   不经容器路径翻译）。
# ★ 不用 /tmp 固定共享路径 ★（本项目教训：共享固定路径 + rm -rf 会删掉
#   别人的工作文件）。用 mktemp -d 拿随机名，再拼内核视角。
STAGE_K=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-nss-edge-XXXXXX") || exit 2
STAGE_NAME=$(basename "$STAGE_K")
STAGE_LD="$ROOTFS/${STAGE_K#/}"
MINI_LD="$STAGE_LD/mini"          # bxroot 侧的迷你 rootfs（内核视角）
WORK="$STAGE_K/work"

# 对照侧的真实 /etc 目标（容器视角 == 内核视角，同一 inode）
REAL_ETC="/etc"

mkdir_in_rootfs() {
    python3 - "$@" <<'PYEOF'
import os, sys
for d in sys.argv[1:]:
    os.makedirs(d, exist_ok=True)
PYEOF
}
rm_rootfs_dir() {
    python3 - "$1" <<'PYEOF' || true
import shutil, sys
shutil.rmtree(sys.argv[1], ignore_errors=True)
PYEOF
}

# ---------------------------------------------------------------------
# 对照侧的 /etc 备份 + 恢复（trap 兜底）
# ---------------------------------------------------------------------
# ★ 为什么备份要**硬链接**，不是 cat 复制 ★
#
# 本容器是「官方 proroot 容器」：容器视角 /etc/passwd 与内核视角
# $ROOTFS/etc/passwd 是**同一个 inode**。第一版 runner 用
# `cat 备份 > /etc/passwd` 换内容，跑完再 `cat 回去` ——
# **内容 md5 恢复了，inode 却变了**（6012456 → 6080154）。inode 一变，
# 别的进程/别的视角里那份"同一个文件"就对不上了，属于本项目反复出现的
# 双视角陷阱。改法：备份时**留一个硬链接**（同 inode），换文件用
# `rm + 新建`，恢复时 `rm + ln 硬链接` —— inode 与内容都能逐位还原。
#
# 之所以能这么做，是因为本容器 CapEff=0（无 CAP_DAC_READ_SEARCH，
# mknod 不可用），但硬链接可用（实测 /etc 内可以建硬链接）。
BACKUP=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-nss-edge-bak-XXXXXX") || exit 2
# 残留状态文件：记录"本次运行可能改过 /etc"，正常结束时由 cleanup 删除。
# 下次启动若看到它，说明上一次是被信号打断的（cleanup 的中止检测）。
BAK_STATE_FILE="${TMPDIR:-/tmp}/.bxroot-nss-edge-state"
bak_state() { echo "$BACKUP/$1.state"; }

prepare_backup() {
    for f in passwd group; do
        if [ -e "$REAL_ETC/$f" ]; then
            # 硬链接保留 inode（跨设备会失败，失败就退回内容备份）
            if ln "$REAL_ETC/$f" "$BACKUP/$f.inode" 2>/dev/null; then
                echo inode > "$(bak_state "$f")"
            elif cat "$REAL_ETC/$f" > "$BACKUP/$f" 2>/dev/null; then
                echo copy > "$(bak_state "$f")"
                echo "   ⚠️  /etc/$f 硬链接失败，退回内容备份（恢复后 inode 会变）"
            else
                return 1
            fi
            md5sum "$REAL_ETC/$f" | awk '{print $1}' > "$BACKUP/$f.md5"
            stat -c '%a'  "$REAL_ETC/$f" > "$BACKUP/$f.mode" 2>/dev/null || echo 644 > "$BACKUP/$f.mode"
            stat -c '%d:%i' "$REAL_ETC/$f" > "$BACKUP/$f.ino" 2>/dev/null || echo none > "$BACKUP/$f.ino"
        else
            echo absent > "$(bak_state "$f")"
        fi
    done
    return 0
}

restore_etc() {
    for f in passwd group; do
        st=$(cat "$(bak_state "$f")" 2>/dev/null || echo unknown)
        case "$st" in
            inode)
                rm -f "$REAL_ETC/$f" 2>/dev/null
                ln "$BACKUP/$f.inode" "$REAL_ETC/$f" 2>/dev/null \
                    || cat "$BACKUP/$f.inode" > "$REAL_ETC/$f" 2>/dev/null || true
                [ -f "$BACKUP/$f.mode" ] && chmod "$(cat "$BACKUP/$f.mode")" "$REAL_ETC/$f" 2>/dev/null
                ;;
            copy)
                cat "$BACKUP/$f" > "$REAL_ETC/$f" 2>/dev/null || true
                [ -f "$BACKUP/$f.mode" ] && chmod "$(cat "$BACKUP/$f.mode")" "$REAL_ETC/$f" 2>/dev/null
                ;;
            absent) rm -f "$REAL_ETC/$f" 2>/dev/null || true ;;
        esac
    done
}

verify_restore() {
    bad=0
    for f in passwd group; do
        st=$(cat "$(bak_state "$f")" 2>/dev/null || echo unknown)
        [ "$st" = absent ] && continue
        [ "$st" = unknown ] && continue
        want=$(cat "$BACKUP/$f.md5" 2>/dev/null || echo none)
        got=$(md5sum "$REAL_ETC/$f" 2>/dev/null | awk '{print $1}')
        if [ "$want" != "$got" ]; then
            echo "   ❌ /etc/$f 内容恢复校验失败: want=$want got=$got"; bad=1
        fi
        # ★ inode 也要校验 ★（第一版只查 md5，漏掉了 inode 变化）
        if [ "$st" = inode ]; then
            wi=$(cat "$BACKUP/$f.ino" 2>/dev/null || echo none)
            gi=$(stat -c '%d:%i' "$REAL_ETC/$f" 2>/dev/null || echo none)
            if [ "$wi" != "$gi" ]; then
                echo "   ❌ /etc/$f inode 未还原: want=$wi got=$gi（双视角会不一致）"; bad=1
            fi
        fi
    done
    return $bad
}

# ★ 清理必须**幂等**，而且要把「恢复 /etc」放在「删暂存」之前 ★
#
# 实测教训（本 runner 第一版）：`sh RUN_NSS_EDGE.sh | head -30` 会在输出被
# 截断时给脚本发 SIGPIPE。dash 收到 PIPE 后**逐条执行 trap 命令**，若 trap
# 里的命令自己也写 stdout（比如 echo 一句"已删除…"），它会**再次**触发 PIPE，
# 于是 trap 在半路被打断 —— 暂存目录留了下来（实测残留三个）。
#
# 后果分两级：
#   - 只留下 /tmp 里的暂存目录：脏，但无害。
#   - **若打断发生在 restore_etc 之前/之中，真实 /etc/passwd 会停在合成内容上**
#     —— 那是真正危险的。所以：① 恢复放最前面；② 打断后重复调用要安全；
#     ③ 清理过程**绝不写 stdout/stderr**（写文件或 /dev/null）。
#
# 另外补一层**兜底**：把自己的 PID 记进状态文件，下次启动时如果发现残留的
# 状态文件（说明上一次没清干净），先恢复再继续。
cleanup() {
    # ① 先恢复真实 /etc（最要紧的事，且本身不写 stdout）
    restore_etc
    # ② 再删暂存（同样不写 stdout）
    if [ "${KEEP:-0}" = 1 ]; then
        : # --keep 时保留
    else
        rm_rootfs_dir "$STAGE_LD"
        rm -rf "$STAGE_K" "$BACKUP" 2>/dev/null
    fi
    rm -f "$BAK_STATE_FILE" 2>/dev/null
}

# 上一次运行是否留下了未清理的状态？（有 = 上次被信号打断或被 SIGKILL）
if [ -f "$BAK_STATE_FILE" ]; then
    echo "   ⚠️  检测到上一次运行残留的状态文件：$BAK_STATE_FILE"
    echo "      备份目录: $(cat "$BAK_STATE_FILE" 2>/dev/null)"
    echo "      上一次可能被信号打断（含不可捕获的 SIGKILL），/etc/passwd、"
    echo "      /etc/group 也许没恢复。请先核对并恢复："
    echo "          sh test/RUN_NSS_EDGE.sh --restore      # 自动从备份还原"
    echo "          md5sum /etc/passwd /etc/group          # 人工核对"
fi
# HUP/QUIT/PIPE 也要接（★ 尤其是 PIPE ★）：`sh RUN_NSS_EDGE.sh | head` 会因为
# 读者退出而给脚本发 SIGPIPE，不接就等于"最常见的调用方式下没有兜底"。
trap 'cleanup; exit 129' HUP
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM
trap 'cleanup; exit 141' PIPE
trap 'cleanup' EXIT

echo "== NSS 直解回退 · 边界回归 =="
echo "   rootfs    : $ROOTFS"
echo "   bxroot rt : $BXROOT_SO"
echo "              md5=$(md5sum "$BXROOT_SO" 2>/dev/null | awk '{print $1}')"
# 源比产物新 → 产物可能对应的是**别的**代码状态（本项目并行跑多个 agent）
if [ "$ROOT/src/runtime/preload.c" -nt "$BXROOT_SO" ]; then
    echo "   ⚠️  src/runtime/preload.c 比该 .so 新 —— 产物可能已过期/对应别的源码状态。"
    echo "      建议：BXROOT_SO=<自建路径> sh test/RUN_NSS_EDGE.sh（结论才可归因）"
fi
echo "   官方库目录: $APP_LIB"
echo "   暂存      : $STAGE_K（内核视角 $STAGE_LD）"
if [ "$BXROOT_ONLY" = 1 ]; then
    echo "   模式      : --bxroot-only（不跑对照侧，不碰真实 /etc）"
fi
echo

# ---------------------------------------------------------------------
# 编译
# ---------------------------------------------------------------------
mkdir -p "$WORK" 2>/dev/null
mkdir_in_rootfs "$STAGE_LD" "$MINI_LD" "$MINI_LD/etc" "$MINI_LD/tmp" "$WORK" || {
    echo "❌ 无法在 ROOTFS 内创建暂存目录"; exit 2; }

# gcc 13.3.0 有间歇性 ICE：重试；用 'internal compiler error' 区分 ICE 与真错误。
# ★ 成败一律以**产物文件是否存在**为准 ★（`grep -cE "error: "` 在输出为空时
#   返回 0，会把失败误报成成功 —— 本项目踩过这个坑）。
compile_retry() {
    # $1 = 输出路径，$2 = 日志，其余 = 编译参数
    out="$1"; log="$2"; shift 2
    i=1
    while [ "$i" -le 10 ]; do
        rm -f "$out"
        "$CC" "$@" -o "$out" 2>"$log"
        [ -f "$out" ] && return 0
        if ! grep -q 'internal compiler error' "$log"; then
            return 1        # 真错误，重试无意义
        fi
        echo "   ℹ️  gcc ICE，重试第 $i 次" >&2
        i=$((i + 1))
    done
    return 1
}

echo "--- 编译 ---"
# 探针：**动态**链接（LD_PRELOAD 的前提）
if ! compile_retry "$WORK/probe" "$WORK/probe.cc.err" -O1 -g -Wall "$PROBE_SRC"; then
    echo "❌ 探针编译失败（非 ICE）"; head -15 "$WORK/probe.cc.err"; exit 2
fi
if ! readelf -l "$WORK/probe" 2>/dev/null | grep -q 'INTERP'; then
    echo "❌ 探针不是动态链接 —— LD_PRELOAD 不会生效，测不出直解路径"
    exit 2
fi
echo "   ✅ 探针已编译（动态链接，INTERP 存在）"

# launcher：静态（仅用于诊断，不做判据）。★ 产物名不能以 .so 结尾 ★
# （否则 glibc _dl_get_origin 断言崩溃）
LAUNCHER="$WORK/bxroot-launcher-bin"
HAVE_LAUNCHER=0
if [ -f "$LAUNCHER_SRC" ]; then
    if compile_retry "$LAUNCHER" "$WORK/launcher.cc.err" \
        -static -O1 -Wall -Wextra -Wno-nonnull-compare "$LAUNCHER_SRC"; then
        HAVE_LAUNCHER=1
        # launcher 在**自己所在目录**找 libbxroot-runtime.so（无 BXROOT_LIB_PATH 时）。
        # 不放的话 LD_PRELOAD 指向一个不存在的文件，诊断会得出一句
        # "bxroot=0" —— 那是"没注入成功"，会被误读成"被官方顶掉"。
        cp "$BXROOT_SO" "$WORK/libbxroot-runtime.so" 2>/dev/null
        echo "   ✅ launcher 已编译（静态，仅诊断用）"
    else
        echo "   ⚠️  launcher 编译失败（非 ICE）—— 跳过 launcher 诊断"
        head -5 "$WORK/launcher.cc.err" | sed 's/^/      /'
    fi
fi

# ---------------------------------------------------------------------
# 迷你 rootfs（只放跑探针必需的几个文件）
# ---------------------------------------------------------------------
# ★ 强烈推荐路径 ★：不动真 rootfs。bxroot 的 rootfs 换成这个副本后，
# /etc/passwd、/etc/group 都是我们自己的合成文件。
echo "--- 准备迷你 rootfs ---"
python3 - "$ROOTFS" "$MINI_LD" "$BXROOT_SO" "$WORK/probe" <<'PYEOF' || { echo "❌ 迷你 rootfs 准备失败"; exit 2; }
import os, shutil, sys, glob
rootfs, mini, so, probe = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

def cp(src, dst):
    if os.path.exists(src) or os.path.islink(src):
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if os.path.islink(src):
            t = os.readlink(src)
            if os.path.lexists(dst): os.remove(dst)
            os.symlink(t, dst)
        else:
            shutil.copy2(src, dst)
        return True
    return False

# 加载器 + libc：探针能起来的最小集合
libdir = os.path.join(rootfs, "lib/aarch64-linux-gnu")
for name in ("ld-linux-aarch64.so.1", "libc.so.6"):
    cp(os.path.join(libdir, name), os.path.join(mini, "lib/aarch64-linux-gnu", name))
# /lib/ld-linux-aarch64.so.1 通常是符号链接；两条都铺，避免依赖宿主
ld = os.path.join(mini, "lib/ld-linux-aarch64.so.1")
if not os.path.lexists(ld):
    os.makedirs(os.path.dirname(ld), exist_ok=True)
    try: os.symlink("aarch64-linux-gnu/ld-linux-aarch64.so.1", ld)
    except FileExistsError: pass
# libnss_files：真实 NSS 的 files 后端（glibc 2.39 已内置于 libc，这里铺上更忠实）
for pat in ("lib/aarch64-linux-gnu/libnss_files.so.2",
            "usr/lib/aarch64-linux-gnu/libnss_files.so.2"):
    if cp(os.path.join(rootfs, pat), os.path.join(mini, pat)): break

# nsswitch：让「真实 NSS 先试、失败才回退」这件事有据可依
with open(os.path.join(mini, "etc/nsswitch.conf"), "w") as f:
    f.write("passwd: files\ngroup: files\n")

shutil.copy2(so, os.path.join(mini, "libbxroot-runtime.so"))
shutil.copy2(probe, os.path.join(mini, "probe"))
os.chmod(os.path.join(mini, "probe"), 0o755)
print("   ✅ 迷你 rootfs 就绪:", sorted(os.listdir(mini)))
PYEOF

# ---------------------------------------------------------------------
# 文件组表
# ---------------------------------------------------------------------
# 每组的 (passwd, group) 内容 —— 探针注释里说的「runner 的组表」。
# 用例归属是从 probe_nss_edge.c 的实际实现读出来的，不是照抄题面：
#   T01 只查 passwd root（uid/dir/shell）+ getpwnam_r
#   T02 passwd 缺字段行 bad:x:1:2        T03 passwd/group 都只有空行
#   T04 passwd 超长行 + group 超长行      T05 passwd uid/gid 非数字
#   T06 group 多成员 5 个                T07 group 空成员列表
#   T08 passwd 文件不存在                T09 四族 ×100 次
#   T10 ERANGE（buf=8），用 passwd root + group g
GROUP_CASES_A="1,6,7,9,10"
GROUP_CASES_B="2,5"
GROUP_CASES_C="4"
GROUP_CASES_D="3"
GROUP_CASES_E="8"
GROUP_CASES_F=""            # F 只跑缺陷钉桩（见 §6），不跑 T 用例
GROUPS="A B C D E F"

# 把组内容写进 $1/etc（内核视角目录）
write_group() {
    grp="$1"; dest="$2"
    python3 - "$grp" "$dest" <<'PYEOF'
import os, sys
grp, dest = sys.argv[1], sys.argv[2]
os.makedirs(dest, exist_ok=True)
ROOT_ENTRY = "root:x:0:0:root:/root:/bin/sh\n"      # T01 期望 shell=/bin/sh
CONTENT = {
 "A": (ROOT_ENTRY,
       "root:x:0:\ng:x:1:m1,m2,m3,m4,m5\nempty:x:1:\n"),
 "B": (ROOT_ENTRY + "bad:x:1:2\nbadnum:x:abc:def:junk:/home/badnum:/bin/sh\n",
       "root:x:0:\n"),
 "C": ("LONG:" + "a" * 990 + ":1:1:G:/H:/BIN\n" + ROOT_ENTRY,
       "longg:x:7:" + "b" * 1200 + "\nroot:x:0:\n"),
 "D": ("\n\n\n", "\n\n\n"),
 "E": (None, "root:x:0:\n"),                          # passwd 缺失（fopen 失败路径）
 "F": ("root:x:0:0:root:/root:/bin/sh\n"
       "lastuser:x:777:777:L:/home/last:/bin/sh",    # ★ 末尾故意不带换行
       "root:x:0:\nnine:x:9:" + ",".join("m%d" % i for i in range(1, 10)) + "\n"
       "empty:x:1:\ns:x:5:a\n"),
}
pw, gr = CONTENT[grp]
for name, data in (("passwd", pw), ("group", gr)):
    p = os.path.join(dest, name)
    if os.path.lexists(p):
        os.remove(p)
    if data is not None:
        with open(p, "w") as f:
            f.write(data)
PYEOF
}

# ---------------------------------------------------------------------
# 两个侧的执行器
# ---------------------------------------------------------------------
run_bxroot() {
    # $1 = EDGE_CASES（空 = 全跑）
    EDGE_EXPECT_DIRECT=1 \
    BXROOT_ROOTFS="$MINI_LD" \
    BXROOT_TMP_DIR="$MINI_LD/tmp" \
    BXROOT_WORKDIR="/" \
    BXROOT_FAKEROOT=1 \
    BXROOT_GUEST_EXE="$MINI_LD/probe" \
    EDGE_CASES="$1" \
    timeout 180 "$BRIDGE" "$LINKER" \
        --argv0 probe --preload "$MINI_LD/libbxroot-runtime.so" \
        "$MINI_LD/probe" 2>&1 \
      | grep -vE '^\[NEXT\]|^\[bxroot\]'
}

run_control() {
    # $1 = EDGE_CASES；★ 不设 EDGE_EXPECT_DIRECT ★
    # 直接在容器里跑（完整 glibc + NSS），/etc 已由调用方换成同组合成内容
    EDGE_CASES="$1" \
    timeout 120 env -u EDGE_EXPECT_DIRECT "$WORK/probe" 2>&1
}

# 缺陷钉桩探针：由 runner 生成（不进 test/ 的交付面，保持交付物只有 runner + 报告）
cat > "$WORK/defect.c" <<'CEOF'
/* 缺陷钉桩：把「直解解析器」与「glibc 的 NSS files 解析器」在同一份合成
 * 文件上的行为差异钉住。判据的期望值来自 glibc 语义与 passwd/group 格式
 * 规范，不是来自 bxroot 的当前实现。 */
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>

#define NINE_MEMBERS 9          /* nine:x:9:m1..m9 */

static int nmem(char **m) { int n = 0; if (m) while (m[n]) n++; return n; }

/* D2 用：buf 前后各放哨兵，检测越界写 */
static struct {
    unsigned char pre[16];
    char buf[20];
    unsigned char post[32];
} g_f;

static void canary_fill(void)
{
    memset(g_f.pre, 0xA5, sizeof g_f.pre);
    memset(g_f.buf, 0x00, sizeof g_f.buf);
    memset(g_f.post, 0x5A, sizeof g_f.post);
}
static int canary_check(void)
{
    size_t i; int bad = 0;
    volatile unsigned char *p = g_f.pre, *q = g_f.post;
    for (i = 0; i < sizeof g_f.pre; i++)  if (p[i] != 0xA5) bad++;
    for (i = 0; i < sizeof g_f.post; i++) if (q[i] != 0x5A) bad++;
    return bad;
}

int main(void)
{
    struct group gt, *gres = NULL;
    struct passwd pt, *pres = NULL;
    char big[4096];
    int rc, bad = 0;

    /* D1: getgrnam_r 多成员组 —— 应返回全部 9 个成员 */
    rc = getgrnam_r("nine", &gt, big, sizeof big, &gres);
    printf("D1 getgrnam_r(nine) nmem=%d rc=%d (期望 nmem=%d)\n",
           nmem(gres ? gres->gr_mem : NULL), rc, NINE_MEMBERS);
    if (rc != 0 || gres == NULL || nmem(gres->gr_mem) != NINE_MEMBERS) bad++;

    /* D2: getgrnam_r 缓冲区不足时**不得**越界写调用方缓冲 */
    canary_fill();
    {
        struct group g2; struct group *r2 = NULL;
        int rc2 = getgrnam_r("s", &g2, g_f.buf, sizeof g_f.buf, &r2);
        int clob = canary_check();
        printf("D2 getgrnam_r(s,buflen=20) rc=%d 哨兵被破坏=%d 字节 (期望 0)\n", rc2, clob);
        if (clob != 0) bad++;
    }

    /* D3: getgrnam 多成员组 —— 应返回全部 9 个成员 */
    {
        struct group *g = getgrnam("nine");
        printf("D3 getgrnam(nine)   nmem=%d (期望 %d)\n",
               nmem(g ? g->gr_mem : NULL), NINE_MEMBERS);
        if (g == NULL || nmem(g->gr_mem) != NINE_MEMBERS) bad++;
    }

    /* D4: 文件末行不带换行符 —— 仍是合法记录，应能查到 */
    {
        struct passwd *pw = getpwnam("lastuser");
        printf("D4 getpwnam(lastuser) = %s (期望 lastuser；末行无换行)\n",
               pw && pw->pw_name ? pw->pw_name : "(NULL)");
        if (pw == NULL || pw->pw_uid != 777) bad++;
    }

    /* D5: _r 版「查不到」的返回契约 —— glibc 是 rc=0 且 *result=NULL */
    rc = getpwnam_r("nosuchuser", &pt, big, sizeof big, &pres);
    printf("D5 getpwnam_r(不存在) rc=%d res=%s (glibc 契约 rc=0 res=NULL)\n",
           rc, pres ? "non-NULL" : "NULL");
    if (rc != 0 || pres != NULL) bad++;
    rc = getgrnam_r("nosuchgrp", &gt, big, sizeof big, &gres);
    printf("D5 getgrnam_r(不存在) rc=%d res=%s (glibc 契约 rc=0 res=NULL)\n",
           rc, gres ? "non-NULL" : "NULL");
    if (rc != 0 || gres != NULL) bad++;

    printf("probe DEFECT: fail=%d\n", bad);
    return bad > 0 ? 1 : 0;
}
CEOF

if ! compile_retry "$WORK/defect" "$WORK/defect.cc.err" -O1 -Wall "$WORK/defect.c"; then
    echo "❌ 缺陷钉桩探针编译失败（非 ICE）"; head -15 "$WORK/defect.cc.err"; exit 2
fi
readelf -l "$WORK/defect" 2>/dev/null | grep -q INTERP || {
    echo "❌ 缺陷钉桩探针不是动态链接"; exit 2; }
python3 -c "import shutil,sys; shutil.copy2(sys.argv[1], sys.argv[2])" \
    "$WORK/defect" "$MINI_LD/defect" 2>/dev/null || cp "$WORK/defect" "$MINI_LD/defect"
chmod 755 "$MINI_LD/defect" 2>/dev/null || true

run_defect_bxroot() {
    EDGE_EXPECT_DIRECT=1 \
    BXROOT_ROOTFS="$MINI_LD" BXROOT_TMP_DIR="$MINI_LD/tmp" BXROOT_WORKDIR="/" \
    BXROOT_FAKEROOT=1 BXROOT_GUEST_EXE="$MINI_LD/defect" \
    timeout 180 "$BRIDGE" "$LINKER" \
        --argv0 defect --preload "$MINI_LD/libbxroot-runtime.so" "$MINI_LD/defect" 2>&1 \
      | grep -vE '^\[NEXT\]|^\[bxroot\]'
}
run_defect_control() {
    timeout 120 "$WORK/defect" 2>&1
}

# =====================================================================
# §1 launcher 诊断（不做判据，只留证）
# =====================================================================
if [ "$HAVE_LAUNCHER" = 1 ]; then
    echo
    echo "--- §1 launcher 路径诊断（非判据）---"
    cat > "$WORK/who.c" <<'CEOF'
#include <stdio.h>
#include <string.h>
int main(void){
    FILE *f=fopen("/proc/self/maps","r"); char l[512]; int bx=0, off=0;
    while(f && fgets(l,sizeof l,f)){
        if(strstr(l,"bxroot")) bx++;
        if(strstr(l,"libproroot-runtime")) off++;
    }
    if(f) fclose(f);
    printf("maps: bxroot=%d official_runtime=%d\n", bx, off);
    f=fopen("/etc/passwd","r");
    printf("first line of /etc/passwd: %s", f&&fgets(l,sizeof l,f)?l:"(unreadable)\n");
    if(f) fclose(f);
    return 0;
}
CEOF
    compile_retry "$WORK/who" "$WORK/who.cc.err" -O1 -Wall "$WORK/who.c" >/dev/null 2>&1
    cp "$WORK/who" "$MINI_LD/who" 2>/dev/null
    chmod 755 "$MINI_LD/who" 2>/dev/null
    if [ -f "$WORK/who" ]; then
        # ★ launcher 的 guest 路径必须用**容器视角** ★
        # launcher 用 access() 找命令，而 access 走容器路径翻译。
        # 第一版这里传了内核视角（$MINI_LD），于是 access("//data/data/...") 
        # 失败 → 输出里根本没有 maps: 行 → case 匹配掉进 else 分支，
        # 打出一句**与实际相反的**"本次未被顶掉"。教训：诊断分支必须先把
        # "探针压根没跑起来"和"跑起来了但结论不同"区分开。
        guest_k="$STAGE_K/mini/who"
        lout=$(env -i PATH=/usr/bin:/bin timeout 60 "$LAUNCHER" -r / -0 -w / \
                  "$guest_k" 2>&1 | grep -E 'maps:|first line')
        echo "$lout" | sed 's/^/   /'
        case "$lout" in
            *"maps:"*)
                case "$lout" in
                    *official_runtime=1*|*official_runtime=2*)
                        echo "   ℹ️  本容器已被官方 proroot 接管：launcher 注入的 bxroot 运行时"
                        echo "      在 guest 里被官方 runtime 顶掉（见报告「环境事实 E1」）。"
                        echo "      → 因此正式判据走 bridge --preload 路（本仓库其余测试同）" ;;
                    *"bxroot="*)
                        echo "   ℹ️  launcher 路径本次未被顶掉（与既有结论不同，值得复查）" ;;
                esac ;;
            *)
                echo "   ⚠️  launcher 诊断未产出 maps 行 —— 探针没跑起来（不是结论）。"
                printf '%s\n' "$lout" | sed 's/^/      /'
                echo "      → 忽略本节，正式判据见 §2/§3" ;;
        esac
    fi
fi

# =====================================================================
# §2 bxroot 侧：按文件组跑 T01..T10
# =====================================================================
echo
echo "--- §2 bxroot 侧（直解路径，EDGE_EXPECT_DIRECT=1）---"
BX_ALL="$WORK/bx_all.txt"
: > "$BX_ALL"
for g in $GROUPS; do
    [ "$g" = F ] && continue
    eval "cases=\$GROUP_CASES_$g"
    write_group "$g" "$MINI_LD/etc"
    echo "   [组 $g] cases=$cases"
    out=$(run_bxroot "$cases")
    printf '%s\n' "$out" | sed 's/^/     /'
    printf '%s\n' "$out" >> "$BX_ALL"
    # 每组都应当有且仅有末行小结
    case "$out" in
        *"probe EDGE: ok="*) ;;
        *) echo "     ❌ 组 $g 没有产出小结行（探针崩溃或被拒？）" ;;
    esac
done

# =====================================================================
# §3 对照侧：真实 NSS（trap 保护下换真实 /etc）
# =====================================================================
CT_ALL="$WORK/ct_all.txt"
: > "$CT_ALL"
CT_RUN=0
if [ "$BXROOT_ONLY" = 1 ]; then
    echo
    echo "--- §3 对照侧：--bxroot-only，跳过 ---"
else
    echo
    echo "--- §3 对照侧（真实 glibc NSS，同一个探针、同一份合成文件）---"
    if ! prepare_backup; then
        echo "   ⚠️  无法备份 /etc/passwd、/etc/group —— 跳过对照侧（不冒险改真实文件）"
    else
        CT_RUN=1
        # ★ 进入"会改真实 /etc"的窗口：立刻立状态文件 ★
        # 之后无论怎么退出（正常/信号/被打断），残留状态文件都会让**下一次**
        # 运行在开头警告。正常跑完由 cleanup 删掉它。
        printf '%s\n' "$BACKUP" > "$BAK_STATE_FILE" 2>/dev/null || true
        # 备份指纹留证
        echo "   备份指纹（恢复后校验用）:"
        for f in passwd group; do
            st=$(cat "$(bak_state "$f")")
            case "$st" in
                absent) echo "     /etc/$f = 原本不存在" ;;
                *)      echo "     /etc/$f md5=$(cat "$BACKUP/$f.md5") mode=$(cat "$BACKUP/$f.mode") inode=$(cat "$BACKUP/$f.ino") 方式=$st" ;;
            esac
        done
        for g in $GROUPS; do
            eval "cases=\$GROUP_CASES_$g"
            write_group "$g" "$REAL_ETC"
            if [ "$g" = F ]; then
                echo "   [组 $g] 缺陷钉桩"
                out=$(run_defect_control)
            else
                echo "   [组 $g] cases=$cases"
                out=$(run_control "$cases")
            fi
            printf '%s\n' "$out" | sed 's/^/     /'
            printf '%s\n' "$out" >> "$CT_ALL"
            # 立即恢复，缩小风险窗口
            restore_etc
        done
        echo "   ✅ 已恢复真实 /etc/passwd、/etc/group"
        if verify_restore; then
            echo "   ✅ 恢复校验通过（md5 与备份一致）"
        else
            echo "   ❌ 恢复校验失败 —— 真实 /etc 可能已损坏，请立即人工检查！"
            CT_RESTORE_BAD=1
        fi
    fi
fi

# =====================================================================
# §4 T01..T10 两侧结果汇总
# =====================================================================
echo
echo "--- §4 用例汇总（T01..T10）---"
printf '   %-5s %-46s %-10s %-10s\n' "用例" "判据（探针首列描述）" "bxroot" "对照"
PASS=0; FAIL=0; SKIP=0
FAILED_LIST=""
i=1
while [ "$i" -le 10 ]; do
    id=$(printf 'T%02d' "$i")
    bx=$(grep -m1 "^\[.*\] $id " "$BX_ALL" 2>/dev/null || true)
    ct=$(grep -m1 "^\[.*\] $id " "$CT_ALL" 2>/dev/null || true)
    bxs=$(printf '%s' "$bx" | sed -n 's/^\[\([a-zA-Z]*\)\].*/\1/p')
    cts=$(printf '%s' "$ct" | sed -n 's/^\[\([a-zA-Z]*\)\].*/\1/p')
    [ -n "$bxs" ] || bxs="缺失"
    [ -n "$cts" ] || cts="-"
    # 判据描述：取探针行里用例号之后的部分，去掉结果详情
    desc=$(printf '%s' "$bx" | sed -n "s/^\[[a-zA-Z]*\] $id //p" | cut -c1-44)
    [ -n "$desc" ] || desc=$(printf '%s' "$ct" | sed -n "s/^\[[a-zA-Z]*\] $id //p" | cut -c1-44)
    printf '   %-5s %-46s %-10s %-10s\n' "$id" "$desc" "$bxs" "$cts"
    case "$bxs" in
        ok)   PASS=$((PASS + 1)) ;;
        skip) SKIP=$((SKIP + 1)) ;;
        *)    FAIL=$((FAIL + 1)); FAILED_LIST="$FAILED_LIST $id" ;;
    esac
    i=$((i + 1))
done

echo
echo "   bxroot 侧明细："
grep -E '^\[(ok|FAIL|skip)\]' "$BX_ALL" 2>/dev/null | sed 's/^/     /'
echo "   bxroot 小结："
grep 'probe EDGE: ok=' "$BX_ALL" 2>/dev/null | sed 's/^/     /'
if [ "$CT_RUN" = 1 ]; then
    echo "   对照侧明细："
    grep -E '^\[(ok|FAIL|skip)\]' "$CT_ALL" 2>/dev/null | sed 's/^/     /'
    echo "   对照侧小结："
    grep 'probe EDGE: ok=' "$CT_ALL" 2>/dev/null | sed 's/^/     /'
fi

# =====================================================================
# §5 缺陷钉桩：D1..D5
# =====================================================================
echo
echo "--- §5 缺陷钉桩（直解解析器 vs glibc 语义）---"
DF_BAD=0
# ★ 必须先换文件再跑 ★
# 本 runner 第一版在这里踩了自己的坑：§2 的起跑循环把 F 组 `continue` 掉了，
# 于是 §5 是在**上一组（E 组：passwd 缺失）**的文件上跑的 —— D1/D3/D4/D5
# 全部返回 ENOENT，看起来像"一堆缺陷"，实为文件组错配。
# 「跑之前先确认文件组」这条纪律，对 runner 自己和被测代码一样适用。
write_group F "$MINI_LD/etc"
DBX=$(run_defect_bxroot)
echo "   bxroot："
printf '%s\n' "$DBX" | grep -E '^D[0-9]|probe DEFECT' | sed 's/^/     /'
if printf '%s\n' "$DBX" | grep -q 'probe DEFECT: fail=0'; then
    echo "   ✅ bxroot 缺陷钉桩全部通过（D1..D5 无差异）"
else
    DF_BAD=1
    echo "   ❌ bxroot 缺陷钉桩有差异（见上）—— 这些是本轮**新发现**的真实缺陷，"
    echo "      已登记在 docs/NSS直解边界测试报告.md，未改 src/（按任务约束）"
fi
if [ "$CT_RUN" = 1 ]; then
    DCT=$(grep -E '^D[0-9]|probe DEFECT' "$CT_ALL" 2>/dev/null || true)
    if [ -n "$DCT" ]; then
        echo "   对照（真实 glibc，同一份合成文件）："
        printf '%s\n' "$DCT" | sed 's/^/     /'
        case "$DCT" in
            *"probe DEFECT: fail=0"*) echo "   ✅ 对照侧无差异 → 说明 D1..D5 是 bxroot 直解侧的问题，不是文件格式或环境问题" ;;
            *) echo "   ⚠️  对照侧也有差异 —— 需先排除文件内容/环境因素再下结论" ;;
        esac
    fi
fi

# =====================================================================
# §6 真实 rootfs 上的 NSS 全家（回归锚点：本特性最初就是为 dpkg 修的）
# =====================================================================
# ★ 与 §2/§3 的区别 ★
# §2/§3 用**迷你 rootfs / 换真实 /etc** 制造边界文件，测的是「解析器边界」。
# 本节反过来：**不动任何文件**，在真实 rootfs 上问一次「常见 NSS 查询还能不能
# 正常工作」。这是回归锚点 —— 缺口 D 的原始症状就是 `getent passwd root` 空、
# `dpkg -i` 报 unknown system user 'root'（见 docs/缺口D-NSS用户库查询失败.md）。
# 边界用例再多，如果这条断了，特性就是没修好。
#
# ★ 官方 runtime 不能作为本节的对照 ★
# 实测：官方 libproroot-runtime.so 在本容器 harness 下**不做任何路径翻译**
# （把 PROROOT_ROOTFS 指向一个只有 MINI-UNIQUE-HOST 的 rootfs，它仍读到容器
# 的 /etc/hostname；PROROOT_BINDS / PROROOT_ESCAPE_FD / PROROOT_CFG_FD 均试过）。
# 也就是说官方那侧看到的是**容器的真 /etc/passwd**，与 bxroot 的 rootfs 不是
# 同一个文件 —— 拿它当对照会得出"两侧一致"的假结论。所以本节只做
# 「bxroot 侧绝对判据」，官方数字若打印仅作现象记录。
echo
echo "--- §6 真实 rootfs 上的 NSS 全家（回归锚点，非边界）---"
rcmd='printf "getent passwd root: [%s]\n" "$(getent passwd root)"; printf "getent group root: [%s]\n" "$(getent group root)"; printf "getent group messagebus: [%s]\n" "$(getent group messagebus)"; printf "id: [%s]\n" "$(id)"'
# ★ --preload 的 .so 必须放在 ROOTFS 内（内核视角）★
# 直接给容器视角的 build/ 路径会得到 `deps: failed to preload ...` ——
# 这是本项目"双视角陷阱"的又一实例：--preload 的值直达内核，不经翻译。
cp "$BXROOT_SO" "$STAGE_LD/libbxroot-real.so" 2>/dev/null
bxout=$(BXROOT_ROOTFS="$ROOTFS" BXROOT_TMP_DIR="$STAGE_LD/tmp" BXROOT_WORKDIR=/ \
    BXROOT_FAKEROOT=1 timeout 120 "$BRIDGE" "$LINKER" --argv0 sh \
    --preload "$STAGE_LD/libbxroot-real.so" "$ROOTFS/bin/sh" -c "$rcmd" 2>&1 \
    | grep -vE '^\[NEXT\]|^\[bxroot\]')
echo "   bxroot:"
printf '%s\n' "$bxout" | sed 's/^/     /'

REAL_ROOT_PW=$(grep -m1 '^root:' "$ROOTFS/etc/passwd" 2>/dev/null || true)
REAL_ROOT_GR=$(grep -m1 '^root:' "$ROOTFS/etc/group" 2>/dev/null || true)
REAL_MSGBUS=$(grep -m1 '^messagebus:' "$ROOTFS/etc/group" 2>/dev/null || true)

SEC6_BAD=0
case "$bxout" in
    *"getent passwd root: [$REAL_ROOT_PW]"*)
        echo "   ✅ getent passwd root 与 rootfs/etc/passwd 逐字一致" ;;
    *)  echo "   ❌ getent passwd root 与 rootfs/etc/passwd 不一致"
        echo "      rootfs 期望: $REAL_ROOT_PW"; SEC6_BAD=1 ;;
esac
case "$bxout" in
    *"getent group root: [$REAL_ROOT_GR]"*)
        echo "   ✅ getent group root 与 rootfs/etc/group 逐字一致" ;;
    *)  echo "   ❌ getent group root 与 rootfs/etc/group 不一致"
        echo "      rootfs 期望: $REAL_ROOT_GR"; SEC6_BAD=1 ;;
esac
case "$bxout" in
    *"getent group messagebus: [$REAL_MSGBUS]"*)
        echo "   ✅ getent group messagebus（非 root 的普通组）一致" ;;
    *)  echo "   ❌ getent group messagebus 不一致"
        echo "      rootfs 期望: $REAL_MSGBUS"; SEC6_BAD=1 ;;
esac
case "$bxout" in
    *"id: [uid=0(root) gid=0(root) groups=0(root)]"*)
        echo "   ✅ id 的组名解析正常（缺口 D 的原始症状之一）" ;;
    *)  echo "   ❌ id 的组名解析异常（期望 gid=0(root) groups=0(root)）"; SEC6_BAD=1 ;;
esac

# =====================================================================
# §7 汇总
# =====================================================================
echo
echo "----------------------------------------"
echo "契约用例 T01..T10：通过 $PASS / 失败 $FAIL / 跳过 $SKIP（bxroot 侧）"
if [ -n "$FAILED_LIST" ]; then
    echo "失败项:$FAILED_LIST"
fi
if [ "$DF_BAD" = 1 ]; then
    echo "缺陷钉桩 D1..D5：有差异（见 §5）"
fi
if [ "${CT_RESTORE_BAD:-0}" = 1 ]; then
    echo "❌ /etc 恢复校验失败 —— 请立即人工检查 $REAL_ETC/passwd 与 group"
fi
if [ "${SEC6_BAD:-0}" = 1 ]; then
    echo "回归锚点 §6：有差异（真实 rootfs 上的 NSS 全家）"
fi

if [ "$FAIL" -gt 0 ] || [ "$DF_BAD" = 1 ] || [ "${CT_RESTORE_BAD:-0}" = 1 ] \
   || [ "${SEC6_BAD:-0}" = 1 ]; then
    echo "RESULT: FAIL"
    exit 1
fi
echo "RESULT: PASS"
exit 0
