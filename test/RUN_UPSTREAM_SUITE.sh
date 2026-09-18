#!/bin/sh
# =====================================================================
# 上游 proot 测试套件移植 runner
# =====================================================================
#
# 由来
# ----
# bxroot 有一层 proot CLI 兼容层，目标是「上游 proot 能接受的命令行，
# bxroot 也要能接受，语义一致」。`test/RUN_UPSTREAM_CLI.sh` 已把**选项表**
# 逐条钉住，但"选项能解析" ≠ "行为一致"。上游 proot 自带 126 个 test-*
# 用例（38 个 .c + 88 个 .sh），是行为一致性的权威判据来源。
#
# 本脚本把其中**在本机可执行**的部分移植成可复现的 runner，并把移植
# 过程中发现的 bxroot 真实缺陷钉成回归断言（D 段）。
#
# ★★★ 容器内运行的四个关键事实（踩了很久才定位，勿重复排查）★★★
# ---------------------------------------------------------------------
# 我们**正运行在官方 proroot 容器内**（env | grep PROROOT 可见一堆变量）。
# 这带来四个必须绕开的陷阱：
#
# ① 静态二进制拿不到 LD_PRELOAD。
#    proroot 的 ldso 只在**动态 ELF** 上注入运行时。实测：用 `gcc -static`
#    编的探针，maps 里既没有官方 runtime 也没有 bxroot 运行时，且 getcwd
#    返回宿主 cwd —— 即"完全没有容器语义"。
#    → 上游 GNUmakefile 默认 `gcc -static`，本脚本一律改成**动态链接**。
#
# ② `--preload` 只接受动态 ELF。
#    给静态二进制会报 `loader: map ...: failed no PT_DYNAMIC`
#    或 `proroot-ldso: failure rc=22`。
#    → launcher 也必须用**动态链接**版本才能在容器内被装载。
#      （Android 真机上 launcher 是静态的，见 Makefile；这里只是**容器内
#       测试**需要动态版本，src/ 下源码一字未改。）
#
# ③ ★ 直接跑静态 launcher 会**静默跑成官方 runtime** ★
#    `gcc -static` 出来的 launcher 以普通进程启动时，proroot 的
#    ld.so.preload 机制会把**官方** libproroot-runtime.so 注入进去，
#    launcher 自己 setenv 的 LD_PRELOAD（bxroot 运行时）被静默忽略。
#    实测 guest 的 /proc/self/maps 里只有 libproroot-runtime.so。
#    → 这是本项目最危险的一类假信号：**测试全绿，但测的是官方实现。**
#      唯一可靠的启动链条是显式三层：
#          bridge --argv0 X --preload <bxroot 运行时> <动态 launcher> <args>
#      本脚本启动前用「-b 探针 + launcher 横幅」双判据自检（见 selftest），
#      自检失败直接判 FAIL，绝不产出可信度不明的绿色结果。
#
# ④ 双视角 + launcher 自查。
#    launcher 自己就运行在 bxroot 运行时的路径翻译之下，它的
#    access()/stat() 也会被翻译。若不预设环境变量，launcher 把自己拼出的
#    `<rootfs>/bin/true` 再加一次前缀 ⇒ 找不到（幂等分支只在入参已带该
#    前缀时命中）。
#    → 启动前 export `BXROOT_ROOTFS=<容器根>`（即 $HOST_ROOTFS），
#      并用 `-DBXROOT_DEFAULT_ROOTFS=$HOST_ROOTFS` 编译 launcher。
#      这样 `-r $HOST_ROOTFS` 时得到**恒等翻译**，上游"直接操作宿主 /tmp"
#      的那批用例才能真实执行。
#
# 上游对照基线为什么缺席
# ----------------------
# 上游 proot 是 ptrace 实现，在 proroot 容器内跑会发生**双重翻译**
# （容器自身已在做路径翻译），实测 `proot -r /proc/self/root$ROOTFS /bin/echo hi`
# 亦失败。任务书已就此定调不要钻这个死胡同。
# 本脚本因此以**上游用例自带的 rc 约定**为绝对判据（0=通过 / 125=跳过）。
#
# 已知缺陷与 `-b` 归一化
# ----------------------
# 上游 `src/cli/proot.c:handle_option_b` 在参数无 ':' 时把 guest 传 NULL，
# 语义等价 `-b PATH:PATH`；bxroot 则直接报错拒绝。而上游 GNUmakefile 对
# **全部 38 个 .c 用例**都用 `-b /proc -r $ROOTFS` 这一写法。
# 为了让 .c 批次能真正跑出结果，shim 会把 `-b X` 归一化成 `-b X:X`；
# 同时 D1 断言把这个缺陷本身钉住（所以本脚本当前预期为 FAIL，
# 缺陷修好后应转为 PASS）。若只想看批次结果、不想被已知缺陷染红：
#     UPSTREAM_KNOWN_DEFECTS_OK=1 sh test/RUN_UPSTREAM_SUITE.sh
#
# 用法
# ----
#   sh test/RUN_UPSTREAM_SUITE.sh
#   UPSTREAM_TESTS=/path/to/tests sh test/RUN_UPSTREAM_SUITE.sh
#   VERBOSE=1 sh test/RUN_UPSTREAM_SUITE.sh
#
# 退出码
# ------
#   0 = 全过 / 含 SKIP      1 = 有 FAIL      2 = 环境不满足（整体 SKIP）
# =====================================================================

set -u

SELF_DIR=$(dirname "$0")
ROOT=$(cd "$SELF_DIR/.." && pwd)
cd "$ROOT" || { echo "❌ 无法进入仓库根目录"; exit 2; }

UPSTREAM_TESTS="${UPSTREAM_TESTS:-/tmp/proot-src/tests}"
HOST_ROOTFS="${ROOTFS:-/data/data/com.dsh.client/files/linux/ubuntu}"
VERBOSE="${VERBOSE:-0}"
KNOWN_DEFECTS_OK="${UPSTREAM_KNOWN_DEFECTS_OK:-0}"

# ---------------------------------------------------------------------
# 前置条件探测：缺任何一项都整体 SKIP（rc=2，不是 FAIL）
# ---------------------------------------------------------------------
if [ ! -d "$UPSTREAM_TESTS" ]; then
    echo "⏭️  跳过：找不到上游测试套件 $UPSTREAM_TESTS"
    echo "    （预期 /tmp/proot-src/tests；可用 UPSTREAM_TESTS= 指定）"
    exit 2
fi
N_SH=$(ls "$UPSTREAM_TESTS"/test-*.sh 2>/dev/null | wc -l)
N_C=$(ls "$UPSTREAM_TESTS"/test-*.c 2>/dev/null | wc -l)
if [ "$N_SH" -lt 10 ]; then
    echo "⏭️  跳过：$UPSTREAM_TESTS 里 test-*.sh 只有 $N_SH 个，不像完整套件"
    exit 2
fi

CC="${CC:-gcc}"
command -v "$CC" >/dev/null 2>&1 || { echo "⏭️  跳过：找不到编译器 $CC"; exit 2; }

if [ ! -f "$HOST_ROOTFS/usr/lib/aarch64-linux-gnu/libc.so.6" ]; then
    echo "⏭️  跳过：$HOST_ROOTFS 不像 proroot rootfs（缺 libc）"
    exit 2
fi
[ -f build/libbxroot-runtime.so ] || {
    echo "⏭️  跳过：没有 build/libbxroot-runtime.so（先跑 sh BUILD_RUNTIME.sh）"
    exit 2
}

# 官方 bridge/linker 目录。
# ★ 不要用 [ -f ] / [ -d ] 探测内核视图路径 ★
#   本项目经典双视角陷阱：shell 的 test 看不到 /data/app/... ，
#   而 exec 却能正常工作。唯一可靠判据是"试着跑一次"。
detect_app_lib() {
    for m in /proc/[0-9]*/maps; do
        [ -r "$m" ] || continue
        p=$(grep -a 'libproroot-bridge\.so' "$m" 2>/dev/null | head -1 | awk '{print $6}')
        [ -n "${p:-}" ] && { echo "${p%/*}"; return 0; }
    done
    return 1
}
APP_LIB="${APP_LIB:-$(detect_app_lib)}"
[ -n "$APP_LIB" ] || { echo "⏭️  跳过：探测不到官方库目录（需要真机容器）"; exit 2; }
case "$APP_LIB" in
    */lib/arm64) ;;
    *) echo "⏭️  跳过：探测到的官方库目录形状异常（$APP_LIB）"; exit 2 ;;
esac
BRIDGE="$APP_LIB/libproroot-bridge.so"
LINKER="$APP_LIB/libproroot-linker.so"

# ---------------------------------------------------------------------
# 工作目录
#
# ★ 双视角 ★  容器视角 $WORK 与内核视角 $WORK_K 是**同一 inode**。
#   - 造文件 / 编译 / shell 判断  → 用容器视角（shell 能看见）
#   - --preload / 传给 guest 的绝对路径 → 用内核视角
# 教训：对内核视角路径做 mkdir -p 会造出 <rootfs><rootfs>/... 的
#       双重前缀目录，且**不报错**。所以一律用容器视角建目录。
# ---------------------------------------------------------------------
WORK=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-upstream-XXXXXX" 2>/dev/null) || {
    echo "❌ 无法创建临时目录"; exit 2
}
WORK_K="$HOST_ROOTFS${WORK}"

# ★ 禁止 pkill/killall/按名字杀进程（本项目因此自伤过 3 次）★
#   只对自己记录下来的 PID 做 kill。
CHILD_PID=""
cleanup() {
    [ -n "$CHILD_PID" ] && kill "$CHILD_PID" 2>/dev/null
    rm -rf "$WORK" 2>/dev/null
}
trap cleanup EXIT INT TERM

RT_C="$WORK/rt.so"                 # 容器视角
RT_K="$WORK_K/rt.so"               # 内核视角
LAUNCHER_C="$WORK/bxroot-l"
LAUNCHER_K="$WORK_K/bxroot-l"
HOSTBIN="$WORK/hostbin"
GUESTBIN="$WORK/gbin"              # guest 侧 helper（同时是 guest 视角路径）

mkdir -p "$WORK" "$HOSTBIN" "$GUESTBIN" "$WORK/tmp" || { echo "❌ 建目录失败"; exit 2; }
[ -d "$WORK_K" ] || { echo "❌ 内核视角 $WORK_K 不存在（proroot 双重翻译？）"; exit 2; }

cp -f build/libbxroot-runtime.so "$RT_C" || { echo "❌ 复制运行时失败"; exit 2; }
[ -f "$RT_K" ] || { echo "❌ 运行时复制后在内核视角不可见"; exit 2; }

# 动态链接的 launcher（容器内 bridge 只接受动态 ELF；src/ 源码未改）。
# ★ 必须 -DBXROOT_DEFAULT_ROOTFS=$HOST_ROOTFS ★ 见文件头第 ④ 点。
i=1
while [ "$i" -le 10 ]; do
    if "$CC" -O1 -w -DBXROOT_DEFAULT_ROOTFS="\"$HOST_ROOTFS\"" \
        -o "$LAUNCHER_C" src/launcher/launcher.c 2>"$WORK/cc.err"; then
        break
    fi
    # 区分 ICE 与真错误：本容器 gcc 13.3.0 有间歇性 internal compiler error
    if ! grep -q 'internal compiler error' "$WORK/cc.err"; then
        echo "❌ launcher.c 编译失败（非 ICE）"; head -15 "$WORK/cc.err"; exit 1
    fi
    i=$((i + 1))
done
[ -x "$LAUNCHER_C" ] || { echo "❌ launcher 编译 10 次仍失败（ICE）"; exit 1; }
cp -f "$LAUNCHER_C" "$LAUNCHER_K" 2>/dev/null

# ---------------------------------------------------------------------
# ${PROOT} 替身（两个）
#
#  - proot-bxroot    ：带 `-b X` → `-b X:X` 归一化，供批次用例使用
#  - proot-bxroot-raw：**不**归一化，供 D1 缺陷取证使用
#    （D1 必须测 bxroot 本身；走归一化 shim 会把缺陷掩盖成"已接受"）
#
# ★ 改写 argv 必须保持**参数边界** ★
#   曾经用 `out="$out $a"` 拼字符串再 `set -- $out`，结果把上游
#   `sh -c "{ echo x; ... } | head -c 2 > /dev/null"` 这类**含空格与
#   重定向的单个参数**重新切分了 —— 表现为 `Syntax error: end of file
#   unexpected`。正确做法是逐项 shift 到尾部再 set --，每个参数始终是
#   独立的一个 word。
#
# 归一化的理由见文件头「已知缺陷与 -b 归一化」。
# ---------------------------------------------------------------------
make_shim() { # $1=输出路径 $2=yes|no（是否归一化 -b）
    _norm="$2"
    cat > "$1" <<WEOF
#!/bin/sh
BXROOT_ROOTFS="$HOST_ROOTFS"
BXROOT_TMP_DIR="$WORK_K/tmp"
export BXROOT_ROOTFS BXROOT_TMP_DIR

_norm="$_norm"
if [ "\$_norm" = "yes" ]; then
    _n=\$#
    _i=0
    while [ \$_i -lt \$_n ]; do
        _a="\$1"; shift
        case "\$_a" in
            -b|--bind|-m|--mount)
                if [ \$# -gt 0 ]; then
                    _v="\$1"; shift; _i=\$((_i + 1))
                    case "\$_v" in
                        *:*) : ;;
                        *)   _v="\$_v:\$_v" ;;
                    esac
                    set -- "\$@" "\$_a" "\$_v"
                else
                    set -- "\$@" "\$_a"
                fi ;;
            *)
                set -- "\$@" "\$_a" ;;
        esac
        _i=\$((_i + 1))
    done
fi

exec "$BRIDGE" "$LINKER" --argv0 bxroot --preload "$RT_K" "$LAUNCHER_K" "\$@"
WEOF
    chmod +x "$1"
}
make_shim "$WORK/proot-bxroot" yes
make_shim "$WORK/proot-bxroot-raw" no
PROOT_BX="$WORK/proot-bxroot"
PROOT_BX_RAW="$WORK/proot-bxroot-raw"

echo "== 上游 proot 测试套件移植（bxroot 侧）=="
echo "   上游套件: $UPSTREAM_TESTS  ($N_SH 个 .sh + $N_C 个 .c)"
echo "   容器根  : $HOST_ROOTFS"
echo

# ---------------------------------------------------------------------
# 启动自检
#
# ★ 这一步不能省 ★ 见文件头第 ③ 点 —— 容器内极易**静默**跑成官方
# runtime，那时所有用例都会"通过"，但结论完全无效。
# 判据用两条互相独立的证据：
#   1) `-b` 生效  —— 官方 runtime 由 PROROOT_* 驱动，不吃 -b
#   2) launcher 的 verbose 横幅 —— 只可能来自 bxroot launcher
#
# ★ bind 的 source 必须用**内核视角** ★
#   实测：`-b $WORK/sb:/ced`（容器视角）下 guest 读 /ced/m 得 ENOENT，
#   而 `-b $WORK_K/sb:/ced` 成功。原因与 ④ 同理 —— bind source 是交给
#   内核去 open 的宿主路径，不参与 guest 视角翻译。
#   （容器视角与内核视角是同一 inode，所以两者"看起来都对"，极易踩错。）
# ---------------------------------------------------------------------
SELFTEST_FAIL=0
echo "--- 启动自检（确认运行的是 bxroot 运行时，而非官方 runtime）---"
mkdir -p "$WORK/sb"
echo "SELFTEST-OK" > "$WORK/sb/m"
sb_got=$(timeout 60 "$PROOT_BX" -r "$HOST_ROOTFS" -b "$WORK_K/sb:/ced" \
         /bin/cat /ced/m 2>&1 | grep -v '^\[bxroot-launcher\]' | head -1)
banner=$(timeout 60 "$PROOT_BX" -r "$HOST_ROOTFS" -v /bin/true 2>&1 \
         | grep -c 'bxroot-launcher')
if [ "$sb_got" = "SELFTEST-OK" ]; then
    echo "  ✅ -b 探针：bind 生效（官方 runtime 不吃 -b）"
else
    echo "  ❌ -b 探针：期望 'SELFTEST-OK'，实得 '$sb_got'"
    SELFTEST_FAIL=1
fi
if [ "$banner" -gt 0 ]; then
    echo "  ✅ launcher 横幅：$banner 行（bxroot launcher 独有）"
else
    echo "  ❌ launcher 横幅：0 行 —— 没走到 bxroot launcher"
    SELFTEST_FAIL=1
fi
if [ "$SELFTEST_FAIL" -ne 0 ]; then
    echo
    echo "RESULT: FAIL —— 启动自检未通过，跑的很可能不是 bxroot，结果无效"
    exit 1
fi
echo

# ---------------------------------------------------------------------
# 从上游源码编译 guest helper
#
# ★ 动态链接，不是上游默认的 -static ★ 见文件头第 ① 点。
# ---------------------------------------------------------------------
cc_dyn() { # $1=源文件 $2=输出名
    j=1
    while [ "$j" -le 10 ]; do
        if "$CC" -O1 -w -o "$GUESTBIN/$2" "$1" 2>"$WORK/cc2.err"; then
            return 0
        fi
        grep -q 'internal compiler error' "$WORK/cc2.err" || return 1
        j=$((j + 1))
    done
    return 1
}

HELPER_OK=0
for h in true false echo pwd cat readlink symlink argv argv0 readdir chdir_getcwd \
         fchdir_getcwd exec getresuid getresgid puts_proc_self_exe fork-wait; do
    [ -f "$UPSTREAM_TESTS/$h.c" ] || continue
    cc_dyn "$UPSTREAM_TESTS/$h.c" "$h" && HELPER_OK=$((HELPER_OK + 1))
done

# 上游 GNUmakefile 会在 ${ROOTFS}/bin 里放 abs-true / rel-true 两个符号链接，
# 供 test-d2175fc3、test-44444444 等使用。
#
# ★ 不要把它们直接写进共享的 $HOST_ROOTFS ★
#   早期版本这么做过，结果是 C 段一度"通过"靠的是这些残留物；
#   一旦清理，test-44444444 立刻变红 —— 典型的**不可复现的假通过**。
#   改用 bind：源留在私有 $WORK，只在 guest 视角出现，零污染。
GUEST_LINKS="$WORK/guest-links"
mkdir -p "$GUEST_LINKS"
ln -sf /bin/true "$GUEST_LINKS/abs-true"
ln -sf ./true   "$GUEST_LINKS/rel-true"
LINKS_K="$WORK_K/guest-links"

# 上游脚本会直接调用宿主工具（pwd/grep/stat/...）。把它们复制进一个
# **私有**目录并前置到 PATH —— 保持动态链接，这样它们同样受 bxroot 翻译；
# 同时避免与 rootfs 内同名文件互相遮蔽。
for t in sh bash ls ln rm mkdir rmdir chmod touch cat stat id uname env head tail \
         grep cut tr readlink realpath pwd sleep timeout yes wc echo mcookie cmp \
         chroot domainname hostname mknod; do
    p=$(command -v "$t" 2>/dev/null) || continue
    case "$p" in /*) cp -f "$p" "$HOSTBIN/$t" 2>/dev/null ;; esac
done

# ---------------------------------------------------------------------
# 逐用例执行
# ---------------------------------------------------------------------
PASS=0; FAIL=0; SKIP=0
FAILED_LIST=""; SKIPPED_LIST=""

ok()   { PASS=$((PASS + 1)); printf '  ✅ %-18s %s\n' "$1" "$2"; }
bad()  { FAIL=$((FAIL + 1)); FAILED_LIST="$FAILED_LIST $1"
         printf '  ❌ %-18s %s\n' "$1" "$2"; }
skip() { SKIP=$((SKIP + 1)); SKIPPED_LIST="$SKIPPED_LIST $1"
         printf '  ⏭️  %-18s %s\n' "$1" "$2"; }

# 上游 GNUmakefile 的判据：rc=0 通过，rc=125 跳过，其余失败
verdict() { # $1=名字 $2=rc $3=输出摘要
    case "$2" in
        0)   ok   "$1" "rc=0" ;;
        125) skip "$1" "rc=125（上游约定的前置不满足）" ;;
        *)   bad  "$1" "rc=$2 | $3" ;;
    esac
}

# 上游调用约定：ROOT_RAW= PROOT= ROOTFS= sh -ex test-xxx.sh
#
# ★ ROOTFS 一律给 $HOST_ROOTFS（容器根）★
#
# 为什么不用「专用测试 rootfs」：实测**在容器内做不到**。
# 三组对照（wrapper 分别预设 BXROOT_ROOTFS=$R / $RF / $RFK / 不设，
# 各配 -r $RF 与 -r $RFK）结果是无解：
#
#   BXROOT_ROOTFS=$R   + -r $RF  → launcher 自查失败（access 被翻译成 $R/$RF/...）
#   BXROOT_ROOTFS=$RF  + -r $RF  → 同上
#   BXROOT_ROOTFS=$RFK + -r $RFK → 走到 guest，但静态链接的 helper 无 PT_DYNAMIC
#                                  被 loader 拒绝（hashes: "deps: cannot find libc.so.6"）
#   不预设             + -r $RF  → launcher 自查失败
#
# 根因是两条互相打架的约束：
#   (a) launcher 自身跑在 bxroot 运行时下，它的 access()/stat() 会被按
#       **编译期默认 rootfs**（$HOST_ROOTFS）翻译 —— 这是它自查能过的唯一条件；
#   (b) 一旦 runtime 的 rootfs 是 $HOST_ROOTFS，`-r` 的相对路径解析基准
#       也随之固定，指向容器根以外的 rootfs 都无法命中。
#
# 又因为本容器根**就是** $HOST_ROOTFS（实测 `stat -c '%d:%i' /etc/hostname`
# 与 `$HOST_ROOTFS/etc/hostname` 完全相同），`-r $HOST_ROOTFS` 恰好退化为
# **恒等翻译** —— 此时 guest 视角 == 容器视角，上游"操作宿主 /tmp"的那批
# 用例可以**真实执行且判据有效**。
#
# 因此本 runner 的诚实边界是：
#   ✅ A 段（宿主路径型）：真实有效
#   ✅ C 段（.c 用例，恒等翻译下）：真实有效
#   ⚠️ B 段（-r 隔离语义）：ROOTFS 传 $HOST_ROOTFS，**测的是 rc 与健壮性，
#      不覆盖 rootfs 隔离本身**；且因 helper 位于容器根之外，必然 rc≠0。
#      runner 把 B 段判为 SKIP 而非 FAIL，并在此显式声明这一局限。
#
# ★ 不要把 stray 文件留在共享的 $HOST_ROOTFS 里 ★
#   早期版本把 helper 符号链接（/bin/abs-true、/bin/rel-true）直接写进
#   $HOST_ROOTFS —— B 段一度"通过"正是依赖这些残留物；一旦清理，
#   同一批用例立刻变红（test-d2175fc3、test-44444444）。
#   那样的"通过"不可复现，已改为不依赖任何预先存在的文件。
run_sh() {
    n="$1"; shift
    _extra="$1"
    [ -f "$UPSTREAM_TESTS/$n.sh" ] || { skip "$n" "源文件不存在"; return; }
    out=$(cd "$UPSTREAM_TESTS" && env ROOT_RAW="$PROOT_BX" PROOT="$PROOT_BX" \
          ROOTFS="$HOST_ROOTFS" PATH="$HOSTBIN:$PATH" \
          timeout 90 sh -ex "$n.sh" 2>&1)
    rc=$?
    summary=$(printf '%s\n' "$out" | grep -v '^+' | grep -v '^\[bxroot-launcher\]' \
              | grep -v '^$' | head -1 | cut -c1-52)
    [ "$VERBOSE" = "1" ] && printf '      | %s\n' "$summary"
    if [ "$_extra" = "isolated" ]; then
        # B 段：-r 隔离语义在本容器内无法成立（见上方说明），不做 PASS/FAIL 判定
        skip "$n" "rc=$rc（-r 隔离语义容器内不可达，仅记录）"
    else
        verdict "$n" "$rc" "$summary"
    fi
}

# 上游 .c 用例：GNUmakefile 把它编成 ${ROOTFS}/bin/<name>，再以
#     proot -b /proc -r ${ROOTFS} /bin/<name>
# 运行。本机用**恒等翻译**（-r $HOST_ROOTFS）复现同一语义：guest 的
# /bin/<name> 就是容器的 /bin/<name>，所以 helper 放在 $GUESTBIN，
# 并以容器视角绝对路径调用。
run_c() {
    n="$1"; shift
    [ -f "$UPSTREAM_TESTS/$n.c" ] || { skip "$n" "源文件不存在"; return; }
    cc_dyn "$UPSTREAM_TESTS/$n.c" "$n" || { skip "$n" "编译失败（本机不可用）"; return; }
    out=$(timeout 90 "$PROOT_BX" -b /proc -r "$HOST_ROOTFS" \
          -b "$LINKS_K/abs-true:/bin/abs-true" \
          -b "$LINKS_K/rel-true:/bin/rel-true" \
          "$GUESTBIN/$n" "$@" 2>&1)
    rc=$?
    summary=$(printf '%s\n' "$out" | grep -v '^\[bxroot-launcher\]' | grep -v '^$' \
              | head -1 | cut -c1-52)
    [ "$VERBOSE" = "1" ] && printf '      | %s\n' "$summary"
    verdict "$n" "$rc" "$summary"
}

echo "--- A) 宿主路径型 .sh 用例（路径翻译 / cwd / 符号链接 / 管道）---"
#
# 这批用例不依赖 ${ROOTFS}，直接操作宿主路径。/tmp 与 $HOST_ROOTFS/tmp
# 是同一 inode，因此在本机可真实执行。
for t in test-1cd9d8f9 test-eddeba0e test-55b731d3 test-cccccccc test-mmmmmmmm \
         test-53355a5b test-7601199b test-c15999f9 test-bbbbbbbb test-b3e7f2d8 \
         test-9d41c0b2 test-3ac8ef15 test-6b0d29c7 test-dfb0c3b6 test-a4d7ed70 \
         test-cb1143ab test-8a2c4f01 test-8a83376a test-dddddddd test-713b6910 \
         test-311b7a95 test-691786c8 test-b6df3cbe test-3624be91 test-55fd1da5 \
         test-commmmmm test-99999999 test-1743dd3d test-305ae31d; do
    run_sh "$t" normal
done

echo
echo "--- B) -r 型 .sh 用例（rootfs 语义 / 选项优先级）---"
#
# ⚠️ 本段在本容器内**测不到 rootfs 隔离本身**（理由见 run_sh 上方长注释）。
#    ROOTFS 传 $HOST_ROOTFS，只记录 rc 与健壮性，结果一律 SKIP。
#    真机 Android 上应把 ROOTFS 换成真实 rootfs 并恢复 PASS/FAIL 判定。
for t in test-00000000 test-b94dd86a test-6d1e2650 test-d2175fc3 test-22222222 \
         test-e99993c8 test-5996858d test-2db65cd2 test-82ba4ba1; do
    run_sh "$t" isolated
done

echo
echo "--- C) .c 用例（fork/exec/cwd/符号链接/raw syscall）---"
for t in test-0cf405b0 test-16573e73 test-25069c12 test-25069c13 test-33333333 \
         test-33333334 test-44444444 test-51943658 test-88888888 test-a8e69d6f \
         test-c10e2073 test-d2175fc4 test-e87b34ae test-fdf487a0 test-07e9b1a2 \
         test-5bed7143 test-1c68c218 test-79cf6614 test-1ffc8309 test-9c07fad8 \
         test-305ae31d test-oooooooo test-ssssssss; do
    run_c "$t"
done

# ---------------------------------------------------------------------
# D) 缺陷取证：把移植过程中发现的**真实行为差异**钉成回归断言
#
# 每条都给：最小复现命令 + 宿主基线对照 + 上游依据。
# 详细分析见 docs/上游proot测试套件移植报告.md。
# ---------------------------------------------------------------------
echo
echo "--- D) 缺陷取证（bxroot 与上游 proot 的行为差异）---"
D_OK=0; D_BAD=0; D_FAILED_LIST=""
dchk() { # $1=标签 $2=说明 $3=ok|bad
    if [ "$3" = "ok" ]; then
        printf '  ✅ %-40s %s\n' "$1" "$2"; D_OK=$((D_OK + 1))
    else
        printf '  ❌ %-40s %s\n' "$1" "$2"; D_BAD=$((D_BAD + 1))
        D_FAILED_LIST="$D_FAILED_LIST ${1%% *}"
    fi
}

# D1. 上游 handle_option_b：无 ':' 时 guest=NULL，等价 -b PATH:PATH。
#     bxroot 报错拒绝 —— 而上游 .c 批次全用这一写法。
#     ★ 必须走 raw shim（不归一化），否则缺陷被 shim 掩盖 ★
got=$(timeout 30 "$PROOT_BX_RAW" -b /etc /bin/true 2>&1 | head -1)
case "$got" in
    *"需要 <host>:<guest> 格式"*)
        dchk "D1 -b 单路径" "拒绝了上游合法写法（上游按 path:path 处理）" bad ;;
    *) dchk "D1 -b 单路径" "被接受（与上游一致）" ok ;;
esac

# D2. 上游 cli.c:initialize_cwd —— 未给 -w/--cwd 时**继承宿主 cwd**，
#     并把它按 guest 视角规范化（上游 test-eddeba0e 即断言 pwd -P == $PWD）。
#     bxroot 强制回落到 '/'。
got=$(cd /tmp/proot-src/tests 2>/dev/null && timeout 30 "$PROOT_BX" pwd -P 2>&1 \
      | grep -v '^\[bxroot-launcher\]' | head -1)
case "$got" in
    /tmp/proot-src/tests) dchk "D2 cwd 继承" "继承了宿主 cwd（与上游一致）" ok ;;
    /) dchk "D2 cwd 继承" "被强制为 /，未继承宿主 cwd（上游继承）" bad ;;
    *) dchk "D2 cwd 继承" "实得 '$got'" bad ;;
esac

# D3. readlink("/proc/self/fd/N")：openat(dirfd,".") 得到的是 /，
#     readlink 必须按 **guest 视角**返回 "/"。bxroot 返回宿主路径，
#     泄漏了内核视角前缀。上游 test-51943658 断言 /. == /。
cat > "$WORK/fdprobe.c" <<'FEOF'
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
int main(void){
  char p[PATH_MAX], l[64];
  int d = open("/", O_RDONLY), d1 = openat(d, ".", O_RDONLY);
  if (d < 0 || d1 < 0) return 2;
  sprintf(l, "/proc/self/fd/%d", d1);
  ssize_t n = readlink(l, p, sizeof p - 1);
  if (n < 0) return 2;
  p[n] = 0;
  puts(p);
  return strcmp(p, "/") ? 1 : 0;
}
FEOF
if gcc -O1 -w -o "$WORK/fdprobe" "$WORK/fdprobe.c" 2>/dev/null; then
    host_got=$("$WORK/fdprobe" 2>/dev/null)
    bx_got=$(timeout 30 "$PROOT_BX" -r "$HOST_ROOTFS" "$WORK/fdprobe" 2>&1 \
             | grep -v '^\[bxroot-launcher\]' | head -1)
    if [ "$bx_got" = "/" ]; then
        dchk "D3 /proc/self/fd/N 视角" "返回 guest 视角 '/'（与上游一致）" ok
    else
        dchk "D3 /proc/self/fd/N 视角" "返回 '$bx_got'（宿主基线 '$host_got'，上游要求 /）" bad
    fi
else
    skip "D3 /proc/self/fd/N 视角" "探针编译失败"
fi

# D4. 尾部斜杠语义：符号链接指向目录时 `ls L1/` 必须成功。
#     上游 test-cb1143ab 依赖它；宿主基线 rc=0。
TD="$WORK/d4"; mkdir -p "$TD/a/b" 2>/dev/null
ln -sfn "$TD/a/b/./." "$TD/L1" 2>/dev/null
ls "$TD/L1/" >/dev/null 2>&1; host_rc=$?
timeout 30 "$PROOT_BX" ls "$TD/L1/" >/dev/null 2>&1; bx_rc=$?
if [ "$bx_rc" -eq "$host_rc" ]; then
    dchk "D4 symlink->dir 的 L1/" "rc=$bx_rc（与宿主基线一致）" ok
else
    dchk "D4 symlink->dir 的 L1/" "bxroot rc=$bx_rc，宿主基线 rc=$host_rc" bad
fi

# D5. SIGPIPE 处置：上游 test-6b0d29c7。上游专门修过这一条 ——
#     SIG_IGN 会跨 fork/exec 存活，Android zygote 留下 SIGPIPE=SIG_IGN，
#     容器运行时必须把它复位为 SIG_DFL，否则 guest 里 `yes | head -1`
#     会打印 "Broken pipe" 而不是被静默杀死。
#     期望 PIPESTATUS[0] == 141 (128+SIGPIPE)。
st=$(bash -c "trap '' PIPE; timeout 20 '$PROOT_BX' bash -c \
     'yes | head -1 > /dev/null; echo \${PIPESTATUS[0]}'" 2>/dev/null | tail -1)
if [ "$st" = "141" ]; then
    dchk "D5 SIGPIPE 复位" "PIPESTATUS[0]=141（与上游一致）" ok
else
    dchk "D5 SIGPIPE 复位" "PIPESTATUS[0]=$st，上游要求 141（未复位 SIG_DFL）" bad
fi

echo
echo "    缺陷取证：$D_OK 符合上游 / $D_BAD 与上游不一致"

# ---------------------------------------------------------------------
# 汇总
# ---------------------------------------------------------------------
echo
echo "----------------------------------------"
echo "通过 $PASS / 失败 $FAIL / 跳过 $SKIP"
[ -n "$FAILED_LIST" ] && echo "失败项:$FAILED_LIST"
[ -n "$SKIPPED_LIST" ] && echo "跳过项:$SKIPPED_LIST"
echo "（helper 编译成功 $HELPER_OK 个；缺陷取证 $D_OK 符合 / $D_BAD 不一致）"

RC=0
if [ "$FAIL" -gt 0 ]; then
    echo "RESULT: FAIL（$FAIL 个上游用例未通过）"
    RC=1
fi
if [ "$D_BAD" -gt 0 ]; then
    if [ "$KNOWN_DEFECTS_OK" = "1" ]; then
        echo "⚠️  已知缺陷 $D_BAD 项与上游不一致（UPSTREAM_KNOWN_DEFECTS_OK=1，仅放行 D 段；批次失败仍计入）"
        echo "    清单:$D_FAILED_LIST"
    else
        echo "RESULT: FAIL（$D_BAD 项与上游行为不一致:$D_FAILED_LIST）"
        echo "  这些都是 bxroot 的真实缺陷，详见 docs/上游proot测试套件移植报告.md"
        echo "  只放行 D 段（不改批次判据）：UPSTREAM_KNOWN_DEFECTS_OK=1"
        RC=1
    fi
fi
if [ "$RC" -eq 0 ]; then
    if [ "$D_BAD" -gt 0 ] || [ "$FAIL" -gt 0 ]; then
        echo "RESULT: PASS（$FAIL 个用例失败 / $D_BAD 项已知缺陷，按 UPSTREAM_KNOWN_DEFECTS_OK=1 放行）"
    else
        echo "RESULT: PASS"
    fi
fi
exit "$RC"
