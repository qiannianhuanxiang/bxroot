#!/system/bin/sh
# =====================================================================
# bxroot 版 DSHA 端到端试跑脚本
# =====================================================================
#
# 用途
# ----
# 在 Android 手机容器内，用 **bxroot 运行时**替换官方 proroot 运行时来
# 启动 dsh（DeepSeek Harness），以此验证 bxroot 的路径翻译、fakeroot、
# l2s、子进程派生等能力在真实负载下是否可用。
#
# 为什么不是简单改个环境变量
# --------------------------
# 官方 proroot **不用 LD_PRELOAD 注入**。实测 /proc/<pid>/environ 里
# LD_PRELOAD 为空，真实启动链路是：
#
#   libproroot-bridge.so  libproroot-linker.so \
#       --argv0 <name> --preload <runtime> <guest-exe> [args...]
#
# 其中 libproroot-linker.so 是**自研 ELF 加载器**（不是运行时），
# bridge 是外层宿主加载器。因此"换运行时"= 换 --preload 指向的那个库，
# 两个加载器保持官方原版不动。
#
# 实测约束（重要）
# ----------------
# ① **不要把官方运行时和 bxroot 同时 preload。**
#    那样 bxroot 会被完全架空 —— 官方运行时符号优先级更高，先处理掉
#    所有路径操作，bxroot 的钩子一条都收不到。
#    判定证据（决定性）：同时加载时 BXROOT_VERBOSE=1 的版本
#    **零条** "translate:" 日志；只加载 bxroot 时日志大量出现。
#    也就是说，双加载下"测试通过"实际证明的是官方在干活。
#    本脚本因此默认**只 preload bxroot**。
#
# ② 仅 bxroot 时的真实边界（实测）：
#      node --version         → rc=0    ✅
#      node -e 'console.log'  → rc=159  ❌ SIGSYS
#      dsh --version          → rc=159  ❌ SIGSYS
#    报错为 `sigsys: trap on syscall nr not on allow-list, terminating`，
#    出自 proroot-ldso（自研加载器）自己的 SIGSYS 白名单 —— 实测
#    **不加任何 preload 时同样如此**，所以这不是 bxroot 引入的缺陷。
#    官方运行时之所以能跑，是因为它含 2624 字节的 SIGSYS 模拟层
#    （proroot_sigsys_emulate / sigsys_log_append / proroot_sigsys_handler）
#    兜住了被 TRAP 的系统调用（已确认含 io_uring_setup=425）。
#    这是 bxroot 目前**唯一真正的能力缺口**，也是下一步要做的事。
#
# ② 不能用 `timeout` 包装（或任何 shell 包装）。
#    proroot 的加载器自己 mmap 客户程序而不 execve，所以
#    /proc/self/exe 指向的是**启动器**而非 node，argv[0] 亦然。
#    用 timeout 包一层会让 process.execPath 变成 /usr/bin/timeout，
#    node 的 child_process 会拿它去派生 —— 现象诡异且与 bxroot 无关
#    （官方运行时下表现完全相同，属架构固有行为）。
#
# ③ rootfs 必须用**内核视图的真实路径**，即
#    /data/data/com.dsh.client/files/linux/ubuntu
#    而不是容器内的 "/"。因为在 Ubuntu 容器内看到的是 proroot 翻译后的
#    视图；bxroot 自己要做翻译，就必须拿到翻译**之前**的真实路径。
#
# 用法
# ----
#   sh RUN_E2E.sh --version          # 跑 dsh --version
#   sh RUN_E2E.sh --help             # 跑 dsh --help
#   sh RUN_E2E.sh web --port 43901   # 启动 Web UI
#   sh RUN_E2E.sh --selftest         # 跑内置能力自检
#
# =====================================================================

set -u

# ---------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------
# 官方库目录**动态探测**。
#
# 两个坑，都实测踩过：
# ① APK 路径含随机后缀（~~XXXXXXXX==），重装即变，硬编码必然失效。
# ② 更隐蔽：官方 .so 在**容器视角下根本不可见**。
#    proroot 是纯用户态路径翻译，不做命名空间隔离，所以
#    /proc/self/maps 里写的是内核视图路径 /data/app/~~…/lib/arm64/…，
#    而在容器里 `ls` 那个路径会说不存在 —— 因为 shell 的路径解析
#    同样经过 proroot 翻译，被加上了 rootfs 前缀。
#
# 因此必须经 /proc/<pid>/root/ 访问"绕过翻译的那一侧"：
#   /proc/<pid>/root/data/app/~~…/lib/arm64/libproroot-bridge.so
# 实测可读。本脚本用 $APP_LIB_REAL 作为可用前缀。
detect_app_lib() {
    # 关键：返回**内核视图路径**（maps 里那个），不加 /proc/<pid>/root 前缀。
    #
    # 为什么不能用 /proc/<pid>/root 前缀：实测会 SIGSEGV(139)。
    # proroot 的自研加载器从**自身路径**推导库目录，前缀会让它算出错误的
    # lib_dir，进而污染客户程序的所有后续路径解析。
    #
    # 为什么不能在这里用 [ -f ] 校验：shell 内置 test/[ 与 ls 都走
    # **翻译后的视图**，看不到 /data/app（那里被映射到 rootfs 内）。
    # 而 exec 由 shell 直接交给内核，内核看到的是真实路径 —— 所以
    # "[ -f ] 说不存在" 与 "exec 能跑" 可以同时成立。本函数只负责找出
    # 路径，可用性交给后面的 exec 去证明。
    for m in /proc/[0-9]*/maps; do
        [ -r "$m" ] || continue
        p=$(grep -a 'libproroot-bridge\.so' "$m" 2>/dev/null | head -1 | awk '{print $6}')
        [ -n "${p:-}" ] && { echo "${p%/*}"; return 0; }
    done
    for d in /data/app/*/com.dsh.client-*/lib/arm64; do
        [ -n "$d" ] && { echo "$d"; return 0; }
    done
    return 1
}

APP_LIB="${APP_LIB:-$(detect_app_lib)}"
ROOTFS="${ROOTFS:-/data/data/com.dsh.client/files/linux/ubuntu}"
NODE="$ROOTFS/usr/local/bin/node"

# ★ DSH_JS 必须是**容器视角**（guest 会再翻译一次）★
#
# 踩过的坑（2026-09-19 发现）：这里原先写的是宿主视角
# `$ROOTFS/usr/local/lib/.../bin.js`，而它被当作**参数传给 guest 的 node**。
# node 收到后会自己做一次路径翻译 → 变成 `<rootfs><rootfs>/...` →
# 实测报 `Error: ENOENT: no such file or directory, lstat '/data'`
# （`/data/data/...` 被当成 guest 路径再拼一层 rootfs，于是只拼到 `/data`）。
#
# 对照实测（同一环境，只改这一个参数）：
#     宿主视角 $ROOTFS/usr/local/lib/.../bin.js → ENOENT（如上）
#     容器视角 /usr/local/lib/.../bin.js        → 0.1.5-rc.2  ✅
#
# 判据不是"统一用某种视角"，而是**这个值由谁消费**：
#   --preload / --argv0 / BXROOT_TMP_DIR / BXROOT_GUEST_EXE → 宿主视角（内核/launcher 用）
#   guest 可执行文件的 argv（脚本路径、目标文件）           → 容器视角（guest 会翻译）
# 注意 NODE（guest 可执行文件本身）用宿主视角是**对的** —— 它由 exec 消费。
DSH_JS_GUEST="${DSH_JS_GUEST:-/usr/local/lib/node_modules/@deepseek-ai/dsh/lib/bin.js}"
DSH_JS="$ROOTFS$DSH_JS_GUEST"   # 宿主视角，仅供本脚本做存在性检查

# bxroot 运行时的来源：优先用与本脚本同级的 ../build/，其次用环境变量指定
SELF_DIR=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
BXROOT_SO="${BXROOT_SO:-$SELF_DIR/../build/libbxroot-runtime.so}"
if [ ! -f "$BXROOT_SO" ]; then
    BXROOT_SO="/root/proroot-work/agents/rename-bxroot/build/libbxroot-runtime.so"
fi

# 运行时落地目录 —— 这里有一个**必须两个视角各用一次**的坑。
#
# proroot 是纯用户态路径翻译，同一份文件有两个名字：
#    容器视角  /tmp/x            （经过翻译，客户程序看到的名字）
#    内核视角  $ROOTFS/tmp/x     （未翻译，加载器实际打开的名字）
# 两者 inode 相同（实测 5899539），但**两个操作分别只认其中一个**：
#
#   mkdir  → 只认容器视角。给它 $ROOTFS/tmp/x 会返回 0 却不创建
#            （路径被再套一层前缀），是静默失败。
#   --preload → 只认内核视角。给它 /tmp/x 会报
#            "deps: failed to preload … proroot-ldso: failure rc=2"。
#
# 所以：用 STAGE_MKDIR 建目录，用 STAGE_LOAD 引用文件。
#
# ★ 落地目录按进程隔离（实测教训）★
#
# 这里原先是**固定路径** `/tmp/bxroot-e2e`，而且下面有一句
# `rm -rf "$STAGE_MKDIR"`。后果：任何人跑本脚本都会**删掉别人放在那里
# 的工作文件**。本项目并行开发时实际发生过 —— 三个探针被删了三次，
# 有个 agent 的官方 runtime 副本也被清掉，导致"官方对照"一度跑不起来
# （报 `deps: failed to preload ...`），排查方向被带偏。
#
# 固定共享路径 + 无条件 rm -rf，是并行环境里的一个**协作陷阱**：
# 它不报错，只是让别人的东西静默消失。
#
# 改为带 $$ 的私有目录后：可以并发跑、互不干扰；`rm -rf` 也
# 只删自己的。需要保留现场的，用 BXROOT_STAGE 显式指定路径。
STAGE_MKDIR="${BXROOT_STAGE:-/tmp/bxroot-e2e-$$}"   # 容器视角，供 mkdir/cp 使用
# ★ STAGE_LOAD 必须由 STAGE_MKDIR **派生**，不能另起一个固定名 ★
#
# 踩过的坑（2026-09-19 发现）：这里原先写死 `$ROOTFS/tmp/bxroot-e2e`
# （**没有** `$$`），而 STAGE_MKDIR 带 `$$` —— 两者永远不是同一个目录。
# 于是下面 `[ -d "$STAGE_LOAD" ]` 的守卫必然失败，脚本**永远跑不到 exec**，
# 并且把自己造的 bug 打印成「proroot 双重翻译？」—— 把排查方向引向了
# 外层运行时（那里其实没问题：本容器 /tmp 与 $ROOTFS/tmp 实测同 inode，
# stat 均为 65086:5781241，所以这不是视角问题，只是名字不同）。
#
# 修法：内核视角 = ROOTFS 前缀 + 容器视角的相对部分。
# 其他 runner 写的是 `STAGE_LOAD="$ROOTFS${STAGE_MKDIR}"`（要求
# STAGE_MKDIR 在 guest 里可见），这里用去 /tmp 前缀的等价表达，
# 同时兼容 BXROOT_STAGE 被指到别处的情形。
case "$STAGE_MKDIR" in
    /tmp/*) STAGE_LOAD="$ROOTFS/tmp/${STAGE_MKDIR#/tmp/}" ;;
    *)      STAGE_LOAD="$ROOTFS$STAGE_MKDIR" ;;
esac

# ---------------------------------------------------------------------
# 前置检查
# ---------------------------------------------------------------------
die() { echo "错误: $*" >&2; exit 1; }

# 注意：这里**不能**用 [ -f ] 校验 APP_LIB —— 见 detect_app_lib 的说明，
# shell 的内置 test 看不到内核视图路径，会误报不存在。
[ -n "$APP_LIB" ] || die "无法探测官方库目录（/proc/*/maps 里没有 libproroot-bridge.so）"
case "$APP_LIB" in
    */lib/arm64) ;;
    *) die "探测到的官方库目录形状异常: $APP_LIB" ;;
esac
[ -f "$NODE" ]     || die "找不到 node: $NODE"
[ -f "$DSH_JS" ]   || die "找不到 dsh 入口: $DSH_JS"
[ -f "$BXROOT_SO" ] || die "找不到 bxroot 运行时: $BXROOT_SO"

#
# ★ rm -rf 的护栏 ★
# 只允许删「名字里含 bxroot-e2e」的目录。如果用户用 BXROOT_STAGE 指了
# 别的路径（比如想复用现场），一个手滑的变量就会删掉无关目录 ——
# 这类脚本级误删没有回收站，所以宁可拒绝执行。
case "$STAGE_MKDIR" in
    *bxroot-e2e*) ;;
    *) die "拒绝删除 $STAGE_MKDIR：路径不含 bxroot-e2e，疑似误配 BXROOT_STAGE" ;;
esac
rm -rf "$STAGE_MKDIR" 2>/dev/null
mkdir -p "$STAGE_MKDIR" || die "无法创建落地目录 $STAGE_MKDIR"
# mkdir 返回 0 不代表成功（见上文双重翻译说明），必须实测
[ -f "$STAGE_LOAD" ] || [ -d "$STAGE_LOAD" ] || die "创建 $STAGE_MKDIR 返回成功但 $STAGE_LOAD 不存在（proroot 双重翻译？）"
cp -f "$BXROOT_SO" "$STAGE_MKDIR/libbxroot-runtime.so" || die "复制运行时失败"
[ -f "$STAGE_LOAD/libbxroot-runtime.so" ] || die "复制后 $STAGE_LOAD/libbxroot-runtime.so 不存在"

# ---------------------------------------------------------------------
# 运行环境
# ---------------------------------------------------------------------
# BXROOT_ROOTFS 是最关键的：它让 bxroot 知道把 guest 的 / 映射到哪里。
export BXROOT_ROOTFS="$ROOTFS"
export BXROOT_TMP_DIR="$STAGE_LOAD/tmp"
export BXROOT_WORKDIR="/"
export BXROOT_GUEST_EXE="/usr/local/bin/node"
# fakeroot：让客户看到 uid=0（apt/dpkg/pnpm 都依赖它）
export BXROOT_FAKEROOT=1
# 需要排障时设 BXROOT_VERBOSE=1（会把每次路径翻译打到 stderr）
[ "${BXROOT_VERBOSE:-0}" = "1" ] || unset BXROOT_VERBOSE

# ---------------------------------------------------------------------
# 自检模式
# ---------------------------------------------------------------------
if [ "${1:-}" = "--selftest" ]; then
    cat > "$STAGE_MKDIR/selftest.js" <<'JSEOF'
const fs = require("fs"), cp = require("child_process"), os = require("os");
let pass = 0, fail = 0;
function t(name, fn) {
    try { const v = fn(); console.log("  ✅ " + name + ": " + v); pass++; }
    catch (e) { console.log("  ❌ " + name + ": " + String(e.message).split("\n")[0]); fail++; }
}
console.log("=== 路径翻译 ===");
t("读 rootfs 的 /etc/hostname", () => fs.readFileSync("/etc/hostname", "utf8").trim());
t("readdir('/') 项数",          () => fs.readdirSync("/").length);
t("stat('/') 是目录",           () => fs.statSync("/").isDirectory());
t("存在 /usr/local/bin/node",   () => fs.existsSync("/usr/local/bin/node"));
console.log("=== fakeroot 身份 ===");
t("getuid()", () => process.getuid());
t("getgid()", () => process.getgid());
console.log("=== 子进程派生 ===");
t("execSync /bin/echo", () => cp.execSync("/bin/echo ok", {encoding:"utf8"}).trim());
t("execSync /usr/bin/id -u", () => cp.execSync("/usr/bin/id -u", {encoding:"utf8"}).trim());
console.log("=== l2s 硬链接模拟（st_nlink 契约）===");
const d = "/tmp/bxroot-e2e/l2s";
try { fs.mkdirSync(d, {recursive:true}); } catch(e){}
const a = d + "/a.txt", b = d + "/b.txt";
fs.writeFileSync(a, "hello");
try { fs.unlinkSync(b); } catch(e){}
let nlink = "n/a";
try { fs.linkSync(a, b); nlink = fs.statSync(a).nlink; }
catch (e) { nlink = "link 不支持: " + e.code; }
console.log("  ℹ️  link() 后 st_nlink = " + nlink + "  (期望 2；为 1 说明 l2s 未生效)");
console.log("  ℹ️  statSync 看到的是普通文件: " + !fs.lstatSync(a).isSymbolicLink());
console.log("\n结果: " + pass + " 通过 / " + fail + " 失败");
process.exit(fail ? 1 : 0);
JSEOF
    exec "$APP_LIB/libproroot-bridge.so" "$APP_LIB/libproroot-linker.so" \
        --argv0 node \
        --preload "$STAGE_LOAD/libbxroot-runtime.so" \
        "$NODE" "$STAGE_LOAD/selftest.js"
fi

# ---------------------------------------------------------------------
# 正常启动：转发全部参数给 dsh
# ---------------------------------------------------------------------
exec "$APP_LIB/libproroot-bridge.so" "$APP_LIB/libproroot-linker.so" \
    --argv0 node \
    --preload "$STAGE_LOAD/libbxroot-runtime.so" \
    "$NODE" "$DSH_JS_GUEST" "$@"
