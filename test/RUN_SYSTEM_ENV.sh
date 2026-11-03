#!/bin/sh
# ---------------------------------------------------------------------
# environ / system() 崩溃回归（2026-10-26）
#
# 缺陷：px_runtime_build_env() 在入口取 src = environ，之后
# px_build_forced() 为回写 BXROOT_ULX_PATH/LDSO 调 setenv()；glibc 空位
# 不足时会 realloc 整个 environ 数组并 free 旧块 → src 悬垂 →
# px_env_build 遍历时 SIGSEGV（fault 地址恰为 environ 基址）。
#
# 复现条件：rootfs 内 /bin/sh 可达（bxroot-run 默认把 runtime 放进
# rootfs 并注入 ULX 配置），此时 px_build_forced 走"缓存回写"分支触发
# setenv。用 BXROOT_RUN_RUNTIME 指定宿主侧 runtime 时不复现 —— 这正是
# 它长期未被发现的原因，所以本测试**必须**用默认形态。
#
# 退出：0 通过 / 1 失败 / 2 环境不满足
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BX="$ROOT/tools/bxroot-run"

grep -q 'libproroot' /proc/self/maps 2>/dev/null || {
    echo "⏭️  跳过：不在外层 proroot 下，bxroot-run 无法注入"; exit 2; }
[ -f "$ROOT/build/libbxroot-runtime.so" ] || { echo "⏭️  跳过：没有 runtime 产物"; exit 2; }
command -v gcc >/dev/null 2>&1 || { echo "⏭️  跳过：无 gcc"; exit 2; }

W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-sysenv-XXXXXX")
trap 'rm -rf "$W"' EXIT
F=0
bad()  { F=$((F + 1)); echo "  ❌ $*"; }
good() { echo "  ✅ $*"; }

bld() {
    i=1
    while [ $i -le 10 ]; do
        gcc "$@" 2>"$W/cc" && return 0
        grep -q 'internal compiler error' "$W/cc" || { cat "$W/cc"; return 1; }
        i=$((i + 1))
    done
    return 1
}

# rootfs 里必须有可用的 /bin/sh —— px_guest_shell 找到它才走
# px_system_via_guest，才会触发 px_runtime_build_env 的整条路径。
RF="$W/rf"
mkdir -p "$RF/etc" "$RF/tmp"
ln -s ../../../usr "$RF/usr"
ln -s usr/bin "$RF/bin"
ln -s usr/lib "$RF/lib"

bld -O1 -w -o "$RF/tmp/se" "$ROOT/test/probe_system_env.c" || exit 1

run() { (cd / && timeout 120 "$BX" --rootfs "$RF" -- "$@") 2>&1; }

echo "== system() / environ 安全性 =="
o=$(run /tmp/se)
if printf '%s\n' "$o" | grep -q '^SYSTEM_ENV_SAFETY_OK$'; then
    good "execve(environ)/execv/system 三种入口在 pristine/扩容/挖洞环境下均未崩溃"
else
    if printf '%s' "$o" | grep -q 'Segmentation'; then
        bad "system() 触发 SIGSEGV（environ 悬垂指针回归）"
    else
        bad "system()/environ → [$(printf '%s' "$o" | grep -E '^FAIL|failures=' | head -3 | tr '\n' ' ')]"
    fi
    printf '%s\n' "$o" | grep -E '^ok|^FAIL' | sed 's/^/     /'
fi

echo "------------------------------------------------------"
[ $F -eq 0 ] && { echo "RESULT: PASS"; exit 0; }
echo "RESULT: FAIL（$F 项）"; exit 1
