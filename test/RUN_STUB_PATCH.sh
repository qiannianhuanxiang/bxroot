#!/bin/sh
# ---------------------------------------------------------------------
# bxroot 自带 stub-loader 的 patch_static_elf()（行动清单 #6 的 /tmp 与正确性）
#
# 两处缺陷都由本测试抓出：
#   1. 临时副本硬编码写 /tmp（Android/部分容器 /tmp 不存在或 noexec，
#      上游 #79 同类）→ 改为 BXROOT_TMP_DIR → TMPDIR → /tmp；
#   2. 补丁产物本身是**损坏的 ELF**：新 PT_INTERP 追加到文件末尾，却只把
#      e_phnum+1、e_phoff 不动 → 头部声明的第 N+1 项落在节数据上，
#      readelf 看不到 INTERP。已改为"新 phdr 表 + 解释器串追加到末尾、
#      e_phoff 指向新表、PT_INTERP 排表首"。
# 判据：四档目录选择各落对目录；每个产物 readelf 能读出
#       "Requesting program interpreter" 且无 Warning/Error。
# 纯本地测试，不需要外层 proroot。
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-stub-XXXXXX")
trap 'rm -rf "$W"; rm -f /tmp/.bxroot_stub_*_p_static 2>/dev/null' EXIT

command -v readelf >/dev/null 2>&1 || { echo "⏭️  跳过：没有 readelf"; exit 2; }
bld() {
    i=1
    while [ $i -le 10 ]; do
        gcc "$@" 2>"$W/cc" && return 0
        grep -q 'internal compiler error' "$W/cc" || { cat "$W/cc"; return 1; }
        i=$((i + 1))
    done
    return 1
}
bld -O1 -static -o "$W/p_static" "$ROOT/test/static/probe_static_read.c" || { echo "⏭️  跳过：无静态 libc"; exit 2; }
bld -O0 -w -D_GNU_SOURCE -o "$W/t" "$ROOT/test/stub/test_stub_tmpdir.c" -ldl || { echo "❌ 单测编译失败"; exit 1; }
mkdir -p "$W/d1" "$W/d2"

echo "--- 目录选择 + PT_INTERP 存在 ---"
"$W/t" "$W/p_static" "$W/d1" "$W/d2"
rc=$?

echo "--- readelf 结构校验 ---"
cat > "$W/one.c" <<EOF
#define main stub_main_unused
#include "$ROOT/src/stub-loader/stub-loader.c"
#undef main
int main(int c, char **v) { char *o; (void)c; setenv("BXROOT_TMP_DIR", v[2], 1);
    o = patch_static_elf(v[1], "/lib/ld-linux-aarch64.so.1"); if (!o) return 1; puts(o); return 0; }
EOF
bld -O0 -w -D_GNU_SOURCE -o "$W/one" "$W/one.c" -ldl || exit 1
out=$("$W/one" "$W/p_static" "$W/d1") || { echo "  ❌ patch 失败"; exit 1; }
r=$(readelf -lW "$out" 2>&1)
if printf '%s' "$r" | grep -q 'Requesting program interpreter: /lib/ld-linux-aarch64.so.1' && \
   ! printf '%s' "$r" | grep -qiE 'warning|error'; then
    echo "  ✅ readelf 读出 PT_INTERP，无 Warning/Error"
else
    echo "  ❌ 产物结构异常："; printf '%s\n' "$r" | head -8; rc=1
fi
# 原程序的 LOAD 段必须原封不动
if [ "$(readelf -lW "$W/p_static" | grep -c ' LOAD ')" = "$(readelf -lW "$out" | grep -c ' LOAD ')" ]; then
    echo "  ✅ PT_LOAD 段数量不变"
else
    echo "  ❌ PT_LOAD 段数量变了"; rc=1
fi

echo
[ "$rc" = 0 ] && { echo "RESULT: PASS"; exit 0; }
echo "RESULT: FAIL"; exit 1
