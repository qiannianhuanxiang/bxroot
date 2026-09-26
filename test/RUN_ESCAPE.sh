#!/bin/sh
# ---------------------------------------------------------------------
# 沙箱逃逸回归（2026-09-27 真机爆破测试发现，Termux 与本容器均复现）
#
#   BXR-ESC-1  translate_path 不处理 `..`：open("/../x") → "<rootfs>/../x"
#              由内核解析，直接走出 rootfs（真机 14 种写法全部逃逸）。
#              修：guest 视角逐组件解析 `..` 并在根处夹紧（上游 proot 语义）。
#   BXR-ESC-2  open 族叶子链接解析后打开失败时回退 open(链接本体)，
#              内核按宿主根跟随绝对目标。修：已解析时直接返回失败。
#   BXR-ESC-3  fopen/access/opendir/truncate/chmod/chown/creat/statfs/
#              *xattr/inotify/__open_nocancel 等只加前缀、不跟随链接。
#              修：统一走 translate_follow。
#
# 判据：rootfs 外放 canary（内容 CANARY）+ 宿主绝对目标的链接；两个探针
# 必须报 escapes=0，且 canary 目录不得出现被写入的新文件。
# 语义不倒退：`..` 仍按 Linux 语义工作（/bin/.. 先解链接、/etc/../etc 可读、
# cd ../.. 到根为止）。判别力：BXROOT_ESCAPE_DISCRIM=1 时额外用 `git stash`
# 前的 runtime 不可用，故由 test/device/ 与手工对照保证（见 docs）。
# 退出：0 通过 / 1 失败 / 2 环境不满足
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BX="$ROOT/tools/bxroot-run"
grep -q 'libproroot-runtime\.so' /proc/self/maps 2>/dev/null || {
    echo "⏭️  跳过：需要外层 proroot 注入链路"; exit 2; }
[ -f "$ROOT/build/libbxroot-runtime.so" ] || { echo "⏭️  跳过：没有 build/libbxroot-runtime.so"; exit 2; }

W=$(mktemp -d /tmp/bxroot-escape-XXXXXX)
trap 'rm -rf "$W"' EXIT
F=0
bad()  { F=$((F + 1)); echo "  ❌ $*"; }
good() { echo "  ✅ $*"; }

# rootfs = W/rf（usr 复用宿主，/bin -> usr/bin 相对链接）；canary 在 W/ 与 W/hd/
RF="$W/rf"
mkdir -p "$RF/etc" "$RF/tmp" "$W/hd"
ln -s ../../../usr "$RF/usr"
ln -s usr/bin "$RF/bin"; ln -s usr/lib "$RF/lib"
echo "ESC-GUEST" > "$RF/etc/hostname"
echo CANARY > "$W/canary"
echo CANARY > "$W/hd/canary"

bld() {
    i=1
    while [ $i -le 10 ]; do
        gcc "$@" 2>"$W/cc" && return 0
        grep -q 'internal compiler error' "$W/cc" || { cat "$W/cc"; return 1; }
        i=$((i + 1))
    done
    return 1
}
bld -O1 -w -o "$RF/tmp/pe1" "$ROOT/test/probe_escape_dotdot.c" || exit 1
bld -O1 -w -o "$RF/tmp/pe2" "$ROOT/test/probe_escape_symlink.c" || exit 1

run() { (cd / && timeout 60 "$BX" --rootfs "$RF" -- "$@") 2>&1; }

echo "== ESC-1 \`..\` 夹紧 =="
o=$(run /tmp/pe1 "$W")
echo "$o" | grep -q "DONE escapes=0" && good "\`..\` 各写法 0 逃逸" || bad "$(echo "$o" | grep -E 'ESCAPE|DONE' | tr '\n' ' ')"

echo "== ESC-2/3 宿主绝对链接 × 跟随型钩子 =="
o=$(run /tmp/pe2 "$W/hd")
echo "$o" | grep -q "DONE escapes=0" && good "open/fopen/access/opendir/truncate/chmod/link… 0 逃逸" || bad "$(echo "$o" | grep -E 'ESCAPE|DONE' | tr '\n' ' ')"
n=$(ls "$W/hd" | wc -l)
[ "$n" -eq 1 ] && good "canary 目录未被写入" || bad "canary 目录多出文件: $(ls "$W/hd" | tr '\n' ' ')"
grep -q '^CANARY$' "$W/hd/canary" && good "canary 内容未被改动" || bad "canary 被改动"

echo "== 语义不倒退 =="
o=$(run /bin/sh -c 'cat /etc/../etc/hostname')
[ "$o" = "ESC-GUEST" ] && good "/etc/../etc/hostname" || bad "/etc/../etc/hostname → [$o]"
o=$(run /bin/sh -c 'cat /../../etc/hostname')
[ "$o" = "ESC-GUEST" ] && good "/../../etc/hostname 夹紧到根" || bad "/../../etc/hostname → [$o]"
# 链接先解再 ..（Linux 语义）：/tmp/lk -> d1/d2，/tmp/lk/../f 应是 /tmp/d1/f，
# 而不是字面折叠的 /tmp/f。（不用 /bin：本测试 rootfs 的 usr 是指向 rootfs
# 外的相对链接，按 guest 语义会被夹紧成环，那是正确行为，不是回归。）
mkdir -p "$RF/tmp/d1/d2"; echo IN-D1 > "$RF/tmp/d1/f"; echo LITERAL > "$RF/tmp/f"
ln -s d1/d2 "$RF/tmp/lk"
o=$(run /bin/sh -c 'cat /tmp/lk/../f')
[ "$o" = "IN-D1" ] && good "/tmp/lk/../f（先解链接再 ..）" || bad "/tmp/lk/../f → [$o]（期望 IN-D1）"
o=$(run /bin/sh -c 'mkdir -p /tmp/a/b && cd /tmp/a/b && cd ../../.. && pwd && cd .. && pwd && cat etc/hostname')
[ "$(echo "$o" | tr '\n' ' ')" = "/ / ESC-GUEST " ] && good "cd ../.. 到根为止" || bad "cd .. → [$(echo "$o" | tr '\n' ' ')]"
o=$(run /bin/sh -c 'mkdir -p /tmp/a/b && cd /tmp/a/b && cat ../../../etc/hostname && cat ../../../../../etc/hostname')
[ "$(echo "$o" | tr '\n' ' ')" = "ESC-GUEST ESC-GUEST " ] && good "相对 ../ 越界夹紧" || bad "相对 ../ → [$(echo "$o" | tr '\n' ' ')]"
o=$(run /bin/sh -c 'ln -s /etc /tmp/le && cat /tmp/le/../etc/hostname')
[ "$o" = "ESC-GUEST" ] && good "绝对链接中间组件 + .." || bad "/tmp/le/../etc/hostname → [$o]"
o=$(run /bin/sh -c 'cat /proc/self/root/../etc/hostname')
[ "$o" = "ESC-GUEST" ] && good "/proc/self/root/.. 夹紧" || bad "/proc/self/root/../etc/hostname → [$o]"

echo "------------------------------------------------------"
[ $F -eq 0 ] && { echo "RESULT: PASS"; exit 0; }
echo "RESULT: FAIL（$F 项）"; exit 1
