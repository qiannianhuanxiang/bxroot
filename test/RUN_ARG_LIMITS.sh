#!/bin/sh
# ---------------------------------------------------------------------
# exec 参数/环境/嵌套 shebang 边界（2026-09-27 爆破测试，真机与容器均复现）
#
#   BXR-ARG-1  exec 钩子的 argv 数组是栈上 PX_ARGV_MAX(4096)，循环到上限即停：
#              guest 里 `/bin/echo $(seq 1 5000) | wc -w` → 4095（Linux 5000），
#              xargs 批量也被截成 4095 一批。静默丢参数。
#   BXR-ENV-1  透传环境变量单条 >16 KiB 被静默丢弃：
#              X=<60 KB> sh -c 'echo ${#X}' → 0（Linux 60000）。
#   BXR-SB-1   嵌套 shebang（解释器本身是脚本）只改写一层 →
#              "file too short" rc=127。Linux 允许 4 层，第 5 层 ELOOP。
# 退出：0 通过 / 1 失败 / 2 环境不满足
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BX="$ROOT/tools/bxroot-run"
grep -q 'libproroot-runtime\.so' /proc/self/maps 2>/dev/null || {
    echo "⏭️  跳过：需要外层 proroot 注入链路"; exit 2; }
[ -f "$ROOT/build/libbxroot-runtime.so" ] || { echo "⏭️  跳过：没有 build/libbxroot-runtime.so"; exit 2; }
W=$(mktemp -d /tmp/bxroot-arglim-XXXXXX)
trap 'rm -rf "$W"' EXIT
F=0
bad()  { F=$((F + 1)); echo "  ❌ $*"; }
good() { echo "  ✅ $*"; }
RF="$W/rf"
mkdir -p "$RF/etc" "$RF/tmp"
ln -s ../../../usr "$RF/usr"; ln -s usr/bin "$RF/bin"; ln -s usr/lib "$RF/lib"
run() { (cd / && timeout 60 "$BX" --no-check --rootfs "$RF" -- /bin/sh -c "$1") 2>&1; }

o=$(run '/bin/echo $(seq 1 5000) | wc -w')
[ "$o" = "5000" ] && good "5000 个参数全部送达" || bad "5000 参数 → [$o]（BXR-ARG-1）"
# 9000 条：本容器外层 proroot 的 mmap_loader 自身有条数上限（报 "too many argv
# entries"），那不是 bxroot 的截断 —— 判据放宽为「全部送达，或被外层**显式拒绝**」，
# 唯独不接受「静默截断成 4095」。真机（无外层 loader）在 test/device/ 里要求 9000。
o=$(run '/bin/sh -c "exec /bin/echo \$(seq 1 9000)" | wc -w; true' 2>&1)
case "$o" in
  9000) good "9000 参数经嵌套 exec 送达" ;;
  *"too many argv entries"*) good "9000 参数：外层 loader 显式拒绝（环境限制，非静默截断）" ;;
  *) bad "9000 参数 → [$o]" ;;
esac
o=$(run 'x=$(head -c 60000 /dev/zero | tr "\0" a); X=$x /bin/sh -c "echo \${#X}"')
[ "$o" = "60000" ] && good "60 KB 环境变量保留" || bad "60 KB env → [$o]（BXR-ENV-1）"
o=$(run 'x=$(head -c 100000 /dev/zero | tr "\0" a); X=$x /bin/sh -c "echo \${#X}"')
[ "$o" = "100000" ] && good "100 KB 环境变量保留" || bad "100 KB env → [$o]"

cat > "$RF/tmp/s1" <<'S'
#!/bin/sh
echo S1 "$0" "$1" "$2" "$3"
S
printf '#!/tmp/s1 A1\n' > "$RF/tmp/s2"
chmod +x "$RF/tmp/s1" "$RF/tmp/s2"
o=$(run '/tmp/s2 X; echo r=$?' | tr '\n' ' ')
[ "$o" = "S1 /tmp/s1 A1 /tmp/s2 X r=0 " ] && good "两层 shebang argv 与 Linux 一致" || bad "两层 shebang → [$o]（BXR-SB-1）"
printf '#!/tmp/l1\n' > "$RF/tmp/l0"
for i in 1 2 3 4 5; do printf '#!/tmp/l%d\n' $((i + 1)) > "$RF/tmp/l$i"; done
printf '#!/bin/sh\necho deep\n' > "$RF/tmp/l6"
chmod +x "$RF"/tmp/l0 "$RF"/tmp/l1 "$RF"/tmp/l2 "$RF"/tmp/l3 "$RF"/tmp/l4 "$RF"/tmp/l5 "$RF"/tmp/l6
o=$(run '/tmp/l3; echo r=$?' | tr '\n' ' ')
[ "$o" = "deep r=0 " ] && good "4 层 shebang 可执行" || bad "4 层 → [$o]"
o=$(run '/tmp/l0 2>/dev/null; echo r=$?')
[ "$o" = "r=127" ] || [ "$o" = "r=126" ] && good "6 层 shebang 拒绝（ELOOP，与 Linux 同）" || bad "6 层 → [$o]"

echo "------------------------------------------------------"
[ $F -eq 0 ] && { echo "RESULT: PASS"; exit 0; }
echo "RESULT: FAIL（$F 项）"; exit 1
