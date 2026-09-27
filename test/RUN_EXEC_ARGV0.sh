#!/bin/sh
# ---------------------------------------------------------------------
# execve 家族保留调用方 argv[0] 回归（自主发现，2026-09-28）
#
#   guest 内 execve(path, argv, env) 经 trampoline（bridge+linker+--argv0）
#   启动时，guest 看到的 argv[0] 必须是**调用方传入的 argv[0]**，而不是
#   翻译后的宿主/guest 路径。
#
#   缺陷：proc.c px_do_execve 保存了 raw_argv0（注释写明 trampoline 的
#   --argv0 用它），但调用点却传了解析后的 `guest` 路径 → guest 的
#   $0/progname 变成路径。对照 px_do_spawn 传的是 raw_argv0（正确），
#   所以同一 runtime 内 posix_spawn 正确、execve 错。影响 busybox 多调用
#   分派、登录 shell（-bash/-sh）、任何按 argv[0] 改行为的程序。
#   修：调用点改传 raw_argv0（空时回退 guest）。
#
# 判据：execve("/bin/sh", {"-customname","-c","echo $0"}, …) 后 $0 必须
#   打印为 "-customname"，不能是 "/bin/sh" 或带 rootfs 前缀的路径。
#   与官方基线 /tmp/off-rt.so 对照（基线正确保留）。
# 退出：0 通过 / 1 失败 / 2 环境不满足
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BX="$ROOT/tools/bxroot-run"
grep -q 'libproroot' /proc/self/maps 2>/dev/null || {
    echo "⏭️  跳过：需要外层 proroot 注入链路"; exit 2; }
[ -f "$ROOT/build/libbxroot-runtime.so" ] || {
    echo "⏭️  跳过：没有 build/libbxroot-runtime.so"; exit 2; }
command -v gcc >/dev/null 2>&1 || { echo "⏭️  跳过：无 gcc"; exit 2; }

W=$(mktemp -d /tmp/bxroot-argv0-XXXXXX)
trap 'rm -rf "$W"' EXIT

cat > "$W/argv0.c" <<'CEOF'
/* execve /bin/sh 但把 argv[0] 伪装成 "-customname"，让 sh 打印 $0。 */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
extern char **environ;
int main(void) {
    char *a[] = {(char*)"-customname", (char*)"-c",
                 (char*)"echo argv0-seen=$0", NULL};
    execve("/bin/sh", a, environ);
    perror("execve");
    return 127;
}
CEOF

bld() {
    i=1
    while [ $i -le 10 ]; do
        gcc "$@" 2>"$W/cc" && return 0
        grep -q 'internal compiler error' "$W/cc" || { cat "$W/cc"; return 1; }
        i=$((i + 1))
    done
    return 1
}
# 探针放进 rootfs 内（容器 /tmp = rootfs/tmp），guest 可 exec。
bld -O1 -w -o /tmp/px_argv0 "$W/argv0.c" || exit 1

FAIL=0
echo "== execve 保留调用方 argv[0] =="

bx=$(timeout 60 "$BX" --no-check -- /tmp/px_argv0 2>&1 | grep 'argv0-seen=')
echo "  bxroot : $bx"
case "$bx" in
    *"argv0-seen=-customname"*) echo "  ✅ bxroot 保留了调用方 argv[0]" ;;
    *) echo "  ❌ bxroot 未保留 argv[0]（应为 -customname）"; FAIL=1 ;;
esac

if [ -x /tmp/off-rt.so ] || [ -f /tmp/off-rt.so ]; then
    bl=$(BXROOT_RUN_RUNTIME=/tmp/off-rt.so timeout 60 "$BX" --no-check \
             -- /tmp/px_argv0 2>&1 | grep 'argv0-seen=')
    echo "  基线   : $bl"
    case "$bl" in
        *"argv0-seen=-customname"*) echo "  ✅ 与官方基线一致" ;;
        *) echo "  ⚠️  基线未按预期（环境差异，不判 bxroot 失败）" ;;
    esac
fi

rm -f /tmp/px_argv0
[ "$FAIL" -eq 0 ] && { echo "RESULT: PASS"; exit 0; } || { echo "RESULT: FAIL"; exit 1; }
