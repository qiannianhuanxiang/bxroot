#!/bin/sh
# ---------------------------------------------------------------------
# 只读 bind（`-b host:guest:ro`）回归
#
# 背景：上游 proot 支持在 bind 后显式标记只读；bxroot 加了同语义的
#   第三段 `:ro`。BXROOT_BINDS 编码格式扩展为 `src:dst[:ro]`（无第三段
#   =可写，向后兼容旧格式）。runtime 在所有写意图钩子入口调用
#   bind_is_readonly_target()，命中只读 bind 即返回 EROFS；读操作放行。
#
# 覆盖两部分：
#   ① runtime 语义（经 bxroot-run 直接构造 BXROOT_BINDS）：
#      - 只读 bind 内读成功；
#      - 各类写入（重定向创建/截断、mkdir、rmdir、unlink、chmod、
#        symlink、mv、truncate、chown）一律 EROFS；
#      - 非只读 bind 仍可写。
#   ② launcher 解析（直接编译 launcher.c，RUN_CLI_COMPAT 式）：
#      `-b h:g:ro` 能解析且 BXROOT_BINDS 编码含 `:ro` 尾段；
#      普通 `-b h:g` 不含 `:ro`。
#
# 判别力：本测试的核心断言是「只读 bind 内写入 = EROFS」。若把 runtime
#   里的 EROFS 强制（bind_is_readonly_target / ro_guard_*）撤掉，写入会
#   变成成功 → 断言 a2 立即变红。已在提交说明中记录实测（stub 返回 0
#   后 `echo x >/mnt/ro/f` 返回 WROTE-OK）。
#
# 环境不满足（缺 build/、缺外层 proroot、无 gcc、无 PROROOT_ROOTFS）
#   → rc=2 跳过（见 SUBAGENT-CONTEXT #1/#2）。
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BX="$ROOT/tools/bxroot-run"
W=$(mktemp -d "${TMPDIR:-/tmp}/bxroot-robind-XXXXXX")
trap 'rm -rf "$W"' EXIT

# 外层 proroot 是唯一可用注入链路的前提
grep -q 'libproroot' /proc/self/maps 2>/dev/null || {
    echo "⏭️  跳过：不在外层 proroot 下，bxroot-run 无法注入"; exit 2; }
[ -f "$ROOT/build/libbxroot-runtime.so" ] || { echo "⏭️  跳过：没有 runtime 产物"; exit 2; }

# bind 的 source 是**内核视角**的宿主路径（bxroot-run 默认 rootfs=容器 /，
# 内核视角 = $PROROOT_ROOTFS）。为了让 guest 里 /mnt/ro 能真读到内容，
# source 必须写成内核能直接解析的绝对宿主路径。
HOSTROOT=${PROROOT_ROOTFS:-}
[ -n "$HOSTROOT" ] || { echo "⏭️  跳过：无 PROROOT_ROOTFS，取不到宿主视角"; exit 2; }

command -v gcc >/dev/null 2>&1 || { echo "⏭️  跳过：无 gcc（launcher 解析测试需要）"; exit 2; }

FAIL=0
bad()  { FAIL=$((FAIL + 1)); echo "  ❌ $*"; }
good() { echo "  ✅ $*"; }

# --- 准备只读/可写两个源目录（容器视角写，内核视角 = HOSTROOT/tmp/...）---
RO_C="$W/rosrc"; RW_C="$W/rwsrc"
mkdir -p "$RO_C" "$RW_C"
echo "RO-MARKER-4F7A" > "$RO_C/f"
mkdir -p "$RO_C/sub"; echo sub > "$RO_C/sub/x"
echo "RW-INIT" > "$RW_C/g"

# 内核视角：W 在容器 /tmp 下，等价于 HOSTROOT/tmp/...
# W 形如 /tmp/bxroot-robind-XXXXXX，取相对 / 的部分拼到 HOSTROOT
RO_H="$HOSTROOT${RO_C}"
RW_H="$HOSTROOT${RW_C}"
# 校验内核视角路径确实存在（否则说明 /tmp 不在 rootfs 下，跳过）
[ -f "$RO_H/f" ] || { echo "⏭️  跳过：宿主视角源路径不可见（$RO_H/f）"; exit 2; }

BINDS="$RO_H:/mnt/ro:ro;$RW_H:/mnt/rw"
runbx() { BXROOT_BINDS="$BINDS" timeout 40 "$BX" --no-check -- /bin/sh -c "$1" 2>&1; }

echo "=== ① runtime 语义 ==="

echo "--- a1) 只读 bind 内读成功 ---"
out=$(runbx 'cat /mnt/ro/f')
case "$out" in
*RO-MARKER-4F7A*) good "只读 bind 内读正常" ;;
*) bad "只读 bind 内读失败：$out" ;;
esac

echo "--- a1b) 只读 bind 子路径读成功 ---"
out=$(runbx 'cat /mnt/ro/sub/x')
case "$out" in
*sub*) good "只读 bind 子路径读正常" ;;
*) bad "只读 bind 子路径读失败：$out" ;;
esac

echo "--- a1c) O_RDONLY 打开只读 bind 内文件正常（wc）---"
out=$(runbx 'wc -c < /mnt/ro/f')
case "$out" in
*1[0-9]*) good "O_RDONLY 打开只读 bind 内文件正常（$out 字节）" ;;
*) bad "O_RDONLY 打开只读 bind 内文件异常：$out" ;;
esac

# --- 写入各入口：全部应 EROFS。判据是首选 "Read-only file system"，
#     兜底看 rc≠0 且文件未被改动。 ---
ro_write_check() {
    _label="$1"; _cmd="$2"
    out=$(runbx "$_cmd")
    case "$out" in
    *"Read-only file system"*|*"Read-only"*)
        good "$_label → EROFS" ;;
    *)
        bad "$_label 未被拦成 EROFS：$out" ;;
    esac
}

echo "--- a2) 写入类入口一律 EROFS ---"
ro_write_check "重定向创建/截断 (open O_WRONLY|O_CREAT|O_TRUNC)" 'echo x > /mnt/ro/newf'
ro_write_check "覆盖已存在文件 (open O_TRUNC)"                    'echo x > /mnt/ro/f'
ro_write_check "mkdir"                                          'mkdir /mnt/ro/d'
ro_write_check "rmdir"                                          'rmdir /mnt/ro/sub'
ro_write_check "unlink (rm)"                                    'rm -f /mnt/ro/f'
ro_write_check "chmod"                                          'chmod 700 /mnt/ro/f'
ro_write_check "symlink (ln -s)"                                'ln -s /whatever /mnt/ro/lnk'
ro_write_check "truncate"                                       'truncate -s 0 /mnt/ro/f'
ro_write_check "rename 入 (mv into)"                            'echo z > '"$W"'/z && mv '"$W"'/z /mnt/ro/z'
ro_write_check "chown"                                          'chown 0:0 /mnt/ro/f'

echo "--- a2b) 只读 bind 内容确实未被改动（读回原标记）---"
out=$(runbx 'cat /mnt/ro/f')
case "$out" in
*RO-MARKER-4F7A*) good "写入全部被拦后，只读文件内容原封不动" ;;
*) bad "只读文件疑似被改动：$out" ;;
esac

# --- a2c) fd 版写钩子也必须被只读 bind 拦（此前漏判会写穿宿主）---
#     判别力：程序先 open(O_RDONLY) 拿到只读 bind 内文件的 fd（读打开放行），
#     再用 fchmod/fchown/ftruncate/futimens 这些 **fd 版** 写系统调用改它。
#     修复前 fd 版完全不判 ro_guard → rc=0 且真写穿宿主 backing file。
#     修复后应全部 EROFS。这里用一个自带 C 探针（编译进 rootfs 内）验证。
echo "--- a2c) fd 版写钩子（fchmod/fchown/ftruncate/futimens）→ EROFS ---"
FDPROBE_SRC="$W/rofd.c"
cat > "$FDPROBE_SRC" <<'CEOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/time.h>
/* 只 open(O_RDONLY)（读打开在只读 bind 上是允许的），随后用 fd 版写钩子。
 * 每个都应返回 -1/EROFS。任何一个 rc==0 = 只读语义被 fd 版击穿。 */
int main(int argc, char **argv) {
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) { printf("OPEN-FAIL errno=%d\n", errno); return 3; }
    int bad = 0;
    if (fchmod(fd, 0700) == 0)                 { printf("FCHMOD-WROTE\n");   bad = 1; }
    else if (errno != EROFS)                   { printf("FCHMOD-ERR=%d\n", errno); bad = 1; }
    if (fchown(fd, 0, 0) == 0)                 { printf("FCHOWN-WROTE\n");   bad = 1; }
    else if (errno != EROFS)                   { printf("FCHOWN-ERR=%d\n", errno); bad = 1; }
    if (ftruncate(fd, 0) == 0)                 { printf("FTRUNCATE-WROTE\n"); bad = 1; }
    else if (errno != EROFS)                   { printf("FTRUNCATE-ERR=%d\n", errno); bad = 1; }
    struct timespec ts[2] = {{1000000000,0},{1000000000,0}};
    if (futimens(fd, ts) == 0)                 { printf("FUTIMENS-WROTE\n"); bad = 1; }
    else if (errno != EROFS)                   { printf("FUTIMENS-ERR=%d\n", errno); bad = 1; }
    close(fd);
    printf(bad ? "FD-RO-BREACH\n" : "FD-RO-OK\n");
    return bad ? 1 : 0;
}
CEOF
# 探针二进制放进只读 bind 之外的 rootfs 内（/tmp 下），guest 可 exec。
FDPROBE_C="$W/rofd"
i=1
while [ "$i" -le 15 ]; do
    gcc -O1 -w -o "$FDPROBE_C" "$FDPROBE_SRC" 2>"$W/cc2.err" && break
    grep -q 'internal compiler error' "$W/cc2.err" || { bad "rofd 探针无法编译"; break; }
    i=$((i + 1))
done
if [ -x "$FDPROBE_C" ]; then
    # 探针在容器 /tmp（=rootfs 内），guest 视角同路径可执行。
    out=$(BXROOT_BINDS="$BINDS" timeout 40 "$BX" --no-check -- "$FDPROBE_C" /mnt/ro/f 2>&1)
    case "$out" in
    *FD-RO-OK*)     good "fd 版写钩子全部被只读 bind 拦成 EROFS" ;;
    *FD-RO-BREACH*) bad "fd 版写钩子击穿只读 bind：$(echo "$out" | tr '\n' ' ')" ;;
    *)              bad "fd 版探针输出异常：$(echo "$out" | tr '\n' ' ')" ;;
    esac
fi

echo "--- a3) 非只读 bind 仍可写 ---"
out=$(runbx 'echo RW-NEW > /mnt/rw/h && cat /mnt/rw/h')
case "$out" in
*RW-NEW*) good "非只读 bind 写入成功" ;;
*) bad "非只读 bind 写入失败（不该受影响）：$out" ;;
esac
out=$(runbx 'mkdir -p /mnt/rw/sub2 && ls -d /mnt/rw/sub2')
case "$out" in
*/mnt/rw/sub2*) good "非只读 bind mkdir 成功" ;;
*) bad "非只读 bind mkdir 失败：$out" ;;
esac

echo "--- a4) 普通 rootfs 路径不受只读 bind 影响 ---"
out=$(runbx 'echo T > /tmp/robind-plain-$$ && cat /tmp/robind-plain-$$ && rm -f /tmp/robind-plain-$$')
case "$out" in
*T*) good "rootfs 内 /tmp 路径仍可写" ;;
*) bad "rootfs 内普通路径被误锁：$out" ;;
esac

echo
echo "=== ② launcher 解析（编译 launcher.c）==="

LAUNCHER="$W/launcher"
i=1
while [ "$i" -le 15 ]; do
    if gcc -static -O1 -w -o "$LAUNCHER" "$ROOT/src/launcher/launcher.c" \
        2>"$W/cc.err"; then
        break
    fi
    grep -q 'internal compiler error' "$W/cc.err" || {
        echo "  ⚠️  launcher.c 编译失败（非 ICE），跳过 launcher 解析测试"
        head -8 "$W/cc.err"
        # 编译问题不算 runtime 语义失败；但也不该假绿 → 记一个 fail
        bad "launcher.c 无法编译"
        break
    }
    i=$((i + 1))
done

if [ -x "$LAUNCHER" ]; then
    # -v 时 launcher 打印 "[bxroot-launcher] binds=<BXROOT_BINDS>"。
    # 不需要真正 exec guest：给一个不存在的 rootfs，binds 行在退出前已打印。
    echo "--- b1) -b h:g:ro 编码含 :ro 尾段 ---"
    out=$(timeout 10 "$LAUNCHER" -r /nonexistent-rootfs \
              -b /tmp/rosrc:/mnt/ro:ro -b /tmp/rwsrc:/mnt/rw \
              -v /bin/true 2>&1 | grep '\] binds=')
    case "$out" in
    *"/tmp/rosrc:/mnt/ro:ro"*)
        good "只读 bind 编码为 src:dst:ro（$out）" ;;
    *)
        bad "只读 bind 未编码出 :ro 尾段：$out" ;;
    esac
    case "$out" in
    *"/tmp/rwsrc:/mnt/rw:ro"*)
        bad "普通 bind 被误加 :ro：$out" ;;
    *"/tmp/rwsrc:/mnt/rw"*)
        good "普通 bind 保持两段 src:dst（无 :ro）" ;;
    *)
        bad "普通 bind 编码异常：$out" ;;
    esac

    echo "--- b2) -m h:g:ro（--mount 同样支持）---"
    out=$(timeout 10 "$LAUNCHER" -r /nonexistent-rootfs \
              -m /tmp/a:/mnt/a:ro -v /bin/true 2>&1 | grep '\] binds=')
    case "$out" in
    *"/tmp/a:/mnt/a:ro"*) good "-m 亦支持 :ro（$out）" ;;
    *) bad "-m 未编码 :ro：$out" ;;
    esac
else
    : # 上面已记 fail
fi

echo
if [ "$FAIL" -gt 0 ]; then echo "RESULT: FAIL（$FAIL 项）"; exit 1; fi
echo "RESULT: PASS"
