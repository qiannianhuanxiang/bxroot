#!/bin/sh
# =====================================================================
# RUN_FUZZ_ID.sh —— 身份/权限层爆破回归（BXR-FR-2，2026-09-27）
#
# 覆盖 fakeroot(-0) 下的降权族与身份查询族，对照官方基线钉住语义。
# 前一轮 BXR-FR-1 修的是 chown 账本读回；本轮修的是**降权族**，共 3 类：
#
#   ① seteuid/setegid 完全没被钩住
#      glibc 的 seteuid()/setegid() 内联发 svc(147/149)，既不经 syscall()
#      钩子也不经 setres* 符号钩子；bxroot 从前**没导出这两个符号** →
#      客户调 seteuid 直落内核 → fakeroot 下 EPERM。官方下成功。
#      表现：任何 "setuid 降权后再 seteuid 临时改 euid" 的守护进程崩。
#
#   ② setreuid/setregid 误改 saved-id
#      官方 setreuid(5,6) 从 0/0/0 → r=5 e=6 **s 不变=0**；旧实现照抄内核
#      "euid 变化连带改 suid" 规则 → 5,6,6，与官方不一致。
#
#   ③ 降权后无法回 root / 后续 set*id 全 EPERM
#      旧实现的 MAYBE_DROP_CAPS 在 r/e/s 全非 0 时清 caps_active，之后
#      setuid(0) 返回 EPERM，且此后任意 set*id 全 EPERM。官方 fakeroot
#      下 root 特权**永久**，任何 set*id 都成功。
#
#   ④ 裸 syscall(175 geteuid / 177 getegid) 回 ruid/rgid 而非 euid/egid
#      seteuid(1234) 后裸 syscall(175) 回 0，libc geteuid 回 1234 —— 裸
#      syscall 层与符号层自相矛盾。修：175/177 改走 res_ids 取 euid/egid。
#
# 判据取"被测对象自己的痕迹"：探针直接读回 res-id 与返回值/errno，
# 并（若有官方 runtime）逐字节对照。golden 值即官方实测行为。
#
# 判别力：撤掉 src/runtime/fakeroot.c 的降权族改写 / preload.c 的
# seteuid 符号钩子 / syscall_guard.c 的 175/177 分流，本测试任一都变红。
#
# 退出码：0 通过 / 1 失败 / 2 环境不满足（缺外层 proroot 或缺 build/）
# =====================================================================
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BX="$ROOT/tools/bxroot-run"

grep -q 'libproroot-runtime\.so' /proc/self/maps 2>/dev/null || {
    echo "⏭️  跳过：需要外层 proroot（launcher+LD_PRELOAD 在此不可测）"; exit 2; }
[ -f "$ROOT/build/libbxroot-runtime.so" ] || { echo "⏭️  跳过：无 build/ 产物"; exit 2; }

# 官方基线（可选）：有则做逐字节对照，增强判别力；无则只对 golden。
OFFICIAL_SO="${BXROOT_OFFICIAL_SO:-/tmp/off-rt.so}"
HAVE_OFF=0
[ -f "$OFFICIAL_SO" ] && HAVE_OFF=1

W=$(mktemp -d /tmp/bxroot-fuzzid-XXXXXX); trap 'rm -rf "$W"' EXIT

# ---------------------------------------------------------------------
# 探针：一个二进制，按 argv 走一串降权/身份操作，逐步打印 res-id。
# 用裸 syscall(SYS_getresuid/getresgid) 读回，避免被符号钩子影响判据。
# ---------------------------------------------------------------------
cat > "$W/p.c" <<'C'
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <errno.h>
static void sh(const char *t) {
    unsigned r, e, s, rg, eg, sg;
    syscall(SYS_getresuid, &r, &e, &s);
    syscall(SYS_getresgid, &rg, &eg, &sg);
    printf("%s u=%u,%u,%u g=%u,%u,%u\n", t, r, e, s, rg, eg, sg);
}
int main(int argc, char **argv) {
    int i;
    for (i = 1; i < argc; i++) {
        char *a = strdup(argv[i]);
        char *op = strtok(a, " ");
        long rc = 0; errno = 0;
        if      (!strcmp(op, "su"))    rc = setuid(atoi(strtok(NULL, " ")));
        else if (!strcmp(op, "sg"))    rc = setgid(atoi(strtok(NULL, " ")));
        else if (!strcmp(op, "seu"))   rc = seteuid(atoi(strtok(NULL, " ")));
        else if (!strcmp(op, "seg"))   rc = setegid(atoi(strtok(NULL, " ")));
        else if (!strcmp(op, "sru"))  { int x=atoi(strtok(NULL," "));int y=atoi(strtok(NULL," "));rc=setreuid(x,y); }
        else if (!strcmp(op, "srg"))  { int x=atoi(strtok(NULL," "));int y=atoi(strtok(NULL," "));rc=setregid(x,y); }
        else if (!strcmp(op, "sresu")){int x=atoi(strtok(NULL," "));int y=atoi(strtok(NULL," "));int z=atoi(strtok(NULL," "));rc=setresuid(x,y,z);}
        else if (!strcmp(op, "sresg")){int x=atoi(strtok(NULL," "));int y=atoi(strtok(NULL," "));int z=atoi(strtok(NULL," "));rc=setresgid(x,y,z);}
        printf("[%s] rc=%ld e=%d\n", argv[i], rc, errno);
        sh("  ");
        free(a);
    }
    /* 结尾再打印 libc-vs-raw 一致性：seteuid 后 libc.geteuid 必须 == 裸 175 */
    printf("consistency libc.euid=%d raw.euid=%ld libc.uid=%d raw.uid=%ld\n",
           geteuid(), syscall(SYS_geteuid), getuid(), syscall(SYS_getuid));
    return 0;
}
C

i=0
until gcc -O0 -w -o "$W/p" "$W/p.c" 2>"$W/cc"; do
    i=$((i + 1)); grep -q 'internal compiler error' "$W/cc" || { echo "❌ 编译失败"; cat "$W/cc"; exit 1; }
    [ $i -ge 8 ] && { echo "❌ 编译反复 ICE"; exit 1; }
done

run_bx()  { BXROOT_FAKEROOT=1 timeout 60 "$BX" --no-check -- "$W/p" "$@" 2>/dev/null | grep -vE '^\[NEXT\]|^\[bxroot\]'; }
run_off() { BXROOT_FAKEROOT=1 BXROOT_RUN_RUNTIME="$OFFICIAL_SO" timeout 60 "$BX" --no-check -- "$W/p" "$@" 2>/dev/null | grep -vE '^\[NEXT\]|^\[bxroot\]'; }

FAIL=0
ok()  { echo "  ✅ $*"; }
bad() { FAIL=$((FAIL + 1)); echo "  ❌ $*"; }

# ---------------------------------------------------------------------
# 场景表：每行一组操作序列（op 之间用 | 分隔）。golden 是官方实测输出。
# 用 case 精确核对关键行，避免脆弱的整块字符串比较。
# ---------------------------------------------------------------------
echo "== A) 降权族逐场景（golden = 官方基线实测）=="

# ① seteuid 从 root：只改 euid，成功
o=$(run_bx "seu 5")
case "$o" in
    *"[seu 5] rc=0 e=0"*"u=0,5,0"*) ok "seteuid(5) 只改 euid → 0/5/0，rc=0" ;;
    *) bad "seteuid(5) 偏离：$(echo "$o" | tr '\n' ';')" ;;
esac

# ② setuid 降权后回 root
o=$(run_bx "su 1000" "su 0")
case "$o" in
    *"[su 0] rc=0 e=0"*"u=0,0,0"*) ok "setuid(1000)→setuid(0) 回 root，rc=0" ;;
    *) bad "回 root 失败：$(echo "$o" | tr '\n' ';')" ;;
esac

# ③ setreuid 不动 saved-id
o=$(run_bx "sru 5 6")
case "$o" in
    *"u=5,6,0"*) ok "setreuid(5,6) 从 0/0/0 → 5,6,0（suid 不动）" ;;
    *) bad "setreuid 误改 suid：$(echo "$o" | tr '\n' ';')" ;;
esac

# ④ setregid 不动 sgid
o=$(run_bx "srg 5 6")
case "$o" in
    *"g=5,6,0"*) ok "setregid(5,6) 从 0/0/0 → 5,6,0（sgid 不动）" ;;
    *) bad "setregid 误改 sgid：$(echo "$o" | tr '\n' ';')" ;;
esac

# ⑤ 降权后任意 setresuid 成功（root 特权永久）
o=$(run_bx "su 1000" "sresu 5 6 7")
case "$o" in
    *"[sresu 5 6 7] rc=0 e=0"*"u=5,6,7"*) ok "降权后 setresuid(5,6,7) rc=0 → 5,6,7" ;;
    *) bad "降权后 setresuid 被拒：$(echo "$o" | tr '\n' ';')" ;;
esac

# ⑥ setuid 三置
o=$(run_bx "su 42")
case "$o" in
    *"u=42,42,42"*) ok "setuid(42) 三置 → 42,42,42" ;;
    *) bad "setuid 未三置：$(echo "$o" | tr '\n' ';')" ;;
esac

echo "== B) 符号层与裸 syscall 层自洽 =="

# ⑦ seteuid 后 libc.geteuid == 裸 syscall(175)
o=$(run_bx "seu 1234")
case "$o" in
    *"consistency libc.euid=1234 raw.euid=1234 "*) ok "seteuid(1234) 后 libc/裸 geteuid 一致=1234" ;;
    *) bad "geteuid 符号/裸 syscall 不一致：$(echo "$o" | grep consistency)" ;;
esac

echo "== C) 与官方 runtime 逐字节对照（判别力增强）=="
if [ "$HAVE_OFF" = 1 ]; then
    DIFF=0
    for seq in "seu 5" "su 1000|su 0" "sru 5 6" "srg 5 6" \
               "su 1000|sresu 5 6 7" "seu 1234" "sresu 10 20 30|sru 40 50" \
               "sg 1000|srg 5 6" "seg 500|su 0"; do
        oldIFS=$IFS; IFS='|'; set --; for a in $seq; do set -- "$@" "$a"; done; IFS=$oldIFS
        b=$(run_bx "$@"); f=$(run_off "$@")
        if [ "$b" != "$f" ]; then
            DIFF=$((DIFF + 1))
            echo "     ✗ 序列 [$seq]"
            echo "       bxroot: $(echo "$b" | tr '\n' ';')"
            echo "       官方  : $(echo "$f" | tr '\n' ';')"
        fi
    done
    [ "$DIFF" = 0 ] && ok "9 组序列与官方逐字节一致" || bad "$DIFF 组与官方不一致"
else
    echo "  ⏭️  无官方 runtime（$OFFICIAL_SO）→ 跳过对照，仅 golden 判据生效"
fi

echo "------------------------------------------------------"
if [ "$FAIL" = 0 ]; then
    echo "RESULT: PASS"; exit 0
else
    echo "RESULT: FAIL（$FAIL 项）—— 身份/权限层降权族语义偏离官方"; exit 1
fi
