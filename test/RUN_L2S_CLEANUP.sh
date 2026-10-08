#!/bin/sh
# ---------------------------------------------------------------------
# l2s 中间文件的**清理行为**（上游 proot #131/#28）—— 双基线端到端
#
# 【背景】link2symlink 用三个文件模拟一条硬链接：
#     中间层 .l2s.<name>0001 -> 数据文件 .l2s.<name>0001.0002 + 计数 .cnt
# 布局两种：集中目录 <rootfs>/.l2s（BXROOT_L2S_DIR 有值）与散落在客户
# 文件旁（BXROOT_L2S_DIR 显式为空）。上游 #131/#28 抱怨"中间文件越积越
# 多"，本测试把"每一条会改变引用计数的入口"都实测一遍，并与官方 runtime
# （同一 bridge/linker，只换 --preload）对照。
#
# 【2026-09-26 实测发现的两个缺陷（本测试即其回归）】
#   ① 裸 syscall(SYS_unlinkat) 不记账：只翻译路径然后让内核删符号链接，
#      .cnt 不减 → 另一名字 nlink 停在 2 → 最后一次 unlink 只减到 1 →
#      三个中间文件永久残留。官方：nlink 正确回到 1。
#      修法：syscall_guard.c 在 svc 前接 l2s_rt_unlink（与 libc 钩子同源）。
#   ② rename 覆盖伪造链接（`mv c b`，b 是 l2s 链接）不记账：内核用 c 顶掉
#      符号链接 b，.cnt 仍是 2 → a 报 nlink=2（官方 1）→ rm a 后残留。
#      libc rename/renameat/renameat2 与裸 38/276 都缺。
#      修法：l2s_rt_rename_replace_prepare/commit（svc 前判定、成功后递减）。
#
# 【判据】被测对象自己的痕迹：客户目录 + 集中目录里 .l2s.* 的个数、
# 客户视角 st_nlink。程序"跑起来了"不算证据。
#
# 【期望值取 Linux 硬链接语义，不直接取官方输出 —— 实测官方在四处偏离】
#   C3/C3b/C5 覆盖后官方仍报 a=2（Linux：1；b 已是别的文件）；
#   C7 同一链两个名字互相 rename：Linux 是 no-op 且 a 仍在，官方把 a 删了；
#   C8 官方 lstat 报 4/3（同进程 stat 报 3/2，自身不一致）。
# 官方基线仍然跑并打印，作为对照信息；逐行断言以 Linux 语义（下方 EXPECT）
# 为准 —— 与官方一致的项自然也一致。
# 退出：0 通过 / 1 失败 / 2 环境不满足。
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BX="$ROOT/tools/bxroot-run"

[ -f "$ROOT/build/libbxroot-runtime.so" ] || { echo "⏭️  跳过：没有 build/libbxroot-runtime.so"; exit 2; }
[ -x "$BX" ] || { echo "⏭️  跳过：缺 tools/bxroot-run"; exit 2; }
grep -q 'libproroot-runtime\.so' /proc/self/maps 2>/dev/null || {
    echo "⏭️  跳过：不在官方 proroot 下（bxroot-run 需要其注入链路，且无对照组）"; exit 2; }
[ -n "${PROROOT_ROOTFS:-}" ] || { echo "⏭️  跳过：无 PROROOT_ROOTFS"; exit 2; }
command -v gcc >/dev/null 2>&1 || { echo "⏭️  跳过：没有 gcc"; exit 2; }

APP_LIB=""
for m in /proc/[0-9]*/maps; do
    p=$(grep -a 'libproroot-bridge\.so' "$m" 2>/dev/null | head -1 | awk '{print $6}')
    [ -n "${p:-}" ] && { APP_LIB=${p%/*}; break; }
done
[ -n "$APP_LIB" ] || { echo "⏭️  跳过：探测不到官方库目录"; exit 2; }

W=${TMPDIR:-/tmp}/l2s_cleanup_$$
mkdir -p "$W"
trap 'rm -rf "$W" /tmp/l2scl_*' EXIT INT TERM
# 集中目录必须是本测试私有的临时路径。
# 生产环境 PROOT_L2S_DIR / 容器视角 /.l2s 里是真实 rootfs 的硬链接后备
# （例如 /usr/bin/perl → /.l2s/.l2s.perl.dpkg-new0001）。曾经把
# L2SDIR=/.l2s 再 rm -rf，会把生产树的 perl backing 一并清掉。
# 用例后数这个私有目录 —— 仍是"中间文件是否回收"的直接判据。
L2SDIR="$W/l2s-central"
mkdir -p "$L2SDIR"

# ---------- 探针：所有会改变计数的入口，逐步打印 nlink 与目录残留 ----------
cat > "$W/probe.c" <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/syscall.h>
static const char *D;
static unsigned nl(const char *n){ char p[512]; struct stat s; snprintf(p,512,"%s/%s",D,n);
    if (lstat(p,&s)) return 0; return (unsigned)s.st_nlink; }
static void mk(const char *n,const char *c){ char p[512]; snprintf(p,512,"%s/%s",D,n);
    int fd=open(p,O_CREAT|O_WRONLY|O_TRUNC,0644); if(fd>=0){ write(fd,c,strlen(c)); close(fd);} }
static int ex(const char *n){ char p[512]; struct stat s; snprintf(p,512,"%s/%s",D,n); return lstat(p,&s)==0; }
static void P(const char *a,const char *b,int flags){ char pa[512],pb[512]; snprintf(pa,512,"%s/%s",D,a); snprintf(pb,512,"%s/%s",D,b);
    (void)flags; }
static int LN(const char *a,const char *b){ char pa[512],pb[512]; snprintf(pa,512,"%s/%s",D,a); snprintf(pb,512,"%s/%s",D,b); return link(pa,pb); }
static int RM(const char *a){ char pa[512]; snprintf(pa,512,"%s/%s",D,a); return unlink(pa); }
static long RAWRM(const char *a){ char pa[512]; snprintf(pa,512,"%s/%s",D,a); return syscall(SYS_unlinkat,AT_FDCWD,pa,0); }
static int MV(const char *a,const char *b){ char pa[512],pb[512]; snprintf(pa,512,"%s/%s",D,a); snprintf(pb,512,"%s/%s",D,b); return rename(pa,pb); }
static long RAWMV(const char *a,const char *b){ char pa[512],pb[512]; snprintf(pa,512,"%s/%s",D,a); snprintf(pb,512,"%s/%s",D,b); return syscall(SYS_renameat2,AT_FDCWD,pa,AT_FDCWD,pb,0); }
static int RMAT(const char *a){ char pa[512]; snprintf(pa,512,"%s/%s",D,a); return unlinkat(AT_FDCWD,pa,0); }
static int MVAT2(const char *a,const char *b){ char pa[512],pb[512]; snprintf(pa,512,"%s/%s",D,a); snprintf(pb,512,"%s/%s",D,b); return renameat2(AT_FDCWD,pa,AT_FDCWD,pb,0); }
/* 客户视角能列举到的、非 a/b/c 的名字（散落布局下会看到 .l2s.*，只打印个数） */
static int stray(void){ DIR *d=opendir(D); struct dirent *e; int n=0; if(!d) return -1;
    while((e=readdir(d))) { if(strcmp(e->d_name,".")&&strcmp(e->d_name,"..")&&strcmp(e->d_name,"a")&&strcmp(e->d_name,"b")&&strcmp(e->d_name,"c")) n++; }
    closedir(d); return n; }
int main(int argc,char **argv){
    D=argv[1]; (void)P;
    printf("C1 ln a b; rm a; rm b\n");
    mk("a","hi"); if(LN("a","b")){printf("  link failed errno=%d\n",errno); return 1;}
    printf("  after ln: a=%u b=%u\n",nl("a"),nl("b"));
    RM("a"); printf("  after rm a: b=%u a_exists=%d\n",nl("b"),ex("a"));
    RM("b"); printf("  after rm b: b_exists=%d\n",ex("b"));
    printf("C2 ln a b; rm b\n");
    mk("a","hi"); LN("a","b"); RM("b");
    printf("  a=%u\n",nl("a")); RM("a");
    printf("C3 libc rename c over b\n");
    mk("a","hi"); LN("a","b"); mk("c","zz"); MV("c","b");
    printf("  a=%u b=%u c_exists=%d\n",nl("a"),nl("b"),ex("c")); RM("a"); RM("b");
    printf("C3b libc renameat2 c over b\n");
    mk("a","hi"); LN("a","b"); mk("c","zz"); MVAT2("c","b");
    printf("  a=%u b=%u\n",nl("a"),nl("b")); RM("a"); RM("b");
    printf("C4 raw unlinkat a; raw unlinkat b\n");
    mk("a","hi"); LN("a","b"); RAWRM("a");
    printf("  after raw rm a: b=%u\n",nl("b")); RAWRM("b"); printf("  b_exists=%d\n",ex("b"));
    printf("C4b libc unlinkat\n");
    mk("a","hi"); LN("a","b"); RMAT("a"); printf("  after unlinkat a: b=%u\n",nl("b")); RMAT("b");
    printf("C5 raw renameat2 c over b\n");
    mk("a","hi"); LN("a","b"); mk("c","zz"); RAWMV("c","b");
    printf("  a=%u b=%u\n",nl("a"),nl("b")); RM("a"); RM("b");
    printf("C6 rename the link itself (b->c) keeps chain\n");
    mk("a","hi"); LN("a","b"); MV("b","c");
    printf("  a=%u c=%u\n",nl("a"),nl("c")); RM("a"); printf("  after rm a: c=%u\n",nl("c")); RM("c");
    printf("C7 rename between two names of the same link is a no-op\n");
    mk("a","hi"); LN("a","b"); { int r=MV("a","b"); printf("  rc=%d a_exists=%d b=%u\n",r,ex("a"),nl("b")); }
    RM("a"); RM("b");
    printf("C8 3 names, drop in odd order\n");
    mk("a","hi"); LN("a","b"); LN("b","c"); printf("  a=%u b=%u c=%u\n",nl("a"),nl("b"),nl("c"));
    RM("b"); printf("  after rm b: a=%u c=%u\n",nl("a"),nl("c")); RM("a"); RM("c");
    printf("END stray=%d\n",stray());
    return 0;
}
EOF
ok=0; i=1
while [ $i -le 8 ]; do
    gcc -O0 -w -o "$W/probe" "$W/probe.c" 2>"$W/cc" && { ok=1; break; }
    grep -q 'internal compiler error' "$W/cc" || break
    i=$((i + 1))
done
[ $ok = 1 ] || { echo "❌ 探针编译失败"; cat "$W/cc"; exit 1; }

FAIL=0
bad() { FAIL=$((FAIL + 1)); echo "  ❌ $*"; }
good() { echo "  ✅ $*"; }

run_off() {   # 官方 runtime 基线：同一 bridge/linker，只换 --preload
    timeout 120 "$APP_LIB/libproroot-bridge.so" "$APP_LIB/libproroot-linker.so" \
        --argv0 probe --preload "$APP_LIB/libproroot-runtime.so" \
        "$PROROOT_ROOTFS$W/probe" "$1" 2>&1 | grep -v '^\[NEXT\]'
}
run_bx() {    # $1 = 工作目录  $2 = central|scatter
    if [ "$2" = scatter ]; then
        BXROOT_LINK2SYMLINK=1 BXROOT_L2S_DIR= timeout 120 "$BX" -- "$W/probe" "$1" 2>&1
    else
        BXROOT_LINK2SYMLINK=1 BXROOT_L2S_DIR="$L2SDIR" timeout 120 "$BX" -- "$W/probe" "$1" 2>&1
    fi | grep -v '^\[bxroot\]'
}
# 官方基线里 stray 恒 0（它的中间文件不在客户树里），bxroot 散落布局下
# 中途会出现 .l2s.*，但 END 时必须为 0 —— 所以对照时忽略 END 行的 stray。
norm() { sed 's/^END stray=.*/END/' "$1"; }

cat > "$W/expect.txt" <<'EXPECT_EOF'
C1 ln a b; rm a; rm b
  after ln: a=2 b=2
  after rm a: b=1 a_exists=0
  after rm b: b_exists=0
C2 ln a b; rm b
  a=1
C3 libc rename c over b
  a=1 b=1 c_exists=0
C3b libc renameat2 c over b
  a=1 b=1
C4 raw unlinkat a; raw unlinkat b
  after raw rm a: b=1
  b_exists=0
C4b libc unlinkat
  after unlinkat a: b=1
C5 raw renameat2 c over b
  a=1 b=1
C6 rename the link itself (b->c) keeps chain
  a=2 c=2
  after rm a: c=1
C7 rename between two names of the same link is a no-op
  rc=0 a_exists=1 b=2
C8 3 names, drop in odd order
  a=3 b=3 c=3
  after rm b: a=2 c=2
END
EXPECT_EOF

echo "== 0) 官方基线（信息）=="
mkdir -p /tmp/l2scl_off
run_off /tmp/l2scl_off > "$W/off.txt"
grep -q '^END' "$W/off.txt" || { echo "⏭️  跳过：官方探针没跑完"; sed 's/^/   /' "$W/off.txt" | head; exit 2; }
sed 's/^/   /' "$W/off.txt"

for L in central scatter; do
    echo "== $L 布局 =="
    WD=/tmp/l2scl_$L
    rm -rf "$WD" "$L2SDIR"; mkdir -p "$WD" "$L2SDIR"
    run_bx "$WD" "$L" > "$W/bx_$L.txt"
    grep -q '^END' "$W/bx_$L.txt" || { bad "探针没跑完"; sed 's/^/   /' "$W/bx_$L.txt" | head -20; continue; }

    # (1) 先证明 l2s 真生效：中途创建一条链，外层 readlink 必须指到 .l2s.*
    mkdir -p "$WD/chk"
    if [ "$L" = scatter ]; then
        BXROOT_LINK2SYMLINK=1 BXROOT_L2S_DIR= "$BX" -- /bin/sh -c "echo x > $WD/chk/f && ln $WD/chk/f $WD/chk/g" >/dev/null 2>&1
    else
        BXROOT_LINK2SYMLINK=1 BXROOT_L2S_DIR="$L2SDIR" "$BX" -- /bin/sh -c "echo x > $WD/chk/f && ln $WD/chk/f $WD/chk/g" >/dev/null 2>&1
    fi
    tgt=$(readlink "$WD/chk/f" 2>/dev/null)
    case "$L:$tgt" in
        central:*/.l2s/.l2s.*) good "l2s 生效（集中布局，f -> $tgt）" ;;
        scatter:*/.l2s/*)       bad "散落布局却落进集中目录（f -> $tgt）" ;;
        scatter:*.l2s.f*)       good "l2s 生效（散落布局，f -> $tgt）" ;;
        *) bad "l2s 未生效或布局不对（readlink f = '$tgt'）—— 后续结论无效" ;;
    esac
    rm -rf "$WD/chk"; rm -rf "$L2SDIR"/.l2s.f0001* 2>/dev/null

    # (2) 与 Linux 语义逐行对照（EXPECT），并报告与官方的差异（信息）
    if norm "$W/bx_$L.txt" > "$W/b" && cmp -s "$W/expect.txt" "$W/b"; then
        good "全部 $(grep -c '^C' "$W/b") 个用例的 nlink/存在性符合 Linux 硬链接语义"
    else
        bad "与 Linux 语义不一致（< 期望 / > bxroot）："; diff "$W/expect.txt" "$W/b" | sed 's/^/     /' | head -20
    fi
    if norm "$W/off.txt" > "$W/o" && ! cmp -s "$W/o" "$W/b"; then
        echo "  ℹ️  与官方 runtime 的差异（< 官方 / > bxroot；官方偏离处见文件头）："
        diff "$W/o" "$W/b" | grep '^[<>]' | sed 's/^/     /' | head -12
    fi
    # (3) 客户树里 0 残留（END stray）
    s=$(sed -n 's/^END stray=\([0-9-]*\).*/\1/p' "$W/bx_$L.txt")
    [ "$s" = 0 ] && good "客户目录 END 时无 .l2s.* 残留（stray=0）" || bad "客户目录残留 stray=$s"
    # (4) 集中目录 0 残留；散落布局下集中目录不该被创建/使用
    n=$(ls -A "$L2SDIR" 2>/dev/null | wc -l)
    [ "$n" = 0 ] && good "集中目录 $L2SDIR 条目数 0" || { bad "集中目录残留 $n 个："; ls -A "$L2SDIR" | sed 's/^/     /' | head; }
    # (5) 外层视角：客户目录也必须干净
    r=$(find "$WD" -name '.l2s.*' 2>/dev/null | wc -l)
    [ "$r" = 0 ] && good "外层视角客户目录 0 个 .l2s.*" || bad "外层视角客户目录残留 $r 个 .l2s.*"
    # (6) 集中目录不出现在 / 以外：客户 ls -a 工作目录里不该有 .l2s 目录
    if [ "$L" = central ]; then
        e=$(BXROOT_LINK2SYMLINK=1 BXROOT_L2S_DIR="$L2SDIR" "$BX" -- /bin/sh -c "ls -a $WD /tmp | grep -c '^\.l2s\$'" 2>/dev/null | tail -1)
        [ "${e:-0}" = 0 ] && good "集中目录不泄漏到 /tmp 或工作目录的列举中" || bad "在 /tmp 或工作目录列举里看到 .l2s 目录"
    fi
    rm -rf "$WD"
done

echo
[ "$FAIL" -gt 0 ] && { echo "RESULT: FAIL（$FAIL 项）"; exit 1; }
echo "RESULT: PASS"
