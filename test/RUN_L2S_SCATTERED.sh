#!/bin/sh
# ---------------------------------------------------------------------
# l2s **散落布局**（中间层生成在客户文件旁边）的端到端契约
#
# 【为什么要有这个文件】
#
# `tools/bxroot-run` 给 `BXROOT_L2S_DIR` 兜底后，"不设该变量"已经
# 不再走散落布局了（默认 `<rootfs>/.l2s`）。若不显式清空，散落这条
# 真实端到端路径就没有覆盖了 —— 只有 `test/test_l2s_rt.c` 用**注入的
# 内存 FS** 在测它，那条路径与真实 stat 钩子不同，测不出布局缺陷。
#
# 【判据】与集中布局完全相同（布局是内部实现，不该影响客户可见语义）：
#   stat/lstat 都报 nlink=2、非符号链接、size 是真实内容长度；
#   两个名字都能读到内容。
# ---------------------------------------------------------------------

set -u

ROOT=/root/bxroot
PROBE_C=${TMPDIR:-/tmp}/l2s_scatter_probe.c
PROBE=${TMPDIR:-/tmp}/l2s_scatter_probe
WORK=${TMPDIR:-/tmp}/l2s_scatter_work

cat > "$PROBE_C" <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
int main(void){
    const char *a = "/tmp/l2s_scatter_work/a";
    const char *b = "/tmp/l2s_scatter_work/b";
    struct stat s, l;
    char buf[64];
    ssize_t n;
    int fd, bad = 0;

    unlink(a); unlink(b);
    fd = open(a, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (fd < 0) { printf("open failed\n"); return 2; }
    if (write(fd, "hello", 5) != 5) { printf("write failed\n"); return 2; }
    close(fd);

    if (link(a, b) != 0) { printf("link failed\n"); return 2; }

    if (stat(a, &s) != 0)  { printf("stat failed\n"); return 2; }
    if (lstat(a, &l) != 0) { printf("lstat failed\n"); return 2; }

    if (s.st_nlink != 2) { printf("  stat  nlink=%lu 期望 2\n",
                                  (unsigned long)s.st_nlink); bad = 1; }
    if (l.st_nlink != 2) { printf("  lstat nlink=%lu 期望 2\n",
                                  (unsigned long)l.st_nlink); bad = 1; }
    if (S_ISLNK(s.st_mode)) { printf("  stat 报成符号链接\n"); bad = 1; }
    if (S_ISLNK(l.st_mode)) { printf("  lstat 报成符号链接\n"); bad = 1; }
    if (s.st_size != 5) { printf("  stat size=%ld 期望 5\n",
                                 (long)s.st_size); bad = 1; }

    fd = open(b, O_RDONLY);
    if (fd < 0) { printf("  第二个名字读不到\n"); bad = 1; }
    else {
        n = read(fd, buf, sizeof(buf) - 1);
        if (n == 5 && buf[0] == 'h') { /* ok */ }
        else { printf("  内容不对 n=%zd\n", n); bad = 1; }
        close(fd);
    }

    unlink(a); unlink(b);
    return bad ? 1 : 0;
}
EOF

if ! gcc -O0 -w -o "$PROBE" "$PROBE_C" 2>/dev/null; then
    echo "❌ 探针编译失败"
    exit 1
fi
mkdir -p "$WORK"

# ★ 关键：显式清空，强制散落布局 ★
BXROOT_L2S_DIR= "$ROOT/tools/bxroot-run" -- "$PROBE"
rc=$?

rm -f "$PROBE" "$PROBE_C"
rm -rf "$WORK"

if [ "$rc" -eq 0 ]; then
    echo "RESULT: PASS —— 散落布局下硬链接契约成立"
else
    echo "RESULT: FAIL —— 散落布局下硬链接契约被破坏（见上面的明细）"
fi
exit "$rc"
