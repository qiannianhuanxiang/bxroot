#!/bin/sh
# ---------------------------------------------------------------------
# fakeroot：同进程内 chown/lchown/fchownat/fchown 后 stat/fstat/lstat 读回
# （BXR-FR-1，2026-09-27 爆破测试）
#
# 缺陷：路径 chown 只记 by_path 表，stat 补丁只按 dev+ino 查 → 读回恒为 0:0；
#       fchown 只记 fd 键 → stat(路径) 读不到。修：两路都补记 inode。
# 已知限制（与官方 proroot 一致，不在本测试范围）：记账是**进程内**的，
#       `chown 7:8 f; stat f` 分两个进程时读回 0:0。
# 退出：0 通过 / 1 失败 / 2 环境不满足
# ---------------------------------------------------------------------
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BX="$ROOT/tools/bxroot-run"
grep -q 'libproroot-runtime\.so' /proc/self/maps 2>/dev/null || { echo "⏭️  跳过：需要外层 proroot"; exit 2; }
[ -f "$ROOT/build/libbxroot-runtime.so" ] || { echo "⏭️  跳过：无 runtime"; exit 2; }
W=$(mktemp -d /tmp/bxroot-frchown-XXXXXX); trap 'rm -rf "$W"' EXIT
RF="$W/rf"; mkdir -p "$RF/etc" "$RF/tmp"
ln -s ../../../usr "$RF/usr"; ln -s usr/bin "$RF/bin"; ln -s usr/lib "$RF/lib"
cat > "$W/p.c" <<'C'
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
int main(void) { struct stat st; int fd;
  fd = open("/tmp/c", O_CREAT | O_WRONLY, 0600); close(fd);
  chown("/tmp/c", 1000, 2000); stat("/tmp/c", &st); printf("chown=%d:%d\n", st.st_uid, st.st_gid);
  lchown("/tmp/c", 1001, 2001); lstat("/tmp/c", &st); printf("lchown=%d:%d\n", st.st_uid, st.st_gid);
  fchownat(AT_FDCWD, "/tmp/c", 1002, 2002, 0); stat("/tmp/c", &st); printf("fchownat=%d:%d\n", st.st_uid, st.st_gid);
  fd = open("/tmp/c", O_RDONLY); fchown(fd, 1003, 2003); close(fd);
  stat("/tmp/c", &st); printf("fchown=%d:%d\n", st.st_uid, st.st_gid);
  chown("/tmp/c", 42, 43); fd = open("/tmp/c", O_RDONLY); fstat(fd, &st); close(fd);
  printf("fstat=%d:%d\n", st.st_uid, st.st_gid);
  rename("/tmp/c", "/tmp/d"); stat("/tmp/d", &st); printf("rename=%d:%d\n", st.st_uid, st.st_gid);
  unlink("/tmp/d"); return 0; }
C
i=0; until gcc -O1 -w -o "$RF/tmp/p" "$W/p.c" 2>/dev/null; do i=$((i+1)); [ $i -ge 8 ] && { echo "❌ 编译失败"; exit 1; }; done
o=$(cd / && BXROOT_FAKEROOT=1 timeout 60 "$BX" --no-check --rootfs "$RF" -- /tmp/p 2>&1 | tr '\n' ' ')
exp="chown=1000:2000 lchown=1001:2001 fchownat=1002:2002 fchown=1003:2003 fstat=42:43 rename=42:43 "
if [ "$o" = "$exp" ]; then echo "  ✅ $o"; echo "RESULT: PASS"; exit 0; fi
echo "  ❌ 得到 [$o]"; echo "     期望 [$exp]"; echo "RESULT: FAIL"; exit 1
