/* 沙箱逃逸探针：`..` 夹紧（BXR-ESC-1）。argv[1] = rootfs 之外 canary 所在的宿主目录。见 test/RUN_ESCAPE.sh */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
static int hit;
static void chk(const char *how, int fd) {
  char b[64] = {0};
  if (fd >= 0) { int n = read(fd, b, 63); close(fd); if (n > 0 && strstr(b, "CANARY")) { printf("ESCAPE %s\n", how); hit++; } }
}
int main(int c, char **v) {
  const char *H = v[1];           /* host path of canary dir, e.g. /data/.../bxfz */
  char p[4096];
  const char *rel[] = {"/../canary", "/../../canary", "/tmp/../../canary", "//..//canary", "/./../canary",
                       "/proc/self/root/../canary", "/proc/self/cwd/../canary", "/proc/1/root/canary", NULL};
  for (int i = 0; rel[i]; i++) chk(rel[i], open(rel[i], O_RDONLY));
  snprintf(p, sizeof p, "%s/canary", H); chk("host-abs", open(p, O_RDONLY));
  snprintf(p, sizeof p, "/proc/self/root%s/canary", H); chk("proc-root+host", open(p, O_RDONLY));
  chk("raw openat ..", syscall(SYS_openat, AT_FDCWD, "/../canary", O_RDONLY));
  int d = open("/", O_RDONLY | O_DIRECTORY);
  chk("openat(/,..)", openat(d, "../canary", O_RDONLY));
  chk("raw openat(/,..)", syscall(SYS_openat, d, "../canary", O_RDONLY));
  int op = open("/", O_PATH);
  chk("openat(O_PATH /,..)", openat(op, "../canary", O_RDONLY));
  chdir("/"); chk("rel ../canary", open("../canary", O_RDONLY));
  chk("rel ../../../canary", open("../../../canary", O_RDONLY));
  chk("fchdir+..", (fchdir(d), open("../canary", O_RDONLY)));
  symlink("../canary", "/tmp/l1"); chk("symlink rel", open("/tmp/l1", O_RDONLY));
  symlink("/../canary", "/tmp/l2"); chk("symlink abs..", open("/tmp/l2", O_RDONLY));
  snprintf(p, sizeof p, "%s/canary", H); symlink(p, "/tmp/l3"); chk("symlink host-abs", open("/tmp/l3", O_RDONLY));
  mkdir("/tmp/dd", 0755); int dd = open("/tmp/dd", O_RDONLY); rmdir("/tmp/dd");
  chk("deleted-dir fd ../../..", openat(dd, "../../../canary", O_RDONLY));
  char buf[256]; long n = readlink("/proc/self/cwd", buf, sizeof buf - 1); if (n > 0) { buf[n] = 0; printf("cwd-link=%s\n", buf); }
  n = readlink("/proc/self/exe", buf, sizeof buf - 1); if (n > 0) { buf[n] = 0; printf("exe-link=%s\n", buf); }
  unlink("/tmp/l1"); unlink("/tmp/l2"); unlink("/tmp/l3");
  printf("DONE escapes=%d\n", hit);
  return 0;
}
