/* 沙箱逃逸探针：宿主绝对目标符号链接 × 各跟随型钩子（BXR-ESC-2/3）。见 test/RUN_ESCAPE.sh */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <dirent.h>
int hit;
#define E(name, cond) do { if (cond) { printf("ESCAPE %s\n", name); hit++; } } while (0)
static int rd(int fd) { char b[32] = {0}; if (fd < 0) return 0; int n = read(fd, b, 31); close(fd); return n > 0 && strstr(b, "CANARY"); }
int main(int c, char **v) {
  char h[4096]; snprintf(h, sizeof h, "%s/canary", v[1]);
  char hd[4096]; snprintf(hd, sizeof hd, "%s", v[1]);
  symlink(h, "/tmp/L"); symlink(hd, "/tmp/D");
  struct stat st; FILE *f; char buf[64];
  E("open", rd(open("/tmp/L", O_RDONLY)));
  E("open64", rd(open64("/tmp/L", O_RDONLY)));
  E("openat", rd(openat(AT_FDCWD, "/tmp/L", O_RDONLY)));
  E("raw openat", rd(syscall(SYS_openat, AT_FDCWD, "/tmp/L", O_RDONLY)));
  E("fopen", (f = fopen("/tmp/L", "r")) && fgets(buf, 64, f) && strstr(buf, "CANARY"));
  E("stat size", stat("/tmp/L", &st) == 0 && st.st_size == 7);
  E("access", access("/tmp/L", R_OK) == 0);
  E("dir-link open", rd(open("/tmp/D/canary", O_RDONLY)));
  E("dir-link stat", stat("/tmp/D/canary", &st) == 0);
  E("opendir", opendir("/tmp/D") != NULL);
  E("chdir+rel", chdir("/tmp/D") == 0 && rd(open("canary", O_RDONLY)));
  chdir("/");
  { char rb[4096]; E("realpath", realpath("/tmp/L", rb) && 0); }
  E("rename out", rename("/tmp/x_nonexist", "/tmp/D/pwn") == 0);
  int w = open("/tmp/D/pwned", O_WRONLY | O_CREAT, 0644); E("create via dir link", w >= 0); if (w >= 0) close(w);
  w = open("/tmp/L", O_WRONLY | O_APPEND); E("write via link", w >= 0); if (w >= 0) close(w);
  E("truncate", truncate("/tmp/L", 7) == 0);
  E("chmod", chmod("/tmp/L", 0644) == 0);
  E("link/hardlink", link("/tmp/L", "/tmp/HL") == 0 && rd(open("/tmp/HL", O_RDONLY)));

  unlink("/tmp/L"); unlink("/tmp/D"); unlink("/tmp/HL");
  printf("DONE escapes=%d\n", hit); return 0;
}
