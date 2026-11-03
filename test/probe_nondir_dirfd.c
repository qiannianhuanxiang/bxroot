/*
 * 非目录 dirfd 语义回归（审计 PR #1 P1）
 *
 * 内核契约：*at 族的相对路径必须以 dirfd 为基准解析；dirfd 不是目录时
 * 返回 ENOTDIR，fd 无效时返回 EBADF —— **绝不**退回按 cwd 解释。
 *
 * 曾经的缺陷：resolve_dirfd_path() 在 dirfd 非目录时仍把
 * "<dir>/../victim" 拼好交给内核，规范化后 "../" 被消掉，于是本该
 * ENOTDIR 的调用变成一次**成功**的对兄弟文件的操作。
 *
 * 本探针在 dir 下放 filefd 与 sibling，cwd 放另一个同名 victim，
 * 断言 fstatat/fstatat64/readlinkat/utimensat/fchownat/openat 全部
 * 以 ENOTDIR 失败，且 cwd 下的 victim 未被触碰。
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;

static void expect_enotdir(const char *what, int rc, int err, int want)
{
    if (rc != -1 || err != want) {
        fprintf(stderr, "FAIL %s: rc=%d errno=%d(%s) 期望 errno=%d(%s)\n",
                what, rc, err, strerror(err), want, strerror(want));
        failures++;
    } else {
        printf("ok   %s -> %s\n", what, strerror(err));
    }
}

int main(void)
{
    char dir[] = "/tmp/nondirfd-XXXXXX";
    char victim_cwd[] = "/tmp/nondirfd-cwd-XXXXXX";
    char fdpath[4096], sib[4096], cwdvictim[4096], cwdlink[4096];
    struct stat st;
    struct stat64 st64;
    int dfd, ffd;
    int rc;

    if (mkdtemp(dir) == NULL) { perror("mkdtemp dir"); return 2; }
    if (mkdtemp(victim_cwd) == NULL) { perror("mkdtemp cwd"); return 2; }
    snprintf(fdpath, sizeof(fdpath), "%s/notadir", dir);
    snprintf(sib, sizeof(sib), "%s/victim", dir);
    snprintf(cwdvictim, sizeof(cwdvictim), "%s/victim", victim_cwd);
    snprintf(cwdlink, sizeof(cwdlink), "%s/link", victim_cwd);

    /* dirfd 指向一个**普通文件**；兄弟 victim 与 cwd 下的 victim 都在 */
    { int f = open(fdpath, O_CREAT | O_WRONLY | O_TRUNC, 0644);
      if (f < 0) { perror("create notadir"); return 2; }
      if (write(f, "X", 1) != 1) { perror("write"); return 2; }
      close(f); }
    { int f = open(sib, O_CREAT | O_WRONLY | O_TRUNC, 0644);
      if (f < 0) { perror("create sibling victim"); return 2; }
      if (write(f, "SIB", 3) != 3) { perror("write"); return 2; }
      close(f); }
    { int f = open(cwdvictim, O_CREAT | O_WRONLY | O_TRUNC, 0644);
      if (f < 0) { perror("create cwd victim"); return 2; }
      if (write(f, "CWD", 3) != 3) { perror("write"); return 2; }
      close(f); }
    if (symlink(cwdvictim, cwdlink) != 0) { perror("symlink"); return 2; }
    if (chdir(victim_cwd) != 0) { perror("chdir"); return 2; }

    dfd = open(dir, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) { perror("open dir"); return 2; }
    ffd = openat(dfd, "notadir", O_RDONLY);
    if (ffd < 0) { perror("open notadir"); return 2; }

    /* ① fstatat：非目录 fd + "../victim" 必须 ENOTDIR */
    errno = 0;
    rc = fstatat(ffd, "../victim", &st, 0);
    expect_enotdir("fstatat(filefd, \"../victim\")", rc, errno, ENOTDIR);

    /* ② fstatat64：同上（glibc 的 stat64 底层入口） */
    errno = 0;
    rc = fstatat64(ffd, "../victim", &st64, 0);
    expect_enotdir("fstatat64(filefd, \"../victim\")", rc, errno, ENOTDIR);

    /* ③ openat：非目录 fd + "../victim" 必须 ENOTDIR（否则读到了兄弟文件） */
    errno = 0;
    rc = openat(ffd, "../victim", O_RDONLY);
    if (rc >= 0) {
        char got[8] = {0};
        ssize_t n = read(rc, got, sizeof(got) - 1);
        close(rc);
        fprintf(stderr, "FAIL openat(filefd, \"../victim\") 竟然成功，读到 [%s]\n",
                n > 0 ? got : "");
        failures++;
    } else {
        expect_enotdir("openat(filefd, \"../victim\")", rc, errno, ENOTDIR);
    }

    /* ④ readlinkat：非目录 fd + "../link" 必须 ENOTDIR */
    { char buf[512];
      errno = 0;
      rc = (int)readlinkat(ffd, "../link", buf, sizeof(buf));
      expect_enotdir("readlinkat(filefd, \"../link\")", rc, errno, ENOTDIR); }

    /* ⑤ utimensat：非目录 fd + "../victim" 必须 ENOTDIR，且不得改 mtime */
    { struct stat before, after;
      if (stat(sib, &before) != 0) { perror("stat sibling"); return 2; }
      errno = 0;
      rc = utimensat(ffd, "../victim", NULL, 0);
      expect_enotdir("utimensat(filefd, \"../victim\")", rc, errno, ENOTDIR);
      if (stat(sib, &after) != 0) { perror("restat sibling"); return 2; }
      if (before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
          before.st_mtim.tv_nsec != after.st_mtim.tv_nsec) {
          fprintf(stderr, "FAIL 兄弟文件 mtime 被改动（utimensat 逃到了 cwd）\n");
          failures++;
      } }

    /* ⑥ fchownat：非目录 fd + "../victim" 必须 ENOTDIR */
    { struct stat before, after;
      if (stat(sib, &before) != 0) { perror("stat sibling"); return 2; }
      errno = 0;
      rc = fchownat(ffd, "../victim", (uid_t)-1, (gid_t)-1, 0);
      expect_enotdir("fchownat(filefd, \"../victim\")", rc, errno, ENOTDIR);
      if (stat(sib, &after) != 0) { perror("restat sibling"); return 2; }
      if (before.st_uid != after.st_uid || before.st_gid != after.st_gid) {
          fprintf(stderr, "FAIL 兄弟文件属主被改动\n");
          failures++;
      } }

    /* ⑦ 无效 fd：必须 EBADF，不是 cwd 相对解析 */
    errno = 0;
    rc = fstatat(-12345, "victim", &st, 0);
    expect_enotdir("fstatat(badfd, \"victim\")", rc, errno, EBADF);

    /* ⑧ 正向对照：正常目录 fd 仍然按 dirfd 解析（语义没改坏） */
    { struct stat a, b;
      if (stat(sib, &a) != 0) { perror("stat sibling"); return 2; }
      if (fstatat(dfd, "victim", &b, 0) != 0) {
          fprintf(stderr, "FAIL 目录 fd 相对解析失败: %s\n", strerror(errno));
          failures++;
      } else if (a.st_ino != b.st_ino) {
          fprintf(stderr, "FAIL 目录 fd 相对解析命中了别的文件（ino %llu != %llu）\n",
                  (unsigned long long)a.st_ino, (unsigned long long)b.st_ino);
          failures++;
      } else {
          printf("ok   fstatat(dirfd, \"victim\") 按 dirfd 解析\n");
      } }

    /* ⑨ cwd 下的 victim 从未被这些调用碰到 */
    { char got[8] = {0};
      int f = open(cwdvictim, O_RDONLY);
      if (f < 0) { perror("open cwd victim"); return 2; }
      if (read(f, got, sizeof(got) - 1) <= 0) { /* 内容检查即可 */ }
      close(f);
      if (strcmp(got, "CWD") != 0) {
          fprintf(stderr, "FAIL cwd 下的 victim 被改写为 [%s]\n", got);
          failures++;
      } else {
          printf("ok   cwd 下的同名文件未被触碰\n");
      } }

    close(ffd);
    close(dfd);
    if (chdir("/") != 0) { /* ignore */ }
    { char cmd[512];
      snprintf(cmd, sizeof(cmd), "rm -rf '%s' '%s'", dir, victim_cwd);
      if (system(cmd) != 0) { /* 清理失败无害 */ } }

    if (failures == 0) {
        puts("NONDIRFD_SEMANTICS_OK");
        return 0;
    }
    fprintf(stderr, "NONDIRFD failures=%d\n", failures);
    return 1;
}
