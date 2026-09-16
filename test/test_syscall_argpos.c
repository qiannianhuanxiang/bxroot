/*
 * 系统调用参数位置的防回归测试。
 *
 * 由来：本项目的 syscall_guard 里有一张表声明"第几个参数是路径"。
 * 曾把 symlinkat(36) 错列成"a1 是路径"，而实际上：
 *
 *     symlinkat(const char *target, int newdirfd, const char *linkpath)
 *                    ↑ x0               ↑ x1            ↑ x2
 *
 * a1 是 dirfd（一个 int），于是 guard 把 AT_FDCWD(-100) 当指针解引用，
 * **每一次裸 syscall 的 symlinkat 都 SIGSEGV**。而 symlinkat 正是
 * 创建符号链接的入口 —— l2s 层大量依赖它。
 *
 * 本测试用实测方式锁定每个"带 dirfd 的路径型调用"的 a1 语义：
 * 构造一个必然因参数位置不同而给出不同 errno 的调用，据以判定。
 *
 * 这些断言不需要 root、不需要真机，纯逻辑 + 内核返回值。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

static int cases = 0, failed = 0;

static void check(const char *name, int ok, const char *detail)
{
    cases++;
    if (!ok) {
        failed++;
        printf("  [FAIL] %s  %s\n", name, detail);
    } else {
        printf("  [ok]   %s\n", name);
    }
}

int main(void)
{
    printf("=== 系统调用参数位置契约 ===\n");

    /*
     * symlinkat(36)：a1 必须是 dirfd，不是路径。
     *
     * 判据：把 AT_FDCWD 放在 a1、把合法路径放在 a2，调用应当**成功**；
     * 若 a1 被当成路径，内核会返回 ENOENT/ENOTDIR 之类而非成功。
     *
     * 用一个临时目录里的真实路径做这件事。
     */
    {
        char dir[] = "/tmp/bxroot-argpos-XXXXXX";
        if (mkdtemp(dir) == NULL) {
            printf("  [skip] 无法创建临时目录\n");
        } else {
            char tgt[512], lnk[512];
            snprintf(tgt, sizeof tgt, "%s/t", dir);
            snprintf(lnk, sizeof lnk, "%s/l", dir);

            unlink(lnk);
            errno = 0;
            long r = syscall(36 /*symlinkat*/, tgt, AT_FDCWD, lnk);
            int e = errno;

            check("symlinkat: a1 是 dirfd（不是路径）",
                  r == 0,
                  r == 0 ? "" : "内核拒绝了「target, AT_FDCWD, linkpath」——"
                                "说明 a1 的语义与预期不符");

            if (r == 0) {
                char buf[512];
                ssize_t n = readlink(lnk, buf, sizeof buf - 1);
                check("symlinkat: 链接内容正确",
                      n > 0 && (size_t)n == strlen(tgt) &&
                      memcmp(buf, tgt, (size_t)n) == 0,
                      "创建的链接内容与 target 不符");
            }
            (void)e;
            unlink(lnk);
            rmdir(dir);
        }
    }

    /*
     * faccessat(48) / openat(56)：a1 **确实**是路径。
     * 用 AT_FDCWD 做对照即可 —— 若 a1 被当成 dirfd，/etc 会被当作 fd 而失败。
     */
    {
        errno = 0;
        long r = syscall(56 /*openat*/, AT_FDCWD, "/", O_RDONLY | O_DIRECTORY, 0);
        if (r >= 0) {
            close((int)r);
            check("openat: a1 是路径", 1, "");
        } else {
            check("openat: a1 是路径", 0, "openat(AT_FDCWD, \"/\") 失败");
        }
    }
    {
        errno = 0;
        long r = syscall(48 /*faccessat*/, AT_FDCWD, "/", F_OK, 0);
        check("faccessat: a1 是路径", r == 0, "faccessat(AT_FDCWD, \"/\") 失败");
    }

    printf("\n----------------------------------------\n");
    printf("cases:  %d  (%d failed)\n", cases, failed);
    printf("RESULT: %s\n", failed ? "FAIL" : "PASS");
    return failed ? 1 : 0;
}
