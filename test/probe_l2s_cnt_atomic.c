/*
 * 真机探针：l2s `.cnt` 引用计数的跨进程原子性（2026-10-18 修复）
 *
 * --- 缺陷 ---
 * 引用计数的语义是"读 `.cnt` → ±1 → 写回"，而 l2s 的 ops 只提供
 * 独立的 read_small / write_small 两个回调，锁跨不过这两步：
 *
 *     P1 读 2 → P2 读 2 → P1 写 3 → P2 写 3      实际引用 4，计数 3
 *
 * 之后 `rm` 掉足够多个名字，l2s 会认为"没人引用了"而回收 final ——
 * **仍被引用的数据被删掉**。进程内自旋锁只能挡同进程的线程。
 *
 * --- 修复 ---
 * ops 增加可选的 update_small(path, delta, &new_value)：把"读-改-写"
 * 整体交给注入方，注入方用 **OFD 字节锁**（F_OFD_SETLKW）在 `.cnt`
 * 自身上互斥。l2s-runtime 的 cnt_add() 优先用它，为 NULL 时回退到
 * 进程内锁 + 读 + 写（修前行为）。
 *
 * --- 本探针 ---
 * 用**真实文件系统**的 ops，起 N 个子进程，每个各自对同一个 `.cnt`
 * 做 M 次 +1，然后比较最终值与期望值：
 *
 *   组 1（回退路径：update_small = NULL）—— 期望**丢更新**（值 < N*M）
 *   组 2（原子路径：update_small 用 OFD 锁）—— 期望**恰好** N*M
 *
 * 组 1 是反向对照：它证明这个探针确实能测出竞争，而不是"不管怎么改
 * 都通过"。若组 1 也恰好正确（竞争窗口没撞上），探针会把结论标成
 * SKIP 而不是 PASS —— 不能用一个没触发竞争的实验去证明修复有效。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "l2s-runtime.h"

static int fails, checks;

static void ck(const char *what, int cond)
{
    checks++;
    if (!cond) {
        fails++;
        printf("  [FAIL] %s\n", what);
    } else {
        printf("  [ok]   %s\n", what);
    }
}

/* ---------------- 真实文件系统的 ops ---------------- */

static int fs_lstat(const char *p, struct stat *st) { return lstat(p, st); }
static int fs_symlink(const char *t, const char *l) { return symlink(t, l); }
static int fs_rename(const char *o, const char *n) { return rename(o, n); }
static int fs_unlink(const char *p) { return unlink(p); }
static ssize_t fs_readlink(const char *p, char *b, size_t s) { return readlink(p, b, s); }
static int fs_access(const char *p, int m) { return access(p, m); }

static int fs_read_small(const char *p, char *buf, size_t bufsz, size_t *out_len)
{
    int fd = open(p, O_RDONLY);
    ssize_t n;
    if (fd < 0)
        return -errno;
    n = read(fd, buf, bufsz - 1);
    close(fd);
    if (n < 0)
        return -errno;
    buf[n] = '\0';
    *out_len = (size_t)n;
    return 0;
}

static int fs_write_small(const char *p, const char *buf, size_t len)
{
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    ssize_t n;
    if (fd < 0)
        return -errno;
    n = write(fd, buf, len);
    close(fd);
    return n == (ssize_t)len ? 0 : -EIO;
}

/*
 * 原子版本：与 src/runtime/preload.c 的 l2s_real_update_small 同构
 * （OFD 锁 + 锁内读-改-写）。这里独立实现一份，是为了让探针只依赖
 * 公开的 ops 接口，而不是去 #include 14k 行的 preload.c。
 */
static int fs_update_small(const char *p, int delta, unsigned int *out_value)
{
    struct flock fl;
    char buf[32];
    int fd, rc = 0;
    ssize_t n;
    unsigned long v = 0;
    int i, digits = 0;

    fd = open(p, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0)
        return -errno;

    memset(&fl, 0, sizeof fl);
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    fl.l_pid = 0;
    if (fcntl(fd, F_OFD_SETLKW, &fl) != 0) {
        rc = -errno;
        close(fd);
        return rc;
    }

    n = read(fd, buf, sizeof buf);
    if (n < 0) {
        rc = -errno;
        goto done;
    }
    for (i = 0; i < (int)n; i++) {
        if (buf[i] >= '0' && buf[i] <= '9') {
            v = v * 10ul + (unsigned long)(buf[i] - '0');
            digits = 1;
        } else if (buf[i] == '\n' || buf[i] == ' ') {
            continue;
        } else {
            rc = -EIO;
            goto done;
        }
    }
    if (!digits)
        v = 0;

    {
        long nv = (long)v + (long)delta;
        if (nv < 0) {
            rc = -ERANGE;
            goto done;
        }
        v = (unsigned long)nv;
    }

    /*
     * ★ 必须先把偏移复位 ★
     *
     * read() 之后文件偏移停在 EOF；ftruncate 只改长度、**不改偏移**，
     * 于是紧接着的 write 会从旧偏移处写，前面留一串 NUL 空洞 ——
     * 下次读到的就是 "\0\0" 这种垃圾。（第一版就是这么错的，
     * 探针自己先崩在 -EIO 上。）
     */
    if (lseek(fd, 0, SEEK_SET) != 0) {
        rc = -errno;
        goto done;
    }
    if (ftruncate(fd, 0) != 0) {
        rc = -errno;
        goto done;
    }
    {
        char ob[16];
        int len = snprintf(ob, sizeof ob, "%lu", v);
        n = write(fd, ob, (size_t)len);
        if (n != (ssize_t)len) {
            rc = -EIO;
        }
    }

done:
    fl.l_type = F_UNLCK;
    (void)fcntl(fd, F_OFD_SETLK, &fl);
    close(fd);
    if (rc == 0)
        *out_value = (unsigned int)v;
    return rc;
}

/*
 * 起 nproc 个子进程，每个对 .cnt 做 rounds 次 +1。
 * 用统一的 barrier（一个管道）让它们尽量同时开跑，制造真实竞争。
 */
static int hammer(const char *cnt_path, int nproc, int rounds, int use_atomic)
{
    pid_t pids[64];
    int i, k, ready[2], go[2];
    int ok = 1, bad = 0;

    if (pipe(ready) != 0 || pipe(go) != 0)
        return -1;

    for (i = 0; i < nproc; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            ok = 0;
            break;
        }
        if (pid == 0) {
            char b;
            close(ready[0]); close(go[1]);
            if (write(ready[1], "x", 1) != 1)
                _exit(31);
            /* 等父进程发令：尽量让所有子进程在同一瞬间开跑 */
            if (read(go[0], &b, 1) != 1)
                _exit(32);
            for (k = 0; k < rounds; k++) {
                if (use_atomic) {
                    unsigned int nv = 0;
                    {
                        int erc = fs_update_small(cnt_path, +1, &nv);
                        if (erc != 0) {
                            fprintf(stderr, "  [child] update_small rc=%d (%s)\n",
                                    erc, strerror(-erc));
                            _exit(4);
                        }
                    }
                } else {
                    /* 回退路径的原样复现：读 → 加一 → 写（三步，无锁） */
                    char buf[32];
                    size_t len = 0;
                    unsigned long v = 0;
                    int j;
                    if (fs_read_small(cnt_path, buf, sizeof buf, &len) != 0)
                        v = 0;
                    else
                        for (j = 0; j < (int)len; j++)
                            if (buf[j] >= '0' && buf[j] <= '9')
                                v = v * 10ul + (unsigned long)(buf[j] - '0');
                    v++;
                    snprintf(buf, sizeof buf, "%lu", v);
                    if (fs_write_small(cnt_path, buf, strlen(buf)) != 0)
                        _exit(4);
                }
            }
            _exit(0);
        }
        pids[i] = pid;
    }

    close(ready[1]); close(go[0]);
    {
        char b;
        for (k = 0; k < i; k++)
            if (read(ready[0], &b, 1) != 1)
                break;
        for (k = 0; k < i; k++)
            if (write(go[1], "x", 1) != 1)
                break;
    }
    close(ready[0]); close(go[1]);

    for (k = 0; k < i; k++) {
        int st = 0;
        if (waitpid(pids[k], &st, 0) < 0 ||
            !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
            ok = 0;
            bad++;
        }
    }
    if (bad)
        printf("    （%d 个子进程非正常退出）\n", bad);
    return ok ? 0 : -1;
}

static unsigned long read_cnt(const char *p)
{
    char buf[32];
    size_t len = 0;
    unsigned long v = 0;
    int j;

    if (fs_read_small(p, buf, sizeof buf, &len) != 0)
        return 0;
    for (j = 0; j < (int)len; j++)
        if (buf[j] >= '0' && buf[j] <= '9')
            v = v * 10ul + (unsigned long)(buf[j] - '0');
    return v;
}

#define NPROC  16
#define ROUNDS 40

int main(void)
{
    char dir[] = "/tmp/l2s-cnt-race-XXXXXX";
    char cnt[512];
    unsigned long want = (unsigned long)NPROC * ROUNDS;
    unsigned long got_fb, got_at;

    printf("=== l2s .cnt 跨进程原子性 探针 ===\n");
    printf("并发: %d 进程 × %d 次 +1，期望 %lu\n\n", NPROC, ROUNDS, want);

    if (mkdtemp(dir) == NULL) {
        printf("  [SKIP] mkdtemp 失败: %s\n", strerror(errno));
        return 0;
    }
    snprintf(cnt, sizeof cnt, "%s/.l2s.probe.0002.cnt", dir);

    /* ---------------- 组 1：回退路径（反向对照） ---------------- */
    printf("--- 1) 无 update_small（修前行为）---\n");
    unlink(cnt);
    (void)fs_write_small(cnt, "1", 1);
    if (hammer(cnt, NPROC, ROUNDS, 0) != 0) {
        printf("  [SKIP] 子进程执行失败\n");
        return 0;
    }
    got_fb = read_cnt(cnt);
    printf("  最终计数 = %lu（期望 %lu，起点 1）\n", got_fb, 1 + want);
    if (got_fb == 1 + want) {
        printf("  [SKIP] 本次没有撞上竞争 —— 这个实验无法证明修复有效\n");
        printf("RESULT: SKIP\n");
        return 0;
    }
    printf("  [ok]   确实丢更新（少 %lu 次）—— 证明探针能测出竞争\n",
           1 + want - got_fb);

    /* ---------------- 组 2：原子路径 ---------------- */
    printf("\n--- 2) 有 update_small（OFD 锁）---\n");
    unlink(cnt);
    (void)fs_write_small(cnt, "1", 1);
    if (hammer(cnt, NPROC, ROUNDS, 1) != 0) {
        printf("  [FAIL] 子进程执行失败\n");
        return 1;
    }
    got_at = read_cnt(cnt);
    printf("  最终计数 = %lu（期望 %lu，起点 1）\n", got_at, 1 + want);
    ck("原子路径没有丢更新", got_at == 1 + want);

    /* 清理 */
    {
        char cmd[600];
        snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
        if (system(cmd) != 0) { /* 忽略 */ }
    }

    printf("\n----------------------------------------\n");
    printf("checks: %d  failed: %d\n", checks, fails);
    printf("RESULT: %s\n", fails == 0 ? "PASS" : "FAIL");
    return fails == 0 ? 0 : 1;
}
