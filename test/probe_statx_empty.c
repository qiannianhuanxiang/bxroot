/* ---------------------------------------------------------------------
 * probe_statx_empty —— statx AT_EMPTY_PATH 空路径回归探针
 *
 * 防的缺陷（自主发现，2026-09-28）：
 *   statx(fd, "", AT_EMPTY_PATH, …) 语义是「对 fd 自身取属性」，path 是
 *   空串。preload.c 的 statx 钩子对空串误判为「相对路径」→
 *   bxroot_absolutize("") 产出 "cwd/"，把对 fd 的 stat 误导到 CWD。
 *
 * 判据：对同一个已打开文件，
 *   ① statx(fd, "", AT_EMPTY_PATH)      —— 走缺陷路径
 *   ② fstat(fd)                          —— 基准真值（不经路径翻译）
 * 二者的 st_ino / st_size 必须一致。若 statx 被误导到 CWD（目录），
 * ino 不同、size 也不同（目录 vs 文件），探针报 MISMATCH。
 *
 * 用绝对不可能巧合相等的方式判别：文件内容写成固定长度，CWD 是目录。
 *
 * 退出：stdout 打 "DONE ok=1" 表示通过，"DONE ok=0" 表示缺陷复现。
 * --------------------------------------------------------------------- */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    const char *path = (argc > 1) ? argv[1] : "/tmp/bxroot-statx-empty-canary";
    int ok = 1;

    /* 建一个内容确定的文件（长度 = 13） */
    int wfd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (wfd < 0) { printf("SETUP-FAIL open-w %s\n", path); printf("DONE ok=0\n"); return 1; }
    if (write(wfd, "STATX_CANARY\n", 13) != 13) { printf("SETUP-FAIL write\n"); printf("DONE ok=0\n"); close(wfd); return 1; }
    close(wfd);

    int fd = open(path, O_RDONLY);
    if (fd < 0) { printf("SETUP-FAIL open-r\n"); printf("DONE ok=0\n"); return 1; }

    /* 基准：fstat(fd) —— 不经路径翻译，恒真 */
    struct stat fst;
    if (fstat(fd, &fst) != 0) { printf("SETUP-FAIL fstat\n"); printf("DONE ok=0\n"); close(fd); return 1; }

    /* 被测：statx(fd, "", AT_EMPTY_PATH) */
    struct statx stx;
    memset(&stx, 0, sizeof(stx));
    int rc = statx(fd, "", AT_EMPTY_PATH, STATX_INO | STATX_SIZE, &stx);
    if (rc != 0) {
        printf("STATX-FAIL rc=%d (statx AT_EMPTY_PATH 应成功)\n", rc);
        ok = 0;
    } else {
        if ((unsigned long long)stx.stx_ino != (unsigned long long)fst.st_ino) {
            printf("MISMATCH ino statx=%llu fstat=%llu (空路径被误导)\n",
                   (unsigned long long)stx.stx_ino, (unsigned long long)fst.st_ino);
            ok = 0;
        }
        if ((unsigned long long)stx.stx_size != (unsigned long long)fst.st_size) {
            printf("MISMATCH size statx=%llu fstat=%llu\n",
                   (unsigned long long)stx.stx_size, (unsigned long long)fst.st_size);
            ok = 0;
        }
    }

    close(fd);
    unlink(path);
    printf("DONE ok=%d\n", ok);
    return ok ? 0 : 1;
}
