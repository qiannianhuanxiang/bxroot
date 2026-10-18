/*
 * 真机探针：验证 syscall() 在 fakeroot 模式下对**不可写客户指针**的处理
 *          （2026-10-18 修复 #4 / #5）
 *
 * 修复前：
 *   getresuid/getresgid/getgroups 直接 `*(volatile unsigned int*)a0 = ...`，
 *   只判 NULL。客户传不可写地址会让**本进程 SIGSEGV**，
 *   而内核语义本应是返回 -EFAULT。
 *
 * 修复后：写之前用 ptr_writable_or_default() 探测；不可写则返回 -EFAULT。
 *
 * 做法：提供 bxroot_fakeroot_* 的桩（让仿真路径生效），再用各种坏指针
 *       调用 syscall()，检查返回 EFAULT 而不是崩溃。
 *
 * 注意：本探针若在修复前的代码上运行，应当 SIGSEGV —— 这正是它的判别力。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

/* ---- fakeroot 桩：让 fakeroot 仿真路径生效 ---- */
int bxroot_fakeroot_res_ids(unsigned int *ruid, unsigned int *euid,
                            unsigned int *suid, unsigned int *rgid,
                            unsigned int *egid, unsigned int *sgid)
{
    /* 假装 fakeroot 开着，身份全是 0 */
    if (ruid) *ruid = 0;
    if (euid) *euid = 0;
    if (suid) *suid = 0;
    if (rgid) *rgid = 0;
    if (egid) *egid = 0;
    if (sgid) *sgid = 0;
    return 1;
}

int bxroot_fakeroot_groups(unsigned int *groups, int cap, int *count)
{
    if (count) *count = 1;
    if (groups != NULL && cap >= 1)
        groups[0] = 0;
    return 1;
}

/* 翻译桩（weak，可执行文件里必须解析） */
int bxroot_translate_path(const char *path, char *out, size_t out_size)
{
    (void)path; (void)out; (void)out_size;
    return 0;
}

#include "syscall_guard.c"

static int fails, checks;

static void ck_ret(const char *what, long got, long want)
{
    checks++;
    if (got != want) {
        fails++;
        printf("  [FAIL] %-52s got=%ld want=%ld (errno=%d)\n",
               what, got, want, errno);
    } else {
        printf("  [ok]   %-52s = %ld\n", what, got);
    }
}

int main(void)
{
    unsigned int ok[3] = {0, 0, 0};
    long r;

    printf("=== fakeroot 客户指针安全性 真机探针 ===\n");
    printf("pid=%d, SYS_getresuid=%d SYS_getgroups=%d\n\n",
           (int)getpid(), (int)SYS_getresuid, (int)SYS_getgroups);

    /*
     * 1) 正常指针：应成功返回 0 且填好值
     */
    errno = 0;
    r = syscall(SYS_getresuid, &ok[0], &ok[1], &ok[2]);
    ck_ret("getresuid(正常栈指针) -> 0", r, 0);
    printf("        填回 uid=%u euid=%u suid=%u\n", ok[0], ok[1], ok[2]);

    /*
     * 2) 不可写指针：**修复前会 SIGSEGV**，修复后应返回 -1 / EFAULT
     */
    errno = 0;
    r = syscall(SYS_getresuid, (void *)(uintptr_t)1, NULL, NULL);
    ck_ret("getresuid(地址 0x1) -> -1", r, -1);
    checks++;
    if (errno != EFAULT) {
        fails++;
        printf("  [FAIL] %-52s errno=%d want=EFAULT(%d)\n",
               "  且 errno 应为 EFAULT", errno, EFAULT);
    } else {
        printf("  [ok]   %-52s errno=EFAULT\n", "  且 errno 为 EFAULT");
    }

    /*
     * 3) 只读映射指针
     */
    {
        void *m = mmap(NULL, 4096, PROT_READ,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (m != MAP_FAILED) {
            errno = 0;
            r = syscall(SYS_getresuid, m, NULL, NULL);
            ck_ret("getresuid(只读映射) -> -1", r, -1);
            munmap(m, 4096);
        }
    }

    /*
     * 4) 部分 NULL 仍应成功（合法调用）
     */
    errno = 0;
    r = syscall(SYS_getresuid, &ok[0], NULL, NULL);
    ck_ret("getresuid(部分 NULL) -> 0", r, 0);

    /*
     * 5) getgroups：正常容量
     */
    {
        unsigned int g[8];
        memset(g, 0xAA, sizeof g);   /* 先污染，验证真的被填 */
        errno = 0;
        r = syscall(SYS_getgroups, 8, g);
        ck_ret("getgroups(cap=8) -> 1", r, 1);
        printf("        g[0]=%u (应为 0，且不再是 0xAAAAAAAA)\n", g[0]);
        checks++;
        if (g[0] == 0xAAAAAAAAu) {
            fails++;
            printf("  [FAIL] 缓冲未被填充（修复 #5 前的症状）\n");
        }
    }

    /*
     * 6) getgroups：不可写缓冲，应 EFAULT 而不是崩溃
     */
    errno = 0;
    r = syscall(SYS_getgroups, 8, (void *)(uintptr_t)1);
    ck_ret("getgroups(地址 0x1) -> -1", r, -1);

    printf("\n----------------------------------------\n");
    printf("checks: %d  failed: %d\n", checks, fails);
    printf("RESULT: %s\n", fails == 0 ? "PASS" : "FAIL");
    return fails == 0 ? 0 : 1;
}
