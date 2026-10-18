/*
 * 真机探针：验证 ptr_writable_or_default() 的行为（2026-10-18 修复 #4/#5）
 *
 * 背景：修复前 getresuid/getresgid/getgroups 直接解引用客户指针、只判 NULL，
 *       客户传不可写地址会让本进程 SIGSEGV（内核本应返回 EFAULT）。
 *       修复引入 ptr_writable_or_default() 做可写性探测。
 *
 * 本探针直接 #include syscall_guard.c 以访问该 static 函数，在真机上跑。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/mman.h>   /* 本探针自用；syscall_guard.c 刻意不含它 */

/*
 * syscall_guard.c 里 bxroot_translate_path 是 weak 声明；在**可执行文件**
 * 里链接器仍要求它被解析，所以给一个桩（本探针不测翻译，只测可写性判定）。
 */
int bxroot_translate_path(const char *path, char *out, size_t out_size)
{
    (void)path; (void)out; (void)out_size;
    return 0;   /* 0 = 未翻译，与 runtime 未加载时的语义一致 */
}

/* 把被测实现整体包含进来（含 static 辅助函数） */
#include "syscall_guard.c"

static int fails;
static int checks;

static void ck(const char *what, int got, int want)
{
    checks++;
    if (got != want) {
        fails++;
        printf("  [FAIL] %-46s got=%d want=%d\n", what, got, want);
    } else {
        printf("  [ok]   %-46s = %d\n", what, got);
    }
}

int main(void)
{
    unsigned int stackvar = 0;
    static const char rostr[] = "read-only?";
    void *heap = NULL;

    printf("=== ptr_writable_or_default 真机探针 ===\n");
    printf("pid=%d\n\n", (int)getpid());

    /* 1) NULL 必须判不可写 */
    ck("NULL -> 不可写", ptr_writable_or_default(NULL, 4), 0);

    /* 2) 栈变量：.bss/.stack 可写 */
    ck("栈变量 -> 可写", ptr_writable_or_default(&stackvar, sizeof stackvar), 1);

    /* 3) 字符串字面量：.rodata 只读 */
    ck("字符串字面量(.rodata) -> 不可写",
       ptr_writable_or_default(rostr, 4), 0);

    /* 4) 明显未映射的低地址 */
    ck("地址 0x1 -> 不可写",
       ptr_writable_or_default((const void *)(uintptr_t)1, 4), 0);
    ck("地址 0x1000 -> 不可写",
       ptr_writable_or_default((const void *)(uintptr_t)0x1000, 4), 0);

    /* 5) 堆：可写 */
    heap = malloc(64);
    if (heap != NULL) {
        ck("malloc 堆块 -> 可写", ptr_writable_or_default(heap, 32), 1);
        free(heap);
    }

    /* 6) len=0 应等价于 len=1（内部处理），NULL 仍不可写 */
    ck("len=0 + NULL -> 不可写", ptr_writable_or_default(NULL, 0), 0);

    /* 7) 溢出：addr + len - 1 回绕 */
    ck("addr=UINTPTR_MAX-2, len=8 -> 不可写",
       ptr_writable_or_default((const void *)(uintptr_t)(UINTPTR_MAX - 2), 8), 0);

    /* 8) 只读映射（mmap PROT_READ）不可写 */
    {
        void *m = mmap(NULL, 4096, PROT_READ,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (m != MAP_FAILED) {
            ck("mmap(PROT_READ) -> 不可写",
               ptr_writable_or_default(m, 4), 0);
            munmap(m, 4096);
        }
    }

    /* 9) 可写映射（mmap PROT_READ|WRITE）可写 */
    {
        void *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (m != MAP_FAILED) {
            ck("mmap(PROT_READ|WRITE) -> 可写",
               ptr_writable_or_default(m, 4), 1);
            munmap(m, 4096);
        }
    }

    /*
     * 10) 代码段不可写：指向本函数自身地址（r-xp）
     *     注意：部分环境允许通过 /proc/self/mem 写 r-xp，本函数是按
     *     maps 的 'w' 位判定的，所以这里期望"不可写"。
     */
    ck("代码段(r-xp) -> 不可写",
       ptr_writable_or_default((const void *)(uintptr_t)&main, 4), 0);

    printf("\n----------------------------------------\n");
    printf("checks: %d  failed: %d\n", checks, fails);
    printf("RESULT: %s\n", fails == 0 ? "PASS" : "FAIL");
    return fails == 0 ? 0 : 1;
}
