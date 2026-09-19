/*
 * probe_raw_syscall.c —— BXROOT_RAW_SYSCALL 透传开关的源码级单元测试
 *
 * 为什么源码级：被测对象是 syscall_guard.c 里的 static 决策函数
 * should_block() / raw_passthrough_enabled()（不导出，避免扩符号面），
 * 而本容器 LD_PRELOAD 惰性（外层 proroot loader 劫持 execve），hook
 * 无法运行时生效。include 源码是唯一能在「无 interpose」环境下钉住
 * 「开关置位 → 放行 / 未置位 → 中和」这对契约的方式。
 *
 * 为什么直接测决策函数、不发真实 svc：契约只钉「守卫层替不替内核做
 * 决定」（should_block 的布尔结果：1 = 中和/ENOSYS，0 = 放行）。
 * io_uring 在本机内核上真实可用与否与本契约无关。
 *
 * 为什么不用 setenv/unsetenv 驱动开关：preload.c 钩住了这两个符号
 * （preload.c:6197/6222），钩子经 bxroot_next_symbol 解析真实 libc
 * 符号 —— 静态探针环境下解析失败返回 -1，环境根本不会被改（实测
 * 踩过）。因此本探针直接改写 environ 数组：raw_passthrough_enabled()
 * 扫描的就是 environ，语义与「exec 前真实注入」逐位等价。
 *
 * 验证边界（诚实声明）：syscall() 入口的 va_arg 展开、raw_syscall6
 * 的真实 svc、以及 statx 结果补丁不在本测试范围，由 RUN_ID_SYSCALL /
 * 真机回归兜底；本测试钉的是 3.6/8.3 修复的决策层。
 *
 * 用法：sh test/RUN_RAW_SYSCALL.sh
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

/* preload.c 自带 __dso_handle（供 D4/proc.c 桥接），静态编译时会与
 * crtbeginS 的冲突 —— 与 RUN_D3_FIXUP.sh 同一处理。 */
#define __dso_handle bxroot_internal_dso_handle

/* 先 include preload.c（构造链在 BXROOT_NO_AUTORUN=1 下整体跳过），
 * 再 include syscall_guard.c：两个单元的 static 名字经核实无交集，
 * preload.c 也不定义 syscall()，可以安全合并为一个编译单元。 */
#include "../src/runtime/preload.c"
#include "../src/runtime/syscall_guard.c"

/* ------------------------------------------------------------------ */
/* 环境 drv：绕过 preload.c 的 setenv/unsetenv 钩子（见文件头说明）      */
/* ------------------------------------------------------------------ */

/* 自建环境数组：静态存储期，environ 可整体替换指向它 */
static char *env_slots[128];
/* 新建条目的保管处（避免被 gcc 判为“分配后即丢失”） */
static char *env_owned[16];
static int env_owned_n;

/* value == NULL 表示删除该变量；否则设为 "name=value"。
 * 同名替换、完整名匹配（"FOO" 不动 "FOOX"），语义与 setenv/unsetenv 一致。 */
static void env_apply(const char *name, const char *value)
{
    extern char **environ;
    char **src = environ;
    char **dst = env_slots;
    size_t nl = strlen(name);
    int i;

    for (i = 0; src[i] != NULL; i++) {
        if (strncmp(src[i], name, nl) == 0 && src[i][nl] == '=')
            continue;                       /* 丢弃同名旧项 */
        if (dst >= env_slots + 126) {
            fprintf(stderr, "env_apply: 环境数组溢出\n");
            exit(2);
        }
        *dst++ = src[i];
    }
    if (value != NULL) {
        char *e;

        if (env_owned_n >= 16) {
            fprintf(stderr, "env_apply: 条目保管区溢出\n");
            exit(2);
        }
        e = malloc(nl + strlen(value) + 2);
        if (e == NULL) {
            fprintf(stderr, "env_apply: malloc 失败\n");
            exit(2);
        }
        sprintf(e, "%s=%s", name, value);
        env_owned[env_owned_n++] = e;
        *dst++ = e;
    }
    *dst = NULL;
    environ = env_slots;
}

static int g_ok = 0, g_fail = 0;

static void check_int(const char *name, long got, long want)
{
    if (got == want) {
        g_ok++;
        printf("  [PASS] %-40s got=%ld\n", name, got);
    } else {
        g_fail++;
        printf("  [FAIL] %-40s got=%ld want=%ld\n", name, got, want);
    }
}

int main(void)
{
    int i;

    /* ================================================================
     * 组 1：未设 BXROOT_RAW_SYSCALL —— 行为与历史版本一致（中和）
     * ================================================================ */
    env_apply("BXROOT_RAW_SYSCALL", NULL);
    g_raw_init = 0;                 /* 重置开关缓存，强制重扫 environ */
    check_int("un set: block io_uring_setup 425", should_block(425), 1);
    check_int("un set: block io_uring_enter 426", should_block(426), 1);
    check_int("un set: block io_uring_register 427", should_block(427), 1);
    check_int("un set: non-list 291 not blocked", should_block(291), 0);
    check_int("un set: non-list 174 not blocked", should_block(174), 0);

    /* ================================================================
     * 组 2：BXROOT_RAW_SYSCALL=0 —— 与未设完全等价
     * ================================================================ */
    env_apply("BXROOT_RAW_SYSCALL", "0");
    g_raw_init = 0;
    check_int("=0: block 425", should_block(425), 1);
    check_int("=0: block 427", should_block(427), 1);

    /* ================================================================
     * 组 3：BXROOT_RAW_SYSCALL=1 —— Android 策略中和全部放行
     * ================================================================ */
    env_apply("BXROOT_RAW_SYSCALL", "1");
    g_raw_init = 0;
    check_int("=1: pass io_uring_setup 425", should_block(425), 0);
    check_int("=1: pass io_uring_enter 426", should_block(426), 0);
    check_int("=1: pass io_uring_register 427", should_block(427), 0);
    /* 开关只作用于中和名单：其余判定照旧为 0（不拦） */
    check_int("=1: non-list 291 not blocked", should_block(291), 0);
    check_int("=1: non-list 174 not blocked", should_block(174), 0);

    /* ================================================================
     * 组 4：environ 扫描必须精确匹配（值/名字变体不得误放行）
     * ================================================================ */
    env_apply("BXROOT_RAW_SYSCALL", "01");      /* 值不是 "1"：不得放行 */
    g_raw_init = 0;
    check_int("value \"01\" still blocks", should_block(425), 1);
    env_apply("BXROOT_RAW_SYSCALL", "true");    /* 其他真值写法同样不放行 */
    g_raw_init = 0;
    check_int("value \"true\" still blocks", should_block(425), 1);
    env_apply("BXROOT_RAW_SYSCALL", NULL);

    env_apply("BXROOT_RAW_SYSCALLX", "1");      /* 超长名字变体 */
    g_raw_init = 0;
    check_int("variant RAW_SYSCALLX still blocks", should_block(425), 1);
    env_apply("BXROOT_RAW_SYSCALLX", NULL);

    /* 精确名 + 更长名同时存在：长名不得遮蔽/干扰精确匹配 */
    env_apply("BXROOT_RAW_SYSCALL", "1");
    env_apply("BXROOT_RAW_SYSCALL_LONG", "1");
    g_raw_init = 0;
    check_int("exact name wins over longer name", should_block(425), 0);
    env_apply("BXROOT_RAW_SYSCALL", NULL);
    env_apply("BXROOT_RAW_SYSCALL_LONG", NULL);

    /* ================================================================
     * 组 5：开关不得波及路径参数表（3.6 修复的边界）
     *          —— 表内任何一个号在任何开关状态下都必须保持不拦
     * ================================================================ */
    env_apply("BXROOT_RAW_SYSCALL", "1");
    g_raw_init = 0;
    for (i = 0; i < 40; i++) {
        char nm[64];
        if (bxroot_test_path_arg_mask(i) == 0)
            continue;
        snprintf(nm, sizeof(nm), "=1: path-table nr=%d not blocked", i);
        check_int(nm, should_block(i), 0);
    }
    env_apply("BXROOT_RAW_SYSCALL", NULL);
    g_raw_init = 0;
    for (i = 0; i < 40; i++) {
        char nm[64];
        if (bxroot_test_path_arg_mask(i) == 0)
            continue;
        snprintf(nm, sizeof(nm), "unset: path-table nr=%d not blocked", i);
        check_int(nm, should_block(i), 0);
    }

    /* ================================================================
     * 组 6：裸 syscall 路径的 SIGSYS 剔除（sigsys_strip_raw）
     *          —— sigsys.c 只挡 4 个 libc 符号，裸 syscall(135) 那条路
     *             原先没有任何剔除（上游 #134 引申，rc=159 的成因之一）
     * ================================================================ */
    {
        sigset_t set;
        unsigned long out, out2;

        /* 6.1 SIG_BLOCK + 集合里有 SIGSYS → 必须剔除 */
        sigemptyset(&set); sigaddset(&set, SIGSYS);
        out = 0xdeadbeefUL;
        check_int("strip: SIG_BLOCK{SIGSYS} 被剔除",
                  sigsys_strip_raw(SIG_BLOCK, &set, (long)sizeof(unsigned long),
                                   &out), 1);
        check_int("strip: 剔除后 SIGSYS 位为 0",
                  (int)((out >> SCG_SIGSYS_BIT_INDEX) & 1UL), 0);

        /* 6.2 SIG_SETMASK 同样剔除 */
        sigemptyset(&set); sigaddset(&set, SIGSYS);
        check_int("strip: SIG_SETMASK{SIGSYS} 被剔除",
                  sigsys_strip_raw(SIG_SETMASK, &set, (long)sizeof(unsigned long),
                                   &out), 1);

        /* 6.3 ★ SIG_UNBLOCK 必须**放行** ★
         *     改写它会破坏客户"解除屏蔽"的请求 —— 这是本判据最易写错的
         *     一条（把 how 判成"包含 SIGSYS 就动"会连解除一起改坏）。 */
        sigemptyset(&set); sigaddset(&set, SIGSYS);
        check_int("strip: SIG_UNBLOCK 不被改写（解除请求必须放行）",
                  sigsys_strip_raw(SIG_UNBLOCK, &set,
                                   (long)sizeof(unsigned long), &out), 0);

        /* 6.4 集合里没有 SIGSYS → 不动 */
        sigemptyset(&set); sigaddset(&set, SIGUSR1);
        out = 0xdeadbeefUL;
        check_int("strip: 无 SIGSYS 不改写",
                  sigsys_strip_raw(SIG_BLOCK, &set, (long)sizeof(unsigned long),
                                   &out), 0);
        check_int("strip: 未改写时 out 不被写",
                  (int)(out == 0xdeadbeefUL), 1);

        /* 6.5 sigsetsize 不是 8 → 不动（那种调用内核自己回 EINVAL） */
        sigemptyset(&set); sigaddset(&set, SIGSYS);
        check_int("strip: sigsetsize=128 不改写（交内核裁决）",
                  sigsys_strip_raw(SIG_BLOCK, &set, (long)sizeof(sigset_t),
                                   &out), 0);
        check_int("strip: sigsetsize=0 不改写",
                  sigsys_strip_raw(SIG_BLOCK, &set, 0, &out), 0);

        /* 6.6 NULL 集合 / NULL 出参 → 安全返回 0（客户可传 NULL） */
        check_int("strip: set=NULL 不改写",
                  sigsys_strip_raw(SIG_BLOCK, NULL, (long)sizeof(unsigned long),
                                   &out), 0);
        check_int("strip: out=NULL 不改写",
                  sigsys_strip_raw(SIG_BLOCK, &set, (long)sizeof(unsigned long),
                                   NULL), 0);

        /* 6.7 ★ 客户的 set 结构体不得被污染 ★
         *     只改本地副本 —— 客户之后读回自己的 set 仍应看到 SIGSYS 位。 */
        sigemptyset(&set); sigaddset(&set, SIGSYS);
        (void)sigsys_strip_raw(SIG_BLOCK, &set, (long)sizeof(unsigned long), &out);
        check_int("strip: 客户原 set 未被污染（仍含 SIGSYS）",
                  sigismember(&set, SIGSYS), 1);

        /* 6.8 ★ 同集合里的**其他信号必须保留** ★（别把整个 word 清掉） */
        sigemptyset(&set); sigaddset(&set, SIGSYS); sigaddset(&set, SIGUSR2);
        out2 = 0;
        (void)sigsys_strip_raw(SIG_SETMASK, &set, (long)sizeof(unsigned long),
                               &out2);
        {
            unsigned long usr2bit = 1UL << (SIGUSR2 - 1);
            check_int("strip: 其他信号(SIGUSR2)位保留",
                      (int)((out2 & usr2bit) != 0), 1);
            check_int("strip: 同集合里 SIGSYS 位已清",
                      (int)((out2 >> SCG_SIGSYS_BIT_INDEX) & 1UL), 0);
        }
    }

    printf("\n=== 结果: %d 通过 / %d 失败 ===\n", g_ok, g_fail);
    return g_fail ? 1 : 0;
}
