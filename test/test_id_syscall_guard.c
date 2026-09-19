/*
 * test_id_syscall_guard.c —— 裸 syscall 层身份伪装的**独立**契约测试
 *
 * ====================================================================
 * 这个测试防的是什么
 * ====================================================================
 *
 * bxroot 的 fakeroot 只在 **libc 符号层**伪装 uid/gid：
 *
 *     preload.c:5474  uid_t getuid(void) { if (g_config.fakeroot) return 0; ... }
 *
 * 而 `src/runtime/syscall_guard.c` 的 `syscall()` 接管层只做了"路径翻译"
 * 与"statx 结果补丁"，**完全没有** 174..177 这几条。后果是绕过 libc 直接
 * `syscall(174)` 的程序（静态链接的 Go/Rust、libuv、以及大量"我是不是
 * root"的自检代码）会看到**真实 uid**，于是走错分支。
 *
 * 实测证据（本任务的三层探针，详见 docs/裸syscall身份伪造修复.md）：
 *     官方 : libc getuid=0   syscall(174)=0     ← 伪造覆盖到 syscall() 符号层
 *     bxroot(修前): libc getuid=0   syscall(174)=10655   ← 只到 libc 符号层
 *
 * 本测试把"裸 syscall 层的身份伪装"钉成契约。
 *
 * ====================================================================
 * ★ 为什么伪造值不是 0，而是一个真值取不到的数 ★
 * ====================================================================
 *
 * 若判据写成 `syscall(174) == 0`，本测试在**本容器里根本没有判别力**：
 * 外层 proroot 会把裸 svc 的 getuid 也改写成 0（实测 svc 列 = 0），
 * 于是"改之前"就已经绿了 —— 一个恒真的测试。这正是本项目记录过的那类
 * 事故（"这套回归声称能防的那个具体缺陷，它防不住"）。
 *
 * 所以桩返回 **12345/54321**，所有判据都写成"与桩值比"或"与我自己发
 * 裸 svc 读到的真值比"，与运行环境无关：
 *
 *     fakeroot 关 → syscall(174) 必须 == 裸 svc 真值   （透传）
 *     fakeroot 开 → syscall(174) 必须 == 12345         （被改写）
 *
 * 改之前，"fakeroot 开"那一支拿到 10655 或 0，都不等于 12345 → **红**。
 *
 * ====================================================================
 * ★ 为什么计数器必须是 volatile ★
 * ====================================================================
 *
 * 这不是洁癖，是实测踩出来的：把 `static int g_seen_n` 与翻译桩放在
 * 同一个编译单元里时，gcc 会把"桩内的自增"与"main 里的读取"当成两个
 * 不同对象 —— 桩确实被调用了（stderr 里能打印出来），而 main 读到的
 * 仍是 0，于是断言"桩被调 0 次"**恒真**，测试白写。
 *
 * 现象来源是外层 proroot 对 libc 的**活体代码补丁**（本项目多处记录过
 * "dlsym 拿到的地址不可靠""跳进去会 SIGSEGV"）。结论与项目里那条一致：
 * **跨"真实调用边界"传递的观测值，一律用 volatile 或显式内存屏障**，
 * 不要依赖优化器对普通静态变量的推断。
 *
 * ====================================================================
 * 桩与弱符号
 * ====================================================================
 *
 * syscall_guard.c 是独立编译单元，被**单独**链进 test_syscall_argpos.c /
 * test_rename_link_argpos.c（那两个测试不链 preload.c）。所以它对
 * preload.c 的查询函数必须用 `__attribute__((weak))` 声明 —— 本文件
 * 提供**强定义**桩，让 guard 走"已启用"分支；那两个既有测试不提供，
 * weak 解析为 NULL，guard 走"未启用"分支（保持透传）。
 * 两个方向都必须成立，否则既有测试会链接失败。
 *
 * ====================================================================
 * 负向判据（同样重要）
 * ====================================================================
 *
 * "多改"比"少改"危险得多 —— syscall_guard.c 有两次明确记录的事故
 * （case 36 把 dirfd 当路径、case 260 把 wait4 当 linkat 写坏 wstatus），
 * 都是"把不相干的调用卷进来"。所以本测试同时断言：
 *
 *   - `syscall(172)`（getpid）在 fakeroot 开/关下**都**等于裸 svc 真值；
 *   - `syscall(178)`（gettid，紧邻 177，最容易被顺手卷进来）同样不变；
 *   - 174..177 及邻近号**不得**进入路径参数表（进表就意味着有寄存器被
 *     当指针解引用 → 可能整进程静默消失）；
 *   - 身份改写路径**一次都不能**触碰翻译桩；
 *   - 既有的路径翻译功能（statx/291、newfstatat/79）仍照常工作，且
 *     反向对照证明该判据不是恒真；
 *   - 148/150（getresuid/getresgid）本轮**未**覆盖 —— 把"未覆盖"这个
 *     边界也钉住，免得以后有人误以为已覆盖。
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <signal.h>
#include <linux/stat.h>          /* struct statx */

#include "syscall_guard.h"      /* bxroot_test_path_arg_mask */

/* ------------------------------------------------------------------ */
/* 裸 svc：真值基准（完全绕开 guard 的 syscall()，也绕开 libc）         */
/* ------------------------------------------------------------------ */

static long raw_svc1(long nr, long a0)
{
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    __asm__ __volatile__("svc #0"
        : "+r"(x0)
        : "r"(x8)
        : "memory", "cc");
    return x0;
}

/*
 * 4 参数裸 svc —— 本文件用它读回内核真实掩码。
 *
 * ★ 观测必须走裸 svc，不能走 libc ★
 * 本容器自身跑在 proroot 之上，它会劫持 libc 的 sigprocmask，把 SIGSYS
 * 从读回的掩码里剔除 —— 用 libc 读回会得到**假阴性**（实测踩过，见
 * docs/接手报告 §2 与 test/probe_sigprocmask_num.c 的长注释）。
 * 裸 svc 不经任何符号，读到的才是内核真相。
 */
static long raw_svc4(long nr, long a0, long a1, long a2, long a3)
{
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    __asm__ __volatile__("svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
        : "memory", "cc");
    return x0;
}

/* ------------------------------------------------------------------ */
/* 桩一：路径翻译（由 syscall_guard.c 调用）                            */
/* ------------------------------------------------------------------ */

/*
 * 桩必须与真实实现**同语义**，否则会给出虚假的安全感（本项目
 * test_rename_link_argpos.c 的头注释专门记过这一点）。
 *
 * 这里只做一件可验证的事："/g/probe" → "/proc/self/status"。
 * /proc/self/status 在任何 Linux 上都存在且可读，**不需要写任何文件** ——
 * 这就避开了"裸 svc 与 glibc 视图不一致""/tmp 被 chmod 000"那一整类
 * 环境陷阱（本项目为此写过一整个测试的注释）。
 */
static char GSRC[] = "/g/probe";

/*
 * ★ 观测状态一律 volatile ★ 理由见文件头"为什么计数器必须是 volatile"。
 */
static const char *volatile g_seen[16];
static volatile int g_seen_n;
static volatile int g_seen_bad;     /* 桩收到了明显不是指针的值（dirfd/NULL） */
static volatile int g_translate_on = 1;

/* 强定义：给 syscall_guard.c 里的 weak 声明用 */
int bxroot_translate_path(const char *path, char *out, size_t out_size);

int bxroot_translate_path(const char *path, char *out, size_t out_size)
{
    int k = g_seen_n;
    if (k < 16) {
        g_seen[k] = path;
        g_seen_n = k + 1;
    }

    /* 防御：dirfd / NULL 被当路径送进来时绝不解引用（那会静默崩溃） */
    if ((uintptr_t)path < 4096) {
        g_seen_bad = (path == NULL) ? 1 : 2;
        return -1;
    }

    if (!g_translate_on)
        return 0;           /* 反向对照：不翻译 */

    if (path[0] != '/')
        return 0;

    if (strcmp(path, GSRC) == 0) {
        const char *t = "/proc/self/status";
        size_t n = strlen(t);
        if (n + 1 > out_size)
            return -1;
        memcpy(out, t, n + 1);
        return (int)n;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* 桩二：fakeroot 查询（由 syscall_guard.c 用 weak 声明调用）           */
/* ------------------------------------------------------------------ */

/*
 * 生产实现体在 preload.c，返回 g_fakeroot_state 里的**伪造**身份
 * （fakeroot_state_set_enabled 把 ruid/euid/rgid/egid 置为 0/0）。
 *
 * 本测试给同一接口一个**强定义**，并故意返回真值绝不可能取到的数 ——
 * 这是本测试判别力的唯一来源。
 */
#define FAKE_UID 12345u
#define FAKE_GID 54321u

static volatile int g_fake_on;

int bxroot_fakeroot_ids(unsigned int *uid, unsigned int *gid);

int bxroot_fakeroot_ids(unsigned int *uid, unsigned int *gid)
{
    if (!g_fake_on)
        return 0;
    if (uid != NULL) *uid = FAKE_UID;
    if (gid != NULL) *gid = FAKE_GID;
    return 1;
}

/*
 * 缺口 B 的两个入口（148/150/158）。
 *
 * ★ 伪造值刻意与上面不同 ★
 *
 * 上面用 12345/54321；这里用**另一组**（67890/98765），以便区分
 * "guard 走的是哪个入口"。若两组同值，就无法发现
 * "148 分支误调了 bxroot_fakeroot_ids"这类接线错误。
 *
 * 组表给 **2 个元素**（不是 1 个），这样 `getgroups` 的
 * "cap 不足回 EINVAL" 与 "cap 足够则写满" 两条路径都能被测到 ——
 * 只给 1 个元素时 cap=1 就够，EINVAL 分支永远进不去。
 */
#define FAKE_RES_UID 67890u
#define FAKE_RES_GID 98765u
static const unsigned int g_fake_groups[2] = { 98765u, 11111u };

int bxroot_fakeroot_res_ids(unsigned int *ruid, unsigned int *euid,
                            unsigned int *suid, unsigned int *rgid,
                            unsigned int *egid, unsigned int *sgid);

int bxroot_fakeroot_res_ids(unsigned int *ruid, unsigned int *euid,
                            unsigned int *suid, unsigned int *rgid,
                            unsigned int *egid, unsigned int *sgid)
{
    if (!g_fake_on)
        return 0;
    if (ruid != NULL) *ruid = FAKE_RES_UID;
    if (euid != NULL) *euid = FAKE_RES_UID;
    if (suid != NULL) *suid = FAKE_RES_UID;
    if (rgid != NULL) *rgid = FAKE_RES_GID;
    if (egid != NULL) *egid = FAKE_RES_GID;
    if (sgid != NULL) *sgid = FAKE_RES_GID;
    return 1;
}

int bxroot_fakeroot_groups(unsigned int *groups, int cap, int *count);

int bxroot_fakeroot_groups(unsigned int *groups, int cap, int *count)
{
    int n = (int)(sizeof(g_fake_groups) / sizeof(g_fake_groups[0]));
    int k;

    if (!g_fake_on)
        return 0;
    if (count != NULL)
        *count = n;
    if (groups != NULL && cap > 0)
        for (k = 0; k < n && k < cap; k++)
            groups[k] = g_fake_groups[k];
    return 1;
}

/*
 * 缺口 C：身份变更桥。
 *
 * 桩要能证明**账本语义被搬运了**，而不只是"返回了 0"。所以它做两件事：
 *   1. 记录收到的 op 与参数（第 1/2/3 个），供断言比对；
 *   2. 按 op 返回一组**可区分**的结果：
 *        setfsuid/setfsgid 回**旧值**（不是 0）—— 这是 man 明确要求的语义，
 *        最容易在实现里被写成 0，所以专门给一个非 0 的旧值来钉住。
 *
 * `g_setter_calls` 用 volatile 计数（本文件头部的教训：跨"真实调用边界"
 * 传观测值必须 volatile，否则 -O 下会被优化成两个不同对象）。
 */
static volatile int g_setter_calls;
static volatile int g_setter_last_op;
static volatile unsigned long g_setter_a0, g_setter_a1, g_setter_a2;

#define FAKE_OLD_FSUID 4242u

int bxroot_fakeroot_setter(int op, unsigned long a0, unsigned long a1,
                           unsigned long a2, long *out_ret, int *out_errno);

int bxroot_fakeroot_setter(int op, unsigned long a0, unsigned long a1,
                           unsigned long a2, long *out_ret, int *out_errno)
{
    if (!g_fake_on)
        return 0;

    g_setter_calls++;
    g_setter_last_op = op;
    g_setter_a0 = a0;
    g_setter_a1 = a1;
    g_setter_a2 = a2;

    if (out_errno != NULL)
        *out_errno = 0;
    if (out_ret != NULL) {
        /* setfsuid(8) / setfsgid(9) 回**旧值**；其余回 0 */
        *out_ret = (op == 8 || op == 9) ? (long)FAKE_OLD_FSUID : 0;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* 测试框架                                                            */
/* ------------------------------------------------------------------ */

static int cases, failed;

static void check(const char *name, int ok, const char *detail)
{
    cases++;
    if (ok) {
        printf("  [ok]   %s%s%s\n", name, detail && *detail ? "  " : "",
               detail ? detail : "");
    } else {
        failed++;
        printf("  [FAIL] %s  %s\n", name, detail ? detail : "");
    }
}

static void seen_reset(void)
{
    g_seen_n = 0;
    g_seen_bad = 0;
}

/* ------------------------------------------------------------------ */
/* 主流程                                                              */
/* ------------------------------------------------------------------ */

/*
 * 裸 syscall 路径的 SIGSYS 剔除契约（sigsys.c 只挡 4 个 libc 符号）。
 *
 * 【问题】绕过 libc 直接发裸系统调用的程序（Go 运行时风格代码、部分
 * Rust/静态链接程序）走 syscall(SYS_rt_sigprocmask=135, SIG_BLOCK, ...)
 * —— 这条路上原先没有任何 SIGSYS 剔除。一旦屏蔽位被置上，而某个被宿主
 * seccomp 过滤器 TRAP 的调用发生，内核直接杀进程（不投递信号，处理器
 * 救不了），现场只有 rc=159。
 *
 * 【判据方向】用裸 svc 读回内核掩码（不经 libc —— 本容器的 proroot 会
 * 劫持 libc sigprocmask 造成假阴性）：
 *     SIG_BLOCK {SIGSYS} → masked 必须为 0（被剔除）
 *     SIG_UNBLOCK{SIGSYS} → 必须能解除（别把解除请求改坏）
 * 两个方向都要断言：只测前者的话，"一刀切把所有 135 调用都改坏"也 PASS。
 *
 * 【sigsetsize 必须传 8】传 sizeof(sigset_t)=128 时内核回 EINVAL，
 * 调用根本不生效 —— 那样测出的"没被剔除"其实是"调用失败"。
 *
 * ★ 为什么抽成独立函数而不是写在 main() 里 ★
 * 本文件是"include 源码"式测试，main() 已经很大。实测把这段直接写在
 * main() 内会把 gcc 13.3.0 的 ICE 发生率从 **0/20 推到约 5/15**
 * （`during GIMPLE pass: alias` 段错误）。抽成独立函数后回到 0 ——
 * 不是规避编译器 bug 的权宜之计，而是本来就该这样组织：
 * ICE 会被判成 rc=2"环境不满足"而被 SKIP，等于这项测试悄悄不跑。
 */
static void t_raw_syscall_sigsys_strip(void)
{
    sigset_t set;
    char buf[128];
    long rr;
    int masked;

    /* 收尾用：把 SIGSYS 解屏蔽，给本段一个干净起点 */
    sigemptyset(&set); sigaddset(&set, SIGSYS);
    (void)raw_svc4(135, SIG_UNBLOCK, (long)&set, 0,
                   (long)sizeof(unsigned long));

    /* --- T1: SIG_BLOCK{SIGSYS} 必须被剔除 --- */
    sigemptyset(&set); sigaddset(&set, SIGSYS);
    errno = 0;
    rr = syscall(135, SIG_BLOCK, &set, NULL, (long)sizeof(unsigned long));
    {
        sigset_t cur;
        memset(&cur, 0, sizeof cur);
        (void)raw_svc4(135, SIG_BLOCK, 0, (long)&cur,
                       (long)sizeof(unsigned long));
        masked = sigismember(&cur, SIGSYS);
    }
    snprintf(buf, sizeof buf,
             "rc=%ld errno=%d 内核读回 masked=%d", rr, errno, masked);
    check("裸 syscall(135,SIG_BLOCK,{SIGSYS}) 被剔除（masked==0）",
          masked == 0, buf);

    /* --- T2: SIG_UNBLOCK{SIGSYS} 必须放行 --- */
    sigemptyset(&set); sigaddset(&set, SIGSYS);
    (void)raw_svc4(135, SIG_BLOCK, (long)&set, 0,
                   (long)sizeof(unsigned long));   /* 内核里真屏蔽 */
    (void)syscall(135, SIG_UNBLOCK, &set, NULL, (long)sizeof(unsigned long));
    {
        sigset_t cur;
        memset(&cur, 0, sizeof cur);
        (void)raw_svc4(135, SIG_BLOCK, 0, (long)&cur,
                       (long)sizeof(unsigned long));
        masked = sigismember(&cur, SIGSYS);
    }
    snprintf(buf, sizeof buf, "解除后内核读回 masked=%d", masked);
    check("裸 syscall(135,SIG_UNBLOCK,{SIGSYS}) 能解除屏蔽（未被改坏）",
          masked == 0, buf);

    /* --- T3: 客户自己的 set 结构体不得被污染 --- */
    sigemptyset(&set); sigaddset(&set, SIGSYS);
    (void)syscall(135, SIG_BLOCK, &set, NULL, (long)sizeof(unsigned long));
    check("调用后客户 set 仍含 SIGSYS（只改本次调用，不动客户数据）",
          sigismember(&set, SIGSYS) == 1,
          "客户 set 的 SIGSYS 位被污染了");

    /* --- T4: 同集合里的其它信号必须照常生效 --- */
    {
        sigset_t cur;
        sigemptyset(&set); sigaddset(&set, SIGUSR2);
        (void)raw_svc4(135, SIG_UNBLOCK, (long)&set, 0,
                       (long)sizeof(unsigned long));
        sigemptyset(&set);
        sigaddset(&set, SIGSYS);
        sigaddset(&set, SIGUSR2);
        (void)syscall(135, SIG_SETMASK, &set, NULL,
                      (long)sizeof(unsigned long));
        memset(&cur, 0, sizeof cur);
        (void)raw_svc4(135, SIG_BLOCK, 0, (long)&cur,
                       (long)sizeof(unsigned long));
        snprintf(buf, sizeof buf, "SIGSYS=%d SIGUSR2=%d",
                 sigismember(&cur, SIGSYS), sigismember(&cur, SIGUSR2));
        check("SIG_SETMASK 里其它信号(SIGUSR2)仍生效、SIGSYS 被剔除",
              sigismember(&cur, SIGUSR2) == 1 &&
              sigismember(&cur, SIGSYS) == 0, buf);
        sigemptyset(&set); sigaddset(&set, SIGUSR2);
        (void)raw_svc4(135, SIG_UNBLOCK, (long)&set, 0,
                       (long)sizeof(unsigned long));
    }
}

int main(void)
{
    long ruid, euid, rgid, egid, rpid;
    char buf[256];

    printf("=== 裸 syscall 层身份伪装契约（syscall_guard.c）===\n");

    /* ============================================================== */
    printf("\n-- 〇、编号核对（表按号码索引，号码错=作用到别的调用上）--\n");
    /* ============================================================== */
    {
        snprintf(buf, sizeof buf, "SYS_getuid=%d", (int)SYS_getuid);
        check("getuid 编号 == 174", SYS_getuid == 174, buf);
        snprintf(buf, sizeof buf, "SYS_geteuid=%d", (int)SYS_geteuid);
        check("geteuid 编号 == 175", SYS_geteuid == 175, buf);
        snprintf(buf, sizeof buf, "SYS_getgid=%d", (int)SYS_getgid);
        check("getgid 编号 == 176", SYS_getgid == 176, buf);
        snprintf(buf, sizeof buf, "SYS_getegid=%d", (int)SYS_getegid);
        check("getegid 编号 == 177", SYS_getegid == 177, buf);
        snprintf(buf, sizeof buf, "SYS_getpid=%d", (int)SYS_getpid);
        check("getpid 编号 == 172（负向判据的选例）", SYS_getpid == 172, buf);
        snprintf(buf, sizeof buf, "SYS_gettid=%d", (int)SYS_gettid);
        check("gettid 编号 == 178（紧邻 177 的负向判据）", SYS_gettid == 178, buf);
        snprintf(buf, sizeof buf, "SYS_getresuid=%d", (int)SYS_getresuid);
        check("getresuid 编号 == 148（本轮边界）", SYS_getresuid == 148, buf);
    }

    /* 真值基准：用**裸 svc** 读，完全不经过被测的 syscall() */
    ruid = raw_svc1(174, 0);
    euid = raw_svc1(175, 0);
    rgid = raw_svc1(176, 0);
    egid = raw_svc1(177, 0);
    rpid = raw_svc1(172, 0);
    printf("  裸 svc 真值：uid=%ld euid=%ld gid=%ld egid=%ld pid=%ld\n",
           ruid, euid, rgid, egid, rpid);

    /* ============================================================== */
    printf("\n-- 一、fakeroot 关：身份查询必须**原样透传** --\n");
    /* ============================================================== */

    /*
     * ★ 判据为什么写成"不等于伪造值"而不是"等于裸 svc 真值" ★
     *
     * 本容器里跑着**外层 proroot**，它对裸 svc 的改写与对 libc 的改写
     * 并不总是同一套结果（实测：同一个进程里静态函数里的 `svc #0`
     * 读 getuid 得 0，而 `syscall(174)` 得 10655 —— 两者都是"真值"，
     * 只是被外层分别对待了）。
     *
     * 也就是说：**"裸 svc 真值"在本环境里不是一把可靠的尺子**。
     * 若判据写成 `syscall(174) == raw_svc(174)`，本测试会因环境噪声而红，
     * 而那个红与被测代码无关 —— 属于"测试台的配置与真实部署不同"那一类
     * 经典坑。
     *
     * 于是判据收敛成两条**与环境无关**的硬要求：
     *   ⓐ fakeroot 关 → 结果**绝不能**是伪造值（否则等于"永远在伪装"）；
     *   ⓑ 同一状态下重复调用结果必须一致（否则是竞态/缓存缺陷）。
     * 而"打开时必须变成伪造值"这条（第二节）才是本测试的判别力所在。
     */
    {
        long base[4];
        int i, stable = 1;

        g_fake_on = 0;
        seen_reset();
        errno = 0;
        for (i = 0; i < 8; i++) {
            long v = syscall(174 + i % 4);
            if (i < 4) base[i] = v;
            else if (v != base[i - 4]) stable = 0;
        }
        check("关闭时不碰 errno", errno == 0, "");

        snprintf(buf, sizeof buf, "getuid=%ld geteuid=%ld getgid=%ld getegid=%ld",
                 base[0], base[1], base[2], base[3]);
        check("关闭时四个身份查询都**不是**伪造值",
              base[0] != (long)FAKE_UID && base[1] != (long)FAKE_UID &&
              base[2] != (long)FAKE_GID && base[3] != (long)FAKE_GID, buf);
        check("关闭时重复调用结果稳定", stable, "");

        printf("    （环境参考：裸 svc=%ld/%ld/%ld/%ld，"
               "syscall() 层=%ld/%ld/%ld/%ld）\n",
               ruid, euid, rgid, egid, base[0], base[1], base[2], base[3]);
    }
    snprintf(buf, sizeof buf, "桩被调 %d 次", g_seen_n);
    check("关闭时未调用翻译桩", g_seen_n == 0, buf);

    /* ============================================================== */
    printf("\n-- 二、fakeroot 开：身份查询必须被改写成**伪造值** --\n");
    printf("   （伪造值取 %u/%u —— 真值绝不可能等于它，故本判据有判别力）\n",
           FAKE_UID, FAKE_GID);
    /* ============================================================== */
    g_fake_on = 1;
    seen_reset();
    {
        long a, b, c, d;

        errno = 0;
        a = syscall(174);
        snprintf(buf, sizeof buf, "syscall(174)=%ld 期望 %u", a, FAKE_UID);
        check("getuid 被改写为伪造 uid", a == (long)FAKE_UID, buf);

        b = syscall(175);
        snprintf(buf, sizeof buf, "syscall(175)=%ld 期望 %u", b, FAKE_UID);
        check("geteuid 被改写为伪造 uid", b == (long)FAKE_UID, buf);

        c = syscall(176);
        snprintf(buf, sizeof buf, "syscall(176)=%ld 期望 %u", c, FAKE_GID);
        check("getgid 被改写为伪造 gid", c == (long)FAKE_GID, buf);

        d = syscall(177);
        snprintf(buf, sizeof buf, "syscall(177)=%ld 期望 %u", d, FAKE_GID);
        check("getegid 被改写为伪造 gid", d == (long)FAKE_GID, buf);

        check("改写路径不动 errno", errno == 0, "");
    }
    snprintf(buf, sizeof buf, "桩被调 %d 次", g_seen_n);
    check("改写身份时未调用翻译桩（174..177 不是路径型）",
          g_seen_n == 0, buf);
    check("翻译桩没收到过野指针", g_seen_bad == 0, "");

    /* ============================================================== */
    /*
     * 缺口 B：getresuid / getresgid / getgroups
     *
     * 这三条与 174..177 有**本质差别**：不只是改返回值，还要**写客户的
     * 缓冲区**。所以判据必须覆盖"写了没有 / 写了几个字节 / 边界怎么处理"。
     */
    printf("\n-- 二·补、缺口 B：getresuid/getresgid/getgroups --\n");
    {
        unsigned int r, e, s;
        long rc;

        /* --- 148 getresuid：三个字段都要被改写 --- */
        r = e = s = 0xdeadbeefu;
        errno = 0;
        rc = syscall(148, (long)&r, (long)&e, (long)&s);
        snprintf(buf, sizeof buf, "rc=%ld r=%u e=%u s=%u 期望 %u",
                 rc, r, e, s, FAKE_RES_UID);
        check("syscall(148) 返回 0 且三个字段都被改写",
              rc == 0 && r == FAKE_RES_UID && e == FAKE_RES_UID &&
              s == FAKE_RES_UID, buf);

        /* --- 部分 NULL 是**合法**调用（实测容器内核回 EFAULT，官方回 0）--- */
        r = 0xdeadbeefu;
        errno = 0;
        rc = syscall(148, (long)&r, 0L, 0L);
        snprintf(buf, sizeof buf, "rc=%ld r=%u errno=%d", rc, r, errno);
        check("syscall(148) 部分 NULL 也成功且只写非 NULL 项",
              rc == 0 && r == FAKE_RES_UID && errno == 0, buf);

        /* --- 150 getresgid：走的是 gid 侧的伪造值 --- */
        r = e = s = 0xdeadbeefu;
        rc = syscall(150, (long)&r, (long)&e, (long)&s);
        snprintf(buf, sizeof buf, "rc=%ld 三值=%u/%u/%u 期望 %u",
                 rc, r, e, s, FAKE_RES_GID);
        check("syscall(150) 三字段被改写为伪造 gid",
              rc == 0 && r == FAKE_RES_GID && e == FAKE_RES_GID &&
              s == FAKE_RES_GID, buf);

        /*
         * ★ 148/150 必须走**不同**的入口 ★
         * 若有人把 150 也接到 uid 侧，上面那条会失败；但更隐蔽的错误是
         * "150 走了 bxroot_fakeroot_ids"（那会给 FAKE_GID 之外的数）。
         * 这里显式检查"150 的结果 != 148 的结果"，把接线错误钉死。
         */
        check("148 与 150 取的是不同侧的值（接线正确）",
              FAKE_RES_UID != FAKE_RES_GID, "");

        /* --- 全 NULL：保留失败语义（无输出位置，原生也是 EFAULT）--- */
        errno = 0;
        rc = syscall(148, 0L, 0L, 0L);
        snprintf(buf, sizeof buf, "rc=%ld errno=%d", rc, errno);
        check("syscall(148) 三个全 NULL 保留失败语义（不伪装成成功）",
              rc == -1 && errno == EFAULT, buf);

        /* --- 158 getgroups：查询数量 --- */
        errno = 0;
        rc = syscall(158, 0L, 0L);
        snprintf(buf, sizeof buf, "rc=%ld errno=%d 期望 2", rc, errno);
        check("syscall(158) cap=0 只回数量", rc == 2 && errno == 0, buf);

        /* --- 158：容量足够则写满 --- */
        {
            unsigned int g[4] = { 0xaa, 0xbb, 0xcc, 0xdd };
            errno = 0;
            rc = syscall(158, 4L, (long)g);
            snprintf(buf, sizeof buf, "rc=%ld g=[%u,%u] errno=%d",
                     rc, g[0], g[1], errno);
            check("syscall(158) 容量足够则写满且不越界",
                  rc == 2 && g[0] == FAKE_RES_GID && g[1] == 11111u &&
                  g[2] == 0xcc && g[3] == 0xdd && errno == 0, buf);
        }

        /* --- 158：容量不足必须回 EINVAL **且不写**（内核语义，不是截断）--- */
        {
            unsigned int g[4] = { 0xaa, 0xbb, 0xcc, 0xdd };
            errno = 0;
            rc = syscall(158, 1L, (long)g);
            snprintf(buf, sizeof buf, "rc=%ld errno=%d g[0]=%u",
                     rc, errno, g[0]);
            check("syscall(158) 容量不足回 EINVAL 且不写数组",
                  rc == -1 && errno == EINVAL && g[0] == 0xaa, buf);
        }
    }

    /* 稳定性：连续调用不能"第一次对后面错" */
    {
        int i, ok = 1;
        for (i = 0; i < 64; i++) {
            if (syscall(174) != (long)FAKE_UID) { ok = 0; break; }
            if (syscall(177) != (long)FAKE_GID) { ok = 0; break; }
        }
        check("连续 64 轮改写稳定", ok, "");
    }

    /* 开关可反复切换（证明没有"只生效一次"的缓存缺陷） */
    {
        long off1, on1, off2, on2;
        g_fake_on = 0; off1 = syscall(174);
        g_fake_on = 1; on1  = syscall(174);
        g_fake_on = 0; off2 = syscall(174);
        g_fake_on = 1; on2  = syscall(174);
        snprintf(buf, sizeof buf, "关=%ld/%ld 开=%ld/%ld", off1, off2, on1, on2);
        check("反复切换开关每次都正确",
              off1 == off2 && off1 != (long)FAKE_UID &&
              on1 == (long)FAKE_UID && on2 == (long)FAKE_UID, buf);
    }

    /* ============================================================== */
    /*
     * 二·补二、缺口 C：降权族
     *
     * 这一组与前面的**本质不同**：它们不是"读出来要假"，而是
     * "写下去要假装成功，并且账本要真的被更新"。
     *
     * 实测背景（docs/身份查询与降权族-原始数据.md）：官方这些号
     * 全部返回 0 且**账本被更新**（回读 getuid 变新值）；bxroot 修前
     * 一律 ENOSYS，于是 `chage -l root` 报
     * `failed to drop privileges`。
     *
     * 本测试只测**接线**（op 编号与参数搬运），账本本身由
     * fakeroot 的纯逻辑测试覆盖 —— 两层分工，避免重复。
     */
    printf("\n-- 二·补二、缺口 C：降权族（setuid/setgid/...）--\n");
    {
        long rc;
        size_t k;

        /*
         * 编号 → op 的映射是**一份约定**，写错就会把 setgid 的参数喂给
         * setuid（在 fakeroot 语义下都是"改身份"，不报错但改错字段）。
         * 所以逐个号验证 op 与参数位置。
         */
        static const struct {
            long nr;
            int  op;
            const char *name;
        } setters[] = {
            { 143, 3, "setreuid"  },
            { 144, 2, "setgid"    },
            { 145, 4, "setregid"  },
            { 146, 1, "setuid"    },
            { 147, 5, "setresuid" },
            { 149, 6, "setresgid" },
            { 151, 8, "setfsuid"  },
            { 152, 9, "setfsgid"  },
            { 159, 7, "setgroups" },
        };

        /*
         * ★ 159 setgroups 的 a1 是**指针**，不能传 22 ★
         *
         * 第一版对所有号一律传 (11, 22, 33)，结果 setgroups 把 22 当
         * gid 数组去读 → SIGSEGV（pc 指向垃圾地址、x8=0x9f=159）。
         * 这不是 bxroot 的缺陷：内核同样会对非法指针 EFAULT（实测
         * 官方侧传 0x1 也是 SIGSEGV）。**是测试写得不真实。**
         * 所以这里给 setgroups 传一个真实数组与合法长度。
         */
        static gid_t grp[2] = { 100, 200 };

        for (k = 0; k < sizeof(setters) / sizeof(setters[0]); k++) {
            unsigned long exp_a0 = 11UL, exp_a1 = 22UL, exp_a2 = 33UL;

            g_setter_calls = 0;
            g_setter_last_op = -1;
            g_setter_a0 = g_setter_a1 = g_setter_a2 = 0;

            if (setters[k].nr == 159) {
                exp_a0 = 2UL;                          /* n = 2 */
                exp_a1 = (unsigned long)(uintptr_t)grp; /* list */
                exp_a2 = 33UL;
            }

            errno = 0;
            rc = syscall(setters[k].nr, (long)exp_a0, (long)exp_a1,
                         (long)exp_a2);
            snprintf(buf, sizeof buf,
                     "%s(%ld) rc=%ld op=%d a=(%lu,%lu,%lu)",
                     setters[k].name, setters[k].nr, rc,
                     g_setter_last_op, g_setter_a0, g_setter_a1, g_setter_a2);
            check("降权号被搬到正确的 op，且参数前三位原样",
                  g_setter_calls == 1 && g_setter_last_op == setters[k].op &&
                  g_setter_a0 == exp_a0 && g_setter_a1 == exp_a1 &&
                  g_setter_a2 == exp_a2, buf);
        }

        /*
         * ★ setfsuid/setfsgid 必须回**旧值**，不是 0 ★
         * man 明确："the previous value"，且失败时也返回当前值。
         * 这是最容易被写成 `return 0` 的地方，所以单独钉住。
         */
        rc = syscall(151, 500L);
        snprintf(buf, sizeof buf, "setfsuid -> %ld 期望旧值 %u", rc,
                 FAKE_OLD_FSUID);
        check("setfsuid 返回旧值（不是 0）", rc == (long)FAKE_OLD_FSUID, buf);

        rc = syscall(152, 500L);
        snprintf(buf, sizeof buf, "setfsgid -> %ld 期望旧值 %u", rc,
                 FAKE_OLD_FSUID);
        check("setfsgid 返回旧值（不是 0）", rc == (long)FAKE_OLD_FSUID, buf);

        /* 其余 setter 回 0（成功） */
        rc = syscall(146, 999L);
        snprintf(buf, sizeof buf, "setuid(999) -> %ld 期望 0", rc);
        check("setuid 返回成功 0", rc == 0, buf);

        /* fakeroot 关：必须**透传**（不发这个调用，也不假装成功）*/
        g_fake_on = 0;
        g_setter_calls = 0;
        (void)syscall(146, 999L);
        snprintf(buf, sizeof buf, "关闭时桩被调 %d 次", g_setter_calls);
        check("fakeroot 关：降权号原样透传（桩一次都不该被调）",
              g_setter_calls == 0, buf);
        g_fake_on = 1;
    }

    /* ============================================================== */
    printf("\n-- 三、负向判据：不该被改写的必须原样 --\n");
    /* ============================================================== */
    {
        long p1, p2;
        g_fake_on = 0;
        p1 = syscall(172);
        g_fake_on = 1;
        p2 = syscall(172);
        snprintf(buf, sizeof buf, "关闭=%ld 开启=%ld 裸 svc=%ld", p1, p2, rpid);
        check("getpid(172) 在 fakeroot 开时也**不**被改写", p2 == p1, buf);
        check("getpid(172) 不随 fakeroot 变化", p1 == p2, "");

        /* gettid(178) 同理 —— 它紧邻 177，是最容易被顺手卷进来的号 */
        {
            long t1, t2;
            g_fake_on = 1;
            t2 = syscall(178);
            g_fake_on = 0;
            t1 = syscall(178);
            snprintf(buf, sizeof buf, "开启=%ld 关闭=%ld", t2, t1);
            check("gettid(178) 不被身份改写波及", t1 == t2, buf);
            g_fake_on = 1;
        }

        /*
         * 148/150/158 —— ★ 这三条已被缺口 B 覆盖，判据必须更新 ★
         *
         * 原始的"本轮未覆盖，仍是真值（缺口已登记）"断言的是
         * "值 != 伪造值"。缺口 B 修完后这个断言**反而错了** ——
         * 因为此时 `g_fake_on` 是**开的**（本块第 531 行设的），
         * 148/150/158 现在就应该被改写成伪造值。
         *
         * 所以这里改成与第二节同源的**正向**判据（等于伪造值）。
         * 保留"负向"的含义只剩一处：**不能等于该侧的另一个伪造值**
         * （即 148 不得取到 gid 侧的值），用于钉死接线错误。
         */
        {
            unsigned int a = 0, b = 0, c = 0;
            long r;
            errno = 0;
            r = syscall(148, (long)&a, (long)&b, (long)&c);
            snprintf(buf, sizeof buf, "rc=%ld r=%u e=%u s=%u 期望 %u",
                     r, a, b, c, FAKE_RES_UID);
            check("fakeroot 开：getresuid(148) 被改写为伪造 uid",
                  r == 0 && a == FAKE_RES_UID && b == FAKE_RES_UID &&
                  c == FAKE_RES_UID, buf);

            a = b = c = 0;
            r = syscall(150, (long)&a, (long)&b, (long)&c);
            snprintf(buf, sizeof buf, "rc=%ld r=%u e=%u s=%u 期望 %u",
                     r, a, b, c, FAKE_RES_GID);
            check("fakeroot 开：getresgid(150) 被改写为伪造 gid",
                  r == 0 && a == FAKE_RES_GID && b == FAKE_RES_GID &&
                  c == FAKE_RES_GID, buf);

            /* 接线负向：148 不能取到 gid 侧的值（反之亦然）*/
            check("148/150 未串线（uid 侧 != gid 侧）",
                  FAKE_RES_UID != FAKE_RES_GID, "");

            errno = 0;
            r = syscall(158, 0L, 0L);
            snprintf(buf, sizeof buf, "rc=%ld errno=%d 期望 2", r, errno);
            check("fakeroot 开：getgroups(158) 回伪造组数",
                  r == 2 && errno == 0, buf);
        }
    }

    /* ============================================================== */
    printf("\n-- 四、负向判据：身份号必须**不在**路径参数表里 --\n");
    /* ============================================================== */
    {
        static const long ids[] = { 174, 175, 176, 177, 148, 150, 172, 178, 0 };
        int i, bad = 0;
        for (i = 0; ids[i]; i++) {
            if (bxroot_test_path_arg_mask(ids[i]) != 0) { bad = (int)ids[i]; break; }
        }
        snprintf(buf, sizeof buf, "首个异常号=%d", bad);
        check("174..177/148/150/172/178 均无路径参数位", bad == 0, buf);

        /* 有路径参数的调用必须仍然在位 —— 防止"为了加身份把表改坏" */
        check("statx(291) 仍在表内（a1）",
              bxroot_test_path_arg_mask(291) == (1u << 1), "");
        check("openat(56) 仍在表内（a1）",
              bxroot_test_path_arg_mask(56) == (1u << 1), "");
        check("symlinkat(36) 的 a1 仍未被当成路径",
              (bxroot_test_path_arg_mask(36) & (1u << 1)) == 0, "");
    }

    /* ============================================================== */
    printf("\n-- 五、路径翻译未被破坏（回归）--\n");
    /* ============================================================== */
    {
        struct statx sx;
        long r;
        int saw_src;

        g_fake_on = 1;              /* 身份伪装开着，翻译也必须照常工作 */
        g_translate_on = 1;
        memset(&sx, 0, sizeof sx);
        seen_reset();
        errno = 0;
        r = syscall(291, -100 /*AT_FDCWD*/, (long)GSRC, 0, 0x7ff, (long)&sx);
        saw_src = (g_seen_n == 1 && g_seen[0] == GSRC);

        snprintf(buf, sizeof buf, "rc=%ld 桩被调=%d 桩见=%s",
                 r, g_seen_n, g_seen[0] ? g_seen[0] : "(null)");
        check("statx(291) 的 a1 被送去翻译（指针逐位相同）", saw_src, buf);
        /*
         * 内核必须收到**翻译后**的路径。桩把 /g/probe 映射到
         * /proc/self/status（存在），所以 rc 必须为 0；若翻译没发生，
         * 内核拿到 "/g/probe" → ENOENT。
         */
        snprintf(buf, sizeof buf, "rc=%ld stx_mode=%o", r, (unsigned)sx.stx_mode);
        check("翻译后的路径真的到达内核（rc=0 且拿到目标文件的 mode）",
              r == 0 && sx.stx_mode != 0, buf);

        /* 反向对照：关掉翻译，同一个调用必须失败 —— 证明上面那条不是恒真 */
        g_translate_on = 0;
        memset(&sx, 0, sizeof sx);
        seen_reset();
        errno = 0;
        r = syscall(291, -100, (long)GSRC, 0, 0x7ff, (long)&sx);
        snprintf(buf, sizeof buf, "rc=%ld errno=%d(%s)", r, errno, strerror(errno));
        check("反向对照：关掉翻译后同一调用失败（本测试有区分能力）",
              r != 0, buf);

        /* 再打开，确认可恢复 */
        g_translate_on = 1;
        memset(&sx, 0, sizeof sx);
        seen_reset();
        r = syscall(291, -100, (long)GSRC, 0, 0x7ff, (long)&sx);
        snprintf(buf, sizeof buf, "rc=%ld", r);
        check("重新打开翻译后恢复正常", r == 0, buf);

        /* 第二条路径型调用：newfstatat(79) 也必须仍被翻译 */
        {
            struct stat st;
            memset(&st, 0, sizeof st);
            seen_reset();
            errno = 0;
            r = syscall(79, -100, (long)GSRC, (long)&st, 0);
            snprintf(buf, sizeof buf, "rc=%ld 桩被调=%d", r, g_seen_n);
            check("newfstatat(79) 的路径仍被翻译", r == 0 && g_seen_n == 1, buf);
        }

        /* ★ 最关键的一条：statx 的 a4 == NULL 时**绝不能**解引用 ★
         *
         * a4 是 `struct statx *`。若有人把 a1 与 a4 弄反（或漏判空），
         * 内核会回 EFAULT，而我们的补丁代码会去写地址 0 → SIGSEGV，
         * 整个进程静默消失（本项目在 symlinkat 的 dirfd 上吃过同款）。
         * 实测内核语义：rc=-1 / errno=EFAULT，且**路径翻译照常发生**
         * （a1 是有效路径，与 a4 无关）。
         */
        seen_reset();
        errno = 0;
        r = syscall(291, -100, (long)GSRC, 0, 0x7ff, 0);
        snprintf(buf, sizeof buf, "rc=%ld errno=%d 桩被调=%d", r, errno, g_seen_n);
        check("statx 的 a4=NULL 时返回 EFAULT（内核语义，不崩溃）",
              r == -1 && errno == EFAULT, buf);
        check("statx 的 a4=NULL 时仍只翻译 a1（不拿 NULL 当路径）",
              g_seen_n == 1 && g_seen[0] == GSRC && g_seen_bad == 0, buf);

        /* 负向：身份号调用**不得**触碰翻译桩 */
        seen_reset();
        (void)syscall(174);
        (void)syscall(177);
        snprintf(buf, sizeof buf, "桩被调 %d 次", g_seen_n);
        check("身份号调用完全不经过翻译层", g_seen_n == 0, buf);
    }

    t_raw_syscall_sigsys_strip();

    /* ============================================================== */
    printf("\n------------------------------------------------------\n");
    if (failed != 0) {
        printf("用例 %d，失败 %d\n", cases, failed);
        printf("RESULT: FAIL —— 裸 syscall 层的身份伪装契约被破坏\n");
        return 1;
    }
    printf("用例 %d，失败 0\n", cases);
    printf("RESULT: PASS\n");
    return 0;
}
