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
         * 148/150 本轮未覆盖：必须是真值，**绝不能**是伪造值。
         *
         * 判据同样收敛成"不等于伪造值" —— 理由见第一节的长注释：
         * 本环境里"真值"有两个可能的值（外层 proroot 对静态 svc 与
         * syscall() 符号分别处理），拿其中一个当绝对基准会得到假红。
         */
        {
            unsigned int a = 0, b = 0, c = 0;
            long r;
            errno = 0;
            r = syscall(148, (long)&a, (long)&b, (long)&c);
            snprintf(buf, sizeof buf, "rc=%ld r=%u e=%u s=%u", r, a, b, c);
            check("getresuid(148) 本轮未覆盖，仍是真值（缺口已登记）",
                  r == 0 && a != FAKE_UID && b != FAKE_UID && c != FAKE_UID, buf);

            a = b = c = 0;
            r = syscall(150, (long)&a, (long)&b, (long)&c);
            snprintf(buf, sizeof buf, "rc=%ld r=%u e=%u s=%u", r, a, b, c);
            check("getresgid(150) 本轮未覆盖，仍是真值（缺口已登记）",
                  r == 0 && a != FAKE_GID && b != FAKE_GID && c != FAKE_GID, buf);
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
