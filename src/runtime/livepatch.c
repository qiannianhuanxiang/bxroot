/*
 * livepatch.c —— 最小化运行时指令补丁（seccomp 中和）
 *
 * ====================================================================
 * 为什么必须做（实测证据链）
 * ====================================================================
 *
 * 最小复现：一个只做 pthread_create 的程序。
 *
 *     仅加载器：       pthread_create 返回 0 → 进程立即死于 159
 *     加本补丁后：     pthread_create 返回 0 → join 完成 → rc=0 ✅
 *
 * 根因：`宿主 loader` 给进程装了 seccomp 过滤器，**逐个列举**了 80+ 个
 * 系统调用号以 KILL_PROCESS 方式禁止（425/426/427 在内，424 不在）。
 * 被禁止的调用一旦发出，内核直接杀死进程 —— **不投递信号**，因此
 * 任何 SIGSYS 处理器都无法挽救（我们的处理器实测一次都没被调用）。
 *
 * 关键认知：`syscall()` 符号接管**不足以**解决，因为 glibc 内部有
 * **内联 `svc`**，它们不经 PLT、不经任何导出符号。
 *
 * ====================================================================
 * 补丁策略：把 `svc #0` 中和成"立即成功返回"
 * ====================================================================
 *
 * 参考实现的做法是把 `svc #0`（0xd4000001）改写成
 * `mov x0, #0`（0xd2800000）—— 即让该系统调用**报告成功且返回值 0**。
 * 单条指令，无需代码洞，不改变指令长度，最安全。
 *
 * 但**不能对所有站点一刀切**：某些站点的 `svc` 之后紧跟错误检查
 * （如 `cmn w0,#1,lsl#12` / `b.lt`），返回 0 会被当作成功而跳过初始化。
 * 因此本模块采用**站点表**，逐点声明语义。
 *
 * 站点来源：
 *   - `set_robust_list`(99) / `rseq`(293) / `_Fork`(99)：子代理通过
 *     活体内存比对（218 个差异字）确证的官方补丁点
 *   - `clone3`(435)：本轮实测发现（补丁后 pthread_create 从死变活）
 *
 * ====================================================================
 * 克制原则
 * ====================================================================
 * bxroot 的架构优势是"用 glibc 原生 ld.so"，而活体补丁正是官方
 * issue #22/#23 的来源。因此本模块：
 *   1. **只补站点表里列出的地址**，不扫描、不启发式、不批量改写
 *   2. **补丁前逐字节校验**原指令，不匹配即放弃
 *   3. **失败不致命**，静默跳过并保留原有行为
 *
 * ====================================================================
 * ★ 门控（P1 修复，2026-09-17）★
 * ====================================================================
 * 原实现在**任何**环境都无条件动手：把 libc 代码页 mprotect 成 RWX，
 * 再逐字节改写站点。这套动作在 Android（宿主 loader 装了 seccomp
 * 白名单）里是必需的，但在**没有**那套白名单的环境（普通 Ubuntu、
 * 其它容器）里是纯风险：
 *
 *   1. **毫无收益** —— 没有白名单要绕，那些 svc 本来就能正常执行
 *      （本容器实测：内联 svc 直发 set_robust_list(99) / rseq(293)
 *       分别得到 -38/ENOSYS，**都不是被 KILL**，所以没有东西要中和）
 *   2. **可能崩** —— mprotect 库代码页 + 逐字节写是可写代码页操作，
 *      在带 W^X / SELinux 域转换 / 完整性校验的受限环境里会直接挂
 *      （报告实测：bxroot_livepatch_apply() 一点就 SIGSEGV，
 *       连崩溃现场都来不及打印）
 *
 * 所以加门控。三道门，**都是"跳过"而不是"失败"** —— 调用方本来就把
 * 本层当尽力而为的优化，跳过不该有任何副作用：
 *
 *   ① BXROOT_NO_LIVEPATCH=1        硬开关（用户/脚本强制关）
 *   ② prctl(PR_GET_SECCOMP) != 2   当前进程没有过滤器 → 本层与环境无关
 *   ③ glibc 版本 != 站点表声明版本  偏移不可信 → 跳过 + 告警（P2-4.1）
 *
 * ★ 门的顺序是有意的：seccomp 门在版本门之前 ★
 * 版本告警是给"本来要打补丁、结果打不上"的场景用的。没有 seccomp 的
 * 环境连补丁都不需要，再报一行"站点表过期"只是噪声 —— 而 LD_PRELOAD
 * 的构造函数**每个 exec 都跑一次**，噪声会被放大成刷屏。反过来，只要
 * seccomp 在（= 真机场景），版本不符就一定会报出来，不会静默。
 *
 * ====================================================================
 * ★ 边界一：PR_GET_SECCOMP 判不出"这是不是 Android 那套过滤器" ★
 * ====================================================================
 * prctl(PR_GET_SECCOMP) 的三个取值（内核 ABI）：
 *
 *     0 = 没有过滤器
 *     1 = SECCOMP_MODE_STRICT（只放行 read/write/_exit/sigreturn）
 *     2 = SECCOMP_MODE_FILTER（装了 BPF 过滤器）
 *
 * ★ 该判据的局限：返回 2 只证明"**存在某个** seccomp 过滤器"，
 *   证明不了"这是 Android 那套需要中和的白名单"。★
 *
 * 实测证据（本容器）：
 *   - 自己装一个**只对 chmod 返回 ENOSYS** 的极简过滤器（3 条 BPF 指令，
 *     与 Android 白名单毫无关系）→ PR_GET_SECCOMP 同样返回 2；
 *   - 该过滤器下，站点里的 set_robust_list(99)/rseq(293) 照常正常执行。
 * 也就是说本判据必然存在两类误判，方向相反：
 *
 *   误**跳过**（有白名单却说没有）：本判据不会发生 —— 它只对 0/1 跳过，
 *     而 Android 白名单一定让 PR_GET_SECCOMP 读到 2。
 *   误**执行**（过滤器不是白名单却说"有"）：**会发生**，且无法从 prctl
 *     的返回值里区分。这时补丁会照打。
 *
 * ★ 为什么仍然接受这个不精确的判据 ★
 * 因为"误执行"一侧有**站点表自身的逐字节校验**兜底，"误跳过"一侧没有：
 *
 *   - 误执行 → patch_one 先比对原指令是否 `svc #0`。非 Android 的过滤器
 *     不会改变 libc 的**字节**，所以校验照样通过、补丁照样打上；语义上
 *     把这两个调用变成"成功 / ENOSYS"。而这正是内核在过滤器下**本来就
 *     会给**的结果（本容器实测两个号都返回 -38 = ENOSYS），不制造新的
 *     不一致。风险是"多做了一件没必要的事 + 一次可写代码页窗口"，
 *     **不是崩溃**。
 *   - 误跳过 → 在真机上必然死于 159（Bad system call），而且**无法挽救**
 *     （seccomp 以 KILL_PROCESS 处理，不投递信号，实测 SIGSYS 处理器
 *     一次都没被调用）。真机是主战场，这一侧不能赌。
 *
 * 所以门控写成"**宁可多跑一次 livepatch，不可在 Android 上误跳过**"：
 *   - 只有明确读到"没有过滤器"（0 / 1）才跳过；
 *   - prctl **调用失败**（返回 -1，例如极老内核不认 PR_GET_SECCOMP）时
 *     **不跳过**，照常打补丁 —— 未知一律按"可能有过滤器"处理。
 *
 * 【兜底够不够？】站点表的"校验失败即跳过"能兜住"该地址上不是 svc"
 * 这一类问题（换编译器/换 glibc 导致布局漂移），但兜不住"过滤器不是
 * 白名单、而站点确实是 svc"—— 后者**不需要**兜，理由见上。真正还需要
 * 额外兜的是"换 glibc 版本让偏移整体漂移、校验失败、补丁一条都没打"
 * 这类**静默失效**，那由门 ③ 的运行期版本断言负责（见下）。
 *
 * ====================================================================
 * ★ 边界二：站点表写死 glibc 2.39 偏移，换版本会静默失效（P2-4.1）★
 * ====================================================================
 * 表里的 0x855c4 / 0x85850 是 Ubuntu 24.04 glibc **2.39**（aarch64）的
 * 偏移。换一个 glibc，最坏情况是逐字节校验失败 → hits=0 → 补丁一条都
 * 没打，而进程照样启动、一句话都不说。真机上这等于**静默**失去 pthread
 * 能力 —— 现象（pthread_create 死 159）离原因（libc 换了）极远。
 *
 * 所以在动手之前先做**运行期版本断言**：读当前 libc 版本，与站点表声明
 * 的版本比对，不一致就打印一行清晰告警并跳过。
 *
 * ★ 为什么用严格相等而不是"major.minor >=" ★
 * 站点偏移是**版本精确绑定**的：2.40 相对 2.39 的布局没有任何兼容保证。
 * "大于等于"会放过一次真实的不匹配，让补丁打在错的地址上（虽然有逐字节
 * 校验，但那是"更坏情况是没生效"，不该拿它当版本检查的替代）。
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <gnu/libc-version.h>

#include "livepatch.h"

/* ------------------------------------------------------------------ */
/* 门控                                                                */
/* ------------------------------------------------------------------ */

/*
 * 站点表覆盖的 glibc 版本清单（供告警文案与访问器用）。
 * **增删表就必须同时改这里** —— 两者是同一条信息的两个副本。
 * 真正的选表逻辑看 g_tables（按 gnu_get_libc_version() 精确匹配）。
 */
#define LP_SITE_LIBC_VERSION "2.39/2.41"

/*
 * 强制跳过开关。值语义与 BXROOT_FAKEROOT / BXROOT_VERBOSE 一致：
 * atoi() != 0 即生效，所以 `=1` 关，`=0`（或未设）不关。
 * 用 `=0` 而不是"删除变量"来表达"不关"，是为了让上层脚本能**覆盖**
 * 父进程环境里的 `=1`（删不掉，只能改值）。
 */
#define LP_ENV_OFF "BXROOT_NO_LIVEPATCH"

/*
 * 本模块只对 aarch64 有意义：站点表里是 aarch64 的指令编码
 * （0xd4000001 / 0xd2800000），其它架构上这两个偏移对应的字节
 * 完全是别的东西。用编译期常量 + 一条运行期判断实现，好处是
 * 非 aarch64 分支**照样参与编译**（不会变成没人编译过的死代码）。
 */
#if defined(__aarch64__)
#define LP_ARCH_OK 1
#else
#define LP_ARCH_OK 0
#endif

/* ------------------------------------------------------------------ */
/* 站点表                                                              */
/* ------------------------------------------------------------------ */

#define SVC_INSN   0xd4000001u      /* svc #0            */
#define MOV_X0_0   0xd2800000u      /* mov x0, #0                  */
/*
 * `mov x0, #-38` —— 即返回 ENOSYS。
 *
 * 与"返回 0（成功）"的区别至关重要：内核不支持某个系统调用时，
 * 正确的返回值就是 -ENOSYS，调用方（glibc）会据此走**回退路径**。
 * 谎报成功会让上层以为设施已就绪，而实际并没有 —— 后果见站点表里
 * rseq 那一条的注释。
 *
 * ★ 现状备注（2026-09-17 门控修复时核对）★
 * 本宏目前**没有任何站点在用** —— 下面站点表的两条都是 MOV_X0_0。
 * 保留它是为了不改动既有站点语义（本修复只加门控，不动补丁内容），
 * 同时把"rseq 该给 0 还是该给 ENOSYS"这个悬而未决的问题留在原处。
 * 实测佐证：外层 runtime 在活体 libc 上把 rseq(293) 站点也改成了
 * `mov x0,#0`（本容器活体内存比对：0x85850 = 0xd2800000），且
 * dsh/node 在该补丁下运行正常 —— 所以 MOV_X0_0 这条路是走得通的。
 */
#define MOV_X0_ENOSYS 0x928004a0u   /* mov x0, #-38 (ENOSYS)       */

typedef struct {
    unsigned long off;       /* 相对 libc 基址的偏移 */
    unsigned int  patch;     /* 改写成哪条指令       */
    const char   *what;      /* 该系统调用是什么     */
    long          nr;        /* 系统调用号           */
} lp_site;

/*
 * glibc 里需要中和的内联 svc 站点。
 *
 * 这些地址对应 Ubuntu 24.04 glibc 2.39（aarch64）。每个站点在打补丁
 * 前都会校验是否为 `svc #0`，因此换一个 glibc 版本时最坏情况是
 * **不生效**，而不会打错位置。
 */
/*
 * 站点表。**每条都要单独想清楚"返回什么"** —— 不能一刀切。
 *
 * 实测教训：先前两者都写成"返回 0（成功）"，结果 `dsh web` 不再崩溃，
 * 但**主线程进入 100% CPU 死循环**（state=R，utime 持续上涨，
 * 不发起任何系统调用）。用看门狗线程 dump 栈，定位到：
 *
 *     libc+0x85844:  mov  x8, #0x125   ; 293 = rseq
 *
 * 即 rseq 注册点。**谎报成功**让 glibc 以为 rseq 已就绪，于是它按
 * "有 rseq"的路径去初始化每个新线程 —— 而内核侧根本没有该注册，
 * 线程状态与 glibc 的预期不一致，最终在 __clone 返回路径上反复重试。
 *
 * 对照实验：
 *     不打补丁        → Bad system call（159）
 *     两处都返回 0    → 主线程死循环
 *     下面这个组合    → 正常
 *
 * 【判据】内核若真的不支持某系统调用，它返回的就是 -ENOSYS。
 * 我们要做的是**如实模拟"这个内核对它不支持"**，而不是假装成功。
 * 对 set_robust_list 而言返回 0 是安全的（该设施是可选优化，
 * glibc 对"调用成功"与"根本没这个调用"都能工作）；
 * 对 rseq 则必须返回 ENOSYS。
 */
/*
 * ★ 站点表按 glibc 版本分表（2026-09-26）★
 *
 * 【起因】Debian 13 rootfs（glibc 2.41）下，任何经 bxroot exec 钩子
 * 重入的进程，其 `fork()`/`_Fork()` 出的子进程 100% 死于 SIGSYS(159)：
 *
 *     bxroot-run --rootfs <trixie> -- /bin/sh -c '/bin/sh -c "/bin/true"'
 *     → Bad system call（第二层 sh 的每个子进程）
 *
 * 逐条系统调用用内联 svc 复刻 _Fork 子进程的动作后定位到：
 * **在全信号屏蔽状态下发出 set_robust_list(99)**。宿主 seccomp 对 99
 * 是 TRAP；SIGSYS 被屏蔽时内核不投递而直接杀进程（159）。
 *
 *     child: rawblock + raw99  → sig=31     ← 屏蔽 + 99 = 死
 *     child: rawblock only     → 正常       ← 只屏蔽不死
 *     parent unblocked  raw99  → -38 ENOSYS ← 不屏蔽时由处理器兜住
 *
 * 而 glibc 2.41 的 `_Fork` 正是这个形态：它先调 `__abort_lock_rdlock`
 * 用**内部** rt_sigprocmask 屏蔽全部信号（不经任何导出符号，bxroot 的
 * sigprocmask 钩子与裸 syscall() 钩子都拦不到），再在子进程里内联 svc
 * 发 set_robust_list。2.39 的 `_Fork` 没有那一步屏蔽，所以同一个站点
 * 漏补在 2.39 上只表现为"多进一次 SIGSYS 处理器"，看不出来。
 *
 * 所以两件事都得做：
 *   1. 站点表必须覆盖 `_Fork` 里的 99 站点（此前只补了 pthread_create
 *      路径那一个，两个版本都漏了它）；
 *   2. 版本门不再是"不是 2.39 就整体跳过"，而是按当前版本**选表**；
 *      没有表的版本才跳过 + 告警（语义不变：不打错位置、要出声）。
 *
 * 偏移由 `objdump -d libc.so.6` 逐条核对（`mov x8,#nr` 后 12 条内的
 * `svc #0`），打补丁前仍逐字节校验 svc，换小版本最坏是不生效。
 *
 * 【为什么第一层进程在 2.41 下没事、第二层才死】bxroot-run 直接启动
 * 的首进程由外层 proroot 的 linker 加载**容器自己的** glibc 2.39
 * （见 /proc/self/maps）；只有经 exec 钩子重入 trampoline 的进程才
 * 真正加载 --rootfs 里的 2.41。这也是为什么这个缺陷藏在"两层 sh"后面。
 */
static const lp_site g_sites_2_39[] = {
    { 0x855c4UL, MOV_X0_0,      "set_robust_list", 99  },
    { 0xbd3d0UL, MOV_X0_0,      "_Fork set_robust_list", 99 },
    { 0x85850UL, MOV_X0_0,      "rseq",            293 },
    /*
     * ★ `__spawni` 里的身份内联 svc（新增，2026-09-20）★
     *
     * 【为什么必须补这两条】
     *
     * `posix_spawn(..., POSIX_SPAWN_RESETIDS, ...)` 会让 glibc 在
     * **子进程里**把 uid/gid 重置回真实值。这段代码在 `__spawni` 内部，
     * 用的是**自己的内联 svc**，不经过 `setresuid`/`setresgid` 的
     * 导出符号 —— 所以 bxroot 的符号钩子和 `syscall()` 钩子都拦不到。
     *
     * 更要命的是：glibc 创建这个子进程用的是
     *     clone3(CLONE_VM|CLONE_VFORK|CLONE_CLEAR_SIGHAND)
     * `CLONE_CLEAR_SIGHAND`（bit 32）会**把所有信号处置重置为默认**，
     * 包括 bxroot 安装的 SIGSYS 处理器。于是：
     *
     *     子进程 SIGSYS = SIG_DFL
     *       → 内联 svc setresgid 撞上外层 seccomp 的 TRAP
     *       → 没有处理器可投递（且是 KILL_PROCESS 类）
     *       → 子进程被直接杀死，父进程 wait4 收到
     *         "{WIFSIGNALED(s) && WTERMSIG(s) == SIGSYS}"
     *
     * 最小复现（本容器实测，A/B/C 三方对照）：
     *
     *     posix_spawnattr_setflags(&a, POSIX_SPAWN_RESETIDS);
     *     posix_spawn(&p, "/bin/echo", NULL, &a, av, environ);
     *
     *     无 runtime      → child rc=0          ✅
     *     官方 proroot    → child rc=0          ✅
     *     bxroot          → child sig=31 (SIGSYS) ❌
     *
     * 【为什么这直接解释 `make` 完全不可用】
     *
     * GNU make 用 `posix_spawn` 起配方子进程，并且**总是**设
     * `POSIX_SPAWN_RESETIDS`。所以每条 recipe 的子进程都在
     * `setresgid` 上被杀 —— 表现为：
     *
     *     $ make
     *     make: *** [Makefile:2: all] Bad system call    ← strerror(SIGSYS)
     *
     * 【修成什么值】返回 0（成功）。
     *
     * 判据来自这两处站点的**后续指令**：svc 之后紧跟
     *     cmn  x0, #0x1, lsl #12    ; 检查 x0 是否在 -4095..-1
     *     b.hi <error>
     *     cbz  x0, <ok>
     * 即"x0 == 0 视为成功"。所以 MOV_X0_0 与 glibc 的预期一致。
     *
     * 这一点与 rseq 那条（必须 ENOSYS）**不同**，逐条判断而不是
     * 一刀切，理由见上方站点表头的说明。
     *
     * 【安全性】与其余站点同款：打补丁前逐字节校验 `svc #0`，
     * 换 glibc 版本时最坏是"不生效"，不会打错位置。
     */
    { 0xd6fa0UL, MOV_X0_0,      "__spawni setresuid", 147 },
    { 0xd7160UL, MOV_X0_0,      "__spawni setresgid", 149 },
};

/* Debian 13 (trixie) glibc 2.41-12+deb13u4，aarch64。同一套站点，偏移不同。 */
static const lp_site g_sites_2_41[] = {
    { 0x85f6cUL, MOV_X0_0,      "set_robust_list", 99  },
    { 0xbfc08UL, MOV_X0_0,      "_Fork set_robust_list", 99 },
    { 0x86224UL, MOV_X0_0,      "rseq",            293 },
    { 0xda1e0UL, MOV_X0_0,      "__spawni setresuid", 147 },
    { 0xda3a0UL, MOV_X0_0,      "__spawni setresgid", 149 },
};

typedef struct {
    const char    *version;   /* gnu_get_libc_version() 的精确值 */
    const lp_site *sites;
    size_t         n;
} lp_table;

#define LP_TBL(v, arr) { v, arr, sizeof(arr) / sizeof((arr)[0]) }
static const lp_table g_tables[] = {
    LP_TBL("2.39", g_sites_2_39),
    LP_TBL("2.41", g_sites_2_41),
};
#define NTABLES (sizeof(g_tables) / sizeof(g_tables[0]))

/* 门控选中的表；命中的版本用它补 147/149。未命中为 NULL（走纯扫描）。 */
static const lp_site *g_sites;
static size_t         g_nsites;

#define NSITES g_nsites

/*
 * ====================================================================
 * ★ 运行期指令扫描（2026-09-27）—— 让 99/293 覆盖任意 glibc 版本 ★
 * ====================================================================
 *
 * 【动机】版本精确表（上面 g_tables）只覆盖 2.39/2.41。换一个 glibc 就
 * 得人肉 objdump 补偏移，否则真机上 fork/pthread 子进程死于 SIGSYS(159)
 * ——因为 set_robust_list(99) 与 rseq(293) 是 glibc 线程/进程初始化里的
 * **内联 svc**，没有导出符号能被 bxroot 的钩子拦到，不打补丁就必死。
 *
 * 【为什么 99/293 可以放心扫全补、147/149 不行】
 *   - 99(set_robust_list)/293(rseq)：glibc 里这两个号**只**出现在
 *     __tls_init_tp / _Fork / pthread 创建路径的内联 svc。它们是可选设施
 *     （内核不支持时本就返回 -ENOSYS），把它们中和成"该内核不支持"对
 *     任何调用方都安全，与落在哪个函数无关。所以按指令形态扫描全补。
 *   - 147/149(setresuid/setresgid)：既有 __spawni 内部站点（要补），也有
 *     **导出符号入口** setresuid()/seteuid() 自身的 svc。bxroot 已用符号
 *     钩子接管导出符号；若把入口 svc 也无条件改成"成功"，非 fakeroot
 *     模式下语义就错了。区分这两类需要符号地址信息，扫描给不了 ——
 *     所以 147/149 仍走版本精确表，未知版本宁可不补（退化为该版本 make
 *     的 RESETIDS 子进程受限），也不冒语义错误的险。
 *
 * 【安全边界】扫描只认"mov x8,#nr 后近距离跟 svc #0"这一确定形态，且
 * 打补丁前逐字节校验 svc（patch_one）。中途遇到另一个写 x8 的 movz 或
 * 分支就放弃本窗口，避免跨站点/跨函数误配。
 */
#define LP_SCAN_WINDOW 12           /* mov x8 到 svc 之间最多隔几条指令 */
#define LP_SCAN_MAX_HITS 32         /* 单个号在 libc 里的站点数上限（实测 ≤3） */

/* 需要扫描中和的系统调用号（只放"落在哪都安全"的）。 */
static const int g_scan_nrs[] = { 99 /* set_robust_list */, 293 /* rseq */ };
#define NSCAN_NRS (sizeof(g_scan_nrs) / sizeof(g_scan_nrs[0]))

/* movz x8, #imm16 的编码（rd=x8, hw=0）：0xd2800008 | (imm<<5)。 */
static uint32_t lp_mov_x8_imm(int nr)
{
    return 0xd2800008u | ((uint32_t)(nr & 0xffff) << 5);
}

static int       g_applied;
static int       g_hits;
static int       g_scan_hits;
static int       g_skip_reason;
static uintptr_t g_base;

/* ------------------------------------------------------------------ */
/* 门控实现                                                            */
/* ------------------------------------------------------------------ */

/*
 * 是否装了 seccomp 过滤器。
 *
 * 返回 1 = 有（PR_GET_SECCOMP == 2）；0 = 明确没有（0 或 1）；
 * 返回 -1 = **问不出来**（prctl 失败）。★ 调用方必须把 -1 当"可能有"
 * 处理，不能当"没有" ★ —— 详见文件头"边界一"。
 *
 * ★ 为什么用 prctl 而不是读 /proc/self/status 的 Seccomp 字段 ★
 * /proc/self/status 需要 fopen/fscanf，而本函数在 LD_PRELOAD 构造函数
 * 里、**可能早于任何 libc 内部初始化**被调用；prctl 是一条系统调用，
 * 无内存分配、无 FILE 状态，依赖面最小。另外 status 里的字段只在
 * 2.6.39+ 才有，而 PR_GET_SECCOMP 同样是 2.6.39 引入的，两者等价，
 * 但 status 多一层 stdio。
 */
int bxroot_livepatch_has_seccomp(void)
{
    int rc = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);

    if (rc < 0)
        return -1;                  /* 问不出来 —— 上层按"可能有"处理 */
    return (rc == 2) ? 1 : 0;       /* 0=无过滤器 1=STRICT 2=FILTER */
}

/*
 * 当前 libc 的版本串（形如 "2.39"）。
 *
 * 用 gnu_get_libc_version()：它是 glibc 自带的**直接调用**（不需要
 * dlsym），返回的就是裸版本号，不用像 confstr(_CS_GNU_LIBC_VERSION)
 * 那样再去剥 "glibc " 前缀。
 *
 * ★ 这里必须用直接调用、不能用 dlsym ★
 * 本文件顶部与 sigsys.c 都记录过同一个坑：在本环境里 dlsym(RTLD_NEXT)
 * 拿到的 libc 地址不可靠（外层做了活体代码补丁），跳进去会 SIGSEGV。
 * gnu_get_libc_version 由链接器在加载期解析，不经过 dlsym，没有这个问题。
 */
static const char *lp_libc_version(void)
{
    const char *v = gnu_get_libc_version();

    if (v == NULL || v[0] == '\0')
        return NULL;                /* 拿不到版本 —— 上层按"不确定"处理 */
    return v;
}

/* BXROOT_VERBOSE 是否打开（语义与 preload.c 的 init_config 一致）。 */
static int lp_verbose(void)
{
    const char *e = getenv("BXROOT_VERBOSE");

    return (e != NULL && atoi(e) != 0) ? 1 : 0;
}

/* 诊断输出。构造函数里 stdio 可用（实测），不引额外依赖。 */
static void lp_say(const char *s)
{
    if (s != NULL) {
        ssize_t r = write(2, s, strlen(s));
        (void)r;
    }
}

/*
 * 门控判定。返回 LP_SKIP_*（0 = 不跳过，可以动手）。
 *
 * 顺序：env → arch → seccomp → 版本。理由见文件头。
 */
static int lp_gate(void)
{
    const char *e;
    int sec;
    const char *ver;

    /* ---- 门 ①：硬开关 ---- */
    e = getenv(LP_ENV_OFF);
    if (e != NULL && atoi(e) != 0) {
        lp_say("[bxroot] livepatch: " LP_ENV_OFF "=");
        lp_say(e);
        lp_say(" → 已跳过（硬开关）\n");
        return LP_SKIP_ENV;
    }

    /* ---- 门 ②：架构 ---- */
    if (!LP_ARCH_OK) {
        /* 非 aarch64 上这里**根本不该被跑到**（站点表是 aarch64 指令），
         * 但万一被跑到，唯一正确的动作是别碰那些字节。 */
        lp_say("[bxroot] livepatch: 非 aarch64 架构，站点指令编码不适用 → 已跳过\n");
        return LP_SKIP_ARCH;
    }

    /* ---- 门 ③：seccomp 过滤器 ---- */
    sec = bxroot_livepatch_has_seccomp();
    if (sec == 0) {
        /*
         * 明确没有过滤器（MODE_DISABLED 或 MODE_STRICT）。没有白名单
         * 要绕 ⇒ 本层毫无收益 ⇒ 跳过。**默认静默**：这是非 Android
         * 环境的正常路径，每进程打印一行会变成噪声。
         * BXROOT_VERBOSE=1 时打一行，便于排障时确认门控判据。
         */
        if (lp_verbose())
            lp_say("[bxroot] livepatch: 无 seccomp 过滤器 → 已跳过（环境不需要）\n");
        return LP_SKIP_NO_SECCOMP;
    }
    if (sec < 0 && lp_verbose()) {
        /* ★ 关键：未知不跳过 ★ 见文件头"边界一"。 */
        lp_say("[bxroot] livepatch: prctl(PR_GET_SECCOMP) 失败，"
               "按\"可能有过滤器\"处理，继续打补丁\n");
    }

    /* ---- 门 ④：libc 版本（决定 147/149 精确表是否可用）----
     *
     * ★ 语义变更（2026-09-27）★ 版本不符**不再整体跳过**。99/293 由
     * 运行期指令扫描覆盖（对任意版本都安全，见 g_scan_nrs 处的说明）；
     * 版本表只用于 147/149 这类"扫描给不了符号信息、不能全补"的号。
     * 所以：读不到版本 / 版本没登记 → g_sites=NULL，仅少补 147/149，
     * 不再放弃 99/293（那才是 fork/pthread 必死的根因）。
     */
    ver = lp_libc_version();
    g_sites = NULL;
    g_nsites = 0;
    if (ver != NULL) {
        size_t t;
        for (t = 0; t < NTABLES; t++) {
            if (strcmp(ver, g_tables[t].version) == 0) {
                g_sites = g_tables[t].sites;
                g_nsites = g_tables[t].n;
                break;
            }
        }
    }
    if (g_sites == NULL && lp_verbose()) {
        lp_say("[bxroot] livepatch: glibc ");
        lp_say(ver ? ver : "(未知)");
        lp_say(" 无精确站点表 → 99/293 走指令扫描，147/149 本版不补\n");
    }

    return LP_SKIP_NONE;
}

/* ------------------------------------------------------------------ */
/* 基址解析                                                            */
/* ------------------------------------------------------------------ */

/*
 * 用 /proc/self/maps 找 libc 基址。
 *
 * 不用 dladdr/dlsym：实测该环境下其返回值不可靠（外层做了活体补丁）。
 * maps 由内核提供，最可信。
 */
static uintptr_t find_libc_base(void)
{
    FILE *f = fopen("/proc/self/maps", "r");
    char line[1024];
    uintptr_t base = 0;

    if (f == NULL)
        return 0;

    while (fgets(line, sizeof(line), f) != NULL) {
        unsigned long long a, b, off;
        char perms[8];

        if (sscanf(line, "%llx-%llx %7s %llx", &a, &b, perms, &off) < 4)
            continue;
        if (off != 0)                       /* 只取文件起始段 = 基址 */
            continue;
        if (strstr(line, "libc.so.6") == NULL)
            continue;
        base = (uintptr_t)a;
        break;
    }
    fclose(f);
    return base;
}

/* ------------------------------------------------------------------ */
/* 应用                                                                */
/* ------------------------------------------------------------------ */

static int patch_one(uint32_t *p, const lp_site *s)
{
    if (*p != SVC_INSN)
        return 0;               /* 不是 svc，跳过（版本不同/已打过） */

    *p = s->patch;              /* svc #0 → 站点指定的指令 */
    __builtin___clear_cache((char *)p, (char *)p + 4);
    return 1;
}

/*
 * 找 libc.so.6 的**可执行**段范围 [lo,hi)（r-xp 的那一段），供扫描界定。
 * 只扫这一段：数据段里可能恰好有等于 svc/mov 编码的字节，扫到就会误判。
 * 返回 0 = 没找到。
 */
static int find_libc_exec_range(uintptr_t *lo_out, uintptr_t *hi_out)
{
    FILE *f = fopen("/proc/self/maps", "r");
    char line[1024];
    int found = 0;

    if (f == NULL)
        return 0;

    while (fgets(line, sizeof(line), f) != NULL) {
        unsigned long long a, b, off;
        char perms[8];

        if (sscanf(line, "%llx-%llx %7s %llx", &a, &b, perms, &off) < 4)
            continue;
        if (strstr(line, "libc.so.6") == NULL)
            continue;
        if (perms[2] != 'x')                 /* 只要可执行段 */
            continue;
        *lo_out = (uintptr_t)a;
        *hi_out = (uintptr_t)b;
        found = 1;
        break;
    }
    fclose(f);
    return found;
}

/*
 * ====================================================================
 * ★ 静态链接 guest 的主映像扫描（2026-09-28）★
 * ====================================================================
 *
 * 【为什么必须补】静态链接（gcc -static）的 guest 里，glibc 的代码在
 * **主可执行映像自己的 .text**，而不是独立的 libc.so.6 段。于是：
 *   - find_libc_base() 找不到 libc.so.6 → g_base=0 → apply() 早退 -1；
 *   - find_libc_exec_range() 也找不到 libc.so.6 的 r-x → 扫描一条不扫。
 * 结果静态 guest 的 set_robust_list(99)/rseq(293) 内联 svc 一个都没中和。
 *
 * 【实测残余的真实性（本容器 vs 真机）】
 * 本容器嵌套在外层 proroot 上，外层会把静态主映像里**紧凑形态**
 * （mov x8,#99|#293 后≤2 条即 svc）的站点预打成 mov x0,#0，所以看起来
 * 静态多线程也活 —— 那是外层的功劳，不是 bxroot。实测：
 *   - 直接跑静态线程程序（含 BXROOT_NO_LIVEPATCH=1）站点已 PATCHED；
 *   - 但**带栈 spill 的间隔站点**（mov x8,#99 → str/ldr x8 → svc）外层
 *     漏补，UNPATCHED；masked set_robust_list 实测 DIED sig=31（SIGSYS
 *     KILL_PROCESS，处理器投递不了）。
 * 真机（Termux）没有外层 proroot，这些站点**全部**要 bxroot 自己补，
 * 否则 pthread_create 的新线程在 clone 前掩全信号、start_thread 内联发
 * set_robust_list → 被杀（159）。这正是 docs/真机验证清单.md 记的残余。
 *
 * 【安全边界（与 libc 扫描同款，且更克制）】
 *   - **只在没有独立 libc.so.6 r-x 段时**（= 静态链接特征）才扫主映像，
 *     动态 guest 一律不碰主映像（它的 99/293 在 libc.so.6 里，已被覆盖），
 *     把误配/性能面限制到"确实是静态"这一种情形；
 *   - 扫描逻辑复用 lp_scan_and_patch：只认 mov x8,#99|#293 近距离跟 svc#0
 *     的确定形态，打补丁前逐字节校验 svc，中途遇到再写 x8 或分支即放弃；
 *   - 99/293 中和成"该内核不支持"（rseq 走回退、robust list 降级）对任何
 *     调用方安全 —— 这是本模块既定前提（见 g_scan_nrs 处说明），落在主
 *     程序 .text 还是 libc .text 不改变这一点。
 *
 * 【主映像段如何认定 —— 用代码地址锚点，不用路径匹配】
 * 不能拿 /proc/self/exe 的路径去 maps 里比：proroot 类路径翻译下
 * /proc/self/exe 是 **guest 视角**（如 /tmp/prog），而 maps 里是**内核
 * 视角**（如 <rootfs>/tmp/prog），两者前缀不同，字符串比会漏。
 * 而本函数只在静态链接情形被调用 —— 静态链接把本模块的代码也编进主
 * 映像，所以**本函数自己的地址**必落在主映像的 r-x 段内。用它当锚点
 * 找"包含该地址的 r-x 段"，与路径无关、与视角无关。
 * 返回 0 = 没找到（读不到 maps / 无匹配段 → 不扫，退化为原行为）。
 */
static int find_main_exec_range(uintptr_t *lo_out, uintptr_t *hi_out)
{
    /* 锚点：本函数自身的地址。静态链接时它就在主可执行映像的 .text。 */
    uintptr_t anchor = (uintptr_t)(void *)&find_main_exec_range;
    FILE *f;
    char line[1024];
    int found = 0;

    f = fopen("/proc/self/maps", "r");
    if (f == NULL)
        return 0;

    while (fgets(line, sizeof(line), f) != NULL) {
        unsigned long long a, b, off;
        char perms[8];

        if (sscanf(line, "%llx-%llx %7s %llx", &a, &b, perms, &off) < 4)
            continue;
        if (perms[2] != 'x')                 /* 只要可执行段 */
            continue;
        if (anchor < (uintptr_t)a || anchor >= (uintptr_t)b)
            continue;                        /* 锚点不在本段 → 不是主映像段 */
        *lo_out = (uintptr_t)a;
        *hi_out = (uintptr_t)b;
        found = 1;
        break;
    }
    fclose(f);
    return found;
}

/*
 * 扫描 [lo,hi) 内的指令，把 g_scan_nrs 里的号对应的内联 svc 中和为
 * `mov x0,#0`。返回改写的站点数。已在 g_sites 版本表里出现过的偏移
 * 会被后续 apply 再校验一次 svc（幂等，patch_one 只认 svc），不会重打。
 *
 * 形态：mov(z) x8,#nr  →（≤LP_SCAN_WINDOW 条内，中途不得再写 x8/不得分支）→ svc #0
 */
static int lp_scan_and_patch(uintptr_t lo, uintptr_t hi)
{
    uint32_t *code = (uint32_t *)lo;
    size_t n = (hi - lo) / 4;
    size_t j;
    int total = 0;
    size_t s;

    for (j = 0; j < n; j++) {
        int matched_nr = 0;
        size_t t;

        for (t = 0; t < NSCAN_NRS; t++) {
            if (code[j] == lp_mov_x8_imm(g_scan_nrs[t])) {
                matched_nr = 1;
                break;
            }
        }
        if (!matched_nr)
            continue;

        for (s = 1; s <= LP_SCAN_WINDOW && j + s < n; s++) {
            uint32_t ins = code[j + s];

            if (ins == SVC_INSN) {
                uint32_t *p = &code[j + s];
                if (*p == SVC_INSN) {
                    *p = MOV_X0_0;
                    __builtin___clear_cache((char *)p, (char *)p + 4);
                    total++;
                    if (total >= LP_SCAN_MAX_HITS)
                        return total;
                }
                break;
            }
            /* 又一次写 x8（movz x8,#..）或任何分支 → 放弃本窗口，避免误配。
             * movz x8,#imm16 编码：0xd2800008 | (imm<<5)，imm 占 bit5..20，
             * 故掩掉 imm 位后比较；B/BL：bit31..26 = 000101/100101。 */
            if ((ins & 0xffe0001fu) == 0xd2800008u)
                break;
            if ((ins >> 26) == 0x05u || (ins >> 26) == 0x25u)
                break;
        }
    }
    return total;
}

#ifdef LP_TEST_HOOK
/*
 * 测试专用：对一段调用方提供的机器码缓冲跑扫描逻辑（不碰 /proc、不
 * mprotect）。让离线测试能构造合成站点、断言"哪些 svc 被改成 mov x0,#0、
 * 哪些没被碰"。仅在 -DLP_TEST_HOOK 下编入，生产构建不含。
 */
int bxroot_livepatch_scan_buffer_for_test(uint32_t *buf, size_t words)
{
    return lp_scan_and_patch((uintptr_t)buf, (uintptr_t)(buf + words));
}
#endif

int bxroot_livepatch_apply(void)
{
    long pg;
    uintptr_t lo = 0, hi = 0;
    size_t i;
    int skip;

    if (g_applied)
        return 0;

    /*
     * ★ 门控必须在**任何** mprotect / 写内存之前 ★
     * 报告实测的崩溃点正是"mprotect 整个 libc 代码页成 RWX"这一步：
     * 一旦先把页改成可写、再发现环境不对，窗口已经打开了。所以三道门
     * 全部前置，一处内存属性都不碰。
     */
    skip = lp_gate();
    /*
     * ★ 无条件记录，**包括 LP_SKIP_NONE** ★
     * 否则本函数被调用两次（第一次跳过、第二次不跳）时，skip_reason
     * 会残留上一次的值 —— 一个"看起来还在被跳过"的假象。本进程实际
     * 只调用一次，但访问器不该依赖调用次数才正确。
     */
    g_skip_reason = skip;
    if (skip != LP_SKIP_NONE)
        return skip;            /* 正数 = 跳过，调用方不该当失败 */

    /*
     * ★ g_base==0 不再早退 ★
     * 静态链接 guest 没有独立 libc.so.6 段，find_libc_base() 必然返回 0。
     * 早先在这里 return -1 会让静态 guest 一条都不补 —— 而它的 99/293
     * 内联 svc 恰恰在主可执行映像自己的 .text 里（见下面第三部分）。
     * 所以 g_base==0 只意味着"版本精确表那部分不做"（它依赖 libc 基址），
     * 不代表"整个 livepatch 无事可做"。
     */
    g_base = find_libc_base();

    pg = sysconf(_SC_PAGESIZE);
    if (pg <= 0)
        return -2;

    /*
     * 第一部分：版本精确表（仅当命中已登记版本 **且**找到了 libc 基址）。
     * 覆盖 147/149 这类扫描不能安全全补的号；99/293 若在表里也会被打，
     * 与扫描重叠但幂等（patch_one 只认 svc，已被扫描改写的就不是 svc 了）。
     */
    if (g_base != 0 && g_sites != NULL && NSITES > 0) {
        for (i = 0; i < NSITES; i++) {
            uintptr_t a = (g_base + g_sites[i].off) & ~(uintptr_t)(pg - 1);
            uintptr_t b = (g_base + g_sites[i].off + 4 + (uintptr_t)pg - 1)
                          & ~(uintptr_t)(pg - 1);
            if (lo == 0 || a < lo) lo = a;
            if (b > hi) hi = b;
        }
        if (lo != 0 && hi > lo &&
            mprotect((void *)lo, (size_t)(hi - lo),
                     PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
            for (i = 0; i < NSITES; i++) {
                uint32_t *p = (uint32_t *)(g_base + g_sites[i].off);
                g_hits += patch_one(p, &g_sites[i]);
            }
        }
    }

    /*
     * 第二部分：运行期扫描，把 99/293 的内联 svc 中和 —— 对任意 glibc
     * 版本生效（这才是 fork/pthread 子进程在 seccomp 下不被 SIGSYS 杀的
     * 关键）。只扫 libc 的 r-x 段；期间把该段临时置为可写，改完复位。
     */
    {
        uintptr_t elo = 0, ehi = 0;
        int have_libc_exec = find_libc_exec_range(&elo, &ehi);

        if (have_libc_exec && ehi > elo) {
            if (mprotect((void *)elo, (size_t)(ehi - elo),
                         PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
                g_scan_hits = lp_scan_and_patch(elo, ehi);
                g_hits += g_scan_hits;
                /* 复位为 r-x，缩小可写代码页窗口（失败不致命，已改完）。 */
                (void)mprotect((void *)elo, (size_t)(ehi - elo),
                               PROT_READ | PROT_EXEC);
            }
        } else if (!have_libc_exec) {
            /*
             * ★ 第三部分：静态链接 guest —— 扫主可执行映像 r-x 段 ★
             * 没有独立 libc.so.6 r-x 段 = 静态链接特征（glibc 代码在主
             * 映像自己的 .text）。这时 99/293 站点在主程序里，第二部分
             * 扫不到，必须扫主映像。**只在这种情形**扫主映像，动态 guest
             * （有 libc.so.6 段）一律不碰主程序，把误配/性能面限制到确
             * 实是静态的场景。安全性同第二部分：形态识别 + 逐字节校验 svc。
             */
            uintptr_t mlo = 0, mhi = 0;
            if (find_main_exec_range(&mlo, &mhi) && mhi > mlo) {
                if (mprotect((void *)mlo, (size_t)(mhi - mlo),
                             PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
                    g_scan_hits = lp_scan_and_patch(mlo, mhi);
                    g_hits += g_scan_hits;
                    (void)mprotect((void *)mlo, (size_t)(mhi - mlo),
                                   PROT_READ | PROT_EXEC);
                }
            }
        }
    }

    /*
     * ★ g_applied 只在**真的改写了至少一个站点**时才置位 ★
     * 原实现无条件置 1，于是"一条都没打上"也会对外报 applied=1 ——
     * 那是"看起来干了活"的假象，正是本项目反复吃过亏的静默失效形态。
     * 现在 applied 与 hits 同源，调用方可以信任它。
     */
    if (g_hits > 0) {
        g_applied = 1;
        if (lp_verbose())
            fprintf(stderr, "[bxroot] livepatch: 已中和 %d 个站点"
                    "（扫描 %d + 版本表 %d）\n",
                    g_hits, g_scan_hits, g_hits - g_scan_hits);
        return 0;
    }
    return -5;
}

int bxroot_livepatch_applied(void)
{
    return g_applied;
}

int bxroot_livepatch_hits(void)
{
    return g_hits;
}

int bxroot_livepatch_scan_hits(void)
{
    return g_scan_hits;
}

int bxroot_livepatch_skip_reason(void)
{
    return g_skip_reason;
}

const char *bxroot_livepatch_site_libc_version(void)
{
    return LP_SITE_LIBC_VERSION;
}

uintptr_t bxroot_livepatch_libc_base(void)
{
    return g_base;
}
