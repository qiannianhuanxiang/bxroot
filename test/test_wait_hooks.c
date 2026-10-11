/*
 * wait hooks: directly call exported runtime functions and verify real child
 * status plus the runtime ledger. A late RTLD_GLOBAL dlopen does NOT guarantee
 * RTLD_NEXT resolves a stub: libc may already precede it in the lookup scope,
 * the runtime may cache a resolver result or use a raw syscall fallback.
 * Test the stub independently through its own handle; never infer PLT injection
 * or a selected forwarding backend from its mere presence in the link map.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* 只取纯逻辑声明（账本原语 + px_procinfo + 枚举），不要钩子层声明 */
#define PX_PURE_LOGIC 1
#include "proc.h"

/*
 * ★ 下面这些一律**不声明**、只留函数指针，运行时用 dlsym 从被测 .so 取 ★
 *
 * 原因：它们在 proc.h 里要么位于钩子层声明区（PX_PURE_LOGIC=0 才可见），
 * 要么定义在 proc.o 里 —— 而本测试**不链接** proc.c（它 dlopen 产物），
 * 直接声明会变成无法解析的外部符号，链接就失败。
 */

/* ---------------- 测试框架 ---------------- */
static int g_cases, g_checks, g_failed;

#define CASE(name) do { g_cases++; printf("- %s\n", name); } while (0)

#define CHECK(cond, fmt, ...) do {                                    \
        g_checks++;                                                   \
        if (cond) {                                                   \
            printf("    ✅ " fmt "\n", ##__VA_ARGS__);                \
        } else {                                                      \
            g_failed++;                                               \
            printf("    ❌ " fmt "   [%s:%d]\n", ##__VA_ARGS__,       \
                   __FILE__, __LINE__);                               \
        }                                                             \
    } while (0)

/* ---------------- 被测函数指针 ---------------- */
static pid_t (*p_waitpid)(pid_t, int *, int);
static pid_t (*p_wait4)(pid_t, int *, int, struct rusage *);
static pid_t (*p_wait3)(int *, int, struct rusage *);
static int   (*p_waitid)(idtype_t, id_t, siginfo_t *, int);

static px_ledger *g_l;
static int        (*p_ledger_add)(px_ledger *, pid_t, pid_t, uint32_t);
static int        (*p_ledger_get)(const px_ledger *, pid_t, px_entry_kind,
                                  px_procinfo *);
static size_t     (*p_ledger_live)(const px_ledger *);
static size_t     (*p_ledger_reaped)(const px_ledger *);
static px_ledger *(*p_runtime_ledger)(void);
static int         (*p_stub_calls)(void);
static void        (*p_stub_reset)(void);

/* Independent kernel oracle: bypass libc/runtime symbol resolution on ARM64. */
static pid_t kernel_wait(pid_t pid, int *status, int options)
{
#if defined(__aarch64__)
    register long x8 __asm__("x8") = SYS_wait4;
    register long x0 __asm__("x0") = pid;
    register long x1 __asm__("x1") = (long)status;
    register long x2 __asm__("x2") = options;
    register long x3 __asm__("x3") = 0;
    __asm__ __volatile__("svc #0" : "+r"(x0)
                         : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory", "cc");
    if (x0 < 0 && x0 >= -4095) { errno = (int)-x0; return -1; }
    return (pid_t)x0;
#else
    return (pid_t)syscall(SYS_wait4, pid, status, options, NULL);
#endif
}

static int kill_owned_child(pid_t pid, int sig)
{
    if (pid <= 0) { fprintf(stderr, "refusing non-positive child pid\n"); exit(1); }
    return kill(pid, sig);
}

static void expect_kernel_reaped(const char *who, pid_t pid)
{
    int st = 0;
    pid_t rc;
    if (pid <= 0) { fprintf(stderr, "invalid oracle pid\n"); exit(1); }
    errno = 0;
    rc = kernel_wait(pid, &st, WNOHANG);
    CHECK(rc == -1 && errno == ECHILD,
          "%s: kernel 确认正 PID %d 已回收（rc=%d errno=%d）",
          who, (int)pid, (int)rc, errno);
}

/* 账本里这个 pid 的 life（取不到时返回 -1） */
static int life_of(pid_t pid)
{
    px_procinfo info;

    memset(&info, 0, sizeof(info));
    if (p_ledger_get(g_l, pid, PX_ENTRY_PID, &info) != PX_OK) {
        return -1;
    }
    return (int)info.life;
}

/* fork 一个子进程并**显式登记**（模拟 proc.c 的 fork 钩子） */
static pid_t spawn_registered(void)
{
    pid_t p = fork();
    if (p < 0) {
        perror("spawn_registered: fork");
        exit(1);
    }

    if (p > 0) {
        if (p_ledger_add(g_l, p, 0, PX_TAG_FORK) != PX_OK) {
            (void)kill_owned_child(p, SIGKILL);
            (void)kernel_wait(p, NULL, 0);
            fprintf(stderr, "ledger registration failed\n");
            exit(1);
        }
    }
    return p;
}

static void case_stub_contract(void *hs)
{
    pid_t (*s_waitpid)(pid_t, int *, int) = dlsym(hs, "waitpid");
    pid_t (*s_wait4)(pid_t, int *, int, struct rusage *) = dlsym(hs, "wait4");
    pid_t (*s_wait3)(int *, int, struct rusage *) = dlsym(hs, "wait3");
    int (*s_waitid)(idtype_t, id_t, siginfo_t *, int) = dlsym(hs, "waitid");
    int i;
    CASE("S0 独立 stub 契约：句柄直调四入口、精确计数和 kernel 状态");
    CHECK(s_waitpid && s_wait4 && s_wait3 && s_waitid && p_stub_calls && p_stub_reset,
          "stub 四入口与计数接口完整");
    if (!(s_waitpid && s_wait4 && s_wait3 && s_waitid && p_stub_calls && p_stub_reset))
        exit(1);
    for (i = 0; i < 4; i++) {
        pid_t p = fork(), rc;
        int st = 0;
        siginfo_t si;
        struct rusage ru;
        if (p < 0) { perror("stub fork"); exit(1); }
        if (p == 0) _exit(20 + i);
        p_stub_reset();
        memset(&si, 0, sizeof si);
        memset(&ru, 0, sizeof ru);
        if (i == 0) rc = s_waitpid(p, &st, 0);
        else if (i == 1) rc = s_wait4(p, &st, 0, &ru);
        else if (i == 2) rc = s_wait3(&st, 0, &ru);
        else {
            int result = s_waitid(P_PID, (id_t)p, &si, WEXITED | WNOWAIT);
            CHECK(result == 0 && si.si_pid == p && si.si_code == CLD_EXITED &&
                  si.si_status == 23, "stub waitid WNOWAIT 保留真实退出状态");
            CHECK(p_stub_calls() == 1, "stub waitid 精确调用数=1（实际%d）", p_stub_calls());
            rc = kernel_wait(p, &st, 0);
        }
        CHECK(rc == p && WIFEXITED(st) && WEXITSTATUS(st) == 20 + i,
              "stub 入口%d交付真实 kernel 子进程状态", i);
        CHECK(p_stub_calls() == 1, "stub 入口%d精确计数=1（实际%d）", i, p_stub_calls());
        expect_kernel_reaped("stub", p);
    }
    p_stub_reset();
}

/* ---------------- 用例 ---------------- */

static void case_exited_normal(void)
{
    pid_t p, rc;
    int st = 0;

    CASE("W1 正常退出：waitpid 返回子进程并把它标 REAPED");
    p = spawn_registered();
    if (p == 0) { _exit(7); }
    CHECK(life_of(p) == PX_LIVE, "fork 后账本状态 = LIVE（%d）", life_of(p));

    rc = p_waitpid(p, &st, 0);
    CHECK(rc == p, "waitpid 返回子 pid（%d）", (int)rc);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 7, "退出码 = 7（%d）",
          WEXITSTATUS(st));
    CHECK(life_of(p) == PX_REAPED, "★账本已标 REAPED（%d）", life_of(p));
    expect_kernel_reaped("waitpid", p);
}

static void case_wnohang_zero(void)
{
    pid_t p, rc;
    int st = 0;

    CASE("W2 ★WNOHANG 返回 0 时不得标 REAPED★（子进程还活着）");
    p = spawn_registered();
    if (p == 0) { sleep(30); _exit(0); }

    rc = p_waitpid(p, &st, WNOHANG);
    CHECK(rc == 0, "WNOHANG 返回 0（%d）", (int)rc);
    /*
     * 这是本文件最重要的一条断言：标错了就再也杀不掉这个孩子
     * （px_check_kill 对 REAPED 一律拒绝），比不实现还糟。
     */
    CHECK(life_of(p) == PX_LIVE, "★账本仍是 LIVE，没有被误标（%d）",
          life_of(p));

    CHECK(kill_owned_child(p, SIGKILL) == 0, "子进程仍可被 kill（说明白名单没被污染）");
    rc = p_waitpid(p, &st, 0);
    CHECK(rc == p && WIFSIGNALED(st), "随后的阻塞 waitpid 正常收到 SIGKILL");
    CHECK(life_of(p) == PX_REAPED, "此时才标 REAPED（%d）", life_of(p));
    expect_kernel_reaped("waitpid(WNOHANG)", p);
}

static void case_wait4(void)
{
    pid_t p, rc;
    int st = 0;
    struct rusage ru;

    CASE("W3 wait4（python3/gcc 走这条）：回收 + 记账");
    memset(&ru, 0, sizeof(ru));
    p = spawn_registered();
    if (p == 0) { _exit(3); }

    rc = p_wait4(p, &st, 0, &ru);
    CHECK(rc == p, "wait4 返回子 pid（%d）", (int)rc);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 3, "退出码 = 3");
    CHECK(life_of(p) == PX_REAPED, "★账本已标 REAPED（%d）", life_of(p));
    expect_kernel_reaped("wait4", p);
}

static void case_wait4_wnohang(void)
{
    pid_t p, rc;
    int st = 0;

    CASE("W4 wait4 + WNOHANG=0 同样不得误标");
    p = spawn_registered();
    if (p == 0) { sleep(30); _exit(0); }

    rc = p_wait4(p, &st, WNOHANG, NULL);
    CHECK(rc == 0, "wait4(WNOHANG) 返回 0（%d）", (int)rc);
    CHECK(life_of(p) == PX_LIVE, "★账本仍是 LIVE（%d）", life_of(p));

    kill_owned_child(p, SIGKILL);
    CHECK(p_wait4(p, &st, 0, NULL) == p, "收尾 wait4 正常");
    CHECK(life_of(p) == PX_REAPED, "收尾后标 REAPED（%d）", life_of(p));
    expect_kernel_reaped("wait4", p);
}

static void case_wait3(void)
{
    pid_t p, rc;
    int st = 0;

    CASE("W5 wait3（= wait4(-1)）：等任意子进程并记账");
    p = spawn_registered();
    if (p == 0) { _exit(5); }

    rc = p_wait3(&st, 0, NULL);
    CHECK(rc == p, "wait3 返回该子 pid（%d）", (int)rc);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 5, "退出码 = 5");
    CHECK(life_of(p) == PX_REAPED, "★账本已标 REAPED（%d）", life_of(p));
    expect_kernel_reaped("wait3", p);
}

static void case_waitid_ppid(void)
{
    pid_t p;
    int rc;
    siginfo_t si;

    CASE("W6 waitid(P_PID)：CLD_EXITED 时记账");
    p = spawn_registered();
    if (p == 0) { _exit(9); }

    memset(&si, 0, sizeof(si));
    rc = p_waitid(P_PID, (id_t)p, &si, WEXITED);
    CHECK(rc == 0, "waitid 返回 0（%d）", rc);
    CHECK(si.si_pid == p && si.si_code == CLD_EXITED,
          "si_pid=%d si_code=CLD_EXITED(%d)", (int)si.si_pid, si.si_code);
    CHECK(life_of(p) == PX_REAPED, "★账本已标 REAPED（%d）", life_of(p));
    expect_kernel_reaped("waitid", p);
}

static void case_waitid_wnohang_empty(void)
{
    /* P_ALL + WNOHANG 且当前无子进程 → 必须「什么都没发生」 */
    siginfo_t si;
    int rc;

    CASE("W7 waitid + WNOHANG 无子进程：si_pid=0，不得把 0 写进账本");
    errno = 0;
    memset(&si, 0, sizeof(si));
    rc = p_waitid(P_ALL, (id_t)0, &si, WEXITED | WNOHANG);
    if (rc == 0) {
        CHECK(si.si_pid == 0, "si_pid = 0（%d）", (int)si.si_pid);
    } else {
        CHECK(errno == ECHILD, "返回 -1 且 errno = ECHILD（%d）", errno);
    }
    /* pid 0 绝不能被记账：它是 kill 的「广播」形态，写进去会污染判定 */
    CHECK(life_of(0) == -1, "账本里没有 pid 0 条目（life=%d）", life_of(0));
}

static void case_stopped_not_reaped(void)
{
    pid_t p, rc;
    int st = 0;

    CASE("W8 ★停住的子进程（WUNTRACED）不得标 REAPED★");
    p = spawn_registered();
    if (p == 0) {
        /* 等父进程把它停下来，再退出 */
        for (;;) { pause(); }
    }

    usleep(100000);
    kill_owned_child(p, SIGSTOP);
    rc = p_waitpid(p, &st, WUNTRACED);
    CHECK(rc == p, "waitpid(WUNTRACED) 返回子 pid（%d）", (int)rc);
    CHECK(WIFSTOPPED(st), "状态是「已停止」而非退出");
    /*
     * 只停住没退出：还能被继续 wait。标 reaped 会让 kill 永久失效。
     */
    CHECK(life_of(p) == PX_LIVE, "★账本仍是 LIVE（%d）", life_of(p));

    kill_owned_child(p, SIGCONT);
    kill_owned_child(p, SIGKILL);
    rc = p_waitpid(p, &st, 0);
    CHECK(rc == p && WIFSIGNALED(st), "继续后仍能正常回收");
    CHECK(life_of(p) == PX_REAPED, "退出后才标 REAPED（%d）", life_of(p));
}

static void case_wnowait_compat(void)
{
    pid_t p, rc;
    int st = 0;

    CASE("W9 WNOWAIT 兼容：本内核 wait4 不支持该位，剥掉转发");
    p = spawn_registered();
    if (p == 0) { _exit(1); }

    /*
     * 说明：实测本容器内核（6.1.145-android14）对
     *   wait4(…, WNOHANG|WNOWAIT, …) → EINVAL(22)
     *   waitid(…, WEXITED|WNOHANG|WNOWAIT, …) → 正常（保留僵尸）
     * 钩子对 wait4/waitpid/wait3 剥掉 WNOWAIT 再转发，于是这里拿到的是
     * 「普通 wait」的结果（真的回收了），并据此标 REAPED —— 与内核实情
     * 一致。若将来内核实现了 wait4 的 WNOWAIT，这一条会变成误标，
     * 所以钩子里用的是调用方传进来的原始 options 判定（见 W10）。
     */
    usleep(100000);
    rc = p_waitpid(p, &st, WNOHANG | WNOWAIT);
    CHECK(rc == p, "带 WNOWAIT 的 waitpid 仍能回收（rc=%d，非 EINVAL）",
          (int)rc);
    CHECK(life_of(p) == PX_REAPED, "确实回收了 → 标 REAPED（%d）",
          life_of(p));
}

static void case_waitid_wnowait_keeps_live(void)
{
    pid_t p;
    int rc;
    siginfo_t si;

    CASE("W10 ★waitid + WNOWAIT：内核保留僵尸 → 绝不能标 REAPED★");
    p = spawn_registered();
    if (p == 0) { _exit(2); }

    usleep(200000);   /* 让子进程变成僵尸 */
    memset(&si, 0, sizeof(si));
    rc = p_waitid(P_PID, (id_t)p, &si, WEXITED | WNOHANG | WNOWAIT);
    if (rc == 0 && si.si_pid == p) {
        CHECK(1, "内核对 waitid 生效 WNOWAIT（si_pid=%d）", (int)si.si_pid);
        CHECK(life_of(p) == PX_LIVE,
              "★账本仍是 LIVE —— 僵尸还被内核保留，还能再 wait（%d）",
              life_of(p));
        /* 真的回收一次，确认它确实还在 */
        memset(&si, 0, sizeof(si));
        rc = p_waitid(P_PID, (id_t)p, &si, WEXITED | WNOHANG);
        CHECK(rc == 0 && si.si_pid == p, "再 wait 一次仍拿得到（WNOWAIT 生效）");
        CHECK(life_of(p) == PX_REAPED, "这次才标 REAPED（%d）", life_of(p));
    } else {
        /* 内核不支持 waitid 的 WNOWAIT：那第一次调用就已经回收了 */
        CHECK(rc == 0 && si.si_pid == p,
              "内核不支持 waitid+WNOWAIT（si_pid=%d, errno=%d），退化为直接回收",
              (int)si.si_pid, errno);
        CHECK(life_of(p) == PX_REAPED, "直接回收 → 标 REAPED（%d）",
              life_of(p));
    }
}

static void case_echild(void)
{
    pid_t rc;
    int st = 0;

    CASE("W11 ECHILD：不存在的子进程不得污染账本");
    errno = 0;
    rc = p_waitpid((pid_t)999999, &st, WNOHANG);
    CHECK(rc == -1 && errno == ECHILD, "返回 -1/ECHILD（rc=%d errno=%d）",
          (int)rc, errno);
    CHECK(life_of((pid_t)999999) == -1, "账本里没有被凭空写入该 pid");
}

static void case_ledger_drains(void)
{
    int i;
    int ok = 1;
    size_t live;

    CASE("W12 ★长跑不退化★：30 轮 fork+waitpid 后账本无残留 LIVE");
    for (i = 0; i < 30; i++) {
        pid_t p = spawn_registered();
        int st = 0;
        if (p == 0) { _exit(0); }
        if (p_waitpid(p, &st, 0) != p || life_of(p) != PX_REAPED) {
            ok = 0;
            break;
        }
    }
    live = p_ledger_live(g_l);
    CHECK(ok, "30 轮全部「wait 完即 REAPED」");
    /*
     * live 计数里应当只剩测试进程自己（px_runtime_register_self 记的），
     * 也就是「子进程条目全部离开了 LIVE 状态」。这正是 REPORT §9 里
     * 「账本只增不减 → fork EAGAIN」的修复判据。
     */
    CHECK(live <= 1, "★残留 LIVE 条目 = %zu（应 ≤1，仅自身）", live);
    CHECK(p_ledger_reaped(g_l) >= 30,
          "REAPED 条目 ≥30（%zu），说明回收确实落在账本上",
          p_ledger_reaped(g_l));
}

/* ---------------- 入口 ---------------- */
static int run_all(void)
{
    void *h, *hs;
    const char *lib = getenv("BXROOT_WAIT_TEST_LIB");

    if (lib == NULL || lib[0] == '\0') {
        fprintf(stderr, "缺少 BXROOT_WAIT_TEST_LIB\n");
        return 1;
    }

    printf("== wait 家族钩子验证 ==\n");
    printf("   被测库: %s\n", lib);

    /* Preserve late loading as an observation, not an RTLD_NEXT guarantee. */
    h = dlopen(lib, RTLD_NOW | RTLD_GLOBAL);
    if (h == NULL) {
        fprintf(stderr, "dlopen(产物) 失败: %s\n", dlerror());
        return 1;
    }
    {
        const char *stub = getenv("BXROOT_WAIT_STUB_LIB");
        if (stub == NULL || stub[0] == '\0') {
            fprintf(stderr, "缺少 BXROOT_WAIT_STUB_LIB\n");
            return 1;
        }
        hs = dlopen(stub, RTLD_NOW | RTLD_GLOBAL);
        if (hs == NULL) {
            fprintf(stderr, "dlopen(stub) 失败: %s\n", dlerror());
            return 1;
        }
        p_stub_calls = (int (*)(void))dlsym(hs, "waitstub_calls");
        p_stub_reset = (void (*)(void))dlsym(hs, "waitstub_reset");
        CHECK(p_stub_calls != NULL, "stub 已加载供独立契约测试");
    }

    /* 动态符号表里必须真的有这四个（这就是 LD_PRELOAD 的插入入口） */
    p_waitpid = (pid_t (*)(pid_t, int *, int))dlsym(h, "waitpid");
    p_wait4   = (pid_t (*)(pid_t, int *, int, struct rusage *))dlsym(h, "wait4");
    p_wait3   = (pid_t (*)(int *, int, struct rusage *))dlsym(h, "wait3");
    p_waitid  = (int (*)(idtype_t, id_t, siginfo_t *, int))dlsym(h, "waitid");

    CASE("W0 四个符号都在动态符号表里（否则钩子根本没插入点）");
    CHECK(p_waitpid && p_wait4 && p_wait3 && p_waitid,
          "waitpid=%p wait4=%p wait3=%p waitid=%p",
          (void *)(uintptr_t)p_waitpid, (void *)(uintptr_t)p_wait4,
          (void *)(uintptr_t)p_wait3, (void *)(uintptr_t)p_waitid);
    if (!(p_waitpid && p_wait4 && p_wait3 && p_waitid)) {
        return 1;
    }

    p_runtime_ledger = (px_ledger *(*)(void))dlsym(h, "px_runtime_ledger");
    CHECK(p_runtime_ledger != NULL, "能从产物里解析 px_runtime_ledger");
    if (p_runtime_ledger == NULL) {
        return 1;
    }
    g_l = p_runtime_ledger();
    CHECK(g_l != NULL,
          "构造函数 px_runtime_init() 已建立账本（%p）—— 顺带证明 D4 初始化真的跑了",
          (void *)g_l);
    if (g_l == NULL) {
        return 1;
    }

    p_ledger_add = (int (*)(px_ledger *, pid_t, pid_t, uint32_t))
                   dlsym(h, "px_ledger_add");
    p_ledger_get = (int (*)(const px_ledger *, pid_t, px_entry_kind,
                            px_procinfo *))dlsym(h, "px_ledger_get");
    p_ledger_live = (size_t (*)(const px_ledger *))
                    dlsym(h, "px_ledger_live_count");
    p_ledger_reaped = (size_t (*)(const px_ledger *))
                      dlsym(h, "px_ledger_reaped_count");
    CHECK(p_ledger_add && p_ledger_get && p_ledger_live && p_ledger_reaped,
          "账本查询原语可用");

    case_stub_contract(hs);
    CASE("W0b runtime 自证：真实 kernel 回收与 ledger 同时成立");
    {
        pid_t p = spawn_registered();
        int st = 0;
        if (p == 0) { _exit(9); }
        p_stub_reset();
        CHECK(p_waitpid(p, &st, 0) == p && WIFEXITED(st) && WEXITSTATUS(st) == 9,
              "runtime 交付真实子进程退出9");
        CHECK(life_of(p) == PX_REAPED, "runtime 自证 ledger REAPED");
        expect_kernel_reaped("runtime 自证", p);
        printf("    INFO: late stub calls=%d (backend observation, not assertion)\n", p_stub_calls());
        p_stub_reset();
    }

    case_exited_normal();
    case_wnohang_zero();
    case_wait4();
    case_wait4_wnohang();
    case_wait3();
    case_waitid_ppid();
    case_waitid_wnohang_empty();
    case_stopped_not_reaped();
    case_wnowait_compat();
    case_waitid_wnowait_keeps_live();
    case_echild();
    case_ledger_drains();

    printf("\n----------------------------------------\n");
    printf("cases:  %d  (%d failed)\n", g_cases, g_failed);
    printf("checks: %d  (%d failed)\n", g_checks, g_failed);
    printf("RESULT: %s\n", g_failed ? "FAIL" : "PASS");
    return g_failed ? 1 : 0;
}

int main(int argc, char **argv)
{
    pid_t child;
    int crash_selftest = argc == 2 && strcmp(argv[1], "--crash-selftest") == 0;
    if (argc != 1 && !crash_selftest) return 1;
    int st = 0;

    /*
     * 在子进程里跑：被测 .so 的构造函数会安装 SIGSEGV/SIGSYS 处理器并
     * 做 seccomp 探测，那些副作用不该影响测试驱动本身，更不该让
     * 「库的副作用」被误判成「钩子失败」。
     */
    fflush(NULL);          /* 先把父进程已缓冲的内容落盘，避免 fork 后重复 */
    child = fork();
    if (child == 0) {
        if (crash_selftest) {
            pid_t self = getpid();
            if (self <= 0) _exit(1);
            (void)kill_owned_child(self, SIGKILL);
            _exit(1);
        }
        int rc = run_all();
        /*
         * ★ 必须先 fflush 再 _exit ★
         * _exit 不刷 stdio 缓冲，而 stdout 重定向到管道/文件时是**全缓冲**，
         * 于是子进程的全部输出会被静默丢掉 —— 症状是「测试什么都没打印
         * 但退出码是 0」，比失败更难查。
         */
        fflush(NULL);
        _exit(rc);
    }
    if (child < 0) {
        perror("fork");
        return 1;
    }
    pid_t got;
    do { got = kernel_wait(child, &st, 0); } while (got < 0 && errno == EINTR);
    if (got != child) {
        perror("waitpid");
        return 1;
    }
    if (WIFSIGNALED(st)) {
        printf("子进程被信号 %d 终止（库的构造函数副作用？）\n", WTERMSIG(st));
        return 1;
    }
    return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
}
