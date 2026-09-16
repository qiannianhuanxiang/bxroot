/*
 * test_wait_hooks.c -- 验证 preload.c 的 wait 家族钩子（P0-3 / D4 补充项）
 *
 * ★ 这个测试能证明什么、不能证明什么（务必先读）★
 *
 * 能证明：
 *   - 构建产物**真实导出** waitpid / wait4 / wait3 / waitid（dlopen + dlsym
 *     拿到的就是 .so 动态符号表里的那四个函数，等于运行期的插入入口）；
 *   - 这四个钩子**确实按契约把回收掉的 pid 标成 PX_REAPED**，以及
 *     **在不能标的时候没有标**（WNOHANG 返回 0、停住的子进程）——
 *     判据不是「看返回值」，而是直接查 .so 内部 pid 账本的 life 字段。
 *
 * 不能证明：
 *   - 真实 LD_PRELOAD 场景下 PLT 插入是否生效。本容器外层 proot 会吞掉
 *     注入（已知限制，见 _shared/容器内测试不可信.md），所以这里用
 *     dlopen + dlsym **直接调用**同一份机器码。走的是同一个函数体、
 *     同一份账本，但绕过了符号插入那一层。
 *
 * 另一个必须说明的模拟：真实场景里子进程是 proc.c 的 fork 钩子记进账本的；
 * 本测试不经过那个钩子（测试进程自己没被 preload），所以 fork 之后**显式**
 * 调 px_ledger_add 模拟 fork 钩子的登记动作 —— 与 proc.c:
 * px_forkguard_parent_register 的行为一致。
 *
 * ★ 怎么绕过「本容器 LD_PRELOAD 与 RTLD_NEXT 都不可用」★
 *
 * 实测两条硬约束：① LD_PRELOAD 在本容器完全不被采纳（连玩具 preload
 * 都收不到）；② dlsym(RTLD_NEXT, ...) 在 dlopen 场景下解析 libc 导出
 * 符号返回 NULL（外层 proot 的加载器行为异常）。
 *
 * 于是本文件用 waitstub.c 构造一个**语义等价**的插入场景：
 *   1. dlopen(被测产物, RTLD_GLOBAL)          ← 排在前面（= preload 的效果）
 *   2. dlopen(libwaitstub.so, RTLD_GLOBAL)    ← 排在后面，充当「真实实现」
 *   3. dlsym(产物句柄, "waitpid") 拿到**钩子本体**并直接调用
 *
 * 钩子内部的 RTLD_NEXT 查找会先命中 libwaitstub.so 的同名符号，
 * 走的是与真实 preload 完全相同的代码路径；测试还会断言
 * 「stub 确实被调用过」（否则钩子就是在自己吞调用，没转发）。
 *
 * 用法：BXROOT_WAIT_TEST_LIB=<产物.so> BXROOT_WAIT_STUB_LIB=<libwaitstub.so> ./test_wait_hooks
 *       RUN_WAIT_TESTS.sh 会自己构建并调用它。
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

/* 钩子是否真的把调用转发给了 stub（而不是自己吞掉） */
static void expect_forwarded(const char *who)
{
    if (p_stub_calls == NULL) {
        return;
    }
    CHECK(p_stub_calls() > 0, "%s 已转发到真实实现（stub 调用数=%d）",
          who, p_stub_calls());
    if (p_stub_reset != NULL) {
        p_stub_reset();
    }
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

    if (p > 0) {
        (void)p_ledger_add(g_l, p, 0, PX_TAG_FORK);
    }
    return p;
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
    expect_forwarded("waitpid");
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

    CHECK(kill(p, SIGKILL) == 0, "子进程仍可被 kill（说明白名单没被污染）");
    rc = p_waitpid(p, &st, 0);
    CHECK(rc == p && WIFSIGNALED(st), "随后的阻塞 waitpid 正常收到 SIGKILL");
    CHECK(life_of(p) == PX_REAPED, "此时才标 REAPED（%d）", life_of(p));
    expect_forwarded("waitpid(WNOHANG)");
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
    expect_forwarded("wait4");
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

    kill(p, SIGKILL);
    CHECK(p_wait4(p, &st, 0, NULL) == p, "收尾 wait4 正常");
    CHECK(life_of(p) == PX_REAPED, "收尾后标 REAPED（%d）", life_of(p));
    expect_forwarded("wait4");
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
    expect_forwarded("wait3");
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
    expect_forwarded("waitid");
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
    kill(p, SIGSTOP);
    rc = p_waitpid(p, &st, WUNTRACED);
    CHECK(rc == p, "waitpid(WUNTRACED) 返回子 pid（%d）", (int)rc);
    CHECK(WIFSTOPPED(st), "状态是「已停止」而非退出");
    /*
     * 只停住没退出：还能被继续 wait。标 reaped 会让 kill 永久失效。
     */
    CHECK(life_of(p) == PX_LIVE, "★账本仍是 LIVE（%d）", life_of(p));

    kill(p, SIGCONT);
    kill(p, SIGKILL);
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
    void *h;
    const char *lib = getenv("BXROOT_WAIT_TEST_LIB");

    if (lib == NULL || lib[0] == '\0') {
        fprintf(stderr, "缺少 BXROOT_WAIT_TEST_LIB\n");
        return 2;
    }

    printf("== wait 家族钩子验证 ==\n");
    printf("   被测库: %s\n", lib);

    /* 顺序是关键：产物先加载（= 被 preload 的那个），stub 后加载
     * （= 它「后面」的真实实现，钩子的 RTLD_NEXT 会命中它）。 */
    h = dlopen(lib, RTLD_NOW | RTLD_GLOBAL);
    if (h == NULL) {
        fprintf(stderr, "dlopen(产物) 失败: %s\n", dlerror());
        return 2;
    }
    {
        const char *stub = getenv("BXROOT_WAIT_STUB_LIB");
        void *hs;
        if (stub == NULL || stub[0] == '\0') {
            fprintf(stderr, "缺少 BXROOT_WAIT_STUB_LIB\n");
            return 2;
        }
        hs = dlopen(stub, RTLD_NOW | RTLD_GLOBAL);
        if (hs == NULL) {
            fprintf(stderr, "dlopen(stub) 失败: %s\n", dlerror());
            return 2;
        }
        p_stub_calls = (int (*)(void))dlsym(hs, "waitstub_calls");
        p_stub_reset = (void (*)(void))dlsym(hs, "waitstub_reset");
        CHECK(p_stub_calls != NULL, "stub 已加载并可用于「是否转发」断言");
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
        return 2;
    }

    p_runtime_ledger = (px_ledger *(*)(void))dlsym(h, "px_runtime_ledger");
    CHECK(p_runtime_ledger != NULL, "能从产物里解析 px_runtime_ledger");
    if (p_runtime_ledger == NULL) {
        return 2;
    }
    g_l = p_runtime_ledger();
    CHECK(g_l != NULL,
          "构造函数 px_runtime_init() 已建立账本（%p）—— 顺带证明 D4 初始化真的跑了",
          (void *)g_l);
    if (g_l == NULL) {
        return 2;
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

    /*
     * 先自证 harness 成立：直接调一次 waitpid（会解析到谁来着不重要），
     * 关键是后面每个用例里的 expect_forwarded 断言 —— 若钩子没转发，
     * 那些断言会失败而不是静默通过。
     */
    CASE("W0b harness 自证：钩子内部 RTLD_NEXT 能命中 stub");
    {
        pid_t p = spawn_registered();
        int st = 0;
        if (p == 0) { _exit(0); }
        if (p_stub_reset) { p_stub_reset(); }
        (void)p_waitpid(p, &st, 0);
        CHECK(p_stub_calls != NULL && p_stub_calls() > 0,
              "stub 被命中（%d 次）—— 否则本测试的「真实实现」根本没接上",
              p_stub_calls ? p_stub_calls() : -1);
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

int main(void)
{
    pid_t child;
    int st = 0;

    /*
     * 在子进程里跑：被测 .so 的构造函数会安装 SIGSEGV/SIGSYS 处理器并
     * 做 seccomp 探测，那些副作用不该影响测试驱动本身，更不该让
     * 「库的副作用」被误判成「钩子失败」。
     */
    fflush(NULL);          /* 先把父进程已缓冲的内容落盘，避免 fork 后重复 */
    child = fork();
    if (child == 0) {
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
        return 2;
    }
    if (waitpid(child, &st, 0) != child) {
        perror("waitpid");
        return 2;
    }
    if (WIFSIGNALED(st)) {
        printf("子进程被信号 %d 终止（库的构造函数副作用？）\n", WTERMSIG(st));
        return 2;
    }
    return WEXITSTATUS(st);
}
