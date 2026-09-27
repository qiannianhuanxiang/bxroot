/*
 * probe_seccomp_isolation.c —— livepatch 扫描的**强隔离**端到端验证
 *
 * 【与 probe_livepatch_scan.c 的分工】
 *   probe_livepatch_scan.c 只对**合成机器码缓冲**跑扫描逻辑，断言"哪些
 *   svc 被改、哪些没被碰"——它证明扫描*认得*站点，但不涉及真实 seccomp。
 *   本探针更进一步：在**本进程**里亲手装一个 seccomp BPF 过滤器，把
 *   set_robust_list(99) 设成 SECCOMP_RET_TRAP，然后复刻 glibc `_Fork` 的
 *   致命形态（全信号屏蔽下发 99 的内联 svc），用 A/B 对照证明：
 *
 *     A 对照（不打补丁）：子进程屏蔽 SIGSYS 后发 99 → TRAP 无处投递
 *                         → 内核直接杀 → 父进程 wait 到 WTERMSIG==SIGSYS
 *     B 打补丁（跑真实扫描）：同一段代码的 svc 已被扫描中和为 mov x0,#0
 *                         → 根本不进内核 → 子进程存活、rc=0
 *
 * 这条链**不依赖 bxroot-run / 外层 proroot**：seccomp 过滤器是本进程自己
 * 装的，svc 站点是本进程自己 mmap 的一段 RWX 代码，补丁走的是
 * livepatch.c 里**真实的** lp_scan_and_patch（经 -DLP_TEST_HOOK 暴露的
 * bxroot_livepatch_scan_buffer_for_test）。因此它把"扫描独立地救活了
 * 一个 seccomp 下必死的进程"钉成了容器内可复现的契约。
 *
 * 【为什么要屏蔽全部信号】SECCOMP_RET_TRAP 正常会投递 SIGSYS；只要有
 * 处理器（本容器外层 proroot 预置了一个）就能兜住，看不出补丁的作用。
 * glibc `_Fork` 恰恰先屏蔽全部信号再在子进程里发 set_robust_list ——
 * 屏蔽态下内核不投递 SIGSYS 而直接 KILL，无可挽救。复刻这个形态才能
 * 让"补丁 vs 不补丁"产生生死之别（这也正是真机上 2.41 fork 必死的机理）。
 *
 * 【模式】
 *   argv[1] == "control"：不打补丁，子进程期望**死于 SIGSYS**
 *   argv[1] == "patch"  ：跑真实扫描打补丁，子进程期望**存活**
 *                         但若 BXROOT_NO_LIVEPATCH!=0 则**跳过打补丁**
 *                         （让本探针也具备判别力：关掉开关 → patch 模式
 *                          退化为 control → 变红）
 *
 * 退出码：0 = 该模式的期望成立；1 = 期望被打破；2 = 环境/构建问题。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stddef.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>

/* livepatch.c 以 -DLP_TEST_HOOK 编入时暴露的真实扫描入口。 */
int bxroot_livepatch_scan_buffer_for_test(uint32_t *buf, size_t words);

/* aarch64 指令编码。 */
#define MOVZ_X8_99 0xd2800c68u   /* movz x8, #99   (set_robust_list) */
#define SVC0       0xd4000001u   /* svc #0                           */
#define RET        0xd65f03c0u   /* ret                              */
#define MOV_X0_0   0xd2800000u   /* mov x0, #0（扫描的补丁值）       */

static int env_off(void)
{
    const char *e = getenv("BXROOT_NO_LIVEPATCH");
    return (e != NULL && atoi(e) != 0);
}

/* 只对 set_robust_list(99) 返回 SECCOMP_RET_TRAP，其余放行。 */
static int install_trap_99(void)
{
    struct sock_filter filt[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 99 /* set_robust_list */, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = { .len = 4, .filter = filt };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("PR_SET_NO_NEW_PRIVS");
        return -1;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
        perror("PR_SET_SECCOMP");
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int do_patch;
    uint32_t *pg;
    pid_t pid;
    int st = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2 || (strcmp(argv[1], "control") != 0 &&
                     strcmp(argv[1], "patch") != 0)) {
        fprintf(stderr, "用法: %s control|patch\n", argv[0]);
        return 2;
    }
    do_patch = (strcmp(argv[1], "patch") == 0);

    /* 一段自有的 RWX 代码：movz x8,#99 ; svc #0 ; ret —— 复刻 glibc 里
     * set_robust_list 的内联 svc 形态。用自有页而非改 libc，隔离更干净。 */
    pg = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pg == MAP_FAILED) {
        perror("mmap");
        return 2;
    }
    pg[0] = MOVZ_X8_99;
    pg[1] = SVC0;
    pg[2] = RET;
    __builtin___clear_cache((char *)pg, (char *)pg + 12);

    if (do_patch) {
        if (env_off()) {
            fprintf(stderr, "[probe] BXROOT_NO_LIVEPATCH 生效 → 跳过打补丁"
                            "（patch 模式退化为 control，用于判别力）\n");
        } else {
            int n = bxroot_livepatch_scan_buffer_for_test(pg, 3);
            __builtin___clear_cache((char *)pg, (char *)pg + 12);
            fprintf(stderr, "[probe] 扫描改写 %d 处；pg[1]=0x%08x（应为 0x%08x）\n",
                    n, pg[1], MOV_X0_0);
            if (n != 1 || pg[1] != MOV_X0_0) {
                fprintf(stderr, "[probe] 补丁未按预期落地\n");
                return 2;
            }
        }
    }

    /* 过滤器装在父进程 → 子进程继承。补丁在 fork 前完成 → 子进程继承
     * 已改写的页（MAP_PRIVATE 匿名页按 COW 继承内容）。 */
    if (install_trap_99() != 0)
        return 2;

    pid = fork();
    if (pid < 0) {
        perror("fork");
        return 2;
    }
    if (pid == 0) {
        /* 子进程：复刻 _Fork 的致命形态 —— 先屏蔽全部信号（含 SIGSYS），
         * 再执行那段内联 svc。屏蔽态下 TRAP 无法投递 → 未打补丁必被杀。 */
        sigset_t all;
        long (*fn)(void) = (long (*)(void))pg;
        long r;

        sigfillset(&all);
        syscall(SYS_rt_sigprocmask, SIG_BLOCK, &all, (void *)0, (size_t)8);
        r = fn();                      /* 未打补丁：走到内核 99 → 被杀 */
        /* 走到这里说明 svc 已被中和；解除屏蔽后正常退出。 */
        {
            sigset_t none;
            sigemptyset(&none);
            syscall(SYS_rt_sigprocmask, SIG_SETMASK, &none, (void *)0, (size_t)8);
        }
        _exit(r == 0 ? 0 : 3);         /* 补丁把返回值置 0 */
    }

    /* 父进程：观察子进程结局。 */
    if (waitpid(pid, &st, 0) < 0) {
        perror("waitpid");
        return 2;
    }

    if (WIFSIGNALED(st)) {
        int sig = WTERMSIG(st);
        printf("child: 被信号 %d 杀死%s\n", sig,
               sig == SIGSYS ? "（SIGSYS）" : "");
        if (do_patch && !env_off()) {
            printf("RESULT: FAIL（patch 模式下子进程仍死于信号 %d）\n", sig);
            return 1;
        }
        /* control 模式，或 patch+env_off：死于 SIGSYS 正是预期。 */
        if (sig == SIGSYS) {
            printf("RESULT: PASS（对照：seccomp 下 99 无补丁 → 进程被杀，符合预期）\n");
            return 0;
        }
        printf("RESULT: FAIL（对照期望 SIGSYS，实得信号 %d）\n", sig);
        return 1;
    }

    printf("child: 正常退出 rc=%d\n", WEXITSTATUS(st));
    if (do_patch && !env_off()) {
        if (WEXITSTATUS(st) == 0) {
            printf("RESULT: PASS（打补丁：扫描中和 99 → 子进程存活）\n");
            return 0;
        }
        printf("RESULT: FAIL（补丁后子进程 rc=%d，非 0）\n", WEXITSTATUS(st));
        return 1;
    }
    /* control 却存活 —— 说明环境没有真正把 99 拦成致命（无判别力）。 */
    printf("RESULT: FAIL（对照本应死于 SIGSYS，却存活了；本环境 99 未被致命拦截）\n");
    return 1;
}
