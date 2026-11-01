/*
 * seccomp-window probe —— 验证"按指令地址窗口 TRAP"方案的前提
 *
 * 1. 非特权进程能否在 Android app 过滤器之上再叠加一层 seccomp
 * 2. BPF 按 instruction_pointer 分流是否生效（窗口内 TRAP、窗口外放行）
 * 3. 陷阱里翻译路径再重发 openat 是否正确
 * 4. fork+exec 后过滤器被继承，但窗口外代码的子进程不受影响
 * 另测：Syscall User Dispatch 可用性；各类 syscall 耗时。
 *
 * 模拟方式：在固定地址 WINDOW 映射一页 "mov x8,x6; svc #0; ret"，
 * 代表"被 ULX 加载进 guest 窗口的代码"。
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#define WINDOW    0x1000000000UL /* 高 32 位 = 0x10 */
#define WINDOW_HI 0x10u
#define TRAP_TAG  0x0bb0u        /* RET_DATA，内核填进 si_errno */
#define FAKE_PPID 4242

/* 窗口内的 svc 桩：x0..x5 为参数，x6 为调用号 */
typedef long (*stub_fn)(long, long, long, long, long, long, long nr);
static stub_fn guest_svc;
static char probe_root[512];
static volatile long traps;

static long now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000L + ts.tv_nsec;
}

/* 陷阱处理器：只处理带我们标签的 SIGSYS */
static void on_sigsys(int sig, siginfo_t *si, void *ctx) {
    (void)sig;
    if (si->si_code != 1 /* SYS_SECCOMP */ || si->si_errno != TRAP_TAG)
        return;
    traps++;
    ucontext_t *uc = ctx;
    unsigned long long *r = uc->uc_mcontext.regs;
    long nr = (long)r[8];
    if (nr == __NR_getppid) {
        r[0] = FAKE_PPID;
    } else if (nr == __NR_openat) {
        const char *p = (const char *)r[1];
        char buf[1024];
        if (strncmp(p, "/bxprobe/", 9) == 0) {
            size_t n = strlen(probe_root);
            memcpy(buf, probe_root, n);
            snprintf(buf + n, sizeof(buf) - n, "%s", p + 8);
            p = buf;
        }
        /* 从窗口外重发：过滤器放行 */
        long rc = syscall(__NR_openat, (int)r[0], p, (int)r[2], (int)r[3]);
        r[0] = (unsigned long long)(rc < 0 ? -errno : rc);
    } else {
        r[0] = (unsigned long long)-ENOSYS;
    }
    /* 不推进 PC：进入处理器时 PC 已在 svc 之后 */
}

static int install_filter(void) {
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        /* instruction_pointer 高 32 位（小端：偏移 +4） */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, instruction_pointer) + 4),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, WINDOW_HI, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getppid, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP | TRAP_TAG),
    };
    struct sock_fprog prog = {sizeof(f) / sizeof(f[0]), f};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        printf("NO_NEW_PRIVS: FAIL errno=%d\n", errno);
        return -1;
    }
    if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) != 0) {
        printf("seccomp(SET_MODE_FILTER): FAIL errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    }
    return 0;
}

static int map_window(void) {
    void *p = mmap((void *)WINDOW, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (p != (void *)WINDOW) {
        printf("mmap window: FAIL p=%p errno=%d\n", p, errno);
        return -1;
    }
    uint32_t code[] = {
        0xaa0603e8, /* mov x8, x6 */
        0xd4000001, /* svc #0 */
        0xd65f03c0, /* ret */
    };
    memcpy(p, code, sizeof(code));
    __builtin___clear_cache((char *)p, (char *)p + sizeof(code));
    if (mprotect(p, 4096, PROT_READ | PROT_EXEC) != 0) {
        printf("mprotect window: FAIL errno=%d\n", errno);
        return -1;
    }
    guest_svc = (stub_fn)p;
    return 0;
}

#define N 200000
static double bench_libc_getppid(void) {
    long t = now_ns();
    for (int i = 0; i < N; i++) syscall(__NR_getppid);
    return (double)(now_ns() - t) / N;
}
static double bench_window(long nr) {
    long t = now_ns();
    for (int i = 0; i < N; i++) guest_svc(0, 0, 0, 0, 0, 0, nr);
    return (double)(now_ns() - t) / N;
}


/* 改写路径：窗口内 svc 被替换成 "ldr x16,=handler; br x16"，handler 在窗口外 */
static long rewritten_handler(long a0, long a1, long a2, long a3, long a4, long a5, long nr) {
    if (nr == __NR_getppid) return FAKE_PPID;
    if (nr == __NR_openat) {
        const char *p = (const char *)a1;
        char buf[1024];
        if (strncmp(p, "/bxprobe/", 9) == 0) {
            size_t n = strlen(probe_root);
            memcpy(buf, probe_root, n);
            snprintf(buf + n, sizeof(buf) - n, "%s", p + 8);
            p = buf;
        }
        long rc = syscall(__NR_openat, (int)a0, p, (int)a2, (int)a3);
        return rc < 0 ? -errno : rc;
    }
    long rc = syscall(nr, a0, a1, a2, a3, a4, a5);
    return rc < 0 ? -errno : rc;
}
static stub_fn rewritten_svc;
static int map_rewritten(void) {
    void *p = mmap((void *)(WINDOW + 0x10000), 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (p == MAP_FAILED) return -1;
    uint32_t code[] = {
        0x58000050, /* ldr x16, #8  (取后面的 .quad) */
        0xd61f0200, /* br x16 */
        0, 0,
    };
    uint64_t h = (uint64_t)rewritten_handler;
    memcpy(&code[2], &h, 8);
    memcpy(p, code, sizeof(code));
    __builtin___clear_cache((char *)p, (char *)p + sizeof(code));
    mprotect(p, 4096, PROT_READ | PROT_EXEC);
    rewritten_svc = (stub_fn)p;
    return 0;
}
static double bench_rewritten(long nr) {
    long t = now_ns();
    for (int i = 0; i < N; i++) rewritten_svc(0, 0, 0, 0, 0, 0, nr);
    return (double)(now_ns() - t) / N;
}

static void probe_sud(void) {
#ifndef PR_SET_SYSCALL_USER_DISPATCH
#define PR_SET_SYSCALL_USER_DISPATCH 59
#define PR_SYS_DISPATCH_OFF 0
#define PR_SYS_DISPATCH_ON 1
#endif
    static volatile char sel = 0;
    int rc = prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON, 0, 0, &sel);
    printf("SUD prctl: rc=%d errno=%d (%s)\n", rc, rc ? errno : 0,
           rc ? strerror(errno) : "available");
    if (rc == 0) prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_OFF, 0, 0, 0);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *child = argc > 1 ? argv[1] : "/bin/true";
    printf("pid=%d ppid=%d\n", getpid(), getppid());
    probe_sud();

    /* 准备 probe_root/hello.txt，用于验证路径翻译 */
    snprintf(probe_root, sizeof(probe_root), "/tmp/bxprobe-root-%d", getpid());
    mkdir(probe_root, 0755);
    char f[600];
    snprintf(f, sizeof(f), "%s/hello.txt", probe_root);
    FILE *fp = fopen(f, "w");
    fputs("translated-ok\n", fp);
    fclose(fp);

    if (map_window() != 0) return 2;
    double base = bench_libc_getppid();
    double win_pre = bench_window(__NR_getppid);
    printf("bench before filter: libc getppid %.0f ns, window getppid %.0f ns\n",
           base, win_pre);

    struct sigaction sa = {0};
    sa.sa_sigaction = on_sigsys;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSYS, &sa, NULL);
    if (install_filter() != 0) return 3;
    printf("filter: installed\n");

    /* 正确性 */
    long pp = guest_svc(0, 0, 0, 0, 0, 0, __NR_getppid);
    printf("window getppid -> %ld (expect %d) traps=%ld\n", pp, FAKE_PPID, traps);
    printf("libc   getppid -> %d (expect real)\n", getppid());
    long fd = guest_svc(AT_FDCWD, (long)"/bxprobe/hello.txt", O_RDONLY, 0, 0, 0, __NR_openat);
    char buf[64] = {0};
    if (fd >= 0) { read((int)fd, buf, sizeof(buf) - 1); close((int)fd); }
    printf("window openat /bxprobe/hello.txt -> fd=%ld content=%s", fd, fd >= 0 ? buf : "(none)\n");
    long fd2 = guest_svc(AT_FDCWD, (long)"/bxprobe/hello.txt", O_RDONLY, 0, 0, 0, __NR_openat);
    (void)fd2;
    int fd3 = open("/bxprobe/hello.txt", O_RDONLY);
    printf("libc   open   /bxprobe/hello.txt -> %d (expect -1, not translated)\n", fd3);

    /* 性能 */
    double after_libc = bench_libc_getppid();
    double after_win_untrapped = bench_window(__NR_getpid);
    long t0 = traps;
    double after_trap = bench_window(__NR_getppid);
    printf("bench after filter: libc getppid %.0f ns, window getpid(untrapped) %.0f ns, "
           "window getppid(trapped) %.0f ns, traps=%ld\n",
           after_libc, after_win_untrapped, after_trap, traps - t0);

    if (map_rewritten() == 0) {
        long t1 = traps;
        long pp2 = rewritten_svc(0, 0, 0, 0, 0, 0, __NR_getppid);
        long rfd = rewritten_svc(AT_FDCWD, (long)"/bxprobe/hello.txt", O_RDONLY, 0, 0, 0, __NR_openat);
        char b2[64] = {0};
        if (rfd >= 0) { if (read((int)rfd, b2, 63) < 0) {} close((int)rfd); }
        printf("rewritten getppid -> %ld, openat -> fd=%ld content=%s", pp2, rfd, rfd >= 0 ? b2 : "(none)\n");
        double rw = bench_rewritten(__NR_getppid);
        double rw_fwd = bench_rewritten(__NR_getpid);
        printf("rewritten path: getppid(emulated) %.0f ns, getpid(forwarded syscall) %.0f ns, traps during=%ld\n",
               rw, rw_fwd, traps - t1);
    }

    /* 继承：子进程 exec 一个普通程序，它的代码不在窗口里 */
    pid_t c = fork();
    if (c == 0) {
        execl(child, child, (char *)NULL);
        _exit(127);
    }
    int st = 0;
    waitpid(c, &st, 0);
    printf("child exec %s -> %s %d\n", child, WIFEXITED(st) ? "exit" : "signal",
           WIFEXITED(st) ? WEXITSTATUS(st) : WTERMSIG(st));
    return 0;
}
