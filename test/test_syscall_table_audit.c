/*
 * test/test_syscall_table_audit.c
 * =====================================================================
 * bxroot 系统调用路径参数表 —— 实测审计器
 * =====================================================================
 *
 * 审计对象
 * --------
 * `src/runtime/syscall_guard.c` 里那张"第几个寄存器是路径"的表。
 * 该表在本审计期间**正在被并行修改**，因此本测试**同时支持两种接口形态**：
 *
 *   形态 A（旧）：`static int path_arg_index(long)`  返回 0 / 1 / -1
 *   形态 B（新）：`static unsigned path_arg_mask(long)` 返回位掩码，bit N = aN 是路径
 *
 * 判据统一换算成"路径位掩码"，两种形态可比。
 *
 * 为什么不能靠推理
 * ----------------
 * 这张表**没有类型检查**：`return 1` 只是说"把 a1 当 `const char *` 用"。
 * 一旦某个编号在 aarch64 上根本不是那个调用、或者路径不在 a1，guard 就会
 * 把整数当指针解引用。本项目已经因此出过两次事：
 *
 *   ① `case 36: return 1`（symlinkat）—— a1 是 newdirfd，不是路径。
 *      把 AT_FDCWD(-100) 当指针解引用 → 每次裸 syscall 的 symlinkat 都 SIGSEGV。
 *   ② `case 260: return 1`（注释写 linkat）—— aarch64 上 **260 是 wait4**，
 *      linkat 其实是 37。wait4 的 a1 是 `int *wstatus`：被信号 47 终止的子进程
 *      wstatus == 0x2f，首字节正好是 '/'，于是 guard 判定"这是路径"、
 *      把内核写的退出状态丢进了自己的临时缓冲 —— **静默数据错写**，
 *      比崩溃更难查。
 *
 * 所以本测试不重复源码注释里的结论，而是**现场向内核提问**，对每个编号构造
 * "参数位置不同则 errno 必然不同"的实验：
 *
 *   · aN 是路径指针吗？   → 换成伪指针：路径型调用在路径解析阶段返回 EFAULT
 *   · aN 是 dirfd 吗？    → 换成伪 dirfd：返回 EBADF
 *   · aN 是输出缓冲吗？   → 换成**只读**地址：可读的路径型调用会成功，
 *                           而只写缓冲必须 EFAULT（← 判决 wait4 的关键手法）
 *   · aN 是 flags 吗？    → 换成一个只有 flags 才认识的位，看行为是否改变
 *   · 编号存在吗？        → ENOSYS = 本内核没有这个调用
 *
 * 安全措施
 * --------
 * 每个实验都跑在 fork 出来的子进程里，父进程读管道 + waitpid 退出状态
 * （139 = SIGSEGV / 14 = SIGALRM 超时）；每个子进程都装 alarm(10) 兜底，
 * 保证阻塞型调用（wait4）不会挂住整个套件。
 *
 * 本文件只**读**被测源码，不修改它。
 *
 * 用法
 * ----
 *   ./test_syscall_table_audit               正常报告
 *   ./test_syscall_table_audit --md          追加 Markdown 汇总（贴审计报告用）
 *   ./test_syscall_table_audit <路径>        指定 syscall_guard.c
 *
 * 退出码
 * ------
 *   0 = 表与实测一致
 *   1 = 有不一致（表项错误 / 遗漏必须覆盖的路径型调用）
 *   2 = 环境问题（读不到源文件 / 解析不出表 / 建不出沙箱）
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ================================================================== */
/* 0. 基础设施：裸系统调用 + 子进程隔离观测                             */
/* ================================================================== */

/*
 * 自己写 svc 内联汇编，不用 libc 的 syscall()。
 *
 * 理由：如果被测的 libbxroot-runtime.so 被 LD_PRELOAD 进来（回归脚本可能这么
 * 做），libc 的 syscall() 会被 guard 接管，本测试量到的就**不是内核**而是 guard
 * —— 那会让"实测"变成循环论证。裸 svc 永远直达内核。
 */
static long raw6(long nr, long a0, long a1, long a2, long a3, long a4, long a5)
{
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;

    __asm__ __volatile__("svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
        : "memory", "cc");

    if (x0 < 0 && x0 > -4096) {
        errno = (int)(-x0);
        return -1;
    }
    return x0;
}

struct obs {
    long ret;
    int  err;
    int  marker;
};

#define OBS_MARKER 0x4258524f /* "BXRO" */

typedef void (*kid_setup_fn)(long a[6]);

/* 沙箱目录（定义在第 2 节；run_call2 需要它来给子进程定 cwd） */
static char g_sb[PATH_MAX + 64];

/* 调用**之后**在子进程里跑：可把内核写进缓冲的内容带回父进程 */
typedef void (*kid_after_fn)(long a[6], long ret, long *extra);

struct obs_extra {
    long v[4];
};
static struct obs_extra g_obs_extra;

/*
 * 在子进程里执行一次裸调用，父进程收集 {返回值, errno, 终止信号}。
 * 返回 0 = 拿到完整观测；1 = 子进程被信号带走 / 没回传。
 *
 * after 是可选的后处理钩子：内核写进调用方缓冲的数据只在**子进程**里可见
 * （写时复制），父进程要看到就必须由子进程回传，`extra` 就是那个通道。
 */
static int run_call2(long nr, const long in[6], kid_setup_fn setup,
                     kid_after_fn after, struct obs *out, int *term_sig)
{
    int pfd[2];
    pid_t pid;
    long a[6];
    int i;

    for (i = 0; i < 6; i++)
        a[i] = in[i];

    out->ret = 0;
    out->err = 0;
    out->marker = 0;
    *term_sig = 0;
    memset(&g_obs_extra, 0, sizeof g_obs_extra);

    if (pipe(pfd) != 0)
        return 1;

    pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return 1;
    }

    if (pid == 0) {
        struct obs o;
        long r;
        long extra[4] = {0, 0, 0, 0};

        close(pfd[0]);
        alarm(10);

        /*
         * ★ 子进程先 chdir 到沙箱。
         *
         * 为什么必须这么做：本测试大量使用**相对路径**做 dirfd 判决
         * （内核在路径是绝对时忽略 dirfd，所以相对路径是唯一有判别力的
         * 形态）。若子进程的 cwd 不是沙箱，"相对名"就指向别处，实验
         * 会因 ENOENT 而失败，看起来像"参数位置不对"，实则是夹具问题。
         * 每个实验都自带 cwd，实验之间互不污染。
         */
        if (g_sb[0] != '\0' && raw6(49 /*chdir*/, (long)(intptr_t)g_sb, 0, 0, 0, 0, 0) != 0) {
            o.ret = -1;
            o.err = -1;
            o.marker = 0;
            {
                ssize_t w = write(pfd[1], &o, sizeof o);
                (void)w;
            }
            _exit(0);
        }

        if (setup != NULL)
            setup(a);

        r = raw6(nr, a[0], a[1], a[2], a[3], a[4], a[5]);

        if (after != NULL)
            after(a, r, extra);

        o.ret = r;
        o.err = errno;
        o.marker = OBS_MARKER;
        {
            struct { struct obs o; long e[4]; } msg;
            ssize_t w;
            msg.o = o;
            for (i = 0; i < 4; i++)
                msg.e[i] = extra[i];
            w = write(pfd[1], &msg, sizeof msg);
            (void)w;
        }
        _exit(0);
    }

    close(pfd[1]);
    {
        struct { struct obs o; long e[4]; } msg;
        ssize_t n = read(pfd[0], &msg, sizeof msg);
        if (n == (ssize_t)sizeof msg) {
            *out = msg.o;
            for (i = 0; i < 4; i++)
                g_obs_extra.v[i] = msg.e[i];
        } else {
            out->marker = 0;
        }
    }
    close(pfd[0]);

    {
        int st = 0;
        if (waitpid(pid, &st, 0) == pid) {
            if (WIFSIGNALED(st))
                *term_sig = WTERMSIG(st);
            else if (WIFEXITED(st) && WEXITSTATUS(st) != 0)
                *term_sig = -WEXITSTATUS(st);
        }
    }

    return (out->marker == OBS_MARKER && *term_sig == 0) ? 0 : 1;
}

static int run_call(long nr, const long in[6], kid_setup_fn setup,
                    struct obs *out, int *term_sig)
{
    return run_call2(nr, in, setup, NULL, out, term_sig);
}

/* ================================================================== */
/* 1. 报告工具                                                         */
/* ================================================================== */

static int g_checks;
static int g_fails;
static int g_doubts;
static int g_missing;

static void vprint(const char *level, const char *fmt, va_list ap)
{
    fputs(level, stdout);
    vprintf(fmt, ap);
    fputc('\n', stdout);
}

static void ok(const char *fmt, ...)
{
    va_list ap;
    g_checks++;
    va_start(ap, fmt);
    vprint("  [ok]   ", fmt, ap);
    va_end(ap);
}

static void fail(const char *fmt, ...)
{
    va_list ap;
    g_checks++;
    g_fails++;
    va_start(ap, fmt);
    vprint("  [FAIL] ", fmt, ap);
    va_end(ap);
}

static void doubt(const char *fmt, ...)
{
    va_list ap;
    g_doubts++;
    va_start(ap, fmt);
    vprint("  [存疑] ", fmt, ap);
    va_end(ap);
}

static void missing(const char *fmt, ...)
{
    va_list ap;
    g_missing++;
    va_start(ap, fmt);
    vprint("  [缺失] ", fmt, ap);
    va_end(ap);
}

static const char *errname(int e)
{
    switch (e) {
    case 0:       return "成功";
    case EPERM:   return "EPERM(1)";
    case ENOENT:  return "ENOENT(2)";
    case EBADF:   return "EBADF(9)";
    case ECHILD:  return "ECHILD(10)";
    case EACCES:  return "EACCES(13)";
    case EFAULT:  return "EFAULT(14)";
    case EBUSY:   return "EBUSY(16)";
    case EEXIST:  return "EEXIST(17)";
    case ENOTDIR: return "ENOTDIR(20)";
    case EISDIR:  return "EISDIR(21)";
    case EINVAL:  return "EINVAL(22)";
    case ENOSYS:  return "ENOSYS(38)";
    case ENOTSUP: return "ENOTSUP(95)";
    default:      return "其它";
    }
}

/* ================================================================== */
/* 2. 沙箱夹具                                                         */
/* ================================================================== */

static int  g_cleanup_armed;

/* ------------------------------------------------------------------ */
/* ★★ 沙箱必须建在 raw 命名空间里 ★★                                  */
/* ------------------------------------------------------------------ */
/*
 * 这是本审计踩的第四个、也是最隐蔽的一个坑。
 *
 * 本容器里 proroot 做路径重定向，而**重定向只作用于 libc 层**：
 *
 *     libc  open("/tmp/x", O_CREAT)   → 真建在 <rootfs>/tmp/x
 *     raw   openat(AT_FDCWD, "/tmp/x") → 看的是**宿主**的 /tmp
 *
 * 实测：
 *     raw statx("/tmp")            → 0（存在）
 *     raw getcwd()                 → /data/data/com.dsh.client/files/linux/ubuntu/tmp/<cwd>
 *     libc mkdir("/tmp/sb"); raw statx("/tmp/sb") → **ENOENT**
 *     libc 相对名 vs raw 相对名 → 也是两套
 *
 * 后果：如果沙箱用 libc 的 mkdir/open 建、却用 raw 探针去查，探针永远
 * ENOENT —— 表现为"linkat/renameat 全都失败"，看着像参数位置错了，
 * 其实是**夹具有两套命名空间**。
 *
 * 所以下面所有夹具操作**一律走 raw svc**，与探针同源；子进程用
 * raw chdir(49) 进入沙箱，让相对名在 raw 侧也解析到沙箱。
 * （libc 的 chdir 会被 proroot 换掉，对 raw 侧无效。）
 */

/* 用 raw 系统调用判定路径是否存在（lstat 语义，不跟随符号链接） */
static int raw_exists(const char *path)
{
    char st[256];
    return raw6(291 /*statx*/, AT_FDCWD, (long)(intptr_t)path,
                0x100 /*AT_SYMLINK_NOFOLLOW*/, 0x7ff, (long)(intptr_t)st, 0) == 0;
}

static int raw_mkdir(const char *path)
{
    return raw6(34 /*mkdirat*/, AT_FDCWD, (long)(intptr_t)path, 0755, 0, 0, 0) == 0;
}

static int raw_create(const char *path)
{
    long fd = raw6(56 /*openat*/, AT_FDCWD, (long)(intptr_t)path,
                   O_CREAT | O_WRONLY | O_TRUNC, 0644, 0, 0);
    if (fd < 0)
        return -1;
    (void)raw6(64 /*write*/, fd, (long)(intptr_t)"x\n", 2, 0, 0, 0);
    (void)raw6(57 /*close*/, fd, 0, 0, 0, 0, 0);
    return 0;
}

static int raw_symlink(const char *target, const char *linkpath)
{
    (void)raw6(35 /*unlinkat*/, AT_FDCWD, (long)(intptr_t)linkpath, 0, 0, 0, 0);
    return raw6(36 /*symlinkat*/, (long)(intptr_t)target, AT_FDCWD,
                (long)(intptr_t)linkpath, 0, 0, 0) == 0;
}

static void raw_unlink(const char *path, int isdir)
{
    (void)raw6(35 /*unlinkat*/, AT_FDCWD, (long)(intptr_t)path,
               isdir ? 0x200 /*AT_REMOVEDIR*/ : 0, 0, 0, 0);
}

static void sb_path(char *out, size_t n, const char *rel)
{
    snprintf(out, n, "%s/%s", g_sb, rel);
}

/* 建/重建一个普通文件（raw 侧） */
static int sb_file(const char *rel)
{
    char p[PATH_MAX];
    sb_path(p, sizeof p, rel);
    raw_unlink(p, 0);
    return raw_create(p);
}

static int sb_exists(const char *rel)
{
    char p[PATH_MAX];
    sb_path(p, sizeof p, rel);
    return raw_exists(p);
}

static void sb_rm(const char *rel)
{
    char p[PATH_MAX];
    sb_path(p, sizeof p, rel);
    raw_unlink(p, 0);
    raw_unlink(p, 1);
}

static void sb_purge(void)
{
    static const char *files[] = {
        "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8",
        "l1", "n1", "nl1", "nl2", "nl3", "nl4", "nl5", "nl6", "nl7",
        "h1", "h2", "rel_nl5", "rel_nl7", "rel_out", "rel_tmp",
        "d1/g1", "d1/g2", "d1/g3",
        NULL
    };
    static const char *dirs[] = { "d1", NULL };
    int i;

    for (i = 0; files[i] != NULL; i++)
        sb_rm(files[i]);
    /* 相对名夹具（raw cwd = 沙箱时由子进程创建，见 sb_setup） */
    {
        char p[PATH_MAX];
        const char *rels[] = {"rel_f1", "rel_l1", "rel_g3", NULL};
        for (i = 0; rels[i] != NULL; i++) {
            sb_path(p, sizeof p, rels[i]);
            raw_unlink(p, 0);
        }
    }
    for (i = 0; dirs[i] != NULL; i++)
        sb_rm(dirs[i]);
    raw_unlink(g_sb, 1);
}

/*
 * 沙箱建立。
 *
 * 注意 raw 侧 cwd 与 libc 侧 cwd 不是同一个目录：raw getcwd 得到的是
 * **宿主真实路径**（实测 .../linux/ubuntu/tmp/...）。沙箱就建在这个
 * 宿主路径下，这样绝对路径与相对路径在 raw 侧都成立。
 */
static int sb_setup(void)
{
    char cw[PATH_MAX];
    char p[PATH_MAX];
    int i;

    memset(cw, 0, sizeof cw);
    if (raw6(17 /*getcwd*/, (long)(intptr_t)cw, sizeof cw - 1, 0, 0, 0, 0) < 0)
        return -1;

    /* g_sb 比 cw 大 64 字节，snprintf 不会截断；返回值再校验一次 */
    if (snprintf(g_sb, sizeof g_sb, "%s/.bxroot-scg-audit-%d", cw, (int)getpid())
            >= (int)sizeof g_sb)
        return -1;
    raw_unlink(g_sb, 0);
    raw_unlink(g_sb, 1);
    if (!raw_mkdir(g_sb))
        return -1;

    sb_path(p, sizeof p, "d1");
    if (!raw_mkdir(p))
        return -1;
    if (raw_create(p) != 0) { /* 占位，下面覆盖 */ }
    raw_unlink(p, 0);

    sb_path(p, sizeof p, "d1/g1");
    if (raw_create(p) != 0)
        return -1;
    sb_path(p, sizeof p, "f1");
    if (raw_create(p) != 0)
        return -1;

    /* 相对名夹具：raw 侧相对名以 raw cwd 为基准，而子进程会 raw chdir
     * 进入沙箱 —— 所以这里必须把相对名夹具建在**沙箱**里，
     * 同时子进程 chdir 后它们才可见。 */
    {
        const char *rels[] = {"rel_f1", "rel_g3", NULL};
        for (i = 0; rels[i] != NULL; i++) {
            sb_path(p, sizeof p, rels[i]);
            if (raw_create(p) != 0)
                return -1;
        }
        sb_path(p, sizeof p, "rel_l1");
        if (!raw_symlink("rel_f1", p))
            return -1;
    }

    /* d1 里也放一份相对名（供 a0=dfd 的配对实验） */
    sb_path(p, sizeof p, "d1/rel_g3");
    if (raw_create(p) != 0)
        return -1;

    /* 绝对符号链接 l1 -> f1 */
    sb_path(p, sizeof p, "l1");
    if (!raw_symlink("f1", p))
        return -1;

    if (!g_cleanup_armed) {
        g_cleanup_armed = 1;
        atexit(sb_purge);
    }
    return 0;
}

/* ================================================================== */
/* 3. 事实库：aarch64 上"真实是什么"                                    */
/* ================================================================== */

#define BADPTR ((long)999999)
#define BADFD  ((long)999999)

/*
 * measured 字段：
 *    0  未实测（仅文档推断，报告中必须分开标注）
 *    1  本次实测确认
 *   -1  本次实测**否定**了预期
 *    2  编号在本内核上 ENOSYS（存在性无法确认）
 *    3  实测非路径型
 */
typedef struct {
    long nr;
    const char *name;
    int  parg[3];   /* 实测确认的路径参数下标 */
    int  npath;
    int  measured;
    int  vital;     /* 1 = 在 bxroot 路径翻译语义下必须覆盖 */
    const char *why;
} fact_t;

static fact_t g_facts[] = {
    /* 号   名字                  路径位          个数 证据 必须  备注 */
    {   5, "setxattr",          {0,-1,-1}, 1, 0, 1, "a0=path, a1=name, a2=value" },
    {   6, "lsetxattr",         {0,-1,-1}, 1, 0, 1, "a0=path（不跟随符号链接）" },
    {   8, "getxattr",          {0,-1,-1}, 1, 0, 1, "a0=path" },
    {   9, "lgetxattr",         {0,-1,-1}, 1, 0, 1, "a0=path" },
    {  11, "listxattr",         {0,-1,-1}, 1, 0, 1, "a0=path" },
    {  12, "llistxattr",        {0,-1,-1}, 1, 0, 1, "a0=path" },
    {  14, "removexattr",       {0,-1,-1}, 1, 0, 1, "a0=path" },
    {  15, "lremovexattr",      {0,-1,-1}, 1, 0, 1, "a0=path" },
    {  27, "inotify_add_watch", {1,-1,-1}, 1, 0, 1, "a0=fd(int), a1=path, a2=mask" },
    {  33, "mknodat",           {1,-1,-1}, 1, 0, 1, "a0=dirfd, a1=path, a2=mode, a3=dev" },
    {  34, "mkdirat",           {1,-1,-1}, 1, 0, 1, "a0=dirfd, a1=path, a2=mode" },
    {  35, "unlinkat",          {1,-1,-1}, 1, 0, 1, "a0=dirfd, a1=path, a2=flags" },
    {  36, "symlinkat",         {2,-1,-1}, 1, 0, 1, "★a0=target(链接内容,不翻), a1=dirfd(int), a2=linkpath" },
    {  37, "linkat",            {1,3,-1},  2, 0, 1, "★a0=olddirfd, a1=oldpath, a2=newdirfd, a3=newpath, a4=flags" },
    {  38, "renameat",          {1,3,-1},  2, 0, 1, "★同上布局，无 flags" },
    {  39, "umount2",           {0,-1,-1}, 1, 0, 1, "a0=target path, a1=flags" },
    {  40, "mount",             {0,1,-1},  2, 0, 1, "★a0=source(常为类型名), a1=target, a2=fstype, a3=flags" },
    {  41, "pivot_root",        {0,1,-1},  2, 0, 1, "★a0=new_root, a1=put_old" },
    {  43, "statfs",            {0,-1,-1}, 1, 0, 1, "a0=path, a1=buf" },
    {  45, "truncate",          {0,-1,-1}, 1, 0, 1, "a0=path, a1=length" },
    {  48, "faccessat",         {1,-1,-1}, 1, 0, 1, "a0=dirfd, a1=path, a2=mode" },
    {  49, "chdir",             {0,-1,-1}, 1, 0, 1, "a0=path" },
    {  50, "fchdir",            {-1,-1,-1},0, 3, 0, "非路径型：a0=fd（误列只会 EBADF，不崩）" },
    {  51, "chroot",            {0,-1,-1}, 1, 0, 1, "a0=path —— 容器根切换核心" },
    {  53, "fchmodat",          {1,-1,-1}, 1, 0, 1, "a0=dirfd, a1=path, a2=mode, a3=flags" },
    {  54, "fchownat",          {1,-1,-1}, 1, 0, 1, "a0=dirfd, a1=path, a2=uid, a3=gid, a4=flags" },
    {  56, "openat",            {1,-1,-1}, 1, 0, 1, "a0=dirfd, a1=path, a2=flags, a3=mode" },
    {  60, "quotactl",          {1,-1,-1}, 1, 0, 0, "a0=cmd, a1=special(仅部分 cmd 是路径)" },
    {  78, "readlinkat",        {1,-1,-1}, 1, 0, 1, "a0=dirfd, a1=path, a2=buf, a3=size" },
    {  79, "newfstatat",        {1,-1,-1}, 1, 0, 1, "a0=dirfd, a1=path, a2=statbuf, a3=flags" },
    {  88, "utimensat",         {1,-1,-1}, 1, 0, 1, "a0=dirfd, a1=path, a2=times, a3=flags" },
    { 180, "mq_open",           {0,-1,-1}, 1, 0, 0, "a0=POSIX mq 名（不是文件系统路径）" },
    { 181, "mq_unlink",         {0,-1,-1}, 1, 0, 0, "a0=POSIX mq 名" },
    { 221, "execve",            {0,-1,-1}, 1, 0, 1, "a0=path, a1=argv, a2=envp" },
    { 260, "wait4",             {-1,-1,-1},0, 0, 0, "★★非路径型：a0=pid, a1=int *wstatus, a2=options, a3=rusage" },
    { 264, "name_to_handle_at", {1,-1,-1}, 1, 0, 1, "a0=dirfd, a1=path, a2=handle, a3=mount_id, a4=flags" },
    { 265, "open_by_handle_at", {-1,-1,-1},0, 0, 0, "a0=mount_fd, a1=handle(二进制结构，非路径串)" },
    { 276, "renameat2",         {1,3,-1},  2, 0, 1, "★a0=olddirfd, a1=oldpath, a2=newdirfd, a3=newpath, a4=flags" },
    { 281, "execveat",          {1,-1,-1}, 1, 0, 1, "a0=dirfd, a1=path, a2=argv, a3=envp, a4=flags" },
    { 291, "statx",             {1,-1,-1}, 1, 0, 1, "a0=dirfd, a1=path, a2=flags, a3=mask, a4=buf" },
    { 428, "open_tree",         {1,-1,-1}, 1, 0, 1, "a0=dirfd, a1=path, a2=flags" },
    { 429, "move_mount",        {1,3,-1},  2, 0, 1, "★a0=from_dfd, a1=from_path, a2=to_dfd, a3=to_path, a4=flags" },
    { 430, "fsopen",            {0,-1,-1}, 1, 0, 0, "a0=fs_name（类型名，非挂载点路径）" },
    { 431, "fsconfig",          {-1,-1,-1},0, 0, 0, "无路径：key/value 由 fd 定位" },
    { 433, "fspick",            {1,-1,-1}, 1, 0, 0, "a0=dirfd, a1=path, a2=flags" },
    { 435, "clone3",            {-1,-1,-1},0, 3, 0, "非路径型（本项目另有 clone3 守卫）" },
    { 437, "openat2",           {1,-1,-1}, 1, 0, 1, "a0=dirfd, a1=path, a2=open_how*, a3=size" },
    { 439, "faccessat2",        {1,-1,-1}, 1, 0, 1, "a0=dirfd, a1=path, a2=mode, a3=flags" },
    { 442, "mount_setattr",     {1,-1,-1}, 1, 0, 0, "a0=dirfd, a1=path(可 NULL), a2=flags, a3=attr" },
    { 452, "fchmodat2",         {1,-1,-1}, 1, 0, 1, "a0=dirfd, a1=path, a2=mode, a3=flags" },
    { 457, "statmount",         {-1,-1,-1},0, 0, 0, "无路径" },
    { 458, "listmount",         {-1,-1,-1},0, 0, 0, "无路径" },
};

#define NFACTS ((int)(sizeof g_facts / sizeof g_facts[0]))

static fact_t *fact_find(long nr)
{
    int i;
    for (i = 0; i < NFACTS; i++)
        if (g_facts[i].nr == nr)
            return &g_facts[i];
    return NULL;
}

/* ================================================================== */
/* 3.5 ★ 第三种干扰源：proroot 的 SIGSYS 仿真层 ★                      */
/* ================================================================== */

/*
 * 本容器里 proroot 不只是"转发"系统调用 —— 它用 `SECCOMP_RET_TRAP` 把
 * **一批**调用拦下来，在自己的处理器里**仿真**，再把结果写回。
 *
 * 实测（见报告"三种干扰源"一节）：39 umount2 / 40 mount / 51 chroot /
 * 180 mq_open / 181 mq_unlink / 264 name_to_handle_at / 265 open_by_handle_at /
 * 428 open_tree / 429 move_mount / 430 fsopen / 431 fsconfig / 433 fspick /
 * 437 openat2 / 439 **faccessat2** / 442 mount_setattr / 452 fchmodat2
 * 都走这条路径。
 *
 * 对**参数位置审计**而言这是致命的：被仿真的调用不经过内核的路径解析，
 * 于是"伪指针 → EFAULT"这条判据完全不成立。faccessat2 就是活例：
 *
 *     439(AT_FDCWD, "/tmp", 0, 0) → 0        （正确）
 *     439(AT_FDCWD, 999999, 0, 0) → EPERM    （**不是 EFAULT**）
 *     439(999999,   "/tmp", 0, 0) → 0        （**伪 dirfd 被无视**）
 *
 * 若照搬"伪指针应 EFAULT"的判据，就会得出"439 的 a1 不是路径"这个
 * **错误结论**。所以必须先判定"这个调用有没有被仿真"，再决定用哪套判据。
 *
 * 判定手段：proroot 会把每次 trap 写进 PROROOT_SIGSYS_LOG_HOST_PATH 指向
 * 的文件（形如 `[proroot-hook] SIGSYS trapped syscall=439 pc=... pid=...`）。
 * 我们把每个受测调用单独放进一个子进程，调用后读该文件，看有没有
 * 本条 pid + 编号的记录。
 */
static const char *g_sigsys_log;

static int sigsys_trapped(pid_t pid, long nr)
{
    FILE *f;
    char buf[4096];
    char pidtag[48], nrtag[48];
    size_t n;

    if (g_sigsys_log == NULL)
        return 0;
    f = fopen(g_sigsys_log, "r");
    if (f == NULL)
        return 0;
    n = fread(buf, 1, sizeof buf - 1, f);
    buf[n] = '\0';
    fclose(f);

    snprintf(pidtag, sizeof pidtag, "pid=%d", (int)pid);
    snprintf(nrtag, sizeof nrtag, "syscall=%ld", nr);
    return strstr(buf, pidtag) != NULL && strstr(buf, nrtag) != NULL;
}

/*
 * 单独跑一次调用并判定它是否被 proroot 仿真。
 * 只看子进程"自己那次"的 trap 记录，避免不同实验互相污染。
 */
static int probe_is_trapped(long nr, const long base[6], kid_setup_fn setup)
{
    pid_t pid;
    int trapped = 0;

    if (g_sigsys_log == NULL)
        return 0;

    pid = fork();
    if (pid < 0)
        return 0;
    if (pid == 0) {
        long a[6];
        int i;
        alarm(10);
        if (g_sb[0] != '\0')
            (void)raw6(49 /*chdir*/, (long)(intptr_t)g_sb, 0, 0, 0, 0, 0);
        for (i = 0; i < 6; i++)
            a[i] = base[i];
        if (setup != NULL)
            setup(a);
        raw6(nr, a[0], a[1], a[2], a[3], a[4], a[5]);
        _exit(0);
    }
    {
        int st = 0;
        waitpid(pid, &st, 0);
    }
    trapped = sigsys_trapped(pid, nr);
    return trapped;
}


/* 把 fact_t 的路径位格式化成 "a1 + a3" 这样的串（显示用） */
static void fmt_pos(const fact_t *f, char *out, size_t n)
{
    int k;
    size_t off = 0;
    out[0] = '\0';
    for (k = 0; k < f->npath && off + 8 < n; k++)
        off += (size_t)snprintf(out + off, n - off, "%sa%d", k ? " + " : "", f->parg[k]);
    if (f->npath == 0)
        snprintf(out, n, "无");
}

/* ================================================================== */
/* 4. 每个编号的基线实参                                                */
/* ================================================================== */

/*
 * ====================================================================
 * 基线实参的两个硬性要求（两条都是踩出来的）
 * ====================================================================
 *
 * 【一】路径字符串必须放在**静态**存储里。
 * `run_call` 会 fork()，而子进程在 `pipe()` 之后才创建 —— 也就是说
 * `baseline_for()` 那个栈帧在子进程里**早已随函数返回而消失**。
 * 把它的局部数组地址塞进 a[]，子进程解引用时读到的就是已经被覆盖的栈
 * 内存（实测症状：伪指针探针得到 ENOENT 而不是 EFAULT，整个第一段
 * 满屏假 FAIL，还伴随 proroot 的 SIGSEGV 报告）。
 * 所以下面所有要用作**路径参数**的串都取自静态缓冲 g_s_f1 / g_s_dir 等。
 *
 * 【二】a0 是 dirfd 的调用，其路径参数必须用**相对路径**。
 * 内核在路径是绝对时**直接忽略 dirfd**（这是 POSIX 的既有语义，实测：
 * 伪 dirfd 999999 + 绝对路径依然成功）。因此"把 a0 换成伪 fd 看是否
 * EBADF"这条判据，只有在 a1 是相对路径时才有效 —— 否则内核根本不会
 * 去取用 a0，实验恒为"未确认"。这是本测试第一版最大的方法论错误。
 */
static char g_s_f1[PATH_MAX];     /* 普通文件            */
static char g_s_dir[PATH_MAX];    /* 目录                */
static char g_s_l1[PATH_MAX];     /* 指向 f1 的符号链接   */
static char g_s_rel[]  = "rel_f1";   /* 相对名：已存在的源文件      */
static char g_s_rel2[] = "rel_out";  /* 相对名：输出侧（不存在也行）*/
static char g_s_rel3[] = "rel_tmp";  /* 相对名：unlinkat 用的临时名 */
static char g_static_scratch[1024];

static void baseline_paths_init(void)
{
    sb_path(g_s_f1, sizeof g_s_f1, "f1");
    sb_path(g_s_dir, sizeof g_s_dir, "d1");
    sb_path(g_s_l1, sizeof g_s_l1, "l1");
}

static int baseline_for(long nr, long a[6], kid_setup_fn *setup, const char **what)
{
    char np[PATH_MAX];

    *setup = NULL;
    *what = "";

    switch (nr) {
    case 5: case 6:     /* setxattr / lsetxattr(path, name, value, size, flags) */
        a[0] = (long)(intptr_t)g_s_f1;
        a[1] = (long)(intptr_t)"user.bxroot.audit";
        a[2] = (long)(intptr_t)"v";
        a[3] = 1;
        a[4] = 0;
        *what = "xattr(path, name, value, size, flags)";
        return 1;
    case 8: case 9: case 11: case 12: case 14: case 15:
        a[0] = (long)(intptr_t)g_s_f1;
        a[1] = (long)(intptr_t)"user.bxroot.audit";
        a[2] = (long)(intptr_t)g_static_scratch;
        a[3] = sizeof g_static_scratch;
        *what = "xattr(path, name, buf, size)";
        return 1;
    case 27:            /* inotify_add_watch(fd, path, mask) —— fd 由 setup 建 */
        a[0] = -1;
        a[1] = (long)(intptr_t)g_s_dir;   /* 监视目录本身，不依赖 cwd */
        a[2] = 0xfff;
        *what = "inotify_add_watch(fd, path, mask)";
        return 1;
    case 33: case 34:   /* mknodat/mkdirat(dirfd, path, mode) —— 相对路径 */
        a[0] = AT_FDCWD;
        a[1] = (long)(intptr_t)g_s_rel2;
        a[2] = (nr == 33) ? (S_IFREG | 0644) : 0755;
        a[3] = 0;
        *what = "mknodat/mkdirat(dirfd, 相对 path, mode)";
        return 1;
    case 35:            /* unlinkat(dirfd, path, flags) */
        a[0] = AT_FDCWD;
        a[1] = (long)(intptr_t)g_s_rel3;
        a[2] = 0;
        *what = "unlinkat(dirfd, 相对 path, flags)";
        return 1;
    case 36:            /* symlinkat(target, newdirfd, linkpath) */
        a[0] = (long)(intptr_t)"rel_f1";   /* target = 链接内容，不翻译 */
        a[1] = AT_FDCWD;
        a[2] = (long)(intptr_t)g_s_rel2;
        *what = "symlinkat(target, dirfd, 相对 linkpath)";
        return 1;
    case 37:            /* linkat(olddirfd, oldpath, newdirfd, newpath, flags) */
        a[0] = AT_FDCWD;
        a[1] = (long)(intptr_t)g_s_rel;
        a[2] = AT_FDCWD;
        a[3] = (long)(intptr_t)g_s_rel2;
        a[4] = 0;
        *what = "linkat(olddirfd, 相对 oldpath, newdirfd, 相对 newpath, flags)";
        return 1;
    case 38: case 276:  /* renameat / renameat2 */
        /*
         * ★ 这两个调用**有破坏性副作用**：它们真的会把源改名走。★
         * 第一版让它们和 linkat 共用夹具 rel_f1，结果 run_measure 跑完
         * 38/276 之后 rel_f1 已经不存在了 —— 后面所有用到相对名 rel_f1
         * 的实验全部 ENOENT，看着像"参数位置错"，其实是夹具被上一个
         * 实验吃掉了。所以这里用**专用**源名，并由 setup_rename_src
         * 在子进程里（chdir 之后）重建。
         */
        a[0] = AT_FDCWD;
        a[1] = (long)(intptr_t)"rel_rnsrc";
        a[2] = AT_FDCWD;
        a[3] = (long)(intptr_t)"rel_rndst";
        a[4] = 0;
        *what = "renameat/renameat2(odfd, 相对 oldpath, ndfd, 相对 newpath, flags)";
        return 1;
    case 39:            /* umount2(target, flags) */
        a[0] = (long)(intptr_t)g_s_dir;
        a[1] = 0;
        *what = "umount2(target, flags)";
        return 1;
    case 40:            /* mount(source, target, fstype, flags, data) */
        a[0] = (long)(intptr_t)"none";
        a[1] = (long)(intptr_t)g_s_dir;
        a[2] = (long)(intptr_t)"tmpfs";
        a[3] = 0;
        a[4] = 0;
        *what = "mount(source, target, fstype, flags, data)";
        return 1;
    case 41:            /* pivot_root(new_root, put_old) */
        a[0] = (long)(intptr_t)g_s_dir;
        a[1] = (long)(intptr_t)g_s_dir;
        *what = "pivot_root(new_root, put_old)";
        return 1;
    case 43:            /* statfs(path, buf) */
        a[0] = (long)(intptr_t)g_s_f1;
        a[1] = (long)(intptr_t)g_static_scratch;
        *what = "statfs(path, buf)";
        return 1;
    case 45:            /* truncate(path, length) */
        a[0] = (long)(intptr_t)g_s_f1;
        a[1] = 2;
        *what = "truncate(path, length)";
        return 1;
    case 48: case 439:  /* faccessat(dirfd, path, mode, flags) */
        a[0] = AT_FDCWD;
        a[1] = (long)(intptr_t)g_s_rel;
        a[2] = F_OK;
        a[3] = 0;
        *what = "faccessat(dirfd, 相对 path, mode, flags)";
        return 1;
    case 49:            /* chdir(path) —— 绝对路径避免改变子进程 cwd 语义 */
        a[0] = (long)(intptr_t)g_s_dir;
        *what = "chdir(path)";
        return 1;
    case 50:            /* fchdir(fd) —— 非路径型 */
        a[0] = BADFD;
        *what = "fchdir(fd)";
        return 1;
    case 51:            /* chroot(path) */
        a[0] = (long)(intptr_t)g_s_dir;
        *what = "chroot(path)";
        return 1;
    case 53:            /* fchmodat(dirfd, path, mode, flags) */
        a[0] = AT_FDCWD;
        a[1] = (long)(intptr_t)g_s_rel;
        a[2] = 0644;
        a[3] = 0;
        *what = "fchmodat(dirfd, 相对 path, mode, flags)";
        return 1;
    case 54:            /* fchownat(dirfd, path, uid, gid, flags) */
        a[0] = AT_FDCWD;
        a[1] = (long)(intptr_t)g_s_rel;
        a[2] = (long)-1;
        a[3] = (long)-1;
        a[4] = 0;
        *what = "fchownat(dirfd, 相对 path, uid, gid, flags)";
        return 1;
    case 56:            /* openat(dirfd, path, flags, mode) */
        a[0] = AT_FDCWD;
        a[1] = (long)(intptr_t)g_s_rel;
        a[2] = O_RDONLY;
        a[3] = 0;
        *what = "openat(dirfd, 相对 path, flags, mode)";
        return 1;
    case 60:            /* quotactl(cmd, special, id, addr) */
        a[0] = 0x800001;
        a[1] = (long)(intptr_t)g_s_f1;
        a[2] = 0;
        a[3] = 0;
        *what = "quotactl(cmd, special, id, addr)";
        return 1;
    case 78:            /* readlinkat(dirfd, path, buf, size) */
        a[0] = AT_FDCWD;
        a[1] = (long)(intptr_t)"rel_l1";
        a[2] = (long)(intptr_t)g_static_scratch;
        a[3] = sizeof g_static_scratch;
        *what = "readlinkat(dirfd, 相对 path, buf, size)";
        return 1;
    case 79:            /* newfstatat(dirfd, path, buf, flags) */
        a[0] = AT_FDCWD;
        a[1] = (long)(intptr_t)g_s_rel;
        a[2] = (long)(intptr_t)g_static_scratch;
        a[3] = 0;
        *what = "newfstatat(dirfd, 相对 path, buf, flags)";
        return 1;
    case 88:            /* utimensat(dirfd, path, times, flags) */
        a[0] = AT_FDCWD;
        a[1] = (long)(intptr_t)g_s_rel;
        a[2] = 0;
        a[3] = 0;
        *what = "utimensat(dirfd, 相对 path, times, flags)";
        return 1;
    case 180: case 181: /* mq_open / mq_unlink(name) */
        a[0] = (long)(intptr_t)"/bxroot-audit-q";
        *what = "mq_open/mq_unlink(name)";
        return 1;
    case 221: case 281: /* execve / execveat —— 用**不存在**的路径做基线。
                         *
                         * 不能用 /bin/true：本容器设了 PROROOT_GUEST_EXE，
                         * exec 会被 proroot 的 trampoline 接管并改道，
                         * 拿到的 errno 与内核无关（实测 "toybox: Unknown
                         * command"、退出码 127）。用不存在的路径则子进程
                         * 能存活并把 errno 回传。 */
        if (nr == 281) {
            a[0] = AT_FDCWD;
            /* 必须用**相对名**：dirfd 探针只在相对路径下有判别力 */
            a[1] = (long)(intptr_t)"rel_no_such_exec";
            a[2] = 0;
            a[3] = 0;
            a[4] = 0;
            *what = "execveat(dirfd, path, argv, envp, flags)";
        } else {
            a[0] = (long)(intptr_t)"rel_no_such_exec";
            a[1] = 0;
            a[2] = 0;
            *what = "execve(path, argv, envp)";
        }
        return 1;
    case 260:           /* wait4(pid, int *wstatus, options, rusage) */
        a[0] = 0;                                   /* setup 填真 pid */
        a[1] = (long)(intptr_t)"/dev/null";          /* 只读地址 */
        a[2] = 0;
        a[3] = 0;
        *what = "wait4(pid, int *wstatus, options, rusage)";
        return 1;
    case 264:           /* name_to_handle_at(dirfd, path, handle, mount_id, flags) */
        a[0] = AT_FDCWD;
        a[1] = (long)(intptr_t)g_s_rel;
        a[2] = (long)(intptr_t)g_static_scratch;
        a[3] = (long)(intptr_t)(g_static_scratch + 256);
        a[4] = 0;
        *what = "name_to_handle_at(dirfd, 相对 path, handle, mount_id, flags)";
        return 1;
    case 265:           /* open_by_handle_at(mount_fd, handle, flags) */
        a[0] = BADFD;
        a[1] = (long)(intptr_t)g_static_scratch;
        a[2] = 0;
        *what = "open_by_handle_at(mount_fd, handle, flags)";
        return 1;
    case 291:           /* statx(dirfd, path, flags, mask, buf) */
        a[0] = AT_FDCWD;
        a[1] = (long)(intptr_t)g_s_rel;
        a[2] = 0;
        a[3] = 0x7ff;
        a[4] = (long)(intptr_t)g_static_scratch;
        *what = "statx(dirfd, 相对 path, flags, mask, buf)";
        return 1;
    case 428:           /* open_tree(dirfd, path, flags) */
        a[0] = AT_FDCWD;
        a[1] = (long)(intptr_t)g_s_rel;
        a[2] = 0;
        *what = "open_tree(dirfd, 相对 path, flags)";
        return 1;
    case 429:           /* move_mount(from_dfd, from_path, to_dfd, to_path, flags) */
        a[0] = AT_FDCWD;
        a[1] = (long)(intptr_t)g_s_rel;
        a[2] = AT_FDCWD;
        a[3] = (long)(intptr_t)g_s_rel2;
        a[4] = 0;
        *what = "move_mount(fdfd, 相对 from_path, tdfd, 相对 to_path, flags)";
        return 1;
    case 430:           /* fsopen(fs_name, flags) */
        a[0] = (long)(intptr_t)"tmpfs";
        a[1] = 0;
        *what = "fsopen(fs_name, flags)";
        return 1;
    case 431:           /* fsconfig(fd, cmd, key, value, aux) —— 无路径 */
        a[0] = BADFD;
        a[1] = 1;
        a[2] = (long)(intptr_t)"source";
        a[3] = (long)(intptr_t)"none";
        a[4] = 0;
        *what = "fsconfig(fd, cmd, key, value, aux)";
        return 1;
    case 433:           /* fspick(dirfd, path, flags) */
        a[0] = AT_FDCWD;
        a[1] = (long)(intptr_t)g_s_rel;
        a[2] = 0;
        *what = "fspick(dirfd, 相对 path, flags)";
        return 1;
    case 435:           /* clone3(args, size) —— 非路径型 */
        a[0] = 0;
        a[1] = 0;
        *what = "clone3(args, size)";
        return 1;
    case 437:           /* openat2(dirfd, path, open_how*, size) */
        a[0] = AT_FDCWD;
        a[1] = (long)(intptr_t)g_s_rel;
        a[2] = (long)(intptr_t)g_static_scratch;   /* open_how{0,0,0} */
        a[3] = 24;
        *what = "openat2(dirfd, 相对 path, open_how*, size)";
        return 1;
    case 442:           /* mount_setattr(dfd, path, flags, attr, size) */
        a[0] = AT_FDCWD;
        a[1] = (long)(intptr_t)g_s_rel;
        a[2] = 0;
        a[3] = 0;
        a[4] = 0;
        *what = "mount_setattr(dfd, 相对 path, flags, attr, size)";
        return 1;
    case 452:           /* fchmodat2(dirfd, path, mode, flags) */
        a[0] = AT_FDCWD;
        a[1] = (long)(intptr_t)g_s_rel;
        a[2] = 0644;
        a[3] = 0;
        *what = "fchmodat2(dirfd, 相对 path, mode, flags)";
        return 1;
    case 457: case 458: /* statmount / listmount —— 无路径 */
        a[0] = 0;
        a[1] = 0;
        *what = "statmount/listmount（无路径）";
        return 1;
    default:
        return 0;
    }
    (void)np;
}

/* inotify_add_watch 需要真 fd；setup 钩子在子进程里建 */
static void setup_inotify(long a[6])
{
    long fd = raw6(26 /* inotify_init1 */, 0, 0, 0, 0, 0, 0);
    if (fd >= 0)
        a[0] = fd;
}

/*
 * renameat/renameat2 的源：在**子进程里**（已经 chdir 进沙箱之后）
 * 用 raw 相对名重建，保证每个实验都有一份新鲜的源。
 */
static void setup_rename_src(long a[6])
{
    (void)raw6(35 /*unlinkat*/, AT_FDCWD, (long)(intptr_t)"rel_rnsrc", 0, 0, 0, 0);
    (void)raw6(35 /*unlinkat*/, AT_FDCWD, (long)(intptr_t)"rel_rndst", 0, 0, 0, 0);
    {
        long fd = raw6(56 /*openat*/, AT_FDCWD, (long)(intptr_t)"rel_rnsrc",
                       O_CREAT | O_WRONLY | O_TRUNC, 0644, 0, 0);
        if (fd >= 0)
            (void)raw6(57 /*close*/, fd, 0, 0, 0, 0, 0);
    }
    (void)a;
}

/* wait4 需要一个必然立刻变僵尸的子进程 */
static void setup_wait4_child(long a[6])
{
    pid_t c = fork();
    if (c == 0)
        _exit(42);
    if (c > 0)
        a[0] = (long)c;
}

/*
 * ====================================================================
 * ★★ 本审计最重要的方法论修正：ENOSYS 不等于"内核没有这个调用" ★★
 * ====================================================================
 *
 * 本容器（DSHA 的 Ubuntu proot 环境）里，proroot 装了一个 seccomp 过滤器，
 * 对**一大批**系统调用直接返回 ENOSYS。实测证据（0..441 全扫描，
 * 见第七段）：
 *
 *     ENOSYS 的编号里包含 39 umount2、40 mount、51 chroot、
 *     180/181 mq_open/mq_unlink、264 name_to_handle_at、265 open_by_handle_at、
 *     428 open_tree、429 move_mount、430 fsopen、431 fsconfig、433 fspick、
 *     437 openat2、273 finit_module、161/162 等
 *
 * 这些调用的编号在 asm-generic（aarch64）里**确定存在**，其中 mount/chroot
 * 是 Linux 1.x 就有的。所以这里的 ENOSYS **只可能由 seccomp 伪造**，
 * 与"内核是否实现"无关。
 *
 * 判别内核编号上限的独立实验（第七段）：全零参数扫 400..480，
 *     441 及以下仍会被派发（clone3 得 EINVAL、pidfd_getfd 得 EBADF）；
 *     442 起**全部** ENOSYS（442..461 全在内）。
 * 内核 6.1 的当前上限正好是 441，与 asm-generic 编号表完全吻合。
 * 即：**≤441 的 ENOSYS 是策略产物；≥442 的 ENOSYS 才是真"内核无此号"。**
 *
 * 后果：本次审计中凡是拿到 ENOSYS 的编号，其**参数位置一律未经实测**，
 * 报告中必须标为"未实测"，不得当作"内核不支持所以不用管"。
 * seccomp 过滤器是可变的 —— 换一个环境（或 proroot 改策略）这些调用
 * 就会出现，届时表里若有错位条目就会立刻伤人。
 */
static int g_kernel_ceiling;   /* 实测得到的编号上限（含） */

/* ---- 第二段专用：把 wstatus 带回父进程 ---------------------------- */

static long g_wstatus_probe[6];

static void after_wait4_read_writeable(long a[6], long ret, long *extra)
{
    extra[0] = ret;
    /* a1 指向可写缓冲时才读得到；a1 是只读地址则内核已 EFAULT，这里不读 */
    if (a[1] != 0 && ret > 0) {
        int ws = 0;
        memcpy(&ws, (void *)(intptr_t)a[1], sizeof ws);
        extra[1] = ws;
    }
}

static void after_wait4_read_slashbuf(long a[6], long ret, long *extra)
{
    int ws = 0;
    extra[0] = ret;
    memcpy(&ws, g_wstatus_probe, sizeof ws);
    extra[1] = ws;
    (void)a;
}

/* 子进程里：起一个被信号 SIGRTMIN+... 终止的孙进程，返回其 pid。
 * 返回 0 表示本平台信号号不可用。 */
static pid_t spawn_signal_killed(int sigdelivered)
{
    pid_t c = fork();
    if (c == 0) {
        /* 等父进程发信号；用 pause 避免忙等 */
        pause();
        _exit(0);
    }
    if (c < 0)
        return -1;
    /* 让子进程先跑起来 */
    {
        struct timespec ts = {0, 20 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    if (kill(c, sigdelivered) != 0) {
        kill(c, SIGKILL);
        return -1;
    }
    return c;
}

static void setup_wait4_signal_killed(long a[6])
{
    pid_t c = spawn_signal_killed(47);
    a[0] = (long)c;
    a[1] = (long)(intptr_t)g_wstatus_probe;   /* 可写 */
    a[2] = 0;
    a[3] = 0;
}

/* ================================================================== */
/* 5. 实测执行                                                         */
/* ================================================================== */

/*
 * aN 是路径指针？把该寄存器换成不可读伪指针 → 路径型调用在解析阶段 EFAULT。
 * **注意**：这条判据不受 dirfd 影响 —— 伪指针直接不可读，无论路径相对还是
 * 绝对，内核都要先把它当字符串读。
 *
 * setup 必须一并传入：有些调用（inotify_add_watch）的 fd 是 setup 里才建的，
 * 不跑 setup 就会在更早的阶段（EBADF）失败，从而观察不到路径解析。
 */
static int probe_is_path(long nr, int idx, const long base[6],
                         kid_setup_fn setup, int *out_err)
{
    long a[6];
    struct obs o;
    int sig, i;

    for (i = 0; i < 6; i++)
        a[i] = base[i];
    a[idx] = BADPTR;

    if (run_call(nr, a, setup, &o, &sig) != 0) {
        if (out_err) *out_err = o.err;
        return 0;
    }
    if (out_err) *out_err = o.err;
    return o.ret == -1 && o.err == EFAULT;
}

/*
 * aN 是 dirfd？换成伪 fd → EBADF。
 *
 * ★ 前提条件（第一版就在这里翻车）★
 * 内核在**路径是绝对路径时完全忽略 dirfd**。所以这个探针只有在被考察的
 * 路径参数是**相对路径**时才有判别力；用在绝对路径的基线上会恒为
 * "未确认"，与事实无关。调用方负责保证这一点（见基线的"相对 path"注释）。
 */
static int probe_is_dirfd(long nr, int idx, const long base[6],
                          kid_setup_fn setup, int *out_err)
{
    long a[6];
    struct obs o;
    int sig, i;

    for (i = 0; i < 6; i++)
        a[i] = base[i];
    a[idx] = BADFD;

    if (run_call(nr, a, setup, &o, &sig) != 0) {
        if (out_err) *out_err = o.err;
        return 0;
    }
    if (out_err) *out_err = o.err;
    return o.ret == -1 && o.err == EBADF;
}

/* 该编号是否"在路径解析之前就被权限/策略拒绝"（此时参数位置测不出来） */
static int probe_pre_path_reject(long nr, const long base[6], kid_setup_fn setup,
                                 int *out_err)
{
    long a[6];
    struct obs o;
    int sig, i;

    for (i = 0; i < 6; i++)
        a[i] = base[i];
    a[0] = BADPTR;
    a[1] = BADPTR;

    if (run_call(nr, a, setup, &o, &sig) != 0) {
        if (out_err) *out_err = o.err;
        return 0;
    }
    if (out_err) *out_err = o.err;
    /* 两个伪指针都没换来 EFAULT ⇒ 内核根本没走到路径解析 */
    return !(o.ret == -1 && o.err == EFAULT);
}

static void run_measure(void)
{
    int i;

    printf("--- 第一段：逐编号实测（每个实验都在子进程里跑，alarm(10) 兜底）---\n");

    for (i = 0; i < NFACTS; i++) {
        fact_t *f = &g_facts[i];
        long base[6] = {0, 0, 0, 0, 0, 0};
        kid_setup_fn setup = NULL;
        const char *what = "";
        struct obs o;
        int sig = 0, err = 0, rc;

        if (!baseline_for(f->nr, base, &setup, &what)) {
            doubt("编号 %-3ld %-20s 本测试未备基线，结论仅文档推断", f->nr, f->name);
            continue;
        }
        if (f->nr == 27)
            setup = setup_inotify;   /* a0 必须是**真 inotify fd**，
                                      * 否则内核在取 fd 时就 EBADF，
                                      * 永远走不到 a1 的路径解析 */
        if (f->nr == 260)
            setup = setup_wait4_child;
        /* renameat/renameat2 会真的改名，必须每次重建源 */
        if (f->nr == 38 || f->nr == 276)
            setup = setup_rename_src;

        /*
         * ============================================================
         * ★ 先判定这个调用是否被 proroot 的 SIGSYS 层**仿真** ★
         * ============================================================
         * 仿真调用的 errno 由 proroot 的处理器给出，不经过内核的路径
         * 解析，"伪指针 → EFAULT"这条判据**不成立**。此时唯一诚实的
         * 做法是标为"未实测"，而不是拿仿真结果去否定事实库
         * （faccessat2 就是这么被误判过的）。
         */
        if (probe_is_trapped(f->nr, base, setup)) {
            f->measured = 6;
            doubt("%-3ld %-20s 被 proroot 的 **SIGSYS 仿真层**接管"
                  "（日志见 PROROOT_SIGSYS_LOG_HOST_PATH）—— 本环境下"
                  "**参数位置无法实测**，只能靠 aarch64 编号表与手册推断",
                  f->nr, f->name);
            continue;
        }

        /* --- 非路径型：判据是"传伪指针不会 EFAULT" ---
         *
         * ★ wait4 必须**不带 setup** ★
         * 它的 setup 会把 a0 填成真子进程 pid —— 那正是探针要覆盖的寄存器，
         * setup 后跑就会把 BADPTR 冲掉，再因为"有子进程 + a1 是只读地址"
         * 得到 EFAULT，被误判成"a0 是路径"。这是本测试踩过的第三个坑。
         * 不带 setup 时无子进程，wait4 必返回 ECHILD，与 a0 的值无关。 */
        if (f->npath == 0) {
            int e0 = 0;
            kid_setup_fn psetup = (f->nr == 260) ? NULL : setup;
            if (probe_is_path(f->nr, 0, base, psetup, &e0)) {
                f->measured = -1;
                fail("%-3ld %-20s 事实库称非路径型，实测 a0 竟被当路径解引用（EFAULT）",
                     f->nr, f->name);
                (void)psetup;
            } else {
                f->measured = (e0 == ENOSYS) ? 4 : 3;
                ok("%-3ld %-20s 实测非路径型：a0 传伪指针不产生 EFAULT（errno=%s）",
                   f->nr, f->name, errname(e0));
            }
            continue;
        }

        /* --- 编号是否存在 --- */
        rc = run_call(f->nr, base, setup, &o, &sig);
        err = (rc == 0) ? o.err : 0;
        if (err == ENOSYS) {
            /*
             * ENOSYS 有两种完全不同的来源，必须分开报：
             *   nr > 内核编号上限  → 内核真的没这个号（"不存在"）
             *   nr <= 上限         → seccomp 过滤器伪造的 ENOSYS（"被策略屏蔽"）
             * 两者的共同点是**参数位置都没测到**，都不能当"已确认"。
             */
            f->measured = (f->nr > g_kernel_ceiling) ? 2 : 4;
            if (f->nr > g_kernel_ceiling)
                doubt("%-3ld %-20s 内核**确实没有**这个编号（> 实测上限 %d）"
                      "—— 存在性与参数位置均未实测",
                      f->nr, f->name, g_kernel_ceiling);
            else
                doubt("%-3ld %-20s ENOSYS 来自 **seccomp 策略**（编号 ≤ 实测上限 %d，"
                      "该调用在 aarch64 上确实存在）—— **参数位置未实测**，"
                      "不得记为「已验证」", f->nr, f->name, g_kernel_ceiling);
            continue;
        }

        /*
         * --- exec 系（221/281）的说明 ---
         *
         * 本容器设了 PROROOT_GUEST_EXE，**成功**的 exec 会被 proroot 的
         * trampoline 改道（实测 "toybox: Unknown command"、退出码 127）。
         * 但那不影响本审计：我们用的是**不存在的相对路径**，走的是
         * "路径解析失败"分支，伪指针 → EFAULT / 伪 dirfd → EBADF 这两条
         * 判据都仍然由内核给出（实测复核过）。所以这里**不做特殊跳过**。
         */

        /*
         * --- 有些特权调用在**路径解析之前**就做权限检查 ---
         * 典型是 pivot_root：本容器是 Android，uid 非 root，内核先返回
         * EPERM，永远走不到路径解析。此时伪指针探针没有判别力，
         * 必须如实标为"未实测"，不能因为"没得 EFAULT"就判成"a0 不是路径"。
         */
        {
            int epp = 0;
            if (probe_pre_path_reject(f->nr, base, setup, &epp)) {
                f->measured = 5;
                doubt("%-3ld %-20s 内核在**路径解析之前**就拒绝（两伪指针均无 EFAULT，"
                      "errno=%s）—— 本环境下参数位置**无法实测**", f->nr, f->name,
                      errname(epp));
                continue;
            }
        }

        /* --- 逐个寄存器实测路径位 --- */
        {
            int k, all_ok = 1;

            for (k = 0; k < f->npath; k++) {
                int idx = f->parg[k], e1 = 0;
                if (!probe_is_path(f->nr, idx, base, setup, &e1)) {
                    all_ok = 0;
                    fail("%-3ld %-20s 事实库称 a%d 是路径，实测**不是**（errno=%s，非 EFAULT）",
                         f->nr, f->name, idx, errname(e1));
                }
            }

            /* dirfd 验证：a0 以及（三参式调用的）a2 */
            if (f->nr == 33 || f->nr == 34 || f->nr == 35 || f->nr == 37 ||
                f->nr == 38 || f->nr == 48 || f->nr == 53 || f->nr == 54 ||
                f->nr == 56 || f->nr == 78 || f->nr == 79 || f->nr == 88 ||
                f->nr == 264 || f->nr == 276 || f->nr == 281 || f->nr == 291 ||
                f->nr == 428 || f->nr == 429 || f->nr == 433 || f->nr == 437 ||
                f->nr == 439 || f->nr == 442 || f->nr == 452) {
                int e2 = 0;
                if (!probe_is_dirfd(f->nr, 0, base, setup, &e2)) {
                    all_ok = 0;
                    fail("%-3ld %-20s 事实库称 a0 是 dirfd，实测**不是**（errno=%s，非 EBADF）",
                         f->nr, f->name, errname(e2));
                }
            }
            if (f->nr == 37 || f->nr == 38 || f->nr == 276 || f->nr == 429) {
                int e3 = 0;
                if (!probe_is_dirfd(f->nr, 2, base, setup, &e3)) {
                    all_ok = 0;
                    fail("%-3ld %-20s 事实库称 a2 是 dirfd，实测**不是**（errno=%s，非 EBADF）",
                         f->nr, f->name, errname(e3));
                }
            }

            if (all_ok) {
                f->measured = 1;
                if (f->npath == 2) {
                    char pos[32];
                    fmt_pos(f, pos, sizeof pos);
                    ok("%-3ld %-20s **双路径** %s 与 dirfd 全部实测确认（基线 errno=%s）",
                       f->nr, f->name, pos, errname(err));
                }
                else
                    ok("%-3ld %-20s 单路径 a%d 实测确认（基线 errno=%s）",
                       f->nr, f->name, f->parg[0], errname(err));
            } else {
                f->measured = -1;
            }
        }
    }
}

/* ---- 第二段：260 与 37 的专项判决（本审计的头号发现）---------------- */

static void d_wait4_vs_linkat(void)
{
    struct obs o;
    int sig, i;
    long a[6];

    printf("\n--- 第二段：编号 260 与 37 的专项判决 ---\n");
    printf("    待判命题：旧表 `case 260: return 1` 的注释写的是 linkat。\n");
    printf("    aarch64 上 linkat 到底是 37 还是 260？260 又是什么？\n\n");

    /* 实验 A：260 用"无子进程"的 wait4 参数 → ECHILD */
    for (i = 0; i < 6; i++) a[i] = 0;
    a[0] = -1;
    a[1] = 0;
    a[2] = WNOHANG;
    a[3] = 0;
    if (run_call(260, a, NULL, &o, &sig) == 0 && o.ret == -1 && o.err == ECHILD)
        ok("260 ← wait4 证据①：wait4(-1, NULL, WNOHANG, NULL) → ECHILD(%d)"
           "（只有 wait 家族在无子进程时返回 ECHILD）", o.err);
    else
        fail("260 传 wait4 参数未得 ECHILD（ret=%ld errno=%s sig=%d）",
             o.ret, errname(o.err), sig);

    /* 实验 B：260 的 a1 是**只写**缓冲 —— 用只读地址判决 */
    for (i = 0; i < 6; i++) a[i] = 0;
    a[0] = 0;                                 /* setup 填真 pid */
    a[1] = (long)(intptr_t)"/dev/null";        /* 可读、不可写 */
    a[2] = 0;
    a[3] = 0;
    if (run_call(260, a, setup_wait4_child, &o, &sig) == 0 &&
        o.ret == -1 && o.err == EFAULT)
        ok("260 ← wait4 证据②：a1 是**只写输出缓冲**（只读地址 → EFAULT(%d)）。"
           "路径型调用此时会**成功读**该字符串，故本条把两者区分开", o.err);
    else
        fail("260 的 a1 只写性未确证（ret=%ld errno=%s sig=%d）",
             o.ret, errname(o.err), sig);

    /* 实验 C：260 真的是 wait4 时，正常调用必须成功并写出 wstatus。
     * 注意：缓冲是**子进程**写的（fork 后写时复制），父进程要看到必须由
     * 子进程回传 —— 这正是 run_call2 的 after 钩子存在的理由。 */
    for (i = 0; i < 6; i++) a[i] = 0;
    a[0] = 0;
    a[1] = (long)(intptr_t)g_wstatus_probe;
    a[2] = 0;
    a[3] = 0;
    if (run_call2(260, a, setup_wait4_child, after_wait4_read_writeable,
                  &o, &sig) == 0 && o.ret > 0) {
        int ws = (int)g_obs_extra.v[1];
        if (WIFEXITED(ws) && WEXITSTATUS(ws) == 42)
            ok("260 ← wait4 证据③：返回子进程 pid=%ld，且子进程里读到的 "
               "wstatus=0x%x 解出 WIFEXITED=1 / WEXITSTATUS=42 —— "
               "只有 wait 家族会写这个字段", o.ret, (unsigned)ws);
        else
            doubt("260 返回 pid=%ld 但 wstatus=0x%x 解不出预期退出码 42",
                  o.ret, (unsigned)ws);
    } else {
        fail("260 的 wait4 行为未确证（ret=%ld errno=%s sig=%d）",
             o.ret, errname(o.err), sig);
    }

    /*
     * 实验 C2：**复现 case 260 的真实危害**。
     *
     * 被信号 47 终止的子进程，其 wstatus == 47 == 0x2f，首字节正好是 '/'。
     * guard 的 looks_like_guest_abs_path() 只看首字节 —— 于是它会把
     * `int *wstatus` 当路径，翻译后替换掉指针，内核把状态写进 guard 的
     * 临时缓冲，**调用方的 wstatus 永远保持原值**。
     *
     * 判据：把 wstatus 缓冲预置成一个哨兵值，调用后它必须变成 47；
     * 若仍是哨兵值，就说明发生了"写入被改道"。
     */
    {
        long a2[6];
        struct obs o2;
        int sig2 = 0;

        for (i = 0; i < 6; i++)
            g_wstatus_probe[i] = 0;
        g_wstatus_probe[0] = (long)0x5A5A5A5A;   /* 哨兵 */

        for (i = 0; i < 6; i++) a2[i] = 0;
        a2[0] = 0;                                /* setup 填 pid */
        a2[1] = (long)(intptr_t)g_wstatus_probe;
        a2[2] = 0;
        a2[3] = 0;

        if (run_call2(260, a2, setup_wait4_signal_killed, after_wait4_read_slashbuf,
                      &o2, &sig2) == 0 && o2.ret > 0) {
            int ws = (int)g_obs_extra.v[1];
            if (WIFSIGNALED(ws) && WTERMSIG(ws) == 47 && (ws & 0xff) == 0x2f)
                ok("260 危害机制已复现：被信号 47 终止的子进程 wstatus=0x%x，"
                   "**首字节 = 0x2f = '/'** —— 这正是 guard 的绝对路径判据；"
                   "若 260 被列为路径型，内核就会把状态写进 guard 的缓冲，"
                   "调用方读到哨兵 0x5A5A5A5A 而不是真实状态（**静默数据错写**）",
                   (unsigned)ws);
            else
                doubt("信号 47 实验的 wstatus=0x%x（预期 0x2f）", (unsigned)ws);
        } else {
            doubt("信号终止的 wait4 实验未跑通（ret=%ld errno=%s sig=%d）",
                  o2.ret, errname(o2.err), sig2);
        }
    }

    /*
     * 实验 D：linkat(37) 的四寄存器逐个判决。
     *
     * ★ 为什么不用"建出硬链接"做判据 ★
     * 本容器的文件系统**不允许硬链接**：实测哪怕用 libc 的 link() 在
     * 沙箱所在目录也拿 EACCES（而在别处 libc link() 反而成功 —— 又是
     * 两套命名空间的表现）。所以"成功建链"根本不是本环境可用的判据。
     * 改用三态判决，两条都发生在"建链"之前，因此与最终结果无关：
     *     a1/a3 换成伪指针 → 路径解析阶段必然 EFAULT
     *     a0/a2 换成伪 fd  → fd 解析阶段必然 EBADF
     */
    {
        static const struct {
            int idx;
            int want_err;
            const char *desc;
        } sw[4] = {
            {1, EFAULT, "a1 是 oldpath"},
            {3, EFAULT, "a3 是 newpath"},
            {0, EBADF,  "a0 是 olddirfd"},
            {2, EBADF,  "a2 是 newdirfd"},
        };
        int k, hits = 0;

        for (k = 0; k < 4; k++) {
            for (i = 0; i < 6; i++) a[i] = 0;
            a[0] = AT_FDCWD;
            a[1] = (long)(intptr_t)g_s_rel;    /* 源存在，故能走到 a0/a2 检查 */
            a[2] = AT_FDCWD;
            a[3] = (long)(intptr_t)"rel_out_ln";
            a[4] = 0;
            a[sw[k].idx] = (sw[k].want_err == EFAULT) ? BADPTR : BADFD;
            sb_rm("rel_out_ln");

            if (run_call(37, a, NULL, &o, &sig) == 0 &&
                o.ret == -1 && o.err == sw[k].want_err)
                hits++;
            else
                fail("37 的 %s 实测不符（ret=%ld errno=%s，期望 %s）",
                     sw[k].desc, o.ret, errname(o.err), errname(sw[k].want_err));
        }
        if (hits == 4)
            ok("37 ← linkat 四寄存器全部实测确认：a1/a3 是路径（→EFAULT）、"
               "a0/a2 是 dirfd（→EBADF）。本环境**禁止硬链接**（EACCES），"
               "但这两条判据都发生在建链之前，故仍然可用");
        sb_rm("rel_out_ln");
    }

    /* 实验 D2：**反证 260 不是 linkat** —— 把 linkat 的参数布局原样丢给 260。
     *
     * 判据不依赖"建出链接"（本环境禁止硬链接），而用 wait4 独有的语义：
     *   · a0 传 AT_FDCWD(-100) 当 pid → 必然 ESRCH/ECHILD 之类的 wait 错误，
     *     而 linkat 会把 -100 当 dirfd 并**正常走到建链**
     *   · a1 传一个**可读的合法路径指针**：wait4 会把它当 `int *wstatus` 并
     *     尝试写入；该指针指向只读的 .rodata 字符串 → 必然 EFAULT
     *     （linkat 会把同一指针当路径读，绝不会 EFAULT）
     * 两条同时成立即可确证 260 是 wait4。 */
    {
        sb_rm("rel_out_rn");
        for (i = 0; i < 6; i++) a[i] = 0;
        a[0] = AT_FDCWD;                      /* wait4 会当成 pid = -100 */
        a[1] = (long)(intptr_t)g_s_rel;        /* 可读路径串；wait4 会当 status 写 */
        a[2] = 0;                             /* ★ options 必须是合法值：
                                               * 塞 AT_FDCWD(-100) 会先得 EINVAL，
                                               * 观察不到 wait 的 pid 语义 */
        a[3] = 0;
        a[4] = 0;

        if (run_call(260, a, NULL, &o, &sig) == 0 && o.ret == -1 &&
            (o.err == ECHILD || o.err == ESRCH))
            ok("260 **不是** linkat（证据一）：a0 = AT_FDCWD(-100) 被当成 **pid**，"
               "得到 wait 家族独有的 %s(%d)。若 260 是 linkat，-100 会被当 dirfd "
               "并继续走路径解析，绝不会返回这个错误",
               o.err == ECHILD ? "ECHILD" : "ESRCH", o.err);
        else
            fail("260 的 linkat 反证（证据一）失败（ret=%ld errno=%s）",
                 o.ret, errname(o.err));
    }
    {
        /* 证据二：a1 指向**只读**内存 → wait4 写 status 必 EFAULT */
        for (i = 0; i < 6; i++) a[i] = 0;
        a[0] = (long)-1;                  /* 任意子进程；无子进程则 ECHILD */
        a[1] = (long)(intptr_t)"/dev/null"; /* 可读、**不可写** */
        a[2] = 0;
        a[3] = 0;
        if (run_call(260, a, NULL, &o, &sig) == 0 && o.ret == -1 && o.err == ECHILD)
            ok("260 **不是** linkat（证据二）：无子进程时 a1 根本不被写入，"
               "得到 ECHILD(%d) —— 说明 260 确实在找子进程，而不是在建硬链接",
               o.err);
        else
            doubt("260 反证（证据二）结果：ret=%ld errno=%s（不构成反证但不影响结论）",
                  o.ret, errname(o.err));
    }

    /* 实验 E：37 的 a3 是 newpath 且 a3 与 a2 配对。
     * 本环境禁止硬链接，所以判据是"伪 a2 → EBADF 且伪 a3 → EFAULT"，
     * 它在建链之前发生（已在实验 D 的四寄存器判决里覆盖）。
     * 这里补一条**正例**：用真 dfd + 相对 a3，验证内核确实去取用了 a2。 */
    {
        long dfd = raw6(56 /*openat*/, AT_FDCWD, (long)(intptr_t)g_sb,
                        O_RDONLY | O_DIRECTORY, 0, 0, 0);
        if (dfd >= 0) {
            sb_rm("rel_out_ln");
            for (i = 0; i < 6; i++) a[i] = 0;
            a[0] = AT_FDCWD;
            a[1] = (long)(intptr_t)g_s_rel;
            a[2] = dfd;
            a[3] = (long)(intptr_t)"rel_out_ln";
            a[4] = 0;
            /*
             * 真 dfd + 相对 a3：本环境会 EACCES（不许硬链接），
             * 但**绝不是** EBADF —— 说明 a2 被当成有效 dirfd 接受了。
             * 伪 a2 则 EBADF（实验 D）。两者对照即可确证 a2 是 dirfd。
             */
            if (run_call(37, a, NULL, &o, &sig) == 0 && o.err != EBADF)
                ok("37 ← a2 是 dirfd（配对确证）：真目录 fd + 相对 a3 得到 %s，"
                   "**不是** EBADF；而伪 fd 得到 EBADF（见实验 D）",
                   errname(o.err));
            else
                fail("37 的 a2 dirfd 配对未确证（ret=%ld errno=%s）",
                     o.ret, errname(o.err));
            (void)raw6(57 /*close*/, dfd, 0, 0, 0, 0, 0);
        }
        sb_rm("rel_out_ln");
    }

    /* 实验 E2：renameat(38) / renameat2(276) —— 本环境**允许**改名，
     * 所以这里能做完整的"配对 + 副作用"判决。 */
    {
        static const long rnrs[2] = {38, 276};
        int q;

        for (q = 0; q < 2; q++) {
            long rnr = rnrs[q];
            long dfd = raw6(56 /*openat*/, AT_FDCWD, (long)(intptr_t)g_sb,
                            O_RDONLY | O_DIRECTORY, 0, 0, 0);
            char nm[64];

            if (dfd < 0)
                continue;
            snprintf(nm, sizeof nm, "rel_out_%ld", rnr);
            sb_rm(nm);
            sb_rm("rel_f2");
            sb_file("rel_f2");

            /* a0 = a2 = dfd（沙箱根）；a1 相对 a0、a3 相对 a2。
             * 判据：改名成功 + 源消失 + 目标出现 = 四个寄存器全部配对正确。 */
            for (i = 0; i < 6; i++) a[i] = 0;
            a[0] = dfd;
            a[1] = (long)(intptr_t)"rel_f2";
            a[2] = dfd;
            a[3] = (long)(intptr_t)nm;
            a[4] = 0;

            if (run_call(rnr, a, NULL, &o, &sig) == 0 && o.ret == 0 &&
                sb_exists(nm) && !sb_exists("rel_f2"))
                ok("%ld ← 四寄存器全部配对正确：a1 相对 **a0** 解析、"
                   "a3 相对 **a2** 解析（真目录 fd + 相对名 → 改名成功，"
                   "源从原位置消失、目标出现）", rnr);
            else if (run_call(rnr, a, NULL, &o, &sig) == 0 && o.err == 0)
                doubt("%ld 改名成功但副作用不符（源/目标状态异常）", rnr);
            else
                fail("%ld 的 a0/a1/a2/a3 配对未确证（ret=%ld errno=%s）",
                     rnr, o.ret, errname(o.err));

            /* 还原，供后续实验复用 */
            {
                char back[PATH_MAX], from[PATH_MAX];
                sb_path(back, sizeof back, "rel_f2");
                sb_path(from, sizeof from, nm);
                if (!raw_exists(back) && raw_exists(from))
                    (void)raw6(38, AT_FDCWD, (long)(intptr_t)from,
                               AT_FDCWD, (long)(intptr_t)back, 0, 0);
            }
            sb_rm(nm);
            (void)raw6(57 /*close*/, dfd, 0, 0, 0, 0, 0);
        }
    }

    /* 实验 F：复现"把 a1 当路径"的致命后果 */
    {
        pid_t p = fork();
        if (p == 0) {
            volatile char c;
            alarm(5);
            c = *(const char *)(intptr_t)AT_FDCWD;  /* = 旧的 case 36: return 1 */
            (void)c;
            _exit(0);
        }
        {
            int st = 0;
            waitpid(p, &st, 0);
            /*
             * 两种表现都算命中：
             *   WIFSIGNALED + SIGSEGV  —— 无 proroot 时的原生表现
             *   WIFEXITED + 139        —— proroot 捕获 SIGSEGV 后 exit(139)
             * 本容器实测是后者（proroot 会打印寄存器现场再退出）。
             */
            if (WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV)
                ok("复现历史事故：把 AT_FDCWD(-100) 当 `const char *` 解引用 → SIGSEGV(%d)"
                   " —— 这正是 `case 36: return 1` 当年的后果", WTERMSIG(st));
            else if (WIFEXITED(st) && WEXITSTATUS(st) == 139)
                ok("复现历史事故：把 AT_FDCWD(-100) 当 `const char *` 解引用 → "
                   "proroot 捕获 SIGSEGV 后 exit(139)（stderr 可见 `fault=0xffffffffffffff9c`）"
                   " —— 这正是 `case 36: return 1` 当年的后果");
            else
                doubt("复现实验未得到 SIGSEGV/139（status=0x%x）", st);
        }
    }
}

/* ---- 第三段：symlinkat 判决（含"注释里那条复现不出来的证据"）-------- */

static void d_symlinkat(void)
{
    struct obs o;
    int sig, i;
    long a[6];
    char nl5[PATH_MAX], nl6[PATH_MAX], nl7[PATH_MAX];

    printf("\n--- 第三段：symlinkat(36) 参数位置判决 ---\n");

    sb_path(nl5, sizeof nl5, "nl5");
    sb_path(nl6, sizeof nl6, "nl6");
    sb_path(nl7, sizeof nl7, "nl7");
    sb_file("f5");

    /* ① 伪 dirfd(999999) + 相对 linkpath → EBADF；若 a1 是路径会 EFAULT */
    sb_rm("nl5");
    for (i = 0; i < 6; i++) a[i] = 0;
    a[0] = (long)(intptr_t)"f5";
    a[1] = BADFD;
    a[2] = (long)(intptr_t)"nl5";
    if (run_call(36, a, NULL, &o, &sig) == 0 && o.ret == -1 && o.err == EBADF)
        ok("symlinkat ①：a1 是 dirfd —— 伪 dirfd 999999 + 相对 linkpath → EBADF(%d)"
           "（若 a1 是路径，会得 EFAULT）", o.err);
    else
        fail("symlinkat 的 a1 语义未确证（ret=%ld errno=%s sig=%d）",
             o.ret, errname(o.err), sig);

    /* ② 真目录 fd + 相对 linkpath → 链接落在该目录 */
    {
        int dfd = open(g_sb, O_RDONLY | O_DIRECTORY);
        if (dfd >= 0) {
            sb_rm("nl6");
            for (i = 0; i < 6; i++) a[i] = 0;
            a[0] = (long)(intptr_t)"f5";
            a[1] = dfd;
            a[2] = (long)(intptr_t)"nl6";
            if (run_call(36, a, NULL, &o, &sig) == 0 && o.ret == 0 && sb_exists("nl6"))
                ok("symlinkat ②：相对 linkpath 相对 **a1 的 dirfd** 解析（链接落在该目录）");
            else
                fail("symlinkat 的相对路径未相对 a1 解析（ret=%ld errno=%s）",
                     o.ret, errname(o.err));
            close(dfd);
        }
    }

    /* ③ a2 是 linkpath：绝对 a2 建出链接 */
    sb_rm("nl7");
    for (i = 0; i < 6; i++) a[i] = 0;
    a[0] = (long)(intptr_t)"f5";
    a[1] = AT_FDCWD;
    a[2] = (long)(intptr_t)nl7;
    if (run_call(36, a, NULL, &o, &sig) == 0 && o.ret == 0 && sb_exists("nl7"))
        ok("symlinkat ③：a2 是 linkpath（绝对 a2 被解析并建出链接）");
    else
        fail("symlinkat 的 a2 未确证为 linkpath（ret=%ld errno=%s）",
             o.ret, errname(o.err));

    /* ④ 否证"绝对 linkpath 时内核忽略 dirfd"这条注释 */
    sb_rm("nl5");
    for (i = 0; i < 6; i++) a[i] = 0;
    a[0] = (long)(intptr_t)"f5";
    a[1] = BADFD;
    a[2] = (long)(intptr_t)nl5;
    if (run_call(36, a, NULL, &o, &sig) == 0 && o.ret == 0)
        ok("symlinkat ④：源码注释「绝对 linkpath 时内核忽略 dirfd」**可复现** —— "
           "伪 dirfd + 绝对 linkpath 竟然成功，所以那条实验不能用来判定 a1 语义");
    else
        doubt("symlinkat ④ 绝对 linkpath + 伪 dirfd 得到 ret=%ld errno=%s（与注释不同）",
              o.ret, errname(o.err));

    /* ⑤ 正确形态本身成功 —— 证明崩溃只可能来自 guard，不是内核拒绝 */
    sb_rm("nl5");
    for (i = 0; i < 6; i++) a[i] = 0;
    a[0] = (long)(intptr_t)"f5";
    a[1] = AT_FDCWD;
    a[2] = (long)(intptr_t)nl5;
    if (run_call(36, a, NULL, &o, &sig) == 0 && o.ret == 0)
        ok("symlinkat ⑤：symlinkat(\"f5\", AT_FDCWD, linkpath) 本身成功 —— "
           "崩溃只可能来自 guard 把 a1 当路径解引用，而不是内核拒绝");
    else
        doubt("symlinkat ⑤ 基线异常（ret=%ld errno=%s sig=%d）",
              o.ret, errname(o.err), sig);

    /* ⑥ a0 是"链接内容"而非待解析路径：target 原样写入 */
    {
        char buf[PATH_MAX];
        ssize_t n;
        sb_rm("nl6");
        for (i = 0; i < 6; i++) a[i] = 0;
        a[0] = (long)(intptr_t)g_sb;      /* 一段"看起来像要翻译的绝对路径" */
        a[1] = AT_FDCWD;
        a[2] = (long)(intptr_t)nl6;
        if (run_call(36, a, NULL, &o, &sig) == 0 && o.ret == 0) {
            /*
             * 注意：readlink 走的是 libc 钩子（preload.c 的 readlink hook），
             * 它会做**反向翻译**，把宿主路径还原成 guest 视角。
             * 所以这里不能用 strcmp 比原串 —— 实测传入宿主路径
             * /data/.../linux/ubuntu/root/... 读回来是 /root/...。
             * 判据改成"去掉 rootfs 前缀后完全一致"，那正是内核原样
             * 存入了 target 的证据。
             */
            const char *rf = getenv("PROROOT_ROOTFS");
            const char *expect = g_sb;
            if (rf != NULL && strncmp(g_sb, rf, strlen(rf)) == 0)
                expect = g_sb + strlen(rf);

            n = readlink(nl6, buf, sizeof buf - 1);
            if (n > 0) {
                buf[n] = '\0';
                if (strcmp(buf, expect) == 0)
                    ok("symlinkat ⑥：a0（target）是**链接内容**，内核原样存入，"
                       "未被当作待解析路径（readlink 得 %s；传入的宿主路径去除 "
                       "rootfs 前缀后同值，前缀 %s 正是 proroot libc 反向翻译所为）",
                       buf, rf != NULL ? rf : "(未设)");
                else
                    doubt("symlinkat ⑥：readlink 得 %s，期望 %s", buf, expect);
            }
        }
    }

    sb_rm("nl5"); sb_rm("nl6"); sb_rm("nl7"); sb_rm("f5");
}

/* ---- 第四段：wait4 的 wstatus 首字节 '/' 危险通道 ------------------- */

/*
 * 这是 `case 260: return 1` 的真实危害机制，必须实测复现才有说服力：
 * 被信号 N 终止的子进程 status == N；N = 47 时 status == 0x2f，首字节正好 '/'。
 * guard 的 looks_like_guest_abs_path() 只看首字节 —— 于是它会判定
 * "这是绝对路径"，把 wstatus 指针替换成自己的翻译缓冲，内核写进缓冲，
 * 调用方的 wstatus 永远不更新。
 *
 * 本段用**纯用户态逻辑**复现该判据，不依赖 guard 在场：
 * 直接按同一个判据判定一份真实的 wstatus，指出哪些信号号会触发误判。
 */
/*
 * ====================================================================
 * ★ 260 号的完整因果链（这是本审计最有价值的发现）★
 * ====================================================================
 *
 * 旧表写了 `case 260: return 1;`，注释说 260 是 linkat。
 * aarch64 上 260 其实是 **wait4**，linkat 是 37。链条如下：
 *
 *   ① 表返回 1 → guard 把 a1 当 `const char *` 读首字节
 *   ② wait4 的 a1 是 `int *wstatus`（一个**输出**缓冲）
 *   ③ 被信号 N 终止的子进程，wstatus == N；N = 47 时 wstatus == 0x2f，
 *      首字节正好是 '/' → looks_like_guest_abs_path() 返回真
 *   ④ guard 于是把 a1 **替换成自己的翻译缓冲**，内核把退出状态写进缓冲
 *   ⑤ 调用方的 wstatus 永远保持原值 → **静默数据错写**
 *
 * 本段逐环给出实测证据：③ 由下面的信号号枚举证明；
 * ⑤ 的等价实验（把缓冲预置哨兵，看它是否被写）在第二段的"实验 C2"里做。
 */
static void d_wstatus_slash_channel(void)
{
    int sig;
    int hits = 0;
    char list[256];
    size_t off = 0;
    int found47 = 0;

    printf("\n--- 第四段：wait4 的 wstatus 为何会被误判为路径 ---\n");

    list[0] = '\0';
    for (sig = 1; sig < 64; sig++) {
        /*
         * 复刻内核 wait 任务的 wstatus 编码（Linux 通用）：
         *   WIFSIGNALED  : status = 信号号（低位）
         *   WIFEXITED    : status = 退出码 << 8
         */
        int ws = sig;             /* 被信号 sig 终止 */
        unsigned char first = (unsigned char)(ws & 0xff);

        if (first == (unsigned char)'/') {
            hits++;
            if (sig == 47)
                found47 = 1;
            if (off + 8 < sizeof list)
                off += (size_t)snprintf(list + off, sizeof list - off, "%d ", sig);
        }
        /* 退出码侧：只有 exit code 0 让 status==0（首字节 0，不是 '/'） */
    }

    printf("    wstatus 首字节等于 '/' (0x2f) 的信号号共 %d 个：%s\n", hits, list);
    if (hits > 0) {
        ok("危险通道成立：被信号 %s终止的子进程，其 wstatus 首字节 = 0x2f = '/'，"
           "而 guard 的判据只看首字节 —— 于是 wait4 的**输出缓冲被当成路径**",
           list);
        if (found47)
            ok("其中包含**信号 47**（wstatus == 47 == 0x2f）—— 这就是第二段"
               "实验 C2 用来复现该危害的信号号");
        ok("该故障是**静默数据错写**（内核把退出状态写进 guard 的翻译缓冲，"
           "调用方的 wstatus 保持原值），比 SIGSEGV 更难排查");
    } else {
        doubt("未找到使 wstatus 首字节为 '/' 的信号号");
    }
}

/* ---- 第七段：区分"内核没有这个号"与"被 seccomp 策略屏蔽" ---------- */

/*
 * 全零参数扫描一段编号区间，找出"连续 ENOSYS 的起点"。内核在派发**之前**
 * 用 `nr >= __NR_syscalls` 挡掉越界号并返回 ENOSYS，所以这个起点就是
 * 内核的编号上限 + 1（前提：扫描区间要够宽，且上限之上确实没有任何号）。
 *
 * 有了这个上限，才能把两种 ENOSYS 分开：
 *     nr <= 上限 且 ENOSYS  →  **seccomp 伪造**（调用存在，参数位置"未实测"）
 *     nr >  上限 且 ENOSYS  →  内核确实没有这个号
 * 这个区分是本审计的关键：容器里 39/40/51/264/428/429/430/431/433/437
 * 全部报 ENOSYS，若照单全收当成"内核不支持"，就会把一大片**真实存在的
 * 路径型调用**误判为"不用管"。
 */
static void scan_kernel_ceiling(void)
{
    const int lo = 400, hi = 500;
    int nr, run_start = -1, last_live = -1;

    printf("\n--- 第七段：实测内核系统调用编号上限 ---\n");
    printf("    方法：全零参数逐个发起 %d..%d，找「连续 ENOSYS」的起点。\n", lo, hi);
    printf("    内核用 `nr >= __NR_syscalls` 在派发前挡掉越界号，\n");
    printf("    所以「连续 ENOSYS 的起点」= 上限+1。\n\n");

    for (nr = lo; nr <= hi; nr++) {
        pid_t c = fork();
        int st = 0, e = 0;

        if (c == 0) {
            alarm(3);
            raw6(nr, 0, 0, 0, 0, 0, 0);
            e = errno > 127 ? 127 : errno;
            _exit(e);
        }
        if (waitpid(c, &st, 0) != c)
            continue;
        if (WIFSIGNALED(st)) {
            run_start = -1;
            continue;
        }
        e = WEXITSTATUS(st);
        if (e == ENOSYS) {
            if (run_start < 0)
                run_start = nr;
        } else {
            last_live = nr;
            run_start = -1;
        }
    }

    if (run_start > 0 && last_live > 0) {
        /* 复查：起点之后直到 hi 必须**全部** ENOSYS，否则不是上限 */
        int probe_ok = 1, k;
        for (k = run_start; k <= hi && k <= run_start + 20; k++) {
            pid_t c = fork();
            int st = 0;
            if (c == 0) {
                alarm(3);
                raw6(k, 0, 0, 0, 0, 0, 0);
                _exit(errno > 127 ? 127 : errno);
            }
            if (waitpid(c, &st, 0) == c && !WIFSIGNALED(st) && WEXITSTATUS(st) != ENOSYS)
                probe_ok = 0;
        }
        if (probe_ok) {
            g_kernel_ceiling = run_start - 1;
            ok("内核编号上限实测 = %d（最后一个被派发的号是 %d，%d 起全部 ENOSYS）"
               "—— 与 asm-generic 编号表吻合（clone3=435、pidfd_getfd=438、"
               "faccessat2=439 都在上限内且非 ENOSYS）",
               g_kernel_ceiling, last_live, run_start);
            printf("    ★ 推论：**≤ %d 的任何 ENOSYS 都是 seccomp 策略伪造的**，\n"
                   "      不代表内核没有该调用。\n", g_kernel_ceiling);
        } else {
            doubt("连续 ENOSYS 起点 %d 之后并非全 ENOSYS，无法断定上限", run_start);
            g_kernel_ceiling = 441;   /* 本内核 6.1 的已知值，作为保守回退 */
        }
    } else {
        doubt("未扫出连续 ENOSYS 区间，无法确定上限；保守取 441");
        g_kernel_ceiling = 441;
    }
}

/* ================================================================== */
/* 6. 解析 syscall_guard.c 里**实际**的表                              */
/* ================================================================== */

typedef struct {
    long nr;
    unsigned mask;    /* 归一化后的路径位掩码（两种接口形态统一到这里） */
    int  raw;         /* 源码里原样的返回值，供报告展示 */
    int  legacy;      /* 1 = 形态 A（下标/-1），0 = 形态 B（掩码） */
    int  lineno;
} decl_t;

#define MAXDECL 64
static decl_t g_decls[MAXDECL];
static int g_ndecl;
static int g_legacy_form;   /* 1 = path_arg_index（旧），0 = path_arg_mask（新） */

static void strip_comments(const char *in, char *out, size_t n)
{
    size_t i = 0, j = 0;
    int in_block = 0, in_line = 0, in_str = 0;

    while (in[i] != '\0' && j + 1 < n) {
        char c = in[i], d = in[i + 1];

        if (in_line) {
            if (c == '\n') { in_line = 0; out[j++] = c; }
            else out[j++] = ' ';
            i++;
            continue;
        }
        if (in_block) {
            if (c == '*' && d == '/') { in_block = 0; out[j++] = ' '; out[j++] = ' '; i += 2; }
            else { out[j++] = (c == '\n') ? '\n' : ' '; i++; }
            continue;
        }
        if (in_str) {
            out[j++] = c;
            if (c == '\\' && d != '\0') { out[j++] = d; i += 2; continue; }
            if (c == '"') in_str = 0;
            i++;
            continue;
        }
        if (c == '/' && d == '*') { in_block = 1; out[j++] = ' '; out[j++] = ' '; i += 2; continue; }
        if (c == '/' && d == '/') { in_line = 1; out[j++] = ' '; out[j++] = ' '; i += 2; continue; }
        if (c == '"') { in_str = 1; out[j++] = c; i++; continue; }
        out[j++] = c;
        i++;
    }
    out[j] = '\0';
}

static char *slurp(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    char *buf;
    long sz;

    if (f == NULL)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    rewind(f);
    buf = (char *)malloc((size_t)sz + 1);
    if (buf == NULL) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) { free(buf); fclose(f); return NULL; }
    buf[sz] = '\0';
    fclose(f);
    if (len != NULL) *len = (size_t)sz;
    return buf;
}

static unsigned long fingerprint(const char *s)
{
    unsigned long h = 5381;
    while (*s != '\0')
        h = ((h << 5) + h) + (unsigned char)*s++;
    return h;
}

/*
 * 把源文件里的 case 归一到"路径位掩码"。
 *
 * 形态 A：`case 36: return 1;`      → 下标 1 → 掩码 1u<<1
 *         `case 221: return 0;`     → 下标 0 → 掩码 1u<<0
 *         `case 36: return -1;`     → 不是路径型（表里一般不写）
 * 形态 B：`case 276: return (1u << 1) | (1u << 3);` → 直接解析表达式
 */
static int parse_case_expr(const char *p, unsigned *mask, int *raw, int legacy)
{
    const char *q = strchr(p, ':');
    long nr;
    char expr[128];
    int i = 0;

    if (q == NULL)
        return 0;
    if (sscanf(p, "case %ld", &nr) != 1)
        return 0;

    q++;
    while (*q == ' ' || *q == '\t')
        q++;
    if (strncmp(q, "return", 6) != 0)
        return 0;
    q += 6;
    while (*q == ' ' || *q == '\t')
        q++;
    while (*q != '\0' && *q != ';' && *q != '\n' && i < (int)sizeof expr - 1)
        expr[i++] = *q++;
    expr[i] = '\0';

    if (legacy) {
        long v = strtol(expr, NULL, 10);
        *raw = (int)v;
        if (v < 0 || v > 5) { *mask = 0; return -1; }  /* -1 = 非路径型 */
        *mask = 1u << v;
        return (int)nr;
    }

    /* 形态 B：只接受 `1u << N` 与 `|` 组合 */
    {
        unsigned m = 0;
        const char *r = expr;
        while (*r != '\0') {
            while (*r == ' ' || *r == '(' || *r == ')') r++;
            if (*r == '\0')
                break;
            if (sscanf(r, "1u << %u", &m) == 1 || sscanf(r, "1 << %u", &m) == 1) {
                if (m > 5) { *mask = 0; *raw = 0; return (int)nr; }
                *mask |= 1u << m;
                while (*r != '\0' && *r != '|') r++;
                if (*r == '|') r++;
                continue;
            }
            if (*r == '0') { r++; continue; }   /* return 0 */
            break;
        }
        *raw = (int)*mask;
        *mask = (*raw == 0) ? 0u : *mask;
        return (int)nr;
    }
}

static int parse_table(const char *srcfile)
{
    size_t len = 0;
    char *raw = slurp(srcfile, &len);
    char *clean;
    char *p;
    int lineno = 1;

    if (raw == NULL) {
        fprintf(stderr, "❌ 读不到 %s\n", srcfile);
        return -1;
    }

    clean = (char *)malloc(len + 1);
    if (clean == NULL) { free(raw); return -1; }
    strip_comments(raw, clean, len + 1);

    g_legacy_form = (strstr(clean, "path_arg_index") != NULL &&
                     strstr(clean, "path_arg_mask") == NULL) ? 1 : 0;

    printf("源文件 : %s\n", srcfile);
    printf("字节数 : %lu\n", (unsigned long)len);
    printf("指纹   : %08lx（djb2，用于标注审计快照）\n", fingerprint(raw));
    printf("表接口 : %s（%s）\n",
           g_legacy_form ? "path_arg_index" : "path_arg_mask",
           g_legacy_form ? "形态 A：返回 0/1 下标" : "形态 B：返回 1u<<N 位掩码");

    free(raw);

    p = strstr(clean, g_legacy_form ? "path_arg_index" : "path_arg_mask");
    if (p == NULL)
        p = strstr(clean, "path_arg_");
    if (p == NULL) {
        fprintf(stderr, "❌ 在源文件里找不到 path_arg_* 函数\n");
        free(clean);
        return -1;
    }

    /* 从函数定义处往后扫到第一个顶格的 '}' */
    while (*p != '\0') {
        if (*p == '\n') {
            lineno++;
            if (p[1] == '}')
                break;
        }
        if (strncmp(p, "case ", 5) == 0) {
            unsigned mask = 0;
            int rawv = 0;
            int nr = parse_case_expr(p, &mask, &rawv, g_legacy_form);
            if (nr > 0 && g_ndecl < MAXDECL) {
                g_decls[g_ndecl].nr = nr;
                g_decls[g_ndecl].mask = (rawv < 0) ? 0u : mask;
                g_decls[g_ndecl].raw = rawv;
                g_decls[g_ndecl].legacy = g_legacy_form;
                g_decls[g_ndecl].lineno = lineno;
                g_ndecl++;
            }
        }
        p++;
    }

    free(clean);
    return g_ndecl > 0 ? 0 : -1;
}

static decl_t *decl_find(long nr)
{
    int i;
    for (i = 0; i < g_ndecl; i++)
        if (g_decls[i].nr == nr)
            return &g_decls[i];
    return NULL;
}

/* ================================================================== */
/* 7. 表 × 事实库 交叉核对                                             */
/* ================================================================== */

static void audit_table(void)
{
    int i, j;

    printf("\n--- 第五段：表内条目逐条核对（实测事实库 × 源码实际表项）---\n");
    printf("    从源码解析出 %d 个 case 条目\n\n", g_ndecl);

    for (i = 0; i < g_ndecl; i++) {
        long nr = g_decls[i].nr;
        unsigned mask = g_decls[i].mask;
        fact_t *f = fact_find(nr);
        char decltxt[64];

        if (g_legacy_form)
            snprintf(decltxt, sizeof decltxt, "return %d", g_decls[i].raw);
        else
            snprintf(decltxt, sizeof decltxt, "掩码 0x%x", mask);

        if (f == NULL) {
            doubt("case %-3ld (%s) @L%d：本测试无该编号的事实，无法判定",
                  nr, decltxt, g_decls[i].lineno);
            continue;
        }

        if (f->measured == 4) {
            doubt("case %-3ld (%s) %-20s：ENOSYS 由 **seccomp 策略**伪造（编号存在），"
                  "**参数位置未经实测** —— 表中该条目前只有文档依据", nr, decltxt, f->name);
            continue;
        }
        if (f->measured == 5) {
            doubt("case %-3ld (%s) %-20s：内核在路径解析前就拒绝（权限/环境），"
                  "**参数位置未经实测**", nr, decltxt, f->name);
            continue;
        }
        if (f->measured == 6) {
            doubt("case %-3ld (%s) %-20s：被 proroot **SIGSYS 仿真层**接管，"
                  "**参数位置未经实测** —— 表中该条目前只有文档依据",
                  nr, decltxt, f->name);
            continue;
        }
        if (f->measured == 2) {
            doubt("case %-3ld (%s) %-20s：内核确实无此编号，**参数位置未经实测**",
                  nr, decltxt, f->name);
            continue;
        }
        if (f->measured == 0) {
            doubt("case %-3ld (%s) %-20s：%s —— 结论仅有文档推断，需补实测",
                  nr, decltxt, f->name, f->why);
            continue;
        }
        if (f->measured == -1) {
            fail("case %-3ld (%s) %-20s：事实库自身被实测否定，详见第一段",
                 nr, decltxt, f->name);
            continue;
        }

        /* 编号本身是不是路径型 */
        if (f->npath == 0) {
            fail("case %-3ld (%s) @L%d：编号 %ld 在 aarch64 上是 **%s**，"
                 "实测**非路径型** —— 表里把它当路径会把非指针参数解引用",
                 nr, decltxt, g_decls[i].lineno, nr, f->name);
            continue;
        }

        /* 掩码里的每个位都必须是实测确认的路径位 */
        {
            int bad = 0;
            for (j = 0; j < 6; j++) {
                int k, hit;
                if (!(mask & (1u << j)))
                    continue;
                hit = 0;
                for (k = 0; k < f->npath; k++)
                    if (f->parg[k] == j)
                        hit = 1;
                if (!hit) {
                    char pos[32];
                    fmt_pos(f, pos, sizeof pos);
                    fail("case %-3ld (%s) @L%d：%s 的**路径位**是 %s，"
                         "表中把 a%d 标为路径 —— 实测错误（a%d 不是路径）",
                         nr, decltxt, g_decls[i].lineno, f->name, pos, j, j);
                    bad = 1;
                }
            }
            if (bad)
                continue;
        }

        /* 覆盖完整性 */
        {
            int covered = 0;
            for (j = 0; j < f->npath; j++)
                if (mask & (1u << f->parg[j]))
                    covered++;
            if (covered < f->npath) {
                char pos[32];
                fmt_pos(f, pos, sizeof pos);
                doubt("case %-3ld (%s) @L%d：%s 有 %d 个路径参数（%s），"
                      "表只标了 %d 个 —— 有路径位**未被翻译**",
                      nr, decltxt, g_decls[i].lineno, f->name, f->npath, pos, covered);
                continue;
            }
            {
                char pos[32];
                fmt_pos(f, pos, sizeof pos);
                ok("case %-3ld (%s) %-20s 正确：实测路径位 %s 全部覆盖",
                   nr, decltxt, f->name, pos);
            }
        }
    }
}

/* ================================================================== */
/* 8. 遗漏清单                                                         */
/* ================================================================== */

static void audit_omissions(void)
{
    int i;

    printf("\n--- 第六段：遗漏清单（实测为路径型但表里没有）---\n");

    for (i = 0; i < NFACTS; i++) {
        fact_t *f = &g_facts[i];

        if (f->npath == 0 || decl_find(f->nr) != NULL)
            continue;

        if (f->measured == 4 || f->measured == 5 || f->measured == 6) {
            if (f->vital) {
                char pos[32];
                fmt_pos(f, pos, sizeof pos);
                missing("%-3ld %-20s 路径位 %s —— **未列入**（本机被 seccomp/仿真层"
                        "遮挡，但该调用确实存在；环境一变即绕过翻译）",
                        f->nr, f->name, pos);
            }
            continue;
        }
        if (f->measured == 2) {
            if (f->vital)
                doubt("%-3ld %-20s 内核无此编号；列入与否取决于目标内核版本", f->nr, f->name);
            continue;
        }

        {
            char pos[32];
            fmt_pos(f, pos, sizeof pos);
            if (f->vital)
                missing("%-3ld %-20s 路径位 %s —— 未列入，走裸 syscall 时绕过翻译",
                        f->nr, f->name, pos);
            else
                printf("  [低频] %-3ld %-20s 路径位 %s —— 未列入（影响面小，可接受）\n",
                       f->nr, f->name, pos);
        }
    }

    for (i = 0; i < g_ndecl; i++)
        if (fact_find(g_decls[i].nr) == NULL)
            doubt("表里的 case %ld 不在事实库中 —— 请补一条实测后加入事实库",
                  g_decls[i].nr);
}

/* ================================================================== */
/* 9. Markdown 汇总                                                    */
/* ================================================================== */

static const char *meas_text(int m)
{
    switch (m) {
    case 1:  return "实测确认";
    case 2:  return "内核无此编号（未实测）";
    case 3:  return "实测非路径型";
    case 4:  return "seccomp 屏蔽（未实测）";
    case 5:  return "权限先于路径解析（未实测）";
    case 6:  return "**proroot 仿真（未实测）**";
    case -1: return "被实测否定";
    default: return "**仅文档推断**";
    }
}

static void emit_markdown(void)
{
    int i;

    printf("\n\n===== MARKDOWN 汇总（可直接引用进审计报告）=====\n\n");
    printf("| 编号 | aarch64 真实名字 | 路径参数 | 证据等级 | 表中是否列出 |\n");
    printf("|---|---|---|---|---|\n");
    for (i = 0; i < NFACTS; i++) {
        fact_t *f = &g_facts[i];
        char pos[64];
        decl_t *d = decl_find(f->nr);

        if (f->npath == 0)
            snprintf(pos, sizeof pos, "无（非路径型）");
        else
            fmt_pos(f, pos, sizeof pos);

        printf("| %ld | `%s` | %s | %s | %s |\n",
               f->nr, f->name, pos, meas_text(f->measured),
               d != NULL ? "是" : "否");
    }
    printf("\n");
}

/* ================================================================== */
/* 10. main                                                            */
/* ================================================================== */

int main(int argc, char **argv)
{
    const char *src = "src/runtime/syscall_guard.c";
    int want_md = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--md") == 0)
            want_md = 1;
        else
            src = argv[i];
    }

    setvbuf(stdout, NULL, _IOLBF, 0);

    printf("======================================================================\n");
    printf(" bxroot 系统调用路径参数表 —— 实测审计\n");
    printf(" 本测试用**裸 svc**，不经 libc 的 syscall()，量的是内核而不是 guard\n");
    printf("======================================================================\n");

    if (parse_table(src) != 0) {
        fprintf(stderr, "❌ 解析不出表（源文件可能正在被并行修改）\n");
        return 2;
    }

    if (sb_setup() != 0) {
        fprintf(stderr, "❌ 无法建立沙箱目录 %s\n", g_sb);
        return 2;
    }
    baseline_paths_init();

    /*
     * SIGSYS 仿真层探测所需。没有这个环境变量就退化为"不做仿真判定"，
     * 测试仍能跑，只是会少一重甄别（报告里会说明）。
     */
    g_sigsys_log = getenv("PROROOT_SIGSYS_LOG_HOST_PATH");

    printf("沙箱   : %s\n", g_sb);
    printf("SIGSYS 日志 : %s\n\n",
           g_sigsys_log != NULL ? g_sigsys_log : "（未设置 → 跳过仿真层甄别）");
    fflush(stdout);

    /* 必须最先跑：g_kernel_ceiling 决定了后面所有 ENOSYS 的解释方式 */
    scan_kernel_ceiling();

    run_measure();
    d_wait4_vs_linkat();
    d_symlinkat();
    d_wstatus_slash_channel();
    audit_table();
    audit_omissions();

    printf("\n--- 汇总 ---\n");
    printf("  检查项        : %d\n", g_checks);
    printf("  不一致 (FAIL) : %d\n", g_fails);
    printf("  存疑          : %d\n", g_doubts);
    printf("  遗漏（必须覆盖）: %d\n", g_missing);
    printf("  RESULT        : %s\n", (g_fails == 0 && g_missing == 0) ? "PASS" : "FAIL");

    if (want_md)
        emit_markdown();

    return (g_fails == 0 && g_missing == 0) ? 0 : 1;
}
