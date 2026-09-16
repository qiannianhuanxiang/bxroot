/*
 * renameat / renameat2 / linkat / symlinkat 的**参数位置契约**测试。
 *
 * ====================================================================
 * 由来
 * ====================================================================
 *
 * syscall_guard.c 里有一张"哪些参数寄存器是路径"的位掩码表。本文件是
 * 它的防回归测试，覆盖这一族调用的**每一个**参数位置。
 *
 * 之所以要单独写一份（test/test_syscall_argpos.c 已覆盖 symlinkat 的 a1），
 * 是因为本轮修 renameat/renameat2/linkat 的**第二个路径参数**时，
 * 实测翻出了两个既有缺陷：
 *
 *   ① 表里的 `case 260` 被当作 linkat —— **错**。260 是 wait4，
 *      真正的 SYS_linkat == 37。后果不是"少翻译一条"而是主动制造故障：
 *      wait4 的 a1 是 `int *wstatus`，而把被信号 47 杀死的子进程
 *      wstatus（=47=0x2F）首字节恰好是 '/'，于是 guard 把**退出状态
 *      缓冲区**当路径送去翻译，内核把状态写进了 guard 的临时缓冲，
 *      调用方永远读不到 —— 静默的数据错写。
 *   ② renameat/renameat2/linkat 的 newpath 在 a3，旧接口只能表达一个
 *      位置，于是第二个路径长久没被翻译。
 *
 * ====================================================================
 * 本测试怎么"真的"区分「翻译了」和「没翻译」
 * ====================================================================
 *
 * syscall_guard.c 把路径翻译委托给 `bxroot_translate_path()`（正常由
 * preload.c 提供）。本测试**自带一个翻译桩**，并与 syscall_guard.c
 * 一起编译，于是能在**同一个进程内**观察并驱动翻译层：
 *
 *   - 桩把 guest 路径 "/g/xxx" 映射到宿主临时目录 <base>/xxx；
 *   - 于是 `syscall(SYS_renameat2, AT_FDCWD, "/g/src", AT_FDCWD, "/g/dst", 0)`
 *     只有在 **a1 与 a3 都被翻译**时才会成功，文件才会真的落到
 *     <base>/dst。若 a3 漏翻，内核收到的 new="/g/dst"，调用必然失败、
 *     文件原地不动 —— 测试立刻变红。
 *   - 同时桩**记录每一次被传入的指针**，据此断言"被当路径解引用的
 *     寄存器"恰好是 a1/a3（renameat 族）、a2（symlinkat），
 *     且**永远不含 dirfd**（AT_FDCWD = -100 的历史事故点）。
 *     这是最硬的一类证据：直接看是哪个寄存器被送去翻译。
 *   - 反向对照（g_translate_on=0）证明"不翻译时本测试确实会失败"，
 *     也就是证明本测试**有区分能力**，而不是恒真。
 *
 * 桩对 < 4096 的"指针"（含 NULL 与 AT_FDCWD=-100）**拒绝解引用**，
 * 只置错误标志并返回 -1。这样一旦 guard 退回到"把 dirfd 当路径"的
 * 老 bug，测试会**报出可读的 FAIL**，而不是以 SIGSEGV 静默收场。
 *
 * ====================================================================
 * ★ 为什么文件系统操作全部走**裸系统调用** ★
 * ====================================================================
 *
 * 这是本测试最容易写错、也最值得记录的一点。
 *
 * 症状：最初版本用 glibc 的 open()/mkdir() 造测试夹具，再用
 * `syscall()`（= guard 的裸 svc）去断言，结果在**某些环境下**全红：
 * 用 glibc 建好的文件，裸 svc 报 ENOENT；裸 svc 建的目录，glibc 看不见。
 *
 * 根因：本容器里存在**外层 proroot** 的用户态路径翻译。它工作在
 * glibc 符号层，而 syscall_guard.c 的转发是**裸 svc**（这是它存在的
 * 全部理由 —— 绕开会被递归调用的 libc syscall()）。两者因此可能
 * 落在**不同的命名空间视图**里。实测证据（base 目录选 /tmp 时）：
 *
 *     glibc mkdir("/tmp/x")  → 成功；裸 svc newfstatat("/tmp/x") → ENOENT
 *     glibc stat() 看得见自己建的文件 = 是；裸 svc 看得见 = 否
 *
 * 而换到 /sdcard/Download 下，两者就**一致**（这是本测试选 base 的依据）。
 *
 * 所以本测试的做法是：
 *   ① 先**探测**一个"裸 svc 能写、且 glibc 也看得见"的 base 目录；
 *   ② 之后**所有**夹具创建与结果核对都走裸 svc —— 调用方式自洽，
 *      不再依赖 glibc 与裸 svc 视图一致这个假设。
 *
 * 这样本测试在任何环境（普通 CI 的 /tmp 可用，或只有 /sdcard 可写）
 * 都能给出可信结论，而不是把环境差异误报成代码缺陷。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/wait.h>

/* ------------------------------------------------------------------ */
/* 裸系统调用（与 guard 内部同一手法，供夹具与核对使用）               */
/* ------------------------------------------------------------------ */

static long raw6(long nr, long a0, long a1, long a2, long a3, long a4)
{
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = 0;

    __asm__ __volatile__("svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
        : "memory", "cc");

    if (x0 < 0 && x0 > -4096) { errno = (int)(-x0); return -1; }
    return x0;
}

#define R_mkdirat(dirfd, path, mode)   raw6(SYS_mkdirat,   (dirfd), (long)(path), (mode), 0, 0)
#define R_openat(dirfd, path, fl, md)  raw6(SYS_openat,    (dirfd), (long)(path), (fl), (md), 0)
#define R_close(fd)                    raw6(SYS_close,     (fd), 0, 0, 0, 0)
#define R_read(fd, buf, n)             raw6(SYS_read,      (fd), (long)(buf), (n), 0, 0)
#define R_write(fd, buf, n)            raw6(SYS_write,     (fd), (long)(buf), (n), 0, 0)
#define R_unlinkat(dirfd, path, fl)    raw6(SYS_unlinkat,  (dirfd), (long)(path), (fl), 0, 0)
#define R_fstatat(dirfd, path, st)     raw6(SYS_newfstatat,(dirfd), (long)(path), (long)(st), 0, 0)
#define R_lstatat(dirfd, path, st)     raw6(SYS_newfstatat,(dirfd), (long)(path), (long)(st), AT_SYMLINK_NOFOLLOW, 0)

/*
 * 路径是否存在。两个版本，用途不同 —— 这里踩过一次坑：
 *
 *   fstatat 默认**跟随**符号链接。符号链接的目标不存在时（悬空链接），
 *   它返回 ENOENT，于是"链接明明建成功了"却判成不存在。
 *   实测：symlinkat 建出 l -> "TGT"（TGT 不存在）后，
 *         fstatat(l)                → ENOENT   ← 看起来像没建成
 *         fstatat(l, NOFOLLOW)      → 0        ← 这才是"链接存在"
 *         readlinkat(l)             → "TGT"
 *
 * 所以：核对**普通文件**用 r_exists；核对**符号链接本身**必须用 r_lexists。
 */
static int r_exists(const char *p)
{
    struct stat st;
    return R_fstatat(AT_FDCWD, p, &st) == 0;
}

/* 不跟随符号链接的存在性（悬空链接也算存在） */
static int r_lexists(const char *p)
{
    struct stat st;
    return R_lstatat(AT_FDCWD, p, &st) == 0;
}

/* 用裸 svc 建文件并写入内容 */
static int r_write_file(const char *p, const char *s)
{
    long fd = R_openat(AT_FDCWD, p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    if (R_write(fd, s, (long)strlen(s)) < 0) { R_close(fd); return -1; }
    R_close(fd);
    return 0;
}

/* 用裸 svc 读文件内容；返回 1 表示读到，内容放 out */
static int r_read_file(const char *p, char *out, size_t n)
{
    long fd = R_openat(AT_FDCWD, p, O_RDONLY, 0);
    long k;
    if (fd < 0) return 0;
    k = R_read(fd, out, (long)(n - 1));
    R_close(fd);
    if (k < 0) k = 0;
    out[k] = '\0';
    return 1;
}

/* ------------------------------------------------------------------ */
/* 翻译桩：由 syscall_guard.c 调用（它声明为 extern）                   */
/* ------------------------------------------------------------------ */

#define SEEN_MAX 32

static char  g_hostroot[1024];      /* "/g/xxx"  →  <hostroot>/xxx        */
static int   g_translate_on = 1;    /* 反向对照用：关掉翻译               */
static const char *g_seen[SEEN_MAX];/* 桩被传入的每个指针（按顺序）       */
static int   g_seen_n;
static int   g_bad_ptr;             /* 桩收到了明显不是指针的值（dirfd）  */

/*
 * guest 侧路径用**具名静态数组**，这样测试可以取到它们的地址，
 * 与桩看到的指针逐位比对 —— "哪个寄存器被当路径解引用"的直接证据。
 */
static char GSRC[] = "/g/src";
static char GDST[] = "/g/dst";
static char GLNK[] = "/g/lnk";
static char GX[]   = "/g/x";   /* NULL 用例里的"另一条有效路径" */

int bxroot_translate_path(const char *path, char *out, size_t out_size);

int bxroot_translate_path(const char *path, char *out, size_t out_size)
{
    if (g_seen_n < SEEN_MAX)
        g_seen[g_seen_n++] = path;

    /* 防御：dirfd / NULL 被当路径送进来时，绝不解引用（那会静默崩溃） */
    if ((uintptr_t)path < 4096) {
        g_bad_ptr = (path == NULL) ? 1 : 2;
        return -1;
    }

    if (!g_translate_on)
        return 0;

    /*
     * 忠实模仿 preload.c 的 translate_path：**任何**以 '/' 开头的字符串
     * 都当成 guest 绝对路径，加上前缀后返回 >0。
     *
     * 【为什么必须"忠实"，不能图省事】
     * 我第一版写成"只认 /g/ 前缀，其余返回 0（无需翻译）"。那看起来
     * 更干净，却**掩盖了 260 事故**：wait4 的 a1 是 `int *wstatus`，
     * 若它的首字节恰好是 '/'，真实 translate_path 会把它当绝对路径
     * 翻译掉，而我的桩因为第二个字节不是 'g' 就返回 0，于是 bug
     * 测不出来 —— 测试变绿，缺陷照旧。
     *
     * 教训与项目里记的那次 symlinkat 一模一样：**桩必须和被替代的
     * 东西同语义**，否则测试会给出虚假的安全感。
     */
    if (path[0] != '/')
        return 0;

    if (path[1] == 'g' && path[2] == '/') {
        int n = snprintf(out, out_size, "%s/%s", g_hostroot, path + 3);
        if (n < 0 || (size_t)n >= out_size)
            return -1;
        return n;
    }

    /* 其余绝对路径：按"加 rootfs 前缀"处理，与真实实现同类 */
    {
        int n = snprintf(out, out_size, "%s%s", g_hostroot, path);
        if (n < 0 || (size_t)n >= out_size)
            return -1;
        return n;
    }
}

/* ------------------------------------------------------------------ */
/* 测试框架                                                            */
/* ------------------------------------------------------------------ */

static int cases, failed;

static void check(const char *name, int ok, const char *detail)
{
    cases++;
    if (!ok) {
        failed++;
        printf("  [FAIL] %s\n         %s\n", name, detail);
    } else {
        printf("  [ok]   %s\n", name);
    }
}

static void seen_reset(void)
{
    g_seen_n = 0;
    g_bad_ptr = 0;
}

/* 桩收到的指针里有没有 NULL */
static int seen_has_null(void)
{
    int i;
    for (i = 0; i < g_seen_n; i++)
        if (g_seen[i] == NULL) return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* base 目录探测                                                       */
/* ------------------------------------------------------------------ */

/*
 * 找一个"裸 svc 能写"的目录。判据全部用裸 svc，避免依赖 glibc 视图。
 * 顺序：环境变量指定 → /tmp → TMPDIR → /sdcard/Download → 当前目录。
 */
/*
 * 探测一个可用的 base 目录。要求**全部用裸 svc 验证**：
 *   ① 能建目录；
 *   ② 能在其中建文件，且建完裸 svc 自己看得见（自洽）；
 *   ③ 能建符号链接。
 *
 * ③ 是必须的：不同挂载点能力不同。实测本机：
 *     /tmp、/root、/data/local/tmp  → 裸 svc mkdir 直接被拒（外层只允许
 *                                    经它自己的翻译层写）
 *     /sdcard/Download              → 能建目录/文件/改名，但 symlinkat
 *                                    返回 EACCES（FUSE 上不允许）
 *     <app 私有>/files/linux/tmp    → 目录/文件/符号链接/改名都可用
 * 不探测就选错 base，会把"文件系统能力不足"误报成"代码有缺陷"。
 */
static int try_base(const char *parent, char *out, size_t out_size)
{
    char sub[1200], fil[1300], lnk[1300];
    long fd;
    int ok = 0;

    /*
     * base 取**每次运行唯一**的名字（父目录 + pid），并作为本次测试的
     * 工作目录**保留**下来。
     *
     * 【为什么必须唯一】
     * 最初把工作文件直接放在候选目录下（固定名 "sub" 等），pid 复用或
     * 上一轮异常退出就会撞名：mkdir 报 EEXIST → 整个测试 SKIP。
     * 那种假 SKIP 看起来像"环境不支持"，实际会**掩盖真实回归**。
     * 改成 pid 唯一目录后，每轮都是干净状态。
     */
    snprintf(sub, sizeof sub, "%s/bxrl-%d", parent, (int)getpid());
    snprintf(fil, sizeof fil, "%s/probe", sub);
    snprintf(lnk, sizeof lnk, "%s/link", sub);

    /* 清掉同 pid 的残留（异常退出时可能留下） */
    R_unlinkat(AT_FDCWD, lnk, 0);
    R_unlinkat(AT_FDCWD, fil, 0);
    R_unlinkat(AT_FDCWD, sub, AT_REMOVEDIR);

    if (R_mkdirat(AT_FDCWD, sub, 0700) != 0)
        return 0;

    fd = R_openat(AT_FDCWD, fil, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        R_close(fd);
        /* 自洽性：刚建的文件必须能被裸 svc 看见 */
        if (r_exists(fil) &&
            raw6(SYS_symlinkat, (long)"T", AT_FDCWD, (long)lnk, 0, 0) == 0)
            ok = 1;
    }

    R_unlinkat(AT_FDCWD, lnk, 0);
    R_unlinkat(AT_FDCWD, fil, 0);

    if (!ok) {
        R_unlinkat(AT_FDCWD, sub, AT_REMOVEDIR);
        return 0;
    }

    /*
     * 保留该目录作为工作目录。
     *
     * 用 memcpy 而不是 snprintf：sub 最长 1200 字节，而 out_size 可能只有
     * 1024，gcc 的 -Wformat-truncation 会（正确地）报警。这里长度已在
     * 上面由 snprintf(sub,...) 保证，且调用方给的 out 是 1024 字节的
     * 主程序缓冲 —— 显式判长截断，语义清楚且不产生告警。
     */
    {
        size_t need = strlen(sub);
        if (need + 1 > out_size)
            return 0;
        memcpy(out, sub, need + 1);
    }
    return 1;
}

/* 该文件系统支不支持硬链接？（用裸 svc 判，效果为准） */
static int hardlink_supported(const char *dir)
{
    char a[1400], b[1400];
    int ok;

    snprintf(a, sizeof a, "%s/.hltest-a-%d", dir, (int)getpid());
    snprintf(b, sizeof b, "%s/.hltest-b-%d", dir, (int)getpid());

    R_unlinkat(AT_FDCWD, a, 0);
    R_unlinkat(AT_FDCWD, b, 0);
    if (r_write_file(a, "h") != 0) return 0;

    ok = (raw6(SYS_linkat, AT_FDCWD, (long)a, AT_FDCWD, (long)b, 0) == 0);

    R_unlinkat(AT_FDCWD, a, 0);
    R_unlinkat(AT_FDCWD, b, 0);
    return ok;
}

/* ------------------------------------------------------------------ */
int main(void)
{
    char base[1024];
    char p_src[1400], p_dst[1400], p_sub[1400], p_lnk[1400];
    int found = 0;

    printf("=== renameat/renameat2/linkat/symlinkat 参数位置契约 ===\n");

    /* ============================================================== */
    /* 〇、base 目录探测                                              */
    /* ============================================================== */
    {
        const char *cands[8];
        int n = 0, i;
        char cwdbuf[1024];

        if (getenv("BXARG_BASE") && getenv("BXARG_BASE")[0])
            cands[n++] = getenv("BXARG_BASE");
        if (getenv("TMPDIR") && getenv("TMPDIR")[0])
            cands[n++] = getenv("TMPDIR");
        cands[n++] = "/tmp";
        /* 容器自身的 tmp（Android 上能力最全：符号链接也可用） */
        cands[n++] = "/data/data/com.dsh.client/files/linux/tmp";
        cands[n++] = "/data/local/tmp";
        cands[n++] = "/sdcard/Download";
        if (getcwd(cwdbuf, sizeof cwdbuf) != NULL)
            cands[n++] = cwdbuf;

        for (i = 0; i < n && !found; i++)
            if (cands[i] != NULL && try_base(cands[i], base, sizeof base))
                found = 1;
    }

    if (!found) {
        printf("  [skip] 找不到任何『裸系统调用可写』的目录，无法验证\n");
        printf("\nRESULT: SKIP\n");
        return 0;
    }
    printf("  base 目录 = %s（裸 svc 可写且自洽）\n", base);
    snprintf(g_hostroot, sizeof g_hostroot, "%s", base);

    snprintf(p_src, sizeof p_src, "%s/src", base);
    snprintf(p_dst, sizeof p_dst, "%s/dst", base);
    snprintf(p_sub, sizeof p_sub, "%s/sub", base);
    snprintf(p_lnk, sizeof p_lnk, "%s/lnk", base);

    /*
     * 先清掉可能的残留（上一轮异常退出、或 pid 复用撞名）。
     * 不清就会 EEXIST → 整个测试 SKIP，看起来像"环境不支持"，
     * 实际只是脏状态。这类假 SKIP 会掩盖真实回归。
     */
    R_unlinkat(AT_FDCWD, p_sub, AT_REMOVEDIR);
    if (R_mkdirat(AT_FDCWD, p_sub, 0700) != 0) {
        printf("  [skip] 无法建立子目录 %s: %s\n", p_sub, strerror(errno));
        printf("\nRESULT: SKIP\n");
        return 0;
    }

    /* ============================================================== */
    /* 一、号码核对                                                    */
    /* ============================================================== */
    printf("\n-- 一、系统调用编号 --\n");
    {
        char d[256];

        /*
         * guard 的表按**号码**索引。号码错了，翻译就会作用到完全不相干
         * 的调用上（见头注释里 260=wait4 的事故）。
         */
        snprintf(d, sizeof d, "应为 38，实际 %d", (int)SYS_renameat);
        check("renameat 编号 == 38", SYS_renameat == 38, d);
        snprintf(d, sizeof d, "应为 276，实际 %d", (int)SYS_renameat2);
        check("renameat2 编号 == 276", SYS_renameat2 == 276, d);
        snprintf(d, sizeof d, "应为 37，实际 %d", (int)SYS_linkat);
        check("linkat 编号 == 37（不是 260）", SYS_linkat == 37, d);
        snprintf(d, sizeof d, "应为 36，实际 %d", (int)SYS_symlinkat);
        check("symlinkat 编号 == 36", SYS_symlinkat == 36, d);

        /* 260 事故的核心不变式 */
        snprintf(d, sizeof d, "SYS_wait4=%d 与 SYS_linkat=%d 撞号了",
                 (int)SYS_wait4, (int)SYS_linkat);
        check("wait4 与 linkat 不同号（260 事故防回归）",
              SYS_wait4 != SYS_linkat, d);
        snprintf(d, sizeof d, "应为 260，实际 %d", (int)SYS_wait4);
        check("wait4 编号 == 260（即 guard 原表里被误标为 linkat 的那个）",
              SYS_wait4 == 260, d);
    }

    /* ============================================================== */
    /* 二、参数位置（纯内核 errno 判定）                               */
    /* ============================================================== */
    printf("\n-- 二、参数位置（内核 errno 判定）--\n");

    /*
     * a2 是 dirfd，不是路径。
     *   a2 是 dirfd   → EBADF(9)   （fd 查表失败）
     *   a2 是路径指针 → EFAULT(14) （copy_from_user 失败）
     * 两个 errno 不会混淆，所以这是干净的判别实验。
     */
    {
        long r; int e;
        r_write_file(p_src, "A");

        errno = 0;
        r = raw6(SYS_renameat2, AT_FDCWD, (long)p_src, 999999, (long)"rel-dst", 0);
        e = errno;
        check("renameat2: a2 是 dirfd（伪 dirfd → EBADF，不是 EFAULT）",
              r == -1 && e == EBADF,
              "预期 EBADF；若得到 EFAULT 说明 a2 被当路径");

        errno = 0;
        r = raw6(SYS_renameat, AT_FDCWD, (long)p_src, 999999, (long)"rel-dst", 0);
        e = errno;
        check("renameat: a2 是 dirfd（伪 dirfd → EBADF）",
              r == -1 && e == EBADF, "预期 EBADF");
    }

    /*
     * a3 是第二个路径，且**相对于 a2 解析**。
     * a2 给真实目录 fd、a3 给相对名，成功后文件必须出现在那个目录里。
     */
    {
        long dfd = R_openat(AT_FDCWD, p_sub, O_RDONLY | O_DIRECTORY, 0);
        if (dfd >= 0) {
            char q[1600], c[8];
            long r;
            r_write_file(p_src, "B");
            errno = 0;
            r = raw6(SYS_renameat2, AT_FDCWD, (long)p_src, dfd, (long)"in_sub", 0);
            snprintf(q, sizeof q, "%s/in_sub", p_sub);
            check("renameat2: a3 是路径且相对 a2 解析",
                  r == 0 && r_exists(q),
                  "调用失败，或结果没落在 a2 指定的目录");
            check("renameat2: a3 解析结果内容正确",
                  r_read_file(q, c, sizeof c) && strcmp(c, "B") == 0,
                  "文件内容不符");
            R_close(dfd);
        } else {
            check("renameat2: a3 是路径且相对 a2 解析", 0, "打不开测试目录");
        }
    }

    /* renameat(38) 同法复核 a3 */
    {
        long dfd = R_openat(AT_FDCWD, p_sub, O_RDONLY | O_DIRECTORY, 0);
        if (dfd >= 0) {
            char q[1600], c[8];
            r_write_file(p_src, "C");
            raw6(SYS_renameat, AT_FDCWD, (long)p_src, dfd, (long)"in_sub2", 0);
            snprintf(q, sizeof q, "%s/in_sub2", p_sub);
            check("renameat: a3 是路径且相对 a2 解析",
                  r_exists(q) && r_read_file(q, c, sizeof c) && strcmp(c, "C") == 0,
                  "文件没落在 a2 所指目录，或内容不符");
            R_close(dfd);
        }
    }

    /* a1 是第一个路径，且相对于 a0 解析 */
    {
        long dfd = R_openat(AT_FDCWD, p_sub, O_RDONLY | O_DIRECTORY, 0);
        if (dfd >= 0) {
            char q[1600];
            snprintf(q, sizeof q, "%s/d_src", p_sub);
            r_write_file(q, "D");
            raw6(SYS_renameat2, dfd, (long)"d_src", AT_FDCWD, (long)p_dst, 0);
            check("renameat2: a1 是路径且相对 a0 解析",
                  r_exists(p_dst) && !r_exists(q), "a1 没按 a0 解析");
            R_unlinkat(AT_FDCWD, p_dst, 0);
            R_close(dfd);
        }
    }

    /*
     * a4 是 flags。
     * RENAME_NOREPLACE(1) 且目标已存在 → EEXIST(17)；换成 0 则成功。
     */
    {
        long r; int e;
        r_write_file(p_src, "E1");
        r_write_file(p_dst, "E2");
        errno = 0;
        r = raw6(SYS_renameat2, AT_FDCWD, (long)p_src, AT_FDCWD, (long)p_dst, 1);
        e = errno;
        check("renameat2: a4 是 flags（NOREPLACE + 已存在 → EEXIST）",
              r == -1 && e == EEXIST, "预期 EEXIST");
        R_unlinkat(AT_FDCWD, p_src, 0);
        R_unlinkat(AT_FDCWD, p_dst, 0);
    }

    /* linkat 的 a2/a3 与 renameat 同构 */
    {
        int has_hl = hardlink_supported(base);
        long dfd = R_openat(AT_FDCWD, p_sub, O_RDONLY | O_DIRECTORY, 0);

        if (dfd >= 0) {
            /*
             * a2 是 dirfd 而不是路径。
             *
             * 判据：给 a2 一个**伪 dirfd**。
             *   a2 是 dirfd   → EBADF(9)，或（文件系统禁止硬链接时）
             *                   内核在解析 a2 前先对 a1 报 EACCES/EPERM
             *   a2 是路径指针 → EFAULT(14)，必然发生
             * 所以**唯一**要排除的是 EFAULT：只要不是 EFAULT，就说明
             * a2 没有被当指针解引用。这条断言因此在硬链接受限的环境
             * （Android SELinux 下处处受限，正是 l2s 层存在的原因）
             * 依然成立，不会被环境能力误报成代码缺陷。
             */
            errno = 0;
            raw6(SYS_linkat, AT_FDCWD, (long)p_src, 999999, (long)"rel", 0);
            check("linkat: a2 是 dirfd（伪 dirfd 不给 EFAULT）",
                  errno != EFAULT,
                  "得到 EFAULT —— a2 被当成路径指针解引用了");
            R_close(dfd);
        }

        if (has_hl) {
            struct stat sa, sb;
            char q[1600];

            r_write_file(p_src, "G");
            R_unlinkat(AT_FDCWD, p_dst, 0);
            errno = 0;
            {
                long r = raw6(SYS_linkat, AT_FDCWD, (long)p_src, AT_FDCWD, (long)p_dst, 0);
                int e = errno;
                check("linkat: a1/a3 是路径（绝对 + AT_FDCWD 成功建链）",
                      r == 0 && r_exists(p_dst), e ? strerror(e) : "目标未出现");
            }
            if (R_fstatat(AT_FDCWD, p_src, &sa) == 0 &&
                R_fstatat(AT_FDCWD, p_dst, &sb) == 0)
                check("linkat: 效果证据 —— 同 inode、nlink==2",
                      sa.st_ino == sb.st_ino && sb.st_nlink == 2,
                      "inode 不同或 nlink 不是 2，说明不是真硬链接");

            {
                long d2 = R_openat(AT_FDCWD, p_sub, O_RDONLY | O_DIRECTORY, 0);
                if (d2 >= 0) {
                    snprintf(q, sizeof q, "%s/l_in_sub", p_sub);
                    R_unlinkat(AT_FDCWD, q, 0);
                    raw6(SYS_linkat, AT_FDCWD, (long)p_src, d2, (long)"l_in_sub", 0);
                    check("linkat: a3 是路径且相对 a2 解析", r_exists(q),
                          "链接没落在 a2 所指目录");
                    R_unlinkat(AT_FDCWD, q, 0);
                    R_close(d2);
                }
            }
            R_unlinkat(AT_FDCWD, p_dst, 0);
        } else {
            printf("  [skip] 本 base 目录不支持硬链接，linkat 效果类断言跳过\n");
        }
    }

    /*
     * symlinkat：a1 是 dirfd（历史事故点），linkpath 在 a2。
     *
     * 判别必须用**相对 linkpath** —— 绝对 linkpath 时内核对 dirfd 宽容
     * （直接忽略它），那样测不出 a1 的语义。历史上正是这个取证错误
     * 导致结论一度自相矛盾。
     */
    {
        long r; int e;

        errno = 0;
        r = raw6(SYS_symlinkat, (long)"TGT", 999999, (long)"rel-l", 0, 0);
        e = errno;
        check("symlinkat: a1 是 dirfd（伪 dirfd → EBADF，用相对 linkpath）",
              r == -1 && e == EBADF, "预期 EBADF");

        {
            long ffd = R_openat(AT_FDCWD, p_src, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (ffd >= 0) {
                errno = 0;
                r = raw6(SYS_symlinkat, (long)"TGT", ffd, (long)"rel-l2", 0, 0);
                e = errno;
                check("symlinkat: a1 不是目录时 → ENOTDIR（证明 a1 被当目录 fd）",
                      r == -1 && e == ENOTDIR, "预期 ENOTDIR");
                R_close(ffd);
            }
        }

        /*
         * a2 是路径。这里**不**断言"一定建链成功" —— 有些文件系统
         * （实测 /sdcard 的 FUSE）根本不允许建符号链接，那是环境能力
         * 问题，不是参数位置问题。
         *
         * 真正要证明"a2 被当路径解析"的干净实验：给一个**父目录不存在**
         * 的绝对 linkpath，内核必须报 ENOENT。若 a2 是 dirfd，这个 errno
         * 在语义上不可能出现。
         */
        {
            char nodir[1400];
            snprintf(nodir, sizeof nodir, "%s/no-such-dir/lnk", base);
            errno = 0;
            r = raw6(SYS_symlinkat, (long)"TGT", AT_FDCWD, (long)nodir, 0, 0);
            check("symlinkat: a2 是路径（父目录不存在 → ENOENT，而非 EBADF）",
                  r == -1 && errno == ENOENT,
                  "预期 ENOENT；若是 EBADF 说明 a2 被当成了 dirfd");
        }

        R_unlinkat(AT_FDCWD, p_lnk, 0);
        errno = 0;
        r = raw6(SYS_symlinkat, (long)"TGT", AT_FDCWD, (long)p_lnk, 0, 0);
        if (r == 0) {
            /* 注意必须用 r_lexists：链接指向的 "TGT" 并不存在，
             * 跟随符号链接的 r_exists 会误判为"未建立" */
            check("symlinkat: a2 是路径（AT_FDCWD + 绝对 linkpath 成功）",
                  r_lexists(p_lnk), "链接未建立");
        } else {
            printf("  [skip] 本 base 不允许建符号链接（%s）\n", strerror(errno));
        }
        R_unlinkat(AT_FDCWD, p_lnk, 0);
    }

    /* ============================================================== */
    /* 三、翻译管线（自带翻译桩，同进程驱动 guard）                    */
    /* ============================================================== */
    printf("\n-- 三、翻译管线（自带翻译桩，同进程驱动 guard）--\n");
    {
        char c[16];
        char probe[1200];
        char want[1200];

        {
            int tr = bxroot_translate_path("/g/probe", probe, sizeof probe);
            snprintf(want, sizeof want, "%s/probe", base);
            check("翻译桩自检：/g/... 映射到宿主 base 目录",
                  tr > 0 && strcmp(probe, want) == 0,
                  "桩没有按预期把 /g/probe 映射到 <base>/probe");
        }

        /*
         * ★ 核心用例：renameat2 两个路径都必须是 guest 路径 ★
         * 若 a3 漏翻，内核收到 new="/g/dst"，调用失败、文件留在原处。
         */
        R_unlinkat(AT_FDCWD, p_src, 0);
        R_unlinkat(AT_FDCWD, p_dst, 0);
        r_write_file(p_src, "R2");
        seen_reset();
        errno = 0;
        {
            long r = syscall(SYS_renameat2, AT_FDCWD, GSRC, AT_FDCWD, GDST, 0u);
            int e = errno;
            check("renameat2: a1 与 a3 都被翻译（文件真的搬到翻译后的目标）",
                  r == 0 && r_exists(p_dst) && !r_exists(p_src),
                  e ? strerror(e)
                    : "调用失败或文件没落在翻译后的目标 —— a3 很可能漏翻");
            check("renameat2: 目标内容正确",
                  r_read_file(p_dst, c, sizeof c) && strcmp(c, "R2") == 0,
                  "内容不符");
        }

        /*
         * 指针身份断言：guard 送进翻译桩的指针必须**恰好**是 a1 与 a3
         * 的地址，且顺序为先 a1 后 a3。这是"哪个寄存器被当路径解引用"
         * 的直接证据，能立刻指出"翻错了哪个"。
         */
        {
            char d[220];
            snprintf(d, sizeof d,
                     "桩收到 %d 个指针；期望恰好 2 个，依次为 a1(oldpath)、a3(newpath)",
                     g_seen_n);
            check("renameat2: 恰好翻译 2 个参数", g_seen_n == 2, d);
            check("renameat2: 第 1 个被翻译的是 a1（oldpath）",
                  g_seen_n >= 1 && g_seen[0] == GSRC,
                  "第一个被翻译的不是 a1");
            check("renameat2: 第 2 个被翻译的是 a3（newpath）",
                  g_seen_n >= 2 && g_seen[1] == GDST,
                  "第二个被翻译的不是 a3 —— 这正是本次要修的缺口");
        }

        /* renameat(38) 同法 */
        R_unlinkat(AT_FDCWD, p_src, 0);
        R_unlinkat(AT_FDCWD, p_dst, 0);
        r_write_file(p_src, "R1");
        seen_reset();
        errno = 0;
        {
            long r = syscall(SYS_renameat, AT_FDCWD, GSRC, AT_FDCWD, GDST);
            int e = errno;
            check("renameat: a1 与 a3 都被翻译",
                  r == 0 && r_exists(p_dst) && !r_exists(p_src),
                  e ? strerror(e) : "a3 很可能漏翻");
        }
        check("renameat: 翻译的正是 a1 与 a3",
              g_seen_n == 2 && g_seen[0] == GSRC && g_seen[1] == GDST,
              "被翻译的参数位置不对");

        /* linkat：两个路径都要翻译 */
        if (hardlink_supported(base)) {
            R_unlinkat(AT_FDCWD, p_src, 0);
            R_unlinkat(AT_FDCWD, p_dst, 0);
            r_write_file(p_src, "L");
            seen_reset();
            errno = 0;
            {
                long r = syscall(SYS_linkat, AT_FDCWD, GSRC, AT_FDCWD, GDST, 0);
                int e = errno;
                check("linkat: a1 与 a3 都被翻译（链接建在翻译后的目标）",
                      r == 0 && r_exists(p_dst),
                      e ? strerror(e) : "a3 很可能漏翻");
            }
            check("linkat: 翻译的正是 a1 与 a3",
                  g_seen_n == 2 && g_seen[0] == GSRC && g_seen[1] == GDST,
                  "被翻译的参数位置不对");
            R_unlinkat(AT_FDCWD, p_dst, 0);
        } else {
            printf("  [skip] 本 base 目录不支持硬链接，linkat 翻译用例跳过\n");
        }

        /*
         * symlinkat：只翻 a2（linkpath），**不翻** a0（target）。
         * target 是**链接内容**不是待解析路径；若被翻译，客户 readlink
         * 就会看到宿主路径、泄漏翻译层内部布局。必须与 preload.c 的
         * symlinkat 钩子保持同一语义。
         */
        R_unlinkat(AT_FDCWD, p_lnk, 0);
        seen_reset();
        errno = 0;
        {
            long r = syscall(SYS_symlinkat, "TGT", AT_FDCWD, GLNK);
            int e = errno;
            char buf[128];
            long n = -1;

            if (r == 0 && r_lexists(p_lnk)) {
                check("symlinkat: a2（linkpath）被翻译，链接建在翻译后的位置",
                      1, "");
                n = raw6(SYS_readlinkat, AT_FDCWD, (long)p_lnk, (long)buf,
                         (long)(sizeof buf - 1), 0);
                if (n > 0) buf[n] = '\0';
                check("symlinkat: a0（target）**不被**翻译（保持 guest 视角）",
                      n > 0 && strcmp(buf, "TGT") == 0,
                      "链接内容被改写成了宿主路径");
            } else {
                /*
                 * base 所在文件系统不允许建符号链接（实测 /sdcard 的
                 * FUSE 给 EACCES）。此时**不跳过全部断言** ——
                 * 关键的"指针位置"仍可验：桩已被调用，看它收到的是不是
                 * 恰好 GLNK（a2）。这才是不依赖文件系统能力的那部分证据。
                 */
                printf("  [skip] 本 base 不允许建符号链接（%s），"
                       "改用指针位置断言\n", e ? strerror(e) : "未建立");
            }
        }
        check("symlinkat: 只翻译 a2（linkpath），不碰 a0/a1",
              g_seen_n == 1 && g_seen[0] == GLNK,
              "被翻译的参数位置不对（a0 是 target、a1 是 dirfd，都不该翻）");

        /*
         * ★ dirfd 绝不被当路径 ★
         * AT_FDCWD == -100。桩对 <4096 的"指针"只置标志、不解引用。
         */
        check("dirfd 未被当路径解引用（AT_FDCWD=-100 安全）",
              g_bad_ptr == 0,
              "翻译桩收到了不是指针的值（dirfd 被当成了路径）");
        {
            int bad = 0, i;
            for (i = 0; i < g_seen_n; i++)
                if (g_seen[i] == (const char *)(intptr_t)AT_FDCWD) bad = 1;
            check("被翻译的参数中没有 AT_FDCWD", !bad,
                  "AT_FDCWD 出现在路径参数里 —— dirfd 被误当路径");
        }
    }

    /* ============================================================== */
    /* 四、NULL 安全                                                   */
    /* ============================================================== */
    printf("\n-- 四、NULL 安全 --\n");
    {
        struct { long nr; int which; const char *nm; } tab[] = {
            { SYS_renameat,  1, "renameat  a1=NULL" },
            { SYS_renameat,  3, "renameat  a3=NULL" },
            { SYS_renameat2, 1, "renameat2 a1=NULL" },
            { SYS_renameat2, 3, "renameat2 a3=NULL" },
            { SYS_linkat,    1, "linkat    a1=NULL" },
            { SYS_linkat,    3, "linkat    a3=NULL" },
            { SYS_symlinkat, 2, "symlinkat a2=NULL" },
        };
        unsigned i;

        for (i = 0; i < sizeof tab / sizeof tab[0]; i++) {
            long r; int e;
            seen_reset();
            errno = 0;
            if (tab[i].nr == SYS_symlinkat)
                r = syscall(SYS_symlinkat, "TGT", AT_FDCWD, (const char *)NULL);
            else if (tab[i].which == 1)
                r = syscall(tab[i].nr, AT_FDCWD, (const char *)NULL, AT_FDCWD, GX, 0);
            else
                r = syscall(tab[i].nr, AT_FDCWD, GX, AT_FDCWD, (const char *)NULL, 0);
            e = errno;

            {
                char d[160];
                snprintf(d, sizeof d, "预期 -1/EFAULT；实际 r=%ld errno=%d(%s)",
                         r, e, e ? strerror(e) : "-");
                check(tab[i].nm, r == -1 && e == EFAULT, d);
            }
            /*
             * NULL 绝不能被送进翻译桩 —— 那会解引用 NULL。
             *
             * 但**不能**要求"一个参数都没被翻译"：guard 按 i 从小到大
             * 处理，a1 有效时它会**先**被翻译，之后才轮到 a3=NULL 触发
             * EFAULT。那是正确行为（实测内核正是先解 oldpath、遇 NULL
             * 立即 EFAULT），所以只断言"桩没收到 NULL / 没收到非法指针"。
             */
            check("  └ NULL 未被送进翻译层（不会解引用 NULL）",
                  g_bad_ptr == 0 && !seen_has_null(),
                  "NULL 被当成路径送进了翻译桩");
        }
    }

    /* ============================================================== */
    /* 五、260（wait4）绝不能被当路径                                  */
    /* ============================================================== */
    printf("\n-- 五、wait4(260) 的 wstatus 不得被当路径 --\n");
    {
        pid_t pid = fork();

        if (pid == 0) {
            for (;;) pause();          /* 等父进程发信号 */
            _exit(0);
        } else if (pid < 0) {
            check("wait4: 能 fork 出子进程", 0, "fork 失败");
        } else {
            int st = 0;
            long r;

            usleep(80000);
            kill(pid, 47);             /* 47 = 0x2F，首字节正是 '/' */

            seen_reset();
            errno = 0;
            r = syscall(SYS_wait4, (long)pid, &st, 0L, (void *)0);

            /*
             * 若 guard 仍把 wait4 的 a1 当路径，&st 首字节恰为 '/'，
             * 就会被送去翻译：内核把状态写进 guard 的缓冲，st 保持 0。
             * 于是下面两条断言都会失败 —— 双重信号。
             */
            check("wait4: 返回被回收的子进程 pid", r == (long)pid,
                  "wait4 没有返回子进程 pid");
            check("wait4: wstatus 正确送达调用方（信号 47）",
                  WIFSIGNALED(st) && WTERMSIG(st) == 47,
                  "wstatus 没被写入 —— 疑似被 guard 当路径翻译后写进了别处");
            check("wait4: wstatus 地址未被送进翻译层",
                  g_bad_ptr == 0 && g_seen_n == 0,
                  "wait4 的参数被当成了路径（260 事故复现）");
        }
    }

    /*
     * ★ 260 事故的**判别性**用例 ★
     *
     * 上面那个用例其实测不出 260 的 bug —— 因为 guard 是在**发起系统
     * 调用之前**读 a1 的首字节，而那里 status=0，不是 '/'，于是无论
     * 表里有没有 260 都不会被翻译。我第一版就是这么写的，结果"未修
     * 260"的版本照样全绿（已实测），属于**假安全**。
     *
     * 真正的危险条件是：**调用前** wstatus 缓冲区首字节已经是 '/'。
     * 现实中这很常见 —— 调用方复用/未初始化的栈变量、或者先写了个
     * 以 '/' 开头的字符串（把 status 缓冲区当临时字符缓冲用）。
     *
     * 构造：先把 status 置为 0x0000002f（首字节 '/'），再用**等待
     * 必然成功**的方式发 wait4。若 guard 有 260 bug，它会把这个缓冲
     * 当路径翻译走，内核写进 guard 的临时缓冲，调用方这个 status
     * 保持 0x2f 不变 —— 用这一点判定。
     */
    printf("\n-- 五之二、260 判别用例（调用前 status 首字节已是 '/'）--\n");
    {
        pid_t pid = fork();

        if (pid == 0) {
            _exit(0);                  /* 立刻正常退出，wait 必然成功 */
        } else if (pid < 0) {
            check("260 判别: 能 fork 出子进程", 0, "fork 失败");
        } else {
            int st = 0x0000002f;       /* 首字节正是 '/'（0x2f） */
            long r;

            seen_reset();
            errno = 0;
            r = syscall(SYS_wait4, (long)pid, &st, 0L, (void *)0);

            check("260 判别: wait4 成功回收",
                  r == (long)pid, "wait4 没返回子进程 pid");
            check("260 判别: 首字节为 '/' 的 wstatus 仍被正确写入",
                  WIFEXITED(st) && WEXITSTATUS(st) == 0,
                  "wstatus 保持 0x2f 未被内核写入 —— "
                  "&st 被 guard 当路径翻译走了（260 事故）");
            check("260 判别: 该缓冲区未被送进翻译层",
                  g_seen_n == 0 && g_bad_ptr == 0,
                  "wait4 的 wstatus 被当成路径送去翻译（260 事故复现）");
        }
    }

    /* ============================================================== */
    /* 六、反向对照：证明本测试能区分「翻译」与「没翻译」              */
    /* ============================================================== */
    printf("\n-- 六、反向对照（证明测试有区分能力）--\n");
    {
        char c[16];

        R_unlinkat(AT_FDCWD, p_src, 0);
        R_unlinkat(AT_FDCWD, p_dst, 0);
        r_write_file(p_src, "N");

        g_translate_on = 0;            /* 关掉翻译 */
        errno = 0;
        {
            long r = syscall(SYS_renameat2, AT_FDCWD, GSRC, AT_FDCWD, GDST, 0u);
            check("对照：关掉翻译后，同一调用必须失败（证明用例有区分能力）",
                  r == -1,
                  "关掉翻译竟然还成功了 —— 本用例无法区分翻译与否");
            check("对照：关掉翻译后文件留在原处（未被搬走）",
                  r_exists(p_src) && !r_exists(p_dst),
                  "文件位置变了，说明判定依据不可靠");
        }
        g_translate_on = 1;

        /* 恢复后应立刻又能工作 —— 排除"失败是别的原因" */
        R_unlinkat(AT_FDCWD, p_src, 0);
        R_unlinkat(AT_FDCWD, p_dst, 0);
        r_write_file(p_src, "Y");
        errno = 0;
        {
            long r = syscall(SYS_renameat2, AT_FDCWD, GSRC, AT_FDCWD, GDST, 0u);
            check("对照：重新打开翻译后立即成功",
                  r == 0 && r_read_file(p_dst, c, sizeof c) && strcmp(c, "Y") == 0,
                  "恢复翻译后仍失败");
        }
    }

    /* 清理：先清 sub 里的内容，再逐级删目录 */
    {
        static const char *leaves[] = { "in_sub", "in_sub2", "d_src", "l_in_sub" };
        unsigned k;
        char t[1600];
        for (k = 0; k < sizeof leaves / sizeof leaves[0]; k++) {
            snprintf(t, sizeof t, "%s/%s", p_sub, leaves[k]);
            R_unlinkat(AT_FDCWD, t, 0);
        }
    }
    R_unlinkat(AT_FDCWD, p_src, 0);
    R_unlinkat(AT_FDCWD, p_dst, 0);
    R_unlinkat(AT_FDCWD, p_lnk, 0);
    R_unlinkat(AT_FDCWD, p_sub, AT_REMOVEDIR);
    /* 顺带清掉硬链接能力探测留下的临时名 */
    {
        char t[1600];
        snprintf(t, sizeof t, "%s/.hltest-a-%d", base, (int)getpid());
        R_unlinkat(AT_FDCWD, t, 0);
        snprintf(t, sizeof t, "%s/.hltest-b-%d", base, (int)getpid());
        R_unlinkat(AT_FDCWD, t, 0);
    }
    R_unlinkat(AT_FDCWD, base, AT_REMOVEDIR);

    printf("\n----------------------------------------\n");
    printf("cases:  %d  (%d failed)\n", cases, failed);
    printf("RESULT: %s\n", failed ? "FAIL" : "PASS");
    return failed ? 1 : 0;
}
