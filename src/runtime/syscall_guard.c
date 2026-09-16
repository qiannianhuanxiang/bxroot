/*
 * syscall_guard.c —— syscall() 符号接管层
 *
 * ====================================================================
 * 为什么必须有这一层
 * ====================================================================
 *
 * 两个独立的问题都由这一层解决：
 *
 * 【问题一】proroot-ldso 用 seccomp 以 KILL_PROCESS 方式禁止了一批系统
 * 调用（实测逐个列举，425/426/427 在内而 424 不在）。io_uring 家族一旦
 * 发出就杀进程且**不投递信号**，因此 SIGSYS 处理器救不了，只能从源头
 * 不让它发出去。返回 ENOSYS 是 libuv 期望的回退信号（它会改用 epoll）。
 *
 * 【问题二】node 静态链接的 libuv **不经 libc 的 stat/statx 符号**，
 * 而是用 `syscall(291, AT_FDCWD, path, ...)` 直接发起。实测证据：
 * 开 BXROOT_SCG=1 时 node 的 statSync 产生"转发 291"，却**不产生任何
 * translate 日志** —— 它完全绕过了 stat 钩子，路径未被翻译，于是 /usr
 * 之类全部 ENOENT（而同样功能的 C 程序走符号，一切正常）。
 *
 * ====================================================================
 * 实现要点
 * ====================================================================
 *
 * 1. 转发必须用**裸 svc 内联汇编**：调用 libc 的 syscall() 会绕回本函数
 *    造成无限递归，而没有比 svc 更底层的手段。
 *
 * 2. 路径参数是**客户传来的指针**，必须做安全判定。踩过的坑：
 *    内核对这些参数是宽容的 ——
 *        statx(AT_FDCWD, NULL, AT_EMPTY_PATH, ...) → EFAULT（合法入参！）
 *        openat(fd, NULL, ...)                     → EFAULT
 *    而 `pth[0] == '/'` 直接解引用遇到 NULL 立即 SIGSEGV，症状是整个
 *    进程静默消失。判据因此收敛到 looks_like_guest_abs_path() 一处。
 *
 * 3. 参数位置用**表**而不是散落的 switch：猜错参数位置会把非指针参数
 *    当路径解引用，那比不翻译严重得多。表让"哪些调用被翻译"一目了然。
 *
 * 4. 诊断输出不用 stdio（构造函数早期不可用），由 BXROOT_SCG=1 门控。
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>

#include "syscall_guard.h"

/*
 * l2s 层的 statx 结果补丁。前向声明而不是 #include "l2s-runtime.h"：
 * 本文件是**独立编译单元**，只要一个函数原型，不该为此把整个 l2s 头
 * （进而 <sys/stat.h>、l2s.h）拖进来 —— 编译单元之间保持最小耦合。
 *
 * ★ 必须声明为 weak ★
 *
 * 本文件有两种编译方式：
 *   ① 与 src/l2s/l2s-runtime.c 一起链进 libbxroot-runtime.so —— 正常路径；
 *   ② **单独**与 test/test_syscall_argpos.c / test_rename_link_argpos.c
 *      一起编译（这两个测试自带翻译桩，专门测"参数位置表"这一件事，
 *      不链接 l2s）。
 *
 * 方式 ② 下若用普通声明，链接器会报
 *     undefined reference to `l2s_rt_patch_statx_full'
 * 直接把两个既有测试打红。weak 声明让它在"没有 l2s 参与链接"时
 * 解析为 NULL，调用点判空跳过即可 —— 那两个测试本来也不测 l2s 伪装。
 *
 * 【为什么不用"复制一份实现"绕过】
 * 判据（是不是伪造链接、链长多少、要不要抹 S_IFLNK）只有 l2s 层有。
 * 在这里复制一份等于把同一套规则写两处，两边迟早漂移 —— 那正是本项目
 * 反复踩过的坑（"测试台的配置与真实部署不同"）。
 *
 * 实现体在 src/l2s/l2s-runtime.c。
 */
__attribute__((weak))
void l2s_rt_patch_statx_full(unsigned int *stx_nlink, unsigned int *stx_mask,
                             unsigned int *stx_mode,
                             unsigned int statx_nlink_bit, const char *path);

/*
 * STATX_NLINK：避免为一个常量引入 <linux/stat.h>（见上面的耦合说明）。
 *
 * ★ 值必须是 0x4，不要写成 0x200 ★
 * 实测核对（gcc 打印 <linux/stat.h> 的常量）：
 *     STATX_TYPE  0x1    STATX_MODE  0x2    STATX_NLINK 0x4
 *     STATX_UID   0x8    STATX_GID   0x10   ...
 *     STATX_SIZE  0x200  STATX_BLOCKS 0x400
 * 写成 0x200 会拿 STATX_SIZE 当门控位。而在本环境里内核返回的
 * stx_mask 是 0x17ff —— 同时包含 0x4 与 0x200，于是判定照样通过，
 * 缺陷被**静默掩盖**，只在别的内核/掩码组合下才暴露。这类"碰巧能过"
 * 的常量错误必须靠核对常量本身排除，不能靠"跑起来是对的"下结论。
 */
#define SCG_STATX_NLINK 0x00000004u

/* __NR_statx（asm-generic / aarch64 均为 291，已按本机实测核对）。 */
#define SCG_NR_statx 291

/*
 * preload.c 提供的路径翻译桥（返回值约定与 translate_path 一致：
 * >0 已翻译 / ==0 无需翻译 / <0 失败）。与 preload.c 编进同一个 .so，
 * 直接调用即可，不需要 dlsym。
 */
int bxroot_translate_path(const char *path, char *out, size_t out_size);

/* ------------------------------------------------------------------ */
/* 裸系统调用                                                          */
/* ------------------------------------------------------------------ */

static long raw_syscall6(long nr, long a0, long a1, long a2,
                         long a3, long a4, long a5)
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

/* ------------------------------------------------------------------ */
/* 诊断输出（不用 stdio，避免早期构造阶段不可用）                       */
/* ------------------------------------------------------------------ */

static int g_trace;
static int g_trace_init;
static unsigned long g_blocked;

static void log_str(const char *s)
{
    if (s != NULL) {
        ssize_t w = write(2, s, strlen(s));
        (void)w;
    }
}

static void log_num(const char *prefix, long v, const char *suffix)
{
    char buf[128];
    char digits[24];
    int n = 0, i, dn = 0;
    unsigned long u;

    while (prefix != NULL && prefix[n] != '\0' && n < 60)
        buf[n] = prefix[n], n++;

    u = (v < 0) ? (unsigned long)(-v) : (unsigned long)v;
    do { digits[dn++] = (char)('0' + (u % 10)); u /= 10; } while (u > 0);
    if (v < 0) buf[n++] = '-';
    for (i = dn - 1; i >= 0; i--) buf[n++] = digits[i];

    if (suffix != NULL)
        for (i = 0; suffix[i] != '\0' && n < 120; i++)
            buf[n++] = suffix[i];

    {
        ssize_t w = write(2, buf, (size_t)n);
        (void)w;
    }
}

static void init_trace(void)
{
    if (g_trace_init)
        return;
    g_trace_init = 1;
    {
        extern char **environ;
        char **e;
        for (e = environ; e != NULL && *e != NULL; e++) {
            if (e[0][0] == 'B' && e[0][1] == 'X' &&
                e[0][2] == 'R' && e[0][3] == 'O' &&
                e[0][4] == 'O' && e[0][5] == 'T' &&
                e[0][6] == '_' && e[0][7] == 'S' &&
                e[0][8] == 'C' && e[0][9] == 'G' &&
                e[0][10] == '=' && e[0][11] == '1') {
                g_trace = 1;
                break;
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* 入参安全判定                                                        */
/* ------------------------------------------------------------------ */

/*
 * 客户传进来的路径指针能不能安全地当字符串读？
 *
 * 这个函数的存在本身就是一个教训：先前直接写 `pth[0] == '/'`，
 * 遇到 `statx(AT_FDCWD, NULL, AT_EMPTY_PATH, ...)` 就 SIGSEGV ——
 * 而 NULL 对内核来说是**合法入参**（翻译成 EFAULT），不是编程错误。
 *
 * 只判定两件事：非 NULL、首字节是 '/'（相对路径由 at 系调用的 dirfd
 * 决定，不需要我们翻译）。
 *
 * 注意：**无法**在用户态安全探测任意指针可读性（sigsetjmp 方案会与
 * 客户自己的信号处理冲突）。实践上客户的路径参数要么是有效字符串、
 * 要么是 NULL；野指针不是我们要兜的场景 —— 那时内核自己也会 EFAULT，
 * 而客户程序本就是坏的。
 */
static int looks_like_guest_abs_path(const char *p)
{
    if (p == NULL)
        return 0;
    return p[0] == '/';
}

/* ------------------------------------------------------------------ */
/* 危险系统调用判定                                                    */
/* ------------------------------------------------------------------ */

/*
 * 是否应当在本层拦截（不发 svc，直接返回 ENOSYS）。
 *
 * 编号取自 asm-generic（aarch64 使用同一套编号）：
 *   425 io_uring_setup / 426 io_uring_enter / 427 io_uring_register
 *
 * 这三个是已实测确认被 proroot-ldso 的 seccomp 策略以 KILL_PROCESS
 * 方式禁止的。libuv 在启动事件循环时会尝试 io_uring_setup；返回
 * ENOSYS 后它会**自动回退到 epoll**，这是它既有的代码路径。
 */
static int should_block(long nr)
{
    switch (nr) {
    case 425:
    case 426:
    case 427:
        return 1;
    default:
        return 0;
    }
}

/* ------------------------------------------------------------------ */
/* 路径型系统调用的参数位置                                             */
/* ------------------------------------------------------------------ */

/*
 * 返回该系统调用的**路径参数位掩码**：bit N 置位表示 aN 是路径指针，
 * 返回 0 表示不是路径型调用。
 *
 * 只列出**参数位置实测确定**的那些。不猜、不试探 —— 猜错会把非指针参数
 * （典型是 dirfd，一个 int）当路径解引用，那是比"不翻译"严重得多的故障
 * （整进程静默消失，现场无任何输出）。
 *
 * ====================================================================
 * 为什么是位掩码而不是"一个下标"
 * ====================================================================
 *
 * 早先这里返回 `int`（0 或 1），表达能力只有"a0 或 a1"。这带来两个后果：
 *
 * ① renameat / renameat2 / linkat 各有**两个**路径参数
 *    （oldpath 在 a1、newpath 在 a3），旧接口只能表达一个，
 *    于是 newpath 长久没被翻译 —— 跨目录改名、建硬链接时目标路径
 *    落到宿主真实命名空间，客户看到"文件没动"或 ENOENT。
 *
 * ② symlinkat 的 linkpath 在 **a2**，旧接口完全表达不了。当时为了
 *    不出错，选择**整条不列入**（见下面 case 36 的长注释）——
 *    也就是"创建符号链接"这个入口在裸 syscall 形态下一直没有翻译，
 *    而 l2s 层（硬链接模拟）大量依赖它。
 *
 * 位掩码同时解决这两件事，并且把"表能表达什么"和"有哪些调用"解耦：
 * 再出现 a2/a3 上的路径参数时，只需改一行，不必重构调用方。
 */
static unsigned path_arg_mask(long nr)
{
    switch (nr) {
    /* ---- 传统接口（逐条核对过参数位置）---- */
    case 291:  return 1u << 1;  /* statx(dfd, path, flags, mask, buf)  */
    case 79:   return 1u << 1;  /* newfstatat(dfd, path, buf, flags)   */
    case 78:   return 1u << 1;  /* readlinkat(dfd, path, buf, sz)      */
    case 48:   return 1u << 1;  /* faccessat(dfd, path, mode)          */
    case 56:   return 1u << 1;  /* openat(dfd, path, flags, mode)      */
    case 35:   return 1u << 1;  /* unlinkat(dfd, path, flags)          */
    case 34:   return 1u << 1;  /* mkdirat(dfd, path, mode)            */
    case 221:  return 1u << 0;  /* execve(path, argv, envp) —— a0 是路径 */

    /*
     * ---- 现代内核新增的路径型接口 ----
     *
     * 审计发现的缺口：这张表最初只列了传统调用，而**走裸 `syscall()`
     * 的静态链接程序**（本层存在的全部理由）会用新接口。不列进来 =
     * 那些调用绕过路径翻译，客户看到宿主路径不存在。
     *
     * 【编号逐个实测核对】本机（Android 6.1 内核 + aarch64）。
     *
     * ★ 本轮把整张表拿本机头文件常量逐条重新核对了一遍，因为发现了
     *   一处**真错误**（见下）。核对方法与结果：
     *     gcc 编译期打印 SYS_xxx，与表中号码比对；再对可疑项做行为判决。
     *     291 statx == SYS_statx ✅      79 newfstatat == SYS_newfstatat ✅
     *      78 readlinkat ✅              48 faccessat ✅   56 openat ✅
     *      35 unlinkat ✅                34 mkdirat ✅    221 execve ✅
     *     439 faccessat2 ✅             281 execveat ✅   276 renameat2 ✅
     *      38 renameat ✅                36 symlinkat ✅
     *
     * ★★ case 260 曾是**错的**，已删除 ★★
     *
     * 原表把它当 linkat 并翻译其 a1。实测（行为判决，不是查表）：
     *
     *     fork 一个 _exit(42) 的子进程，
     *     syscall(260, pid, &wstatus, 0, NULL)
     *       → 返回 pid，wstatus 被内核写入，WIFEXITED=1、WEXITSTATUS=42
     *
     * 只有 wait4 会写 wstatus，所以 **260 是 wait4**（asm-generic 编号），
     * 而本机 `SYS_linkat == 37`。原注释里那句"260 linkat → EPERM（存在）"
     * 是把"随便发一个号得到 EPERM"当成了存在性证据 —— 那个推论是无效的。
     *
     * 后果不是"少翻译一条"，而是**主动制造故障**，机制值得记录：
     *   wait4 的 a1 是 `int *wstatus`。guard 的 looks_like_guest_abs_path()
     *   只看首字节是不是 '/'。而被信号 47 终止的子进程 wstatus 恰好是
     *   47 = 0x2F = '/' —— 实测复现：
     *       wstatus=0x0000002f 首字节=0x2f('/') → 判定为路径 → 送去翻译
     *   于是内核把退出状态**写进了 guard 的临时缓冲**，调用方那个
     *   wstatus 永远保持原值。表现是"wait 拿到的退出状态莫名其妙"，
     *   而这个故障只在信号号恰好让首字节变成 '/' 时出现 —— 极难排查。
     *
     * 这正是"猜参数位置比不翻译更危险"的实例：非路径参数被当路径，
     * 不只是崩溃一条路，还可能是**静默的数据错写**。
     *
     *     437 openat2    → **ENOSYS** ← 本内核不支持，故**不列入**
     *    1024 (旧 open)  → **ENOSYS** ← aarch64 无此编号（那是 i386 的）。
     *                              原表里的这一项已按实测**删除**。
     *                              注：它不构成内存缺陷 —— 内核在派发前用
     *                              `nr > __NR_syscalls` 挡掉，永不进入本函数；
     *                              但它会让人误以为 open 已被覆盖。
     *
     * 【双路径参数：本轮已覆盖】
     * renameat2 / renameat / linkat 各有**两个**路径参数
     * （oldpath 在 a1、newpath 在 a3），旧接口表达不了，长久只翻 oldpath。
     * 现在用位掩码一次表达两个，见下面各自的注释。
     */
    case 439:  return 1u << 1;          /* faccessat2(dfd, path, mode, flags) */
    case 281:  return 1u << 1;          /* execveat(dfd, path, argv, envp, flags) */

    /*
     * ---- 双路径调用：a1 = oldpath，a3 = newpath ----
     *
     *   renameat (int olddirfd, const char *oldpath,
     *             int newdirfd, const char *newpath)
     *                a0              a1            a2            a3
     *   renameat2(... 同上 ..., unsigned int flags)               a4 = flags
     *   linkat   (... 同上 ..., int flags)                        a4 = flags
     *
     * 【实测锁定 a3（本轮新增的关键证据）】只翻 a1 是不够的，
     * 但 a3 的位置**必须实测**而不能照抄。本机实测（见下表"方法"列）：
     *
     *   ① 效果：syscall(276, AT_FDCWD, SRC, AT_FDCWD, DST, 0)
     *           → r=0，DST 出现且内容等于 SRC 原内容、SRC 消失。
     *           证明 a3 是被创建/被写入的那个名字。
     *   ② a2 是 dirfd 而非路径：syscall(276, AT_FDCWD, SRC, 999999, "rel", 0)
     *           → r=-1 errno=EBADF。若 a2 是路径指针，内核会 EFAULT。
     *   ③ a3 相对于 a2 解析：a2=真实目录 fd、a3="c_in_sub"
     *           → r=0 且文件落在该目录里（而不是 cwd）。
     *           这条同时证明 a3 是路径、a2 是 dirfd，且二者配对。
     *   ④ a1 相对于 a0 解析：a0=真实目录 fd、a1="d_src"
     *           → r=0，证明 a1 与 a0 配对。
     *   ⑤ a4 是 flags：syscall(276, ..., 1 即 RENAME_NOREPLACE) 且目标已存在
     *           → errno=EEXIST；换成 0 则成功。证明 a4 是 flags。
     *   38 (renameat) 用 ①③⑤ 同法复核，结论一致。
     *
     * 【a0 / a2 永远不是路径 —— 不许"顺手也翻一下"】
     * 它们是 dirfd，合法值 AT_FDCWD 是 **-100**（0xffffffffffffff9c）。
     * 把 -100 当指针解引用就是历史上 symlinkat 那次整进程静默消失的
     * 同一个 bug。所以掩码里**只有 a1 与 a3**，a0/a2 绝不出现在掩码中。
     * 传 AT_FDCWD 时走"相对路径、由 dirfd 决定"的逻辑，我们原样透传。
     */
    case 276:  return (1u << 1) | (1u << 3);   /* renameat2: oldpath + newpath */
    case 38:   return (1u << 1) | (1u << 3);   /* renameat:  oldpath + newpath */

    /*
     * ---- linkat 的**号码**：37，不是 260 ----
     *
     * 本机 SYS_linkat == 37。判定用效果证据而非查表：
     *     syscall(37, AT_FDCWD, A, AT_FDCWD, B, 0)
     *       → r=0，A 与 B 的 st_ino 相同、st_nlink 都是 2（真硬链接）。
     *
     * 【linkat 的翻译有一处必须写清的偏差】
     * linkat 的 a3 在语义上不是"新路径"而是**新链接的名字**，
     * 它和 a1 一样受 dirfd 规则支配；两个路径**都要翻译**，
     * 与 renameat 同构。实测 ③④ 两条对 37 同样成立
     * （a2 伪 dirfd → EBADF；a3 相对 a2 解析）。
     * a4 是 flags（实测 AT_SYMLINK_FOLLOW=0x400 被接受）。
     */
    case 37:   return (1u << 1) | (1u << 3);   /* linkat: oldpath + newlinkpath */

    /*
     * ★ case 36 (symlinkat) —— 曾经**刻意不列入**，本轮改为列入，且只翻 a2。
     *
     * 这是我自己引入过的一次致命回归，记录在此防止重犯：
     *
     *   symlinkat(const char *target, int newdirfd, const char *linkpath)
     *                ↑ a0              ↑ a1            ↑ a2
     *
     * 我先前按"a1 是路径"列了 `case 36: return 1` —— **错**。
     * a1 是 `newdirfd`（一个 int）。于是 guard 会把 `AT_FDCWD`
     * （= -100 = 0xffffffffffffff9c）**当成路径指针解引用**
     * → 每一次走裸 syscall 的 symlinkat 都 SIGSEGV。
     *
     * 【实测证据 —— 注意取证方式】
     * 我第一次写的证据是 "syscall(36, target, AT_FDCWD, linkpath) → ENOTDIR"，
     * 那是**错的、复现不出来**：绝对 linkpath 时内核**忽略 dirfd**，
     * 该调用会成功。后来者照抄会得到相反结果，从而怀疑结论。
     *
     * 能确证 a1 是 dirfd 的最小实验必须用**相对 linkpath**（本轮复跑一致）：
     *     syscall(36, "tgt", 999999, "rel-l")  → EBADF   （伪 dirfd 被拒）
     *     syscall(36, "tgt", <文件fd>, "rel-l") → ENOTDIR（不是目录）
     * 两条都说明 a1 被当作目录 fd，而不是路径。
     *
     * 【为什么当初选"不列入"】旧接口只能返回 0 或 1（表示 a0 或 a1），
     * symlinkat 的 linkpath 在 a2，表**表达不了**；硬塞会再次翻错。
     * 当时的取舍是"不翻译"胜过"翻错"（不翻译只是绕过，翻错是崩溃）。
     *
     * 【本轮为什么可以列入了】接口已升级为位掩码，能精确表达 a2。
     * 于是这条从"已知缺口"变成"已覆盖"：
     *
     *     case 36: return 1u << 2;   ← 只翻 linkpath（a2）
     *
     * ★ target（a0）**刻意不翻**：它是**链接内容**，不是待解析的路径。
     *   若在建立时把它改写成宿主路径，客户 readlink 就会看到宿主路径
     *   （例如 /data/local/tmp/rootfs/usr/lib），泄漏翻译层内部布局，
     *   而且同一个链接在 guest 里表示的含义就错了。
     *   这一点与 preload.c 的 symlinkat 钩子**逐字一致**：
     *   那个钩子同样只翻 linkpath、原样保留 target。两处必须同语义。
     *
     * 【同类核对结论】其余带 dirfd 的调用 a1 确实是路径，均正确：
     *     linkat(olddirfd, oldpath, ...)     → a1 = oldpath ✅
     *     renameat(olddirfd, oldpath, ...)   → a1 = oldpath ✅
     *     renameat2(olddirfd, oldpath, ...)  → a1 = oldpath ✅
     *     faccessat2(dfd, path, ...)         → a1 = path    ✅
     *     execveat(dfd, path, ...)           → a1 = path    ✅
     * symlinkat 是**唯一**把 target 放 a0、linkpath 放 a2 的，所以只有它特殊。
     */
    case 36:   return 1u << 2;         /* symlinkat: 只翻 linkpath（a2），target(a0) 是链接内容，不翻 */

    default:   return 0;
    }
}

/*
 * ★ 测试钩子 —— 让"路径参数表"这件最要命的事变得可回归 ★
 *
 * 背景：本项目出过两次**同类致命缺陷**，都在这张表上：
 *   1. `case 36 (symlinkat): return 1` —— a1 其实是 `newdirfd`（int），
 *      于是 guard 把 `AT_FDCWD`(-100) 当指针解引用，**每一次**裸 syscall
 *      的 symlinkat 都 SIGSEGV；
 *   2. `case 260` 被当成 linkat —— aarch64 上 260 是 **wait4**，它的 a1
 *      是 `int *wstatus`。被信号 47 终止的子进程 wstatus==0x2f，首字节
 *      恰好是 `'/'` → guard 判定为路径 → 内核把退出状态写进 guard 的
 *      临时缓冲，**调用方的 wstatus 永远不被写入**（静默数据错写，
 *      比 SIGSEGV 更难查）。
 *
 * 而当时的回归**测不到这张表**：`test/test_syscall_argpos.c` 只编自己，
 * 从不链接本文件（实测 `nm` 里 0 个 guard 符号），它测的是**内核 ABI**，
 * 不是我们的表。红队复核时把 `path_arg_index()` 改回 `return 1`
 * （历史缺陷本体），该项仍然 PASS、门禁 0 条、全回归绿 ——
 * **这套回归声称能防的那个具体缺陷，它防不住**。
 *
 * 这个钩子就是为此而加：把 `path_arg_mask` 暴露成可链接、可断言的入口，
 * 让测试能直接钉住"哪些参数位置是路径"。
 *
 * ★ 命名与导出 ★
 * 用 `bxroot_test_` 前缀并在头文件里声明，生产代码不调用它。
 * 它不改变任何行为（纯查表），只是把 static 函数转出来。
 * 之所以不直接把 `path_arg_mask` 改成非 static：那会让它进入动态符号
 * 表，而本项目有一条硬约束 —— **不要导出无意义的符号**（官方符号表里
 * 那些空壳就是反例）。
 */
unsigned bxroot_test_path_arg_mask(long nr)
{
    return path_arg_mask(nr);
}

/* ------------------------------------------------------------------ */
/* 对外接口                                                            */
/* ------------------------------------------------------------------ */

long syscall(long number, ...)
{
    va_list ap;
    long a0, a1, a2, a3, a4, a5;
    long *args[6];
    unsigned pmask;
    int i;

    init_trace();

    va_start(ap, number);
    a0 = va_arg(ap, long);
    a1 = va_arg(ap, long);
    a2 = va_arg(ap, long);
    a3 = va_arg(ap, long);
    a4 = va_arg(ap, long);
    a5 = va_arg(ap, long);
    va_end(ap);

    /*
     * 参数寄存器数组 —— 让"第 i 个参数"可以用下标寻址。
     * 翻译分支据此按下标回写，不必为每个位置写一条 if。
     * a0..a5 都是局部变量，取地址安全，且不会逃逸出本函数。
     */
    args[0] = &a0; args[1] = &a1; args[2] = &a2;
    args[3] = &a3; args[4] = &a4; args[5] = &a5;

    if (should_block(number)) {
        g_blocked++;
        if (g_trace)
            log_num("[bxroot] syscall_guard: 拦截 ", number, " -> ENOSYS\n");
        errno = ENOSYS;
        return -1;
    }

    pmask = path_arg_mask(number);
    if (pmask != 0) {
        /*
         * ============================================================
         * 逐个处理被标记为路径的寄存器
         * ============================================================
         *
         * 【为什么是循环而不是把 a1 / a3 写死】
         * 掩码是"哪些参数是路径"的**唯一**表述处，翻译逻辑只写一份。
         * 将来再遇到多路径调用，只需改表一行，不必在翻译分支里
         * 再补一条 if —— 而"补 if"正是 newpath 长久漏翻的成因：
         * 当初只有一个 `pidx == 0 ? a0 : a1` 的三目表达式，
         * a3 根本没有位置可写。
         *
         * 【顺序】i 从小到大（对 renameat 即 a1 先于 a3），与客户
         * 传参顺序一致。两条路径各自独立取缓冲槽位，互不覆盖。
         */
        for (i = 0; i < 6; i++) {
            const char *pth;

            if (!(pmask & (1u << i)))
                continue;

            /*
             * ★ dirfd 永远不在掩码里 ★
             * 掩码只由 path_arg_mask() 产生，而该表对每个带 dirfd 的
             * 调用都只标路径位（a1/a2/a3），绝不标 a0/a2 里的 dirfd。
             * 这是历史事故（symlinkat 把 AT_FDCWD=-100 当指针）的防线：
             * 一旦有人往掩码里加了 dirfd 位，这里就会解引用 -100。
             */
            pth = (const char *)(uintptr_t)*args[i];

            /*
             * ============================================================
             * ★ NULL 路径：直接回 EFAULT，不交给翻译层 ★
             * ============================================================
             *
             * 【为什么必须在这里判，而不是靠下面的 looks_like_guest_abs_path】
             * 那个函数对 NULL 返回 0（"不是 guest 绝对路径"），于是控制流
             * 会**跳过翻译、把 NULL 原样发给内核**。绝大多数情况下这没错
             * —— 实测内核对这些调用的 NULL 路径统一返回 EFAULT：
             *
             *     renameat (AT_FDCWD, NULL, AT_FDCWD, p)  → EFAULT
             *     renameat (AT_FDCWD, p, AT_FDCWD, NULL)  → EFAULT
             *     renameat2(同上两种)                     → EFAULT
             *     linkat   (同上两种)                     → EFAULT
             *     symlinkat("tgt", AT_FDCWD, NULL)        → EFAULT
             *
             * 但仍然显式判一次，理由有二：
             *
             * ① **不要把正确性寄托在"下面那个函数恰好返回 0"上。**
             *    这是隐式契约：将来若有人把 looks_like_guest_abs_path
             *    改成对 NULL 返回 1（例如"NULL 当空路径处理"这种看起来很
             *    合理的改动），翻译层就会去读 NULL → SIGSEGV。
             *    显式判空把这条依赖变成**代码里看得见**的事实。
             *
             * ② 语义精确。EFAULT 是内核给 NULL 路径的**规范答复**，
             *    我们提前给出同一个 errno，客户观察到的行为完全一致；
             *    而"不翻译直接透传"在**两个路径参数**的新形态下还有个
             *    副作用：若 a1 是 NULL 而 a3 是有效 guest 路径，
             *    透传会让 a3 不被翻译，客户拿到 ENOENT 而不是 EFAULT ——
             *    错误码就与原生行为**不一致**了。显式判空后，
             *    errno 与原生逐位一致。
             *
             * 【为什么返回 -1 而不是继续处理另一个路径】
             * 内核先解 oldpath，oldpath 为 NULL 时立即 EFAULT，
             * 第二个路径根本不看（已实测）。提前返回复刻这一顺序，
             * 也避免为一个注定失败的调用做无用的翻译。
             *
             * 注：这里**不**设置 errno 后继续 —— 直接 return -1。
             * 与 raw_syscall6 的约定一致（返回 -1、errno 已设）。
             */
            if (*args[i] == 0) {
                if (g_trace)
                    log_num("[bxroot] syscall_guard: a", i, " 路径为 NULL -> EFAULT\n");
                errno = EFAULT;
                return -1;
            }

        /*
         * ============================================================
         * 重入守卫（防御性）
         * ============================================================
         *
         * `translate_path` 内部用 `snprintf` 拼路径。虽然实测 glibc 的
         * 格式化不会回头调 stat 系系统调用，但这条链**理论上**可以
         * 闭合：任何一次内部 stat 都会重新进入本函数。
         *
         * 加这道守卫的成本是一个 thread_local 读写，收益是把
         * "无限递归到栈溢出"这个**不可调试**的故障模式彻底排除。
         *
         * 【一个必须记录的方法论教训】
         * 我最初的诊断代码是这样写的：
         *
         *     static _Thread_local int d291;
         *     if (number == 291) { d291++; printf("depth=%d", d291); }
         *
         * 它输出了 depth=1,2,3,...,400 —— 我据此判定"无限递归"。
         * **但那个结论是错的**：`d291` 只增不减，所以顺序调用也会
         * 让它单调递增。真正区分"嵌套"与"顺序"要在**函数返回前递减**。
         *
         * 实测（libuv 连续探测数百个 node_modules 子目录）是**顺序**调用，
         * 不是嵌套。这道守卫因此**没有**解决当初的段错误 —— 保留它
         * 是因为它防的是另一件事（理论上的递归），而且成本可忽略。
         *
         * 【为什么必须是 thread_local（历史说明，当前实现已改池化）】
         * `syscall` 会被多线程并发调用。用**全局**标志的话：
         * A 线程正在翻译时，B 线程的翻译会被误判为重入而跳过 ——
         * 表现为"随机某些路径不翻译"，比崩溃更难排查。
         *
         * 【为什么不用 pthread_key】
         * 这是 LD_PRELOAD 层，构造函数极早期就可能被调用，
         * 那时 pthread_key_create 未必可用。`_Thread_local` 由
         * TLS 直接支撑，无此问题。
         *
         * 注：下面这段"重入守卫"的**叙述**保留（它是判据的由来），
         * 但目标缓冲最终没有采用 TLS —— 见紧接着的缓冲选型说明。
         */
        /*
         * ============================================================
         * ★★ 目标缓冲：**不用 _Thread_local、不用 malloc** ★★
         * ============================================================
         *
         * 这里踩过一个非常隐蔽的坑，值得完整记录。
         *
         * 【症状】`dsh web --help` 段错误，崩溃在 glibc 的 `strlen`：
         *     x0 = 0xffffffffffffffff   （即 strlen((char*)-1)）
         * 而 `dsh --help` / `--version` 完全正常。
         *
         * 【判决实验】同一份源码，只改"把翻译结果放哪"：
         *     静态 _Thread_local 缓冲  → 崩溃（2/2 复现）
         *     堆上 malloc 的拷贝       → 正常（3/3 复现）
         * 两者唯一差别就是**缓冲的位置**。
         *
         * 【根因】bxroot 运行在 proroot 的**自研 ELF 加载器**之下
         * （`libproroot-linker.so`，不是 glibc 的 ld.so）。那个加载器
         * 对 TLS 的支持不完整 —— 它的 rodata 里明确带着这条字符串：
         *
         *     tls: runtime static TLS surplus exhausted
         *
         * 也就是说：动态加载的库里，`_Thread_local` 的存储可能**没有
         * 被正确分配**。对它的读写会落到错误的地址，破坏相邻数据
         * （包括 node 自己的指针），最终表现为在 `strlen` 里读到 -1。
         *
         * 这解释了为什么症状如此"挑剔"：
         *   - `--version` 不走多少 statx，碰不到这个缓冲；
         *   - `web` profile 的模块解析要连续探测数百个目录，
         *     每次都写这个坏掉的 TLS 缓冲，很快踩坏关键数据。
         *
         * 【修法】改用**普通静态缓冲池 + 轮转索引**：
         *   - 不依赖 TLS（绕开加载器的缺陷）
         *   - 不 malloc（不会泄漏，也不会在信号处理器里死锁）
         *   - 轮转多个槽位：即使某个调用方短暂持有上一次的指针，
         *     也要过 N 次调用才会被覆写，实践中足够
         *
         * 代价：32 KB 静态内存（8 × 4 KB），每线程共享同一池。
         * 极端并发下仍可能互相覆写 —— 但那是**旧的**风险（原实现的
         * 全局静态缓冲也有），而 TLS 方案的风险是**内存被写坏**，
         * 严重得多。
         */
        if (looks_like_guest_abs_path(pth)) {
            /*
             * 大环形池：64 KB，只在池内前进，到末尾回绕。
             *
             * 为什么不是小池（8 × 4KB）：实测表明**调用方会在内核返回后
             * 继续持有该指针**。判决实验（三种策略，其他条件完全相同）：
             *
             *     静态 8 槽轮转池   → 段错误
             *     堆 + 只分配一次   → 段错误
             *     堆 + 每次分配     → 正常
             *
             * 唯一变量是"缓冲是否被复用"。所以覆写周期必须足够长 ——
             * 64 KB 意味着要经过 16 次以上调用才会回到同一块，
             * 而 libuv 持有路径指针的时间远短于此。
             *
             * 为什么不用"每次 malloc"（实测可行）：**会泄漏**。
             * libuv 探测模块时连续调用数百次 statx，每次 4 KB 就是
             * 数 MB；长跑必然 OOM。环形池是零泄漏的等价方案。
             *
             * 为什么不用 _Thread_local：本机加载器是自研的，TLS 支持
             * 不完整（rodata 里有 "tls: runtime static TLS surplus
             * exhausted"），用它反而会写坏相邻数据。
             */
            #define SG_POOL_SIZE (64 * 1024)
            #define SG_SLOT_SIZE 4096
            #define SG_SLOT_COUNT (SG_POOL_SIZE / SG_SLOT_SIZE)
            static char sg_pool[SG_POOL_SIZE];
            /*
             * ★ 槽位索引用**原子取号**，不是"读-改-写"。
             *
             * 【为什么必须有这一步】
             * `syscall()` 会被多线程并发调用 —— 而 node/libuv 正是多线程的，
             * 模块探测时数个线程同时发 statx。先前写成：
             *
             *     if (sg_pool_off + need > SG_POOL_SIZE) sg_pool_off = 0;
             *     tbuf = sg_pool + sg_pool_off;
             *     sg_pool_off += need;          ← 非原子读-改-写
             *
             * 两个线程可能读到同一个 off，拿到**同一个缓冲**：
             * 一方正在写路径、另一方把它覆盖 —— 内核最终读到一个
             * 半截或完全错乱的路径。这与本项目先前记录过的
             * "复用缓冲会崩"是同一类故障（那次是单线程复用，
             * 这次是并发撞车）。
             *
             * 【为什么用原子而不是锁】
             * 1. 不能加互斥锁：syscall 可能在**信号处理器**上下文被调用
             *    （我们的 SIGSYS 处理器就会），锁会导致自死锁。
             * 2. 不能用 _Thread_local：本机加载器 TLS 不完整（其 rodata 里
             *    有 "tls: runtime static TLS surplus exhausted"），
             *    实测用它会写坏相邻数据。
             * 3. `__atomic_fetch_add` 在 aarch64 上编译成 ldxr/stxr 循环，
             *    无锁、可重入、在信号处理器里安全。
             *
             * 【槽位与轮转】
             * 固定 4 KB 槽位（翻译结果最长 4096，与调用方给的 need 一致）。
             * 取号对槽位数取模实现轮转 —— 16 个槽位意味着要过 16 次调用
             * 才回到同一块，而调用方持有路径指针的时间远短于此。
             */
            static unsigned int sg_pool_seq;

            unsigned int seq = __atomic_fetch_add(&sg_pool_seq, 1, __ATOMIC_RELAXED);
            char *tbuf = sg_pool + (size_t)(seq % SG_SLOT_COUNT) * SG_SLOT_SIZE;
            size_t need = SG_SLOT_SIZE;

            int tr = bxroot_translate_path(pth, tbuf, need);

            if (tr > 0) {
                *args[i] = (long)(uintptr_t)tbuf;
                if (g_trace) {
                    log_num("[bxroot] syscall_guard: 翻译 a", i, " ");
                    log_str(pth);
                    log_str(" -> ");
                    log_str(tbuf);
                    log_str("\n");
                }
            }
        }   /* if (looks_like_guest_abs_path(pth)) */
        }   /* for (i = 0; i < 6; i++) */
    }       /* if (pmask != 0) */

    {
        long ret = raw_syscall6(number, a0, a1, a2, a3, a4, a5);

        /*
         * ============================================================
         * statx 的**结果补丁** —— 裸 syscall 路径上缺失的那一半
         * ============================================================
         *
         * 【问题】libuv（node 的 FS 层）**故意绕开 libc**：
         *
         *     static int uv__fs_statx(int fd, const char* path, ...) {
         *         struct statx statxbuf;
         *         int ret = syscall(SYS_statx, fd, path, flags, mask, &statxbuf);
         *         ...
         *     }
         *
         * 实测证据：node 每次 statSync/lstatSync 都是本函数的
         * `number=291`，而 preload.c 里那个 statx() **符号钩子一次都
         * 没被调用**。node 二进制里 24 条 svc、0 处引用 newfstatat/statx
         * 符号 —— 它只走这条路。
         *
         * 后果：路径翻译那一半（本函数上面的 pmask 分支）**是生效的**，
         * 而结果伪装那一半从未发生。于是 l2s 的硬链接模拟在 node 眼里
         * 等于不存在：st_nlink 停在 1、stx_mode 带 S_IFLNK。
         * pnpm 正是靠 st_nlink 判断 store 里的文件是否已链接，看到 1
         * 就认为没链接，退化成完整复制 —— 这正是 DSHA 被迫使用
         * package-import-method=copy 的根因。
         *
         * 本文件头【问题二】早就记下了"libuv 用 syscall(291) 直接发起"
         * 这件事，但当时只做了翻译、没做伪装。这里补上缺的那一半。
         *
         * 【为什么放在 raw_syscall6 之后】
         * 补丁必须作用于**内核已经写好**的结构体。放在调用前，
         * 内核随后会把真实值覆盖回去，等于白写。
         *
         * 【为什么必须在这里做，而不是"让 libuv 改走 libc"】
         * 客户代码不可改。LD_PRELOAD 层的职责就是在客户选择的路径上
         * 补齐语义，而不是要求客户换路径。
         *
         * 【与 l2s_rt_patch_statx_full 的分工】
         * 本函数只负责"在哪补"（结果缓冲的确切地址 = a4，这是 statx
         * ABI 里 struct statx * 的位置）。"补成什么"全部交给 l2s 层 ——
         * 判据（是不是伪造链接、链长多少、要不要抹 S_IFLNK）只有它有，
         * 这里不复制任何判据。
         *
         * 【门控条件，一条都不能少】
         *   ret == 0   失败时内核没写 buf，改它就是碰运气
         *   number==291 只碰 statx，绝不影响其他系统调用
         *   a4 != 0    客户可能传空指针（statx 会回 EFAULT），
         *              解引用它就是 SIGSEGV
         *   a1 != 0    路径为空指针时 l2s 层无从 probe，直接跳过
         *
         * ★ 官方 proroot 在同一位置做同一件事 ★
         * 实测（同一个裸 statx 探针，同一颗 node 环境）：
         *     官方: mode=0100600 nlink=2 islnk=0   ← 已伪装
         *     bxroot(修前): mode=0120777 nlink=1 islnk=1
         */
        if (ret == 0 && number == SCG_NR_statx && a4 != 0 && a1 != 0 &&
            l2s_rt_patch_statx_full != NULL) {
            /* struct statx 的字段布局（u32 起始部分）：
             *   stx_mask(0) stx_blksize(4) stx_attributes(8)
             *   stx_nlink(16) stx_uid(20) stx_gid(24) stx_mode(28)
             * 前三个字段之后正好是 nlink/uid/gid/mode —— 用 u32 指针
             * 加偏移寻址，避免为一个结构体拖进 <linux/stat.h>。 */
            unsigned int *base = (unsigned int *)(uintptr_t)a4;

            l2s_rt_patch_statx_full(&base[4] /* stx_nlink */,
                                    &base[0] /* stx_mask  */,
                                    &base[7] /* stx_mode  */,
                                    SCG_STATX_NLINK,
                                    (const char *)(uintptr_t)a1);
        }

        return ret;
    }
}
unsigned long bxroot_syscall_guard_blocked(void)
{
    return g_blocked;
}
