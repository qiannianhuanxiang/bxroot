/*
 * static_exec.c —— 进程内装载并执行「无 PT_INTERP」的静态 ELF
 *
 * ====================================================================
 * 为什么需要（2026-10-05 真机 + 容器复现）
 * ====================================================================
 *
 * 冷安装 libc-bin 的 postinst 跑 /sbin/ldconfig.real（static-PIE）。旧路径是
 * `execve(PROROOT_STUB_LOADER, …)`：
 *
 *   1. execve 之后 bxroot runtime（LD_PRELOAD）整个消失；静态程序自己也读不到
 *      LD_PRELOAD，没有任何钩子；
 *   2. 官方 stub-loader 自带的 syscall 翻译只覆盖 openat/stat 一类，对
 *      **绝对路径的 renameat / linkat / unlinkat / mkdirat / symlinkat /
 *      fchmodat / faccessat / truncate 不翻译**（本机用官方 stub-loader 单独
 *      跑探针复现：openat 落进 rootfs，renameat 落到宿主 /etc）；
 *   3. 官方 runtime 靠父进程 ptrace 补这些洞，bxroot 不 ptrace。
 *
 *   现场：ldconfig 先把 /etc/ld.so.cache~ 写进 rootfs（openat 已翻译），再
 *   rename 到宿主 /etc/ld.so.cache → Android 只读 /etc → EROFS。
 *   见设备日志 "Renaming of /etc/ld.so.cache~ to /etc/ld.so.cache failed:
 *   Read-only file system"。STUB_ROOTFS 变体的修法已被该日志证伪。
 *
 * ====================================================================
 * 做法
 * ====================================================================
 *
 * 不经内核 execve：本进程自己 mmap 目标 ELF、搭栈、跳进入口（同 src/ldr/ulx.c）。
 * 进程还是同一个进程，runtime 还映射在里面。再把目标代码段里**路径类**
 * `mov x8,#NR ; … ; svc #0` 站点改写成 `b <veneer>`：
 *
 *     站点:    b   veneer_i                （原 svc #0）
 *     veneer_i: ldr x16, =<站点+4>          （返回地址）
 *               ldr x17, =px_static_tramp
 *               br  x17
 *     px_static_tramp（runtime 内）:
 *               存 x1..x17、q0..q7、x29/x30、静态程序的 TPIDR_EL0
 *               TPIDR_EL0 ← 动态 libc 的 TLS（exec 前记下）
 *               px_static_dispatch(a0..a5, nr)   —— 翻译路径，发真 svc
 *               TPIDR_EL0 ← 静态程序的 TLS；还原寄存器；br x16（回站点+4）
 *
 * 为什么是 B 不是 BL：glibc 的 syscall 包装常是 `svc #0 ; ret` 的叶子函数，
 * BL 会覆盖 x30，ret 就回不去了。veneer 用 x16/x17（AAPCS 的 IP0/IP1，
 * 编译器不会跨 svc 让它们保活；内核虽保留但 glibc 内联 svc 不依赖它们）。
 *
 * 为什么要换 TLS：静态 glibc 的 __libc_setup_tls 会把 TPIDR_EL0 指向自己的
 * TCB；而 runtime 的 errno / __thread / 栈保护 canary 都按动态 libc 的 TLS
 * 布局取址。不换回去，runtime 代码会读写静态程序 TCB 的错位置。
 *
 * ====================================================================
 * 边界（如实）
 * ====================================================================
 *   - 只补 `mov x8/w8,#立即数` 近距离跟 `svc` 的站点。syscall 号来自寄存器的
 *     通用 syscall() 包装补不到。
 *   - execve/execveat 站点转交 runtime 的 exec 钩子（2026-10-31，见
 *     px_static_dispatch）。此前不拦，guest 路径直达内核，真机上会跑到
 *     宿主 /system/bin 的二进制或 ENOENT。
 *   - 多线程进程拒绝（真 execve 会杀其它线程，我们做不到）→ 调用方回退 stub。
 *   - TLS 切换只对单线程静态程序成立（动态 TLS 取 exec 线程的）。
 *   - ET_EXEC 的固定地址与 runtime/堆冲突时 MAP_FIXED_NOREPLACE 失败 → 回退。
 *   - SIGSYS 用 early handler：194..197 交给仅裸 syscall/原子操作的 SHM
 *     后端，其余 TRAP 回 -ENOSYS；不调用会动动态 TLS/errno 的完整处理器。
 *     SHM copyout/锁能力仍由后端的 verified 构建 gate 控制。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "static_exec.h"

#define SX_MAX_PHDR    64
#define SX_STACK_SIZE  (8UL << 20)
#define SX_SCAN_WINDOW 12
#define SX_VENEER_SIZE 32
#define SX_SVC_INSN    0xd4000001u
#define SX_PATHBUF     (PATH_MAX * 2)

/* 翻译桥：与 livepatch.c 同一套 weak 约定（单测里无 preload.c → NULL → 原样发 svc） */
__attribute__((weak))
int bxroot_translate_path(const char *path, char *out, size_t out_size);
__attribute__((weak))
int bxroot_resolve_abs_symlink(const char *translated, char *out, size_t out_size);
__attribute__((weak))
void bxroot_log(const char *fmt, ...);

/*
 * exec 桥（proc.c）：与 syscall_guard 的 syscall(SYS_execve, …) 同一入口，
 * 走完整的 exec 路径（路径翻译 + 环境注入 + trampoline/ULX 或再次 static_exec）。
 * 返回 -1 + errno（成功不返回）。weak：单测里没有 proc.c。
 */
__attribute__((weak))
int bxroot_exec_hook_execve(const char *path, char *const argv[], char *const envp[]);
__attribute__((weak))
int bxroot_exec_hook_execveat(int dirfd, const char *path, char *const argv[],
                              char *const envp[], int flags);
__attribute__((weak))
int bxroot_sysvshm_anchor_fd(void);
__attribute__((weak))
void bxroot_sysvshm_exec_reset(void);
__attribute__((weak))
int bxroot_sysvshm_emulate(long sc, unsigned long a0, unsigned long a1,
                           unsigned long a2, long *x0);

static int sx_preserve_internal_exec_fd(int fd)
{
    return bxroot_sysvshm_anchor_fd != NULL &&
           bxroot_sysvshm_anchor_fd() == fd;
}

/* 新程序的 guest 视角可执行路径（来自 envp 的 BXROOT_GUEST_EXE），答 /proc/self/exe 用。 */
static char sx_guest_exe[PATH_MAX];

/*
 * ★ runtime 自身的路径：路径翻译不碰它（2026-10-31，Fedora ld.so 复现）★
 *
 * 目标是另一个 rootfs 的 ld.so（`<fedora>/usr/lib/ld-linux-aarch64.so.1
 * --library-path … prog`）时，exec 钩子给它的 envp 里带着 LD_PRELOAD=<本 runtime>。
 * 这份 ld.so 的 openat 站点已被上面改写成走 px_static_dispatch，于是它打开
 * LD_PRELOAD 时，路径也会被加上 rootfs 前缀。真机上 runtime 在 rootfs 之外
 * （APK nativeLibraryDir，/data/app/…），加前缀后打不开：
 *     ERROR: ld.so: object '…/libbxroot-runtime.so' from LD_PRELOAD cannot be
 *     preloaded (cannot open shared object file): ignored.
 * 后果：新命名空间里没有 runtime，livepatch 的构造函数不会执行，Fedora
 * libc 的 _Fork 内联 svc set_robust_list 保持原样 → 子进程 SIGSYS。
 *
 * LD_PRELOAD 里的这个路径来自 dladdr（px_cfg_merge_preload），本身就是内核
 * 视角，原样交给内核就对。只对**完全等于**本 runtime 路径的参数透传，
 * 其余路径照常翻译。
 */
static char sx_self_lib[PATH_MAX];

long px_static_dispatch(long a0, long a1, long a2, long a3, long a4, long a5,
                        long nr);

static void sx_record_self_lib(char *const envp[], size_t nenv)
{
    Dl_info di;
    size_t k;

    sx_self_lib[0] = '\0';
    memset(&di, 0, sizeof di);
    if (dladdr((void *)&px_static_dispatch, &di) != 0 && di.dli_fname != NULL &&
        di.dli_fname[0] == '/' && strlen(di.dli_fname) < sizeof(sx_self_lib)) {
        memcpy(sx_self_lib, di.dli_fname, strlen(di.dli_fname) + 1);
        return;
    }
    /* dladdr 拿不到时退回 proc 层记下的 BXROOT_LD_PRELOAD（同为 dladdr 来源） */
    for (k = 0; k < nenv; k++) {
        const char *v;

        if (strncmp(envp[k], "BXROOT_LD_PRELOAD=", 18) != 0)
            continue;
        v = envp[k] + 18;
        if (v[0] == '/' && strchr(v, ':') == NULL && strchr(v, ' ') == NULL &&
            strlen(v) < sizeof(sx_self_lib))
            memcpy(sx_self_lib, v, strlen(v) + 1);
        return;
    }
}

static int sx_is_self_lib(const char *p)
{
    return sx_self_lib[0] == '/' && strcmp(p, sx_self_lib) == 0;
}

/*
 * ★ 当前正在运行的静态映像（由本文件装载）的保留区（2026-10-31）★
 *
 * 静态程序再 exec 另一个 ET_EXEC 静态程序时，两者通常都要 0x400000。
 * 旧映像还映射着，新映像的 MAP_FIXED_NOREPLACE 就 EEXIST → 回退 stub-loader，
 * 而 stub 路径对静态目标的翻译不完整（见文件头）。真 execve 会先拆掉旧映像，
 * 这里在**确认冲突只来自旧映像**后照做。跳转前登记，0 = 当前不是我们装的静态映像。
 */
static unsigned long sx_cur_base, sx_cur_len;

/* 动态 libc 的 TPIDR_EL0（exec 前记下）。汇编跳板用 adrp 直接引用。 */
unsigned long px_static_dyn_tls __attribute__((visibility("hidden")));

/* ------------------------------------------------------------------ */
/* 裸系统调用                                                          */
/* ------------------------------------------------------------------ */

static long sx_sc6(long nr, long a0, long a1, long a2, long a3, long a4, long a5)
{

#if defined(__aarch64__)
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;

    __asm__ volatile(""
        "stp x1, x2, [sp, #-16]!\n\t"
        "stp x3, x4, [sp, #-16]!\n\t"
        "str x5,     [sp, #-16]!\n\t"
        "svc #0\n\t"
        "ldr x5,     [sp], #16\n\t"
        "ldp x3, x4, [sp], #16\n\t"
        "ldp x1, x2, [sp], #16\n"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
        : "memory", "cc");
    return x0;
#else
    /* Non-AArch64 fallback: callers expect the raw kernel value
     * (negative == -errno). */
    long r = syscall(nr, a0, a1, a2, a3, a4, a5);
    return r < 0 ? -(long)errno : r;
#endif

}

#define SC(nr, a, b, c, d) sx_sc6((nr), (long)(a), (long)(b), (long)(c), (long)(d), 0, 0)

/* ------------------------------------------------------------------ */
/* 路径类系统调用表（aarch64 号）                                       */
/* ------------------------------------------------------------------ */

/*
 * bit i 置位 = a<i> 是路径指针。a0/a2 为 dirfd 的位置绝不置位
 * （把 AT_FDCWD=-100 当指针解引用会整进程崩，见 syscall_guard.c 的教训）。
 */
static unsigned sx_path_mask(long nr)
{
    switch (nr) {
    case 33:  return 1u << 1;              /* mknodat(dfd, path, …)        */
    case 34:  return 1u << 1;              /* mkdirat                      */
    case 35:  return 1u << 1;              /* unlinkat                     */
    case 36:  return 1u << 2;              /* symlinkat(target, dfd, link) */
    case 37:  return (1u << 1) | (1u << 3);/* linkat                       */
    case 38:  return (1u << 1) | (1u << 3);/* renameat                     */
    case 43:  return 1u << 0;              /* statfs                       */
    case 45:  return 1u << 0;              /* truncate                     */
    case 48:  return 1u << 1;              /* faccessat                    */
    case 49:  return 1u << 0;              /* chdir                        */
    case 53:  return 1u << 1;              /* fchmodat                     */
    case 54:  return 1u << 1;              /* fchownat                     */
    case 56:  return 1u << 1;              /* openat                       */
    case 78:  return 1u << 1;              /* readlinkat                   */
    case 79:  return 1u << 1;              /* newfstatat                   */
    case 88:  return 1u << 1;              /* utimensat                    */
    case 276: return (1u << 1) | (1u << 3);/* renameat2                    */
    case 291: return 1u << 1;              /* statx                        */
    case 439: return 1u << 1;              /* faccessat2                   */
    case 5: case 6: case 8: case 9: case 11: case 12: case 14: case 15:
              return 1u << 0;              /* *xattr(path, …)              */
    default:  return 0;
    }
}

/* 需要补丁的站点：入参有路径，或出参是路径（getcwd=17，内核写宿主路径回来）。 */
static int sx_wants_site(long nr)
{
    return sx_path_mask(nr) != 0 || nr == 17 || (nr >= 194 && nr <= 197) ||
           nr == 221 /* execve */ || nr == 281 /* execveat */;
}

/* 反向翻译：把内核写回的宿主路径剥成 guest 视角（用 runtime 自己的剥离逻辑）。 */
__attribute__((weak))
int bxroot_strip_rootfs(char *buf);

static long sx_getcwd_fixup(long r, char *buf, unsigned long size)
{
    size_t len;

    if (r <= 0 || buf == NULL || bxroot_strip_rootfs == NULL)
        return r;
    len = strnlen(buf, size);
    if (len >= size)
        return r;                       /* 没有 NUL：不是合法结果，原样交回 */
    if (!bxroot_strip_rootfs(buf))
        return r;
    return (long)strlen(buf) + 1;       /* getcwd 系统调用返回含 NUL 的长度 */
}

/*
 * readlinkat(78)：
 *   - /proc/self/exe → 新程序的 guest 路径（内核只会答 bridge/linker，必错）；
 *     与 runtime 的 readlink 钩子同语义：guest_exe 不是绝对路径时不伪装。
 *   - 其它路径：内核写回的是宿主路径，原地剥 rootfs 前缀（和 getcwd 同类）。
 * readlink 的结果不带 NUL，所以用临时缓冲做剥离，再按原长度回写。
 */
static long sx_readlinkat_fixup(long r, char *buf, unsigned long size)
{
    char tmp[SX_PATHBUF];
    size_t n;

    if (r <= 0 || buf == NULL || bxroot_strip_rootfs == NULL || (unsigned long)r >= sizeof(tmp))
        return r;
    memcpy(tmp, buf, (size_t)r);
    tmp[r] = '\0';
    if (!bxroot_strip_rootfs(tmp))
        return r;
    n = strlen(tmp);
    if (n > size)
        n = size;                       /* readlink 截断语义：不报错 */
    memcpy(buf, tmp, n);
    return (long)n;
}

static int sx_is_proc_self_exe(const char *p)
{
    return p != NULL && strcmp(p, "/proc/self/exe") == 0;
}

/*
 * 由汇编跳板调用（此时 TPIDR_EL0 已切回动态 libc 的 TLS）。
 * 返回内核原始约定（负 errno = 错误）。
 */
__attribute__((visibility("hidden")))
long px_static_dispatch(long a0, long a1, long a2, long a3, long a4, long a5,
                        long nr)
{
    unsigned mask = sx_path_mask(nr);
    long a[6];
    char buf[2][SX_PATHBUF];
    int i, used = 0;

    if (nr >= 194 && nr <= 197 && bxroot_sysvshm_emulate != NULL) {
        long result = -38;
        if (bxroot_sysvshm_emulate(nr, (unsigned long)a0, (unsigned long)a1,
                                  (unsigned long)a2, &result))
            return result;
        return -38;
    }

    /*
     * ★ execve(221) / execveat(281)：交给 runtime 的 exec 钩子（2026-10-31）★
     *
     * 原先不拦（见文件头"边界"）：静态程序 exec 时 guest 路径直达内核。
     * 真机宿主 /bin -> /system/bin，于是 execv("/bin/echo") 跑的是 Android
     * toybox，bionic linker 再按 LD_PRELOAD 去加载 glibc 的 runtime：
     *     CANNOT LINK EXECUTABLE "/bin/echo": library "libc.so.6" not found
     * 其余 guest 路径（/usr/bin/…、/tmp/…）宿主上不存在 → ENOENT。
     * 清掉 LD_PRELOAD 只会让前者"成功"跑宿主二进制（逃出容器），不是修复。
     *
     * 这里的上下文与动态进程调 execve 钩子等价：TLS 已切回动态 libc
     * （errno / getenv / malloc 都是 runtime 那一份）。成功则不返回；
     * 失败把 errno 按内核约定转成负值交回静态程序。
     */
    if (nr == 221 && bxroot_exec_hook_execve != NULL) {
        int rc = bxroot_exec_hook_execve((const char *)(uintptr_t)a0,
                                         (char *const *)(uintptr_t)a1,
                                         (char *const *)(uintptr_t)a2);
        return rc < 0 ? -(long)(errno ? errno : ENOEXEC) : (long)rc;
    }
    if (nr == 281 && bxroot_exec_hook_execveat != NULL) {
        int rc = bxroot_exec_hook_execveat((int)a0, (const char *)(uintptr_t)a1,
                                           (char *const *)(uintptr_t)a2,
                                           (char *const *)(uintptr_t)a3, (int)a4);
        return rc < 0 ? -(long)(errno ? errno : ENOEXEC) : (long)rc;
    }

    if (nr == 78 && sx_guest_exe[0] == '/' &&
        sx_is_proc_self_exe((const char *)(uintptr_t)a1)) {
        size_t n = strlen(sx_guest_exe);
        if ((unsigned long)a3 < n)
            n = (size_t)a3;             /* 截断，不带 NUL，与内核一致 */
        memcpy((void *)(uintptr_t)a2, sx_guest_exe, n);
        return (long)n;
    }
    if (nr == 78) {
        /* 走下面的入参翻译 + 发 svc，再对出参做反向翻译 */
        long rr;
        char tbuf[SX_PATHBUF];
        long aa1 = a1;
        const char *pp = (const char *)(uintptr_t)a1;
        if (pp != NULL && pp[0] == '/' && bxroot_translate_path != NULL &&
            bxroot_translate_path(pp, tbuf, sizeof(tbuf)) > 0)
            aa1 = (long)(uintptr_t)tbuf;
        rr = sx_sc6(nr, a0, aa1, a2, a3, a4, a5);
        return sx_readlinkat_fixup(rr, (char *)(uintptr_t)a2, (unsigned long)a3);
    }
    if (nr == 17)
        return sx_getcwd_fixup(sx_sc6(nr, a0, a1, a2, a3, a4, a5),
                               (char *)(uintptr_t)a0, (unsigned long)a1);
    if (mask == 0 || bxroot_translate_path == NULL)
        return sx_sc6(nr, a0, a1, a2, a3, a4, a5);

    a[0] = a0; a[1] = a1; a[2] = a2; a[3] = a3; a[4] = a4; a[5] = a5;
    for (i = 0; i < 4; i++) {
        const char *p;

        if (!(mask & (1u << i)))
            continue;
        p = (const char *)(uintptr_t)a[i];
        if (p == NULL || p[0] != '/' || used >= 2)
            continue;               /* NULL / 相对路径：内核按 dirfd、cwd 解析 */
        if (sx_is_self_lib(p))
            continue;               /* 本 runtime 的内核视角路径（LD_PRELOAD），见 sx_self_lib */
        if (bxroot_translate_path(p, buf[used], sizeof(buf[used])) > 0)
            a[i] = (long)(uintptr_t)buf[used++];
    }

    {
        long r = sx_sc6(nr, a[0], a[1], a[2], a[3], a[4], a[5]);

        /* openat：与 livepatch 的 relay 同一条「绝对符号链接重试」腿 */
        if (nr == 56 && r == -ENOENT && bxroot_resolve_abs_symlink != NULL &&
            (mask & (1u << 1)) && a[1] != a1) {
            static char sbuf[SX_PATHBUF];

            if (bxroot_resolve_abs_symlink((const char *)(uintptr_t)a[1],
                                           sbuf, sizeof(sbuf)))
                return sx_sc6(nr, -100, (long)(uintptr_t)sbuf, a[2], a[3], 0, 0);
        }
        return r;
    }
}

/*
 * 汇编跳板。入口约定：x16 = 返回地址（站点+4），x17 = 本跳板地址（已被 veneer 用掉）。
 * 栈帧 304 字节：
 *   [0]   x29,x30    [16] x1..x17 (17 个 → 到 152)   [152] 静态 TPIDR
 *   [160] q0..q7 (128 字节 → 288)                     [288..304) 对齐
 */
extern void px_static_tramp(void);
/*
 * 入口约定：x16 = 返回地址（站点+4），x17 = 本跳板地址（已被 veneer 用掉）。
 * 栈帧 688 字节（16 对齐）：
 *   [0]   x29,x30     [16] x1..x17 (17 个 → 152)     [152] 静态 TPIDR_EL0
 *   [160] NZCV        [176] q0..q31 (512 字节 → 688)
 *
 * ★ 已知偏差（如实）：真 syscall 保留 x16/x17，这里不保留 ★
 *   返回时 x16=站点+4，x17=&px_static_tramp。AArch64 没有不占寄存器的间接
 *   跳转，返回路径至少要一个寄存器放地址，故无法在这个设计里同时还原两者。
 *   依据是 x16/x17 是 IP0/IP1：编译器只在 PLT/veneer 里用，不会让它们跨
 *   内联 svc 存活。离线扫描 ldconfig.real 等 75 个补丁站点，svc 之后到
 *   x16/x17 被重写前读取它们的次数为 0。这是文档化的假设，不是无条件保证。
 *
 * v0-v31 与 NZCV 则完整保存：C 的 dispatch 可以随意破坏它们，而真 syscall 不会。
 */
#if defined(__aarch64__)
__asm__(
    ".text\n"
    ".globl px_static_tramp\n"
    ".hidden px_static_tramp\n"
    ".type  px_static_tramp,%function\n"
    "px_static_tramp:\n"
    "    bti  c\n"
    "    sub  sp, sp, #688\n"
    "    stp  x29, x30, [sp, #0]\n"
    "    mov  x29, sp\n"
    "    stp  x1,  x2,  [sp, #16]\n"
    "    stp  x3,  x4,  [sp, #32]\n"
    "    stp  x5,  x6,  [sp, #48]\n"
    "    stp  x7,  x8,  [sp, #64]\n"
    "    stp  x9,  x10, [sp, #80]\n"
    "    stp  x11, x12, [sp, #96]\n"
    "    stp  x13, x14, [sp, #112]\n"
    "    stp  x15, x16, [sp, #128]\n"
    "    str  x17,      [sp, #144]\n"
    "    str  x18,      [sp, #168]\n"           /* x18：GCC 当普通临时寄存器用，内核跨 svc 保留它 */
    "    mrs  x9,  nzcv\n"
    "    str  x9,       [sp, #160]\n"
    "    stp  q0,  q1,  [sp, #176]\n"
    "    stp  q2,  q3,  [sp, #208]\n"
    "    stp  q4,  q5,  [sp, #240]\n"
    "    stp  q6,  q7,  [sp, #272]\n"
    "    stp  q8,  q9,  [sp, #304]\n"
    "    stp  q10, q11, [sp, #336]\n"
    "    stp  q12, q13, [sp, #368]\n"
    "    stp  q14, q15, [sp, #400]\n"
    "    stp  q16, q17, [sp, #432]\n"
    "    stp  q18, q19, [sp, #464]\n"
    "    stp  q20, q21, [sp, #496]\n"
    "    stp  q22, q23, [sp, #528]\n"
    "    stp  q24, q25, [sp, #560]\n"
    "    stp  q26, q27, [sp, #592]\n"
    "    stp  q28, q29, [sp, #624]\n"
    "    stp  q30, q31, [sp, #656]\n"
    "    mrs  x9, tpidr_el0\n"
    "    str  x9, [sp, #152]\n"
    "    adrp x10, px_static_dyn_tls\n"
    "    ldr  x10, [x10, :lo12:px_static_dyn_tls]\n"
    "    msr  tpidr_el0, x10\n"
    "    mov  x6, x8\n"                          /* 第 7 参 = syscall 号；x0..x5 原样 */
    "    bl   px_static_dispatch\n"
    "    ldr  x9, [sp, #152]\n"
    "    msr  tpidr_el0, x9\n"
    "    ldp  q30, q31, [sp, #656]\n"
    "    ldp  q28, q29, [sp, #624]\n"
    "    ldp  q26, q27, [sp, #592]\n"
    "    ldp  q24, q25, [sp, #560]\n"
    "    ldp  q22, q23, [sp, #528]\n"
    "    ldp  q20, q21, [sp, #496]\n"
    "    ldp  q18, q19, [sp, #464]\n"
    "    ldp  q16, q17, [sp, #432]\n"
    "    ldp  q14, q15, [sp, #400]\n"
    "    ldp  q12, q13, [sp, #368]\n"
    "    ldp  q10, q11, [sp, #336]\n"
    "    ldp  q8,  q9,  [sp, #304]\n"
    "    ldp  q6,  q7,  [sp, #272]\n"
    "    ldp  q4,  q5,  [sp, #240]\n"
    "    ldp  q2,  q3,  [sp, #208]\n"
    "    ldp  q0,  q1,  [sp, #176]\n"
    "    ldr  x9,       [sp, #160]\n"
    "    msr  nzcv, x9\n"
    "    ldp  x1,  x2,  [sp, #16]\n"
    "    ldp  x3,  x4,  [sp, #32]\n"
    "    ldp  x5,  x6,  [sp, #48]\n"
    "    ldp  x7,  x8,  [sp, #64]\n"
    "    ldp  x9,  x10, [sp, #80]\n"
    "    ldp  x11, x12, [sp, #96]\n"
    "    ldp  x13, x14, [sp, #112]\n"
    "    ldr  x15,      [sp, #128]\n"
    "    ldr  x16,      [sp, #136]\n"            /* 返回地址 */
    "    ldr  x17,      [sp, #144]\n"
    "    ldr  x18,      [sp, #168]\n"
    "    ldp  x29, x30, [sp, #0]\n"
    "    add  sp, sp, #688\n"
    "    br   x16\n"                              /* x0 = 结果，回站点下一条 */
    ".size px_static_tramp, .-px_static_tramp\n"
);
#endif

/*
 * ★ 动态进程用的跳板（2026-10-31，D1）★
 *
 * 与 px_static_tramp 同一帧布局与保存集（x1..x18、NZCV、q0..q31），唯一区别：
 * **不切 TPIDR_EL0**。动态进程里主程序 / 其它 .so 与 runtime 共用同一份 libc
 * TLS，px_static_dyn_tls 也没被设置过（那是 static_exec 跳转前才记的），
 * 切了反而会把 TLS 指到 0。
 */
extern void px_inline_tramp(void);
#if defined(__aarch64__)
__asm__(
    ".text\n"
    ".globl px_inline_tramp\n"
    ".hidden px_inline_tramp\n"
    ".type  px_inline_tramp,%function\n"
    "px_inline_tramp:\n"
    "    bti  c\n"
    "    sub  sp, sp, #688\n"
    "    stp  x29, x30, [sp, #0]\n"
    "    mov  x29, sp\n"
    "    stp  x1,  x2,  [sp, #16]\n"
    "    stp  x3,  x4,  [sp, #32]\n"
    "    stp  x5,  x6,  [sp, #48]\n"
    "    stp  x7,  x8,  [sp, #64]\n"
    "    stp  x9,  x10, [sp, #80]\n"
    "    stp  x11, x12, [sp, #96]\n"
    "    stp  x13, x14, [sp, #112]\n"
    "    stp  x15, x16, [sp, #128]\n"
    "    str  x17,      [sp, #144]\n"
    "    str  x18,      [sp, #168]\n"           /* x18：GCC 当普通临时寄存器用，内核跨 svc 保留它 */
    "    mrs  x9,  nzcv\n"
    "    str  x9,       [sp, #160]\n"
    "    stp  q0,  q1,  [sp, #176]\n"
    "    stp  q2,  q3,  [sp, #208]\n"
    "    stp  q4,  q5,  [sp, #240]\n"
    "    stp  q6,  q7,  [sp, #272]\n"
    "    stp  q8,  q9,  [sp, #304]\n"
    "    stp  q10, q11, [sp, #336]\n"
    "    stp  q12, q13, [sp, #368]\n"
    "    stp  q14, q15, [sp, #400]\n"
    "    stp  q16, q17, [sp, #432]\n"
    "    stp  q18, q19, [sp, #464]\n"
    "    stp  q20, q21, [sp, #496]\n"
    "    stp  q22, q23, [sp, #528]\n"
    "    stp  q24, q25, [sp, #560]\n"
    "    stp  q26, q27, [sp, #592]\n"
    "    stp  q28, q29, [sp, #624]\n"
    "    stp  q30, q31, [sp, #656]\n"
    "    mov  x6, x8\n"
    "    bl   px_static_dispatch\n"
    "    ldp  q30, q31, [sp, #656]\n"
    "    ldp  q28, q29, [sp, #624]\n"
    "    ldp  q26, q27, [sp, #592]\n"
    "    ldp  q24, q25, [sp, #560]\n"
    "    ldp  q22, q23, [sp, #528]\n"
    "    ldp  q20, q21, [sp, #496]\n"
    "    ldp  q18, q19, [sp, #464]\n"
    "    ldp  q16, q17, [sp, #432]\n"
    "    ldp  q14, q15, [sp, #400]\n"
    "    ldp  q12, q13, [sp, #368]\n"
    "    ldp  q10, q11, [sp, #336]\n"
    "    ldp  q8,  q9,  [sp, #304]\n"
    "    ldp  q6,  q7,  [sp, #272]\n"
    "    ldp  q4,  q5,  [sp, #240]\n"
    "    ldp  q2,  q3,  [sp, #208]\n"
    "    ldp  q0,  q1,  [sp, #176]\n"
    "    ldr  x9,       [sp, #160]\n"
    "    msr  nzcv, x9\n"
    "    ldp  x1,  x2,  [sp, #16]\n"
    "    ldp  x3,  x4,  [sp, #32]\n"
    "    ldp  x5,  x6,  [sp, #48]\n"
    "    ldp  x7,  x8,  [sp, #64]\n"
    "    ldp  x9,  x10, [sp, #80]\n"
    "    ldp  x11, x12, [sp, #96]\n"
    "    ldp  x13, x14, [sp, #112]\n"
    "    ldr  x15,      [sp, #128]\n"
    "    ldr  x16,      [sp, #136]\n"
    "    ldr  x17,      [sp, #144]\n"
    "    ldr  x18,      [sp, #168]\n"
    "    ldp  x29, x30, [sp, #0]\n"
    "    add  sp, sp, #688\n"
    "    br   x16\n"
    ".size px_inline_tramp, .-px_inline_tramp\n"
);
#endif

/*
 * ★ 「野」svc 站点的前置桩（BXROOT_SVC_ALL=1，2026-11-02 实验）★
 *
 * 站点的调用号不是 `movz x8,#imm`（Go 的 syscall.Syscall6、号经寄存器传入等），
 * 扫描期认不出号，原先整点放过 → 路径以 guest 视角直达内核。
 * 现在这类点也改成 `b veneer`；号在运行时读 x8，px_static_dispatch 对不关心的
 * 号原样转发（mask==0 → sx_sc6），所以语义不变，只多一次跳板往返。
 *
 * 但有几个号**不能**进跳板（跳板要建 688 字节栈帧并从原栈返回）：
 *   clone(220)/clone3(435)  子线程/子进程在新栈上返回，原栈帧不存在
 *   rt_sigreturn(139)       不返回，由内核恢复整套上下文
 *   exit(93)/exit_group(94) 不返回
 * 这五个在建帧之前直接发真 svc，再 `br x16` 回站点下一条。
 * 判断用 sub+cbz，不碰 NZCV（内核跨 svc 保留 NZCV，不能被我们改掉）。
 * 入口约定同 veneer：x16 = 返回地址，x17 = 可随意使用。
 */
#if defined(__aarch64__)
__asm__(
    ".text\n"
    ".macro PX_WILD_PRE name, tramp\n"
    ".globl \\name\n"
    ".hidden \\name\n"
    ".type  \\name,%function\n"
    "\\name:\n"
    "    bti  c\n"
    "    sub  x17, x8, #220\n"
    "    cbz  x17, 1f\n"
    "    sub  x17, x8, #435\n"
    "    cbz  x17, 1f\n"
    "    sub  x17, x8, #139\n"
    "    cbz  x17, 1f\n"
    "    sub  x17, x8, #93\n"
    "    cbz  x17, 1f\n"
    "    sub  x17, x8, #94\n"
    "    cbz  x17, 1f\n"
    "    b    \\tramp\n"
    "1:  svc  #0\n"
    "    br   x16\n"
    ".size \\name, .-\\name\n"
    ".endm\n"
    "PX_WILD_PRE px_wild_pre_static, px_static_tramp\n"
    "PX_WILD_PRE px_wild_pre_inline, px_inline_tramp\n"
);
extern void px_wild_pre_static(void);
extern void px_wild_pre_inline(void);
#endif

/* ------------------------------------------------------------------ */
/* ELF 装载                                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    unsigned long base;
    unsigned long entry;
    unsigned long phdr;
    unsigned phnum;
    unsigned long lo, hi;           /* 装载范围（已加 base） */
    Elf64_Phdr ph[SX_MAX_PHDR];
    unsigned nph;
    unsigned long veneer_pool;      /* 预留的 veneer 区（紧邻镜像） */
    size_t veneer_cap;
    unsigned long rsv_base, rsv_len;  /* 实际 mmap 保留区（含 ET_DYN 对齐余量） */
} sx_image;


static void sx_unload(sx_image *img)
{
    if (img == NULL || img->rsv_len == 0)
        return;
    (void)sx_sc6(SYS_munmap, (long)img->rsv_base, (long)img->rsv_len, 0, 0, 0, 0);
    img->rsv_base = img->rsv_len = 0;
    img->lo = img->hi = 0;
}

static int sx_load(const char *path, sx_image *img, size_t veneer_bytes)
{
    Elf64_Ehdr eh;
    unsigned long lo = ~0UL, hi = 0, align = 4096;
    unsigned long ps = (unsigned long)getpagesize();
    unsigned long fsize = 0;
    unsigned nload = 0;
    int entry_ok = 0;
    long fd;
    unsigned i;
    char *res;
    size_t vz = (veneer_bytes + ps - 1) & ~(ps - 1);
    struct stat fst;

    memset(img, 0, sizeof(*img));
    fd = SC(SYS_openat, -100, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) { errno = (int)-fd; return -1; }
    if (sx_sc6(SYS_fstat, fd, (long)&fst, 0, 0, 0, 0) != 0) {
        SC(SYS_close, fd, 0, 0, 0);
        errno = EIO;
        return -1;
    }
    fsize = (unsigned long)fst.st_size;
    if (sx_sc6(SYS_pread64, fd, (long)&eh, sizeof eh, 0, 0, 0) != (long)sizeof eh ||
        memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 || eh.e_ident[EI_CLASS] != ELFCLASS64 ||
        eh.e_machine != EM_AARCH64 || (eh.e_type != ET_DYN && eh.e_type != ET_EXEC) ||
        eh.e_phentsize != sizeof(Elf64_Phdr) || eh.e_phnum == 0 || eh.e_phnum > SX_MAX_PHDR ||
        sx_sc6(SYS_pread64, fd, (long)img->ph, sizeof(Elf64_Phdr) * eh.e_phnum,
               (long)eh.e_phoff, 0, 0) != (long)(sizeof(Elf64_Phdr) * eh.e_phnum)) {
        SC(SYS_close, fd, 0, 0, 0);
        errno = ENOEXEC;
        return -1;
    }
    img->nph = eh.e_phnum;
    for (i = 0; i < eh.e_phnum; i++) {
        Elf64_Phdr *p = &img->ph[i];

        if (p->p_type == PT_INTERP) {
            SC(SYS_close, fd, 0, 0, 0);
            errno = ENOEXEC;
            return -1;
        }
        if (p->p_type != PT_LOAD)
            continue;
        /*
         * 坏/恶意 ELF 一律在这里（任何映射、任何进程状态改动之前）拒绝，
         * 调用方据此安全回退 stub-loader。内核对这些同样返回 ENOEXEC。
         */
        if (p->p_filesz > p->p_memsz ||                       /* 文件映射越过保留区 */
            p->p_vaddr + p->p_memsz < p->p_vaddr ||          /* 回绕 */
            p->p_offset + p->p_filesz < p->p_offset ||
            p->p_offset + p->p_filesz > fsize ||              /* 截断文件 → SIGBUS */
            (p->p_align != 0 && (p->p_align & (p->p_align - 1)) != 0) ||  /* 非 2 的幂 */
            p->p_align > (1UL << 30) ||                      /* 防 hi-lo+align 回绕 */
            (p->p_align > 1 && (p->p_vaddr % p->p_align) != (p->p_offset % p->p_align))) {
            SC(SYS_close, fd, 0, 0, 0);
            errno = ENOEXEC;
            return -1;
        }
        if (p->p_align > align)
            align = p->p_align;
        if ((p->p_vaddr & ~(ps - 1)) < lo)
            lo = p->p_vaddr & ~(ps - 1);
        if (p->p_vaddr + p->p_memsz > hi)
            hi = p->p_vaddr + p->p_memsz;
        nload++;
        if (p->p_flags & PF_X)
            if (eh.e_entry >= p->p_vaddr && eh.e_entry < p->p_vaddr + p->p_memsz)
                entry_ok = 1;                                  /* e_entry 落在可执行段内 */
    }
    if (nload == 0 || hi <= lo || hi + ps < hi || !entry_ok) {
        SC(SYS_close, fd, 0, 0, 0);
        errno = ENOEXEC;
        return -1;
    }
    hi = (hi + ps - 1) & ~(ps - 1);
    if (hi <= lo || hi - lo + vz + align < hi - lo) {           /* 向上取整后再查一次回绕 */
        SC(SYS_close, fd, 0, 0, 0);
        errno = ENOEXEC;
        return -1;
    }

    /* 镜像 + 紧随其后的 veneer 区一起保留，保证 B 可达（±128MB） */
    if (eh.e_type == ET_EXEC) {
        res = (char *)sx_sc6(SYS_mmap, (long)lo, (long)(hi - lo + vz), PROT_NONE,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                             -1, 0);
        if ((unsigned long)res >= (unsigned long)-4095L) {
            SC(SYS_close, fd, 0, 0, 0);
            errno = (int)-(long)res;
            return -1;
        }
        if ((unsigned long)res != lo) {             /* 旧内核把 flag 当 hint：没落在要求的地址 */
            (void)sx_sc6(SYS_munmap, (long)res, (long)(hi - lo + vz), 0, 0, 0, 0);
            SC(SYS_close, fd, 0, 0, 0);
            errno = EEXIST;
            return -1;
        }
        img->base = 0;
        img->rsv_base = lo;
        img->rsv_len  = hi - lo + vz;
    } else {
        res = (char *)sx_sc6(SYS_mmap, 0, (long)(hi - lo + vz + align), PROT_NONE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if ((unsigned long)res >= (unsigned long)-4095L) {
            SC(SYS_close, fd, 0, 0, 0);
            errno = (int)-(long)res;
            return -1;
        }
        img->base = (((unsigned long)res + align - 1) & ~(align - 1)) - lo;
        img->rsv_base = (unsigned long)res;
        img->rsv_len  = hi - lo + vz + align;
    }
    img->lo = img->base + lo;
    img->hi = img->base + hi;
    img->veneer_pool = img->hi;
    img->veneer_cap = vz;

    for (i = 0; i < eh.e_phnum; i++) {
        Elf64_Phdr *p = &img->ph[i];
        unsigned long va, off, a, d, fe, fpe, me;
        int prot;

        if (p->p_type != PT_LOAD)
            continue;
        va = p->p_vaddr;
        off = p->p_offset;
        a = va & ~(ps - 1);
        d = va - a;
        prot = ((p->p_flags & PF_R) ? PROT_READ : 0) |
               ((p->p_flags & PF_W) ? PROT_WRITE : 0) |
               ((p->p_flags & PF_X) ? PROT_EXEC : 0);
        if (p->p_filesz > 0) {
            long m = sx_sc6(SYS_mmap, (long)(img->base + a), (long)(p->p_filesz + d),
                            prot, MAP_PRIVATE | MAP_FIXED, fd, (long)(off - d));
            if ((unsigned long)m >= (unsigned long)-4095L) {
                SC(SYS_close, fd, 0, 0, 0);
                errno = (int)-m;
                return -1;
            }
        }
        fe = va + p->p_filesz;
        fpe = (fe + ps - 1) & ~(ps - 1);
        me = va + p->p_memsz;
        if (p->p_memsz > p->p_filesz) {
            if (p->p_filesz > 0 && fpe > fe) {
                unsigned long pg = img->base + (fe & ~(ps - 1));
                if (!(prot & PROT_WRITE)) {
                    long pr = SC(SYS_mprotect, pg, ps, prot | PROT_WRITE, 0);
                    if (pr != 0) {
                        SC(SYS_close, fd, 0, 0, 0);
                        errno = (int)-pr;
                        return -1;
                    }
                }
                memset((void *)(img->base + fe), 0, fpe - fe);
                if (!(prot & PROT_WRITE))
                    SC(SYS_mprotect, pg, ps, prot, 0);
            }
            if (me > fpe) {
                unsigned long s = p->p_filesz > 0 ? fpe : a;
                long m = sx_sc6(SYS_mmap, (long)(img->base + s), (long)(me - s), prot,
                                MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
                if ((unsigned long)m >= (unsigned long)-4095L) {
                    SC(SYS_close, fd, 0, 0, 0);
                    errno = (int)-m;
                    return -1;
                }
            }
        }
        if (eh.e_phoff >= off && eh.e_phoff + sizeof(Elf64_Phdr) * eh.e_phnum <= off + p->p_filesz)
            img->phdr = img->base + va + (eh.e_phoff - off);
    }
    SC(SYS_close, fd, 0, 0, 0);
    img->entry = img->base + eh.e_entry;
    img->phnum = eh.e_phnum;
    return 0;
}

/* ------------------------------------------------------------------ */
/* 站点扫描与改写                                                       */
/* ------------------------------------------------------------------ */

/*
 * 对 Rd=8 的写都算屏障（而不只是 movk）。Rd 在 bit[4:0]。
 * 粗粒度判据：任何「数据处理立即数 / 寄存器 / 加载」类指令，Rd==8 即清掉 nr。
 * 误清的代价只是少补一个站点（fail-open 到原 svc，路径泄漏可被 B 类回归发现），
 * 误留的代价是把别的 syscall 当成路径类，所以宁可多清。
 */
static int sx_writes_x8(uint32_t ins)
{
    if ((ins & 0x1fu) != 8u)
        return 0;
    /* 排除不写 Rd 的：STR/STP 的 bit[4:0] 是 Rt（源），比较/测试类 Rd=XZR 不会是 8 */
    if ((ins & 0x3f000000u) == 0x39000000u) return 0;  /* STR/STRB/STRH imm (unsigned offset) */
    if ((ins & 0x3f200c00u) == 0x38000000u) return 0;  /* STUR 族 */
    if ((ins & 0x3fc00000u) == 0x29000000u) return 0;  /* STP (signed offset) */
    if ((ins & 0x3fc00000u) == 0x28800000u) return 0;  /* STP (post-index) */
    if ((ins & 0x3fc00000u) == 0x29800000u) return 0;  /* STP (pre-index) */
    return 1;
}

static int sx_is_barrier(uint32_t ins)
{
    if (sx_writes_x8(ins)) return 1;                    /* 任何对 x8/w8 的写 */
    if ((ins >> 26) == 0x05u || (ins >> 26) == 0x25u) return 1;   /* B / BL */
    if ((ins >> 24) == 0x54u) return 1;                 /* B.cond */
    if ((ins & 0x7e000000u) == 0x34000000u) return 1;   /* CBZ/CBNZ */
    if ((ins & 0x7e000000u) == 0x36000000u) return 1;   /* TBZ/TBNZ */
    if ((ins & 0xfe000000u) == 0xd6000000u) return 1;   /* BR/BLR/RET */
    return 0;
}

/* movz x8/w8, #imm16（hw=0）→ 返回 imm16，否则 -1 */
static long sx_movz_x8(uint32_t ins)
{
    if ((ins & 0xffe0001fu) == 0xd2800008u || (ins & 0xffe0001fu) == 0x52800008u)
        return (long)((ins >> 5) & 0xffffu);
    return -1;
}

/*
 * 扫描 [lo,hi)。pool 为 NULL 时只计数；否则写 veneer 并改写站点。
 * 返回站点数。
 */
/*
 * veneer 的跳转目标。静态映像用 px_static_tramp（要切 TLS）；
 * 动态进程的内联 svc 扫描（bxroot_inline_svc_scan）临时换成 px_inline_tramp。
 */
#if defined(__aarch64__)
static void (*sx_scan_tramp)(void) = px_static_tramp;
#endif

/* BXROOT_SVC_ALL=1：连号不明的 svc 站点也改写（实验，默认关）。 */
static int sx_svc_all(void)
{
    static int cached = -1;

    if (cached < 0) {
        const char *e = getenv("BXROOT_SVC_ALL");
        cached = (e != NULL && e[0] == '1') ? 1 : 0;
    }
    return cached;
}

static size_t sx_scan(uint32_t *code, size_t n, uint32_t *pool, size_t pool_cap_bytes)
{
    long nr = -1;
    unsigned since = 0;
    size_t j, total = 0;

    for (j = 0; j < n; j++) {
        uint32_t ins = code[j];
        long m;

        if (ins == SX_SVC_INSN) {
            /* 号已知且不关心（read/write/mmap…）→ 放过；号未知 + 野站点模式 → 也改 */
            if ((nr >= 0 && sx_wants_site(nr)) || (nr < 0 && sx_svc_all())) {
                int wild = nr < 0;
                if (pool != NULL) {
                    uint32_t *v = pool + total * (SX_VENEER_SIZE / 4);
                    long off;

                    if ((total + 1) * SX_VENEER_SIZE > pool_cap_bytes)
                        return total;           /* 容量不足：fail-open，不再补 */
                    off = (long)((intptr_t)v - (intptr_t)&code[j]);
                    if (off >= (1L << 27) || off < -(1L << 27)) {
                        nr = -1;
                        continue;               /* 够不着：跳过该点 */
                    }
                    v[0] = 0x58000090u;         /* ldr x16, #16 */
                    v[1] = 0x580000b1u;         /* ldr x17, #20 */
                    v[2] = 0xd61f0220u;         /* br  x17 */
                    v[3] = 0xd503201fu;         /* nop */
                    *(uint64_t *)(void *)&v[4] = (uint64_t)(uintptr_t)&code[j + 1];
#if defined(__aarch64__)
                    *(uint64_t *)(void *)&v[6] = wild
                        ? (sx_scan_tramp == px_inline_tramp
                               ? (uint64_t)(uintptr_t)px_wild_pre_inline
                               : (uint64_t)(uintptr_t)px_wild_pre_static)
                        : (uint64_t)(uintptr_t)sx_scan_tramp;
#else
                    /* px_static_tramp is AArch64-only (see its #if). */
                    (void)v;
                    return -1;
#endif
                    code[j] = 0x14000000u | ((uint32_t)(off >> 2) & 0x03ffffffu);  /* b v */
                }
                total++;
            }
            nr = -1;
            continue;
        }
        m = sx_movz_x8(ins);
        if (m >= 0) {
            nr = m;
            since = 0;
            continue;
        }
        if (nr >= 0 && (sx_is_barrier(ins) || ++since > SX_SCAN_WINDOW))
            nr = -1;
    }
    return total;
}

static size_t sx_count_sites(const sx_image *img)
{
    size_t total = 0;
    unsigned i;

    for (i = 0; i < img->nph; i++) {
        const Elf64_Phdr *p = &img->ph[i];

        if (p->p_type != PT_LOAD || !(p->p_flags & PF_X))
            continue;
        total += sx_scan((uint32_t *)(img->base + p->p_vaddr), p->p_filesz / 4, NULL, 0);
    }
    return total;
}

/* ------------------------------------------------------------------ */
/* 动态进程：主程序与非 libc 共享库里的内联 svc（D1，2026-10-31）       */
/* ------------------------------------------------------------------ */
/*
 * 【缺口】动态程序只靠 LD_PRELOAD 符号钩子翻译路径。程序**绕过 libc**、
 * 自己 `mov x8,#56 ; svc #0` 发 openat 时，不经任何导出符号，路径以 guest
 * 视角直达内核 → ENOENT（真机复现：同一份探针静态编译返回 fd，动态编译
 * 返回 -2）。静态程序没有这个问题，因为 static_exec 早就改写了这类站点。
 *
 * 【做法】在 runtime 构造函数里，对本进程**文件映射的 r-x 段**跑与静态
 * 程序同一套站点识别（sx_scan：`mov x8,#立即数` 近距离跟 `svc`，号在
 * sx_wants_site 的路径类 / getcwd / execve 集合里），站点改成
 * `b veneer → px_inline_tramp → px_static_dispatch`。
 *
 * 【刻意不碰的映像】
 *   - libc.so.6：runtime 自己的钩子会**有意**用宿主路径调 libc（host-world
 *     等），libc 内部 svc 全改会把这些宿主路径误翻进 rootfs。libc 这条边界
 *     继续由符号钩子 + livepatch 的 openat relay 负责。
 *   - ld-linux*：在 runtime 之前就跑完了加载，dlopen 的路径由 dl 钩子翻译。
 *   - libbxroot* / libproroot* / libdsha-*：本项目与外层容器的组件，里面的
 *     裸 svc 是有意为之。
 *   - 单段 > 64 MB：扫描成本与误配面都随代码量增长，大映像（如 node）
 *     本身走 libc，不扫。
 *
 * 【安全边界】与静态程序同：只认确定形态、改写前逐字节校验、veneer 够不着
 * 的站点跳过（fail-open）。先只读计数，0 命中的映像不改任何内存属性。
 *
 * 【仍覆盖不到】号来自寄存器的通用包装（Go 的 syscall.Syscall6 等）；
 * 构造函数之后才 dlopen 进来的库。
 *
 * BXROOT_NO_INLINE_SVC=1 关闭。返回改写的站点总数。
 */
#define SX_INLINE_MAX_SEG   (64UL << 20)
#define SX_INLINE_MAX_SEGS  64

static int sx_inline_excluded(const char *path)
{
    static const char *const skip[] = {
        "/libc.so.6", "/ld-linux", "/libbxroot", "libproroot", "/libdsha-",
    };
    size_t i;

    for (i = 0; i < sizeof(skip) / sizeof(skip[0]); i++)
        if (strstr(path, skip[i]) != NULL)
            return 1;
    return 0;
}

/* 在 [lo,hi) 附近找一块未占用的地址放 veneer 池，保证 `b`（±128MB）够得着。 */
static unsigned long sx_inline_pool_near(unsigned long lo, unsigned long hi, size_t cap)
{
    unsigned long ps = (unsigned long)getpagesize();
    unsigned long step = 2UL << 20;
    int k;

    for (k = 0; k < 48; k++) {
        unsigned long cand[2];
        int j;

        cand[0] = ((hi + ps - 1) & ~(ps - 1)) + (unsigned long)k * step;
        cand[1] = (lo > cap + (unsigned long)(k + 1) * step)
                      ? ((lo - cap) & ~(ps - 1)) - (unsigned long)k * step : 0;
        for (j = 0; j < 2; j++) {
            long m;

            if (cand[j] == 0)
                continue;
            m = sx_sc6(SYS_mmap, (long)cand[j], (long)cap, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
            if ((unsigned long)m >= (unsigned long)-4095L)
                continue;
            if ((unsigned long)m != cand[j]) {      /* 旧内核把 flag 当提示 */
                (void)sx_sc6(SYS_munmap, m, (long)cap, 0, 0, 0, 0);
                continue;
            }
            return (unsigned long)m;
        }
    }
    return 0;
}

int bxroot_inline_svc_scan(void)
{
#if defined(__aarch64__)
    struct { unsigned long lo, hi; char path[256]; } seg[SX_INLINE_MAX_SEGS];
    int nseg = 0, i, total = 0;
    unsigned long ps = (unsigned long)getpagesize();
    const char *v = getenv("BXROOT_VERBOSE");
    int verbose = (v != NULL && v[0] != '\0' && v[0] != '0');
    char line[1024];
    FILE *f;

    if (getenv("BXROOT_NO_INLINE_SVC") != NULL)
        return 0;
    f = fopen("/proc/self/maps", "re");
    if (f == NULL)
        return 0;
    while (nseg < SX_INLINE_MAX_SEGS && fgets(line, sizeof line, f) != NULL) {
        unsigned long a, b, off;
        char perms[8];
        int pos = 0;
        const char *p;
        size_t pl;

        if (sscanf(line, "%lx-%lx %7s %lx %*s %*s %n", &a, &b, perms, &off, &pos) < 4 || pos == 0)
            continue;
        if (perms[0] != 'r' || perms[2] != 'x' || b <= a || b - a > SX_INLINE_MAX_SEG)
            continue;
        p = line + pos;
        if (p[0] != '/')
            continue;                       /* 匿名 / [vdso] / JIT：不碰 */
        pl = strcspn(p, "\n");
        if (pl >= sizeof(seg[0].path) || sx_inline_excluded(p))
            continue;
        seg[nseg].lo = a;
        seg[nseg].hi = b;
        memcpy(seg[nseg].path, p, pl);
        seg[nseg].path[pl] = '\0';
        nseg++;
    }
    fclose(f);

    sx_scan_tramp = px_inline_tramp;
    for (i = 0; i < nseg; i++) {
        uint32_t *code = (uint32_t *)seg[i].lo;
        size_t words = (seg[i].hi - seg[i].lo) / 4;
        size_t want = sx_scan(code, words, NULL, 0), got;
        size_t cap;
        unsigned long pool;
        long pr;

        if (want == 0)
            continue;
        cap = (want * SX_VENEER_SIZE + ps - 1) & ~(ps - 1);
        pool = sx_inline_pool_near(seg[i].lo, seg[i].hi, cap);
        if (pool == 0)
            continue;                       /* 够不着：fail-open */
        pr = SC(SYS_mprotect, seg[i].lo, seg[i].hi - seg[i].lo,
                PROT_READ | PROT_WRITE | PROT_EXEC, 0);
        if (pr != 0)
            pr = SC(SYS_mprotect, seg[i].lo, seg[i].hi - seg[i].lo, PROT_READ | PROT_WRITE, 0);
        if (pr != 0) {
            (void)sx_sc6(SYS_munmap, (long)pool, (long)cap, 0, 0, 0, 0);
            continue;
        }
        got = sx_scan(code, words, (uint32_t *)pool, cap);
        SC(SYS_mprotect, seg[i].lo, seg[i].hi - seg[i].lo, PROT_READ | PROT_EXEC, 0);
        __builtin___clear_cache((char *)seg[i].lo, (char *)seg[i].hi);
        SC(SYS_mprotect, pool, cap, PROT_READ | PROT_EXEC, 0);
        __builtin___clear_cache((char *)pool, (char *)(pool + cap));
        total += (int)got;
        if (verbose && bxroot_log != NULL)
            bxroot_log("inline-svc: %s 补丁 %zu 个路径 svc 站点", seg[i].path, got);
    }
    sx_scan_tramp = px_static_tramp;
    return total;
#else
    return 0;
#endif
}

/* ------------------------------------------------------------------ */
/* early SIGSYS 处理器（不碰 TLS，与 ldr/early_sigsys.h 同）              */
/* ------------------------------------------------------------------ */

static void sx_early_sigsys(int s, void *si, void *uc)
{
    unsigned long long *regs;
    long result = -38;
    long nr;
    (void)s;
    if (si == NULL || uc == NULL || ((int *)si)[2] != 1)
        return;
    /* AArch64 kernel signal ABI: mcontext.regs starts at byte 184.
     * x8 retains the trapped syscall number; x0 is the return register.
     * Do not call the dynamic full handler: guest TLS may not be initialized. */
    regs = (unsigned long long *)((char *)uc + 184);
    nr = (long)regs[8];
    if (nr >= 194 && nr <= 197 && bxroot_sysvshm_emulate != NULL)
        (void)bxroot_sysvshm_emulate(nr, regs[0], regs[1], regs[2], &result);
    regs[0] = (unsigned long)result;
}

struct sx_ksigaction {
    unsigned long handler;
    unsigned long flags;
    unsigned long restorer;
    unsigned long mask;
};

/* seccomp 兜底层（默认关；BXROOT_SECCOMP_FALLBACK=1）。见该文件头。 */
#include "seccomp_fallback.c"

/* 本次 exec 是否启用兜底层：按**目标** envp 判定（跳转前设置） */
static int sx_sfb_want;

/* 线程数：读 /proc/self/status 的 Threads: 行。读不到按「多线程」处理。 */
static int sx_thread_count(void)
{
    char buf[4096];
    long fd = SC(SYS_openat, -100, "/proc/self/status", O_RDONLY | O_CLOEXEC, 0);
    long n;
    char *p;

    if (fd < 0)
        return 99;
    n = SC(SYS_read, fd, buf, sizeof(buf) - 1, 0);
    SC(SYS_close, fd, 0, 0, 0);
    if (n <= 0)
        return 99;
    buf[n] = '\0';
    p = strstr(buf, "Threads:");
    return p ? atoi(p + 8) : 99;
}

/* 模拟 execve 对进程状态的重置：信号处理、CLOEXEC 描述符 */
static void sx_reset_process_state(void)
{
    if (bxroot_sysvshm_exec_reset != NULL)
        bxroot_sysvshm_exec_reset();
    struct sx_ksigaction sa;
    int sig, fd;

    for (sig = 1; sig <= 64; sig++) {
        struct sx_ksigaction old;

        if (sig == 9 || sig == 19 || sig == 31)
            continue;
        memset(&old, 0, sizeof old);
        if (SC(SYS_rt_sigaction, sig, 0, &old, 8) != 0)
            continue;
        if (old.handler > 1UL) {                /* 自定义处理器 → 默认（SIG_IGN 保留） */
            memset(&sa, 0, sizeof sa);
            SC(SYS_rt_sigaction, sig, &sa, 0, 8);
        }
    }
#if defined(__aarch64__)
    if (sx_sfb_want && sfb_install_handler() == 0) {
        /* 常驻处理器已装（兼含 sx_early_sigsys 的语义） */
    } else
#endif
    {
        memset(&sa, 0, sizeof sa);
        sa.handler = (unsigned long)(void *)&sx_early_sigsys;
        sa.flags = 4 /* SA_SIGINFO */;
        SC(SYS_rt_sigaction, 31, &sa, 0, 8);
    }
    /*
     * ★ 整体清空信号掩码（缺陷修复，2026-10-18 第五轮）★
     *
     * execve 会**丢弃**调用方的信号掩码（新进程从空集开始）。原写法只
     * SIG_UNBLOCK 了 31（SIGSYS），父进程屏蔽的 SIGUSR1/SIGTERM 等全部
     * 被继承下去：实测经 px_static_exec 启动的 guest 读到
     * SIGUSR1=1 SIGTERM=1，而 shell 直接 exec 的是 0/0；决定性后果是
     * guest 里 raise(SIGTERM) 被挂起、进程**杀不掉**（rc=0），依赖
     * SIGCHLD/超时 kill 的监督逻辑会一起挂住。
     *
     * SIG_SETMASK(=2) 传全零集合等价于 execve 的清空语义，SIGSYS 自然
     * 也在未阻塞集合里，无需再单独 UNBLOCK。
     */
    {
        unsigned long empty_mask[2] = { 0, 0 };

        SC(SYS_rt_sigprocmask, 2 /* SIG_SETMASK */, empty_mask, 0, 8);
    }

    /* execve 会关闭备用信号栈；runtime 的 crash.c 装了 altstack，静态程序不该跑在它上面 */
    {
        struct { void *sp; int flags; unsigned long size; } ss;
        memset(&ss, 0, sizeof ss);
        ss.flags = 2;                               /* SS_DISABLE */
        SC(SYS_sigaltstack, &ss, 0, 0, 0);
    }

    /*
     * 关闭全部 FD_CLOEXEC 描述符，含 fd>=1024（RLIMIT_NOFILE 可到 1M）。
     * 优先 close_range(…, CLOSE_RANGE_CLOEXEC 不适用，这里要「只关带标志的」)：
     * 先按 3..1023 逐个判，再用 close_range 的 UNSHARE 不可用，故对 >=1024 读
     * /proc/self/fd 枚举。
     */
    for (fd = 3; fd < 1024; fd++) {
        long fl = SC(SYS_fcntl, fd, F_GETFD, 0, 0);
        if (fl >= 0 && (fl & FD_CLOEXEC) && !sx_preserve_internal_exec_fd(fd))
            SC(SYS_close, fd, 0, 0, 0);
    }
    {
        char dbuf[2048];
        long dfd = SC(SYS_openat, -100, "/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
        if (dfd >= 0) {
            long n;
            while ((n = SC(SYS_getdents64, dfd, dbuf, sizeof dbuf, 0)) > 0) {
                long off = 0;
                while (off < n) {
                    unsigned short reclen = *(unsigned short *)(void *)(dbuf + off + 16);
                    const char *nm = dbuf + off + 19;
                    long v = 0;
                    int digits = 0;
                    while (*nm >= '0' && *nm <= '9') { v = v * 10 + (*nm - '0'); nm++; digits++; }
                    if (digits && *nm == '\0' && v >= 1024 && v != dfd) {
                        long fl = SC(SYS_fcntl, v, F_GETFD, 0, 0);
                        if (fl >= 0 && (fl & FD_CLOEXEC) && !sx_preserve_internal_exec_fd((int)v))
                            SC(SYS_close, v, 0, 0, 0);
                    }
                    if (reclen == 0) break;
                    off += reclen;
                }
            }
            SC(SYS_close, dfd, 0, 0, 0);
        }
    }
}

/* ------------------------------------------------------------------ */
/* 入口                                                                */
/* ------------------------------------------------------------------ */

/*
 * 只读探测 ET_EXEC 目标的装载范围 [lo, hi)（页对齐），不映射任何东西。
 * 返回 1 = 是 ET_EXEC 且范围有效；0 = 不是 / 读不出（调用方按原逻辑处理）。
 */
static int sx_probe_exec_range(const char *path, unsigned long *lo_out, unsigned long *hi_out)
{
    Elf64_Ehdr eh;
    Elf64_Phdr ph[SX_MAX_PHDR];
    unsigned long lo = ~0UL, hi = 0, ps = (unsigned long)getpagesize();
    long fd = SC(SYS_openat, -100, path, O_RDONLY | O_CLOEXEC, 0);
    unsigned i;
    int ok = 0;

    if (fd < 0)
        return 0;
    if (sx_sc6(SYS_pread64, fd, (long)&eh, sizeof eh, 0, 0, 0) == (long)sizeof eh &&
        memcmp(eh.e_ident, ELFMAG, SELFMAG) == 0 && eh.e_type == ET_EXEC &&
        eh.e_phentsize == sizeof(Elf64_Phdr) && eh.e_phnum > 0 && eh.e_phnum <= SX_MAX_PHDR &&
        sx_sc6(SYS_pread64, fd, (long)ph, sizeof(Elf64_Phdr) * eh.e_phnum,
               (long)eh.e_phoff, 0, 0) == (long)(sizeof(Elf64_Phdr) * eh.e_phnum)) {
        for (i = 0; i < eh.e_phnum; i++) {
            if (ph[i].p_type != PT_LOAD)
                continue;
            if ((ph[i].p_vaddr & ~(ps - 1)) < lo)
                lo = ph[i].p_vaddr & ~(ps - 1);
            if (ph[i].p_vaddr + ph[i].p_memsz > hi)
                hi = ph[i].p_vaddr + ph[i].p_memsz;
        }
        hi = (hi + ps - 1) & ~(ps - 1);
        ok = (lo != ~0UL && hi > lo);
    }
    SC(SYS_close, fd, 0, 0, 0);
    if (ok) {
        *lo_out = lo;
        *hi_out = hi;
    }
    return ok;
}

/*
 * [lo, hi) 中除 [xlo, xhi) 外的每一页都**未映射**？用 mincore 逐页判：
 * 未映射页返回 -ENOMEM。只要有一页被别的映射占着，就不能靠拆旧映像解决。
 */
static int sx_range_free_except(unsigned long lo, unsigned long hi,
                                unsigned long xlo, unsigned long xhi)
{
    unsigned long ps = (unsigned long)getpagesize(), a;
    unsigned char vec;

    for (a = lo; a < hi; a += ps) {
        if (a >= xlo && a < xhi)
            continue;
        if (sx_sc6(SYS_mincore, (long)a, (long)ps, (long)&vec, 0, 0, 0) != -ENOMEM)
            return 0;
    }
    return 1;
}

/*
 * 把 host/argv0/argv/envp 整体深拷贝进一块新 mmap（拆旧映像前必须做：
 * 字符串常量可能就在旧映像的 .rodata 里）。这块内存交给新程序，不回收。
 */
static int sx_deep_copy_args(const char **host, const char **argv0,
                             char *const **argv, char *const **envp)
{
    size_t na = 0, ne = 0, bytes, i;
    char **nv, **nenv, *s;
    char *const *av = *argv, *const *ev = *envp;
    long m;

    while (av[na] != NULL) na++;
    if (ev != NULL) while (ev[ne] != NULL) ne++;
    bytes = (na + 1 + ne + 1) * sizeof(char *) + strlen(*host) + 1 +
            (*argv0 != NULL ? strlen(*argv0) + 1 : 0);
    for (i = 0; i < na; i++) bytes += strlen(av[i]) + 1;
    for (i = 0; i < ne; i++) bytes += strlen(ev[i]) + 1;
    m = sx_sc6(SYS_mmap, 0, (long)bytes, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((unsigned long)m >= (unsigned long)-4095L)
        return -1;
    nv = (char **)(uintptr_t)m;
    nenv = nv + na + 1;
    s = (char *)(nenv + ne + 1);
#define SX_DUP(dst, src) do { size_t _l = strlen(src) + 1; memcpy(s, (src), _l); (dst) = s; s += _l; } while (0)
    for (i = 0; i < na; i++) SX_DUP(nv[i], av[i]);
    nv[na] = NULL;
    for (i = 0; i < ne; i++) SX_DUP(nenv[i], ev[i]);
    nenv[ne] = NULL;
    { char *h; SX_DUP(h, *host); *host = h; }
    if (*argv0 != NULL) { char *a0; SX_DUP(a0, *argv0); *argv0 = a0; }
#undef SX_DUP
    *argv = nv;
    *envp = (ev != NULL) ? nenv : NULL;
    return 0;
}

static int px_static_exec_inner(const char *host, const char *argv0, char *const argv[],
                                char *const envp[], int *past_ponr);

/*
 * 拆掉旧映像之后再失败就回不去了（调用者的代码已经没了）——与内核 execve
 * 过了不可回头点之后的语义一致：进程只能死。裸 svc 写一句再 exit_group。
 */
int px_static_exec(const char *host, const char *argv0, char *const argv[], char *const envp[])
{
    int past_ponr = 0;
    int rc = px_static_exec_inner(host, argv0, argv, envp, &past_ponr);

    if (rc != 0 && past_ponr) {
        static const char msg[] = "bxroot: static_exec failed after replacing the old image\n";
        (void)sx_sc6(SYS_write, 2, (long)msg, sizeof msg - 1, 0, 0, 0);
        (void)sx_sc6(SYS_exit_group, 127, 0, 0, 0, 0, 0);
    }
    return rc;
}

static int px_static_exec_inner(const char *host, const char *argv0, char *const argv[],
                                char *const envp[], int *past_ponr)
{
    sx_image *img;
    size_t sites, nargc = 0, nenv = 0, i;
    unsigned long av[64], *sp, *w;
    int na = 0, nav;
    int no_vdso = 0;
    char *stk, *top, *rnd, *execfn;
    char **sa, **se;
    unsigned long tls;
    const char *v = getenv("BXROOT_VERBOSE");
    int verbose = (v != NULL && v[0] != '\0' && v[0] != '0');

    if (host == NULL || argv == NULL || argv[0] == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (getenv("BXROOT_NO_STATIC_EXEC") != NULL) {
        errno = ENOSYS;
        return -1;
    }
    if (sx_thread_count() != 1) {
        errno = EBUSY;              /* 多线程：真 execve 会杀其它线程，我们做不到 */
        return -1;
    }

    img = (sx_image *)malloc(sizeof(*img));
    if (img == NULL)
        return -1;

    /* 先按最大站点数估个 veneer 区：第一遍装载后才知道，所以保守取 4096 个 */
    if (sx_load(host, img, 4096 * SX_VENEER_SIZE) != 0) {
        int e = errno;
        unsigned long tlo, thi, ps = (unsigned long)getpagesize();
        unsigned long vz = ((unsigned long)(4096 * SX_VENEER_SIZE) + ps - 1) & ~(ps - 1);

        sx_unload(img);
        /*
         * 静态程序 exec 静态程序：冲突**只**来自我们自己装的旧映像时，像内核
         * execve 一样拆掉它再装。先探测目标范围，再确认除旧映像外全空，
         * 然后深拷贝参数、屏蔽全部信号（旧处理器指向旧映像，
         * sx_reset_process_state 复位处理器后才清空掩码），最后 munmap。
         */
        if (e == EEXIST && sx_cur_len != 0 &&
            sx_probe_exec_range(host, &tlo, &thi) &&
            tlo < sx_cur_base + sx_cur_len && thi + vz > sx_cur_base &&
            sx_range_free_except(tlo, thi + vz, sx_cur_base, sx_cur_base + sx_cur_len) &&
            sx_deep_copy_args(&host, &argv0, &argv, &envp) == 0) {
            unsigned long all[2] = { ~0UL, ~0UL };

            SC(SYS_rt_sigprocmask, 2 /* SIG_SETMASK */, all, 0, 8);
            (void)sx_sc6(SYS_munmap, (long)sx_cur_base, (long)sx_cur_len, 0, 0, 0, 0);
            sx_cur_base = sx_cur_len = 0;
            *past_ponr = 1;
            if (verbose && bxroot_log != NULL)
                bxroot_log("static_exec: 已拆除旧静态映像，重装 %s", host);
            if (sx_load(host, img, 4096 * SX_VENEER_SIZE) != 0) {
                free(img);
                return -1;
            }
        } else {
            free(img);
            errno = e;
            return -1;
        }
    }

    sites = sx_count_sites(img);
    if (sites * SX_VENEER_SIZE > img->veneer_cap) {
        /* 站点超过预留：不半补（半补 = 一部分路径仍泄漏到宿主），整体放弃 */
        sx_unload(img);
        free(img);
        errno = ENOEXEC;
        return -1;
    }

    /* veneer 区：先 RW 写入，再 RX */
    if (sites > 0) {
        long m = sx_sc6(SYS_mprotect, (long)img->veneer_pool, (long)img->veneer_cap,
                        PROT_READ | PROT_WRITE, 0, 0, 0);
        unsigned k;
        size_t placed = 0;
        unsigned long ps = (unsigned long)getpagesize();

        if (m != 0) { sx_unload(img); free(img); errno = (int)-m; return -1; }
        for (k = 0; k < img->nph; k++) {
            const Elf64_Phdr *p = &img->ph[k];
            unsigned long seg, len;
            int prot;
            size_t got;

            if (p->p_type != PT_LOAD || !(p->p_flags & PF_X))
                continue;
            seg = (img->base + p->p_vaddr) & ~(ps - 1);
            len = (((img->base + p->p_vaddr + p->p_memsz) + ps - 1) & ~(ps - 1)) - seg;
            prot = PROT_READ | PROT_EXEC;
            if (p->p_flags & PF_W)
                prot |= PROT_WRITE;
            /*
             * Android 可能拒绝 RWX。先试 RWX；不行就 RW 写入再恢复原权限。
             * 两次都失败则放弃，避免往 RX 页写触发 SIGSEGV。
             */
            {
                long pr = SC(SYS_mprotect, seg, len, PROT_READ | PROT_WRITE | PROT_EXEC, 0);
                if (pr != 0)
                    pr = SC(SYS_mprotect, seg, len, PROT_READ | PROT_WRITE, 0);
                if (pr != 0) {
                    sx_unload(img);
                    free(img);
                    errno = (int)-pr;
                    return -1;
                }
            }
            got = sx_scan((uint32_t *)(img->base + p->p_vaddr), p->p_filesz / 4,
                          (uint32_t *)(img->veneer_pool + placed * SX_VENEER_SIZE),
                          img->veneer_cap - placed * SX_VENEER_SIZE);
            placed += got;
            SC(SYS_mprotect, seg, len, prot, 0);
            __builtin___clear_cache((char *)seg, (char *)(seg + len));
        }
        SC(SYS_mprotect, img->veneer_pool, img->veneer_cap, PROT_READ | PROT_EXEC, 0);
        __builtin___clear_cache((char *)img->veneer_pool,
                                (char *)(img->veneer_pool + img->veneer_cap));
        if (verbose && bxroot_log != NULL)
            bxroot_log("static_exec: %s 补丁 %zu 个路径 svc 站点", host, placed);
    }

    /* 新栈 */
    stk = (char *)sx_sc6(SYS_mmap, 0, (long)SX_STACK_SIZE, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if ((unsigned long)stk >= (unsigned long)-4095L) {
        sx_unload(img);
        free(img);
        errno = ENOMEM;
        return -1;
    }
    top = stk + SX_STACK_SIZE;

    while (argv[nargc] != NULL) nargc++;
    if (envp != NULL)
        while (envp[nenv] != NULL) nenv++;

    /*
     * argv[0] 用调用者给的（guest 视角）而不是翻译后的宿主路径：execve 不改 argv[0]，
     * 程序看到的 argv[0] 泄漏 /data/data/.../ubuntu/... 会被 basename/usage/argv0 判断用到。
     * 为此复制一份 argv 向量（只换第 0 项），不动调用者的数组。
     */
    if (argv0 != NULL && argv0[0] != '\0' && nargc > 0) {
        char **nv = (char **)calloc(nargc + 1, sizeof(char *));
        if (nv != NULL) {
            memcpy(nv, argv, nargc * sizeof(char *));
            nv[0] = (char *)(uintptr_t)argv0;
            argv = nv;
        }
    }

    /*
     * ldd 模式（LD_TRACE_LOADED_OBJECTS 非空）：目标是 ld.so 自身时，真 ld.so 会照
     * LD_PRELOAD 把 runtime 装进去并多列一行 / 报 "cannot be preloaded"。与
     * px_stub_prepare 同判据：此时摘掉 LD_PRELOAD，并且不给 AT_SYSINFO_EHDR
     * （官方 stub 路径的 ldd 输出没有 linux-vdso 行）。
     */
    {
        int tracing = 0;
        char **fenv;
        size_t k, m = 0;

        for (k = 0; k < nenv; k++)
            if (strncmp(envp[k], "LD_TRACE_LOADED_OBJECTS=", 24) == 0 && envp[k][24] != '\0')
                tracing = 1;
        if (tracing) {
            fenv = (char **)calloc(nenv + 1, sizeof(char *));
            if (fenv != NULL) {
                for (k = 0; k < nenv; k++)
                    if (strncmp(envp[k], "LD_PRELOAD=", 11) != 0)
                        fenv[m++] = envp[k];
                fenv[m] = NULL;
                envp = fenv;
                nenv = m;
                no_vdso = 1;
            }
        }
    }
    {
        /* 字符串 + argv/envp 指针数组 + auxv(≤40 项×16) + 对齐余量，必须整体放得进栈 */
        size_t need = strlen(host) + 1 + (nargc + nenv + 4) * sizeof(char *) + 40 * 16 + 512;
        for (i = 0; i < nargc; i++) need += strlen(argv[i]) + 1;
        for (i = 0; i < nenv; i++)  need += strlen(envp[i]) + 1;
        if (need >= SX_STACK_SIZE) {
            (void)sx_sc6(SYS_munmap, (long)stk, (long)SX_STACK_SIZE, 0, 0, 0, 0);
            sx_unload(img);
            free(img);
            errno = E2BIG;
            return -1;
        }
    }
    sa = (char **)calloc(nargc + 1, sizeof(char *));
    se = (char **)calloc(nenv + 1, sizeof(char *));
    if (sa == NULL || se == NULL) {
        free(sa);
        free(se);
        (void)sx_sc6(SYS_munmap, (long)stk, (long)SX_STACK_SIZE, 0, 0, 0, 0);
        sx_unload(img);
        free(img);
        errno = ENOMEM;
        return -1;
    }
#define SX_PUSH(dst, s) do { \
        size_t _l = strlen(s) + 1; \
        if ((size_t)(top - stk) < _l + 64) { free(sa); free(se); (void)sx_sc6(SYS_munmap, (long)stk, (long)SX_STACK_SIZE, 0, 0, 0, 0); sx_unload(img); free(img); errno = E2BIG; return -1; } \
        top -= _l; memcpy(top, (s), _l); (dst) = top; \
    } while (0)
    for (i = nargc; i-- > 0;)
        SX_PUSH(sa[i], argv[i]);
    for (i = nenv; i-- > 0;)
        SX_PUSH(se[i], envp[i]);
    SX_PUSH(execfn, host);
    top = (char *)((unsigned long)top & ~15UL) - 16;
    rnd = top;
    {
        /* execve 给的是全新随机字节；复用宿主的会让 canary/pointer guard 与 runtime 相同 */
        long g = sx_sc6(278 /* getrandom */, (long)rnd, 16, 0, 0, 0, 0);
        if (g != 16) {
            unsigned long ar = getauxval(AT_RANDOM);
            if (ar != 0)
                memcpy(rnd, (void *)ar, 16);
            else
                memset(rnd, 0xa5, 16);
        }
    }

#define SX_AUX(k, val) do { av[na++] = (unsigned long)(k); av[na++] = (unsigned long)(val); } while (0)
    if (!no_vdso && getauxval(AT_SYSINFO_EHDR))
        SX_AUX(AT_SYSINFO_EHDR, getauxval(AT_SYSINFO_EHDR));
    SX_AUX(AT_HWCAP, getauxval(AT_HWCAP));
    SX_AUX(AT_HWCAP2, getauxval(AT_HWCAP2));
    SX_AUX(AT_PAGESZ, getauxval(AT_PAGESZ));
    SX_AUX(AT_CLKTCK, getauxval(AT_CLKTCK));
    SX_AUX(AT_PHDR, img->phdr);
    SX_AUX(AT_PHENT, sizeof(Elf64_Phdr));
    SX_AUX(AT_PHNUM, img->phnum);
    SX_AUX(AT_BASE, 0);
    SX_AUX(AT_FLAGS, 0);
    SX_AUX(AT_ENTRY, img->entry);
    SX_AUX(AT_UID, getuid());
    SX_AUX(AT_EUID, geteuid());
    SX_AUX(AT_GID, getgid());
    SX_AUX(AT_EGID, getegid());
    SX_AUX(AT_SECURE, 0);
    SX_AUX(AT_RANDOM, rnd);
    SX_AUX(AT_EXECFN, execfn);
    SX_AUX(AT_NULL, 0);
    nav = na;

    sp = (unsigned long *)(((unsigned long)top -
                            (nargc + 1 + nenv + 1 + 1) * 8 - (size_t)nav * 8) & ~15UL);
    w = sp;
    *w++ = (unsigned long)nargc;
    for (i = 0; i < nargc; i++) *w++ = (unsigned long)sa[i];
    *w++ = 0;
    for (i = 0; i < nenv; i++) *w++ = (unsigned long)se[i];
    *w++ = 0;
    memcpy(w, av, (size_t)nav * 8);

    /*
     * 新程序的身份：BXROOT_GUEST_EXE 答 /proc/self/exe，BXROOT_ORIG_COMM 的 basename
     * 作 comm（prctl(PR_SET_NAME)）。缺失时 comm 退回 host 的 basename。
     */
    {
        const char *gx = NULL, *oc = NULL, *base;
        char nm[16];
        size_t k2;

        for (k2 = 0; k2 < nenv; k2++) {
            if (strncmp(envp[k2], "BXROOT_GUEST_EXE=", 17) == 0) gx = envp[k2] + 17;
            else if (strncmp(envp[k2], "BXROOT_ORIG_COMM=", 17) == 0) oc = envp[k2] + 17;
        }
        sx_guest_exe[0] = '\0';
        if (gx != NULL && gx[0] == '/' && strlen(gx) < sizeof(sx_guest_exe))
            memcpy(sx_guest_exe, gx, strlen(gx) + 1);
        base = (oc != NULL && oc[0] != '\0') ? oc : host;
        if (strrchr(base, '/') != NULL)
            base = strrchr(base, '/') + 1;
        memset(nm, 0, sizeof nm);
        strncpy(nm, base, 15);
        (void)sx_sc6(167 /* prctl */, 15 /* PR_SET_NAME */, (long)nm, 0, 0, 0, 0);
    }

    sx_record_self_lib(envp, nenv);
    {
        size_t k3;

        sx_sfb_want = 0;
        for (k3 = 0; k3 < nenv; k3++)
            if (strcmp(envp[k3], "BXROOT_SECCOMP_FALLBACK=1") == 0)
                sx_sfb_want = 1;
    }
    sx_reset_process_state();

#if defined(__aarch64__)
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(tls));
#else
    /* tpidr_el0 does not exist off AArch64. There is no portable
     * equivalent for reading the static-TLS pointer, and this whole
     * path (jumping into a static ELF inside the current process) is an
     * AArch64-only feature anyway, so leave tls at its initial value. */
    tls = 0;
#endif
    px_static_dyn_tls = tls;
    sx_cur_base = img->rsv_base;
    sx_cur_len = img->rsv_len;
#if defined(__aarch64__)
    /*
     * 兜底过滤器最后装：此后本进程（含 runtime）发出的上述调用只要 IP 在
     * [lo, hi) 就进陷阱，所以之前的准备工作（读 /proc、关 fd）不能晚于这里。
     * 装不上不致命：退化为只有改写路径，并如实记日志。
     */
    if (sx_sfb_want) {
        int fr = sfb_install_filter(img->lo, img->hi);

        if (bxroot_log != NULL && (verbose || fr != 0))
            bxroot_log("static_exec: seccomp 兜底层 %s [%lx,%lx) rc=%d",
                       fr == 0 ? "已启用" : "未启用", img->lo, img->hi, fr);
    }
#endif

    if (verbose && bxroot_log != NULL)
        bxroot_log("static_exec: 即将跳转 entry=%lx sp=%lx tls=%lx", img->entry,
                   (unsigned long)sp, tls);
#if defined(__aarch64__)
    {
        /*
         * ★ 操作数必须钉死在固定寄存器 ★ 若让编译器自选，entry 可能落进 x0，
         * 而 `mov x0,#0` 在 `br` 之前 → 跳到地址 0（实测 pc=0）。
         */
        register unsigned long e __asm__("x9") = img->entry;
        register unsigned long s __asm__("x10") = (unsigned long)sp;

        __asm__ volatile("mov sp, x10\n"
                         "mov x0, #0\n"      /* rtld_fini = NULL */
                         "br  x9\n"
                         :: "r"(e), "r"(s) : "memory");
    }
    __builtin_unreachable();
#else
    /* The static-exec path is AArch64-only (it relies on hand-rolled
     * switch-stack code and on the AArch64 entry convention). Off that
     * target, report the same failure the caller would get from any
     * other unsupported situation instead of emitting unknown asm. */
    (void)img;
    return -1;
#endif
}
