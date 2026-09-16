/*
 * ★ _GNU_SOURCE 必须放在**所有系统头文件之前** ★
 *
 * 这是我在修 fakeroot.h 时踩过的同一个坑：定义晚了，`struct stat64`、
 * `S_IFMT`、`dl_phdr_info` 这些符号就不可见，编译报"未声明"。
 * fakeroot 那次是 54 个错误，根因只有这一个。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <dirent.h>
#include <sys/xattr.h>
#include <stdint.h>
#include <linux/limits.h>
#include <pwd.h>
#include <grp.h>
#include <sys/uio.h>
#include <sys/resource.h>
#include <link.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <ifaddrs.h>
#include <stddef.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <dirent.h>
#include <signal.h>
#include <sys/wait.h>

#include "config.h"
#include "l2s-runtime.h"
#include "sigsys.h"
#include "syscall_guard.h"
#include "livepatch.h"

/*
 * fakeroot 用**纯逻辑模式**编进来（测试台也编这个模式）。
 *
 * 必须这样：fakeroot.c 自身也定义了 stat/chown/access 等 LD_PRELOAD 符号，
 * 而本文件已经拥有这些符号的所有权。两条 hook 链同时存在就是符号重定义。
 * 纯逻辑模式只导出记账与字段改写的原语（58 个符号），
 * 由本文件在既有 hook 内部调用 —— 职责单一，也避免了两套 translate_path。
 */
#include "fakeroot.h"
#include "crash.h"
/*
 * D4 进程管理层（P0-3）。
 *
 * proc.h 的钩子层声明区是 `#if !PX_PURE_LOGIC`（**取值式**判定），
 * 所以构建必须带 `-DPX_PURE_LOGIC=0`（不是 `-DPX_PURE_LOGIC`！）——
 * 后者会被当成「已定义但取值为空」，于是钩子层声明被跳过而实现仍编译，
 * 整片 `unknown type name 'px_rtconfig'`。
 */
#include "proc.h"
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <linux/stat.h>
#include <time.h>
/*
 * ★ _GNU_SOURCE 必须放在**所有系统头文件之前** ★
 *
 * 这是我在修 fakeroot.h 时踩过的同一个坑：定义晚了，`struct stat64`、
 * `S_IFMT`、`dl_phdr_info` 这些符号就不可见，编译报"未声明"。
 * fakeroot 那次是 54 个错误，根因只有这一个。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <dirent.h>
#include <sys/xattr.h>
#include <stdint.h>
#include <linux/limits.h>
#include <pwd.h>
#include <grp.h>
#include <sys/uio.h>
#include <sys/resource.h>
#include <link.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <ifaddrs.h>
#include <stddef.h>

/*
 * l2s 硬链接模拟层的真实文件系统操作表。
 *
 * 这些函数指针必须绕开我们自己的 hook（否则 l2s 层内部的 lstat/symlink
 * 会再次触发 translate_path，把中间层路径又加一遍 rootfs 前缀），所以
 * 统一走 dlsym(RTLD_NEXT) 拿到的真实符号。
 */
static void ensure_real_functions(void);

static int l2s_real_lstat(const char *p, struct stat *st);
static int l2s_real_symlink(const char *t, const char *l);
static int l2s_real_rename(const char *o, const char *n);
static int l2s_real_unlink(const char *p);
static ssize_t l2s_real_readlink(const char *p, char *b, size_t sz);
static int l2s_real_access(const char *p, int m);
static int l2s_real_read_small(const char *p, char *b, size_t sz, size_t *len);
static int l2s_real_write_small(const char *p, const char *b, size_t len);

static const l2s_rt_ops L2S_OPS = {
    l2s_real_lstat, l2s_real_symlink, l2s_real_rename, l2s_real_unlink,
    l2s_real_readlink, l2s_real_access, l2s_real_read_small, l2s_real_write_small
};

/* ------------------------------------------------------------------ */
/* fakeroot 状态（钩子在文件后段，声明必须在这里）                     */
/* ------------------------------------------------------------------ */

/*
 * fakeroot 进程级单例。不放在 fakeroot.c 里（那是钩子层的做法），
 * 因为纯逻辑模式不导出 g_fakeroot —— 由本文件拥有这个状态，所有权更清楚。
 */
static fakeroot_state g_fakeroot_state;

/* fakeroot 是否可用（初始化成功且已启用）。热路径上用它做一次短路。 */
static int g_fakeroot_on = 0;

/* 全局配置实例 */
bxroot_config_t g_config = {0};

/* 缓存函数指针 */
static int (*real_open)(const char *, int, ...) = NULL;
static int (*real_openat)(int, const char *, int, ...) = NULL;
static int (*real_stat)(const char *, struct stat *) = NULL;
static int (*real_newfstatat)(int, const char *, struct stat *, int) = NULL;
static int (*real_lstat)(const char *, struct stat *) = NULL;
static int (*real_access)(const char *, int) = NULL;
static ssize_t (*real_readlink)(const char *, char *, size_t) = NULL;
static char *(*real_realpath)(const char *, char *) = NULL;
/* real_execve / real_execvpe 已随 4 个 exec 钩子一并删除（见文件后段
 * 「exec 家族已移交给 D4 进程管理层」）—— 留着会是未使用变量。 */
static pid_t (*real_getpid)(void) = NULL;
static uid_t (*real_getuid)(void) = NULL;
static gid_t (*real_getgid)(void) = NULL;
static uid_t (*real_geteuid)(void) = NULL;
static gid_t (*real_getegid)(void) = NULL;
static int (*real_chdir)(const char *) = NULL;
static int (*real_uname)(struct utsname *) = NULL;
static int (*real_chroot)(const char *) = NULL;
static int (*real_open64)(const char *, int, ...) = NULL;
static int (*real_openat64)(int, const char *, int, ...) = NULL;
static int (*real_stat64)(const char *, struct stat64 *) = NULL;
static int (*real_newfstatat64)(int, const char *, struct stat64 *, int) = NULL;
static int (*real_lstat64)(const char *, struct stat64 *) = NULL;
static DIR *(*real_opendir)(const char *) = NULL;
static FILE *(*real_fopen)(const char *, const char *) = NULL;
static FILE *(*real_fopen64)(const char *, const char *) = NULL;

/* 最大 bind mount 数量 */
#define MAX_BINDS 16

/*
 * 去掉路径尾部的 '/'。
 *
 * F2 修复的一半：`-b /a:/dev/shm/` 这种写法会让匹配全部错位 ——
 * target 长度把尾斜杠算了进去，strncmp 命中后从 path+len 取剩余部分，
 * 分隔符被吞掉，拼出 "/a" + "x" = "/ax"；更糟的是精确匹配
 * path="/dev/shm" 直接不命中（长度对不上），整条 bind 静默失效。
 *
 * 只保留单个 '/'（根路径不能被削成空串）。
 */
static void strip_trailing_slash(char *p) {
    size_t n = strlen(p);
    while (n > 1 && p[n - 1] == '/')
        p[--n] = '\0';
}

/* 从环境变量解析 bind mount */
static void parse_binds(void) {
    const char *env = getenv("BXROOT_BINDS");
    if (!env || !env[0]) return;

    /* 格式: src1:dst1;src2:dst2;... */
    char *copy = strdup(env);
    if (!copy) return;

    g_config.bind_count = 0;
    g_config.bind_sources = calloc(MAX_BINDS, sizeof(char *));
    g_config.bind_targets = calloc(MAX_BINDS, sizeof(char *));
    if (!g_config.bind_sources || !g_config.bind_targets) {
        free(copy);
        return;
    }

    char *saveptr = NULL;
    char *entry = strtok_r(copy, ";", &saveptr);
    while (entry && g_config.bind_count < MAX_BINDS) {
        char *colon = strchr(entry, ':');
        if (colon) {
            *colon = '\0';

            /* 空 source 或空 target 是无效条目：留着会让匹配逻辑把
             * 空前缀当成"匹配一切"，把整棵树都翻译错。 */
            if (entry[0] == '\0' || colon[1] == '\0') {
                LOG("bind: 跳过空条目");
                entry = strtok_r(NULL, ";", &saveptr);
                continue;
            }

            char *src = strdup(entry);
            char *tgt = strdup(colon + 1);
            if (src == NULL || tgt == NULL) {
                free(src); free(tgt);
                entry = strtok_r(NULL, ";", &saveptr);
                continue;
            }
            strip_trailing_slash(src);
            strip_trailing_slash(tgt);

            g_config.bind_sources[g_config.bind_count] = src;
            g_config.bind_targets[g_config.bind_count] = tgt;
            g_config.bind_count++;
            LOG("bind: %s -> %s", src, tgt);
        }
        entry = strtok_r(NULL, ";", &saveptr);
    }

    free(copy);
    LOG("bind mounts: %d", g_config.bind_count);
}

/* 初始化配置 */
static void init_config(void) {
    const char *env;

    /*
     * rootfs。
     *
     * P5 修复：必须和 bind 的 source/target 一样做尾斜杠归一化。
     * 漏掉它的后果与 F1 幂等失效同类 —— rootfs="/r/" 时，长度含尾斜杠，
     * 幂等判定里 path[rootfs_len] 落在 'x' 上，既非 '\0' 也非 '/'，
     * 于是判定失败，已翻译路径被**二次加前缀**：
     *     rootfs="/r/", path="/r/x"  →  "/r//r/x"
     *
     * 这条路径的入参来自 launcher 的 -r（不校验）或 Java 的
     * File.getAbsolutePath()（契约上无尾斜杠）。生产 cmdline 实测无尾斜杠，
     * 故当前不可达；但 launcher 不校验、又零测试覆盖，
     * 一行归一化即可消除整类未定义行为。
     */
    env = getenv("BXROOT_ROOTFS");
    g_config.rootfs = env && env[0] ? strdup(env) : strdup(BXROOT_ROOTFS);
    if (g_config.rootfs != NULL)
        strip_trailing_slash(g_config.rootfs);

    /* 临时目录 */
    env = getenv("BXROOT_TMP_DIR");
    g_config.tmp_dir = env && env[0] ? strdup(env) : strdup("/tmp");

    /* guest exe */
    env = getenv("BXROOT_GUEST_EXE");
    g_config.guest_exe = env && env[0] ? strdup(env) : NULL;

    /* 调试模式 */
    env = getenv("BXROOT_VERBOSE");
    g_config.verbose = env && (atoi(env) != 0);

    /* 工作目录 */
    env = getenv("BXROOT_WORKDIR");
    g_config.workdir = env && env[0] ? strdup(env) : NULL;

    /* fakeroot */
    env = getenv("BXROOT_FAKEROOT");
    g_config.fakeroot = env && (atoi(env) != 0);

    /* bind mount */
    parse_binds();

    LOG("config: rootfs=%s, tmp=%s, verbose=%d, fakeroot=%d, binds=%d",
        g_config.rootfs, g_config.tmp_dir, g_config.verbose, g_config.fakeroot,
        g_config.bind_count);
}

/* 翻译路径：绝对路径加上 rootfs 前缀，处理 bind mount */
static int translate_path(const char *path, char *out, size_t out_size) {
    if (!path || !out || out_size == 0) {
        return -1;
    }

    /* 相对路径，不翻译 */
    if (path[0] != '/') {
        strncpy(out, path, out_size - 1);
        out[out_size - 1] = '\0';
        return 0;
    }

    /* 幂等性：路径已带 rootfs 前缀时不再重复拼接。
     * 否则对已翻译路径再次调用会得到 <rootfs><rootfs>/x。 */
    const char *rootfs = g_config.rootfs ? g_config.rootfs : "";
    size_t rootfs_len = strlen(rootfs);

    if (rootfs_len > 0 &&
        strncmp(path, rootfs, rootfs_len) == 0 &&
        (path[rootfs_len] == '\0' || path[rootfs_len] == '/')) {
        strncpy(out, path, out_size - 1);
        out[out_size - 1] = '\0';
        LOG("translate (already prefixed): %s", path);
        return 0;
    }

    /* F1 修复：bind 的 source 是宿主路径，realpath()/readlink() 返回它之后
     * 再次进入本函数时不应被当成 guest 路径再加 rootfs 前缀
     * （例如 /dev/shm/x → cache/shm/x，再翻一次会变成 <rootfs>/cache/shm/x）。
     *
     * 但**必须排除自映射 bind**（source == target，如 `-b /dev:/dev`）：
     * 那种情况下 source 也是合法的 guest 前缀，若一并视为「已翻译」，
     * 会把 /dev 下的所有路径误判为透传，直接废掉后面更具体的 bind。 */
    for (int i = 0; i < g_config.bind_count; i++) {
        const char *bsrc = g_config.bind_sources ? g_config.bind_sources[i] : NULL;
        const char *btgt = g_config.bind_targets ? g_config.bind_targets[i] : NULL;
        if (!bsrc || !bsrc[0] || !btgt) continue;
        if (strcmp(bsrc, btgt) == 0) continue;   /* 自映射 → 跳过 */

        size_t bl = strlen(bsrc);
        if (strncmp(path, bsrc, bl) == 0 &&
            (path[bl] == '\0' || path[bl] == '/')) {
            strncpy(out, path, out_size - 1);
            out[out_size - 1] = '\0';
            LOG("skip translate (already bind source): %s", path);
            return 0;
        }
    }

    /* bind mount 匹配必须优先于特殊路径透传规则。
     * bind 是用户在命令行显式声明的配置（-b host:guest），优先级高于
     * `/proc/` `/sys/` `/dev/` 的默认透传；否则任何 target 落在这些前缀下的
     * bind 都会被永久短路（例如生产环境实际用到的
     * `-b .../cache/shm:/dev/shm`、`-b /dev:/dev`、`-b /proc:/proc`）。 */
    if (g_config.bind_count > 0) {
        int best = -1;
        size_t best_len = 0;

        /* 选择「最长（最具体）target」而不是第一个命中的条目：
         * `-b /dev:/dev` 会命中 /dev 下的全部路径，若按首次命中取胜，
         * 后面的 `-b .../cache/shm:/dev/shm` 将永远无法生效。 */
        for (int i = 0; i < g_config.bind_count; i++) {
            const char *target = g_config.bind_targets[i];
            if (!target) continue;

            size_t target_len = strlen(target);
            if (target_len == 0) continue;

            /* 精确匹配 target 本身，或以 target + '/' 作为子路径 */
            if (strncmp(path, target, target_len) == 0 &&
                (path[target_len] == '\0' || path[target_len] == '/')) {
                if (best < 0 || target_len > best_len) {
                    best = i;
                    best_len = target_len;
                }
            }
        }

        if (best >= 0) {
            /* 用 source 替换 target，保留剩余子路径 */
            int ret = snprintf(out, out_size, "%s%s",
                g_config.bind_sources[best], path + best_len);
            if (ret < 0 || (size_t)ret >= out_size) {
                LOG("path too long (bind): %s", path);
                return -1;
            }
            LOG("translate (bind): %s -> %s", path, out);
            return 1;
        }
    }

    /*
     * 特殊路径：无 bind 配置时透传（/proc /sys /dev 由宿主提供）。
     *
     * F3 修复：原先只比 "/proc/" 这种**带尾斜杠**的字面量，于是裸路径
     * `/proc`、`/sys`、`/dev` 全都落到下面去加 rootfs 前缀，变成
     * <rootfs>/proc —— 而 rootfs 里那个目录是空挂载点，客户会看到
     * 一个与宿主完全不同的 /proc。stat("/proc")、chdir("/dev") 这类
     * 调用就会读到错误的东西。
     *
     * 判据改成「组件边界」：要么精确相等，要么后面紧跟 '/'。
     * 这样 /procx、/procfs 仍不会被误当成特殊路径。
     */
    {
        static const char *const special[] = { "/proc", "/sys", "/dev" };
        size_t k;

        for (k = 0; k < sizeof(special) / sizeof(special[0]); k++) {
            size_t l = strlen(special[k]);
            if (strncmp(path, special[k], l) == 0 &&
                (path[l] == '\0' || path[l] == '/')) {
                strncpy(out, path, out_size - 1);
                out[out_size - 1] = '\0';
                LOG("skip translate (special): %s", path);
                return 0;
            }
        }
    }

    /* 普通路径翻译：加上 rootfs 前缀 */
    int ret = snprintf(out, out_size, "%s%s", rootfs, path);
    if (ret < 0 || (size_t)ret >= out_size) {
        LOG("path too long: %s", path);
        return -1;
    }

    LOG("translate: %s -> %s", path, out);
    return 1;
}

/* ------------------------------------------------------------------ */
/* 供 D4（proc.c）使用的翻译器与日志桥 + __dso_handle                   */
/* ------------------------------------------------------------------ */

/*
 * ★ 为什么这里必须定义 `__dso_handle` ★
 *
 * proc.c 用 `pthread_atfork` 注册 fork 三件套（没有它，fork 之后
 * 子进程会死锁）。glibc 把 `pthread_atfork` 放在 **libc_nonshared.a**
 * 里，而那个归档的 pthread_atfork.oS 需要 `__dso_handle` —— 该符号的
 * 正常提供者是 crtbeginS.o / crtbegin.o，也就是**启动文件**。
 *
 * 本项目的链接命令行带 `-nostartfiles`（LD_PRELOAD 运行时不要 CRT 的
 * 初始化代码），于是 crtbeginS.o 被排除 → `__dso_handle` 无人定义，
 * 实测报错：
 *
 *   libc_nonshared.a(pthread_atfork.oS): undefined reference to `__dso_handle'
 *   hidden symbol `__dso_handle' isn't defined
 *   final link failed: bad value
 *
 * 这不是 proc.c 的 bug，而是「-nostartfiles 的 .so 里用 pthread_atfork」
 * 的固有缺口 —— 任何在这个 .so 里调用 pthread_atfork 的模块都会踩到。
 * （INTEGRATION.md 的集成验证里没暴露它，是因为那份验证用的链接参数
 *   与生产构建不同。）
 *
 * 定义与 crtbegin 一致（值 = 自身地址），并**保持 hidden**：它只用于与
 * `__cxa_atexit`/`__cxa_finalize` 配对识别「哪个 DSO 在注册」，
 * 不需要（也不应该）出现在动态符号表里污染命名空间。
 */
void *__dso_handle __attribute__((visibility("hidden"))) = &__dso_handle;

/*
 * 供 proc.c（D4 进程管理层）使用的翻译器与日志桥。
 *
 * proc.c 用 **weak 符号**引用这两个名字，缺失时自动回落（翻译器缺失 →
 * 原样返回；日志缺失 → 不打印）。显式提供它们，是为了让两层只有
 * **一套**路径翻译语义 —— 两套实现必然漂移，而漂移的表现是
 * 「某些路径在 exec 里翻、在 open 里不翻」，排查起来极贵。
 *
 * 返回值约定与 translate_path **完全一致**（>0 已翻译 / ==0 无需翻译 /
 * <0 失败），所以 bxroot_translate_path 就是一行转发。
 */
int bxroot_translate_path(const char *path, char *out, size_t out_size) {
    return translate_path(path, out, out_size);
}

/*
 * 日志桥。
 *
 * 刻意**不**用 config.h 的 LOG 宏：那个宏受编译期 `-DBXROOT_VERBOSE=1`
 * 门控（发布构建里整个展开成空语句），而 proc.c 内部已经用运行期的
 * `BXROOT_VERBOSE` 决定要不要调我们。若这里再用编译期门控，就变成
 * 「编译期没开 → 运行期怎么设都看不到日志」，而现场排查时恰恰最需要它。
 */
void bxroot_log(const char *fmt, ...) {
    va_list ap;

    fputs("[bxroot] ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

/* ------------------------------------------------------------------ */
/* wait 家族（waitpid / wait4 / wait3 / waitid）                        */
/* ------------------------------------------------------------------ */

/*
 * ★ 为什么非做不可（这是 D4 域**引用数第一**的符号）★
 *
 * 覆盖率交叉验证：`waitpid` 出现在 9 个程序里（dpkg/find/git/mkdir/node/
 * python3/dash/gcc/make），比 `fork`(8) 还多 —— 因为 shell **每跑一条
 * 命令**就 fork+waitpid 一次，长跑负载下这是最热的进程管理入口。
 *
 * proc.c 实现了 fork/exec/spawn 的账本记账，但**没有** hook wait 家族，
 * 后果是账本**只增不减**：
 *   - 每个 wait 掉的子进程条目永远停在 PX_LIVE；
 *   - 表逐渐填满 → 触发扩容/淘汰 → 全是 live 时 `px_ledger_add` 返回
 *     PX_EFULL → `px_fork_should_abort` 判定为「必须放弃子进程」→
 *     **fork 返回 -1 + EAGAIN**。
 * 也就是说：不是「少了一层安全保护」，而是**长跑负载会把进程创建能力
 * 彻底打掉**。这正是 REPORT §9「已知限制 #1（严重度：高）」。
 *
 * 第二重收益是安全：`px_check_kill` 对 PX_REAPED 的目标一律拒绝。
 * 不标 reaped 的话，「已 wait 掉、pid 已被宿主复用」的窗口里，
 * 一条迟到的 kill 会打进宿主里一个完全无辜的进程（可能是 Android
 * 系统服务）。标了才关上这个窗口。
 *
 * ------------------------------------------------------------------
 * 语义难点：什么时候**不能**标 reaped
 * ------------------------------------------------------------------
 * 只有「这一次调用真的向调用方交付了一个子进程的终止状态」时，该 pid
 * 才算是被回收了。反之标错会把**还活着的子进程**标成 reaped，
 * 而 px_check_kill 对 reaped 一律拒绝 → 从此 kill 不掉自己的孩子
 * （功能回归，比不做还糟）。逐条：
 *
 *   1. `WNOHANG` 且返回 0 —— 子进程还没退出，**绝不能标**。
 *   2. `WNOHANG` 且返回 -1（ECHILD/EINTR/EINVAL）—— 同样不能标。
 *   3. `WNOWAIT` —— 内核**保留**僵尸（Linux 的 waitid 支持它，见下），
 *      同一个子进程还能被再 wait 一次 → **标了就再也回收不了**，
 *      而且它其实是 live 的。所以带 WNOWAIT 一律不标。
 *      ★ 实测记录：本容器的内核（6.1.145-android14）对 `waitid`
 *      生效 WNOWAIT，对 `wait4`/`waitpid` 返回 EINVAL(22)。
 *      为兼容后者，wait4/waitpid 遇到 WNOWAIT 时**剥掉该位转发**
 *      （等价于不带 WNOWAIT 的真实 wait4），否则调用方会拿到一个
 *      它在本文件系统上本来不会遇到的 EINVAL。
 *   4. 停下来的子进程（WUNTRACED / WCONTINUED）—— 只是**状态变化**，
 *      进程没有退出，还能被继续 wait → 不能标。判据见 px_wait_delivered_exit。
 *   5. `waitid` 的 WNOWAIT、以及 P_PIDFD/P_PGID/P_ALL 时的 pid 归属。
 *
 * 另外三条工程细节：
 *
 *   - `waitpid` 与 `wait3` 是 glibc 里的**弱别名**（`W wait3@@GLIBC_2.17`），
 *     底层是 wait4。所以三者都 hook，但各自独立转发，不互相调用 ——
 *     互相调用会让「哪一层负责标 reaped」变成看链接顺序的运气。
 *   - ERR 判断用 `rc > 0` / `si_pid > 0`，**不用** `< 0`：只要 id 类型
 *     比 pid_t 宽（某些 ABI 下 id_t 是 int），`rc < 0` 就永远为假，
 *     于是失败路径被当成成功、把不存在的 pid 标成 reaped。
 *   - 转发走的 `dlsym(RTLD_NEXT, ...)` 懒加载每次判空：LD_PRELOAD 里
 *     一次空指针解引用 = 整个容器进程 SIGSEGV。
 */

static pid_t (*px_real_waitpid)(pid_t, int *, int) = NULL;
static pid_t (*px_real_wait4)(pid_t, int *, int, struct rusage *) = NULL;
static pid_t (*px_real_wait3)(int *, int, struct rusage *) = NULL;
static int   (*px_real_waitid)(idtype_t, id_t, siginfo_t *, int) = NULL;

static void *px_wait_dlsym(const char *name)
{
    void *p = dlsym(RTLD_NEXT, name);

    /*
     * 失败必须留痕。这里**不能**用 LOG 宏（编译期门控，发布构建里
     * 是空语句），而 D4 的日志桥 bxroot_log 是运行期判定的 ——
     * 但 dlsym 失败时我们连「该不该打印」都不该再依赖上层配置：
     * 一个解析不到的 wait4 会让 wait4 钩子直接返回 ENOSYS，
     * 那是**功能缺失**，必须让现场看得见。
     */
    if (p == NULL) {
        fprintf(stderr, "[bxroot] wait: dlsym(%s) 失败: %s\n",
                name, dlerror());
    }
    return p;
}

/*
 * 这一次 wait 调用，是否**真的向调用方交付了一个已终止的子进程**？
 *
 * ★ 传进来的 `options` 必须是**实际转发给内核的那一份** ★
 * 见下面 PX_WAIT4_OPTIONS 的说明：wait4/waitpid/wait3 会在转发前剥掉
 * WNOWAIT，所以那三个钩子要把剥掉后的 options 传进来（此时 WNOWAIT 已
 * 不存在，子进程**确实**被回收了，必须记账）；只有 waitid 原样转发，
 * 才用调用方的原始 options 判定。
 *
 * 判据按顺序：
 *   - options 里有 WNOWAIT → 否（僵尸被内核保留，还能再 wait）。
 *   - status 为空指针 → 保守取「否」。
 *     正常调用方不会传 NULL，但真传了就无法区分「退出」与「停止」，
 *     而 WUNTRACED/WCONTINUED 场景下标错的代价是「杀不掉自己的孩子」。
 *     代价：这种调用形态下账本不回收（退化成当前行为，不会更糟）。
 *   - WIFEXITED / WIFSIGNALED → 是。
 *   - WIFSTOPPED / WIFCONTINUED（需要 WUNTRACED / WCONTINUED 才会出现）
 *     → 否，进程还活着。
 */
static int px_wait_delivered_exit(pid_t rc, const int *status, int options)
{
    if ((options & WNOWAIT) != 0) {
        return 0;
    }
    if (rc <= 0 || status == NULL) {
        return 0;
    }
    if (WIFEXITED(*status) || WIFSIGNALED(*status)) {
        return 1;
    }
    return 0;
}

/* 记账：把一个确实回收掉的 pid 标 REAPED（账本未初始化时静默跳过）。 */
static void px_note_reaped(pid_t pid)
{
    if (pid > 0) {
        (void)px_ledger_reap(px_runtime_ledger(), pid);
    }
}

/*
 * wait4 转发的 options 归一化。
 *
 * 本内核实测：`wait4(…, WNOHANG|WNOWAIT, …)` → EINVAL，而
 * `waitid(…, WEXITED|WNOHANG|WNOWAIT, …)` 正常。Linux 的 wait4 从来
 * 没有实现过 WNOWAIT（该位只对 waitid 有意义），而 glibc 也不拦它 ——
 * 于是调用方拿到的是内核的 EINVAL。
 *
 * 我们在这里剥掉 WNOWAIT 再转发，让 wait4/waitpid 的行为在「支持
 * WNOWAIT 的内核」与「不支持的内核」上一致（都当作普通 wait）。
 * 这既是兼容性处理，也是**我们唯一能守住不标 reaped 的方式** ——
 * 因为剥掉之后那次调用真的回收了子进程，语义上确实该标。
 *
 * 注意：剥掉它只影响我们转发下去的那一份，调用方看到的 options 不变。
 */
#define PX_WAIT4_OPTIONS(o) ((o) & ~WNOWAIT)

pid_t waitpid(pid_t pid, int *status, int options)
{
    pid_t rc;

    if (px_real_waitpid == NULL) {
        px_real_waitpid = (pid_t (*)(pid_t, int *, int))px_wait_dlsym("waitpid");
    }
    if (px_real_waitpid == NULL) {
        errno = ENOSYS;
        return -1;
    }

    rc = px_real_waitpid(pid, status, PX_WAIT4_OPTIONS(options));

    /*
     * ★ WNOHANG 返回 0 时**绝不能**标 reaped ★
     * 返回 0 的含义是「有子进程，但都还没改变状态」—— 它们全是 live 的。
     * px_wait_delivered_exit 里的 `rc <= 0` 把 0 与 -1 一并挡掉。
     *
     * 传进去的是**剥掉 WNOWAIT 之后**的 options（= 真正转发下去的那份）：
     * 既然我们让内核按普通 wait 回收了这个子进程，就必须记账，
     * 否则 WNOWAIT 路径永远不回收（账本只增不减的原病）。
     */
    if (px_wait_delivered_exit(rc, status, PX_WAIT4_OPTIONS(options))) {
        px_note_reaped(rc);
    }
    return rc;
}

pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage)
{
    pid_t rc;

    if (px_real_wait4 == NULL) {
        px_real_wait4 = (pid_t (*)(pid_t, int *, int, struct rusage *))
                        px_wait_dlsym("wait4");
    }
    if (px_real_wait4 == NULL) {
        errno = ENOSYS;
        return -1;
    }

    rc = px_real_wait4(pid, status, PX_WAIT4_OPTIONS(options), rusage);
    if (px_wait_delivered_exit(rc, status, PX_WAIT4_OPTIONS(options))) {
        px_note_reaped(rc);
    }
    return rc;
}

/* wait3 = wait4(-1, ...)。glibc 里是弱别名，这里独立实现同一套语义。 */
pid_t wait3(int *status, int options, struct rusage *rusage)
{
    pid_t rc;

    if (px_real_wait3 == NULL) {
        px_real_wait3 = (pid_t (*)(int *, int, struct rusage *))
                        px_wait_dlsym("wait3");
    }
    if (px_real_wait3 == NULL) {
        /*
         * 回落：glibc 的 wait3 就是 wait4(-1, …)。真实符号解析不到时
         * 走 wait4 才是**语义等价**的，返回 ENOSYS 会让调用方的
         * 「等任意子进程」彻底失效。
         */
        return wait4(-1, status, options, rusage);
    }

    rc = px_real_wait3(status, PX_WAIT4_OPTIONS(options), rusage);
    if (px_wait_delivered_exit(rc, status, PX_WAIT4_OPTIONS(options))) {
        px_note_reaped(rc);
    }
    return rc;
}

/*
 * 从 siginfo 判定「这次 waitid 是否交付了一个已退出的子进程」。
 *
 *   - `si_pid == 0` → WNOHANG 且无人可报，**不是**一次回收。
 *     实测：内核会把 siginfo 清零（si_signo=0/si_pid=0），
 *     所以这个判据是可靠的；但很多调用方会**复用**同一个 siginfo
 *     不初始化，于是残留的旧 si_pid 会被误读成「回收了这个 pid」——
 *     所以下面再用 psi->si_pid（内核实际填的那个）核对一次。
 *   - si_code：CLD_EXITED / CLD_KILLED / CLD_DUMPED 才是终止；
 *     CLD_STOPPED / CLD_CONTINUED 是状态变化，进程还活着。
 */
static int px_waitid_delivered_exit(const siginfo_t *psi, int options)
{
    if ((options & WNOWAIT) != 0 || psi == NULL) {
        return 0;
    }
    if (psi->si_pid <= 0) {
        return 0;
    }
    switch (psi->si_code) {
    case CLD_EXITED:
    case CLD_KILLED:
    case CLD_DUMPED:
        return 1;
    default:
        /* CLD_STOPPED / CLD_CONTINUED / CLD_TRAPPED — 进程没退出 */
        return 0;
    }
}

int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options)
{
    int rc;

    if (px_real_waitid == NULL) {
        px_real_waitid = (int (*)(idtype_t, id_t, siginfo_t *, int))
                         px_wait_dlsym("waitid");
    }
    if (px_real_waitid == NULL) {
        errno = ENOSYS;
        return -1;
    }

    rc = px_real_waitid(idtype, id, infop, options);

    /*
     * 只有 P_PID/P_PIDFD 的 id 才**是**一个进程号，可以直接进账本。
     *   - P_ALL  (id 被忽略) → 回收的是 id 未知的某个子进程，
     *     拿 id 去标只会把 0 或垃圾值写进账本（污染 kill 判定）。
     *   - P_PGID → id 是进程组号，不是 pid。
     * 这两种情况只是「少一次回收」，不会误标 —— 误标的代价（把活着的
     * 子进程标成 reaped 后杀不掉）远高于漏标（下次 wait 再收）。
     */
    if (rc == 0 && (idtype == P_PID || idtype == P_PIDFD) &&
        px_waitid_delivered_exit(infop, options)) {
        px_note_reaped((pid_t)infop->si_pid);
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* l2s 层的真实 FS 适配                                                */
/* ------------------------------------------------------------------ */

/*
 * 这几个包装必须用 RTLD_NEXT 拿到的真实符号，**不能**调用本文件里的
 * hook 版本。原因：l2s 层拿到的是已经翻译过的宿主路径（中间层、数据
 * 文件都在 rootfs 内），若再走一遍 translate_path，就会被重复加上
 * rootfs 前缀，变成 <rootfs><rootfs>/...。
 */
static int l2s_real_lstat(const char *p, struct stat *st)
{
    ensure_real_functions();
    return real_lstat ? real_lstat(p, st) : lstat(p, st);
}

static int l2s_real_symlink(const char *t, const char *l)
{
    static int (*fn)(const char *, const char *) = NULL;
    if (fn == NULL) fn = (int (*)(const char *, const char *))dlsym(RTLD_NEXT, "symlink");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(t, l);
}

static int l2s_real_rename(const char *o, const char *n)
{
    static int (*fn)(const char *, const char *) = NULL;
    if (fn == NULL) fn = (int (*)(const char *, const char *))dlsym(RTLD_NEXT, "rename");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(o, n);
}

static int l2s_real_unlink(const char *p)
{
    static int (*fn)(const char *) = NULL;
    if (fn == NULL) fn = (int (*)(const char *))dlsym(RTLD_NEXT, "unlink");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(p);
}

static ssize_t l2s_real_readlink(const char *p, char *b, size_t sz)
{
    static ssize_t (*fn)(const char *, char *, size_t) = NULL;
    if (fn == NULL) fn = (ssize_t (*)(const char *, char *, size_t))dlsym(RTLD_NEXT, "readlink");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(p, b, sz);
}

static int l2s_real_access(const char *p, int m)
{
    ensure_real_functions();
    return real_access ? real_access(p, m) : access(p, m);
}

/*
 * `.cnt` 旁路小文件的读写。
 *
 * 这里**直接用 syscall()**，不走 libc 也不走 dlsym。理由：
 *   - 走 libc 会进到本文件自己的 open/read hook，路径被再翻译一次；
 *   - 这几个调用发生在 l2s 内部的记账路径上，必须绝对可靠，
 *     不该依赖 GLIBC 版本差异（glibc 2.33+ 已移除 __xstat 家族）。
 * syscall() 本身不被我们 hook，是这里唯一安全的选择。
 */
static int l2s_real_read_small(const char *p, char *b, size_t sz, size_t *len)
{
    long fd = syscall(SYS_openat, AT_FDCWD, p, O_RDONLY | O_CLOEXEC, 0);
    long n;

    if (fd < 0)
        return -(int)errno;
    n = syscall(SYS_read, (int)fd, b, sz - 1);
    syscall(SYS_close, (int)fd);
    if (n < 0)
        return -(int)errno;
    b[n] = '\0';
    if (len != NULL)
        *len = (size_t)n;
    return 0;
}

static int l2s_real_write_small(const char *p, const char *b, size_t len)
{
    long fd = syscall(SYS_openat, AT_FDCWD, p,
                      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    long n;

    if (fd < 0)
        return -(int)errno;
    n = syscall(SYS_write, (int)fd, b, len);
    syscall(SYS_close, (int)fd);
    if (n < 0)
        return -(int)errno;
    return (size_t)n == len ? 0 : -EIO;
}

/* 懒加载真实函数指针 */
static void ensure_real_functions(void) {
    if (!real_open) {
        real_open = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT, "open");
        real_openat = (int (*)(int, const char *, int, ...))dlsym(RTLD_NEXT, "openat");
        real_stat = (int (*)(const char *, struct stat *))dlsym(RTLD_NEXT, "stat");
        real_newfstatat = (int (*)(int, const char *, struct stat *, int))dlsym(RTLD_NEXT, "newfstatat");
        /* glibc 2.33+ 不再导出 newfstatat，现代等价入口是 fstatat。
         * 若 newfstatat 解析失败，回退到 fstatat（glibc 中两者同实现）。 */
        if (!real_newfstatat)
            real_newfstatat = (int (*)(int, const char *, struct stat *, int))dlsym(RTLD_NEXT, "fstatat");
        real_lstat = (int (*)(const char *, struct stat *))dlsym(RTLD_NEXT, "lstat");
        real_access = (int (*)(const char *, int))dlsym(RTLD_NEXT, "access");
        real_readlink = (ssize_t (*)(const char *, char *, size_t))dlsym(RTLD_NEXT, "readlink");
        real_realpath = (char * (*)(const char *, char *))dlsym(RTLD_NEXT, "realpath");
        real_getpid = (pid_t (*)(void))dlsym(RTLD_NEXT, "getpid");
        real_getuid = (uid_t (*)(void))dlsym(RTLD_NEXT, "getuid");
        real_getgid = (gid_t (*)(void))dlsym(RTLD_NEXT, "getgid");
        real_geteuid = (uid_t (*)(void))dlsym(RTLD_NEXT, "geteuid");
        real_getegid = (gid_t (*)(void))dlsym(RTLD_NEXT, "getegid");
        real_chdir = (int (*)(const char *))dlsym(RTLD_NEXT, "chdir");
        real_uname = (int (*)(struct utsname *))dlsym(RTLD_NEXT, "uname");
        real_chroot = (int (*)(const char *))dlsym(RTLD_NEXT, "chroot");
        real_open64 = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT, "open64");
        real_openat64 = (int (*)(int, const char *, int, ...))dlsym(RTLD_NEXT, "openat64");
        real_stat64 = (int (*)(const char *, struct stat64 *))dlsym(RTLD_NEXT, "stat64");
        real_newfstatat64 = (int (*)(int, const char *, struct stat64 *, int))dlsym(RTLD_NEXT, "newfstatat64");
        if (!real_newfstatat64)
            real_newfstatat64 = (int (*)(int, const char *, struct stat64 *, int))dlsym(RTLD_NEXT, "fstatat64");
        real_lstat64 = (int (*)(const char *, struct stat64 *))dlsym(RTLD_NEXT, "lstat64");
        real_opendir = (DIR * (*)(const char *))dlsym(RTLD_NEXT, "opendir");
        real_fopen = (FILE * (*)(const char *, const char *))dlsym(RTLD_NEXT, "fopen");
        real_fopen64 = (FILE * (*)(const char *, const char *))dlsym(RTLD_NEXT, "fopen64");
    }
}

/* Helper: 调用 real_open，正确处理可变参数 */
static int call_real_open(const char *path, int flags, mode_t mode) {
    if (real_open)
        return real_open(path, flags, mode);
    return -1;
}

static int call_real_openat(int dirfd, const char *path, int flags, mode_t mode) {
    if (real_openat)
        return real_openat(dirfd, path, flags, mode);
    return -1;
}

/* Hook: open */
int open(const char *path, int flags, ...) {
    ensure_real_functions();

    mode_t mode = 0666;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    char translated[MAX_PATH_LEN];
    if (translate_path(path, translated, sizeof(translated)) > 0) {
        return call_real_open(translated, flags, mode);
    }
    return call_real_open(path, flags, mode);
}

/* Hook: open64 */
int open64(const char *path, int flags, ...) {
    ensure_real_functions();

    mode_t mode = 0666;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    char translated[MAX_PATH_LEN];
    if (translate_path(path, translated, sizeof(translated)) > 0) {
        return real_open64(translated, flags, mode);
    }
    return real_open64(path, flags, mode);
}

/* Hook: openat */
int openat(int dirfd, const char *path, int flags, ...) {
    ensure_real_functions();

    mode_t mode = 0666;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    char translated[MAX_PATH_LEN];
    if (translate_path(path, translated, sizeof(translated)) > 0) {
        return call_real_openat(dirfd, translated, flags, mode);
    }
    return call_real_openat(dirfd, path, flags, mode);
}

/* Hook: openat64 */
int openat64(int dirfd, const char *path, int flags, ...) {
    ensure_real_functions();

    mode_t mode = 0666;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    char translated[MAX_PATH_LEN];
    if (translate_path(path, translated, sizeof(translated)) > 0) {
        return real_openat64(dirfd, translated, flags, mode);
    }
    return real_openat64(dirfd, path, flags, mode);
}

/* Hook: stat */
int stat(const char *path, struct stat *buf) {
    ensure_real_functions();

    char translated[MAX_PATH_LEN];
    const char *p = path;
    int rc;

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    rc = real_stat(p, buf);

    /* fakeroot：真实调用成功后才改写字段。
     *
     * 必须在**翻译之后**的路径上查表 —— 记账用的是宿主路径，
     * 而 translate_path 给出的正是宿主路径。顺序反了就永远查不到。
     * 失败时不动 buf（内核可能没写全，改它就是碰运气）。 */
    if (rc == 0 && g_fakeroot_on)
        fakeroot_patch_stat(buf, &g_fakeroot_state);

    /*
     * l2s 的 stat 契约 —— 本文件此前最严重的一处静默失效。
     *
     * l2s 把客户眼里的"硬链接"落成"符号链接 + 中间层"，于是 stat 的
     * st_nlink 恒为 1、st_mode 带 S_IFLNK，客户读到的是**与它自己的
     * 写入操作不一致的元数据**。pnpm 正是靠 st_nlink 判断 store 里的
     * 文件是否已被链接，看到 1 就认为没链接，退化成完整复制 ——
     * 这正是 DSHA 被迫使用 package-import-method=copy 的根因。
     *
     * 此前 l2s_rt_patch_stat() 实现完整、单测 119 条全绿，但**没有任何
     * 生产代码调用它**（objdump 中 l2s_rt_patch_stat@plt 的 bl 数为 0）。
     * 单测只测函数自身，没有一条断言检查 preload.c 是否接线 —— 与当年
     * --link2symlink 被 launcher 解析后丢弃完全同类：**能力已实现，
     * 但从未生效**。此处补齐。
     *
     * 路径参数用翻译后的宿主路径 p，不是原始 path：l2s 的中间层与数据
     * 文件都在宿主侧，用 guest 路径永远 probe 不到（与 fakeroot 同理）。
     *
     * 只在 rc == 0 之后调用：失败时 buf 未必被内核写全，改它就是碰运气。
     */
    if (rc == 0)
        l2s_rt_patch_stat(buf, p);

    return rc;
}

/* Hook: stat64 */
int stat64(const char *path, struct stat64 *buf) {
    ensure_real_functions();

    char translated[MAX_PATH_LEN];
    const char *p = path;
    int rc;

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    rc = real_stat64(p, buf);
    if (rc == 0 && g_fakeroot_on)
        fakeroot_patch_stat64(buf, &g_fakeroot_state);
    /* l2s：与 stat 同源，必须一起接（见 stat 处的完整说明） */
    if (rc == 0)
        l2s_rt_patch_stat((struct stat *)buf, p);
    return rc;
}

/* Hook: newfstatat */
int newfstatat(int dirfd, const char *path, struct stat *buf, int flags) {
    ensure_real_functions();

    /* 真实实现解析失败时不得解引用空指针（glibc 2.39 不导出 newfstatat）。 */
    if (!real_newfstatat) {
        errno = ENOSYS;
        return -1;
    }

    char translated[MAX_PATH_LEN];
    const char *p = path;
    int rc;

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    rc = real_newfstatat(dirfd, p, buf, flags);
    if (rc == 0 && g_fakeroot_on)
        fakeroot_patch_stat(buf, &g_fakeroot_state);
    /* l2s：fstatat 是 glibc 现代程序的主路径，绝不能漏 */
    if (rc == 0)
        l2s_rt_patch_stat(buf, p);
    return rc;
}

/* Hook: newfstatat64 */
int newfstatat64(int dirfd, const char *path, struct stat64 *buf, int flags) {
    ensure_real_functions();

    if (!real_newfstatat64) {
        errno = ENOSYS;
        return -1;
    }

    char translated[MAX_PATH_LEN];
    const char *p = path;
    int rc;

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    rc = real_newfstatat64(dirfd, p, buf, flags);
    if (rc == 0 && g_fakeroot_on)
        fakeroot_patch_stat64(buf, &g_fakeroot_state);
    if (rc == 0)
        l2s_rt_patch_stat((struct stat *)buf, p);
    return rc;
}

/* Hook: lstat */
int lstat(const char *path, struct stat *buf) {
    ensure_real_functions();

    char translated[MAX_PATH_LEN];
    const char *p = path;
    int rc;

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    rc = real_lstat(p, buf);

    /*
     * fakeroot：lstat 与 stat **同样**补丁。
     *
     * 我起初在这里写了「故意不补丁」，理由是「lstat 返回链接自身的元数据，
     * 糊上目标的属主会不一致」，还声称 proot 也不这么做。
     * **这个理由是错的，proot 也确实这么做。** 已核实：
     *   - PROOT 的 fake_id0.c:1054-1057 把 PR_lstat/PR_lstat64 与
     *     PR_stat/PR_fstat 放进同一个 branch；
     *   - stat.c:15-50 的 handle_stat_exit_end 对它们一视同仁。
     *
     * 而且这样做是自洽的：fr_decide_ids 的启发式**只改写属主等于真实
     * 用户**的文件（fakeroot.c:1063）。用户自己建的符号链接，其属主正是
     * 真实用户，改写后显示 root —— 这恰恰与「当前身份是 root」的伪装
     * 一致，而不是矛盾。
     *
     * 一致性比「我觉得更合理」重要：与 proot 分叉会让同一份 rootfs
     * 在两套运行时下表现不同，而这种差异极难排查。
     */
    if (rc == 0 && g_fakeroot_on)
        fakeroot_patch_stat(buf, &g_fakeroot_state);

    /* l2s：与 stat 同源（lstat 也要抹掉 S_IFLNK，否则客户看出是符号链接） */
    if (rc == 0)
        l2s_rt_patch_stat(buf, p);

    return rc;
}

/* Hook: lstat64 */
int lstat64(const char *path, struct stat64 *buf) {
    ensure_real_functions();

    char translated[MAX_PATH_LEN];
    const char *p = path;
    int rc;

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    rc = real_lstat64(p, buf);
    /* 与 lstat 保持一致：proot 同样对 lstat64 做 owner 改写 */
    if (rc == 0 && g_fakeroot_on)
        fakeroot_patch_stat64(buf, &g_fakeroot_state);
    /* l2s：与 lstat 一致 */
    if (rc == 0)
        l2s_rt_patch_stat((struct stat *)buf, p);
    return rc;
}

/* Hook: access */
int access(const char *path, int mode) {
    ensure_real_functions();

    char translated[MAX_PATH_LEN];
    const char *p = path;
    struct stat st;
    int have_st = 0;
    int rc;

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    rc = real_access(p, mode);

    /*
     * fakeroot：真实 access() 失败时，用模型再判一次。
     *
     * 场景：文件真实属主是 app uid，权限 0600。客户（自认 root）调
     * access(X_OK) —— 内核按真实身份拒绝。但在伪装语义下，
     * 这个文件属于「root」（启发式会改写属主），而 root 对普通文件的
     * 执行位检查另有规则，且 root 可以绕过读写真检查。
     *
     * 关键原则（proot fake_id0.c:535-559 同一哲学）：
     * **只覆盖错误，绝不凭空造错误。** 所以只在 rc != 0 时考虑改写；
     * 真实成功一律照原样返回。
     */
    if (rc == 0 || !g_fakeroot_on)
        return rc;

    /* 取一次 stat 供模型判断；失败就如实透传真实 errno（通常是 ENOENT） */
    if (real_stat != NULL && real_stat(p, &st) == 0) {
        have_st = 1;
        fakeroot_patch_stat(&st, &g_fakeroot_state);
    }

    {
        fr_access_verdict v = fakeroot_check_access(
            &st, mode, have_st != 0,
            g_fakeroot_state.euid == 0);

        if (fakeroot_access_override(errno, v))
            return 0;   /* 模型放行 → 吞掉错误 */
    }

    return rc;
}

/* ------------------------------------------------------------------ */
/* Hook: chown 家族 —— fakeroot 的另一半（上游 issue #12）            */
/* ------------------------------------------------------------------ */

/*
 * dpkg 解包后会对每个文件 chown(root, root)。非特权进程做不到，
 * 真实调用返回 EPERM。若如实上抛，安装立刻失败。
 *
 * 正确做法（proot chown.c）：吞掉 EPERM/EACCES，把「这文件属于 root」
 * 记进记账表，返回成功；之后 stat 再把属主糊回去。
 *
 * **但非权限类错误必须透传** —— 文件不存在时假装 chown 成功，
 * 会让客户以为改好了，之后一读才发现没有，错误点离现场很远。
 */
static int fr_do_chown(const char *p, uid_t uid, gid_t gid, int which)
{
    static int (*fn_chown)(const char *, uid_t, gid_t) = NULL;
    static int (*fn_lchown)(const char *, uid_t, gid_t) = NULL;
    int rc;

    if (which == 0) {
        if (fn_chown == NULL)
            fn_chown = (int (*)(const char *, uid_t, gid_t))dlsym(RTLD_NEXT, "chown");
        if (fn_chown == NULL) { errno = ENOSYS; return -1; }
        rc = fn_chown(p, uid, gid);
    } else {
        if (fn_lchown == NULL)
            fn_lchown = (int (*)(const char *, uid_t, gid_t))dlsym(RTLD_NEXT, "lchown");
        if (fn_lchown == NULL) { errno = ENOSYS; return -1; }
        rc = fn_lchown(p, uid, gid);
    }

    if (rc == 0) {
        /* 真实成功（比如伪装身份下确有权限）：如实记账，不改写返回值。 */
        if (g_fakeroot_on)
            (void)fakeroot_record_owner_path(&g_fakeroot_state, p, uid, gid);
        return 0;
    }

    if (!g_fakeroot_on)
        return rc;

    {
        int saved = errno;
        uid_t out_uid = uid;
        gid_t out_gid = gid;
        int gate = fakeroot_gate_chown(&g_fakeroot_state, NULL, uid, gid,
                                       &out_uid, &out_gid);
        fr_chown_action act = fakeroot_chown_action(rc, saved, gate);

        if (act == FR_CHOWN_FAKE_OK) {
            (void)fakeroot_record_owner_path(&g_fakeroot_state, p, uid, gid);
            return 0;   /* 吞掉 EPERM/EACCES */
        }
        errno = saved;  /* 透传真实错误 */
    }
    return rc;
}

int chown(const char *path, uid_t uid, gid_t gid) {
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fr_do_chown(p, uid, gid, 0);
}

int lchown(const char *path, uid_t uid, gid_t gid) {
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fr_do_chown(p, uid, gid, 1);
}

int fchown(int fd, uid_t uid, gid_t gid) {
    static int (*fn)(int, uid_t, gid_t) = NULL;
    int rc;

    if (fn == NULL)
        fn = (int (*)(int, uid_t, gid_t))dlsym(RTLD_NEXT, "fchown");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    rc = fn(fd, uid, gid);
    if (!g_fakeroot_on)
        return rc;

    if (rc == 0) {
        (void)fakeroot_record_owner_fd(&g_fakeroot_state, fd, uid, gid);
        return 0;
    }
    {
        int saved = errno;
        uid_t out_uid = uid;
        gid_t out_gid = gid;
        int gate = fakeroot_gate_chown(&g_fakeroot_state, NULL, uid, gid,
                                       &out_uid, &out_gid);
        fr_chown_action act = fakeroot_chown_action(rc, saved, gate);

        if (act == FR_CHOWN_FAKE_OK) {
            (void)fakeroot_record_owner_fd(&g_fakeroot_state, fd, uid, gid);
            return 0;
        }
        errno = saved;
    }
    return rc;
}

/* Hook: readlink */
ssize_t readlink(const char *path, char *buf, size_t buf_size) {
    ensure_real_functions();

    char translated[MAX_PATH_LEN];
    ssize_t n;

    if (translate_path(path, translated, sizeof(translated)) > 0) {
        n = real_readlink(translated, buf, buf_size);
    } else {
        n = real_readlink(path, buf, buf_size);
    }
    if (n <= 0)
        return n;

    /*
     * 反转译：内核可能回给我们的是 l2s 内部路径（中间层名），
     * 客户从没见过这个名字，看到就等于看穿了模拟。
     *
     * 必须自己补 NUL 再交给 l2s 层 —— readlink 不保证结尾有 NUL，
     * 而 l2s_rt_rewrite_readlink() 按 C 字符串处理。这也是历史上
     * 官方实现出过越界读的地方（issue #22）。
     */
    {
        char raw[MAX_PATH_LEN];
        char fixed[MAX_PATH_LEN];
        size_t copy = (size_t)n < sizeof(raw) - 1 ? (size_t)n : sizeof(raw) - 1;

        memcpy(raw, buf, copy);
        raw[copy] = '\0';

        if (l2s_rt_rewrite_readlink(path, raw, fixed, sizeof(fixed)) == 1) {
            size_t flen = strlen(fixed);
            if (flen > buf_size)
                flen = buf_size;          /* 截断，与 readlink(2) 语义一致 */
            memcpy(buf, fixed, flen);
            return (ssize_t)flen;
        }
    }
    return n;
}

/* Hook: realpath */
char *realpath(const char *path, char *resolved) {
    ensure_real_functions();

    char translated[MAX_PATH_LEN];
    if (translate_path(path, translated, sizeof(translated)) > 0) {
        return real_realpath(translated, resolved);
    }
    return real_realpath(path, resolved);
}

/* ------------------------------------------------------------------ */
/* Hook: link / linkat —— 硬链接模拟的入口                             */
/* ------------------------------------------------------------------ */

/*
 * 这是 DSHA 生产最关键的一条 hook。
 *
 * Android app 私有目录被 SELinux 禁止 link(2)，所以 pnpm/dpkg/tar 的每一次
 * 硬链接都会失败。l2s 层把它模拟成「一份数据 + 多条符号链接」的三层结构。
 *
 * 注意翻译方向：l2s 层期望拿到**客户视角**的路径（/root/x），
 * 而不是宿主路径。所以这里先把两个参数各自翻译成宿主路径，交给 l2s 层，
 * 由它用 L2S_OPS 在宿主侧建链。这样 l2s 层的路径拼接与 bxroot/proot
 * 的编码规则保持一致（编码的是宿主路径）。
 */
int link(const char *oldpath, const char *newpath) {
    static int (*fn)(const char *, const char *) = NULL;
    char told[MAX_PATH_LEN], tnew[MAX_PATH_LEN];
    const char *po = oldpath, *pn = newpath;
    int rc;

    if (translate_path(oldpath, told, sizeof(told)) > 0) po = told;
    if (translate_path(newpath, tnew, sizeof(tnew)) > 0) pn = tnew;

    if (l2s_rt_enabled()) {
        rc = l2s_rt_link(po, pn);
        if (rc == 0)
            return 0;
        if (rc != L2S_RT_PASSTHRU) {
            errno = -rc;
            return -1;
        }
    }

    if (fn == NULL) fn = (int (*)(const char *, const char *))dlsym(RTLD_NEXT, "link");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(po, pn);
}

int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath,
           int flags) {
    static int (*fn)(int, const char *, int, const char *, int) = NULL;
    char told[MAX_PATH_LEN], tnew[MAX_PATH_LEN];
    const char *po = oldpath, *pn = newpath;
    int rc;

    if (translate_path(oldpath, told, sizeof(told)) > 0) po = told;
    if (translate_path(newpath, tnew, sizeof(tnew)) > 0) pn = tnew;

    if (l2s_rt_enabled()) {
        rc = l2s_rt_link(po, pn);
        if (rc == 0)
            return 0;
        if (rc != L2S_RT_PASSTHRU) {
            errno = -rc;
            return -1;
        }
    }

    if (fn == NULL) fn = (int (*)(int, const char *, int, const char *, int))dlsym(RTLD_NEXT, "linkat");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(olddirfd, po, newdirfd, pn, flags);
}

/* Hook: unlink —— 递减链长，归零才真正回收 */
int unlink(const char *path) {
    static int (*fn)(const char *) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;
    int rc;

    if (translate_path(path, translated, sizeof(translated)) > 0) p = translated;

    if (l2s_rt_enabled()) {
        rc = l2s_rt_unlink(p);
        if (rc == 0)
            return 0;
        if (rc != L2S_RT_PASSTHRU) {
            errno = -rc;
            return -1;
        }
    }

    if (fn == NULL) fn = (int (*)(const char *))dlsym(RTLD_NEXT, "unlink");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(p);
}

/* ------------------------------------------------------------------ */
/* Hook: FORTIFY 变体 —— 「不补则 hook 白写」的那一类                    */
/* ------------------------------------------------------------------ */

/*
 * 为什么必须补这些：
 *
 * Ubuntu 24.04 默认开 `_FORTIFY_SOURCE`，于是程序**不调用** open/readlink/
 * realpath，而调用 `__open_2`/`__readlink_chk`/`__realpath_chk` 这些带
 * 边界检查的变体。我们只 hook 了前者 —— 那么对被 FORTIFY 过的二进制，
 * 我们的翻译**完全不生效**。
 *
 * 这不是理论问题。实测 rootfs 里的常用二进制：
 *
 *   ls       -> __readlink_chk              （open 族调用数 = 0，全靠这个）
 *   git      -> __open64_2
 *   python3  -> __open64_2, __realpath_chk
 *   node     -> __xstat, __lxstat, __xstat64, __lxstat64  （4 个全用）
 *   tar      -> __open_2, __openat_2, __readlinkat_chk
 *
 * 即：**容器里几乎每一个常用程序都在走这些路径**。不补它们，
 * 前面那 32 个 hook 有一大半是白写的。
 *
 * 官方 proroot 的 D7 域专门覆盖这些（GAP-ANALYSIS 把它列为 P1 关键）。
 *
 * 实现上它们只是**薄转发**：真实符号仍在 glibc 里导出着，
 * 用 dlsym(RTLD_NEXT) 拿得到，翻译逻辑与主 hook 完全一致。
 */

/* __open_2(path, flags) —— 无 mode 参数（O_CREAT 时 glibc 会走非 FORTIFY 版） */
int __open_2(const char *path, int flags) {
    static int (*fn)(const char *, int) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (int (*)(const char *, int))dlsym(RTLD_NEXT, "__open_2");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(p, flags);
}

int __open64_2(const char *path, int flags) {
    static int (*fn)(const char *, int) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (int (*)(const char *, int))dlsym(RTLD_NEXT, "__open64_2");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(p, flags);
}

int __openat_2(int dirfd, const char *path, int flags) {
    static int (*fn)(int, const char *, int) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (int (*)(int, const char *, int))dlsym(RTLD_NEXT, "__openat_2");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(dirfd, p, flags);
}

int __openat64_2(int dirfd, const char *path, int flags) {
    static int (*fn)(int, const char *, int) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (int (*)(int, const char *, int))dlsym(RTLD_NEXT, "__openat64_2");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(dirfd, p, flags);
}

/*
 * __readlink_chk(path, buf, len, buflen)
 *
 * 多出的第 4 个参数是编译期已知的目标缓冲区大小，用于边界检查。
 * 转发时必须原样传下去 —— 丢掉它等于让 FORTIFY 失效（安全检查被绕过），
 * 那比不 hook 更糟：程序以为自己受保护，实际没有。
 */
ssize_t __readlink_chk(const char *path, char *buf, size_t len, size_t buflen) {
    static ssize_t (*fn)(const char *, char *, size_t, size_t) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;
    ssize_t n;

    if (fn == NULL)
        fn = (ssize_t (*)(const char *, char *, size_t, size_t))
             dlsym(RTLD_NEXT, "__readlink_chk");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    n = fn(p, buf, len, buflen);
    if (n <= 0)
        return n;

    /* 与 readlink 一致：把内核回给我们的 l2s 内部名反转译回客户视角 */
    {
        char raw[MAX_PATH_LEN];
        char fixed[MAX_PATH_LEN];
        size_t copy = (size_t)n < sizeof(raw) - 1 ? (size_t)n : sizeof(raw) - 1;

        memcpy(raw, buf, copy);
        raw[copy] = '\0';

        if (l2s_rt_rewrite_readlink(path, raw, fixed, sizeof(fixed)) == 1) {
            size_t flen = strlen(fixed);
            if (flen > len)
                flen = len;
            memcpy(buf, fixed, flen);
            return (ssize_t)flen;
        }
    }
    return n;
}

ssize_t __readlinkat_chk(int dirfd, const char *path, char *buf, size_t len,
                         size_t buflen) {
    static ssize_t (*fn)(int, const char *, char *, size_t, size_t) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;
    ssize_t n;

    if (fn == NULL)
        fn = (ssize_t (*)(int, const char *, char *, size_t, size_t))
             dlsym(RTLD_NEXT, "__readlinkat_chk");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    n = fn(dirfd, p, buf, len, buflen);
    if (n <= 0)
        return n;

    {
        char raw[MAX_PATH_LEN];
        char fixed[MAX_PATH_LEN];
        size_t copy = (size_t)n < sizeof(raw) - 1 ? (size_t)n : sizeof(raw) - 1;

        memcpy(raw, buf, copy);
        raw[copy] = '\0';

        if (l2s_rt_rewrite_readlink(path, raw, fixed, sizeof(fixed)) == 1) {
            size_t flen = strlen(fixed);
            if (flen > len)
                flen = len;
            memcpy(buf, fixed, flen);
            return (ssize_t)flen;
        }
    }
    return n;
}

/*
 * __realpath_chk(path, resolved, resolvedlen)
 *
 * 注意实时翻译方向问题：realpath 返回的是**宿主绝对路径**，
 * 客户期望看到 guest 路径。这一步的反向翻译我们暂未实现
 * （需要知道 rootfs 前缀并做前缀剥离），因此这里只做正向翻译，
 * 保持与现有 realpath hook 的行为一致 —— 不引入新的不一致。
 */
char *__realpath_chk(const char *path, char *resolved, size_t resolvedlen) {
    static char *(*fn)(const char *, char *, size_t) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (char *(*)(const char *, char *, size_t))
             dlsym(RTLD_NEXT, "__realpath_chk");
    if (fn == NULL) { errno = ENOSYS; return NULL; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(p, resolved, resolvedlen);
}

/* ------------------------------------------------------------------ */
/* Hook: __xstat 家族 —— 旧 ABI 的 stat，但 node 仍在用                 */
/* ------------------------------------------------------------------ */

/*
 * glibc 2.33 起在**新编译**的程序里移除了 __xstat，但**旧二进制**仍引用它，
 * 且 glibc 为兼容继续导出这 6 个符号。实测 rootfs 里的 node 正是这样：
 *
 *   node -> __xstat, __lxstat, __xstat64, __lxstat64   （4 个全用）
 *
 * 也就是说 Node 的 stat 调用**完全绕过**我们 hook 的 stat/lstat。
 * 不补这 6 个，fakeroot 的属主伪装对 Node 就形同虚设 ——
 * 这直接影响 dsh 自身的文件操作。
 *
 * 签名特殊：第一个参数是 `_STAT_VER` 版本号（glibc 内部约定），
 * 必须原样转发，不能丢。
 */
int __xstat(int ver, const char *path, struct stat *buf) {
    static int (*fn)(int, const char *, struct stat *) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;
    int rc;

    if (fn == NULL)
        fn = (int (*)(int, const char *, struct stat *))dlsym(RTLD_NEXT, "__xstat");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    rc = fn(ver, p, buf);
    if (rc == 0 && g_fakeroot_on)
        fakeroot_patch_stat(buf, &g_fakeroot_state);
    /* l2s：旧 ABI 家族同样要接线，否则老程序看到 st_nlink=1 */
    if (rc == 0)
        l2s_rt_patch_stat(buf, p);
    return rc;
}

int __lxstat(int ver, const char *path, struct stat *buf) {
    static int (*fn)(int, const char *, struct stat *) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;
    int rc;

    if (fn == NULL)
        fn = (int (*)(int, const char *, struct stat *))dlsym(RTLD_NEXT, "__lxstat");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    rc = fn(ver, p, buf);
    /* 与 lstat 保持一致：proot 同样对 lstat 家族做 owner 改写 */
    if (rc == 0 && g_fakeroot_on)
        fakeroot_patch_stat(buf, &g_fakeroot_state);
    /* l2s：__lxstat 是 lstat 的旧 ABI 入口，同样要抹掉 S_IFLNK */
    if (rc == 0)
        l2s_rt_patch_stat(buf, p);
    return rc;
}

int __fxstat(int ver, int fd, struct stat *buf) {
    static int (*fn)(int, int, struct stat *) = NULL;
    int rc;

    if (fn == NULL)
        fn = (int (*)(int, int, struct stat *))dlsym(RTLD_NEXT, "__fxstat");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    rc = fn(ver, fd, buf);
    if (rc == 0 && g_fakeroot_on)
        fakeroot_patch_stat(buf, &g_fakeroot_state);
    return rc;
}

int __xstat64(int ver, const char *path, struct stat64 *buf) {
    static int (*fn)(int, const char *, struct stat64 *) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;
    int rc;

    if (fn == NULL)
        fn = (int (*)(int, const char *, struct stat64 *))dlsym(RTLD_NEXT, "__xstat64");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    rc = fn(ver, p, buf);
    if (rc == 0 && g_fakeroot_on)
        fakeroot_patch_stat64(buf, &g_fakeroot_state);
    /* l2s：与 __xstat 家族一致 */
    if (rc == 0)
        l2s_rt_patch_stat((struct stat *)buf, p);
    return rc;
}

int __lxstat64(int ver, const char *path, struct stat64 *buf) {
    static int (*fn)(int, const char *, struct stat64 *) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;
    int rc;

    if (fn == NULL)
        fn = (int (*)(int, const char *, struct stat64 *))dlsym(RTLD_NEXT, "__lxstat64");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    rc = fn(ver, p, buf);
    if (rc == 0 && g_fakeroot_on)
        fakeroot_patch_stat64(buf, &g_fakeroot_state);
    /* l2s：与 __xstat 家族一致 */
    if (rc == 0)
        l2s_rt_patch_stat((struct stat *)buf, p);
    return rc;
}

int __fxstat64(int ver, int fd, struct stat64 *buf) {
    static int (*fn)(int, int, struct stat64 *) = NULL;
    int rc;

    if (fn == NULL)
        fn = (int (*)(int, int, struct stat64 *))dlsym(RTLD_NEXT, "__fxstat64");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    rc = fn(ver, fd, buf);
    if (rc == 0 && g_fakeroot_on)
        fakeroot_patch_stat64(buf, &g_fakeroot_state);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Hook: getcwd —— 12 个常用程序都调用它（覆盖率交叉验证的第一名）      */
/* ------------------------------------------------------------------ */

/*
 * 为什么它排第一：
 *
 * 我用「rootfs 里 16 个常用二进制实际引用哪些路径符号」做了一次交叉验证，
 * getcwd 被 **12 个**程序引用（ls/sh/git/python3/node/tar/...），位列榜首。
 *
 * 缺了它的后果不是"少一个功能"，而是**相对路径解析全错**：
 * 程序 `getcwd()` 拿到宿主的真实路径（例如
 * `/data/data/com.dsh.client/files/linux/ubuntu/root/x`），
 * 随后用它拼出的相对路径会带着 rootfs 前缀再进一次翻译 ——
 * 变成 `<rootfs><rootfs>/...`。
 *
 * 正确做法是把宿主路径**反向翻译**成客户视角：剥掉 rootfs 前缀。
 * 这也是反向翻译首次在本文件里出现 —— 之前所有 hook 都是正向的。
 */
char *getcwd(char *buf, size_t size) {
    static char *(*fn)(char *, size_t) = NULL;
    char tmp[MAX_PATH_LEN];
    char *r;
    const char *rootfs;
    size_t rl;

    if (fn == NULL)
        fn = (char *(*)(char *, size_t))dlsym(RTLD_NEXT, "getcwd");
    if (fn == NULL) { errno = ENOSYS; return NULL; }

    /* 允许 buf == NULL：glibc 会 malloc 一块，我们不能用栈缓冲替代 */
    if (buf == NULL)
        return fn(NULL, size);

    r = fn(buf, size);
    if (r == NULL)
        return NULL;

    /*
     * 反向翻译：剥掉 rootfs 前缀。
     *
     * 只在**组件边界**上剥（前缀后面必须是 '\0' 或 '/'），
     * 否则 `/foo/rootfsXYZ` 会被误当成 `/foo/rootfs` 下的路径。
     * 剥完如果剩空串，说明正处于 rootfs 根 —— 返回 "/"。
     */
    rootfs = g_config.rootfs ? g_config.rootfs : "";
    rl = strlen(rootfs);
    if (rl == 0)
        return r;

    if (strncmp(buf, rootfs, rl) == 0 &&
        (buf[rl] == '\0' || buf[rl] == '/')) {
        const char *rest = buf + rl;
        size_t restlen = strlen(rest);

        if (restlen == 0) {
            /* 正好在 rootfs 根 */
            if (size < 2) { errno = ERANGE; return NULL; }
            buf[0] = '/';
            buf[1] = '\0';
            return buf;
        }
        /* rest 以 '/' 开头，直接前移即可（含结尾 NUL） */
        memmove(buf, rest, restlen + 1);
        (void)tmp;
    }
    return r;
}

/*
 * Hook: canonicalize_file_name(path)
 *
 * 等价于 realpath(path, NULL)（glibc 扩展），cp/mv/stat 都在用。
 * 翻译方向与 realpath 一致。
 */
char *canonicalize_file_name(const char *path) {
    static char *(*fn)(const char *) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (char *(*)(const char *))dlsym(RTLD_NEXT, "canonicalize_file_name");
    if (fn == NULL) { errno = ENOSYS; return NULL; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(p);
}

/*
 * Hook: fstat / fstat64 / fstatat / fstatat64
 *
 * 按 fd 或 dirfd 查询。路径翻译只对带路径的那两个有意义；
 * 但**四个都要做 fakeroot 补丁** —— 否则同一文件用不同 API 查会得到
 * 不同的属主，客户立刻能看出矛盾。
 */
int fstat(int fd, struct stat *buf) {
    static int (*fn)(int, struct stat *) = NULL;
    int rc;

    if (fn == NULL)
        fn = (int (*)(int, struct stat *))dlsym(RTLD_NEXT, "fstat");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    rc = fn(fd, buf);
    if (rc == 0 && g_fakeroot_on)
        fakeroot_patch_stat(buf, &g_fakeroot_state);
    return rc;
}

int fstat64(int fd, struct stat64 *buf) {
    static int (*fn)(int, struct stat64 *) = NULL;
    int rc;

    if (fn == NULL)
        fn = (int (*)(int, struct stat64 *))dlsym(RTLD_NEXT, "fstat64");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    rc = fn(fd, buf);
    if (rc == 0 && g_fakeroot_on)
        fakeroot_patch_stat64(buf, &g_fakeroot_state);
    return rc;
}

int fstatat(int dirfd, const char *path, struct stat *buf, int flags) {
    /*
     * glibc 2.39 不导出 fstatat 本身（只有 __fxstatat / fstatat64 变体）。
     * 拿不到就退回 __fxstatat，这是它内部真正调用的。
     */
    static int (*fn)(int, const char *, struct stat *, int) = NULL;
    static int (*fn_fx)(int, int, const char *, struct stat *, int) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;
    int rc;

    if (fn == NULL && fn_fx == NULL) {
        fn = (int (*)(int, const char *, struct stat *, int))
             dlsym(RTLD_NEXT, "fstatat");
        if (fn == NULL)
            fn_fx = (int (*)(int, int, const char *, struct stat *, int))
                    dlsym(RTLD_NEXT, "__fxstatat");
    }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    if (fn != NULL) {
        rc = fn(dirfd, p, buf, flags);
    } else if (fn_fx != NULL) {
        rc = fn_fx(1 /* _STAT_VER */, dirfd, p, buf, flags);
    } else {
        errno = ENOSYS;
        return -1;
    }

    if (rc == 0 && g_fakeroot_on)
        fakeroot_patch_stat(buf, &g_fakeroot_state);
    return rc;
}

int fstatat64(int dirfd, const char *path, struct stat64 *buf, int flags) {
    static int (*fn)(int, const char *, struct stat64 *, int) = NULL;
    static int (*fn_fx)(int, int, const char *, struct stat64 *, int) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;
    int rc;

    if (fn == NULL && fn_fx == NULL) {
        fn = (int (*)(int, const char *, struct stat64 *, int))
             dlsym(RTLD_NEXT, "fstatat64");
        if (fn == NULL)
            fn_fx = (int (*)(int, int, const char *, struct stat64 *, int))
                    dlsym(RTLD_NEXT, "__fxstatat64");
    }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    if (fn != NULL) {
        rc = fn(dirfd, p, buf, flags);
    } else if (fn_fx != NULL) {
        rc = fn_fx(1 /* _STAT_VER */, dirfd, p, buf, flags);
    } else {
        errno = ENOSYS;
        return -1;
    }

    if (rc == 0 && g_fakeroot_on)
        fakeroot_patch_stat64(buf, &g_fakeroot_state);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Hook: 目录项变更家族（unlinkat/mkdir/mkdirat/rmdir/symlink 等）      */
/* ------------------------------------------------------------------ */

/*
 * 这些是覆盖率交叉验证里的高频项：
 *   unlinkat(8) mkdir(5) renameat(5) symlinkat(5)
 *   rmdir(4) rename(4) symlink(4) mkdirat(4)
 *
 * 全部只做**路径翻译**，没有额外的语义 —— 但它们必须存在，
 * 否则 `cp`/`mv`/`tar`/`git` 的目录操作会打到宿主真实路径上。
 *
 * 注意 unlinkat 有一条 l2s 语义：删除伪造硬链接时要递减链长。
 */

/* l2s 的 unlinkat 需要 path 参数；flags 里的 AT_REMOVEDIR 走不同分支 */
int unlinkat(int dirfd, const char *path, int flags) {
    static int (*fn)(int, const char *, int) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;
    int rc;

    if (fn == NULL)
        fn = (int (*)(int, const char *, int))dlsym(RTLD_NEXT, "unlinkat");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    /* 只在"删除文件"时走 l2s（AT_REMOVEDIR 删的是目录，与硬链接无关） */
    if (l2s_rt_enabled() && (flags & AT_REMOVEDIR) == 0) {
        rc = l2s_rt_unlink(p);
        if (rc == 0)
            return 0;
        if (rc != L2S_RT_PASSTHRU) {
            errno = -rc;
            return -1;
        }
    }
    return fn(dirfd, p, flags);
}

int mkdir(const char *path, mode_t mode) {
    static int (*fn)(const char *, mode_t) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (int (*)(const char *, mode_t))dlsym(RTLD_NEXT, "mkdir");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(p, mode);
}

int mkdirat(int dirfd, const char *path, mode_t mode) {
    static int (*fn)(int, const char *, mode_t) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (int (*)(int, const char *, mode_t))dlsym(RTLD_NEXT, "mkdirat");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(dirfd, p, mode);
}

int rmdir(const char *path) {
    static int (*fn)(const char *) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (int (*)(const char *))dlsym(RTLD_NEXT, "rmdir");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(p);
}

int symlink(const char *target, const char *linkpath) {
    static int (*fn)(const char *, const char *) = NULL;
    char tt[MAX_PATH_LEN], tl[MAX_PATH_LEN];
    const char *pt = target, *pl = linkpath;

    if (fn == NULL)
        fn = (int (*)(const char *, const char *))dlsym(RTLD_NEXT, "symlink");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    /*
     * 两个参数都要翻译 —— 这是最容易漏的：target 是**链接内容**，
     * 若它是绝对路径也应指向 guest 视角。但符号链接的 target 在
     * 建立时不该被改写成宿主路径（否则客户 readlink 会看到宿主路径），
     * 所以这里**只翻译 linkpath**，target 原样保留。
     */
    if (translate_path(linkpath, tl, sizeof(tl)) > 0)
        pl = tl;
    (void)tt;
    return fn(pt, pl);
}

int symlinkat(const char *target, int newdirfd, const char *linkpath) {
    static int (*fn)(const char *, int, const char *) = NULL;
    char tl[MAX_PATH_LEN];
    const char *pl = linkpath;

    if (fn == NULL)
        fn = (int (*)(const char *, int, const char *))dlsym(RTLD_NEXT, "symlinkat");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(linkpath, tl, sizeof(tl)) > 0)
        pl = tl;
    return fn(target, newdirfd, pl);
}

int rename(const char *oldpath, const char *newpath) {
    static int (*fn)(const char *, const char *) = NULL;
    char to[MAX_PATH_LEN], tn[MAX_PATH_LEN];
    const char *po = oldpath, *pn = newpath;

    if (fn == NULL)
        fn = (int (*)(const char *, const char *))dlsym(RTLD_NEXT, "rename");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(oldpath, to, sizeof(to)) > 0) po = to;
    if (translate_path(newpath, tn, sizeof(tn)) > 0) pn = tn;

    /* l2s：改名伪造硬链接时，把中间层与数据文件一起搬走（本层当前透传，
     * 理由见 l2s-runtime.c 里 l2s_rt_rename 的长注释） */
    if (l2s_rt_enabled()) {
        int rc = l2s_rt_rename(po, pn);
        if (rc == 0) return 0;
        if (rc != L2S_RT_PASSTHRU) { errno = -rc; return -1; }
    }
    return fn(po, pn);
}

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    static int (*fn)(int, const char *, int, const char *) = NULL;
    char to[MAX_PATH_LEN], tn[MAX_PATH_LEN];
    const char *po = oldpath, *pn = newpath;

    if (fn == NULL)
        fn = (int (*)(int, const char *, int, const char *))
             dlsym(RTLD_NEXT, "renameat");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(oldpath, to, sizeof(to)) > 0) po = to;
    if (translate_path(newpath, tn, sizeof(tn)) > 0) pn = tn;
    return fn(olddirfd, po, newdirfd, pn);
}

/* ------------------------------------------------------------------ */
/* Hook: 权限与时间（D6 域 —— git 可执行位、增量构建时间戳）            */
/* ------------------------------------------------------------------ */

int chmod(const char *path, mode_t mode) {
    static int (*fn)(const char *, mode_t) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;
    int rc;

    if (fn == NULL)
        fn = (int (*)(const char *, mode_t))dlsym(RTLD_NEXT, "chmod");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    rc = fn(p, mode);
    if (rc == 0 && g_fakeroot_on)
        (void)fakeroot_record_mode_path(&g_fakeroot_state, p, mode);
    return rc;
}

int fchmod(int fd, mode_t mode) {
    static int (*fn)(int, mode_t) = NULL;
    int rc;

    if (fn == NULL)
        fn = (int (*)(int, mode_t))dlsym(RTLD_NEXT, "fchmod");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    rc = fn(fd, mode);
    if (rc == 0 && g_fakeroot_on)
        (void)fakeroot_record_mode_fd(&g_fakeroot_state, fd, mode);
    return rc;
}

int fchmodat(int dirfd, const char *path, mode_t mode, int flags) {
    static int (*fn)(int, const char *, mode_t, int) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;
    int rc;

    if (fn == NULL)
        fn = (int (*)(int, const char *, mode_t, int))dlsym(RTLD_NEXT, "fchmodat");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    rc = fn(dirfd, p, mode, flags);
    if (rc == 0 && g_fakeroot_on)
        (void)fakeroot_record_mode_path(&g_fakeroot_state, p, mode);
    return rc;
}

int faccessat(int dirfd, const char *path, int mode, int flags) {
    static int (*fn)(int, const char *, int, int) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;
    int rc;

    if (fn == NULL)
        fn = (int (*)(int, const char *, int, int))dlsym(RTLD_NEXT, "faccessat");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    rc = fn(dirfd, p, mode, flags);
    if (rc == 0 || !g_fakeroot_on)
        return rc;

    /* 与 access 一致的 fakeroot 覆盖逻辑 */
    {
        struct stat st;
        int have_st = 0;
        if (real_stat != NULL && real_stat(p, &st) == 0) {
            have_st = 1;
            fakeroot_patch_stat(&st, &g_fakeroot_state);
        }
        if (fakeroot_access_override(errno, fakeroot_check_access(
                &st, mode, have_st != 0, g_fakeroot_state.euid == 0)))
            return 0;
    }
    return rc;
}

ssize_t readlinkat(int dirfd, const char *path, char *buf, size_t bufsiz) {
    static ssize_t (*fn)(int, const char *, char *, size_t) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;
    ssize_t n;

    if (fn == NULL)
        fn = (ssize_t (*)(int, const char *, char *, size_t))
             dlsym(RTLD_NEXT, "readlinkat");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    n = fn(dirfd, p, buf, bufsiz);
    if (n <= 0)
        return n;

    {
        char raw[MAX_PATH_LEN];
        char fixed[MAX_PATH_LEN];
        size_t copy = (size_t)n < sizeof(raw) - 1 ? (size_t)n : sizeof(raw) - 1;

        memcpy(raw, buf, copy);
        raw[copy] = '\0';
        if (l2s_rt_rewrite_readlink(path, raw, fixed, sizeof(fixed)) == 1) {
            size_t flen = strlen(fixed);
            if (flen > bufsiz)
                flen = bufsiz;
            memcpy(buf, fixed, flen);
            return (ssize_t)flen;
        }
    }
    return n;
}

int chdir(const char *path);   /* 已在前文定义 */

/* Hook: ioctl —— 9 个程序使用，主要影响 /dev/shm、memfd、终端 */
int ioctl(int fd, unsigned long request, ...) {
    static int (*fn)(int, unsigned long, ...) = NULL;
    va_list ap;
    void *arg;

    if (fn == NULL)
        fn = (int (*)(int, unsigned long, ...))dlsym(RTLD_NEXT, "ioctl");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    /*
     * ioctl 的参数是**变参**，且第三个参数可能是指针也可能是一个整数
     * （取决于 request）。我们无法统一翻译它 —— 盲目把它当路径翻译
     * 会破坏绝大多数 ioctl（例如 FIONREAD 传的是 int*）。
     *
     * 因此这里**只做参数搬运，不做路径翻译**。存在的意义是：
     *   1. 让 ioctl 出现在我们的符号表里，便于将来按 request 分派；
     *   2. 为 fakeroot 的 TIOCGWINSZ/终端场景留出介入点。
     *
     * 真正的路径翻译对 ioctl 基本不适用 —— 它操作的是 **fd**，不是路径。
     */
    va_start(ap, request);
    arg = va_arg(ap, void *);
    va_end(ap);

    return fn(fd, request, arg);
}

/* ------------------------------------------------------------------ */
/* exec 家族（execv / execvp / execve / execvpe）已移交给 D4 进程管理层  */
/* ------------------------------------------------------------------ */

/*
 * ★ 这里原先有 4 个钩子，现已删除 —— 不是遗漏，是有意的所有权转移 ★
 *
 * 取而代之的是 agents/proc/proc.c（P0-3 / D4 域）的同名实现，它们比
 * 这里的旧版强在三处：
 *
 *   1. **envp 重建**。旧版 `execve` 把调用方的 envp **原样转发**，
 *      于是调用方传一个干净的 envp（node 的 execFileSync、
 *      python 的 subprocess(env=...)）就足以让 LD_PRELOAD 消失 ——
 *      子进程照样启动、照样运行，只是**钩子全没了**：它看到宿主 /、
 *      stat 返回真实属主、l2s 消失，而且没有任何报错。这是最隐蔽的
 *      容器泄漏。proc.c 会强制重建 envp（并合并而非覆盖 guest 自己的
 *      LD_PRELOAD）。
 *   2. **guest PATH 搜索**。旧版 `execvp` 直接调 RTLD_NEXT 的真实
 *      `execvp`，用的是**宿主 PATH** —— 容器里的 `ls` 可能解析到宿主
 *      的 /usr/bin/ls（版本可能不同），PATH 里的目录在宿主不存在而在
 *      rootfs 存在时直接 ENOENT。proc.c 用自己的搜索 + 宿主路径探测。
 *   3. **argv[0] 与路径参数的翻译策略**（px_plan_argv / px_apply_argv）。
 *
 * 为什么必须**删除**而不是让两者共存：同名符号在同一个 .so 里是
 * `multiple definition` 硬链接错误（已实测）。所以这是一次所有权转移：
 * execve/execv/execvp/execvpe 由 proc.c 提供，preload.c 不再定义。
 *
 * 同理，本文件顶部原先的 `real_execve` / `real_execvpe` 两个函数指针
 * 与 ensure_real_functions() 里的两行 dlsym 也一并删除 ——
 * 删掉上面 4 个钩子后它们无人引用（-Wunused-variable），
 * 且 proc.c 内部自己用 `dlsym(RTLD_NEXT, "execve")` 懒加载。
 */

/* ------------------------------------------------------------------ */
/* Hook: utimensat / fchownat / statx / statvfs / statfs / truncate    */
/* ------------------------------------------------------------------ */

int utimensat(int dirfd, const char *path, const struct timespec times[2],
              int flags) {
    static int (*fn)(int, const char *, const struct timespec[2], int) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (int (*)(int, const char *, const struct timespec[2], int))
             dlsym(RTLD_NEXT, "utimensat");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    /* path 可以是 NULL（对 dirfd 本身操作），必须判空 */
    if (path != NULL && translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(dirfd, p, times, flags);
}

int fchownat(int dirfd, const char *path, uid_t uid, gid_t gid, int flags) {
    static int (*fn)(int, const char *, uid_t, gid_t, int) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;
    int rc;

    if (fn == NULL)
        fn = (int (*)(int, const char *, uid_t, gid_t, int))
             dlsym(RTLD_NEXT, "fchownat");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (path != NULL && translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    rc = fn(dirfd, p, uid, gid, flags);
    if (!g_fakeroot_on)
        return rc;

    if (rc == 0) {
        (void)fakeroot_record_owner_path(&g_fakeroot_state, p, uid, gid);
        return 0;
    }
    /* 与 chown 同策略：吞掉 EPERM/EACCES 并记账，其余如实上抛 */
    {
        int saved = errno;
        uid_t out_uid = uid;
        gid_t out_gid = gid;
        int gate = fakeroot_gate_chown(&g_fakeroot_state, NULL, uid, gid,
                                       &out_uid, &out_gid);
        if (fakeroot_chown_action(rc, saved, gate) == FR_CHOWN_FAKE_OK) {
            (void)fakeroot_record_owner_path(&g_fakeroot_state, p, uid, gid);
            return 0;
        }
        errno = saved;
    }
    return rc;
}

/*
 * statx —— ls 与 stat 在用（现代 coreutils 优先走它）。
 * 与 stat 的关键差异：statx 有自己的 struct，且带 mask 字段。
 */
int statx(int dirfd, const char *path, int flags, unsigned int mask,
          struct statx *buf) {
    static int (*fn)(int, const char *, int, unsigned int, struct statx *) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (int (*)(int, const char *, int, unsigned int, struct statx *))
             dlsym(RTLD_NEXT, "statx");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (path != NULL && translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    {
        int rc = fn(dirfd, p, flags, mask, buf);
        if (rc == 0 && g_fakeroot_on && buf != NULL) {
            /*
             * 只改写 uid/gid，且只在 mask 声明了对应字段时 ——
             * 这正是 l2s 模块里 l2s_patch_statx_nlink 采用的语义
             * （bxroot 的做法：先看 mask 再决定写不写）。
             */
            if ((buf->stx_mask & STATX_UID) != 0)
                buf->stx_uid = g_fakeroot_state.euid;
            if ((buf->stx_mask & STATX_GID) != 0)
                buf->stx_gid = g_fakeroot_state.egid;
        }

        /*
         * l2s：statx 是 coreutils 9.x / rsync / pnpm 的现代主路径，
         * 优先级高于 stat —— 不补这里，stat 补得再对也会被绕过。
         * 只在 mask 声明了 STATX_NLINK 时才改写（与 statx 语义一致：
         * mask 未声明的字段是未定义的，写进去会让客户读到垃圾）。
         */
        if (rc == 0 && buf != NULL)
            l2s_rt_patch_statx(&buf->stx_nlink, &buf->stx_mask,
                               STATX_NLINK, p);
        return rc;
    }
}

int statfs(const char *path, struct statfs *buf) {
    static int (*fn)(const char *, struct statfs *) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (int (*)(const char *, struct statfs *))dlsym(RTLD_NEXT, "statfs");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(p, buf);
}

int statvfs(const char *path, struct statvfs *buf) {
    static int (*fn)(const char *, struct statvfs *) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (int (*)(const char *, struct statvfs *))dlsym(RTLD_NEXT, "statvfs");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(p, buf);
}

int truncate(const char *path, off_t length) {
    static int (*fn)(const char *, off_t) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (int (*)(const char *, off_t))dlsym(RTLD_NEXT, "truncate");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(p, length);
}

int creat(const char *path, mode_t mode) {
    static int (*fn)(const char *, mode_t) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (int (*)(const char *, mode_t))dlsym(RTLD_NEXT, "creat");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    {
        int rc = fn(p, mode);
        if (rc >= 0 && g_fakeroot_on)
            (void)fakeroot_record_create_path(&g_fakeroot_state, p, mode,
                                              (uid_t)-1, (gid_t)-1);
        return rc;
    }
}

int renameat2(int olddirfd, const char *oldpath, int newdirfd,
              const char *newpath, unsigned int flags) {
    static int (*fn)(int, const char *, int, const char *, unsigned int) = NULL;
    char to[MAX_PATH_LEN], tn[MAX_PATH_LEN];
    const char *po = oldpath, *pn = newpath;

    if (fn == NULL)
        fn = (int (*)(int, const char *, int, const char *, unsigned int))
             dlsym(RTLD_NEXT, "renameat2");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(oldpath, to, sizeof(to)) > 0) po = to;
    if (translate_path(newpath, tn, sizeof(tn)) > 0) pn = tn;
    return fn(olddirfd, po, newdirfd, pn, flags);
}

/* ------------------------------------------------------------------ */
/* Hook: 动态链接 dl* —— .node 原生模块加载的必经之路                   */
/* ------------------------------------------------------------------ */

/*
 * 为什么 dlopen 必须翻译路径（被 10 个程序引用）：
 *
 * Node 的 `.node` 原生模块（node-pty / koffi / sharp / better-sqlite3 …）
 * 是通过 dlopen 加载的。DSHA 的 PTY 终端、原生扩展全靠它。
 * 不翻译路径，dlopen 会拿到 guest 路径去宿主找 —— 找不到，
 * 表现为 "Cannot find module xxx.node" 这类看起来像缺文件、
 * 实际是路径没翻译的错误。
 *
 * ★ 红线提醒 ★
 * 本文件**只做路径翻译**，绝不实现符号解析。
 * 早先项目里 linker.c 曾被要求"返回我们的 hook"、stub-loader.c 曾被要求
 * "完整实现 mmap + 符号解析" —— 那两条是红线，会重现官方 issue #23/#24
 * （自研 ELF 重定位器的 TlsDTPMOD / TLS surplus 等一连串问题）。
 * bxroot 的结构性优势就在于**交给 glibc 原生 ld.so**，dlopen/dlsym
 * 一律纯转发。
 */

void *dlopen(const char *filename, int flags) {
    static void *(*fn)(const char *, int) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = filename;

    if (fn == NULL)
        fn = (void *(*)(const char *, int))dlsym(RTLD_NEXT, "dlopen");
    if (fn == NULL) { errno = ENOSYS; return NULL; }

    /* filename 可以为 NULL（获取主程序句柄），必须判空 */
    if (filename != NULL && translate_path(filename, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(p, flags);
}

/*
 * dlsym / dlerror —— 纯转发，**不做任何符号解析**。
 *
 * 导出它们的原因不是路径翻译（它们没有路径参数），而是：
 *   1. 官方导出了，为对齐符号表；
 *   2. 某些程序会 dlsym(RTLD_DEFAULT, "dlsym") 探测 —— 缺失会走进意外分支。
 * 实现上就是转发，一行逻辑都不加。
 */
void *dlsym(void *handle, const char *symbol) {
    static void *(*fn)(void *, const char *) = NULL;

    if (fn == NULL)
        fn = (void *(*)(void *, const char *))dlsym(RTLD_NEXT, "dlsym");
    if (fn == NULL) { errno = ENOSYS; return NULL; }
    return fn(handle, symbol);
}

char *dlerror(void) {
    static char *(*fn)(void) = NULL;

    if (fn == NULL)
        fn = (char *(*)(void))dlsym(RTLD_NEXT, "dlerror");
    if (fn == NULL) return NULL;
    return fn();
}

int dladdr(const void *addr, Dl_info *info) {
    static int (*fn)(const void *, Dl_info *) = NULL;

    if (fn == NULL)
        fn = (int (*)(const void *, Dl_info *))dlsym(RTLD_NEXT, "dladdr");
    if (fn == NULL) return 0;
    return fn(addr, info);
}

int dl_iterate_phdr(int (*callback)(struct dl_phdr_info *, size_t, void *),
                    void *data) {
    static int (*fn)(int (*)(struct dl_phdr_info *, size_t, void *), void *) = NULL;

    if (fn == NULL)
        fn = (int (*)(int (*)(struct dl_phdr_info *, size_t, void *), void *))
             dlsym(RTLD_NEXT, "dl_iterate_phdr");
    if (fn == NULL) return 0;
    return fn(callback, data);
}

/* ------------------------------------------------------------------ */
/* Hook: nocancel 变体 —— 高频（不可取消的内部路径）                    */
/* ------------------------------------------------------------------ */

/*
 * glibc 内部大量使用 `__open_nocancel` / `__open64_nocancel`：
 * 它们是"不被信号中断"的 open，被 stdio、目录遍历、NSS 等广泛调用。
 * 不 hook 它们，很多内部打开会绕过翻译。
 */
int __open_nocancel(const char *path, int flags, mode_t mode) {
    static int (*fn)(const char *, int, mode_t) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (int (*)(const char *, int, mode_t))dlsym(RTLD_NEXT, "__open_nocancel");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(p, flags, mode);
}

int __open64_nocancel(const char *path, int flags, mode_t mode) {
    static int (*fn)(const char *, int, mode_t) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (int (*)(const char *, int, mode_t))dlsym(RTLD_NEXT, "__open64_nocancel");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(p, flags, mode);
}

char *__getcwd_chk(char *buf, size_t size, size_t buflen) {
    /* 边界检查版 getcwd；转发后复用 getcwd 的反向翻译逻辑 */
    (void)buflen;
    return getcwd(buf, size);
}

/* ------------------------------------------------------------------ */
/* Hook: 临时文件家族 —— 被 8+ 程序引用，且都是路径                       */
/* ------------------------------------------------------------------ */

/*
 * mkstemp/mkdtemp 家族的参数是**可写的模板字符串**（结尾 XXXXXX 会被原地改写），
 * 所以不能简单翻译 —— 必须：
 *   1. 在本地缓冲里做翻译
 *   2. 调用真实函数
 *   3. 把结果（路径已被原地改写）**反向翻译**后写回调用方的缓冲
 *
 * 漏掉第 3 步是个隐蔽错误：调用方会拿到宿主路径，
 * 之后用它 open() 时又被加一次 rootfs 前缀。
 */
static void fr_strip_rootfs_inplace(char *buf, size_t bufsz)
{
    const char *rootfs = g_config.rootfs ? g_config.rootfs : "";
    size_t rl = strlen(rootfs);
    size_t len;

    if (rl == 0)
        return;
    len = strnlen(buf, bufsz);
    if (len < rl)
        return;
    if (strncmp(buf, rootfs, rl) != 0)
        return;
    if (buf[rl] != '\0' && buf[rl] != '/')
        return;

    if (buf[rl] == '\0') {
        if (bufsz >= 2) { buf[0] = '/'; buf[1] = '\0'; }
        return;
    }
    {
        size_t restlen = len - rl;
        memmove(buf, buf + rl, restlen + 1);
    }
}

int mkstemp(char *template) {
    static int (*fn)(char *) = NULL;
    char local[MAX_PATH_LEN];
    int rc;

    if (fn == NULL)
        fn = (int (*)(char *))dlsym(RTLD_NEXT, "mkstemp");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(template, local, sizeof(local)) <= 0)
        return fn(template);   /* 相对路径：原样 */

    rc = fn(local);
    /* 无论成败都把改写过/翻译过的结果回写 —— 成功时 local 是新文件名 */
    fr_strip_rootfs_inplace(local, sizeof(local));
    {
        size_t n = strlen(local);
        size_t cap = strlen(template);
        if (n <= cap)
            memcpy(template, local, n + 1);
    }
    return rc;
}

char *mkdtemp(char *template) {
    static char *(*fn)(char *) = NULL;
    char local[MAX_PATH_LEN];
    char *rc;

    if (fn == NULL)
        fn = (char *(*)(char *))dlsym(RTLD_NEXT, "mkdtemp");
    if (fn == NULL) { errno = ENOSYS; return NULL; }

    if (translate_path(template, local, sizeof(local)) <= 0)
        return fn(template);

    rc = fn(local);
    if (rc == NULL)
        return NULL;

    fr_strip_rootfs_inplace(local, sizeof(local));
    {
        size_t n = strlen(local);
        size_t cap = strlen(template);
        if (n <= cap)
            memcpy(template, local, n + 1);
    }
    return template;
}

int mkstemps(char *template, int suffixlen) {
    static int (*fn)(char *, int) = NULL;
    char local[MAX_PATH_LEN];
    int rc;

    if (fn == NULL)
        fn = (int (*)(char *, int))dlsym(RTLD_NEXT, "mkstemps");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(template, local, sizeof(local)) <= 0)
        return fn(template, suffixlen);

    rc = fn(local, suffixlen);
    fr_strip_rootfs_inplace(local, sizeof(local));
    {
        size_t n = strlen(local);
        size_t cap = strlen(template);
        if (n <= cap)
            memcpy(template, local, n + 1);
    }
    return rc;
}

int mkostemp(char *template, int flags) {
    static int (*fn)(char *, int) = NULL;
    char local[MAX_PATH_LEN];
    int rc;

    if (fn == NULL)
        fn = (int (*)(char *, int))dlsym(RTLD_NEXT, "mkostemp");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(template, local, sizeof(local)) <= 0)
        return fn(template, flags);

    rc = fn(local, flags);
    fr_strip_rootfs_inplace(local, sizeof(local));
    {
        size_t n = strlen(local);
        size_t cap = strlen(template);
        if (n <= cap)
            memcpy(template, local, n + 1);
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* Hook: fchdir —— 17 个程序引用，改变进程 cwd 影响后续所有相对路径    */
/* ------------------------------------------------------------------ */

int fchdir(int fd) {
    static int (*fn)(int) = NULL;

    if (fn == NULL)
        fn = (int (*)(int))dlsym(RTLD_NEXT, "fchdir");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    /*
     * fd 已经是打开好的描述符，里面的路径早已翻译过 —— 不需要也不应该
     * 再翻译。存在的意义是：如果将来要维护"虚拟 cwd"（官方有
     * set_virtual_cwd / refresh_virtual_cwd_from_kernel），这里是入口。
     */
    return fn(fd);
}

/* ------------------------------------------------------------------ */
/* Hook: xattr 家族 —— 8 个，全部带路径参数                             */
/* ------------------------------------------------------------------ */

/*
 * 引用数（覆盖率扫描）：ls/python3/tar 都用到 listxattr/getxattr。
 *
 * 为什么必须翻译：xattr 的路径参数与 open 同等地位。
 * `tar --xattrs`（备份还原常用）、`cp --preserve=xattr`、
 * Python 的 shutil.copy2 在某些平台上都会走这些。
 *
 * 不翻译的后果与普通文件操作相同：打到宿主真实路径上。
 *
 * 注意 f/l 前缀的三种变体语义不同：
 *   xxxattr(path, ...)   —— 跟随符号链接
 *   lxxxattr(path, ...)  —— 不跟随（作用于链接本身）
 *   fxxxattr(fd, ...)    —— 作用于 fd，**无路径参数，不需要翻译**
 *
 * 因此 f* 变体不在这里实现（官方也未导出 fgetxattr/fsetxattr 等）。
 */

ssize_t getxattr(const char *path, const char *name, void *value, size_t size) {
    static ssize_t (*fn)(const char *, const char *, void *, size_t) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (ssize_t (*)(const char *, const char *, void *, size_t))
             dlsym(RTLD_NEXT, "getxattr");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(p, name, value, size);
}

ssize_t lgetxattr(const char *path, const char *name, void *value, size_t size) {
    static ssize_t (*fn)(const char *, const char *, void *, size_t) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (ssize_t (*)(const char *, const char *, void *, size_t))
             dlsym(RTLD_NEXT, "lgetxattr");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(p, name, value, size);
}

int setxattr(const char *path, const char *name, const void *value,
             size_t size, int flags) {
    static int (*fn)(const char *, const char *, const void *, size_t, int) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (int (*)(const char *, const char *, const void *, size_t, int))
             dlsym(RTLD_NEXT, "setxattr");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(p, name, value, size, flags);
}

int lsetxattr(const char *path, const char *name, const void *value,
              size_t size, int flags) {
    static int (*fn)(const char *, const char *, const void *, size_t, int) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (int (*)(const char *, const char *, const void *, size_t, int))
             dlsym(RTLD_NEXT, "lsetxattr");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(p, name, value, size, flags);
}

ssize_t listxattr(const char *path, char *list, size_t size) {
    static ssize_t (*fn)(const char *, char *, size_t) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (ssize_t (*)(const char *, char *, size_t))
             dlsym(RTLD_NEXT, "listxattr");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(p, list, size);
}

ssize_t llistxattr(const char *path, char *list, size_t size) {
    static ssize_t (*fn)(const char *, char *, size_t) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (ssize_t (*)(const char *, char *, size_t))
             dlsym(RTLD_NEXT, "llistxattr");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(p, list, size);
}

int removexattr(const char *path, const char *name) {
    static int (*fn)(const char *, const char *) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (int (*)(const char *, const char *))dlsym(RTLD_NEXT, "removexattr");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(p, name);
}

int lremovexattr(const char *path, const char *name) {
    static int (*fn)(const char *, const char *) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (int (*)(const char *, const char *))dlsym(RTLD_NEXT, "lremovexattr");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(p, name);
}

/* Hook: inotify_add_watch —— node 的文件监听（dsh 可能用于热重载） */
int inotify_add_watch(int fd, const char *path, uint32_t mask) {
    static int (*fn)(int, const char *, uint32_t) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (int (*)(int, const char *, uint32_t))dlsym(RTLD_NEXT, "inotify_add_watch");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(fd, p, mask);
}

/* Hook: scandir —— 接受目录路径与过滤/排序回调 */
int scandir(const char *dirp, struct dirent ***namelist,
            int (*filter)(const struct dirent *),
            int (*compar)(const struct dirent **, const struct dirent **)) {
    static int (*fn)(const char *, struct dirent ***,
                     int (*)(const struct dirent *),
                     int (*)(const struct dirent **, const struct dirent **)) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = dirp;

    if (fn == NULL)
        fn = (int (*)(const char *, struct dirent ***,
                      int (*)(const struct dirent *),
                      int (*)(const struct dirent **, const struct dirent **)))
             dlsym(RTLD_NEXT, "scandir");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(dirp, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(p, namelist, filter, compar);
}

/* ------------------------------------------------------------------ */
/* Hook: 64 位 statfs/statvfs 变体 + 身份查询                          */
/* ------------------------------------------------------------------ */

int statfs64(const char *path, struct statfs64 *buf) {
    static int (*fn)(const char *, struct statfs64 *) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (int (*)(const char *, struct statfs64 *))dlsym(RTLD_NEXT, "statfs64");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(p, buf);
}

int statvfs64(const char *path, struct statvfs64 *buf) {
    static int (*fn)(const char *, struct statvfs64 *) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (int (*)(const char *, struct statvfs64 *))dlsym(RTLD_NEXT, "statvfs64");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(p, buf);
}

/*
 * getpwuid —— 被 **27 个程序**引用（覆盖率扫描第一名）。
 *
 * 为什么 fakeroot 必须接管它：
 * 程序用 getpwuid(getuid()) 反查「我是谁」，然后拿结果决定行为 ——
 * 例如 `git` 判断 committer、shell 决定提示符、install 类工具决定是否
 * 以 root 运行。我们伪装 uid=0，如果 getpwuid 返回的是 Android 应用
 * 用户的记录（uid 2000），程序立刻发现矛盾：
 *
 *     getuid() == 0  →  但 getpwuid(0) 返回 NULL 或 uid=2000 的记录
 *
 * 这种矛盾会让 sudo/login/install 类程序直接拒绝工作 —— 正是上游
 * issue #12 的另一种表现。
 *
 * 策略：请求 uid 等于我们的假 uid 时，返回一条合成的 "root" 记录。
 * 不修改真实 passwd 数据库（那会污染宿主）。
 *
 * 注意返回的是**指向静态存储的指针**（getpwuid 的既有契约），
 * 我们用自己的静态缓冲，不覆盖 glibc 的 —— 因为调用方可能同时持有
 * 两个不同 uid 的返回结果（少见但合法）。
 */
struct passwd *getpwuid(uid_t uid) {
    static struct passwd *(*fnsym)(uid_t) = NULL;
    static char name_buf[32];
    static char dir_buf[8] = "/root";
    static char shell_buf[16] = "/bin/sh";
    static struct passwd fake;
    struct passwd *real;

    if (fnsym == NULL)
        fnsym = (struct passwd *(*)(uid_t))dlsym(RTLD_NEXT, "getpwuid");
    if (fnsym == NULL) { errno = ENOSYS; return NULL; }

    real = fnsym(uid);

    /*
     * 只在「fakeroot 启用」且「请求的正是我们伪装的 uid」
     * 且「真实查询失败或不匹配」时才合成。
     *
     * 若真实数据库里恰好有这条记录（例如宿主真有 uid 0 的记录），
     * 直接用真实的 —— 那更完整，没必要造假。
     */
    if (!g_fakeroot_on || real != NULL)
        return real;

    if (uid != g_fakeroot_state.euid)
        return real;   /* 不是我们在伪装的那个 uid，如实返回 NULL */

    memcpy(name_buf, "root", 5);
    fake.pw_name   = name_buf;
    fake.pw_passwd = name_buf;
    fake.pw_uid    = uid;
    fake.pw_gid    = g_fakeroot_state.egid;
    fake.pw_gecos  = name_buf;
    fake.pw_dir    = dir_buf;
    fake.pw_shell  = shell_buf;
    return &fake;
}

/* getpwuid_r 的可重入版本 —— 有些程序只用它 */
int getpwuid_r(uid_t uid, struct passwd *pwd, char *buf, size_t buflen,
               struct passwd **result) {
    static int (*fn)(uid_t, struct passwd *, char *, size_t, struct passwd **) = NULL;
    int rc;

    if (fn == NULL)
        fn = (int (*)(uid_t, struct passwd *, char *, size_t, struct passwd **))
             dlsym(RTLD_NEXT, "getpwuid_r");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    rc = fn(uid, pwd, buf, buflen, result);

    /* 真实查询成功就直接用 */
    if (rc == 0 && result != NULL && *result != NULL)
        return rc;

    if (!g_fakeroot_on || uid != g_fakeroot_state.euid)
        return rc;

    /* 合成一条写进调用方提供的缓冲 —— 这是 _r 版本的契约 */
    {
        static const char nm[] = "root";
        static const char dr[] = "/root";
        static const char sh[] = "/bin/sh";
        size_t need = sizeof(nm) + sizeof(dr) + sizeof(sh);
        char *w = buf;

        if (pwd == NULL || buf == NULL || result == NULL || buflen < need)
            return ERANGE;

        memcpy(w, nm, sizeof(nm)); pwd->pw_name = w; w += sizeof(nm);
        memcpy(w, dr, sizeof(dr)); pwd->pw_dir  = w; w += sizeof(dr);
        memcpy(w, sh, sizeof(sh)); pwd->pw_shell= w;

        pwd->pw_passwd = pwd->pw_name;
        pwd->pw_gecos  = pwd->pw_name;
        pwd->pw_uid    = uid;
        pwd->pw_gid    = g_fakeroot_state.egid;
        *result = pwd;
    }
    return 0;
}

/*
 * getresuid / getresgid —— fakeroot 的四个 uid 必须自洽。
 *
 * 早先只 hook 了 getuid/geteuid 等单个查询。但程序常成组地用
 * getresuid 一次拿全部三个（real/effective/saved）来判断自己
 * 「是不是真的降权了」—— dpkg 的 postinst 就这么做。
 * 只伪装单个而漏掉这组，立刻被看出矛盾。
 */
int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid) {
    if (g_fakeroot_on) {
        if (ruid != NULL) *ruid = g_fakeroot_state.ruid;
        if (euid != NULL) *euid = g_fakeroot_state.euid;
        if (suid != NULL) *suid = g_fakeroot_state.suid;
        return 0;
    }
    {
        static int (*fn)(uid_t *, uid_t *, uid_t *) = NULL;
        if (fn == NULL)
            fn = (int (*)(uid_t *, uid_t *, uid_t *))dlsym(RTLD_NEXT, "getresuid");
        if (fn == NULL) { errno = ENOSYS; return -1; }
        return fn(ruid, euid, suid);
    }
}

int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid) {
    if (g_fakeroot_on) {
        if (rgid != NULL) *rgid = g_fakeroot_state.rgid;
        if (egid != NULL) *egid = g_fakeroot_state.egid;
        if (sgid != NULL) *sgid = g_fakeroot_state.sgid;
        return 0;
    }
    {
        static int (*fn)(gid_t *, gid_t *, gid_t *) = NULL;
        if (fn == NULL)
            fn = (int (*)(gid_t *, gid_t *, gid_t *))dlsym(RTLD_NEXT, "getresgid");
        if (fn == NULL) { errno = ENOSYS; return -1; }
        return fn(rgid, egid, sgid);
    }
}

/* getgroups —— 补充组集合，fakeroot 状态下返回我们维护的那份 */
int getgroups(int size, gid_t list[]) {
    if (g_fakeroot_on) {
        int n = g_fakeroot_state.ngroups;
        if (size == 0)
            return n;
        if (size < n) { errno = EINVAL; return -1; }
        if (list != NULL && n > 0)
            memcpy(list, g_fakeroot_state.groups, (size_t)n * sizeof(gid_t));
        return n;
    }
    {
        static int (*fn)(int, gid_t[]) = NULL;
        if (fn == NULL)
            fn = (int (*)(int, gid_t[]))dlsym(RTLD_NEXT, "getgroups");
        if (fn == NULL) { errno = ENOSYS; return -1; }
        return fn(size, list);
    }
}

/* ------------------------------------------------------------------ */
/* Hook: 环境变量家族 —— fakeroot/l2s 的一致性依赖                     */
/* ------------------------------------------------------------------ */

/*
 * 为什么环境变量要被 hook（setenv 被 9 个程序引用）：
 *
 * 我们靠 `LD_PRELOAD` + `BXROOT_*` 传递运行时状态。如果子进程用
 * `clearenv()` 清空环境、或用 `setenv(LD_PRELOAD, "")` 覆盖它，
 * 那么**孙进程就完全没有钩子了** —— 容器在那一步静默失效。
 *
 * 这不是假想：程序确实会 clearenv（安全敏感的工具常见做法），
 * 也会通过 setenv 构造干净环境再 exec。
 *
 * 策略：**放行调用方的意图，但保证我们的关键变量始终在场**。
 * 即在 setenv/unsetenv/putenv/clearenv 之后重新注入 LD_PRELOAD 与
 * BXROOT_ROOTFS —— 因为运行时的存在性是容器正确性的前提，
 * 优先级高于调用方"想要干净环境"的意愿。
 *
 * 注：`LD_PRELOAD` 只在**当前进程**的环境副本里恢复，不影响已经在跑的
 * 进程（动态链接器只在 exec 时读它）。所以对当前进程无害。
 */
static const char *const FR_CRITICAL_ENV[] = {
    "LD_PRELOAD",
    "BXROOT_ROOTFS",
    "BXROOT_LINK2SYMLINK",
    "BXROOT_L2S_DIR",
    "BXROOT_FAKEROOT",
    NULL
};

/* 记住我们被加载时这几个变量的值，用于重注入 */
static char *g_env_saved[6] = { NULL, NULL, NULL, NULL, NULL, NULL };
static int   g_env_captured = 0;

static void fr_capture_env(void)
{
    int i;
    if (g_env_captured)
        return;
    for (i = 0; FR_CRITICAL_ENV[i] != NULL; i++) {
        const char *v = getenv(FR_CRITICAL_ENV[i]);
        g_env_saved[i] = (v != NULL) ? strdup(v) : NULL;
    }
    g_env_captured = 1;
}

static void fr_reinject_env(void)
{
    static int (*real_setenv)(const char *, const char *, int) = NULL;
    int i;

    if (!g_env_captured)
        return;
    if (real_setenv == NULL)
        real_setenv = (int (*)(const char *, const char *, int))
                      dlsym(RTLD_NEXT, "setenv");
    if (real_setenv == NULL)
        return;

    for (i = 0; FR_CRITICAL_ENV[i] != NULL; i++) {
        if (g_env_saved[i] != NULL)
            (void)real_setenv(FR_CRITICAL_ENV[i], g_env_saved[i], 1);
    }
}

int setenv(const char *name, const char *value, int overwrite) {
    static int (*fn)(const char *, const char *, int) = NULL;
    int rc;

    fr_capture_env();
    if (fn == NULL)
        fn = (int (*)(const char *, const char *, int))dlsym(RTLD_NEXT, "setenv");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    rc = fn(name, value, overwrite);

    /* 若被改的正是我们的关键变量，立刻恢复 —— 不能让它被改掉 */
    if (rc == 0 && name != NULL && g_env_captured) {
        int i;
        for (i = 0; FR_CRITICAL_ENV[i] != NULL; i++) {
            if (strcmp(name, FR_CRITICAL_ENV[i]) == 0) {
                if (g_env_saved[i] != NULL)
                    (void)fn(name, g_env_saved[i], 1);
                break;
            }
        }
    }
    return rc;
}

int unsetenv(const char *name) {
    static int (*fn)(const char *) = NULL;
    int rc;

    fr_capture_env();
    if (fn == NULL)
        fn = (int (*)(const char *))dlsym(RTLD_NEXT, "unsetenv");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    rc = fn(name);
    if (name != NULL && g_env_captured) {
        int i;
        for (i = 0; FR_CRITICAL_ENV[i] != NULL; i++) {
            if (strcmp(name, FR_CRITICAL_ENV[i]) == 0) {
                fr_reinject_env();
                break;
            }
        }
    }
    return rc;
}

int putenv(char *string) {
    static int (*fn)(char *) = NULL;
    int rc;

    fr_capture_env();
    if (fn == NULL)
        fn = (int (*)(char *))dlsym(RTLD_NEXT, "putenv");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    rc = fn(string);
    fr_reinject_env();
    return rc;
}

int clearenv(void) {
    static int (*fn)(void) = NULL;
    int rc;

    fr_capture_env();
    if (fn == NULL)
        fn = (int (*)(void))dlsym(RTLD_NEXT, "clearenv");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    rc = fn();
    /*
     * clearenv 之后**必须**重注入 —— 否则从这一刻起，
     * 本进程后续 exec 出去的每一个子进程都没有钩子。
     * 这是最危险的一个：调用方以为环境干净了，实际我们把它恢复了，
     * 但对我们来说这是**正确**的（容器不能因为 clearenv 就消失）。
     */
    fr_reinject_env();
    return rc;
}

/* ------------------------------------------------------------------ */
/* Hook: fd 操作家族 —— 纯转发，为状态一致性而导出                     */
/* ------------------------------------------------------------------ */

/*
 * 官方导出 close(120B)/dup(140B)/dup3 等，反汇编显示 close 做的是
 * **资源清理记账**（bxroot_drm_on_close / seat_on_close /
 * netlink_on_close / x11_on_close），然后转发。
 *
 * bxroot 目前没有需要清理的 fd 关联状态（l2s 是路径级、fakeroot 是
 * inode/fd 级但无需在 close 时清理），所以这些是**真正的薄转发**。
 *
 * 导出它们的理由：
 *   1. parity —— 官方导出了，符号表要对齐；
 *   2. 有些程序 dlsym(RTLD_DEFAULT, "dup2") 探测；
 *   3. 为将来预留介入点（若加了 fd→路径映射，close 是清理点）。
 */
int close(int fd) {
    static int (*fn)(int) = NULL;
    if (fn == NULL)
        fn = (int (*)(int))dlsym(RTLD_NEXT, "close");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(fd);
}

int dup(int oldfd) {
    static int (*fn)(int) = NULL;
    if (fn == NULL)
        fn = (int (*)(int))dlsym(RTLD_NEXT, "dup");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(oldfd);
}

int dup2(int oldfd, int newfd) {
    static int (*fn)(int, int) = NULL;
    if (fn == NULL)
        fn = (int (*)(int, int))dlsym(RTLD_NEXT, "dup2");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(oldfd, newfd);
}

int dup3(int oldfd, int newfd, int flags) {
    static int (*fn)(int, int, int) = NULL;
    if (fn == NULL)
        fn = (int (*)(int, int, int))dlsym(RTLD_NEXT, "dup3");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(oldfd, newfd, flags);
}

int fcntl(int fd, int cmd, ...) {
    static int (*fn)(int, int, ...) = NULL;
    va_list ap;
    void *arg;

    if (fn == NULL)
        fn = (int (*)(int, int, ...))dlsym(RTLD_NEXT, "fcntl");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    /* 变参原样搬运 —— fcntl 的第三参数类型随 cmd 变化，不能统一处理 */
    va_start(ap, cmd);
    arg = va_arg(ap, void *);
    va_end(ap);
    return fn(fd, cmd, arg);
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt) {
    static ssize_t (*fn)(int, const struct iovec *, int) = NULL;
    if (fn == NULL)
        fn = (ssize_t (*)(int, const struct iovec *, int))dlsym(RTLD_NEXT, "writev");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(fd, iov, iovcnt);
}

/* ------------------------------------------------------------------ */
/* ------------------------------------------------------------------ */
/* Hook: 资源限制 —— node/python3 会调 setrlimit（文件描述符上限）      */
/* ------------------------------------------------------------------ */

/*
 * 签名必须用 glibc 的 **__rlimit_resource_t**（一个 enum），不能用 int ——
 * glibc 在 sys/resource.h:50 就是这么声明的，写成 int 会报类型冲突。
 * 另外某些配置下 getrlimit 会被 __REDIRECT 到 getrlimit64，
 * 所以两个都要导出，否则符号表里可能缺一个。
 */
int getrlimit(__rlimit_resource_t resource, struct rlimit *rlim) {
    static int (*fn)(__rlimit_resource_t, struct rlimit *) = NULL;
    if (fn == NULL)
        fn = (int (*)(__rlimit_resource_t, struct rlimit *))
             dlsym(RTLD_NEXT, "getrlimit");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(resource, rlim);
}

int setrlimit(__rlimit_resource_t resource, const struct rlimit *rlim) {
    static int (*fn)(__rlimit_resource_t, const struct rlimit *) = NULL;
    if (fn == NULL)
        fn = (int (*)(__rlimit_resource_t, const struct rlimit *))
             dlsym(RTLD_NEXT, "setrlimit");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    /*
     * 纯转发。官方在这里会打日志并可能**调整值** ——
     * 它的动机是 guest 想要的 fd 上限可能超过宿主允许的
     * （Android 对每个进程的 fd 数量有限制，而 node/pnpm 会要很高）。
     * bxroot 目前如实转发；若真机上遇到 EPERM，这里是介入点。
     */
    return fn(resource, rlim);
}

int getrlimit64(__rlimit_resource_t resource, struct rlimit64 *rlim) {
    static int (*fn)(__rlimit_resource_t, struct rlimit64 *) = NULL;
    if (fn == NULL)
        fn = (int (*)(__rlimit_resource_t, struct rlimit64 *))
             dlsym(RTLD_NEXT, "getrlimit64");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(resource, rlim);
}

int setrlimit64(__rlimit_resource_t resource, const struct rlimit64 *rlim) {
    static int (*fn)(__rlimit_resource_t, const struct rlimit64 *) = NULL;
    if (fn == NULL)
        fn = (int (*)(__rlimit_resource_t, const struct rlimit64 *))
             dlsym(RTLD_NEXT, "setrlimit64");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(resource, rlim);
}

/* ------------------------------------------------------------------ */
/* Hook: 网络 IPC —— AF_UNIX 路径必须翻译                              */
/* ------------------------------------------------------------------ */

/*
 * 为什么 socket 家族也要 hook：
 *
 * **`bind()` 与 `connect()` 对 AF_UNIX 域接受路径参数**。若不翻译，
 * 容器内的进程会在宿主的文件系统上创建/连接 Unix socket —— 这是
 * 真实的隔离缺口：dsh 的插件通信、Node 的 IPC、Python 的 multiprocessing
 * 都可能用 AF_UNIX。
 *
 * 但**不能无脑翻译**：
 *   - AF_INET/AF_INET6 的地址是 `sockaddr_in`（IP + 端口），不是路径
 *   - AF_UNIX 的**抽象命名空间**（sun_path[0] == '\0'）根本不是文件路径，
 *     翻译它会破坏语义
 *   - 只有 `AF_UNIX` + `sun_path[0] != '\0'` 才是真正的文件路径
 *
 * 所以要先看 family，再看是不是抽象命名空间，再决定翻译。
 * 这里用一个保守策略：**只处理明确是文件路径的情况**，其余原样转发。
 *
 * 注：官方有 `BXROOT_FAIL_NETLINK_SOCKET` / `BXROOT_FAKE_NETLINK_BIND`
 * 等开关，说明它对 netlink 做了特殊处理（getifaddrs 依赖 netlink）。
 * 我们暂不伪造 netlink —— 那属于"让容器看起来有自己的网络栈"，
 * 与路径隔离是两件事。
 */

/* 判断 sockaddr 是否是 AF_UNIX 的文件路径（非抽象命名空间） */
static int is_unix_path_sockaddr(const struct sockaddr *addr, socklen_t len,
                                 const char **out_path, size_t *out_off)
{
    const struct sockaddr_un *un;

    if (addr == NULL || addr->sa_family != AF_UNIX)
        return 0;
    /* 至少要能装下 sun_family + 1 字节路径 */
    if (len <= (socklen_t)offsetof(struct sockaddr_un, sun_path) + 1)
        return 0;

    un = (const struct sockaddr_un *)addr;

    /* 抽象命名空间：sun_path[0] == '\\0'，不是文件路径，不翻译 */
    if (un->sun_path[0] == '\0')
        return 0;

    /* 必须是以 NUL 结尾的路径（否则是未终止的 Linux 扩展用法，保守跳过） */
    if (memchr(un->sun_path, '\0',
               (size_t)len - offsetof(struct sockaddr_un, sun_path)) == NULL)
        return 0;

    *out_path = un->sun_path;
    *out_off  = offsetof(struct sockaddr_un, sun_path);
    return 1;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    static int (*fn)(int, const struct sockaddr *, socklen_t) = NULL;
    const char *path = NULL;
    size_t off = 0;

    if (fn == NULL)
        fn = (int (*)(int, const struct sockaddr *, socklen_t))
             dlsym(RTLD_NEXT, "bind");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (is_unix_path_sockaddr(addr, addrlen, &path, &off)) {
        char translated[MAX_PATH_LEN];
        char buf[sizeof(struct sockaddr_un) + MAX_PATH_LEN];
        struct sockaddr_un *copy;

        if (translate_path(path, translated, sizeof(translated)) > 0) {
            size_t tl = strlen(translated);

            /* 翻译后可能超过 sun_path 的 108 字节上限 —— 那就如实报错，
             * 而不是截断（截断会静默连到错误的 socket） */
            if (off + tl + 1 > sizeof(copy->sun_path)) {
                errno = ENAMETOOLONG;
                return -1;
            }
            if (off + tl + 1 > sizeof(buf)) {
                errno = ENAMETOOLONG;
                return -1;
            }

            memset(buf, 0, sizeof(buf));
            memcpy(buf, addr, off);
            memcpy(buf + off, translated, tl + 1);
            copy = (struct sockaddr_un *)buf;

            return fn(sockfd, (const struct sockaddr *)copy,
                      (socklen_t)(off + tl + 1));
        }
    }
    return fn(sockfd, addr, addrlen);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    static int (*fn)(int, const struct sockaddr *, socklen_t) = NULL;
    const char *path = NULL;
    size_t off = 0;

    if (fn == NULL)
        fn = (int (*)(int, const struct sockaddr *, socklen_t))
             dlsym(RTLD_NEXT, "connect");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (is_unix_path_sockaddr(addr, addrlen, &path, &off)) {
        char translated[MAX_PATH_LEN];
        char buf[sizeof(struct sockaddr_un) + MAX_PATH_LEN];
        struct sockaddr_un *copy;

        if (translate_path(path, translated, sizeof(translated)) > 0) {
            size_t tl = strlen(translated);

            if (off + tl + 1 > sizeof(copy->sun_path) ||
                off + tl + 1 > sizeof(buf)) {
                errno = ENAMETOOLONG;
                return -1;
            }
            memset(buf, 0, sizeof(buf));
            memcpy(buf, addr, off);
            memcpy(buf + off, translated, tl + 1);
            copy = (struct sockaddr_un *)buf;

            return fn(sockfd, (const struct sockaddr *)copy,
                      (socklen_t)(off + tl + 1));
        }
    }
    return fn(sockfd, addr, addrlen);
}

/*
 * socket / getsockname / getsockopt / setsockopt / sendmsg / recvmsg
 *
 * 这些**没有路径参数**（getsockname 会返回已绑定的路径，但调用方通常
 * 只看端口/地址），所以是纯转发。导出它们是为了 parity 与将来介入。
 */
int socket(int domain, int type, int protocol) {
    static int (*fn)(int, int, int) = NULL;
    if (fn == NULL)
        fn = (int (*)(int, int, int))dlsym(RTLD_NEXT, "socket");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(domain, type, protocol);
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    static int (*fn)(int, struct sockaddr *, socklen_t *) = NULL;
    if (fn == NULL)
        fn = (int (*)(int, struct sockaddr *, socklen_t *))
             dlsym(RTLD_NEXT, "getsockname");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(sockfd, addr, addrlen);
}

int getsockopt(int sockfd, int level, int optname, void *optval,
               socklen_t *optlen) {
    static int (*fn)(int, int, int, void *, socklen_t *) = NULL;
    if (fn == NULL)
        fn = (int (*)(int, int, int, void *, socklen_t *))
             dlsym(RTLD_NEXT, "getsockopt");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(sockfd, level, optname, optval, optlen);
}

int setsockopt(int sockfd, int level, int optname, const void *optval,
               socklen_t optlen) {
    static int (*fn)(int, int, int, const void *, socklen_t) = NULL;
    if (fn == NULL)
        fn = (int (*)(int, int, int, const void *, socklen_t))
             dlsym(RTLD_NEXT, "setsockopt");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(sockfd, level, optname, optval, optlen);
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    static ssize_t (*fn)(int, const struct msghdr *, int) = NULL;
    if (fn == NULL)
        fn = (ssize_t (*)(int, const struct msghdr *, int))
             dlsym(RTLD_NEXT, "sendmsg");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(sockfd, msg, flags);
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
    static ssize_t (*fn)(int, struct msghdr *, int) = NULL;
    if (fn == NULL)
        fn = (ssize_t (*)(int, struct msghdr *, int))
             dlsym(RTLD_NEXT, "recvmsg");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(sockfd, msg, flags);
}

/* getifaddrs —— node 用它枚举网络接口（官方有 FORCE_FAKE_GETIFADDRS 开关） */
int getifaddrs(struct ifaddrs **ifap) {
    static int (*fn)(struct ifaddrs **) = NULL;
    if (fn == NULL)
        fn = (int (*)(struct ifaddrs **))dlsym(RTLD_NEXT, "getifaddrs");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(ifap);
}

void freeifaddrs(struct ifaddrs *ifa) {
    static void (*fn)(struct ifaddrs *) = NULL;
    if (fn == NULL)
        fn = (void (*)(struct ifaddrs *))dlsym(RTLD_NEXT, "freeifaddrs");
    if (fn == NULL) return;
    fn(ifa);
}

/* ------------------------------------------------------------------ */
/* Hook: 临时文件 64 位变体 + scandir64                                */
/* ------------------------------------------------------------------ */

int mkstemp64(char *template) {
    static int (*fn)(char *) = NULL;
    char local[MAX_PATH_LEN];
    int rc;

    if (fn == NULL)
        fn = (int (*)(char *))dlsym(RTLD_NEXT, "mkstemp64");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(template, local, sizeof(local)) <= 0)
        return fn(template);

    rc = fn(local);
    fr_strip_rootfs_inplace(local, sizeof(local));
    {
        size_t n = strlen(local), cap = strlen(template);
        if (n <= cap) memcpy(template, local, n + 1);
    }
    return rc;
}

int mkostemp64(char *template, int flags) {
    static int (*fn)(char *, int) = NULL;
    char local[MAX_PATH_LEN];
    int rc;

    if (fn == NULL)
        fn = (int (*)(char *, int))dlsym(RTLD_NEXT, "mkostemp64");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(template, local, sizeof(local)) <= 0)
        return fn(template, flags);

    rc = fn(local, flags);
    fr_strip_rootfs_inplace(local, sizeof(local));
    {
        size_t n = strlen(local), cap = strlen(template);
        if (n <= cap) memcpy(template, local, n + 1);
    }
    return rc;
}

int mkstemps64(char *template, int suffixlen) {
    static int (*fn)(char *, int) = NULL;
    char local[MAX_PATH_LEN];
    int rc;

    if (fn == NULL)
        fn = (int (*)(char *, int))dlsym(RTLD_NEXT, "mkstemps64");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(template, local, sizeof(local)) <= 0)
        return fn(template, suffixlen);

    rc = fn(local, suffixlen);
    fr_strip_rootfs_inplace(local, sizeof(local));
    {
        size_t n = strlen(local), cap = strlen(template);
        if (n <= cap) memcpy(template, local, n + 1);
    }
    return rc;
}

int mkostemps(char *template, int suffixlen, int flags) {
    static int (*fn)(char *, int, int) = NULL;
    char local[MAX_PATH_LEN];
    int rc;

    if (fn == NULL)
        fn = (int (*)(char *, int, int))dlsym(RTLD_NEXT, "mkostemps");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(template, local, sizeof(local)) <= 0)
        return fn(template, suffixlen, flags);

    rc = fn(local, suffixlen, flags);
    fr_strip_rootfs_inplace(local, sizeof(local));
    {
        size_t n = strlen(local), cap = strlen(template);
        if (n <= cap) memcpy(template, local, n + 1);
    }
    return rc;
}

int mkostemps64(char *template, int suffixlen, int flags) {
    static int (*fn)(char *, int, int) = NULL;
    char local[MAX_PATH_LEN];
    int rc;

    if (fn == NULL)
        fn = (int (*)(char *, int, int))dlsym(RTLD_NEXT, "mkostemps64");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(template, local, sizeof(local)) <= 0)
        return fn(template, suffixlen, flags);

    rc = fn(local, suffixlen, flags);
    fr_strip_rootfs_inplace(local, sizeof(local));
    {
        size_t n = strlen(local), cap = strlen(template);
        if (n <= cap) memcpy(template, local, n + 1);
    }
    return rc;
}

int scandir64(const char *dirp, struct dirent64 ***namelist,
              int (*filter)(const struct dirent64 *),
              int (*compar)(const struct dirent64 **, const struct dirent64 **)) {
    static int (*fn)(const char *, struct dirent64 ***,
                     int (*)(const struct dirent64 *),
                     int (*)(const struct dirent64 **,
                             const struct dirent64 **)) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = dirp;

    if (fn == NULL)
        fn = (int (*)(const char *, struct dirent64 ***,
                      int (*)(const struct dirent64 *),
                      int (*)(const struct dirent64 **,
                              const struct dirent64 **)))
             dlsym(RTLD_NEXT, "scandir64");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(dirp, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(p, namelist, filter, compar);
}

/*
 * execve / execvpe 的钩子已移除（所有权转移给 proc.c，见文件前段
 * 「exec 家族已移交给 D4 进程管理层」的说明）。
 *
 * 特别提醒后来者：**不要**为了「补回」而在这里重新定义这两个符号 ——
 * 那会和 proc.c 冲突成 `multiple definition`，而且旧实现会把调用方的
 * envp 原样转发（容器泄漏）。
 */

/* Hook: chdir */
int chdir(const char *path) {
    ensure_real_functions();

    char translated[MAX_PATH_LEN];
    if (translate_path(path, translated, sizeof(translated)) > 0) {
        LOG("chdir: %s -> %s", path, translated);
        return real_chdir(translated);
    }
    return real_chdir(path);
}

/* Hook: chroot */
int chroot(const char *path) {
    ensure_real_functions();

    char translated[MAX_PATH_LEN];
    if (translate_path(path, translated, sizeof(translated)) > 0) {
        LOG("chroot: %s -> %s", path, translated);
        return real_chroot(translated);
    }
    return real_chroot(path);
}

/* Hook: opendir */
DIR *opendir(const char *path) {
    ensure_real_functions();

    char translated[MAX_PATH_LEN];
    if (translate_path(path, translated, sizeof(translated)) > 0) {
        LOG("opendir: %s -> %s", path, translated);
        return real_opendir(translated);
    }
    return real_opendir(path);
}

/* Hook: fopen */
FILE *fopen(const char *path, const char *mode) {
    ensure_real_functions();

    char translated[MAX_PATH_LEN];
    if (translate_path(path, translated, sizeof(translated)) > 0) {
        LOG("fopen: %s -> %s", path, translated);
        return real_fopen(translated, mode);
    }
    return real_fopen(path, mode);
}

/* Hook: fopen64 */
FILE *fopen64(const char *path, const char *mode) {
    ensure_real_functions();

    char translated[MAX_PATH_LEN];
    if (translate_path(path, translated, sizeof(translated)) > 0) {
        return real_fopen64(translated, mode);
    }
    return real_fopen64(path, mode);
}

/* Hook: getpid (fakeroot) */
pid_t getpid(void) {
    ensure_real_functions();

    pid_t pid = real_getpid();

    if (g_config.fakeroot) {
        /* 伪装为 root 进程 */
        return 1;
    }

    return pid;
}

/* Hook: getuid (fakeroot) */
uid_t getuid(void) {
    ensure_real_functions();

    if (g_config.fakeroot) {
        return 0;
    }

    return real_getuid();
}

/* Hook: getgid (fakeroot) */
gid_t getgid(void) {
    ensure_real_functions();

    if (g_config.fakeroot) {
        return 0;
    }

    return real_getgid();
}

/* Hook: geteuid (fakeroot) */
uid_t geteuid(void) {
    ensure_real_functions();

    if (g_config.fakeroot) {
        return 0;
    }

    return real_geteuid();
}

/* Hook: getegid (fakeroot) */
gid_t getegid(void) {
    ensure_real_functions();

    if (g_config.fakeroot) {
        return 0;
    }

    return real_getegid();
}

/* Hook: uname (伪装为 Linux) */
int uname(struct utsname *buf) {
    ensure_real_functions();

    int ret = real_uname(buf);
    if (ret == 0) {
        /* 确保显示为 Linux 而不是 Android */
        if (strstr(buf->sysname, "Android") != NULL) {
            strncpy(buf->sysname, "Linux", sizeof(buf->sysname));
        }
        /* 伪装 kernel release */
        strncpy(buf->release, "6.1.0", sizeof(buf->release));
        strncpy(buf->machine, "aarch64", sizeof(buf->machine));
    }

    return ret;
}

/* 构造函数：库加载时执行 */
/* ------------------------------------------------------------------ */
/* fakeroot 状态与初始化                                               */
/* ------------------------------------------------------------------ */

/*
 * 初始化。读 BXROOT_FAKEROOT，与 l2s 一样默认关闭。
 *
 * 真实身份必须**绕过自己的 hook** 去读，否则 getuid() 会递归回本文件的
 * getuid hook。用 syscall() 直接问内核，这是唯一安全的做法。
 */
static void init_fakeroot(void) {
    const char *on = getenv("BXROOT_FAKEROOT");

    /* 环境变量没开就整体不启用；g_fakeroot_state 保持全零（enabled=false），
     * 所有 patch/查询函数都会立即返回。 */
    if (on == NULL || on[0] == '\0' || on[0] == '0') {
        g_fakeroot_on = 0;
        return;
    }

    /*
     * ★ 调用顺序有硬性契约，改错会**静默失效** ★
     *
     *   fakeroot_state_init()   ← 必须最先，它内部 memset 整个 state
     *   set_real_ids()          ← 必须在 init 之后，否则被 memset 抹掉
     *   set_enabled()           ← 只动假身份，不影响 real ids
     *
     * 把 init 放到 set_real_ids 之后，real_uid 会变成 0，于是
     * fr_decide_ids 的启发式「属主 == 真实用户时才改写」永远不成立 ——
     * fakeroot 什么都不改，却没有任何报错或崩溃。现场表现是
     * 「dpkg 仍因属主不对而失败」，而排查者会去查记账表、查 chown 钩子，
     * 想不到是初始化顺序。
     *
     * 该契约由 test_integration.c 的 I7 用例钉住。
     */
    fakeroot_state_init(&g_fakeroot_state);

    {
        long ruid = syscall(SYS_getuid);
        long euid = syscall(SYS_geteuid);
        long rgid = syscall(SYS_getgid);
        long egid = syscall(SYS_getegid);
        fakeroot_state_set_real_ids(&g_fakeroot_state,
                                     (uid_t)ruid, (uid_t)euid,
                                     (gid_t)rgid, (gid_t)egid);
    }

    fakeroot_state_set_enabled(&g_fakeroot_state, true);

    /* 记账表：有界，避免 dpkg 解包上万文件时吃爆内存。
     * 容量取 1024 槽（FR_MAP_DEFAULT_SLOTS），装载率超阈值自动淘汰最久未用。 */
    g_fakeroot_state.by_path  = fakeroot_map_create(FR_MAP_DEFAULT_SLOTS);
    g_fakeroot_state.by_inode = fakeroot_map_create(FR_MAP_DEFAULT_SLOTS);

    if (g_fakeroot_state.by_path == NULL || g_fakeroot_state.by_inode == NULL) {
        /* 表建不起来就整体关掉 —— 半残的 fakeroot 比没有更危险：
         * 记账写不进去，但 stat 补丁还在改写字段，客户会看到自相矛盾的属主。 */
        if (g_fakeroot_state.by_path)  fakeroot_map_destroy(g_fakeroot_state.by_path);
        if (g_fakeroot_state.by_inode) fakeroot_map_destroy(g_fakeroot_state.by_inode);
        g_fakeroot_state.by_path = NULL;
        g_fakeroot_state.by_inode = NULL;
        fakeroot_state_set_enabled(&g_fakeroot_state, false);
        g_fakeroot_on = 0;
        LOG("fakeroot: 记账表创建失败，整体禁用");
        return;
    }

    g_fakeroot_on = 1;
    LOG("fakeroot enabled: real=%ld/%ld fake=0/0",
        (long)g_fakeroot_state.real_uid, (long)g_fakeroot_state.real_gid);
}

/* ------------------------------------------------------------------ */
/* l2s 层初始化                                                        */
/* ------------------------------------------------------------------ */

/*
 * 读 BXROOT_LINK2SYMLINK。只有显式开启时才初始化 —— 默认关闭，
 * 避免在不需要模拟的场景（rootfs 在支持硬链接的文件系统上）多做一层
 * 间接，也避免把用户的正常符号链接误当成伪造链接。
 *
 * 注意这里**不检查 dlsym 是否可用**：l2s 层完全通过 L2S_OPS 表操作，
 * 而这些包装函数内部各自懒加载，构造函数阶段拿不到符号也没关系。
 */
static void init_l2s(void) {
    const char *on = getenv("BXROOT_LINK2SYMLINK");
    l2s_config cfg;

    if (on == NULL || on[0] == '\0' || on[0] == '0')
        return;

    cfg = (l2s_config)L2S_CONFIG_DEFAULT;
    /*
     * 集中目录布局。DSHA 生产走这条路径（PROOT_L2S_DIR）。
     * 不设时留在 NULL，中间层会生成在客户文件旁边。
     */
    cfg.l2s_dir = getenv("BXROOT_L2S_DIR");
    if (cfg.l2s_dir != NULL && cfg.l2s_dir[0] == '\0')
        cfg.l2s_dir = NULL;

    /*
     * 用 bxroot 方案（哈希键控元数据树 + .cnt 旁路计数），而不是
     * proot 的「链接数编进文件名」方案。
     *
     * 这不是偏好，是必须：proot 方案每次加链长都要 rename 数据文件，
     * 而官方 proroot 运行时的路径缓存在目标改名后会失效，导致已打开过
     * 的路径永久 ENOENT。详见
     * agents/_shared/官方运行时缺陷-符号链接改名后失效.md。
     */
    cfg.scheme = L2S_SCHEME_PROROOT;

    l2s_rt_init(&L2S_OPS, &cfg);
    LOG("l2s enabled: dir=%s", cfg.l2s_dir ? cfg.l2s_dir : "(beside file)");
}

__attribute__((constructor))
static void constructor(void) {
    init_config();
    init_l2s();
    init_fakeroot();

    /*
     * 崩溃现场捕获。
     *
     * 官方 proroot 有一个 3116 字节的 SIGSEGV 处理器（还配 340 字节的
     * 内存窗口转储）；bxroot 此前是**零** —— 崩溃时只留一句
     * "Segmentation fault"。
     *
     * 在 LD_PRELOAD 运行时里这件事格外要紧：一次空指针就会带走整个
     * 容器进程（连同用户正在跑的 node/pnpm/dpkg），排查者面对的是
     * "容器突然没了"，没有现场信息只能靠猜。
     *
     * 放在构造函数里装，保证任何钩子执行前就已就位。
     */
    /*
     * seccomp/SIGSYS 兼容层必须在**任何客户代码之前**就位。
     *
     * Android app 沙箱的 seccomp 过滤器会 TRAP 掉 io_uring_setup(425)，
     * 而 libuv 的工作线程会屏蔽 SIGSYS —— 屏蔽 + TRAP = 内核直接杀进程
     * （退出码 159，无法抢救）。实测这就是 bxroot 此前只能跑
     * `node --version`、一跑事件循环就死的原因。
     *
     * 放在 crash 安装之前：crash 处理的是我们自己的 bug，SIGSYS 处理的
     * 是环境强加的约束，后者更早发生。
     */
    bxroot_sigsys_install();

    /*
     * 运行时指令补丁（seccomp 中和）—— 本轮实测定位的关键一层。
     *
     * 为什么必须有：proroot-ldso 用 seccomp 以 KILL_PROCESS 方式禁止
     * 了 80+ 个系统调用号（逐个列举，425/426/427 在内，424 不在）。
     * glibc 内部有**内联 svc**，它们不经 PLT、不经任何导出符号，
     * 因此 LD_PRELOAD 类手段在原理上拦不住 —— 只能改写指令。
     *
     * 实证（最小复现，一个只做 pthread_create 的程序）：
     *     不打补丁：pthread_create 返回 0 → 进程立即死于 159
     *     打补丁后：pthread_create 返回 0 → join 完成 → rc=0 ✅
     *
     * 站点表刻意收窄到 2 个（set_robust_list / rseq）。实测四个候选点
     * 全打会导致 glibc 断言失败（rseq 返回 0 但未真正注册，破坏了
     * allocatestack.c 的 freesize 假设），只打这两个是必需且充分的。
     *
     * 失败不致命：libc 布局不认识时静默跳过（bxroot_livepatch_apply
     * 内部逐点校验原指令字节，不匹配即放弃）。
     *
     * 放在 sigsys 之后：sigsys 处理"信号能到达"的场景，本层处理
     * "信号根本到不了"的场景，后者是前者的兜底。
     */
    bxroot_livepatch_apply();

    /*
     * 进程管理层初始化（P0-3 / D4）。
     *
     * 必须在 main 之前、且必须在**任何 exec/spawn/fork 之前**：
     *   - 注册 pthread_atfork 三件套（否则 fork 后子进程会死锁，
     *     而且这个故障从外部完全看不出来，只表现为子进程偶尔挂住）；
     *   - 建立 pid 账本（kill 越界防护的白名单）；
     *   - 就地 setenv("LD_PRELOAD", ...) —— 这是 system()/popen()
     *     子进程能带上钩子的**唯一**途径（它们的子进程环境取自
     *     environ，而 glibc 内部硬编码 /bin/sh，hook 不到）。
     *
     * 位置在 init_config() 之后：proc.c 的 rootfs/环境注入配置与
     * preload.c 的翻译器共享同一套语义，先有配置再注入翻译器。
     */
    px_runtime_init();

    /*
     * 把自己记进 pid 账本。
     *
     * 否则 kill(getpid(), ...) 会被我们**自己的**白名单拒绝 ——
     * 而 getpid 在 fakeroot 下被伪装成 1，所以这个自伤场景在容器里
     * 是常态而不是边缘情况（shell 的自杀、node 的 process.kill(pid,0)
     * 探活都会踩到）。
     */
    px_runtime_register_self();

    bxroot_crash_install("bxroot");
    LOG("runtime library loaded");

    /* 设置工作目录 - 使用 syscall 直接调用，因为 dlsym 在 ctor 中不可用 */
    if (g_config.workdir) {
        char translated[MAX_PATH_LEN];
        const char *target = NULL;
        
        if (translate_path(g_config.workdir, translated, sizeof(translated)) > 0) {
            LOG("workdir: %s -> %s", g_config.workdir, translated);
            target = translated;
        } else {
            target = g_config.workdir;
        }
        
        /* 使用 syscall 直接调用 chdir */
        long ret = syscall(SYS_chdir, target);
        if (ret < 0)
            LOG("workdir chdir failed: %s", strerror(errno));
        else
            LOG("workdir chdir OK");
    }
}
