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
/*
 * pthread.h 在这里是**必需**的（pthread_create 钩子要用 pthread_t /
 * pthread_attr_t / pthread_attr_* 的原型）。实测它可以与本文件已在用的
 * 系统头文件共存，且在构建脚本那份严格警告集
 * （-Wall -Wextra -Wformat=2 -D_GNU_SOURCE=）下**零告警**。
 */
#include <pthread.h>

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

/*
 * 符号解析统一入口（实现见文件后段「dl* 家族」处）。
 * 语义 = `dlsym(RTLD_NEXT, name)`，但**不经过 libc 的 dlsym** ——
 * 本库导出了自己的 dlsym，libc 的 dlsym 在 参考实现的 loader 下
 * 会返回 NULL。声明放这里是因为 l2s / wait 家族等早期代码就要用。
 */
static void *bxroot_next_symbol(const char *name);

static int l2s_real_lstat(const char *p, struct stat *st);
static int l2s_real_symlink(const char *t, const char *l);
static int l2s_real_rename(const char *o, const char *n);
static int l2s_real_unlink(const char *p);
static ssize_t l2s_real_readlink(const char *p, char *b, size_t sz);
static int readlink_fixup(const char *raw, char *out, size_t outsz);   /* D3: /proc 泄漏反向翻译 */
static int strip_rootfs_prefix_inplace(char *buf);                     /* 剥 rootfs 前缀核心（定义在 getcwd_fixup 前） */
static int realpath_fixup_inplace(char *buf, size_t cap);              /* realpath 返回值反向翻译 */
static int l2s_real_access(const char *p, int m);
static int l2s_real_read_small(const char *p, char *b, size_t sz, size_t *len);
static int l2s_real_write_small(const char *p, const char *b, size_t len);
static int resolve_dirfd_path(int dirfd, const char *path,
                              char *out, size_t outsz);

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

/*
 * 前向声明：身份变更桥（缺口 C）。
 *
 * 定义在本文件末尾，但符号层的 setuid/setgid/... 钩子（文件中部）要用它。
 * 之所以集中在末尾定义而不是就近：那一组函数与 `bxroot_fakeroot_ids` 等
 * 查询入口放在一起，让"身份账本的所有对外接口"一目了然 —— 本项目在
 * "同一套规则写两处"上反复踩坑，把接口聚在一处是低成本的防漂移手段。
 */
int bxroot_fakeroot_setter(int op, unsigned long a0, unsigned long a1,
                           unsigned long a2, long *out_ret, int *out_errno);

/*
 * `-L`（参考实现的 fix_symlink_size）是否启用。
 *
 * 语义（读 参考实现的 fix_symlink_size.c 确认）：对**真符号链接**，
 * 把 st_size 钉成 readlink() 返回的长度。默认关闭 —— 与参考实现一致。
 *
 * 与 l2s 的 size 补丁**互不相干**：伪造链接的 size 由 l2s 层无条件修正
 * （官方默认就对，已实测；传不传 -L 都该对）。本开关管的是 l2s 没接管
 * 的那些普通符号链接。
 */
static int g_fix_symlink_size = 0;

/*
 * 「工作目录已设过」的标记变量名。
 *
 * 本 .so 会在**每个** exec 出来的进程里重新加载，构造函数随之再跑一遍。
 * BXROOT_WORKDIR 的语义是「容器启动时 cwd 设到哪里」，只在首个进程做一次；
 * 用环境变量当跨 exec 的标记（环境变量会被 fork/exec 继承）。
 * 详见构造函数里那段长注释的实测证据。
 */
#define BXROOT_WORKDIR_DONE_ENV "BXROOT_WORKDIR_DONE"

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
 * 「exec 家族已移交给 D4 进程管理层」）—— 留着会是未使用变量。
 * real_getpid 同理：getpid 钩子已删除（官方从不改 getpid，见其钩子原址
 * 的说明），此处不再需要解析真实 getpid。 */
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

/*
 * ==================================================================
 * 任务 3.5：PROROOT_* 旧前缀防呆警告
 * ==================================================================
 *
 * 本项目曾整体改名 PROROOT_* → BXROOT_*（RENAME-REPORT.md §2.3）。
 * 旧名与官方名都是 PROROOT_*：手滑写回旧前缀（或沿用旧 Java 侧 /
 * 旧文档示例）时，getenv 全部落空，runtime **静默**按另一套默认配置
 * 跑（rootfs 回到编译期默认、/tmp 回退等）—— 排查方向会先指向容器
 * 内部而不是"变量拼错了"。这里在配置初始化时探测一次，把症状拉回
 * 真正的原因。
 *
 * 【只对真实存在的变量做】逐对列出"旧名 + runtime 侧真实读取点"：
 *     ROOTFS    preload.c  BXROOT_ROOTFS（init_config）
 *     TMP_DIR   preload.c  BXROOT_TMP_DIR（init_config）
 *     GUEST_EXE preload.c  BXROOT_GUEST_EXE（init_config）
 *     WORKDIR   preload.c  BXROOT_WORKDIR（init_config）
 *     FAKEROOT  preload.c  BXROOT_FAKEROOT（init_config）
 *     BINDS     preload.c  BXROOT_BINDS（parse_binds）
 *     VERBOSE   preload.c  BXROOT_VERBOSE（init_config）
 *     L2S_DIR   preload.c  BXROOT_L2S_DIR（init_l2s）
 *     FORCE_NO_LDSO_SERVICE  preload.c（ldso 服务开关）
 * 刻意**不**枚举 PROROOT_LINKER_PATH/STUB_LOADER/LIB_PATH/LINKER/
 * RUNTIME 等：它们只被 launcher/Java 侧消费，runtime 从不读取，
 * 列进来是给不存在的行为发警告。
 *
 * 【每进程最多一次】g_prefix_warned 打点；配置只初始化一次，但本
 * 函数与 init_config 解耦，防将来出现二次初始化路径时刷屏。
 */
static void warn_stale_proroot_env(void) {
    static const struct {
        const char *old_name;   /* 旧/官方前缀变量名 */
        const char *new_name;   /* runtime 侧真实读取的 BXROOT_ 名 */
    } stale_map[] = {
        { "PROROOT_ROOTFS",   "BXROOT_ROOTFS" },
        { "PROROOT_TMP_DIR",  "BXROOT_TMP_DIR" },
        { "PROROOT_GUEST_EXE","BXROOT_GUEST_EXE" },
        { "PROROOT_WORKDIR",  "BXROOT_WORKDIR" },
        { "PROROOT_FAKEROOT", "BXROOT_FAKEROOT" },
        { "PROROOT_BINDS",    "BXROOT_BINDS" },
        { "PROROOT_VERBOSE",  "BXROOT_VERBOSE" },
        { "PROROOT_L2S_DIR",  "BXROOT_L2S_DIR" },
        { "PROROOT_FORCE_NO_LDSO_SERVICE", "BXROOT_FORCE_NO_LDSO_SERVICE" },
    };
    static int g_prefix_warned = 0;
    size_t k;

    if (g_prefix_warned)
        return;

    /*
     * ★ 先排除「嵌套容器」这一正常形态，否则警告必然误报 ★
     *
     * bxroot 的**主要部署形态之一**就是跑在另一个 proroot 容器里
     * （DSHA 真机链路即如此）。这时外层 proroot 会向 environ 注入
     * 一整套 PROROOT_* 变量 —— 它们是**外层的实现状态**，而不是
     * "手配 bxroot 时拼错前缀"。不排除的话，警告在每次嵌套启动时
     * 都会刷出来，把正常形态误报成配置错误。
     * （实测：上游套件自检的 stdout 探针因此被判失败，属真实回归。）
     *
     * 判别信号：外层 proroot 会设若干**用户不可能手配的实现细节变量**
     * （配置 fd、跳板路径、stub-loader 路径等）。命中一个即认定
     * "这是嵌套容器"，不报警。
     *
     * 反面：用户真的手配 bxroot 却写成 PROROOT_ROOTFS 时，环境里
     * 不会同时出现 PROROOT_CFG_FD 这类内部变量，警告正常触发。
     */
    {
        static const char *const nested_markers[] = {
            "PROROOT_CFG_FD",               /* 配置传递 fd（内部机制） */
            "PROROOT_ESCAPE_FD",            /* 逃逸 fd */
            "PROROOT_TRAMPOLINE_PATH",      /* 跳板 so 路径 */
            "PROROOT_STUB_LOADER",          /* 静态加载器路径 */
            "PROROOT_LINKER_PATH",          /* 自研 linker 路径 */
            "PROROOT_SIGSYS_LOG_HOST_PATH", /* SIGSYS 日志路径 */
        };
        size_t mi;
        for (mi = 0; mi < sizeof(nested_markers) / sizeof(nested_markers[0]); mi++) {
            const char *mv = getenv(nested_markers[mi]);
            if (mv != NULL && mv[0] != '\0')
                return;   /* 嵌套容器：静默 */
        }
    }

    for (k = 0; k < sizeof(stale_map) / sizeof(stale_map[0]); k++) {
        const char *oldv = getenv(stale_map[k].old_name);

        if (oldv != NULL && oldv[0] != '\0' &&
            getenv(stale_map[k].new_name) == NULL) {
            fprintf(stderr,
                    "[bxroot] 警告: 检测到 %s 环境变量但未设 %s"
                    "（是否拼写/迁移遗漏？）: %s\n",
                    stale_map[k].old_name, stale_map[k].new_name,
                    stale_map[k].old_name);
            g_prefix_warned = 1;
            /* 只报第一条：一句话点破根因即可，逐条刷屏没有增量信息 */
            return;
        }
    }
}

/* 初始化配置 */
static void init_config(void) {
    const char *env;

    /* 任务 3.5：先探测旧前缀变量，再按新名读配置 —— 见函数头注释。 */
    warn_stale_proroot_env();

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

/*
 * 反向 bind 映射：宿主路径 → 客户路径。
 *
 * ====================================================================
 * 为什么需要它（一个真实的故障）
 * ====================================================================
 *
 * DSHA 传给 bxroot 的 bind 里有这样两条：
 *
 *     -b /storage/emulated/0:/sdcard
 *     -b /storage/emulated/0:/storage/emulated/0
 *
 * 正向翻译（客户 → 宿主）工作正常：`/sdcard/x` 会变成
 * `/storage/emulated/0/x`。
 *
 * 但**反向**没人做：`getcwd()` 从内核拿到的是**宿主路径**
 * `/storage/emulated/0/Download/...`，我们的 getcwd 钩子只剥了
 * rootfs 前缀（这里没命中，因为该路径在 rootfs 之外），于是原样返回。
 *
 * 实测后果（`dsh web --help`）：
 *
 *     官方  : cwd = /sdcard/Download/DSHA/工作区
 *             → 尝试读 /sdcard/.../.env → ENOENT（被静默忽略）✅
 *     bxroot: cwd = /storage/emulated/0/Download/DSHA/工作区
 *             → 尝试读该路径 → **EACCES**（/storage 是 FUSE，权限受限）
 *             → dsh 的 .env 加载抛错，后续插件初始化被带偏 ❌
 *
 * 也就是说：**客户看到一个它从没见过的路径，然后在那条路径上失败。**
 *
 * ====================================================================
 * 实现要点
 * ====================================================================
 *
 * - 取**最长（最具体）**的匹配 source，与正向翻译的策略一致。
 *   `/storage/emulated/0` 同时匹配两条 bind，但它们 target 不同
 *   （`/sdcard` 与 `/storage/emulated/0`），必须有一致的选取规则。
 *   这里偏好**与 source 不同**的 target（即真正的重映射），
 *   自映射（source == target）只作为兜底。
 *
 * - 同样只认**组件边界**（前缀后必须是 '\0' 或 '/'），
 *   否则 `/storage/emulated/0X` 会被误判。
 *
 * - 返回 1 表示已重写，0 表示无匹配。
 */
static int detranslate_binds(const char *path, char *out, size_t out_size)
{
    int best = -1;
    size_t best_len = 0;

    if (path == NULL || out == NULL || out_size == 0)
        return 0;
    if (path[0] != '/')
        return 0;

    for (int i = 0; i < g_config.bind_count; i++) {
        const char *src = g_config.bind_sources ? g_config.bind_sources[i] : NULL;
        const char *tgt = g_config.bind_targets ? g_config.bind_targets[i] : NULL;
        size_t sl;

        if (src == NULL || src[0] == '\0' || tgt == NULL)
            continue;

        sl = strlen(src);
        if (strncmp(path, src, sl) != 0)
            continue;
        if (path[sl] != '\0' && path[sl] != '/')
            continue;

        /*
         * 自映射（source == target）在反向时是恒等变换，没有价值。
         * 只有当**没有**更具体的非自映射匹配时才用它兜底。
         */
        if (strcmp(src, tgt) == 0 && best >= 0)
            continue;

        if (sl > best_len) {
            best = i;
            best_len = sl;
        }
    }

    if (best < 0)
        return 0;

    {
        const char *tgt = g_config.bind_targets[best];
        const char *rest = path + best_len;
        int n = snprintf(out, out_size, "%s%s", tgt, rest);

        if (n < 0 || (size_t)n >= out_size)
            return 0;
    }
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
 * 真实符号解析：`dlsym(RTLD_NEXT, name)`。
 *
 * ★ 一段被证伪的弯路，记录在此以免重蹈 ★
 *
 * 曾观察到「bxroot 运行时下 dlsym(RTLD_NEXT,…) 全部返回 NULL」，并据此
 * 写了一大套回退解析（先 dlopen，后来自包含 ELF 解析）。**那个观察是
 * 探针假象**：
 *
 *   - 当时用的探针是**主程序**。主程序的搜索链里，它自己之后**没有**
 *     libc（libc 在它之前），所以 RTLD_NEXT 必然返回 NULL —— 这是
 *     RTLD_NEXT 语义的正常结果，与 bxroot 无关。
 *   - 把同一段探测放进**被 --preload 加载的 .so 的构造函数**里
 *     （也就是本文件真实的运行语境），实测：
 *
 *         fork        RTLD_NEXT=0x7bcab03a10  obj=libc.so.6
 *         posix_spawn RTLD_NEXT=0x7bcab181c0  obj=libc.so.6
 *         execve      RTLD_NEXT=0x7bcaaffcc0  obj=libc.so.6
 *
 *     三个都**合法且解析到 libc**。而且同一个纯 preload 探针里
 *     `posix_spawn` 直接 `rc=0` 成功。
 *
 * 也就是说本文件的写法本来就是对的；那套回退解析修的不是真问题。
 * 教训：**RTLD_NEXT 的结果取决于"谁在调"**，用它做判据时必须确认
 * 探针的链接位置与被测代码一致。
 *
 * ★ 唯一仍然成立的限制：IFUNC ★
 * `dlsym` 对 IFUNC 符号（strlen / memcpy / memset 等）返回的是 resolver
 * 地址而不是实现地址，直接调用会得到垃圾（实测 strlen("hello") 返回
 * 480563740352）。但本文件 hook 的都是路径/进程/权限类函数，它们都是
 * 普通 STT_FUNC，不涉及 IFUNC，所以不受影响。
 */
/*
 * 注意：这里**不再**提供 bxroot_real_symbol 的转发定义。
 * 那个函数由 realsym.c 自己导出（同名），在本文件里再定义一个会
 * multiple definition 链接失败。proc.c 通过 weak 引用它，直接链到
 * realsym.c 的实现。
 */

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
 *   - 转发走的 `bxroot_real_symbol(...)` 懒加载每次判空：LD_PRELOAD 里
 *     一次空指针解引用 = 整个容器进程 SIGSEGV。
 */

static pid_t (*px_real_waitpid)(pid_t, int *, int) = NULL;
static pid_t (*px_real_wait4)(pid_t, int *, int, struct rusage *) = NULL;
static pid_t (*px_real_wait3)(int *, int, struct rusage *) = NULL;
static int   (*px_real_waitid)(idtype_t, id_t, siginfo_t *, int) = NULL;

static void *px_wait_dlsym(const char *name)
{
    /*
     * 走 linker 服务版解析（`bxroot_next_symbol`，语义 = dlsym(RTLD_NEXT)）。
     * 这里**不能**直接写 dlsym(RTLD_NEXT, …)：本库现在导出了自己的
     * `dlsym`，而 libc 的 dlsym 与 参考实现的 loader 不自洽
     * （实测从本库内部调用会返回 NULL）。详见 bxroot_next_symbol 的注释。
     */
    void *p = bxroot_next_symbol(name);

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
    if (fn == NULL) fn = (int (*)(const char *, const char *))bxroot_next_symbol("symlink");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(t, l);
}

static int l2s_real_rename(const char *o, const char *n)
{
    static int (*fn)(const char *, const char *) = NULL;
    if (fn == NULL) fn = (int (*)(const char *, const char *))bxroot_next_symbol("rename");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(o, n);
}

static int l2s_real_unlink(const char *p)
{
    static int (*fn)(const char *) = NULL;
    if (fn == NULL) fn = (int (*)(const char *))bxroot_next_symbol("unlink");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(p);
}

static ssize_t l2s_real_readlink(const char *p, char *b, size_t sz)
{
    static ssize_t (*fn)(const char *, char *, size_t) = NULL;
    if (fn == NULL) fn = (ssize_t (*)(const char *, char *, size_t))bxroot_next_symbol("readlink");
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
        real_open = (int (*)(const char *, int, ...))bxroot_next_symbol("open");
        real_openat = (int (*)(int, const char *, int, ...))bxroot_next_symbol("openat");
        real_stat = (int (*)(const char *, struct stat *))bxroot_next_symbol("stat");
        real_newfstatat = (int (*)(int, const char *, struct stat *, int))bxroot_next_symbol("newfstatat");
        /* glibc 2.33+ 不再导出 newfstatat，现代等价入口是 fstatat。
         * 若 newfstatat 解析失败，回退到 fstatat（glibc 中两者同实现）。 */
        if (!real_newfstatat)
            real_newfstatat = (int (*)(int, const char *, struct stat *, int))bxroot_next_symbol("fstatat");
        real_lstat = (int (*)(const char *, struct stat *))bxroot_next_symbol("lstat");
        real_access = (int (*)(const char *, int))bxroot_next_symbol("access");
        real_readlink = (ssize_t (*)(const char *, char *, size_t))bxroot_next_symbol("readlink");
        real_realpath = (char * (*)(const char *, char *))bxroot_next_symbol("realpath");
        /* 不解析 getpid：钩子已删除（官方从不改 getpid），解析了也没人用 */
        real_getuid = (uid_t (*)(void))bxroot_next_symbol("getuid");
        real_getgid = (gid_t (*)(void))bxroot_next_symbol("getgid");
        real_geteuid = (uid_t (*)(void))bxroot_next_symbol("geteuid");
        real_getegid = (gid_t (*)(void))bxroot_next_symbol("getegid");
        real_chdir = (int (*)(const char *))bxroot_next_symbol("chdir");
        real_uname = (int (*)(struct utsname *))bxroot_next_symbol("uname");
        real_chroot = (int (*)(const char *))bxroot_next_symbol("chroot");
        real_open64 = (int (*)(const char *, int, ...))bxroot_next_symbol("open64");
        real_openat64 = (int (*)(int, const char *, int, ...))bxroot_next_symbol("openat64");
        real_stat64 = (int (*)(const char *, struct stat64 *))bxroot_next_symbol("stat64");
        real_newfstatat64 = (int (*)(int, const char *, struct stat64 *, int))bxroot_next_symbol("newfstatat64");
        if (!real_newfstatat64)
            real_newfstatat64 = (int (*)(int, const char *, struct stat64 *, int))bxroot_next_symbol("fstatat64");
        real_lstat64 = (int (*)(const char *, struct stat64 *))bxroot_next_symbol("lstat64");
        real_opendir = (DIR * (*)(const char *))bxroot_next_symbol("opendir");
        real_fopen = (FILE * (*)(const char *, const char *))bxroot_next_symbol("fopen");
        real_fopen64 = (FILE * (*)(const char *, const char *))bxroot_next_symbol("fopen64");
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

/*
 * ====================================================================
 * ★ O_NOFOLLOW + 伪造链接 = ELOOP ★
 * ====================================================================
 *
 * 【缺陷（实测，2026-09-16）】
 *
 * 客户从 lstat 得知伪造链接是**普通文件**，于是 coreutils 的 `cp -a`
 * 用 `open(path, O_RDONLY|O_NOFOLLOW)` 打开它 —— 这是 cp 防止
 * TOCTOU 掉包的标准做法。但磁盘上那仍是**符号链接**，O_NOFOLLOW 让
 * 内核直接回 ELOOP：
 *
 *     $ cp -a /tmp/x/a /tmp/x/c
 *     /usr/bin/cp: cannot open '/tmp/x/a' for reading:
 *     Too many levels of symbolic links
 *
 * 参考实现不会：它在**系统调用入口**就把伪造链接替换成最终数据
 * 文件（link2symlink.c 的 translated_path()），内核根本见不到那条链接，
 * 所以 O_NOFOLLOW 看到的是一个货真价实的普通文件。
 *
 * 【本层怎么补】
 * 客户说"别跟随符号链接"，而这条路径在模拟语义里**本来就是普通文件**
 * —— 那就把路径换成真正的普通文件（数据文件）再交给内核。语义正好
 * 对应：客户不想跟随链接，我们给它链接背后的那个文件本身。
 *
 * 【只对伪造链接生效】
 * 用户自己的真符号链接必须保持 ELOOP（那是 O_NOFOLLOW 的正确语义）。
 * 判据交给 l2s 层的 l2s_rt_resolve_fake_link —— 与新造一套"怎么认
 * 伪造链接"的规则相比，复用是唯一不会产生第二套判据的做法。
 *
 * p 必须是**翻译后的宿主路径**（中间层与数据文件都在宿主侧）。
 */
static const char *l2s_open_path(const char *p, int flags,
                                char *scratch, size_t scratchsz)
{
    if (p == NULL || (flags & O_NOFOLLOW) == 0)
        return p;
    if (l2s_rt_resolve_fake_link(p, scratch, scratchsz) == 1)
        return scratch;
    return p;
}

/*
 * ====================================================================
 * ★ -L：修正 lstat 对符号链接返回的 size ★
 * ====================================================================
 *
 * 参考实现的 fix_symlink_size 语义（src/extension/fix_symlink_size/）：
 * 只 filter PR_lstat / PR_lstat64，成功返回后
 *
 *     if (!S_ISLNK(statl.st_mode)) return 0;   // 不是符号链接 → 不管
 *     size = readlink(original, intermediate, PATH_MAX);
 *     statl.st_size = (off_t)size;             // 钉成目标串长度
 *
 * 也就是说它把 st_size 设成 **readlink 返回的字节数**，而不是 st_size
 * 原本的值。同架构下内核对符号链接给的通常就是同一个数，所以它多为
 * 恒等操作；真正有差别的是 /proc 下的魔法链接 —— 例如
 * /proc/self/cwd 的 st_size 是 0，而 readlink 返回实际路径长度。
 *
 * ★ 默认关闭 ★ 与参考实现一致（-L 是显式选项）。
 *
 * p 必须是**翻译后的宿主路径**（readlink 要用同一条路径去看目标）。
 */
static void l2s_fix_symlink_size(struct stat *st, const char *p)
{
    char target[MAX_PATH_LEN];
    ssize_t n;

    if (!g_fix_symlink_size || st == NULL || p == NULL)
        return;

    /* 只对符号链接生效 —— 与参考实现的 S_ISLNK 门控一致。 */
    if (!S_ISLNK(st->st_mode))
        return;

    /*
     * ★ /proc/self/exe 要用**客户可见**的长度，不是宿主真实长度 ★
     *
     * 这个路径被 readlink 钩子改写过（返回 g_config.guest_exe，那是客户
     * 以为自己是哪个程序）。若这里仍按宿主真实目标算，客户会看到
     *     st_size = strlen("<...>/libproroot-bridge.so") = 107
     *     readlink()                                        = "/tmp/lprobe" (11)
     * 两者不一致 —— 而"size 与 readlink 一致"正是 -L 要保证的东西。
     * 本函数存在的全部意义就是让这两个数对得上，不能自己制造新的不一致。
     */
    if (p != NULL && g_config.guest_exe != NULL &&
        g_config.guest_exe[0] != '\0' &&
        (strcmp(p, "/proc/self/exe") == 0 ||
         strcmp(p, "/proc/thread-self/exe") == 0)) {
        st->st_size = (off_t)strlen(g_config.guest_exe);
        return;
    }

    n = real_readlink != NULL ? real_readlink(p, target, sizeof(target))
                              : readlink(p, target, sizeof(target));
    if (n < 0)
        return;                     /* 读不到目标就保持原值，不乱猜 */

    st->st_size = (off_t)n;
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
    char resolved[MAX_PATH_LEN];
    const char *q;

    if (translate_path(path, translated, sizeof(translated)) > 0) {
        q = l2s_open_path(translated, flags, resolved, sizeof(resolved));
        return call_real_open(q, flags, mode);
    }
    q = l2s_open_path(path, flags, resolved, sizeof(resolved));
    return call_real_open(q, flags, mode);
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
        char resolved[MAX_PATH_LEN];
    const char *q;

    if (translate_path(path, translated, sizeof(translated)) > 0) {
        q = l2s_open_path(translated, flags, resolved, sizeof(resolved));
        return real_open64(q, flags, mode);
    }
    q = l2s_open_path(path, flags, resolved, sizeof(resolved));
    return real_open64(q, flags, mode);
}

/*
 * ====================================================================
 * ★ (dirfd, 相对路径) → 绝对宿主路径 ★
 * ====================================================================
 *
 * 【为什么需要这个统一入口（反复踩过的同一类缺陷）】
 *
 * 本项目已经**三次**因为"相对路径 + dirfd"这一形态漏处理而出缺陷：
 *     ① fstatat 漏接 l2s 补丁（node 的 statSync 全走它）
 *     ② readlinkat 相对名漏改写（tar 遍历目录时用）
 *     ③ openat + O_NOFOLLOW 漏解链（tar 判断"是不是链接"时用）
 *
 * 三者的**根因完全相同**：translate_path() 对相对路径返回 0（它只翻
 * 绝对路径），于是 p 保持相对名，后续一切"拿 p 去判据"的逻辑都按
 * **进程 cwd** 解析，而客户的意思是**相对 dirfd**。cwd 恰好等于 dirfd
 * 时看着是对的 —— 这就是它难以被单点测试发现的原因。
 *
 * 【统一怎么解】
 * 用 /proc/self/fd/<dirfd> 读出目录的真实宿主路径，与 path 拼成绝对
 * 路径，再交给 translate_path。l2s 层因此可以保持"只认绝对路径"这个
 * 简单不变量（它所有判据都建立在宿主绝对路径上）。
 *
 * 【AT_FDCWD 是特例】
 * 值 -100，**不是**真实 fd，不能拿去做 /proc/self/fd/-100。
 * 它表示"相对于 cwd"，此时原样返回（调用方按既有逻辑走）。
 *
 * 返回 1 = 已拼成绝对路径（out 有效）；0 = 调用方按原样处理。
 */
static int resolve_dirfd_path(int dirfd, const char *path,
                              char *out, size_t outsz)
{
    char proc[64];
    char dir[MAX_PATH_LEN];
    ssize_t n;
    size_t dlen;

    if (dirfd == AT_FDCWD || path == NULL || path[0] == '\0')
        return 0;

    /* 绝对路径与 dirfd 无关（内核也忽略 dirfd） */
    if (path[0] == '/')
        return 0;

    snprintf(proc, sizeof(proc), "/proc/self/fd/%d", dirfd);
    n = real_readlink != NULL ? real_readlink(proc, dir, sizeof(dir) - 1)
                              : readlink(proc, dir, sizeof(dir) - 1);
    if (n <= 0)
        return 0;                   /* 拿不到目录就退回原行为，不乱猜 */
    dir[n] = '\0';

    /*
     * 去重斜杠：dir 以 '/' 结尾（根目录）时不要再插一个。
     */
    dlen = (size_t)n;
    if (dlen > 0 && dir[dlen - 1] == '/')
        snprintf(out, outsz, "%s%s", dir, path);
    else
        snprintf(out, outsz, "%s/%s", dir, path);

    return 1;
}

/*
 * 把 (dirfd, path) 统一解析成**绝对宿主路径**，供后续 l2s 判据使用。
 *
 * 顺序：先按 dirfd 拼绝对（若有 dirfd）→ 再 translate_path 加 rootfs 前缀。
 * translate_path 是幂等的（已带前缀时返回 0 并原样拷贝），所以两条分支
 * 都安全。
 *
 * 返回的指针可能是 out_host（拼好的宿主路径）或 path 本身。
 */
static const char *resolve_host_path(int dirfd, const char *path,
                                     char *joined, size_t joinedsz,
                                     char *out_host, size_t out_hostsz)
{
    const char *abs = path;

    if (resolve_dirfd_path(dirfd, path, joined, joinedsz) == 1)
        abs = joined;

    if (abs != NULL && translate_path(abs, out_host, out_hostsz) > 0)
        return out_host;

    return abs;
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
    char joined[MAX_PATH_LEN];
    char resolved[MAX_PATH_LEN];
    const char *q;

    /*
     * ★ 必须先把 (dirfd, 相对名) 拼成绝对宿主路径 ★
     *
     * 否则 translate_path 对相对名返回 0，q 停在 "a"，l2s 层就 probe
     * 不到伪造链接 —— O_NOFOLLOW 会直接撞上磁盘上那条符号链接并回
     * ELOOP。tar 正是用 openat(dirfd, name, O_NOFOLLOW) 判断"它是不是
     * 链接"的，于是把中间层名字写进归档（实测）。
     */
    q = resolve_host_path(dirfd, path, joined, sizeof(joined),
                          translated, sizeof(translated));
    q = l2s_open_path(q, flags, resolved, sizeof(resolved));
    return call_real_openat(dirfd, q, flags, mode);
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
    char joined[MAX_PATH_LEN];
    char resolved[MAX_PATH_LEN];
    const char *q;

    /* 与 openat 同理：先拼绝对路径，否则 O_NOFOLLOW 会撞上伪造链接 */
    q = resolve_host_path(dirfd, path, joined, sizeof(joined),
                          translated, sizeof(translated));
    q = l2s_open_path(q, flags, resolved, sizeof(resolved));
    return real_openat64(dirfd, q, flags, mode);
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
    char joined[MAX_PATH_LEN];
    const char *p = path;
    int rc;

    /*
     * ★ 必须按 dirfd 解析相对名 ★
     *
     * translate_path() 只翻绝对路径；相对名（tar 的
     * openat+fstatat 组合、node 的 dirfd 用法）原样返回，
     * 于是 l2s 层拿 "a" 去 probe —— 那是相对**进程 cwd**
     * 解析的，不是相对 dirfd。cwd 恰好等于 dirfd 时看着
     * 是对的，一旦不同就 probe 不到，伪造链接的 S_IFLNK
     * 抹不掉 → 客户（tar）判定"这是符号链接" → 去 readlink
     * → EINVAL → "Cannot readlink" 而失败。
     */
    p = resolve_host_path(dirfd, path, joined, sizeof(joined),
                          translated, sizeof(translated));

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
    char joined[MAX_PATH_LEN];
    const char *p = path;
    int rc;

    /*
     * ★ 必须按 dirfd 解析相对名 ★
     *
     * translate_path() 只翻绝对路径；相对名（tar 的
     * openat+fstatat 组合、node 的 dirfd 用法）原样返回，
     * 于是 l2s 层拿 "a" 去 probe —— 那是相对**进程 cwd**
     * 解析的，不是相对 dirfd。cwd 恰好等于 dirfd 时看着
     * 是对的，一旦不同就 probe 不到，伪造链接的 S_IFLNK
     * 抹不掉 → 客户（tar）判定"这是符号链接" → 去 readlink
     * → EINVAL → "Cannot readlink" 而失败。
     */
    p = resolve_host_path(dirfd, path, joined, sizeof(joined),
                          translated, sizeof(translated));

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

    /*
     * ★ -L 必须在 l2s **之后** ★
     *
     * 顺序不能反：l2s 把伪造链接的 mode 从 S_IFLNK 改成 S_IFREG。若 -L
     * 先跑，它会看到 S_ISLNK 并把 size 钉成目标串长度，把 l2s 刚回填的
     * 真实大小覆盖掉 —— 正好退回本次要修的缺陷。
     *
     * 这个顺序与参考实现一致：它的 link2symlink 与 fix_symlink_size 都是
     * 扩展，而 -L 的注释明确写着「l2s 应当已经解链完毕」，即它排在后面。
     */
    if (rc == 0)
        l2s_fix_symlink_size(buf, p);

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
    /* 与 lstat 保持一致：参考实现同样对 lstat64 做 owner 改写 */
    if (rc == 0 && g_fakeroot_on)
        fakeroot_patch_stat64(buf, &g_fakeroot_state);
    /* l2s：与 lstat 一致 */
    if (rc == 0)
        l2s_rt_patch_stat((struct stat *)buf, p);
    /* -L：同样必须在 l2s 之后（理由见 lstat 钩子） */
    if (rc == 0)
        l2s_fix_symlink_size((struct stat *)buf, p);
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
            fn_chown = (int (*)(const char *, uid_t, gid_t))bxroot_next_symbol("chown");
        if (fn_chown == NULL) { errno = ENOSYS; return -1; }
        rc = fn_chown(p, uid, gid);
    } else {
        if (fn_lchown == NULL)
            fn_lchown = (int (*)(const char *, uid_t, gid_t))bxroot_next_symbol("lchown");
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
        fn = (int (*)(int, uid_t, gid_t))bxroot_next_symbol("fchown");
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
    const char *p = path;
    ssize_t n;

    /*
     * ============================================================
     * ★ /proc/self/exe 的伪装 —— dsh web 段错误的**最终根因**
     * ============================================================
     *
     * 完整的因果链（每一环都有实测证据）：
     *
     *   1. bxroot 是 LD_PRELOAD 方案，进程映像由 proroot 的 bridge
     *      加载器创建，所以 readlink("/proc/self/exe") 返回的是
     *      **libproroot-bridge.so**，而不是客户以为自己是那个程序。
     *      实测：官方返回 /usr/bin/bash，bxroot 返回 bridge.so。
     *
     *   2. Node 的 `process.execPath` 走 uv_exepath() → 正是这个
     *      readlink。于是 dsh 依赖的 koffi 原生模块拿它去判断 libc：
     *
     *          let file = openFile(process.execPath, "r");
     *          let interp = findInterpreter64(file, header);
     *          let libc = basename.startsWith("ld-musl-") ? "musl" : "glibc";
     *
     *      它读的是**那个文件的 ELF 解释器**。
     *
     *   3. bridge.so 的解释器是 proroot 的自研加载器，不以 ld-musl-
     *      开头 → koffi 判定为 glibc —— 这一步其实"蒙对了"，
     *      但紧接着它按同一个 execPath 去做**其他**路径推导，
     *      于是选中了 musl_arm64/koffi.node。
     *
     *   4. 容器里没有 libc.musl-aarch64.so.1：
     *          deps: cannot find libc.musl-aarch64.so.1
     *                            (needed by .../musl_arm64/koffi.node)
     *      加载失败后 node 走进错误恢复分支，最终段错误。
     *
     *   5. 官方之所以不崩：它的 execPath 是 /usr/bin/bash（一个正常的
     *      glibc 程序），koffi 的判断与推导全部走对。
     *
     * 【修法】把一直存在却从未被使用的 `g_config.guest_exe` 接上。
     * 它由 launcher 从 BXROOT_GUEST_EXE 读入（launcher.c 里 setenv），
     * 但此前的 preload.c **只赋值、从不读取** —— 典型的死配置。
     *
     * 修复效果（实测 5/5 复现）：
     *     dsh web --help  段错误  →  输出完整帮助
     *     process.execPath        →  /usr/local/bin/node
     *
     * ============================================================
     * 以下为具体实现，必须在路径翻译**之前**处理。
     *
     * 【为什么必须做】
     * `readlink("/proc/self/exe")` 在内核里返回的是**真实启动的那个
     * 可执行文件**。bxroot 是 LD_PRELOAD 方案，客户的进程映像其实是
     * 由 proroot 的 bridge 加载器创建的，所以这个 readlink 会返回
     * `libproroot-bridge.so` —— 而不是客户以为自己是的那个程序。
     *
     * 【真实后果（不是理论问题）】
     * Node 的 `process.execPath` 走 `uv_exepath()` → 正是这个 readlink。
     * 而 dsh 依赖的 `koffi` 原生模块用**读自己 ELF 解释器**的方式
     * 判断 libc 类型：
     *
     *     let file = openFile(process.execPath, "r");
     *     let interp = findInterpreter64(file, header);
     *     let libc = basename.startsWith("ld-musl-") ? "musl" : "glibc";
     *
     * 实测对照：
     *     官方运行时  execPath = /usr/bin/bash   → 判为 glibc ✅
     *     bxroot      execPath = libproroot-bridge.so → 判错 ❌
     *
     * 判错的后果是它去加载 `musl_arm64/koffi.node`，而容器里根本没有
     * `libc.musl-aarch64.so.1`，加载失败后走进错误分支并段错误。
     * 这正是 `dsh web` 崩溃的**触发链**。
     *
     * 【为什么用 g_config.guest_exe】
     * 这个字段一直存在于配置里（由 launcher 从 BXROOT_GUEST_EXE 读入），
     * 但此前的代码**只赋值、从不读取** —— 一个典型的"死配置"，
     * 与本项目历史上 `--link2symlink` 被解析后丢弃完全同类。
     * 现在把它接上：客户问"我是谁"，就告诉它它以为自己是那个程序。
     *
     * 【为什么要判 path 的多种写法】
     * `/proc/self/exe`、`/proc/<pid>/exe`、以及经由 /proc/self 符号链接
     * 解析出的等价路径都可能出现。只比对字面量会漏。
     */
    if (path != NULL && g_config.guest_exe != NULL && g_config.guest_exe[0] != '\0') {
        int is_self_exe = 0;

        if (strcmp(path, "/proc/self/exe") == 0 ||
            strcmp(path, "/proc/thread-self/exe") == 0) {
            is_self_exe = 1;
        } else if (strncmp(path, "/proc/", 6) == 0) {
            /* /proc/<pid>/exe —— 只认形状，不校验 pid */
            const char *p = path + 6;
            const char *slash = strchr(p, '/');
            if (slash != NULL && strcmp(slash, "/exe") == 0 &&
                slash != p) {
                is_self_exe = 1;
            }
        }

        if (is_self_exe) {
            /*
             * readlink(2) 的语义：**不补 NUL**，只写至多 buf_size 字节，
             * 返回实际写入的字节数。这里必须严格照做。
             *
             * 曾经写成"截断后 memcpy 并返回 len"，看起来对，但若
             * strlen(guest_exe) >= buf_size，客户拿到的是一个**没有终止符**
             * 的缓冲 —— 客户随后 strlen(buf) 就越界读。
             *
             * （官方同样不补 NUL。契约如此，我们不能"好心"多写一个字节：
             *   buf_size 恰为 len 时多写就是缓冲溢出。）
             */
            size_t len = strlen(g_config.guest_exe);
            if (len > buf_size)
                len = buf_size;
            memcpy(buf, g_config.guest_exe, len);
            return (ssize_t)len;
        }
    }

    /*
     * ★ 必须把**翻译后的宿主路径**交给 l2s 层，不是客户给的 guest 路径 ★
     *
     * l2s 层的一切 FS 操作都在宿主侧（中间层、数据文件都在 rootfs 内），
     * 它的 probe_fake_link() 会拿这个路径去 lstat。用 guest 路径它就
     * probe 不到，readlink 于是原样漏出内部名 ".l2s.a0001"。
     *
     * 这与 stat/lstat 钩子处的做法一致（那里传的也是 p）。
     */
    if (translate_path(path, translated, sizeof(translated)) > 0) {
        p = translated;
        n = real_readlink(translated, buf, buf_size);
    } else {
        n = real_readlink(path, buf, buf_size);
    }
    if (n <= 0)
        return n;

    /*
     * ★ D3 修复：/proc 泄漏的反向翻译，必须在 l2s 重写**之前**做 ★
     *
     * 内核对 /proc/self/fd/N、/proc/self/cwd、/proc/self/root 返回的
     * 是宿主路径；客户期望 guest 视角。不剥的话，客户把它再喂回
     * open()/stat() 会双重翻译或 ENOENT（实测：内核真值 n=61 带
     * $ROOTFS 前缀）。socket:[N]/pipe:[N] 等非路径形态在 fixup 内部
     * 被规则 1 原样放行。
     */
    {
        char fixedp[MAX_PATH_LEN];
        if (n < (ssize_t)sizeof(fixedp)) {
            char rawp[MAX_PATH_LEN];
            memcpy(rawp, buf, (size_t)n);
            rawp[n] = '\0';
            if (readlink_fixup(rawp, fixedp, sizeof(fixedp)) == 1) {
                size_t flen = strlen(fixedp);
                if (flen > buf_size)
                    flen = buf_size;      /* 截断，与 readlink(2) 语义一致 */
                memcpy(buf, fixedp, flen);
                return (ssize_t)flen;
            }
        }
    }

    /*
     * 伪造链接的 readlink 必须失败（EINVAL）—— 见 l2s_rt_rewrite_readlink
     * 的长注释。判据在 l2s 层，这里只负责把哨兵转成 errno 语义。
     */
    {
        char raw[MAX_PATH_LEN];
        char fixed[MAX_PATH_LEN];
        size_t copy = (size_t)n < sizeof(raw) - 1 ? (size_t)n : sizeof(raw) - 1;
        int lrc;

        memcpy(raw, buf, copy);
        raw[copy] = '\0';

        lrc = l2s_rt_rewrite_readlink(p, raw, fixed, sizeof(fixed));
        if (lrc == L2S_RT_READLINK_FAKE) {
            errno = EINVAL;
            return -1;
        }
        if (lrc == 1) {
            size_t flen = strlen(fixed);
            if (flen > buf_size)
                flen = buf_size;          /* 截断，与 readlink(2) 语义一致 */
            memcpy(buf, fixed, flen);
            return (ssize_t)flen;
        }
    }
    return n;
}

/*
 * realpath 返回值的反向翻译（8.2 修复）。
 *
 * realpath()/canonicalize_file_name() 解析符号链接后返回的是**宿主绝对
 * 路径**（正向翻译过的 path 交给 real_realpath，内核在宿主上解析），
 * 客户期望的是 **guest 视角**。不修的实测后果：tar/git 的绝对路径、
 * 路径相等性判断全错 —— 同一个文件经两条 API 得到两个"不同"的名字。
 *
 * 改写规则与 getcwd_fixup 完全一致（先剥 rootfs 前缀，再反 bind）：
 *   1. 剥 $ROOTFS 前缀（仅组件边界；剥后空串说明正在 rootfs 根 → "/"）；
 *   2. detranslate_binds：结果仍落在某个 bind 的 source（宿主路径）下时，
 *      换回 target（guest 名）。bind source 命中时以 detranslate_binds
 *      的结果为准 —— 与 getcwd_fixup 的串联顺序一致：先脱 rootfs，再脱 bind。
 *
 * 返回 1 = buf 已重写；0 = 保持 real_realpath 的返回值。
 *
 * ★ 原地 memmove 的安全性论证 ★
 * 两个步骤都只让字符串变短或等长（剥前缀是 memmove 前移；bind 反查的
 * target 语义上是 guest 短名，且 snprintf 截断保护兜底），因此可以在
 * 调用方的缓冲上原地修整 —— resolved_path 给的栈缓冲和 glibc malloc
 * 返回的堆缓冲（realpath(path, NULL)）都适用。
 *
 * cap = 缓冲可用字节数：
 *   - 栈缓冲传 sizeof(buf)；
 *   - glibc malloc 返回的堆缓冲没有可查的容量，传 SIZE_MAX 表示
 *     "不会越界"（与 getcwd(NULL, 0) 分支的既有先例一致 —— 剥前缀只缩
 *     不涨，bind 反查的目标名也短于宿主前缀，实际不会写入超过原串长度）。
 */
static int realpath_fixup_inplace(char *buf, size_t cap)
{
    int changed;

    if (buf == NULL)
        return 0;

    /* 第 1 步：剥 rootfs 前缀（组件边界；空余 → "/"） */
    changed = strip_rootfs_prefix_inplace(buf);

    /* 第 2 步：反向 bind 映射（source 命中时优先用它的结果）。
     * 与 getcwd_fixup 顺序一致：先剥 rootfs，再反 bind —— 两者串联，
     * 且 rootfs 之外的 bind 只有这一步能处理。 */
    {
        char reb[MAX_PATH_LEN];

        if (detranslate_binds(buf, reb, sizeof(reb)) == 1) {
            size_t need = strlen(reb) + 1;

            if (need > cap)
                return changed;         /* 放不下：保留已剥前缀的结果 */
            memcpy(buf, reb, need);
            return 1;
        }
    }
    return changed;
}

/* Hook: realpath */
char *realpath(const char *path, char *resolved) {
    ensure_real_functions();

    char translated[MAX_PATH_LEN];
    char *r;

    if (translate_path(path, translated, sizeof(translated)) > 0)
        r = real_realpath(translated, resolved);
    else
        r = real_realpath(path, resolved);

    if (r == NULL)
        return NULL;   /* 失败路径：不动（8.2 任务约束 3） */

    /*
     * ★ resolved == NULL 分支也要修整 ★
     *
     * glibc 此时在堆上按需分配返回缓冲（realpath(path, NULL)，
     * bash/dash 的 abs 目录解析走这条）。那里没有可查的容量，传
     * SIZE_MAX —— 剥前缀只会变短，原地 memmove 安全
     * （getcwd(NULL, 0) 分支已有同款处理先例）。
     *
     * 栈缓冲分支传 PATH_MAX：glibc 的契约是向 resolved 至多写
     * PATH_MAX 字节（调用方因此按 PATH_MAX 备缓冲），cap 取同一值
     * 可保证 bind 反查的 memcpy 绝不越过调用方缓冲的真实边界
     * （sizeof(translated)=8192 会虚高，不能用）。
     */
    realpath_fixup_inplace(r, resolved == NULL ? SIZE_MAX : (size_t)PATH_MAX);
    return r;
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
/* 前向声明：定义在本文件"l2s 启用核心"一节（init_l2s 之后）。 */
static int l2s_autostart_on_link_failure(void);

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

    if (fn == NULL) fn = (int (*)(const char *, const char *))bxroot_next_symbol("link");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    rc = fn(po, pn);
    if (rc == 0)
        return 0;

    /*
     * ★ 真实 link 被内核拒绝 → 自动启用 l2s 并重试一次 ★
     *
     * 只对"环境不允许硬链接"的三种 errno 回退；别的错误（ENOENT、
     * EEXIST、EXDEV…）是**调用方自己的问题**，回退只会掩盖真实故障。
     * 详见上方 l2s_autostart_on_link_failure() 的注释。
     */
    if ((errno == EACCES || errno == EPERM || errno == ENOSYS) &&
        l2s_autostart_on_link_failure()) {
        rc = l2s_rt_link(po, pn);
        if (rc == 0)
            return 0;
        if (rc != L2S_RT_PASSTHRU) {
            errno = -rc;
            return -1;
        }
    }
    return rc;
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

    if (fn == NULL) fn = (int (*)(int, const char *, int, const char *, int))bxroot_next_symbol("linkat");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    rc = fn(olddirfd, po, newdirfd, pn, flags);
    if (rc == 0)
        return 0;

    /* 与 link() 同理：环境禁硬链接时自动启用 l2s（见那里的注释） */
    if ((errno == EACCES || errno == EPERM || errno == ENOSYS) &&
        l2s_autostart_on_link_failure()) {
        rc = l2s_rt_link(po, pn);
        if (rc == 0)
            return 0;
        if (rc != L2S_RT_PASSTHRU) {
            errno = -rc;
            return -1;
        }
    }
    return rc;
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

    if (fn == NULL) fn = (int (*)(const char *))bxroot_next_symbol("unlink");
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
 * 参考实现的 D7 域专门覆盖这些（GAP-ANALYSIS 把它列为 P1 关键）。
 *
 * 实现上它们只是**薄转发**：真实符号仍在 glibc 里导出着，
 * 用 dlsym(RTLD_NEXT) 拿得到，翻译逻辑与主 hook 完全一致。
 */

/* __open_2(path, flags) —— 无 mode 参数（O_CREAT 时 glibc 会走非 FORTIFY 版） */
int __open_2(const char *path, int flags) {
    static int (*fn)(const char *, int) = NULL;
    char translated[MAX_PATH_LEN];
    char resolved[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (int (*)(const char *, int))bxroot_next_symbol("__open_2");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    /*
     * ★ l2s 解链必须在这里也做一遍 ★
     *
     * __open_2 / __openat_2 是 glibc 的 _FORTIFY_SOURCE 变体，
     * **完全绕过 open()/openat()**。tar 正是用它们打开成员的：
     *     nm -D tar | grep open
     *       U __open_2
     *       U __openat_2
     * 所以前一版只修 open/openat/open64/openat64 时，tar 走的这条
     * 路完全没有解链，O_NOFOLLOW 直接撞上磁盘上的符号链接 → ELOOP。
     */
    p = l2s_open_path(p, flags, resolved, sizeof(resolved));
    return fn(p, flags);
}

int __open64_2(const char *path, int flags) {
    static int (*fn)(const char *, int) = NULL;
    char translated[MAX_PATH_LEN];
    char resolved[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (int (*)(const char *, int))bxroot_next_symbol("__open64_2");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    /* 与 __open_2 同理：fortify 变体绕过 open64，也要解链 */
    p = l2s_open_path(p, flags, resolved, sizeof(resolved));
    return fn(p, flags);
}

int __openat_2(int dirfd, const char *path, int flags) {
    static int (*fn)(int, const char *, int) = NULL;
    char translated[MAX_PATH_LEN];
    char joined[MAX_PATH_LEN];
    char resolved[MAX_PATH_LEN];
    const char *p;

    if (fn == NULL)
        fn = (int (*)(int, const char *, int))bxroot_next_symbol("__openat_2");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    /* 与 __open_2 同理：fortify 变体绕过 openat，必须自己解链。
     * 且相对名要先按 dirfd 拼成绝对路径，否则 O_NOFOLLOW 撞上
     * 伪造链接 → ELOOP（tar 的 "Cannot open"）。 */
    p = resolve_host_path(dirfd, path, joined, sizeof(joined),
                          translated, sizeof(translated));
    p = l2s_open_path(p, flags, resolved, sizeof(resolved));
    return fn(dirfd, p, flags);
}

int __openat64_2(int dirfd, const char *path, int flags) {
    static int (*fn)(int, const char *, int) = NULL;
    char translated[MAX_PATH_LEN];
    char joined[MAX_PATH_LEN];
    char resolved[MAX_PATH_LEN];
    const char *p;

    if (fn == NULL)
        fn = (int (*)(int, const char *, int))bxroot_next_symbol("__openat64_2");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    /* 与 __openat_2 同理：dirfd 拼绝对路径 + l2s 解链 */
    p = resolve_host_path(dirfd, path, joined, sizeof(joined),
                          translated, sizeof(translated));
    p = l2s_open_path(p, flags, resolved, sizeof(resolved));
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
             bxroot_next_symbol("__readlink_chk");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    n = fn(p, buf, len, buflen);
    if (n <= 0)
        return n;

    /* 与 readlink 一致：伪造链接必须 EINVAL（理由见 readlink 钩子） */
    {
        char raw[MAX_PATH_LEN];
        char fixed[MAX_PATH_LEN];
        size_t copy = (size_t)n < sizeof(raw) - 1 ? (size_t)n : sizeof(raw) - 1;
        int lrc;

        memcpy(raw, buf, copy);
        raw[copy] = '\0';

        lrc = l2s_rt_rewrite_readlink(p, raw, fixed, sizeof(fixed));
        if (lrc == L2S_RT_READLINK_FAKE) {
            errno = EINVAL;
            return -1;
        }
        if (lrc == 1) {
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
             bxroot_next_symbol("__readlinkat_chk");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    n = fn(dirfd, p, buf, len, buflen);
    if (n <= 0)
        return n;

    {
        char joined[MAX_PATH_LEN];
        char raw[MAX_PATH_LEN];
        char fixed[MAX_PATH_LEN];
        size_t copy = (size_t)n < sizeof(raw) - 1 ? (size_t)n : sizeof(raw) - 1;
        int lrc;

        /* 与 readlinkat 一致：相对名要靠 dirfd 拼成绝对路径（见那里的注释） */
        if (resolve_dirfd_path(dirfd, path, joined, sizeof(joined)) == 1) {
            if (translate_path(joined, translated, sizeof(translated)) > 0)
                p = translated;
            else
                p = joined;
        }

        memcpy(raw, buf, copy);
        raw[copy] = '\0';

        lrc = l2s_rt_rewrite_readlink(p, raw, fixed, sizeof(fixed));
        if (lrc == L2S_RT_READLINK_FAKE) {
            errno = EINVAL;
            return -1;
        }
        if (lrc == 1) {
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
 * 翻译方向与 realpath hook 一致：正向翻译入参，返回值反向翻译。
 * （历史上这里只做正向 —— 当时注释明确以"与现有 realpath hook 的
 * 行为保持一致，不引入新的不一致"为约束；8.2 修复 realpath 后，
 * 本函数同步跟进，否则反而制造出新的不一致。）
 */
char *__realpath_chk(const char *path, char *resolved, size_t resolvedlen) {
    static char *(*fn)(const char *, char *, size_t) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;
    char *r;

    if (fn == NULL)
        fn = (char *(*)(const char *, char *, size_t))
             bxroot_next_symbol("__realpath_chk");
    if (fn == NULL) { errno = ENOSYS; return NULL; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    r = fn(p, resolved, resolvedlen);
    if (r == NULL)
        return NULL;   /* 失败路径：不动 */

    /* resolved == NULL 时 glibc malloc 返回堆缓冲 → SIZE_MAX（同 realpath）；
     * 否则调用方给了 resolvedlen（_FORTIFY_SOURCE 保证 >= PATH_MAX），
     * 直接用真实容量。 */
    realpath_fixup_inplace(r, resolved == NULL ? SIZE_MAX : resolvedlen);
    return r;
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
        fn = (int (*)(int, const char *, struct stat *))bxroot_next_symbol("__xstat");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    /*
     * ★ ver 参数归一化为 0 ★
     *
     * `__xstat`/`__lxstat`/`__fxstat` 家族是 glibc 的旧 ABI，第一个
     * 参数是「结构体版本」。aarch64 上 glibc 只认 `_STAT_VER == 0`
     * （glibc 2.33+ 已把该宏从公开头文件移除，所以直接写字面量）。
     *
     * 调用方可能传别的值（旧约定/其他架构的习惯），此时 glibc 回
     * EINVAL，客户于是以为 stat 失败、退化成 open 探测 —— 那正是
     * `tar`/`dash` 走到 ELOOP 的那条路。
     *
     * 实测（/root/probe/ver.c，ver=0..3 逐个测）：
     *     官方  : ver=0,1,2,3 全部 rc=0 OK
     *     bxroot: ver=0 OK，ver=1,2,3 → EINVAL   ← 修前
     * 官方对任意 ver 都接受，所以这里归一化成 0 与它对齐。
     */
    rc = fn(0, p, buf);
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
        fn = (int (*)(int, const char *, struct stat *))bxroot_next_symbol("__lxstat");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    /*
     * ★ ver 参数归一化为 0 ★
     *
     * `__xstat`/`__lxstat`/`__fxstat` 家族是 glibc 的旧 ABI，第一个
     * 参数是「结构体版本」。aarch64 上 glibc 只认 `_STAT_VER == 0`
     * （glibc 2.33+ 已把该宏从公开头文件移除，所以直接写字面量）。
     *
     * 调用方可能传别的值（旧约定/其他架构的习惯），此时 glibc 回
     * EINVAL，客户于是以为 stat 失败、退化成 open 探测 —— 那正是
     * `tar`/`dash` 走到 ELOOP 的那条路。
     *
     * 实测（/root/probe/ver.c，ver=0..3 逐个测）：
     *     官方  : ver=0,1,2,3 全部 rc=0 OK
     *     bxroot: ver=0 OK，ver=1,2,3 → EINVAL   ← 修前
     * 官方对任意 ver 都接受，所以这里归一化成 0 与它对齐。
     */
    rc = fn(0, p, buf);
    /* 与 lstat 保持一致：参考实现同样对 lstat 家族做 owner 改写 */
    if (rc == 0 && g_fakeroot_on)
        fakeroot_patch_stat(buf, &g_fakeroot_state);
    /* l2s：__lxstat 是 lstat 的旧 ABI 入口，同样要抹掉 S_IFLNK */
    if (rc == 0)
        l2s_rt_patch_stat(buf, p);
    /* -L：__lxstat 是 lstat 的旧 ABI 入口，语义相同（必须在 l2s 之后） */
    if (rc == 0)
        l2s_fix_symlink_size(buf, p);
    return rc;
}

int __fxstat(int ver, int fd, struct stat *buf) {
    static int (*fn)(int, int, struct stat *) = NULL;
    int rc;

    if (fn == NULL)
        fn = (int (*)(int, int, struct stat *))bxroot_next_symbol("__fxstat");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    /*
     * ★ ver 参数归一化为 0 ★
     *
     * `__xstat`/`__lxstat`/`__fxstat` 家族是 glibc 的旧 ABI，第一个
     * 参数是「结构体版本」。aarch64 上 glibc 只认 `_STAT_VER == 0`
     * （glibc 2.33+ 已把该宏从公开头文件移除，所以直接写字面量）。
     *
     * 调用方可能传别的值（旧约定/其他架构的习惯），此时 glibc 回
     * EINVAL，客户于是以为 stat 失败、退化成 open 探测 —— 那正是
     * `tar`/`dash` 走到 ELOOP 的那条路。
     *
     * 实测（/root/probe/ver.c，ver=0..3 逐个测）：
     *     官方  : ver=0,1,2,3 全部 rc=0 OK
     *     bxroot: ver=0 OK，ver=1,2,3 → EINVAL   ← 修前
     * 官方对任意 ver 都接受，所以这里归一化成 0 与它对齐。
     */
    rc = fn(0, fd, buf);
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
        fn = (int (*)(int, const char *, struct stat64 *))bxroot_next_symbol("__xstat64");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    /*
     * ★ ver 参数归一化为 0 ★
     *
     * `__xstat`/`__lxstat`/`__fxstat` 家族是 glibc 的旧 ABI，第一个
     * 参数是「结构体版本」。aarch64 上 glibc 只认 `_STAT_VER == 0`
     * （glibc 2.33+ 已把该宏从公开头文件移除，所以直接写字面量）。
     *
     * 调用方可能传别的值（旧约定/其他架构的习惯），此时 glibc 回
     * EINVAL，客户于是以为 stat 失败、退化成 open 探测 —— 那正是
     * `tar`/`dash` 走到 ELOOP 的那条路。
     *
     * 实测（/root/probe/ver.c，ver=0..3 逐个测）：
     *     官方  : ver=0,1,2,3 全部 rc=0 OK
     *     bxroot: ver=0 OK，ver=1,2,3 → EINVAL   ← 修前
     * 官方对任意 ver 都接受，所以这里归一化成 0 与它对齐。
     */
    rc = fn(0, p, buf);
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
        fn = (int (*)(int, const char *, struct stat64 *))bxroot_next_symbol("__lxstat64");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    /*
     * ★ ver 参数归一化为 0 ★
     *
     * `__xstat`/`__lxstat`/`__fxstat` 家族是 glibc 的旧 ABI，第一个
     * 参数是「结构体版本」。aarch64 上 glibc 只认 `_STAT_VER == 0`
     * （glibc 2.33+ 已把该宏从公开头文件移除，所以直接写字面量）。
     *
     * 调用方可能传别的值（旧约定/其他架构的习惯），此时 glibc 回
     * EINVAL，客户于是以为 stat 失败、退化成 open 探测 —— 那正是
     * `tar`/`dash` 走到 ELOOP 的那条路。
     *
     * 实测（/root/probe/ver.c，ver=0..3 逐个测）：
     *     官方  : ver=0,1,2,3 全部 rc=0 OK
     *     bxroot: ver=0 OK，ver=1,2,3 → EINVAL   ← 修前
     * 官方对任意 ver 都接受，所以这里归一化成 0 与它对齐。
     */
    rc = fn(0, p, buf);
    if (rc == 0 && g_fakeroot_on)
        fakeroot_patch_stat64(buf, &g_fakeroot_state);
    /* l2s：与 __xstat 家族一致 */
    if (rc == 0)
        l2s_rt_patch_stat((struct stat *)buf, p);
    /* -L：__lxstat64 是 lstat64 的旧 ABI 入口（必须在 l2s 之后） */
    if (rc == 0)
        l2s_fix_symlink_size((struct stat *)buf, p);
    return rc;
}

int __fxstat64(int ver, int fd, struct stat64 *buf) {
    static int (*fn)(int, int, struct stat64 *) = NULL;
    int rc;

    if (fn == NULL)
        fn = (int (*)(int, int, struct stat64 *))bxroot_next_symbol("__fxstat64");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    /*
     * ★ ver 参数归一化为 0 ★
     *
     * `__xstat`/`__lxstat`/`__fxstat` 家族是 glibc 的旧 ABI，第一个
     * 参数是「结构体版本」。aarch64 上 glibc 只认 `_STAT_VER == 0`
     * （glibc 2.33+ 已把该宏从公开头文件移除，所以直接写字面量）。
     *
     * 调用方可能传别的值（旧约定/其他架构的习惯），此时 glibc 回
     * EINVAL，客户于是以为 stat 失败、退化成 open 探测 —— 那正是
     * `tar`/`dash` 走到 ELOOP 的那条路。
     *
     * 实测（/root/probe/ver.c，ver=0..3 逐个测）：
     *     官方  : ver=0,1,2,3 全部 rc=0 OK
     *     bxroot: ver=0 OK，ver=1,2,3 → EINVAL   ← 修前
     * 官方对任意 ver 都接受，所以这里归一化成 0 与它对齐。
     */
    rc = fn(0, fd, buf);
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
/*
 * getcwd 的反向翻译：剥 rootfs 前缀 + 反向 bind 映射。
 *
 * 【为什么抽成函数（实测缺陷）】
 *
 * 早前 getcwd() 只给 `buf != NULL` 分支做反向翻译，`buf == NULL` 分支
 * 直接 `return fn(NULL, size)` —— 注释写着"glibc 会 malloc 一块，我们不能
 * 用栈缓冲替代"，解释是对的，但结论是"什么都不做"，于是
 * `getcwd(NULL, 0)` 把**未处理的宿主路径**交给了客户。
 *
 * 实测（/root/fsize/gwf.c，同一进程两个分支）：
 *     官方  : getcwd(buf,size)=/tmp    getcwd(NULL,0)=/tmp
 *     bxroot: getcwd(buf,size)=/tmp    getcwd(NULL,0)=/data/.../ubuntu/tmp  ❌
 *
 * 后果（真实，不是理论）：**dash 的内置 cd/pwd 用的正是 getcwd(NULL, 0)**。
 * 它拿到带 rootfs 前缀的路径后，对 cwd 的认知就错了，于是
 *     cd /tmp/d; ls      → 列出的是 **rootfs 根**（bin boot data ...）
 * 而 `pwd` 看上去是对的（那是 dash 自己的记账）。
 *
 * 修法：把修整逻辑抽出来，两个分支都调它。glibc 的 getcwd(NULL, n)
 * 分配的是"实际路径长度 + 余量"，而剥前缀只会让路径**更短**，
 * 所以对 malloc 缓冲原地 memmove 一定放得下。
 *
 * 返回 0 成功；-ERANGE 表示调用方给的缓冲装不下（仅 buf != NULL 分支可能）。
 */
/*
 * 宿主路径 → guest 路径的核心反向翻译（原地）。
 *
 * 【抽出来共享的动机 —— D3 缺陷】
 * 这段逻辑原先只属于 getcwd：readlink("/proc/self/fd/N") 返回的
 * 同样是宿主路径（内核把 fd 的真实位置暴露出来），却没有任何反向
 * 翻译，客户拿到带 $ROOTFS 前缀的路径后：
 *   - 打日志/比较路径时出现"陌生前缀"；
 *   - 把它再喂回 open()/stat() 会**双重翻译**（<rootfs><rootfs>/...）
 *     或直接 ENOENT。
 *
 * 剥前缀只会让路径更短，原地 memmove 对调用方给的缓冲总是安全的。
 * 返回 1 = 已剥；0 = 没动（路径不在 rootfs 之下）。
 */
static int strip_rootfs_prefix_inplace(char *buf)
{
    const char *rootfs;
    size_t rl;

    if (buf == NULL)
        return 0;

    /*
     * 只在**组件边界**上剥（前缀后面必须是 '\0' 或 '/'），
     * 否则 `/foo/rootfsXYZ` 会被误当成 `/foo/rootfs` 下的路径。
     * 剥完如果剩空串，说明正处于 rootfs 根 —— 返回 "/"。
     */
    rootfs = g_config.rootfs ? g_config.rootfs : "";
    rl = strlen(rootfs);
    if (rl == 0)
        return 0;

    if (strncmp(buf, rootfs, rl) == 0 &&
        (buf[rl] == '\0' || buf[rl] == '/')) {
        const char *rest = buf + rl;
        size_t restlen = strlen(rest);

        if (restlen == 0) {
            /* 正好在 rootfs 根 */
            buf[0] = '/';
            buf[1] = '\0';
            return 1;
        }
        /* rest 以 '/' 开头，直接前移即可（含结尾 NUL） */
        memmove(buf, rest, restlen + 1);
        return 1;
    }
    return 0;
}

/*
 * readlink 系返回值的反向翻译（D3 修复）。
 *
 * 内核对这三类 /proc 链接返回的是**宿主视角**：
 *   /proc/<pid>/fd/N   → fd 真实指向的宿主路径
 *   /proc/<pid>/cwd    → 宿主 cwd
 *   /proc/<pid>/root   → 宿主 rootfs 前缀
 * 客户期望 guest 视角。判别与改写规则：
 *
 *   1. 返回值不以 '/' 开头 → 不动。/proc 对 socket/pipe 返回
 *      "socket:[123]"、"pipe:[456]"、对匿名 inode 返回
 *      "anon_inode:..." —— 这些是内核契约格式，绝不能碰。
 *   2. /proc/<pid>/root/... → 剥 /proc/<pid>/root 前缀后，
 *      剩余部分当作 rootfs 内路径继续剥 $ROOTFS 前缀。
 *   3. 其余绝对路径 → 走与 getcwd 相同的反向翻译
 *      （剥 rootfs 前缀 + 反向 bind），原因同上：双重翻译风险。
 *
 * 返回 1 = out 已重写；0 = 保持内核返回值。
 */
static int readlink_fixup(const char *raw, char *out, size_t outsz)
{
    if (raw == NULL || out == NULL || outsz == 0)
        return 0;

    /* 规则 1：非绝对路径一律保持原样（socket:[N] / pipe:[N] / anon_inode:...） */
    if (raw[0] != '/')
        return 0;

    /* 规则 2：/proc/<pid>/root 与 /proc/<pid>/root/<path> */
    if (strncmp(raw, "/proc/", 6) == 0) {
        const char *rest = raw + 6;
        const char *slash = strchr(rest, '/');
        if (slash != NULL && slash != rest) {
            if (strcmp(slash, "/root") == 0) {
                /* 客户的 / 就是 /（内核给的是宿主 rootfs 前缀） */
                snprintf(out, outsz, "/");
                return 1;
            }
            if (strncmp(slash, "/root/", 6) == 0) {
                char tmp[MAX_PATH_LEN];
                snprintf(tmp, sizeof(tmp), "%s", slash + 5);  /* "/..." */
                (void)strip_rootfs_prefix_inplace(tmp);
                if (detranslate_binds(tmp, out, outsz) == 1)
                    return 1;
                snprintf(out, outsz, "%s", tmp);
                return 1;
            }
        }
    }

    /* 规则 3：普通宿主路径（fd 指向 rootfs 内文件、cwd 等）。
     * 两个反向步骤在同一缓冲上串联（先剥 rootfs，再反 bind），
     * 与 getcwd_fixup 的顺序一致。 */
    {
        char tmp[MAX_PATH_LEN];
        int changed;

        snprintf(tmp, sizeof(tmp), "%s", raw);
        changed = strip_rootfs_prefix_inplace(tmp);
        if (detranslate_binds(tmp, out, outsz) == 1)
            return 1;
        if (changed) {
            snprintf(out, outsz, "%s", tmp);
            return 1;
        }
    }

    /*
     * 规则 4：fd 指向 rootfs 的**祖先目录** → guest 视角是 "/"（上游断言）。
     *
     * 【为什么需要，来自上游用例 test-51943658.c】
     * 该用例（截取）：
     *     dir_fd = open("/", O_RDONLY);
     *     dir_fd1 = openat(dir_fd, ".", O_RDONLY);
     *     dir_fd2 = openat(dir_fd, "..", O_RDONLY);
     *     readlink("/proc/self/fd/<dir_fd1>") 必须等于 "/"
     *     readlink("/proc/self/fd/<dir_fd2>") 必须等于 "/"   ← 这一条我们没过
     *
     * 【机制】guest 的 "/" 在宿主上是 $ROOTFS。fd2 = openat($ROOTFS-fd,
     * "..") 在内核里解析为 **$ROOTFS 的父目录**（rootfs 之外！），于是
     * 内核返回 `/data/data/.../linux/ubuntu/..` 实际解析后的宿主路径
     * `/data/data/.../linux`。这个路径**不含 $ROOTFS 前缀**，规则 3 的
     * 剥离不命中，于是原样泄漏给客户（实测：得到
     * `/data/data/com.dsh.client/files/linux`，期望 "/"）。
     *
     * 【修法】客户能"从 / 往上一级"走到的地方，在我们眼里就是 rootfs
     * 的祖先链 —— 从 guest 视角看只有一个答案："/"。判据是
     * "raw 是 rootfs 的祖先目录（或 rootfs 本身之外的上级）"：
     * rootfs 及其祖先链上的每一级，guest 视角都映射到 "/"。
     *
     * 只在 raw 确实位于 rootfs 的祖先链上时改写，不是"任何 rootfs 外的
     * 路径都变 /" —— 后者会把宿主真实路径也吞掉。
     */
    {
        const char *rootfs = g_config.rootfs ? g_config.rootfs : "";
        size_t rl = strlen(rootfs);

        if (rl > 0 && raw[0] == '/' && strncmp(raw, rootfs, rl) != 0) {
            /*
             * raw 不是 rootfs 自身/其下 —— 检查它是否在 rootfs 的祖先链上：
             *   - raw == "/" ：祖先链顶端，恒真；
             *   - 否则 rootfs 必须以 raw 开头，且 raw 之后紧跟 '/'（组件
             *     边界），防止 /data/rootfX 这类同前缀误命中。
             */
            size_t ql = strlen(raw);
            int is_ancestor = 0;

            if (ql == 1) {                    /* raw == "/" */
                is_ancestor = 1;
            } else if (ql < rl && strncmp(rootfs, raw, ql) == 0 &&
                       rootfs[ql] == '/') {
                is_ancestor = 1;
            }

            if (is_ancestor) {
                snprintf(out, outsz, "/");
                return 1;
            }
        }
    }
    return 0;
}

static int getcwd_fixup(char *buf, size_t size)
{
    const char *rootfs;
    size_t rl;

    if (buf == NULL)
        return 0;

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
        return 0;

    if (strncmp(buf, rootfs, rl) == 0 &&
        (buf[rl] == '\0' || buf[rl] == '/')) {
        const char *rest = buf + rl;
        size_t restlen = strlen(rest);

        if (restlen == 0) {
            /* 正好在 rootfs 根 */
            if (size < 2)
                return -ERANGE;
            buf[0] = '/';
            buf[1] = '\0';
            return 0;
        }
        /* rest 以 '/' 开头，直接前移即可（含结尾 NUL） */
        memmove(buf, rest, restlen + 1);
    }

    /*
     * 反向 bind 映射。
     *
     * 剥完 rootfs 前缀之后，路径可能仍落在某个 bind 的 **source**
     * （宿主路径）之下 —— 客户不该看到那个名字。典型场景就是
     * `-b /storage/emulated/0:/sdcard`：内核给的 cwd 是
     * `/storage/emulated/0/Download/...`，而客户以为自己在
     * `/sdcard/Download/...`。
     *
     * 不做这一步的实测后果：dsh 会拿宿主路径去读 `.env`，撞上
     * FUSE 的 EACCES（而正确路径下那是 ENOENT，被静默忽略），
     * 进而打断启动流程。
     *
     * 放在 rootfs 剥离**之后**：两者是串联的（先脱 rootfs，再脱 bind），
     * 且 rootfs 之外的 bind 只有这一步能处理。
     */
    {
        char reb[MAX_PATH_LEN];
        if (detranslate_binds(buf, reb, sizeof(reb)) == 1) {
            size_t need = strlen(reb) + 1;
            if (need > size)
                return -ERANGE;
            memcpy(buf, reb, need);
        }
    }
    return 0;
}

char *getcwd(char *buf, size_t size) {
    static char *(*fn)(char *, size_t) = NULL;
    char *r;

    if (fn == NULL)
        fn = (char *(*)(char *, size_t))bxroot_next_symbol("getcwd");
    if (fn == NULL) { errno = ENOSYS; return NULL; }

    /*
     * ★ buf == NULL 也要修整 ★
     *
     * 不能用自己的栈缓冲替代 glibc 的 malloc（注释原本就说明了这点），
     * 但**可以**在 glibc 返回的缓冲上原地修整 —— 那是它的堆内存，
     * 剥前缀只会让路径更短，原地 memmove 安全。
     *
     * 这是 dash 的 cd/pwd 走的路径（它用 getcwd(NULL, 0)），不修就会
     * 让 shell 对 cwd 的认知错位（`ls` 列 rootfs 根）。
     */
    if (buf == NULL) {
        r = fn(NULL, size);
        if (r == NULL)
            return NULL;
        /*
         * size 传 0 时 glibc 按需分配；估算可用容量用已分配长度。
         * 这里传 SIZE_MAX 语义上表示"缓冲足够大，不会 ENOSPC" ——
         * 剥前缀只缩不涨，bind 反查的目标名也短于宿主前缀。
         */
        if (getcwd_fixup(r, SIZE_MAX) != 0) {
            /* 理论上到不了；真到了也不能返回错的东西 */
            errno = ERANGE;
            return NULL;
        }
        return r;
    }

    r = fn(buf, size);
    if (r == NULL)
        return NULL;

    if (getcwd_fixup(buf, size) != 0) {
        errno = ERANGE;
        return NULL;
    }
    return r;
}

/*
 * Hook: canonicalize_file_name(path)
 *
 * 等价于 realpath(path, NULL)（glibc 扩展），cp/mv/stat 都在用。
 * 翻译方向与 realpath 一致：正向翻译入参，返回值反向翻译（8.2 修复）。
 */
char *canonicalize_file_name(const char *path) {
    static char *(*fn)(const char *) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;
    char *r;

    if (fn == NULL)
        fn = (char *(*)(const char *))bxroot_next_symbol("canonicalize_file_name");
    if (fn == NULL) { errno = ENOSYS; return NULL; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    r = fn(p);
    if (r == NULL)
        return NULL;   /* 失败路径：不动 */

    /* 无缓冲实参，glibc 必走 malloc 返回 → SIZE_MAX（同 realpath 的
     * resolved == NULL 分支）。 */
    realpath_fixup_inplace(r, SIZE_MAX);
    return r;
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
        fn = (int (*)(int, struct stat *))bxroot_next_symbol("fstat");
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
        fn = (int (*)(int, struct stat64 *))bxroot_next_symbol("fstat64");
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
    char joined[MAX_PATH_LEN];
    const char *p = path;
    int rc;

    if (fn == NULL && fn_fx == NULL) {
        fn = (int (*)(int, const char *, struct stat *, int))
             bxroot_next_symbol("fstatat");
        if (fn == NULL)
            fn_fx = (int (*)(int, int, const char *, struct stat *, int))
                    bxroot_next_symbol("__fxstatat");
    }

    /*
     * ★ 必须按 dirfd 解析相对名 ★
     *
     * translate_path() 只翻绝对路径；相对名（tar 的
     * openat+fstatat 组合、node 的 dirfd 用法）原样返回，
     * 于是 l2s 层拿 "a" 去 probe —— 那是相对**进程 cwd**
     * 解析的，不是相对 dirfd。cwd 恰好等于 dirfd 时看着
     * 是对的，一旦不同就 probe 不到，伪造链接的 S_IFLNK
     * 抹不掉 → 客户（tar）判定"这是符号链接" → 去 readlink
     * → EINVAL → "Cannot readlink" 而失败。
     */
    p = resolve_host_path(dirfd, path, joined, sizeof(joined),
                          translated, sizeof(translated));

    if (fn != NULL) {
        rc = fn(dirfd, p, buf, flags);
    } else if (fn_fx != NULL) {
        /*
         * _STAT_VER：aarch64 上是 **0**，不是 1。
         * 早前硬编码成 1（x86_64 的值）—— 只因这条兜底分支在
         * glibc 2.33+ 上从不被走到（fstatat 符号本身存在）才没暴露。
         * 一旦走到，glibc 会因版本不符回 EINVAL。
         */
        rc = fn_fx(0, dirfd, p, buf, flags);
    } else {
        errno = ENOSYS;
        return -1;
    }

    if (rc == 0 && g_fakeroot_on)
        fakeroot_patch_stat(buf, &g_fakeroot_state);

    /*
     * ★ l2s —— 这一行曾经**漏掉**，而它是危害最大的一个入口 ★
     *
     * 实测（纯 C 探针逐个入口读 st_nlink，BXROOT_LINK2SYMLINK=1）：
     *
     *     stat(a)               nlink=2  islnk=0    ✅
     *     lstat(a)              nlink=2  islnk=0    ✅
     *     fstatat(AT_FDCWD,a)   nlink=1  islnk=0    ❌ ← 本函数
     *     fstatat(dirfd,"a")    nlink=1  islnk=0    ❌ ← 本函数
     *
     * 也就是说 stat/lstat 都对，只有 fstatat 不对。而在产物的调用点统计里，
     * `stat`/`lstat`/`stat64`/`lstat64` 都有 l2s 调用，**fstatat 是唯一
     * 一个 0 调用的**。
     *
     * 【为什么这一个漏掉就足以让整个功能失效】
     * `fstatat` 是 **glibc 现代程序的主路径** —— 新程序（含 node）的
     * `fs.statSync` / `fs.lstatSync` 走的就是它，`stat`/`lstat` 那些老
     * 入口基本不会被调到。所以：
     *   - 用老工具（ls / grep）测，看到的是正确的 nlink=2
     *   - 用 node 测，全错
     * 这种"按调用者不同而表现不同"的缺陷最难查 —— 探针选错就永远看不见。
     *
     * 【为什么 l2s 必须在这里生效】
     * node/PNPM 靠 st_nlink 判断"store 里的文件是否已被链接"，看到 1 就
     * 认为没链接，退化成完整复制 —— 这正是 DSHA 被迫使用
     * package-import-method=copy 的根因。
     *
     * 路径参数用**翻译后的宿主路径 p**，不是原始 path：l2s 的中间层与
     * 数据文件都在宿主侧，用 guest 路径永远 probe 不到（与 stat 处同理）。
     */
    if (rc == 0)
        l2s_rt_patch_stat(buf, p);

    return rc;
}

int fstatat64(int dirfd, const char *path, struct stat64 *buf, int flags) {
    static int (*fn)(int, const char *, struct stat64 *, int) = NULL;
    static int (*fn_fx)(int, int, const char *, struct stat64 *, int) = NULL;
    char translated[MAX_PATH_LEN];
    char joined[MAX_PATH_LEN];
    const char *p = path;
    int rc;

    if (fn == NULL && fn_fx == NULL) {
        fn = (int (*)(int, const char *, struct stat64 *, int))
             bxroot_next_symbol("fstatat64");
        if (fn == NULL)
            fn_fx = (int (*)(int, int, const char *, struct stat64 *, int))
                    bxroot_next_symbol("__fxstatat64");
    }

    /*
     * ★ 必须按 dirfd 解析相对名 ★
     *
     * translate_path() 只翻绝对路径；相对名（tar 的
     * openat+fstatat 组合、node 的 dirfd 用法）原样返回，
     * 于是 l2s 层拿 "a" 去 probe —— 那是相对**进程 cwd**
     * 解析的，不是相对 dirfd。cwd 恰好等于 dirfd 时看着
     * 是对的，一旦不同就 probe 不到，伪造链接的 S_IFLNK
     * 抹不掉 → 客户（tar）判定"这是符号链接" → 去 readlink
     * → EINVAL → "Cannot readlink" 而失败。
     */
    p = resolve_host_path(dirfd, path, joined, sizeof(joined),
                          translated, sizeof(translated));

    if (fn != NULL) {
        rc = fn(dirfd, p, buf, flags);
    } else if (fn_fx != NULL) {
        /*
         * _STAT_VER：aarch64 上是 **0**，不是 1。
         * 早前硬编码成 1（x86_64 的值）—— 只因这条兜底分支在
         * glibc 2.33+ 上从不被走到（fstatat 符号本身存在）才没暴露。
         * 一旦走到，glibc 会因版本不符回 EINVAL。
         */
        rc = fn_fx(0, dirfd, p, buf, flags);
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
        fn = (int (*)(int, const char *, int))bxroot_next_symbol("unlinkat");
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
        fn = (int (*)(const char *, mode_t))bxroot_next_symbol("mkdir");
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
        fn = (int (*)(int, const char *, mode_t))bxroot_next_symbol("mkdirat");
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
        fn = (int (*)(const char *))bxroot_next_symbol("rmdir");
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
        fn = (int (*)(const char *, const char *))bxroot_next_symbol("symlink");
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
        fn = (int (*)(const char *, int, const char *))bxroot_next_symbol("symlinkat");
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
        fn = (int (*)(const char *, const char *))bxroot_next_symbol("rename");
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
             bxroot_next_symbol("renameat");
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
        fn = (int (*)(const char *, mode_t))bxroot_next_symbol("chmod");
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
        fn = (int (*)(int, mode_t))bxroot_next_symbol("fchmod");
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
        fn = (int (*)(int, const char *, mode_t, int))bxroot_next_symbol("fchmodat");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    /*
     * path 可能为 NULL —— 内核把它当合法入参（返回 EFAULT），
     * 而 translate_path() 第一件事就是读 path[0]，不判就会整进程段错误。
     * 同文件的 statx/utimensat/fchownat/dlopen 都判了 NULL，这里曾是漏判。
     */
    if (path == NULL) {
        rc = fn(dirfd, NULL, mode, flags);
        return rc;
    }

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
        fn = (int (*)(int, const char *, int, int))bxroot_next_symbol("faccessat");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    /*
     * path 可能为 NULL —— 内核把它当合法入参（返回 EFAULT），
     * 而 translate_path() 第一件事就是读 path[0]，不判就会整进程段错误。
     * 同文件的 statx/utimensat/fchownat/dlopen 都判了 NULL，这里曾是漏判。
     */
    if (path == NULL) {
        rc = fn(dirfd, NULL, mode, flags);
        return rc;
    }

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
             bxroot_next_symbol("readlinkat");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    /*
     * /proc/self/exe 的伪装 —— 与 readlink() 同一逻辑，见那里的详细说明。
     *
     * 这里额外要处理**相对路径 + dirfd** 的形态：客户可能先 open 了
     * /proc/self 目录，再 readlinkat(fd, "exe", ...)。所以既要认
     * 绝对路径，也要认 dirfd != AT_FDCWD 时的裸 "exe"。
     */
    if (path != NULL && g_config.guest_exe != NULL && g_config.guest_exe[0] != '\0') {
        int is_self_exe = 0;

        if (strcmp(path, "/proc/self/exe") == 0 ||
            strcmp(path, "/proc/thread-self/exe") == 0) {
            is_self_exe = 1;
        } else if (strncmp(path, "/proc/", 6) == 0) {
            const char *q = path + 6;
            const char *slash = strchr(q, '/');
            if (slash != NULL && strcmp(slash, "/exe") == 0 && slash != q)
                is_self_exe = 1;
        } else if (dirfd != AT_FDCWD && strcmp(path, "exe") == 0) {
            /* 相对 /proc/self 目录 fd 的 "exe" */
            is_self_exe = 1;
        }

        if (is_self_exe) {
            /* 与 readlink() 同一语义：不补 NUL，见那里的详细说明。 */
            size_t len = strlen(g_config.guest_exe);
            if (len > bufsiz)
                len = bufsiz;
            memcpy(buf, g_config.guest_exe, len);
            return (ssize_t)len;
        }
    }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;

    n = fn(dirfd, p, buf, bufsiz);
    if (n <= 0)
        return n;

    /*
     * ★ D3 修复：与 readlink() 同一处理 —— /proc 泄漏反向翻译 ★
     * 必须在 l2s 重写之前：l2s 判据用的是宿主路径 p，改写 buf 会
     * 破坏它的 probe；而且 /proc/self/fd/N 的返回值要 guest 视角。
     */
    {
        char fixedp[MAX_PATH_LEN];
        if (n < (ssize_t)sizeof(fixedp)) {
            char rawp[MAX_PATH_LEN];
            memcpy(rawp, buf, (size_t)n);
            rawp[n] = '\0';
            if (readlink_fixup(rawp, fixedp, sizeof(fixedp)) == 1) {
                size_t flen = strlen(fixedp);
                if (flen > bufsiz)
                    flen = bufsiz;        /* 截断，与 readlinkat(2) 语义一致 */
                memcpy(buf, fixedp, flen);
                return (ssize_t)flen;
            }
        }
    }

    {
        char joined[MAX_PATH_LEN];
        char raw[MAX_PATH_LEN];
        char fixed[MAX_PATH_LEN];
        size_t copy = (size_t)n < sizeof(raw) - 1 ? (size_t)n : sizeof(raw) - 1;
        int lrc;

        /*
         * ★ 判据要用**绝对宿主路径** ★
         *
         * 相对名（tar 的 openat+readlinkat 组合）下 p 还是 "a"，
         * l2s 层拿它 probe 不到任何东西 —— 这正是此前漏改写的根因。
         */
        if (resolve_dirfd_path(dirfd, path, joined, sizeof(joined)) == 1) {
            if (translate_path(joined, translated, sizeof(translated)) > 0)
                p = translated;
            else
                p = joined;
        }

        memcpy(raw, buf, copy);
        raw[copy] = '\0';
        lrc = l2s_rt_rewrite_readlink(p, raw, fixed, sizeof(fixed));
        if (lrc == L2S_RT_READLINK_FAKE) {
            errno = EINVAL;
            return -1;
        }
        if (lrc == 1) {
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
        fn = (int (*)(int, unsigned long, ...))bxroot_next_symbol("ioctl");
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
 * 且 proc.c 内部自己用 `bxroot_real_symbol("execve")` 懒加载。
 */

/* ------------------------------------------------------------------ */
/* Hook: utimensat / fchownat / statx / statvfs / statfs / truncate    */
/* ------------------------------------------------------------------ */

int utimensat(int dirfd, const char *path, const struct timespec times[2],
              int flags) {
    static int (*fn)(int, const char *, const struct timespec[2], int) = NULL;
    char translated[MAX_PATH_LEN];
    char joined[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (int (*)(int, const char *, const struct timespec[2], int))
             bxroot_next_symbol("utimensat");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    /*
     * ★ dirfd + 相对路径的解析（2026-09-17 补，由 dpkg -i 暴露）★
     *
     * 【实测缺陷】dpkg unpack 的时序是：
     *     openat(dirfd, "x.dpkg-new")   ← dirfd 是已翻译的目录 fd
     *     write / chown / ...
     *     utimensat(dirfd, "x.dpkg-new") ← 相对路径 + 同一 dirfd
     * 本钩子原先**只**调 translate_path（只认绝对路径），相对路径
     * 原样透传。内核对相对路径按**进程 cwd** 解析 —— 而 bxroot 的
     * cwd 已被设成 workdir，于是内核在 `<workdir>/x.dpkg-new` 下
     * 找不到 → ENOENT → dpkg 报 "error setting timestamps"，
     * **安装中止**。
     *
     * 【为什么 openat 同场景却正常】openat 也走 resolve_dirfd_path，
     * 相对路径会被拼成 dirfd 的真实绝对路径 —— 所以**写**成功了、
     * **改时间戳**失败，两个入口覆盖不全，正好卡在 dpkg 的序列中间。
     *
     * 【为什么先前没测出来】需要"先 openat(dirfd) 再 utimensat(dirfd)"
     * 的真实程序（dpkg 正是）才会同时踩两条路径；单步探针各测一条
     * 是看不出来的。
     */
    if (path != NULL) {
        if (path[0] == '/') {
            if (translate_path(path, translated, sizeof(translated)) > 0)
                p = translated;
        } else if (dirfd == AT_FDCWD) {
            /*
             * ★ AT_FDCWD + 相对路径（2026-09-17 补，由 dpkg -i 暴露）★
             *
             * dpkg unpack 的完整序列是 chdir(目标目录) 后用
             *     utimensat(AT_FDCWD, "x.dpkg-new", ...)
             * 相对路径由**进程 cwd** 解析。bxroot 的 cwd 在内核里是
             * **宿主路径**（chdir 钩子翻译过），所以内核本应找得到 ——
             * 但实测仍 ENOENT。原因：dpkg 的 chdir 目标是它自己算的
             * 路径（经它自己的翻译），而我们的 cwd 翻译与它的不一致，
             * 两者差一层。
             *
             * 修法：把相对路径先用 getcwd 拼成**绝对**路径，再走
             * translate_path —— 与 openat 的 dirfd 解析同一策略。
             * 这样无论进程 cwd 是什么，解析结果都唯一。
             */
            char cwd[MAX_PATH_LEN];
            if (getcwd(cwd, sizeof cwd) != NULL &&
                snprintf(joined, sizeof joined, "%s/%s", cwd, path) <
                    (int)sizeof joined) {
                if (translate_path(joined, translated, sizeof(translated)) > 0)
                    p = translated;
                else
                    p = joined;
            }
            /* getcwd 失败 → 原样透传（保底） */
        } else if (resolve_dirfd_path(dirfd, path, joined,
                                      sizeof(joined)) == 1) {
            /* 相对路径 + 非AT_FDCWD 的 dirfd → 拼成绝对路径后再翻译 */
            if (translate_path(joined, translated, sizeof(translated)) > 0)
                p = translated;
            else
                p = joined;   /* 翻译层不动它（如 /proc 透传），用拼好的 */
        }
        /* path == NULL（对 dirfd 本身操作）不需要翻译 */
    }
    return fn(dirfd, p, times, flags);
}

int fchownat(int dirfd, const char *path, uid_t uid, gid_t gid, int flags) {
    static int (*fn)(int, const char *, uid_t, gid_t, int) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;
    int rc;

    if (fn == NULL)
        fn = (int (*)(int, const char *, uid_t, gid_t, int))
             bxroot_next_symbol("fchownat");
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
             bxroot_next_symbol("statx");
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
         *
         * ★ 必须用 _full 版本，把 stx_mode 的 S_IFLNK 一起抹掉 ★
         *
         * 只补 stx_nlink 会让客户的 lstatSync().isSymbolicLink() 仍为
         * true —— 而 statx 的 stx_mode 与 stat 的 st_mode 是同一个语义，
         * l2s_rt_patch_stat() 早就在抹它了；statx 只是同一个语义的现代
         * 接口，没有理由区别对待。
         *
         * 实测（libc statx 入口）：只补 nlink 时 mode=0120777（带着
         * S_IFLNK），抹掉后是 0100777 —— 与 stat/lstat 两条路一致。
         */
        /*
         * ★ 用 `_buf` 版本（传整个结构体），不是 `_full`（三指针）★
         *
         * 三指针版本**只能改 nlink/mask/mode** —— 它拿不到 stx_size /
         * stx_ino / stx_blocks，而那些字段同样必须回填：
         *
         * 实测（`stat` 命令走的就是 statx 路径）：
         *     bxroot lstat size = 符号链接目标字符串长度（几十字节）
         *     官方   lstat size = 真实文件大小
         * 后果是 `tar` 把伪造链接按符号链接归档（并写入宿主绝对路径）、
         * `cp -a` 报 ELOOP。
         *
         * 字段偏移由 l2s 层按 offsetof 实测值访问，本文件不引
         * <linux/stat.h>（会与 <sys/stat.h> 冲突）。
         */
        if (rc == 0 && buf != NULL)
            l2s_rt_patch_statx_buf(buf, STATX_NLINK, p);
        return rc;
    }
}

int statfs(const char *path, struct statfs *buf) {
    static int (*fn)(const char *, struct statfs *) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = path;

    if (fn == NULL)
        fn = (int (*)(const char *, struct statfs *))bxroot_next_symbol("statfs");
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
        fn = (int (*)(const char *, struct statvfs *))bxroot_next_symbol("statvfs");
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
        fn = (int (*)(const char *, off_t))bxroot_next_symbol("truncate");
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
        fn = (int (*)(const char *, mode_t))bxroot_next_symbol("creat");
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
             bxroot_next_symbol("renameat2");
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

/*
 * ====================================================================
 * 符号解析的统一入口：**linker 服务优先，libc dlsym 兜底**
 * ====================================================================
 *
 * 为什么不能只写 `dlsym(RTLD_NEXT, name)`：见下面「dl* 家族」那段。
 * 在本容器（参考实现 linker + 本运行时）实测：
 *
 *     bxroot_next_symbol("open")  →  0x...22680  ✅（libc 的 open）
 *     换成本库导出 dlsym 之后       →  (nil)     ❌
 *
 * 也就是说**一旦本库把 `dlsym` 导出到动态符号表，libc 的 dlsym 在本进程里
 * 就失效了**（探针实证见 docs/dlsym垫片与插件加载修复.md §3）。
 * 而客户程序（node 与它的 N-API 原生模块）恰恰**必须**能 dlsym 到
 * V8 的导出符号，否则整条 `requireBuiltin` 链断掉、`dsh web` 的 5 个插件
 * 全部加载失败。
 *
 * 因此本库改为：**符号解析本身走 linker 服务**，不再依赖 libc 的 dlsym。
 *
 * 协议（由官方 runtime 反汇编 + 本容器探针双重确认）：
 *   - `ldso_service_dlsym_next_from(retaddr, name)` 语义 = libc 的
 *     `dlsym(RTLD_NEXT, name)`，**retaddr 取调用方的返回地址**
 *     （官方就是 `xpaclri; mov x0, x30; bl ...`）。
 *   - `ldso_service_dlsym(handle, name)` 语义 = libc 的 `dlsym(handle, name)`；
 *     `handle == NULL` 时 = `RTLD_DEFAULT`。
 *   - 两个服务符号由 linker 在装载时填 PLT，本库**不要**定义它们，
 *     只声明为外部引用。
 *
 * ★ 等价性实测（docs 报告 §3.4）★
 *   在同一个函数里同时取
 *       a = dlsym(RTLD_NEXT, name)
 *       b = ldso_service_dlsym_next_from(__builtin_return_address(0), name)
 *   对本库内部解析的**全部 133 个符号名**逐一比对：
 *       **相等 133 / 不等 0**（其中同为 NULL 的 2 个是 glibc 已删除的
 *       newfstatat / newfstatat64，本库本就有 fstatat 回退）。
 *   所以改用服务版是**行为保持**的，不是"换了一套语义"。
 *
 * ★ 为什么不会递归 ★
 *   本函数**不调用任何 dlsym**（既不调 libc 的，也不调自己的）：
 *   服务符号是 linker 直接填的 PLT，与符号解析无关。
 *   实测（probe14）：本库导出自研 dlsym 后，经服务拿到的"真 dlsym"
 *   三种形态（NULL / RTLD_DEFAULT / RTLD_NEXT）调用**递归进入次数均为 0**。
 */

/*
 * linker 提供的私有服务。**只声明，不定义** —— 定义会覆盖 linker 的实现。
 *
 * ★ 必须是 weak（2026-09-18 修）★
 *
 * 这四条曾经是**普通 extern（强引用）**，后果很严重：
 *
 *   纯 glibc 环境（Ubuntu 容器、其它加载器）下，动态链接器在**符号解析
 *   阶段**就失败，构造函数一个都跑不到：
 *
 *       $ LD_PRELOAD=build/libbxroot-runtime.so /bin/true
 *       symbol lookup error: undefined symbol: ldso_service_dlsym_global
 *
 *   即"加载即崩"，一个命令都跑不了。
 *
 * 而下方注释早就写着"纯 glibc 下必须回落到 libc 的 dlsym" ——
 * 承诺在注释里，实现里是强引用，**两者矛盾**。根因是这套代码只在
 * "带 ldso 服务的 linker"（自研 linker / Android 真机）下验证过，
 * 降级路径从未被真实执行过。
 *
 * 改成 weak 后：符号缺失时绑定为 NULL，加载不再失败；
 * 配套地，`bxroot_has_ldso_service()` 的探针**必须先判空**再调用，
 * 否则就是从"加载失败"变成"call NULL 崩溃"—— 两个坑二选一而已。
 */
extern void *ldso_service_dlsym(void *handle, const char *name) __attribute__((weak));
extern void *ldso_service_dlsym_global(const char *name) __attribute__((weak));
extern void *ldso_service_dlsym_next_from(void *retaddr, const char *name) __attribute__((weak));

/*
 * 本库是否运行在**带 ldso 服务的 linker** 下。
 *
 * 官方 linker 一定有；纯 glibc / 其它 loader 下这三个符号解析不到，
 * 此时必须回落到 libc 的 dlsym —— 否则本库在无 loader 服务环境（例如
 * 开发者直接在 Ubuntu 容器里 `LD_PRELOAD` 跑单测）会整片功能失效。
 *
 * 探测方式：`ldso_service_dlsym_global` 是 linker 的全局查找入口，
 * 拿自己的一个自己一定有的符号（`bxroot_translate_path`）即可。
 * 取不到 → 判定为无服务，走 libc。
 *
 * ★ 判空必须在调用之前 ★
 * 弱符号缺失时值为 NULL。若直接 `ldso_service_dlsym_global(...)`，
 * 就是 call NULL —— 实测表现为 `SEGV pc=0x0`，比"加载失败"更难排查
 * （因为程序已经跑起来了，崩在某个看似无关的位置）。
 *
 * 注意：这个探测**不能**在构造函数里缓存死。本库的构造函数可能早于
 * linker 填完 PLT（实测：bxroot linker 场景下构造函数压根没跑到就 SIGILL），
 * 所以每次解析时按需判定一次即可（成本 = 一次查表，热路径上早已判空短路）。
 */
static int bxroot_has_ldso_service(void) {
    static int cached = -1; /* -1 未知 / 0 无 / 1 有 */
    if (cached < 0) {
        /*
         * ★ 测试钩子：强制走降级路径 ★
         *
         * 存在的理由（这是"可测性"问题，不是功能需求）：
         * 本库的降级路径（无 ldso 服务）在**开发环境里根本走不到** ——
         * 无论是 Android 真机还是本容器，linker 服务始终存在。
         * 后果就是用户报告里指出的那条：
         *
         *   「降级路径零测试覆盖。这就是三个 P0 都能活过仓库的原因：
         *     它们全在降级路径上。」
         *
         * 这个判断是对的。2026-09-18 之前，这条分支里 `dlsym` 直接
         * `return NULL`（客户程序 call NULL 崩），而**没有任何测试能发现**，
         * 因为测试跑的全是有服务的路径。
         *
         * 有了这个开关之后，降级路径就能在当前环境里被真实执行，
         * 从而可以被回归套件钉住（见 test/RUN_FALLBACK.sh）。
         *
         * 它只影响"走哪条分支"的判断本身，不改任何业务语义 ——
         * 生产环境不设这个变量，行为与从前完全一致。
         */
        const char *force = getenv("BXROOT_FORCE_NO_LDSO_SERVICE");
        if (force != NULL && force[0] == '1' && force[1] == '\0') {
            cached = 0;
            return cached;
        }

        /* 弱符号判空 —— 见上方"判空必须在调用之前" */
        if (ldso_service_dlsym_global == NULL) {
            cached = 0;
        } else {
            void *probe = ldso_service_dlsym_global("bxroot_translate_path");
            cached = (probe != NULL) ? 1 : 0;
        }
    }
    return cached;
}

/*
 * 解析"本库之后"的真实符号。语义 = `dlsym(RTLD_NEXT, name)`。
 *
 * ★ 必须传调用方的返回地址 ★
 * 服务用 retaddr 定位调用方在 link_map 里的位置，从而决定搜索起点。
 * 传本函数的地址是**错的**：那样搜索起点会变成"本函数所在的目标文件"，
 * 从而把本库自己的钩子当成"真实实现"返回（自递归炸栈）。
 * 所以这里取 `__builtin_return_address(0)`，即**调用 bxroot_next_symbol 的
 * 那个函数**的返回地址 —— 与官方 runtime 取 x30 的做法一致。
 */
__attribute__((noinline))
static void *bxroot_next_symbol(const char *name) {
    if (bxroot_has_ldso_service()) {
        void *p = ldso_service_dlsym_next_from(__builtin_return_address(0), name);
        if (p != NULL)
            return p;
        /*
         * 服务说没有 —— 这就是权威答案（与 libc 的 RTLD_NEXT 语义一致，
         * 例如 glibc 2.33+ 的 newfstatat 确实不存在）。
         * **不**在这里补一次 libc dlsym：那既多余，又会在"本库已导出 dlsym"
         * 的语境下拿到 NULL，掩盖真实原因。
         */
        return NULL;
    }
    /* 无服务：退回 libc 原生 dlsym（无 loader 服务环境） */
    return dlsym(RTLD_NEXT, name);
}

void *dlopen(const char *filename, int flags) {
    static void *(*fn)(const char *, int) = NULL;
    char translated[MAX_PATH_LEN];
    const char *p = filename;

    /*
     * ★ dlopen 的真身解析**不能**走 bxroot_next_symbol / linker 服务 ★
     *
     * 实测诊断（[DLOPEN-RES]，详见 docs 报告 §5）：
     *   ldso_service_dlsym_next_from(__builtin_return_address(0), "dlopen")
     *   从本库的 dlopen 内部调用时返回
     *       q = 0x…99b0 [libbxroot-runtime.so]   dlopen_self = 0x…99b0  ★同一个★
     *   即**解析回了本库自己的 dlopen** → 调用它无限递归 → 栈耗尽段错误。
     *
     * 原因：`next_from(retaddr, …)` 用 retaddr 定位调用方在 link_map 中的位置，
     * 再从**其后**开始搜索。本库的 dlopen 是导出符号，调用方可能在库外
     * （libc / ld.so 的初始化与 node 的装载路径），此时"其后"会绕回本库 →
     * 命中我们自己的 dlopen。
     * 而 `bxroot_next_symbol` 是 `static` + `noinline`，调用方**必然**在本库内部，
     * 所以那里没有这个问题（实测 133/133 与 libc 的 RTLD_NEXT 完全等价）。
     *
     * 因此 dlopen 保持原有已验证写法：走 libc 的 `dlsym(RTLD_NEXT, …)`。
     * 这里不会成环：本库虽然导出 dlsym，但 dlsym 的 RTLD_NEXT 分支走 linker
     * 服务、不回到 libc 的 dlsym，故不存在 dlsym↔dlopen 相互调用。
     */
    if (fn == NULL)
        fn = (void *(*)(const char *, int))dlsym(RTLD_NEXT, "dlopen");

    if (fn == NULL) { errno = ENOSYS; return NULL; }

    /* filename 可以为 NULL（获取主程序句柄），必须判空 */
    if (filename != NULL && translate_path(filename, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(p, flags);
}

/*
 * dl* 家族：**刻意不再导出**（曾经的实现是错的，见下）。
 *
 * ====================================================================
 * 这里曾经有一组 dlsym/dlerror/dladdr/dl_iterate_phdr 的转发包装器，
 * 写法是：
 *
 *     void *dlsym(void *handle, const char *symbol) {
 *         static void *(*fn)(void *, const char *) = NULL;
 *         if (fn == NULL)
 *             fn = (void *(*)(void *, const char *))bxroot_real_symbol("dlsym");
 *         ...
 *     }
 *
 * **这是一个必然无限递归的结构**：
 *
 *   - `bxroot_real_symbol("dlsym")` 的语义是"从本库**之后**的搜索顺序里
 *     找 dlsym"。但解析 `RTLD_NEXT` 这件事本身就要调用 `dlsym` ——
 *     而符号解析先命中**我们自己**（本 .so 在搜索顺序最前面）。
 *   - 于是进入本函数 → fn 仍为 NULL → 再次调用 `bxroot_real_symbol(...)`
 *     → 又进本函数 …… 每层吃一个栈帧，直到栈耗尽。
 *
 * 实测证据（core dump，非推测）：
 *
 *   崩溃 PC = 本 .so + 0x6c44，正是 `dlsym` 的入口。
 *   主线程寄存器 `sp == x29`（栈指针已追平帧指针 = 栈耗尽）。
 *   崩溃前的调用链上是 `Dl_info` / `dlopen` 相关操作 ——
 *   即 dsh 加载原生扩展（.node）时触发了 dlsym。
 *
 * 这也解释了症状为何是"`dsh --help` 正常、`dsh web --help` 段错误"：
 * 只有 web profile 会加载原生 N-API 模块，而那条路径要调 dlsym。
 *
 * ====================================================================
 * 【结论已修订 —— 见下方 "修订" 段】不导出它们**并不正确**。
 *
 * 修订（本轮实测）
 * ----------------
 * 上面那段"不导出比导出更正确"的推理**被实测证伪**：
 *
 *   实测（probeapi2.node，同一份 .node 分别跑在官方/bxroot 运行时下）：
 *
 *     官方 runtime： dlsym(NULL,"malloc")                        = 0x…7490 [libc]
 *                    dlsym(NULL,"napi_create_function")          = 0x876a34 [node]
 *                    dlsym(NULL,"_ZN2v87Isolate10GetCurrentEv")  = 0xc03360 [node]
 *     bxroot runtime：三个**全部 (nil)**
 *
 *   即：**bxroot 运行时下，被 `process.dlopen` 装入的 .node 模块调用
 *   dlsym(RTLD_DEFAULT, …) 拿不到 node 自己导出的任何符号。**
 *
 *   这正是 `node-addon-require-builtin` 报
 *   `Unsupported/no-context (required V8 current-context symbols were not found)`
 *   的直接原因（它内部就是 `dlsym(0, "_ZN2v87Isolate10GetCurrentEv")`），
 *   进而让 `dsh web` 的 5 个插件全部 "Cannot find package"。
 *
 * 为什么"让 libc 接管"在这条链路上不成立
 * --------------------------------------
 * libc 的 dlsym 依赖 `__libc_dlopen`/`_dl_sym` 那套内部符号解析，
 * 而这条路径**只有 glibc 自己的 ld.so 被用作 loader 时才完整**。
 * proroot 用的是自研 loader（官方 `libproroot-linker.so`），它把符号解析
 * 换成了自己的 `ldso_service_*`。于是：
 *   - 官方 runtime：**自研 loader + 自研 dlsym（走服务）** → 自洽，能用；
 *   - bxroot 旧实现：**自研 loader + libc 的 dlsym** → 不自洽，返回 NULL。
 *
 * ★ 不能写成"转发给 libc 的同名函数" ★
 * 上面记录的 core dump 是真实的：`dlsym` 里用 `dlsym(RTLD_NEXT,"dlsym")`
 * 懒加载真身会无限递归（崩溃 PC = 本 .so + 0x6c44 即 dlsym 入口，
 * 主线程 sp == x29 即栈耗尽）。
 *
 * 正确修法（本段实现）
 * -------------------
 * 像官方那样**自己实现 dlsym，内部走 linker 服务**，而不是转发：
 *
 *   void *dlsym(void *handle, const char *symbol) {
 *       RTLD_NEXT(-1)          → ldso_service_dlsym_next_from(retaddr, symbol)
 *       RTLD_DEFAULT(NULL/-2)  → ldso_service_dlsym(NULL, symbol)
 *       其它 handle            → 服务拿到"真 dlsym"后再转交（服务返回的是
 *                                linker 自己的 dlsym 实现，不是本库的）
 *   }
 *
 * 三条安全性质，均已实测（probe14，详见 docs 报告 §4）：
 *   1. **不递归**：服务拿到的"真 dlsym" `0x…ac3590` ≠ 本库 `&dlsym`
 *      `0x…8074a8`；它对 NULL / RTLD_DEFAULT / RTLD_NEXT 三种调用
 *      "递归进入本库 dlsym" 的次数均为 **0**。
 *   2. **内部解析不受影响**：本库自身的
 *      `dlsym(RTLD_NEXT, …)` 全部改为 `bxroot_next_symbol()`（走服务），
 *      与 libc 原生结果等价（133/133 名字逐一比对相同，见上文）。
 *   3. **仍交给 glibc 做真正的解析**：本库只做 **分派**，
 *      不解析 ELF、不做重定位 —— 红线 CL-13/CL-14 未被违反
 *      （linker 服务本来就是官方 loader 的公开入口）。
 *
 * 对 `dlerror` / `dladdr` / `dl_iterate_phdr` 的处理
 * -------------------------------------------------
 * 本轮**只导出 `dlsym`**。理由：
 *   - 客户程序（node + N-API 模块）的失败点只有 dlsym 一处，实测已闭合；
 *   - `dlerror` 为 TLS 错误码语义，自己实现要先复刻 `__libc_dlerror_result`
 *     的布局；**做错比不做更糟**（dsh 会拿到垃圾字符串）；
 *   - `dladdr`/`dl_iterate_phdr` 需要 `_dl_find_object`，服务接口
 *     （`ldso_service_find_object_by_addr`）目前只确认存在、**未验证语义**。
 * 官方导出全套是因为它连 `dlerror` 一起自研了（反汇编可见它直接用
 * `tpidr_el0` 读写 TLS 里的错误码），那是另一件事，不在本轮范围。
 */

/*
 * ====================================================================
 * dl 家族错误状态：`dlerror` 与 `dlsym` 的**同源**实现
 * ====================================================================
 *
 * 为什么必须与 dlsym 同源
 * -----------------------
 * 本库的 `dlsym` 走的是 **linker 服务**（`ldso_service_dlsym*`），
 * **不是 glibc 的 `dlsym`**。于是 glibc 那套 `__libc_dlerror_result`
 * **永远不会被写** —— 客户程序在 `dlsym` 失败后调 `dlerror()` 只能拿到 NULL，
 * 真故障被静默吞掉。实测（本容器 A/B，探针 `dlprobe`）：
 *
 *     官方 runtime: dlsym(不存在)=(nil)  dlerror() = undefined symbol: xxx
 *     bxroot 修前 : dlsym(不存在)=(nil)  dlerror() = NULL (!!)
 *
 * 而本库内部自己就依赖这条契约（`px_wait_dlsym` 与 `proc.c` 都写了
 * `dlsym 失败: %s` 的诊断），所以"错误串恒为 NULL"等于
 * **专门写的诊断代码永远打不出原因**。
 *
 * 官方做法（`libproroot-runtime.so` 反汇编 + `.rodata` 实读）
 * ----------------------------------------------------------
 * 官方把状态放在**自己的 TLS 变量**里（`adrp 0x60000` + `#0x4c8`；
 * 重定位表实测该槽是 `R_AARCH64_TLSDESC`，**不是** `dlsym`）：
 *
 *     dlerror@0x22fa0:  ldr  w3, [tls, off]   ; 有错吗
 *                       add  x2, tls, off
 *                       cbz  w3, -> NULL
 *                       add  x2, x2, #0x10   ; 错误串在 TLS 偏移 +0x10
 *                       str  wzr, [tls, off] ; ★ 读一次即清 ★
 *
 * 布局 = { int 有错标志; 12 字节对齐空洞; char 错误串[128] }，因为官方是
 * `snprintf(x0 = tls+off+0x10, x1 = 0x80, fmt, name)` —— **缓冲区 128 字节**。
 * 标志与串之间的 12 字节空洞是 16 字节对齐的自然结果。
 *
 * ★ 只有 `dlsym` 与 `dlerror` 读写这个槽 ★
 * 全库 `ldr x?,[x0,#1224]`（即该 TLS 描述符槽）的出现点实测为：
 * `dlsym` 三处、`dlerror` 一处、`dlopen` 两处 —— 而 `dlopen` 那两处
 * 只读 `[tls+off+0x90]` 的**另一个**变量（`ldsomutex`）且只 `strb`，
 * **没有**写 dlerror 槽。所以 glibc 里"dlopen 失败也能 dlerror"的语义，
 * 官方**并没有**接：官方侧 `dlopen(不存在)` 之后 `dlerror()` 实测也是 NULL
 * （它把原因 `snprintf` 到栈上 256 字节缓冲再 `write(2,…)` 到 stderr）。
 * 本实现与官方保持一致，**不**替官方臆造那条语义。
 *
 * 格式串原文（从官方 `.rodata` 实读，非转述）
 * -----------------------------------------
 *     0x36c68: "undefined symbol: %s"
 *     0x36c38: "ldso_runtime dlsym: symbol '%s' not found"
 *
 * 两条分支的对应关系由反汇编逐条坐实：
 *   0x22e90: cbz x0, 0x22f14          ; handle == NULL  → RTLD_DEFAULT 分支
 *   0x22ea8: b.eq 0x22f8c             ; handle == RTLD_NEXT → next_from 分支
 *   0x22eb0: b.eq 0x22f14             ; handle == RTLD_DEFAULT（-2）→ 同上
 *   0x22f14: bl ldso_service_dlsym    ; ← **服务分支**，失败 → 0x22f4c
 *   0x22f4c: … add x2,x2,#0xc68       ; ★ "undefined symbol: %s" ★
 *   0x22ed4: … add x2,x2,#0xc38       ; ★ "ldso_runtime dlsym: symbol '%s' not found" ★
 *
 * 即 0x22f4c（服务版失败）用 `undefined symbol: %s`，
 * 0x22ed4（"真 dlsym" 存在但返回 NULL 的失败）用 `ldso_runtime dlsym: …`。
 * 因为本库**全部**查找都走服务，所以本库只会在**服务失败**那条路上出错，
 * 对应官方的就是 0x22f4c → `undefined symbol: %s`。
 * 实测印证（隔离垫片 `dlshim.so`，只实现 dlsym/dlerror/dl_iterate_phdr）：
 *
 *     dlsym(RTLD_DEFAULT, 不存在) → <undefined symbol: bxroot_…_42>
 *     dlsym(libm句柄,    不存在) → <ldso_runtime dlsym: symbol 'no_such_in_libm_xyz' not found>
 *
 * 两条格式串本库都保留（带句柄那条走 `ldso_runtime dlsym: …`），
 * 逐字对齐官方 `.rodata`。
 *
 * ★ 为什么不复刻 glibc 的 `__libc_dlerror_result` ★
 * 客户程序只会通过 `dlerror()` 访问，不会去读布局；而 glibc 的布局是私有的、
 * 随版本漂移。用本库自己的 TLS 变量既安全又足够 —— 这与官方同构
 * （官方用的也只是"自己的一个 TLS 变量"，并非 glibc 那个）。
 *
 * ★ 自递归防护（不做会 100% SIGSEGV）★
 * 见下面 `dlerror` 实现上方的长注释。要点：**本文件中没有任何 dlerror
 * 转发路径**，因此不存在"判据失效导致递归"的可能。
 */

/* 与官方逐字段对齐：{标志; 对齐空洞; 128 字节串} */
struct bxroot_dl_error_state {
    int  flag;          /* +0x00：非 0 = 有未读错误（官方 `str w6,[x4,x0]`） */
    int  _pad[3];       /* +0x04：对齐到 +0x10（官方 `add x2,x2,#0x10`）    */
    char msg[128];      /* +0x10：错误串（官方 `mov x1,#0x80`）             */
};

/*
 * 本库能否用 linker 服务。与 `bxroot_has_ldso_service` 同一个理由，
 * **不能**在构造函数里缓存死（构造函数可能早于 linker 填完 PLT）。
 */
static int bxroot_dl_service_state = -1;

static int bxroot_dl_has_service(void) {
    if (bxroot_dl_service_state < 0)
        bxroot_dl_service_state = bxroot_has_ldso_service() ? 1 : 0;
    return bxroot_dl_service_state;
}

/*
 * 线程局部错误状态。模型与官方一致（`mrs tpidr_el0` + TLSDESC）；
 * 实测本容器 aarch64 glibc 下 `-fPIC` 共享库生成的就是 `R_AARCH64_TLSDESC`。
 *
 * ★ 下面两个写函数**不调用任何外部函数**（连 snprintf/strlen 都不调）★
 * 只在同一个 .so 内部按偏移取地址、逐字节拷贝。理由见 `dlerror` 那段：
 * 任何"调用出去"的动作都可能经 PLT 再绕回本库，而那正是历史上崩过的形状。
 * 逐字节拷贝对本容器 aarch64 是内联的 ldrb/strb 小循环，不产生外部调用。
 */
static _Thread_local struct bxroot_dl_error_state bxroot_dl_err;

static void bxroot_dl_error_set2(const char *prefix, const char *name,
                                 const char *suffix) {
    char *dst = bxroot_dl_err.msg;
    size_t cap = sizeof(bxroot_dl_err.msg);
    size_t n = 0;
    const char *p;

    for (p = prefix; p != NULL && *p != '\0' && n + 1 < cap; p++)
        dst[n++] = *p;
    for (p = name; p != NULL && *p != '\0' && n + 1 < cap; p++)
        dst[n++] = *p;
    for (p = suffix; p != NULL && *p != '\0' && n + 1 < cap; p++)
        dst[n++] = *p;
    dst[n] = '\0';

    bxroot_dl_err.flag = 1;
}

static void bxroot_dl_error_clear(void) {
    bxroot_dl_err.flag = 0;
}

/*
 * 自研 dlerror —— 读本库自己的 TLS 状态，**读一次即清**（与官方逐条同构）。
 *
 * ★★★ 自递归防护：为什么这里一行"转发"都不能有 ★★★
 *
 * 本函数是本库导出的符号，因此：
 *   1. `dlsym(RTLD_NEXT, "dlerror")` / `ldso_service_dlsym_next_from(retaddr,…)`
 *      在本库里解析 `dlerror` 会**解析回本函数自己** —— 本库比 libc 靠前，
 *      而 RTLD_NEXT 的"下一个"在调用方位于库内时会绕回本库。
 *   2. 于是"取下一个 dlerror、为空就转发"这种写法 = **无条件无限自递归**。
 *
 * 这不是推测，是**实测**。本容器 A/B 对照（垫片 `dlbad.c`，实现本函数并
 * 打印解析结果）：
 *
 *     [dlbad] 解析到 0x7bcbe3b4a0；本库 &dlerror=0x7bcbe3b4a0
 *     [dlbad] 命中自己或为空 —— 若继续转发即无限自递归     （连刷数百行）
 *
 * 解析结果与本库 `&dlerror` **是同一个地址**。报告 §2.3 记录的
 * `[selfdetect] 解析到 0x…；本库 &dlerror=0x…` 与此完全一致。
 *
 * 所以本实现的防护**不是**"判一下再转发"，而是**根本不转发**：
 *   - 状态与 dlsym 同源（同一个 TLS 结构），dlerror 只读它；
 *   - 不需要、也不可能从 libc 的 dlerror 取任何东西；
 *   - 唯一的外部影响是读自己的 TLS，`_Thread_local` 访问器由 ld.so 在装载时
 *     填好（TLSDESC），**不经过符号解析**。
 *
 * 这比"加一个自检判据"更强：判据可能因 `dl_iterate_phdr` 残缺而失效
 * （报告 §2.3 实测自检垫片拿到 `base=0x0`，**没拦住**），而"没有转发路径"
 * 不存在失效的可能。这也是本任务要求两个符号**一起修**的原因。
 *
 * 无 loader 服务环境（无 linker 服务）：本库的 `dlsym` 返回 NULL 并在这里登记
 * `undefined symbol: …` —— 语义明确，且**依然不递归**。
 */
char *dlerror(void) {
    if (!bxroot_dl_err.flag)
        return NULL;
    bxroot_dl_err.flag = 0;          /* ★ 读一次即清（官方 `str wzr`）★ */
    return bxroot_dl_err.msg;
}

/*
 * 自研 dlsym —— 只做**分派**，真正的符号解析仍由 linker 服务完成。
 *
 * 为什么必须导出：见上。客户程序（node 的 N-API 模块）要靠它
 * 看到 node 进程的导出符号。
 *
 * 防递归：本函数**绝不在自己的求值路径上调用 dlsym**。
 *   - RTLD_NEXT / RTLD_DEFAULT 直接走 linker 服务（PLT，与符号解析无关）；
 *   - 其它 handle 需要"真 dlsym"，而"真 dlsym"通过
 *     `ldso_service_dlsym(NULL, "dlsym")` 获得 —— 该服务返回 linker
 *     自己的实现（实测 0x…ac3590 ≠ 本库 &dlsym 0x…8074a8），
 *     不是本库的，所以不会回到这里。
 *
 * 若某个环境**没有** ldso 服务（非 proroot loader），本函数退回
 * `dlvsym`/libc 语义不可用，此时保守地返回 NULL 并置 ENOSYS 风格错误 ——
 * 这比"猜一个实现"安全：那种情况下本来也没有服务在提供符号视图。
 */
void *dlsym(void *handle, const char *symbol) {
    void *res;

    if (symbol == NULL) {
        /* glibc 对 symbol==NULL 的行为是未定义；这里明确失败，不猜。
         * 失败也要留痕（与官方一致：官方成功必清标志，失败必登记）。 */
        bxroot_dl_error_set2("undefined symbol: ", "(nil)", NULL);
        return NULL;
    }

    if (bxroot_dl_has_service()) {
        /* RTLD_NEXT：从**调用方**之后开始找 */
        if (handle == RTLD_NEXT) {
            res = ldso_service_dlsym_next_from(__builtin_return_address(0), symbol);
            /* ★ 与 dlerror 同源：成功清标志 / 失败登记错误串 ★
             * 官方 dlsym@0x22f38 `str wzr` 清标志、@0x22f4c 走
             * snprintf(tls+0x10, 0x80, "undefined symbol: %s", name)。
             * 这里必须**每条退出路径**都过一遍，否则会出现
             * "失败返回 NULL 但 dlerror() 说没错误"的假绿。 */
            if (res != NULL) {
                bxroot_dl_error_clear();
            } else {
                bxroot_dl_error_set2("undefined symbol: ", symbol, NULL);
            }
            return res;
        }
        /* RTLD_DEFAULT / NULL：全局查找。
         * 注意服务在 handle==NULL 时的语义就是 RTLD_DEFAULT
         * （实测 ldso_service_dlsym(NULL,"malloc") == global("malloc")）。 */
        if (handle == NULL || handle == RTLD_DEFAULT) {
            res = ldso_service_dlsym(NULL, symbol);
            if (res != NULL) {
                bxroot_dl_error_clear();
            } else {
                /* 官方 @0x22f14→0x22f4c：**服务分支**失败用
                 * `undefined symbol: %s`（.rodata@0x36c68 实读原文）。 */
                bxroot_dl_error_set2("undefined symbol: ", symbol, NULL);
            }
            return res;
        }
        /*
         * ★ 具体句柄：**直接交给 linker 服务**，不要再去找"真 dlsym" ★
         *
         * 为什么不能"取真 dlsym 再转交"：
         *   实测（probe16）：`ldso_service_dlsym(NULL, "dlsym")` 在本库已导出
         *   dlsym 的前提下**返回本库自己的 dlsym**（linker 服务是"全局查找"，
         *   自然优先命中搜索链最前面的本库）。那就是自递归；
         *   加一层"若等于自己就返回 NULL"的防御后，node 的
         *   `dlsym(handle, "napi_register_module_v1")` 会拿到 NULL，
         *   于是报 `Module did not self-register` —— 加载体征与实测完全一致。
         *
         * 正确做法：linker 服务本身就提供**带句柄**的查找
         * （`ldso_service_dlsym(handle, name)`），
         * 实测（probeapi3 stage 11 / 14）它能正确解析：
         *     dlsym(libc_handle, "malloc")                  → libc 的 malloc
         *     dlsym(node_addon_handle, "napi_register_module_v1") → 该 .node 的地址
         * 而那个 handle 正是本库 dlopen（转发给 libc 的 dlopen）返回的句柄，
         * 类型一致，无需转换。
         */
        res = ldso_service_dlsym(handle, symbol);
        if (res != NULL) {
            bxroot_dl_error_clear();
        } else {
            /* 带句柄失败 → 官方 .rodata@0x36c38 那条串（实读原文）：
             * `ldso_runtime dlsym: symbol '%s' not found`
             * 实测隔离垫片复现一致。 */
            bxroot_dl_error_set2("ldso_runtime dlsym: symbol '", symbol,
                                 "' not found");
        }
        return res;
    }

    /*
     * 无 ldso 服务：本库在无 loader 服务环境（例如 Ubuntu 容器里直接
     * LD_PRELOAD 跑单测）。
     *
     * ★ 这里必须真的转发给 libc，不能返回 NULL（2026-09-18 修）★
     *
     * 原先这里直接 `return NULL`，注释说"让无 loader 服务环境退化得明确
     * 而不是递归崩溃"。**实测后果与注释相反**：客户程序拿到 NULL 后
     * 直接调用空指针 —— `bash` 启动即 `SEGV pc=0x0`。
     * 也就是说，"明确退化"实际比"递归崩溃"崩得更早更果断。
     *
     * ----- 原注释里那句"改用 dlvsym 也不行"是**错的** -----
     *
     * 原文写：
     *     「改用 dlvsym 也不行（它内部同样会走到这里）」
     *
     * 这个论断把正确修法挡在门外，所以必须留档纠正：
     *
     *   `dlvsym` **没有被本库导出**（实测 `readelf --dyn-syms` 里
     *   本库只导出 dlopen / dlsym / dlerror / dladdr / dl_iterate_phdr
     *   五个 dl* 符号，**不含 dlvsym**）。
     *
     * 因此从本库调用 `dlvsym` 时，PLT 直接解析到 **libc 的实现**，
     * 根本不会经过本库的 `dlsym`。递归的前提不存在。
     *
     * ----- 为什么用带版本号的 dlvsym 而不是普通 dlsym -----
     *
     * 直接 `dlsym(RTLD_NEXT, "dlsym")` 在这条分支里**不可靠**：
     * 本库自己导出了 `dlsym`，RTLD_NEXT 的搜索起点依赖调用方位置，
     * 在"本库导出同名符号"的语境下可能又拿到自己。
     * `dlvsym` 带显式版本（GLIBC_2.34 是 glibc 里 dlsym 的版本节点），
     * 语义精确，不会命中本库。
     *
     * 回退链：GLIBC_2.34 → GLIBC_2.17（老 glibc 的版本节点）。
     * 两者都拿不到才返回 NULL，并且**登记 dlerror**（不能静默失败 ——
     * 那会让调用方看到"失败但没有错误信息"的假绿）。
     *
     * 性能：结果静态缓存，只解析一次。这是降级路径，不在 Android
     * 热路径上（Android 走上面的服务分支）。
     */
    {
        static void *(*real_dlsym_cached)(void *, const char *) = NULL;
        static int tried = 0;

        if (!tried) {
            tried = 1;
            /*
             * ★ 这里**不**对 dlvsym 判空 —— 编译器是对的 ★
             *
             * 原先写了 `if (dlvsym != NULL)`，`-Waddress` 报：
             *     the comparison will always evaluate as 'true' for the
             *     address of 'dlvsym' will never be NULL
             *
             * 这个告警是**正确的**：`dlvsym` 是 glibc 的公开 API
             * （`dlfcn.h` 声明，libc 始终提供），不是可选的弱符号。
             * 给它判空等于假装它可能缺失，那是把"链接期就能确定的事"
             * 拿到运行期猜 —— 既无效，又掩盖了真正的失败模式。
             *
             * 真正的失败模式是**版本节点不存在**（非 glibc 的 libc、
             * 或极老的 glibc），那时 `dlvsym` 会**返回 NULL**，
             * 而不是函数指针为空。所以判空要判在**返回值**上 ——
             * 下面两条回退链正是这么做的。
             */
            real_dlsym_cached = (void *(*)(void *, const char *))
                dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.34");
            if (real_dlsym_cached == NULL)
                real_dlsym_cached = (void *(*)(void *, const char *))
                    dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.17");
        }

        if (real_dlsym_cached == NULL) {
            /* 连 libc 的 dlsym 都拿不到 —— 如实报错，不假装成功 */
            bxroot_dl_error_set2("undefined symbol: ", symbol,
                                 " (no ldso service, and libc dlsym unreachable)");
            return NULL;
        }

        res = real_dlsym_cached(handle, symbol);
        if (res != NULL) {
            bxroot_dl_error_clear();
        } else {
            bxroot_dl_error_set2("undefined symbol: ", symbol, NULL);
        }
        return res;
    }
}


/*
 * ====================================================================
 * 自研 dladdr —— 补上 `dli_fbase`
 * ====================================================================
 *
 * 为什么非做不可（实测）
 * ---------------------
 * bxroot 运行时下，客户程序看到的是 **glibc 的 dladdr**，它同样依赖
 * glibc 自己的 loader 状态 —— 而 proroot 用的是自研 loader，那份状态是空的。
 * 实测对照（probeapi3 stage 17/18，同一个 .node、同一地址）：
 *
 *   官方 runtime:  dladdr(0x9a2930) → 1, fname=…/usr/local/bin/node, fbase=0x400000
 *   bxroot runtime: dladdr(0x9a2930) → 1, fname=…/usr/local/bin/node, fbase=(nil) ★
 *
 * fname 有值只是巧合（glibc 从 maps 里猜的），**fbase 恒为 NULL**。
 *
 * 这一个 NULL 就是 `dsh web` 插件链的**第二道**卡点：
 * `node-addon-require-builtin` 在用 V8 符号读出 realm 指针后，会做一次
 * “两地址是否属于同一镜像”的一致性校验（反汇编
 * `ValidatePlatformRuntimeImagePointers` @0x1d4f4 可见它连续调用两次
 * `dladdr` 再比较 `dli_fbase`），失败即报
 *     `Unsupported/no-realm (realm vptr image does not match getter image)`
 * —— 正是加完 dlsym 垫片后观察到的下一个错误。
 *
 * 实现方式：**照抄官方的做法**，不自己解析 ELF
 * ------------------------------------------------
 * 官方 `dladdr`（@0x23080）自己没有遍历任何链表，而是：
 *   1. 准备一个 4 字段的 walk 结构 {addr, fbase, fname, ptype}；
 *   2. 调 `ldso_service_dl_iterate_phdr(内部回调, &walk)`；
 *   3. 回调里对每个对象的 PT_LOAD 段做 `vaddr <= addr < vaddr+memsz` 判定，
 *      命中就填 fbase/fname 并返回非 0 停止遍历；
 *   4. 回来后把 walk 里的 {fname, fbase} 写进 Dl_info，sname/saddr 置 NULL。
 *
 * 回调 ABI 由官方那段反汇编**逐条坐实**（`proroot_dladdr_walk_cb` @0x22d40）：
 *     x0 = struct dl_phdr_info *   （用 [x0+16]=dlpi_phdr、[x0+24]=dlpi_phnum、
 *                                   [x0+0]=dlpi_addr、[x0+8]=dlpi_name）
 *     x2 = void *data              （[x2+0]=待查地址；命中后写 [x2+8]=fbase、
 *                                   [x2+16]=fname、[x2+24]=p_type）
 * 这正是 `dl_iterate_phdr` 回调的标准签名。
 *
 * ★ 仍然没有自研 ELF 解析 ★
 * 对象枚举、加载基址、段表全部来自 linker 服务；本函数只做区间比较，
 * 与官方 runtime 的对应函数是同一个形状。红线 CL-13/CL-14 未被触碰。
 */

/*
 * linker 服务：枚举已装载对象（回调签名同 dl_iterate_phdr）。
 *
 * ★ 同样必须是 weak（2026-09-18 修）★
 *
 * 这一条当时被漏掉了 —— 上面三条 `ldso_service_dlsym*` 改成 weak 之后，
 * `readelf --dyn-syms` 里它**仍然是 GLOBAL**，也就是说纯 glibc 环境下
 * 依然会 "symbol lookup error" 加载失败。
 *
 * 教训：改符号绑定强度时，**必须把整族符号一次改完并逐个核对**
 * （用 `readelf --dyn-syms | grep ldso_service` 看每一行的绑定列），
 * 不能只改自己记得的那几个。这一族共 4 个，分两处声明，很容易漏。
 *
 * 两个使用点（dladdr 与 dl_iterate_phdr）本来就在
 * `bxroot_has_ldso_service()` 判断之后，所以改 weak 不需要额外判空 ——
 * 但调用点仍加判空，作为"多层防御"（见各调用点注释）。
 */
extern int ldso_service_dl_iterate_phdr(
    int (*callback)(struct dl_phdr_info *, size_t, void *), void *data)
    __attribute__((weak));

/* 与官方 @0x22d40 的 walk 结构逐字段对齐 */
struct bxroot_dladdr_walk {
    const void *addr;    /* [0]  入参：待查地址               */
    void       *fbase;   /* [8]  出参：所在对象加载基址       */
    const char *fname;   /* [16] 出参：所在对象路径           */
    int         ptype;   /* [24] 出参：命中的 p_type（非 0 = 命中） */
};

static int bxroot_dladdr_walk_cb(struct dl_phdr_info *info, size_t size, void *data) {
    struct bxroot_dladdr_walk *w = (struct bxroot_dladdr_walk *)data;
    (void)size;

    /* 与官方一致：没有段表就跳过该对象 */
    if (info == NULL || info->dlpi_phdr == NULL || info->dlpi_phnum == 0)
        return 0;

    /* ★ `dli_fbase` 不是 `dlpi_addr`，而是**第一个 PT_LOAD 的起始地址** ★
     *
     * 这一点是从官方回调 @0x22d40 逐条读出来的：
     *     22d8c: add  x3, x3, x9        ; x3 = dlpi_addr + p_vaddr
     *     22d90: csel x6, x6, x3, ne    ; x6 为 0 时记下 x3（即首个 PT_LOAD 的 vstart）
     *     22dd4: stp  x6, x1, [x2, #8]  ; w->fbase = x6
     * 初版我写成 `dlpi_addr`，实测主程序（dlpi_addr == 0）得到 fbase=(nil)，
     * 而官方同一地址给出 0x400000 —— 正是主程序首个 PT_LOAD 的 p_vaddr。
     *
     * 语义上也应该如此：`dli_fbase` 是"该对象映射的基址"，
     * 对非零 dlpi_addr 的共享库两者相等，对主程序则等于首个 PT_LOAD 的
     * 虚拟地址（0x400000 之类），这正是 glibc 的行为。
     */
    unsigned long first_load = 0;
    unsigned long a = (unsigned long)w->addr;

    for (unsigned i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        unsigned long vstart, vend;

        if (ph->p_type != PT_LOAD)
            continue;

        vstart = (unsigned long)info->dlpi_addr + (unsigned long)ph->p_vaddr;
        vend   = vstart + (unsigned long)ph->p_memsz;

        /* 与官方 `csel x6, x6, x3, ne` 等价：x6 非 0 则保留，否则取当前 vstart */
        if (first_load == 0)
            first_load = vstart;

        if (a >= vstart && a < vend) {
            w->fbase = (void *)first_load;
            /* 官方对空 dlpi_name 用空串（csel），这里保持一致：
             * 客户代码常直接 printf("%s", dli_fname)，给 NULL 会崩。 */
            w->fname = (info->dlpi_name != NULL) ? info->dlpi_name : "";
            w->ptype = (int)ph->p_type;
            return (int)ph->p_type;   /* 非 0 = 停止遍历 */
        }
    }
    return 0;
}

int dladdr(const void *addr, Dl_info *info) {
    struct bxroot_dladdr_walk w;

    if (addr == NULL || info == NULL)
        return 0;
    if (!bxroot_has_ldso_service())
        return 0;

    memset(&w, 0, sizeof(w));
    w.addr = addr;
    /*
     * 判空：弱符号缺失时为 NULL。
     * 虽然上面的 `bxroot_has_ldso_service()` 已经保证了"有服务"，
     * 但两个判断来自**两处独立的符号解析**（探针用 dlsym_global，
     * 这里用 dl_iterate_phdr）—— 理论上有"前者有、后者无"的组合
     * （例如 linker 只实现了部分服务）。call NULL 的代价是 SIGSEGV，
     * 一次判空换掉这个风险，值得。
     */
    if (ldso_service_dl_iterate_phdr != NULL)
        ldso_service_dl_iterate_phdr(bxroot_dladdr_walk_cb, &w);

    if (w.ptype == 0)
        return 0;   /* 未命中任何 PT_LOAD */

    info->dli_fname = w.fname;
    info->dli_fbase = w.fbase;
    info->dli_sname = NULL;
    info->dli_saddr = NULL;
    return 1;
}

/*
 * ====================================================================
 * 自研 dl_iterate_phdr —— 接上 linker 的**私有模块视图**
 * ====================================================================
 *
 * 为什么必须补（实测）
 * -------------------
 * 不导出它时，客户程序解析到的是 **glibc 的 `dl_iterate_phdr`**，
 * 而 glibc 那份遍历的是 glibc 自己的 loader 状态 —— proroot 用的是
 * 自研 loader，那份状态只认识主程序。本容器 A/B 实测（探针 `dlprobe`）：
 *
 *     官方 runtime: 共 6 个模块（主程序×2 + runtime + libc + ld.so + libm）
 *     bxroot 修前 : 共 1 个模块（只有主程序自己）      ← ★ 缺陷 ★
 *
 * 模块视图不全的直接后果：任何"遍历已加载模块找自己/找别的 so"的代码
 * 都拿到错误结果。报告 §2.3 已经实证了它的**二次伤害** ——
 * 报告作者写的"dlerror 自递归检测垫片"因为拿不到自身基址（`base=0x0`）
 * 而**没能拦住**无限递归，最后 SIGSEGV。所以这两个符号必须一起修。
 *
 * 官方做法（`libproroot-runtime.so` @0x22fec 反汇编逐条）
 * -----------------------------------------------------
 * 官方**先 `dlsym(-1, "dl_iterate_phdr")` 填一个静态缓存并调用**，
 * 返回非 0 就直接返回；返回 0 则**再兜一层** `ldso_service_dl_iterate_phdr`：
 *
 *     22ffc: add  x21, x21, #0xf68        ; x21 = &缓存槽
 *     2300c: ldr  x2, [x21, #8]           ; 读缓存
 *     23010: cbz  x2, 2304c               ; 空 → 去解析
 *     2301c: blr  x2                      ; 调"真正的 dl_iterate_phdr"
 *     23020: cbnz w0, 2303c               ; ★ 非 0 → 直接返回
 *     23038: b    ldso_service_dl_iterate_phdr@plt   ; ★ 否则再兜一层 ★
 *     2304c: … dlsym(-1, "dl_iterate_phdr")          ; .rodata@0x36c80 实读
 *
 * 也就是说：**即使官方也只是转发给 libc，真正干活的是 libc**，
 * 官方额外做的唯一一件事就是那一层 linker 服务兜底 —— 而正是这一层
 * 把模块视图从 1 个补成了 6 个。本实现保留同一形状。
 *
 * ★ 反递归：为什么这里转发给"真 dl_iterate_phdr"是安全的 ★
 *
 * 与 `dlerror` 的关键差别是**返回值的语义**：
 *   - `dlerror` 返回的是"错误串指针"，控制流必须**进入**被解析的函数，
 *     所以解析到自己 = 无限自递归 = 必崩；
 *   - `dl_iterate_phdr` 的结果是"回调被跑了几轮"，官方在
 *     `cbnz w0` **非 0 时就直接返回**，只有 0 才继续兜底。
 *     即便解析结果是自己，也是**有限步**：`libc版 → 服务版`，
 *     不会成环（服务版不再回调本函数）。
 *
 * 但本实现**不依赖**这个论证，而且把防护**限定在真正有环的那条路上**：
 *
 *   1. 有 linker 服务（DSHA / proroot 环境，实测始终有）：
 *      **只**调 `ldso_service_dl_iterate_phdr`。这是 linker 自己的函数，
 *      不会回调本函数 —— **结构上无环**，所以这里**不加任何哨兵**，
 *      `dl_iterate_phdr` 的**嵌套调用照常可用**（回调里再遍历一次是合法用法，
 *      glibc 也允许；实测本容器 glibc 侧嵌套返回 0 且视图完整）。
 *      这一条很重要：把哨兵无差别地罩在服务路径上会**误伤正常嵌套**。
 *   2. 无服务（无 loader 服务环境）：这里要转发给 libc 的 `dl_iterate_phdr`，
 *      是**唯一**可能成环的路径（若解析结果落回本库）。
 *      于是**只在这条路上**加一次性哨兵 + 自身地址判据：
 *        - 解析结果 == 本函数 → 直接失败，不调用（对应报告 §2.3 的"路 B"判据）；
 *        - 重入 → 返回 -1。
 *      两道防护都只在"服务不可用"的降级环境里生效。
 *
 * 实测（本容器 A/B）：官方 runtime 在**嵌套调用**下 SIGSEGV
 * （见 docs/dl家族符号修复.md §5.6）—— 官方没有重入防护；本实现的
 * 服务路径**允许**嵌套，行为比官方更接近 glibc。
 */

/* 降级路径（无 ldso 服务）专用：重入哨兵 + 缓存。
 * 线程局部 —— 它描述的是"本线程正在这条降级路径里"，跨线程共享会误判。 */
static _Thread_local int bxroot_dl_iterate_fallback_busy = 0;

int dl_iterate_phdr(int (*callback)(struct dl_phdr_info *, size_t, void *),
                    void *data) {
    if (callback == NULL)
        return -1;          /* glibc 同：回调为空是调用方的错 */

    if (bxroot_dl_has_service() && ldso_service_dl_iterate_phdr != NULL) {
        /*
         * ★ 与官方 @0x23038 那一层完全对应：linker 的**私有模块视图**。
         * 官方是先 dlsym 拿 libc 版跑一遍、返回 0 才兜到这里；本库直接用服务，
         * 因为服务本身就是完整视图（实测它就是官方那 6 个模块的来源），
         * 而"先跑 libc 版"只会把主程序**重复回调两次** —— 那正是官方实测输出里
         * `phdr[0]` 与 `phdr[1]` 同 name 同 base 的原因（报告 §5 把它列为
         * "像是官方的一个小瑕疵"）。这里不复制那个重复：模块视图**完整**
         * 已达成，重复回调反而会让"数模块数"的调用方多算一个。
         *
         * 无环：服务不回调本函数，故**不加哨兵**，嵌套调用照常可用。
         *
         * ★ 判空不是多余的 ★ 弱符号可能缺失，而这里若 call NULL 就是
         * SIGSEGV。判空后**落到下面的降级路径**（而不是返回失败）——
         * 降级路径能给出正确结果，比返回 0 更有用。
         */
        return ldso_service_dl_iterate_phdr(callback, data);
    }

    /*
     * 降级路径：无 loader 服务环境（例如 Ubuntu 容器里直接 LD_PRELOAD 跑单测）。
     * 只有这条路可能成环，两道防护都放这里。
     */
    {
        static int (*fn)(int (*)(struct dl_phdr_info *, size_t, void *), void *);
        int rc;

        if (bxroot_dl_iterate_fallback_busy)
            return -1;      /* ★ 重入截断：宁可报错，绝不爆栈 ★ */
        bxroot_dl_iterate_fallback_busy = 1;

        if (fn == NULL)
            fn = (int (*)(int (*)(struct dl_phdr_info *, size_t, void *), void *))
                 bxroot_next_symbol("dl_iterate_phdr");

        /* ★ 自身地址判据（报告 §2.3 "路 B"）：解析回本库就绝不调用 ★ */
        if (fn == NULL || (void *)fn == (void *)&dl_iterate_phdr) {
            bxroot_dl_iterate_fallback_busy = 0;
            return -1;
        }

        rc = fn(callback, data);
        bxroot_dl_iterate_fallback_busy = 0;
        return rc;
    }
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
        fn = (int (*)(const char *, int, mode_t))bxroot_next_symbol("__open_nocancel");
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
        fn = (int (*)(const char *, int, mode_t))bxroot_next_symbol("__open64_nocancel");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    if (translate_path(path, translated, sizeof(translated)) > 0)
        p = translated;
    return fn(p, flags, mode);
}

/*
 * __getcwd_chk —— FORTIFY 版的 getcwd。
 *
 * glibc 的契约（与其它 __*_chk 一致）：
 *     if (size > buflen) __chk_fail();     // 缓冲溢出，直接 abort
 *     return getcwd(buf, size);
 *
 * 曾经写成 `(void)buflen; return getcwd(buf, size);` —— 那样**把
 * FORTIFY 保护整个关掉了**：调用方本意是"我声明这个缓冲区只有
 * buflen 字节"，而我们无视这个声明照写。若客户真传了
 * `size > buflen`，它本应立即 abort 暴露自己的 bug，结果变成
 * 静默的栈/堆越界写 —— 比崩溃危险得多。
 *
 * 这条与本文件里 __readlink_chk 的注释自定的规则**直接矛盾**：
 * 那里写着"薄转发，翻译逻辑与主 hook 一致"，而这里却连契约都丢了。
 * 现在按契约补齐校验。
 *
 * 注意：`__chk_fail` 是 glibc 的私有符号（GLIBC_PRIVATE），
 * 用 dlsym 解析；解析不到时退化为 __builtin_trap()（同样能暴露问题，
 * 且不依赖任何符号）。
 */
char *__getcwd_chk(char *buf, size_t size, size_t buflen) {
    static void (*chk_fail)(void) = NULL;
    static int tried = 0;

    if (!tried) {
        tried = 1;
        chk_fail = (void (*)(void))bxroot_next_symbol("__chk_fail");
    }

    if (buflen != (size_t)-1 && size > buflen) {
        if (chk_fail != NULL)
            chk_fail();
        __builtin_trap();       /* 兜底：绝不静默越界写 */
    }

    /* 校验通过后转发，复用 getcwd 的反向翻译逻辑 */
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
        fn = (int (*)(char *))bxroot_next_symbol("mkstemp");
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
        fn = (char *(*)(char *))bxroot_next_symbol("mkdtemp");
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
        fn = (int (*)(char *, int))bxroot_next_symbol("mkstemps");
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
        fn = (int (*)(char *, int))bxroot_next_symbol("mkostemp");
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
        fn = (int (*)(int))bxroot_next_symbol("fchdir");
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
             bxroot_next_symbol("getxattr");
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
             bxroot_next_symbol("lgetxattr");
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
             bxroot_next_symbol("setxattr");
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
             bxroot_next_symbol("lsetxattr");
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
             bxroot_next_symbol("listxattr");
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
             bxroot_next_symbol("llistxattr");
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
        fn = (int (*)(const char *, const char *))bxroot_next_symbol("removexattr");
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
        fn = (int (*)(const char *, const char *))bxroot_next_symbol("lremovexattr");
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
        fn = (int (*)(int, const char *, uint32_t))bxroot_next_symbol("inotify_add_watch");
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
             bxroot_next_symbol("scandir");
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
        fn = (int (*)(const char *, struct statfs64 *))bxroot_next_symbol("statfs64");
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
        fn = (int (*)(const char *, struct statvfs64 *))bxroot_next_symbol("statvfs64");
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
        fnsym = (struct passwd *(*)(uid_t))bxroot_next_symbol("getpwuid");
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

/*
 * ★ getpwnam —— 缺口 D 的最后一块拼图（2026-09-17）★
 *
 * 【实测差异（NSS 全家对照）】
 *
 *     调用              官方      bxroot（修前）
 *     getpwuid(0)       root      root     ← 已有钩子
 *     getpwnam("root")  root      NULL     ← ★ 缺口
 *     getgrgid(0)       root      NULL     ← ★ 缺口
 *     getgrnam("root")  root      NULL     ← ★ 缺口
 *
 * 【为什么必须补，而不只是"NSS 缺陷记录在案"】
 *
 * dpkg -i 的失败（"unknown system user 'root' in statoverride file"）
 * 正是它：dpkg 读 statoverride 后要用 getpwnam('root') 解析用户名，
 * 拿不到就中止。官方同一场景能装包 —— 这是**核心容器工作负载**
 * 的实际断点，不再是"仅显示层"的差异。
 *
 * 【为什么之前没发现】
 * fakeroot 域早先补过 getpwuid（按 uid 查询），但**按名字查**的
 * getpwnam 漏了 —— 又一次"同一功能只覆盖一条路径"：
 * pwuid 覆盖了，pwnam 没覆盖。getgr 系列（组）则是整族缺失。
 *
 * 【为什么合成是安全的】
 * 只在 fakeroot 开启且真实查询**失败**时才合成 root 条目 ——
 * 与 getpwuid 的判据完全一致。真实查询成功时（宿主 passwd 恰好
 * 有该记录）优先用真实的，不覆盖。
 *
 * 【为什么 buf 静态】与 getpwuid 同款：getpwnam 的返回指向**库内部
 * 静态存储**（glibc 对非 _r 版本的契约），调用方不释放。线程安全
 * 由调用方保证（glibc 对非 _r 版本本就不保证）。
 */
/*
 * ★ /etc/passwd 直解回退（缺口 D 的核心修法）★
 *
 * glibc 的 getpwnam 内部走 NSS 分派（__nss_database_lookup →
 * _nss_files_getpwnam_r），实测该分派在 bxroot 下失败（即使
 * /etc/passwd 可读、内容正确）。官方能查到是因为官方对 libc 的
 * 内联 svc 做了 livepatch，NSS 内部那条路是通的。
 *
 * 我们不做 NSS 内部修补（那是官方闭源内部），而是**退而求其次**：
 * NSS 失败时直接 open/parse /etc/passwd。这覆盖了容器最常见
 * （也是唯一）的 passwd 源 —— files。数据来自 rootfs 内的同一份
 * /etc/passwd，与官方查到的内容一致。
 *
 * 【为什么不 hook NSS 内部】_nss_files_* 是 libc 内部符号、
 * glibc 2.39 起已内置 libc.so.6，无独立 .so 可换；而改 NSS 分派
 * 属于"改 glibc 内部"，风险与本仓库 dlsym 垫片的 148 处回滚教训同类。
 *
 * 【线程安全】static 缓冲 + 一次解析后缓存：调用方契约（非 _r）
 * 本就允许覆盖；_r 版本不缓存（写调用方缓冲）。
 */
struct passwd *getpwnam(const char *name) {
    static struct passwd *(*fnsym)(const char *) = NULL;
    static struct passwd fake;
    struct passwd *real;
    FILE *f;
    char line[512];

    if (fnsym == NULL)
        fnsym = (struct passwd *(*)(const char *))bxroot_next_symbol("getpwnam");
    if (fnsym == NULL) { errno = ENOSYS; return NULL; }

    real = fnsym(name);
    if (real != NULL)
        return real;                     /* NSS 通了：用真实的 */

    if (name == NULL)
        return NULL;

    /* NSS 失败 → 直解 /etc/passwd（容器内的同一条记录） */
    f = fopen("/etc/passwd", "r");
    if (f == NULL)
        return NULL;

    while (fgets(line, sizeof line, f) != NULL) {
        char *fields[7];
        int nf = 0, i;
        char *w = line, *e;

        /* 逐字段切（passwd 格式: name:passwd:uid:gid:gecos:dir:shell）*/
        for (i = 0; i < 7; i++) {
            fields[i] = w;
            /* ★ 末行无换行符也要收（D4 修）★ 详见 getpwnam_r 内同款注释 */
            if (i < 6) {
                e = strchr(w, ':');
            } else {
                e = strchr(w, '\n');
                if (e == NULL)
                    e = w + strlen(w);
            }
            if (e == NULL) { break; }
            *e = '\0';
            w = e + 1;
            nf++;
        }
        if (nf < 7)
            continue;
        if (strcmp(fields[0], name) != 0)
            continue;

        /* 命中：填静态 struct passwd（非 _r 版本用静态存储是契约允许的）*/
        {
            /*
             * ★ 改为按需分配，不再用固定小缓冲（D6 修）★
             *
             * 原先 `f_gecos[64]` / `f_dir[256]` 配 `snprintf` —— 超长字段被
             * **静默截断**。实测 104 字节的 GECOS 在 bxroot 下只返回 63 字节，
             * 而 glibc 完整返回 104 字节。
             *
             * 危害不是"少几个字符"：GECOS 里放的是真实姓名/联系方式，
             * 而 `dir`（家目录）被截断会让后续 chdir/家目录解析指向错路径 ——
             * 那类错误离截断点非常远，极难排查。（本项目在别处吃过
             * "静默截断比报错糟"的教训，见 l2s 的 st_nlink 契约。）
             *
             * 现在按实际字段长度 realloc 静态缓冲，只受一个防御上限约束。
             * 到上限时**不静默截断** —— 直接放弃直解并回退返回 NULL，
             * 让调用方看到"查不到"而不是拿到半个字符串。
             */
            static char *f_name = NULL, *f_passwd = NULL, *f_gecos = NULL;
            static char *f_dir = NULL, *f_shell = NULL;
            static size_t f_name_cap = 0, f_passwd_cap = 0, f_gecos_cap = 0;
            static size_t f_dir_cap = 0, f_shell_cap = 0;
            /* 单字段防御上限：/etc/passwd 单行本身限 1024（见 line[]），
             * 所以任何字段都不可能超过它。取 1024 与之一致。 */
            const size_t FIELD_MAX = 1024;

            /* 辅助：把 src 复制进 *dst（容量 *cap），不足则 realloc。
             * 返回 1 成功 / 0 失败（超上限或分配失败）。 */
            #define BXROOT_DUP_FIELD(dst, cap, src)                       \
                do {                                                      \
                    size_t _n = strlen(src) + 1;                           \
                    if (_n > FIELD_MAX) { fclose(f); return NULL; }        \
                    if (*(cap) < _n) {                                      \
                        char *_p = (char *)realloc(*(dst), _n);            \
                        if (_p == NULL) { fclose(f); return NULL; }        \
                        *(dst) = _p; *(cap) = _n;                          \
                    }                                                      \
                    memcpy(*(dst), (src), _n);                             \
                } while (0)

            BXROOT_DUP_FIELD(&f_name,   &f_name_cap,   fields[0]);
            BXROOT_DUP_FIELD(&f_passwd, &f_passwd_cap, fields[1]);
            BXROOT_DUP_FIELD(&f_gecos,  &f_gecos_cap,  fields[4]);
            BXROOT_DUP_FIELD(&f_dir,    &f_dir_cap,    fields[5]);
            BXROOT_DUP_FIELD(&f_shell,  &f_shell_cap,  fields[6]);

            #undef BXROOT_DUP_FIELD

            fake.pw_name   = f_name;
            fake.pw_passwd = f_passwd;
            fake.pw_uid    = (uid_t)atoi(fields[2]);
            fake.pw_gid    = (gid_t)atoi(fields[3]);
            fake.pw_gecos  = f_gecos;
            fake.pw_dir    = f_dir;
            fake.pw_shell  = f_shell;
        }
        fclose(f);
        return &fake;
    }
    fclose(f);
    return NULL;                          /* 表里没有，如实 NULL */
}

/*
 * getpwnam_r —— 与 getpwnam 同一套直解回退（_r 契约：写调用方缓冲）。
 * python 的 pwd 模块、dpkg（多线程路径）都走这个。
 */
int getpwnam_r(const char *name, struct passwd *pwd, char *buf, size_t buflen,
               struct passwd **result) {
    static int (*fn)(const char *, struct passwd *, char *, size_t,
                     struct passwd **) = NULL;
    int rc;
    FILE *f;
    char line[512];

    if (result != NULL) *result = NULL;
    if (name == NULL || pwd == NULL || buf == NULL || result == NULL) {
        return EINVAL;
    }

    if (fn == NULL)
        fn = (int (*)(const char *, struct passwd *, char *, size_t,
                      struct passwd **))bxroot_next_symbol("getpwnam_r");
    if (fn != NULL) {
        errno = 0;
        rc = fn(name, pwd, buf, buflen, result);
        if (rc == 0 && *result != NULL)
            return 0;                    /* NSS 通了 */
        if (rc != 0 && rc != ENOENT && rc != ESRCH)
            return rc;                   /* 非"没找到"的真实错误，透传 */
    }

    /*
     * NSS 失败 → 直解 /etc/passwd。
     * 布局：name:passwd:uid:gid:gecos:dir:shell
     * 解析结果全部写进调用方的 buf（_r 版本的契约），pwd 指进 buf。
     */
    f = fopen("/etc/passwd", "r");
    if (f == NULL)
        return ENOENT;

    while (fgets(line, sizeof line, f) != NULL) {
        char *fields[7];
        int nf = 0, i;
        char *w = line, *e;
        size_t used = 0;

        for (i = 0; i < 7; i++) {
            fields[i] = w;
            /*
             * ★ 末行不带换行符也要收（D4 修）★
             * 第 7 个字段原先只找 '\n'：末行无换行时 strchr 返回 NULL
             * → break → nf<7 → **整条记录被丢弃**。改为接受字符串结尾。
             * （同款问题存在于 getgrnam / getgrgid / getpwnam 三处，
             *   一并修。实测依据见 docs/NSS直解边界测试报告.md D4。）
             */
            if (i < 6) {
                e = strchr(w, ':');
            } else {
                e = strchr(w, '\n');
                if (e == NULL)
                    e = w + strlen(w);
            }
            if (e == NULL) break;
            *e = '\0';
            w = e + 1;
            nf++;
        }
        if (nf < 7 || strcmp(fields[0], name) != 0)
            continue;

        /* 依序把 7 个字段拷进 buf，pwd 指进去 */
        {
            const char *order[7] = { fields[0], fields[1], NULL, NULL,
                                     fields[4], fields[5], fields[6] };
            size_t len[2];
            unsigned uid_v = (unsigned)atoi(fields[2]);
            unsigned gid_v = (unsigned)atoi(fields[3]);

            pwd->pw_uid = uid_v;
            pwd->pw_gid = gid_v;

            len[0] = strlen(fields[0]) + 1;
            if (used + len[0] > buflen) { fclose(f); return ERANGE; }
            pwd->pw_name = buf + used;
            memcpy(buf + used, fields[0], len[0]); used += len[0];

            len[1] = strlen(fields[1]) + 1;
            if (used + len[1] > buflen) { fclose(f); return ERANGE; }
            pwd->pw_passwd = buf + used;
            memcpy(buf + used, fields[1], len[1]); used += len[1];

            if (used + strlen(fields[4]) + 1 > buflen) { fclose(f); return ERANGE; }
            pwd->pw_gecos = buf + used;
            memcpy(buf + used, fields[4], strlen(fields[4]) + 1); used += strlen(fields[4]) + 1;

            if (used + strlen(fields[5]) + 1 > buflen) { fclose(f); return ERANGE; }
            pwd->pw_dir = buf + used;
            memcpy(buf + used, fields[5], strlen(fields[5]) + 1); used += strlen(fields[5]) + 1;

            if (used + strlen(fields[6]) + 1 > buflen) { fclose(f); return ERANGE; }
            pwd->pw_shell = buf + used;
            memcpy(buf + used, fields[6], strlen(fields[6]) + 1); used += strlen(fields[6]) + 1;

            (void)order;
        }

        *result = pwd;
        fclose(f);
        return 0;
    }
    fclose(f);
    /*
     * ★ 查不到 → rc=0 + *result=NULL，不是 ENOENT（D5 修）★
     *
     * glibc 的 `_r` 契约里"查不到"**不是错误**：返回 0 并把 `*result`
     * 置 NULL。返回 ENOENT 会让调用方把"这个用户不存在"当成系统错误。
     * （入口处已 `*result = NULL`，直接 return 0 即符合契约。）
     */
    return 0;
}

/*
 * ★ getgrgid / getgrnam —— 组族查询（缺口 D 的组半边）★
 *
 * 同 getpwnam：只在 fakeroot 开启且真实查询失败时合成 root 组
 * （gid=0 / 组名 root）。glibc 的 group 结构比 passwd 多一个
 * gr_mem（成员列表指针），fakeroot 下没有可信的成员清单，
 * 返回一个**只有单个成员 root** 的列表 —— 这正是 root 组的
 * 实际形态，也够 dpkg/statoverride 的解析需求。
 */
static char gr_mem_buf[8] = "root\0";

struct group *getgrgid(gid_t gid) {
    static struct group *(*fnsym)(gid_t) = NULL;
    static char name_buf[32];
    static char *mem_list[2];
    static struct group fake;
    struct group *real;

    if (fnsym == NULL)
        fnsym = (struct group *(*)(gid_t))bxroot_next_symbol("getgrgid");
    if (fnsym == NULL) { errno = ENOSYS; return NULL; }

    real = fnsym(gid);
    if (!g_fakeroot_on || real != NULL)
        return real;
    if (gid != g_fakeroot_state.egid)
        return real;

    memcpy(name_buf, "root", 5);
    mem_list[0] = gr_mem_buf;
    mem_list[1] = NULL;
    fake.gr_name   = name_buf;
    fake.gr_passwd = name_buf;
    fake.gr_gid    = gid;
    fake.gr_mem    = mem_list;
    return &fake;
}

/*
 * getgrnam —— 同 getpwnam 的直解回退（读 /etc/group）。
 * group 格式：name:passwd:gid:mem（mem 是逗号分隔的成员列表）。
 *
 * ★ 注意 _r 契约：本函数返回静态存储（非 _r 版本允许），但 gr_mem
 *   的成员指针必须指向**持久**存储 —— 所以成员名要拷进静态区，
 *   不能指向 line（那是栈上的，函数返回就失效）。
 */
struct group *getgrnam(const char *name) {
    static struct group *(*fnsym)(const char *) = NULL;
    static struct group fake;
    struct group *real;
    FILE *f;
    char line[1024];

    if (fnsym == NULL)
        fnsym = (struct group *(*)(const char *))bxroot_next_symbol("getgrnam");
    if (fnsym == NULL) { errno = ENOSYS; return NULL; }

    real = fnsym(name);
    if (real != NULL)
        return real;

    if (name == NULL)
        return NULL;

    f = fopen("/etc/group", "r");
    if (f == NULL)
        return NULL;

    while (fgets(line, sizeof line, f) != NULL) {
        char *fields[4];
        int nf = 0, i;
        char *w = line, *e;

        for (i = 0; i < 4; i++) {
            fields[i] = w;
            /* ★ 末行无换行符也要收（D4 修）★ 详见 getpwnam_r 内同款注释 */
            if (i < 3) {
                e = strchr(w, ':');
            } else {
                e = strchr(w, '\n');
                if (e == NULL)
                    e = w + strlen(w);
            }
            if (e == NULL) break;
            *e = '\0';
            w = e + 1;
            nf++;
        }
        if (nf < 4 || strcmp(fields[0], name) != 0)
            continue;

        {
            /* ★ 全部用 static：gr_mem 指向它，函数返回后必须仍有效 ★ */
            static char *g_name = NULL, *g_passwd = NULL, *g_mem = NULL;
            static size_t g_name_cap = 0, g_passwd_cap = 0, g_mem_cap = 0;
            /*
             * ★ 成员指针槽位改为按需扩展，不再固定 8 个（D3 修）★
             *
             * 原先 `static char *g_memlist[8]` + `mi < 7` 让"多于 7 个成员"
             * **静默截断**（实测 `getent group big` 9 个成员只回 7 个）。
             * 静默给错数据比报错糟 —— 调用方无法察觉。
             *
             * 现在按实际成员数 realloc；上限设 4096 作防御（正常
             * /etc/group 远达不到），到顶**不截断而是少填**并在下面
             * 留 NULL 终止（非 _r 版无返回值可报错，这是它能做的最好选择；
             * 4096 个成员的实际文件不会出现）。
             */
            static char **g_memlist = NULL;
            /* g_memlist 的指针槽位数（与字符串容量 g_mem_cap 是**两个量**，
             * 别合并 —— 合并会因单位不同而永不 realloc，见下方注释） */
            static size_t g_slots_cap = 0;
            size_t n_mem = 0;
            const char *t;
            int mi = 0, k;
            char *tok;

            /*
             * ★ 按需分配，不再静默截断（D6 同族修）★
             *
             * 原先 g_name[64] / g_mem[512] 配 snprintf：超长被静默砍掉。
             * `g_mem` 尤其危险 —— 成员列表被截断会让调用方以为"这个组
             * 只有前几个成员"，进而做出错误的权限判断。
             *
             * 上限与 line[]（1024）一致；超限则放弃直解返回 NULL
             * （让调用方看到"查不到"，而不是拿到半个列表）。
             */
            #define BXROOT_DUP_G(dst, cap, src)                           \
                do {                                                      \
                    size_t _n = strlen(src) + 1;                           \
                    if (_n > 1024) { fclose(f); return NULL; }             \
                    if (*(cap) < _n) {                                      \
                        char *_p = (char *)realloc(*(dst), _n);            \
                        if (_p == NULL) { fclose(f); return NULL; }        \
                        *(dst) = _p; *(cap) = _n;                          \
                    }                                                      \
                    memcpy(*(dst), (src), _n);                             \
                } while (0)

            BXROOT_DUP_G(&g_name,   &g_name_cap,   fields[0]);
            BXROOT_DUP_G(&g_passwd, &g_passwd_cap, fields[1]);
            BXROOT_DUP_G(&g_mem,    &g_mem_cap,    fields[3]);

            #undef BXROOT_DUP_G

            /* 先数实际成员数 */
            t = g_mem;
            while (*t != '\0') {
                const char *c = strchr(t, ',');
                size_t seg = (c != NULL) ? (size_t)(c - t) : strlen(t);
                if (seg > 0) n_mem++;
                if (c == NULL) break;
                t = c + 1;
            }
            if (n_mem > 4096) n_mem = 4096;   /* 防御上限 */

            /*
             * ★ 指针槽位单独用自己的容量变量 ★
             *
             * 上一版我复用了 `g_memcap`（它是**字符串字节容量**）去跟
             * `n_mem + 1`（**指针个数**）比较，两个单位不同 ——
             * 结果是"容量够大"的判断永远成立，realloc 从不发生，
             * `g_memlist` 一直是 NULL，成员数变成 0。
             *
             * 这正是"同一变量承担两种语义"的典型后果，也是本项目的
             * 高频缺陷模式（同一功能不同入口覆盖不全）。这里把两者
             * 彻底分开：`g_mem_cap` 管字符串字节，`g_slots_cap` 管指针个数
             * （`g_slots_cap` 在函数上方已声明）。
             */
            /* 需要 n_mem + 1 个槽（含结尾 NULL） */
            if (g_slots_cap < n_mem + 1) {
                char **nw = (char **)realloc(g_memlist,
                                             (n_mem + 1) * sizeof(char *));
                if (nw == NULL) { fclose(f); return NULL; }
                g_memlist = nw;
                g_slots_cap = n_mem + 1;
            }

            tok = g_mem;
            while (tok != NULL && (size_t)mi < n_mem) {
                char *c = strchr(tok, ',');
                if (c != NULL) *c = '\0';
                if (*tok != '\0') g_memlist[mi++] = tok;
                tok = (c != NULL) ? c + 1 : NULL;
            }
            /* 结尾 NULL —— 用**指针槽位**容量判断（不是字符串字节容量） */
            for (k = mi; (size_t)k < g_slots_cap; k++)
                g_memlist[k] = NULL;

            fake.gr_name   = g_name;
            fake.gr_passwd = g_passwd;
            fake.gr_gid    = (gid_t)atoi(fields[2]);
            fake.gr_mem    = g_memlist;
        }
        fclose(f);
        return &fake;
    }
    fclose(f);
    return NULL;
}
/*
 * getgrnam_r —— _r 契约版本（python grp 模块走这条）。
 * 与 getpwnam_r 同款直解回退；成员列表也写进调用方缓冲。
 */
int getgrnam_r(const char *name, struct group *grp, char *buf, size_t buflen,
               struct group **result) {
    static int (*fn)(const char *, struct group *, char *, size_t,
                     struct group **) = NULL;
    int rc;
    FILE *f;
    char line[1024];

    if (result != NULL) *result = NULL;
    if (name == NULL || grp == NULL || buf == NULL || result == NULL)
        return EINVAL;

    if (fn == NULL)
        fn = (int (*)(const char *, struct group *, char *, size_t,
                      struct group **))bxroot_next_symbol("getgrnam_r");
    if (fn != NULL) {
        errno = 0;
        rc = fn(name, grp, buf, buflen, result);
        if (rc == 0 && *result != NULL)
            return 0;
        if (rc != 0 && rc != ENOENT && rc != ESRCH)
            return rc;
    }

    f = fopen("/etc/group", "r");
    if (f == NULL)
        return ENOENT;

    while (fgets(line, sizeof line, f) != NULL) {
        char *fields[4];
        int nf = 0, i;
        char *w = line, *e;
        size_t used = 0;

        /*
         * ★ 末行不带换行符也要收（D4 修）★
         *
         * 原先第 4 个字段找的是 '\n'：文件末行若没有换行符，
         * `strchr(w,'\n')` 返回 NULL → break → nf<4 → **整条记录被丢弃**。
         * 实测：`printf 'root:x:0:root'`（无结尾换行）下 getpwnam 返回
         * NULL，而 glibc 正常命中。
         *
         * 修法：第 4 个字段接受 '\n' 或字符串结尾 —— 两者都算"字段结束"。
         */
        for (i = 0; i < 4; i++) {
            fields[i] = w;
            if (i < 3) {
                e = strchr(w, ':');
            } else {
                e = strchr(w, '\n');
                if (e == NULL)
                    e = w + strlen(w);   /* 末行无换行：以 '\0' 为界 */
            }
            if (e == NULL) break;
            *e = '\0';
            w = e + 1;
            nf++;
        }
        if (nf < 4 || strcmp(fields[0], name) != 0)
            continue;

        {
            size_t len;
            unsigned gid_v = (unsigned)atoi(fields[2]);
            const char *memstr = fields[3];
            size_t n_mem = 0, ptr_bytes, need, align_pad;
            char **ml;
            int k;

            grp->gr_gid = gid_v;

            /*
             * =========================================================
             * ★ 先把总需求算清、再检查、最后才写（D2/D3 修）★
             * =========================================================
             *
             * 【D2：曾经越界写 60 字节】
             *
             * 原先的写法是"先把 8 个指针写进调用方缓冲，写完再查
             * `used > buflen`"。后果是：buflen 不足时虽然**返回了
             * ERANGE**，但**已经越界写过了** ——
             *
             *     实测（哨兵法，buflen=32）：越界写 40 字节，
             *     最远偏移 71；同一场景 glibc 越界 0 字节。
             *
             * 这是**内存安全**问题，不是返回值问题：调用方拿到 ERANGE
             * 后可能重试（用更大的缓冲），但被破坏的内存已经破坏了。
             * glibc 的契约是"失败时不写任何东西"（`*result = NULL`），
             * 必须照做。
             *
             * 【D3：成员数硬上限 7】
             *
             * 原先 `g_memlist[8]` 的固定 8 个槽位（7 个成员 + NULL）
             * 是从原型的栈缓冲写法遗留下来的，且 `mi < 7` 让**多于 7 个
             * 成员时静默截断**。实测 `getent group big`（9 个成员）
             * 只返回 7 个 —— 静默给错数据比报错更糟。
             *
             * 现在按实际成员数动态分配指针槽。上限仍设一个（防御畸形
             * 输入），但**超限时报 ERANGE 而不是静默截断**。
             */
            n_mem = 0;
            {
                const char *t = memstr;
                while (*t != '\0') {
                    const char *c = strchr(t, ',');
                    size_t seg = (c != NULL) ? (size_t)(c - t) : strlen(t);
                    if (seg > 0) n_mem++;
                    if (c == NULL) break;
                    t = c + 1;
                }
            }
            /* 防御：成员数上限（正常 /etc/group 远达不到） */
            if (n_mem > 4096) { fclose(f); return ERANGE; }

            /* 指针数组按指针对齐；每个成员一个指针 + 结尾 NULL */
            ptr_bytes = (n_mem + 1) * sizeof(char *);

            /* ---- 需求计算（只算，不写）---- */
            need = strlen(fields[0]) + 1;          /* gr_name   */
            need += strlen(fields[1]) + 1;         /* gr_passwd */
            need += strlen(memstr) + 1;            /* 成员串本体 */
            /* 指针数组前要对齐 */
            align_pad = (sizeof(char *) - (need % sizeof(char *))) % sizeof(char *);
            need += align_pad + ptr_bytes;

            /* ---- 一次性检查：不够就直接失败，**此时尚未写过任何字节** ---- */
            if (need > buflen) { fclose(f); return ERANGE; }

            /* ---- 检查通过，开始写 ---- */
            used = 0;

            len = strlen(fields[0]) + 1;
            grp->gr_name = buf + used;
            memcpy(buf + used, fields[0], len); used += len;

            len = strlen(fields[1]) + 1;
            grp->gr_passwd = buf + used;
            memcpy(buf + used, fields[1], len); used += len;

            len = strlen(memstr) + 1;
            memcpy(buf + used, memstr, len);
            /* 记住成员串在 buf 里的起点，下面按 ',' 就地切分 */
            {
                char *base = buf + used;
                used += len;

                /* 对齐后放指针数组 */
                used += (sizeof(char *) - (used % sizeof(char *))) % sizeof(char *);
                ml = (char **)(buf + used);

                k = 0;
                {
                    char *t = base;
                    while (*t != '\0' && k < (int)n_mem) {
                        char *c = strchr(t, ',');
                        if (c != NULL) *c = '\0';
                        if (*t != '\0') ml[k++] = t;
                        if (c == NULL) break;
                        t = c + 1;
                    }
                }
                /* 结尾 NULL（可能多个，保持习惯） */
                while (k <= (int)n_mem) ml[k++] = NULL;

                grp->gr_mem = ml;
                used += ptr_bytes;
            }

            *result = grp;
            fclose(f);
            return 0;
        }
    }
    fclose(f);
    /*
     * ★ 查不到时返回 0 + *result=NULL，不是 ENOENT（D5 修）★
     *
     * glibc 的 `_r` 契约：**查不到不是错误**，而是"成功但无结果"：
     *     rc = 0, *result = NULL, errno 不变
     * 返回 ENOENT 会让调用方把"这个用户/组不存在"当成**系统错误** ——
     * 典型后果是程序打印"无法查询用户"而不是走正常的"用户不存在"分支。
     *
     * 实测依据：glibc 对不存在的组返回 rc=0 + *result=NULL。
     * 原先 4 处 `_r` 钩子（getpwnam_r / getpwuid_r / getgrnam_r /
     * getgrgid_r）都写的 `return ENOENT`，一并改正。
     *
     * 注意 `*result` 在函数入口已经置 NULL，所以这里直接 return 0 即可。
     */
    return 0;
}

/* getpwuid_r 的可重入版本 —— 有些程序只用它 */
int getpwuid_r(uid_t uid, struct passwd *pwd, char *buf, size_t buflen,
               struct passwd **result) {
    static int (*fn)(uid_t, struct passwd *, char *, size_t, struct passwd **) = NULL;
    int rc;

    if (fn == NULL)
        fn = (int (*)(uid_t, struct passwd *, char *, size_t, struct passwd **))
             bxroot_next_symbol("getpwuid_r");
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
            fn = (int (*)(uid_t *, uid_t *, uid_t *))bxroot_next_symbol("getresuid");
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
            fn = (int (*)(gid_t *, gid_t *, gid_t *))bxroot_next_symbol("getresgid");
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
            fn = (int (*)(int, gid_t[]))bxroot_next_symbol("getgroups");
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
                      bxroot_next_symbol("setenv");
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
        fn = (int (*)(const char *, const char *, int))bxroot_next_symbol("setenv");
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
        fn = (int (*)(const char *))bxroot_next_symbol("unsetenv");
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
        fn = (int (*)(char *))bxroot_next_symbol("putenv");
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
        fn = (int (*)(void))bxroot_next_symbol("clearenv");
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
        fn = (int (*)(int))bxroot_next_symbol("close");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(fd);
}

int dup(int oldfd) {
    static int (*fn)(int) = NULL;
    if (fn == NULL)
        fn = (int (*)(int))bxroot_next_symbol("dup");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(oldfd);
}

int dup2(int oldfd, int newfd) {
    static int (*fn)(int, int) = NULL;
    if (fn == NULL)
        fn = (int (*)(int, int))bxroot_next_symbol("dup2");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(oldfd, newfd);
}

int dup3(int oldfd, int newfd, int flags) {
    static int (*fn)(int, int, int) = NULL;
    if (fn == NULL)
        fn = (int (*)(int, int, int))bxroot_next_symbol("dup3");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(oldfd, newfd, flags);
}

int fcntl(int fd, int cmd, ...) {
    static int (*fn)(int, int, ...) = NULL;
    va_list ap;
    void *arg;

    if (fn == NULL)
        fn = (int (*)(int, int, ...))bxroot_next_symbol("fcntl");
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
        fn = (ssize_t (*)(int, const struct iovec *, int))bxroot_next_symbol("writev");
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
             bxroot_next_symbol("getrlimit");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(resource, rlim);
}

/*
 * RLIMIT_NOFILE 的 EPERM 吞掉（与官方逐条对齐）。
 *
 * 【为什么需要】实测 A/B（同一个探针程序，只换 --preload 的运行时）：
 *
 *     参考实现：setrlimit(RLIMIT_NOFILE, {1M,1M}) → rc=0, errno=0
 *     bxroot      ：setrlimit(RLIMIT_NOFILE, {1M,1M}) → rc=-1, errno=EPERM
 *
 * Android 对每个进程的 fd 上限卡得很死，而 guest 里的
 * node / pnpm / apt 启动时都会**主动抬高 RLIMIT_NOFILE**并检查返回值。
 * 拿到 EPERM 后它们的处理策略各不相同：轻则打印告警，重则直接
 * 降级或退出 —— 这正是"闭源能跑、开源跑不动"这类差距的典型来源。
 *
 * 【官方怎么做】反汇编 runtime 的 setrlimit(+0xa228) / setrlimit64(+0xa4a8)
 * 与 prlimit(+0xa324) / prlimit64(+0xa38c)，四个入口共用同一段判定：
 *
 *     rc = syscall(261, 0, res, new, 0, 0);   // 261 = prlimit64
 *     if (rc == 0)                     return 0;
 *     if (res != RLIMIT_NOFILE)        { errno 原样; return -1; }
 *     if (errno != EPERM)              { errno 原样; return -1; }
 *     errno = 0;                       return 0;      // ★ 假装成功
 *
 * 即：**只吞 RLIMIT_NOFILE + 只吞 EPERM**，其余资源、其余错误一律如实上报。
 * 不做任何数值调整（内核没答应就不假装内核答应了），
 * 只是不让调用方因为一个它无力改变的宿主限制而走进错误分支。
 *
 * 【为什么不是真去改内核值】那需要 CAP_SYS_RESOURCE，Android 应用进程
 * 没有；能做的只有"如实转发 + 对这一种可预期的失败做兼容"。
 */
static int rl_nofile_eperm_to_ok(__rlimit_resource_t resource, int rc)
{
    if (rc == 0)
        return 0;
    if (resource != RLIMIT_NOFILE)
        return rc;
    if (errno != EPERM)
        return rc;

    errno = 0;      /* 与官方一致：对 NOFILE 的 EPERM 报告为成功 */
    LOG("setrlimit(RLIMIT_NOFILE) EPERM -> 报告成功（与官方一致）");
    return 0;
}

int setrlimit(__rlimit_resource_t resource, const struct rlimit *rlim) {
    static int (*fn)(__rlimit_resource_t, const struct rlimit *) = NULL;
    if (fn == NULL)
        fn = (int (*)(__rlimit_resource_t, const struct rlimit *))
             bxroot_next_symbol("setrlimit");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    return rl_nofile_eperm_to_ok(resource, fn(resource, rlim));
}

int getrlimit64(__rlimit_resource_t resource, struct rlimit64 *rlim) {
    static int (*fn)(__rlimit_resource_t, struct rlimit64 *) = NULL;
    if (fn == NULL)
        fn = (int (*)(__rlimit_resource_t, struct rlimit64 *))
             bxroot_next_symbol("getrlimit64");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(resource, rlim);
}

int setrlimit64(__rlimit_resource_t resource, const struct rlimit64 *rlim) {
    static int (*fn)(__rlimit_resource_t, const struct rlimit64 *) = NULL;
    if (fn == NULL)
        fn = (int (*)(__rlimit_resource_t, const struct rlimit64 *))
             bxroot_next_symbol("setrlimit64");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    return rl_nofile_eperm_to_ok(resource, fn(resource, rlim));
}

/*
 * prlimit / prlimit64 —— 资源限制的"带 pid"版本，同样只吞 NOFILE+EPERM。
 *
 * glibc 的 **setrlimit/setrlimit64 在内部就是走 prlimit64 的**
 * （官方 setrlimit64 是 `b prlimit64@plt`，即直接跳到自己的 prlimit64），
 * 所以这两组符号必须共享同一个判定，否则"谁被调用"会决定行为，
 * 而调用方无从知道 —— 那是最难排查的一类不一致。
 *
 * 官方导出的是 prlimit(104B) / prlimit64(284B)，两者共用同一段判定逻辑，
 * 这里保持同构。注意 prlimit 用 struct rlimit、prlimit64 用 struct rlimit64
 * 两个**不同**的结构体（与 glibc 头文件一致），不能合并成一个函数。
 */
int prlimit(pid_t pid, __rlimit_resource_t resource,
            const struct rlimit *new_limit, struct rlimit *old_limit) {
    static int (*fn)(pid_t, __rlimit_resource_t, const struct rlimit *,
                     struct rlimit *) = NULL;
    if (fn == NULL)
        fn = (int (*)(pid_t, __rlimit_resource_t, const struct rlimit *,
                      struct rlimit *))bxroot_next_symbol("prlimit");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    return rl_nofile_eperm_to_ok(resource,
                                 fn(pid, resource, new_limit, old_limit));
}

int prlimit64(pid_t pid, __rlimit_resource_t resource,
              const struct rlimit64 *new_limit, struct rlimit64 *old_limit) {
    static int (*fn)(pid_t, __rlimit_resource_t, const struct rlimit64 *,
                     struct rlimit64 *) = NULL;
    if (fn == NULL)
        fn = (int (*)(pid_t, __rlimit_resource_t, const struct rlimit64 *,
                      struct rlimit64 *))bxroot_next_symbol("prlimit64");
    if (fn == NULL) { errno = ENOSYS; return -1; }

    return rl_nofile_eperm_to_ok(resource,
                                 fn(pid, resource, new_limit, old_limit));
}

/*
 * ==================================================================
 * pthread_create —— 线程栈下限修正（**已实现**，取代原先"不做"的结论）
 * ==================================================================
 *
 * 官方 runtime 导出一个 pthread_create（+0x104b0），做的事是：
 * **把"显式设过 stacksize 但小于 max(2*PTHREAD_STACK_MIN, 256K)"的
 * attr 抬到那个下限**，其余情况原样转发。bxroot 原先不导出它，
 * 于是所有"给小栈"的程序在 bxroot 下行为与官方不同（见下）。
 *
 * 下面先把**旧注释里被实测推翻的三条**逐条更正 —— 那三条当时都是
 * 真跑出来的现象，但**归因错了**，留着会误导后来人。
 *
 * ------------------------------------------------------------------
 * 更正 1：`addr + region == 0` **不是** proroot 加载器的"溢出哨兵"
 * ------------------------------------------------------------------
 * 旧注释把钩子入口读到的
 *
 *     size=131072  addr=0xfffffffffffe0000  region=131072
 *
 * 当成了"proroot 塞的坏地址"。**它是 glibc 自己的常态输出。**
 *
 * 先把 pthread_attr_t 的字段偏移标定清楚（offsets 探针实测，
 * sizeof(pthread_attr_t) = 64）：
 *
 *     attr+16 = guardsize     （attr_init 后 4096）
 *     attr+24 = stackaddr 字段（未 setstack 时 **0**）
 *     attr+32 = stacksize     （attr_init 后 8M）
 *
 * 反汇编 libc 的 pthread_attr_getstack（@0x82f20）：
 *
 *     ldp  x4, x5, [x3, #24]     ; x4 = [attr+24] = stackaddr 字段
 *     sub  x3, x4, x5            ; x5 = [attr+32] = stacksize
 *     str  x3, [x1]              ; *addr   = stackaddr - stacksize
 *     str  x5, [x2]              ; *region = stacksize
 *
 * 即：**region 就是 stacksize 本身**，addr 是 `stackaddr 字段 - stacksize`。
 * 只设过 stacksize 的 attr，stackaddr 字段恒为 0，于是
 *
 *     addr   = 0 - 131072 = 0xfffffffffffe0000（补码）
 *     region = 131072
 *     addr + region == 0   ← 溢出为 0，**纯属 0 - size + size 的恒等式**
 *
 * 实测（offsets 探针，逐字段标定）：
 *
 *     attr_init            : +16=0x1000(guardsize)           getstack(addr=nil, region=0)
 *     setstacksize(131072) : +16=0x1000  +32=0x20000         getstack(addr=-131072, region=131072)
 *     setguardsize(8192)   : +16=0x2000  +32=0x20000         getstack(addr=-131072, region=131072) ← 与 guard 无关
 *     setstack(buf,524288) : +24=base+size  +32=0x80000      getstack(addr=base, region=524288)   ← addr+region != 0
 *
 * ★ 关键：**官方 runtime 侧、noop 侧、原生侧读到的完全是同一个值**。
 *   所以它既不是 bxroot 引入的，也不是加载器缺陷，更不带来任何危害 ——
 *   pthread_create 只读 attr 里的 stacksize 字段，不看这个派生出来的 addr。
 *   （原先"不带任何 bxroot 代码时也发生 → 是加载器缺陷"的推理，
 *     前提为真、结论为假：那个现象在**没有 proroot 的原生环境里同样存在**。）
 *
 * ------------------------------------------------------------------
 * 更正 2：官方 0x10540 的 `cmn x7,x6 / b.eq` 是【应用修正】，不是【跳过】
 * ------------------------------------------------------------------
 * 旧注释（以及调查报告 §2.4）都把它读成了"命中就跳过修正"。**读反了。**
 * 看分支目标 0x105f4 的实际代码：
 *
 *     10540: cmn  x7, x6          ; addr + region == 0 ?
 *     10544: b.eq 105f4           ; 是 → 去 105f4
 *     ...
 *     105f4: cbz  w21, 1064c      ; 日志关 → 1064c
 *     1064c: cbnz w23, 10550      ; getstacksize 失败 → 直通
 *     10650: mov  w0, #0x4b       ; _SC_THREAD_STACK_MIN
 *     10654: bl   __sysconf
 *     1065c: lsl  x23, x0, #1     ; 2 × PSM
 *     10660: mov  x2, #0x40000    ; 256K
 *     10668: csel x23, x23, x2, cs; 取较大者
 *     10674: b.ls 10550           ; 已够大 → 直通
 *     10678: ldp  q29,q28,[x19]   ; 复制整个 attr（64 字节）
 *     10694: bl   pthread_attr_setstacksize  ; 把副本抬到 x23
 *     106a0: mov  x19, x27        ; 用副本创建
 *
 * 0x105f4 正是**落地修正**的那条路。`b.eq` 在 `addr+region==0` 时**进入**
 * 修正流程，`!b.eq`（真显式栈区）时在 0x10548/0x1054c 记日志后也汇到
 * 0x10600 → 0x1064c → 同样的 10650 修正段。
 * 换句话说：**两条路都做修正**，`b.eq` 只是决定了"要不要先记日志"。
 * 这也解释了为什么"逐位照抄官方判据"在 131072 档位**照样 EINVAL** ——
 * 因为照抄的那份把 `b.eq` 理解反了，命中了哨兵反而**提前 return 直通**，
 * 根本没走到修正段。
 *
 * ------------------------------------------------------------------
 * 更正 3：根因是 glibc 的守卫页下限，不是加载器；且 bxroot 侧**可修**
 * ------------------------------------------------------------------
 * 实测（bound，dlopen("libc.so.6") 绕过一切钩子后直调真 pthread_create）：
 *
 *     size=131072  rc=22 EINVAL      <- 原生、官方、bxroot 三侧**完全一致**
 *     size=135168  rc=22 EINVAL
 *     size=136192  rc=22 EINVAL
 *     size=137216  rc=22 EINVAL
 *     size=138240  rc=22 EINVAL
 *     size=139264  rc=0  OK          <- 134K + 4K(guard) = 138K，向上取整
 *
 * 即 glibc 要求 `stacksize >= PTHREAD_STACK_MIN(128K) + guardsize(4K)`
 * 再对齐到页，故真正的下界是 **139264（136K）**。这纯粹是 libc 的
 * 既有语义 —— 与我们无关，官方 runtime 也**没有**改掉它（官方
 * 139264 以下一样 EINVAL，只是它把 < 256K 的请求**抬到 256K**，
 * 于是调用方根本碰不到那个下界）。
 *
 * ★ 官方与 bxroot 的真实差距（这才是要补的 parity）★
 *
 *   用 pthread_getattr_np 读回线程**真实**拿到的栈大小（realstack）：
 *
 *     请求       官方真实栈   bxroot 真实栈
 *     131072     262144        rc=22 EINVAL（未创建）
 *     135168     262144        rc=0 → **135168**
 *     147456     262144        rc=0 → **147456**
 *     262144     262144        262144
 *     524288     524288        524288
 *
 *   官方把"小于 256K"的请求**静默抬到 256K**；bxroot 不给下限，
 *   于是 131072 直接 EINVAL，135168~262143 则**真的**只给那么小的栈 ——
 *   调用方的线程随后在深调用链上撞守卫页 → SIGSEGV。
 *   这才是本符号必须补的理由，也解释了旧注释第 1 点观察到的
 *   "135168 → rc=0 但随后 SIGSEGV"：**不是加载器坏，是栈真的不够用**。
 *
 * ------------------------------------------------------------------
 * 本实现（与官方语义对齐）
 * ------------------------------------------------------------------
 *   - 判据用"**是否真的带了显式栈区**"，而不是"addr 是否非空"。
 *     glibc 的 attr 里没有"显式栈区"这个独立标志位，它只能从
 *     `pthread_attr_getstack` 的返回值反推（见更正 1 的字段标定）：
 *     只要设过 stacksize，`stackaddr 字段` 恒为 0，getstack 就会返回
 *     `addr = -stacksize, region = stacksize` 这个派生值（addr 非空！）。
 *     若照报告 §2.4 的骨架用 `addr != NULL` 当判据，**每一次**线程创建
 *     都会被当成"有显式栈区"，于是永远走不到修正段（或反过来被无故替换），
 *     把调用方通过 attr 设的 guard size 等语义一起丢掉 ——
 *     这属于"修一个边缘情况而破坏正常路径"，必须避免。
 *     真正的区分依据是 **addr + region 是否为 0**：
 *       - 只设 stacksize：addr = -size, region = size → 和为 0
 *       - 真显式栈区    ：addr = base,  region = size → 和为 base ≠ 0
 *
 *   - 下限取 `max(2 * sysconf(_SC_THREAD_STACK_MIN), 262144)`。
 *     实测本环境 `_SC_THREAD_STACK_MIN = 131072`（PAGESIZE=4096），
 *     故 2×PSM = 262144 = 256K，**与官方的 0x40000 完全吻合**；
 *     两个取较大者的写法也和官方 10660~10668 逐位一致。
 *     256K 这个值本身也是恰当的：它是 glibc 真实下界 139264 的 1.9 倍，
 *     给线程留出了足够的深调用链余量（实测官方抬到 256K 后不再 SIGSEGV）。
 *
 *   - **必须用"副本"，且必须是逐字节复制**：官方在 10678~10690 把调用方
 *     的整个 64 字节 attr **复制**到栈上、只改 stacksize，因为形参是
 *     `const pthread_attr_t *`，就地改是 UB。
 *     ★ 注意与调查报告 §2.4 的两处措辞差异：
 *       ① 报告说"沿用原 attr 会把哨兵 addr 一起带过去，等于没修"——
 *          **这句是错的**（attr 里根本没有哨兵，见更正 1）。
 *          复制是对的，但理由只是"不能改调用方的 const 对象"。
 *       ② 报告给的骨架用 `pthread_attr_init` 造"全新 attr"——
 *          **这个写法与官方不等价**：init 会把 guardsize 重置成默认 4096，
 *          而官方是复制，**保留调用方设的 guardsize**。实测（thredge，
 *          请求 stacksize=128K + guardsize=16384）：
 *
 *            官方      : 真实栈=524288  guard=16384   ← 保留
 *            init 写法 : 真实栈=524288  guard=4096    ← 被改掉
 *
 *          调用方特意放大 guard 是为了防栈溢出，被静默改回默认属于
 *          "修边缘情况而破坏正常路径"，故本实现改为 memcpy 复制。
 *     实测四条档位与官方逐位一致（见 docs/pthread_create栈哨兵修复.md）。
 *
 *   - 失败路径全部**保守直通**：getstacksize/getstack 报错、setstacksize
 *     失败，一律转给真实现，绝不因为修边缘情况而挡住正常路径。
 *     （memcpy 复制不需要 destroy —— 复制的是 POD，没有需要释放的资源。）
 *
 *   - **自递归防护**：真实现经 `bxroot_next_symbol` 解析（语义 = dlsym(RTLD_NEXT)，
 *     走 linker 服务；**无服务环境**下它自己退回 libc 的 dlsym(RTLD_NEXT)，
 *     同样正确跳过本库）。解析不到就返回 EAGAIN(11)，与官方 0x106fc 一致。
 *     ★ 另需防"解析到自己"：本库导出 pthread_create，若 ldso 服务把
 *     **我们自己**返回了，再调用就是无限递归炸栈（每层吃一个栈帧，
 *     症状是 SIGSEGV 且 sp == x29）——另一 agent 在 dlerror 上踩过同样的坑。
 *     这里显式比对函数地址，命中自己即判为解析失败 → EAGAIN。
 *     ★ 刻意**不**补 `dlsym(RTLD_DEFAULT, …)` 兜底：RTLD_DEFAULT 从搜索链
 *     最前面找，必然先命中本库自己；它既冗余（RTLD_NEXT 已覆盖非 proroot
 *     环境），又会因调用本库自己的 dlsym 而**篡改 dlerror 状态**，
 *     把一个本来可用的环境弄坏。详见函数体内那段注释。
 *
 * 附带说明：glob/freopen/utime 等同批探查的符号，实测 bxroot 与官方
 * **行为一致或同源失败**（见报告"实测 parity"一节），无需改动。
 */

/*
 * pthread_create —— 线程栈下限修正。
 *
 * 必须在文件作用域导出（LD_PRELOAD 靠动态符号表插入），所以这里没有
 * 加 static。参数签名与 <pthread.h> 逐字一致，否则符号对不上。
 */
int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                   void *(*start_routine)(void *), void *arg)
{
    static int (*real_fn)(pthread_t *, const pthread_attr_t *,
                          void *(*)(void *), void *) = NULL;
    pthread_attr_t clean;
    size_t size = 0, region = 0;
    void *addr = NULL;
    long psm;
    size_t want;
    int rc;

    if (real_fn == NULL) {
        void *p = bxroot_next_symbol("pthread_create");
        /*
         * ★ 自递归防护 ★
         * 本库自己就导出 pthread_create。若解析结果等于本函数的地址，
         * 说明拿到了自己 —— 再调用就是无限递归（每层吃一个栈帧直到炸栈，
         * 症状是 SIGSEGV 且 sp == x29）。这里直接判定为"解析失败"。
         * 对照：dlsym/dlopen 家族就是被这个坑炸过（见本文件 dl* 家族注释）。
         */
        if (p == (void *)(uintptr_t)&pthread_create)
            p = NULL;
        real_fn = (int (*)(pthread_t *, const pthread_attr_t *,
                           void *(*)(void *), void *))p;
    }

    /*
     * 解析不到真实现。
     *
     * ★ 这里**刻意不再**补一次 `dlsym(RTLD_DEFAULT, "pthread_create")` ★
     *
     * 曾经写过那次兜底，实测它是**有害**的：
     *   1. 冗余。`bxroot_next_symbol` 在"无 linker 服务"的环境里
     *      已经退回了 libc 的 `dlsym(RTLD_NEXT, …)`；而 RTLD_NEXT 的语义
     *      正是"从**本库之后**开始找"，在 LD_PRELOAD 场景下会正确跳过我们
     *      命中真 libc。那条路已经覆盖了无 loader 服务环境。
     *   2. 危险。RTLD_DEFAULT 是"从搜索链**最前面**开始找"，
     *      而本库正是排在 LD_PRELOAD 最前面的那个 —— 于是它**必然**
     *      先命中我们自己。虽然下面有"等于自己就置 NULL"的防护，
     *      但结果是"本来能成功解析"的场合变成了 EAGAIN，
     *      反而把一个可用环境弄坏。
     *   3. 有副作用。本库的 dlsym 是**已实现**的钩子，调用它会去写
     *      dl-error 状态（`bxroot_dl_error_set2`）。为了一个兜底去篡改
     *      "上一次 dlerror 的内容"是错误的：调用方可能刚查过 dlerror。
     *
     * 所以只保留一条解析路径，与官方同构：
     *   官方 106e8~10700 解析失败 → `mov w23, #0xb; ret`（EAGAIN）。
     * 为什么是 EAGAIN(11) 而不是 ENOSYS：逐位保持官方语义。
     */
    if (real_fn == NULL)
        return EAGAIN;

    /* attr == NULL：默认属性（stacksize 由 libc 给 8M），无事可做 */
    if (attr == NULL)
        return real_fn(thread, attr, start_routine, arg);

    /*
     * 读 attr。两者任一失败就直通 —— 读不到就不该猜。
     * 注意 pthread_attr_getstacksize 的返回值是错误码（不设 errno）。
     */
    if (pthread_attr_getstacksize(attr, &size) != 0)
        return real_fn(thread, attr, start_routine, arg);
    if (pthread_attr_getstack(attr, &addr, &region) != 0)
        return real_fn(thread, attr, start_routine, arg);

    /*
     * ★ 判据：区分"只设了 stacksize"与"真的带了显式栈区"。
     *
     * 先看清 libc 的 pthread_attr_getstack 到底返回什么（见文件上方更正 1）：
     *     region = [attr+32] = stacksize
     *     addr   = [attr+24] - [attr+32] = stackaddr字段 - stacksize
     *
     * 于是两种情形自然分开：
     *   - 只设过 stacksize：stackaddr 字段恒为 0
     *       → addr = -stacksize，region = stacksize，**addr + region == 0**
     *   - 真设过显式栈区（pthread_attr_setstack）：
     *       [attr+24] = base + size ≠ 0
     *       → addr = base，**addr + region == base ≠ 0**
     *
     * 官方 0x10540 的 `cmn x7,x6`（addr + region == 0 ?）判的正是同一件事，
     * 两条路都做修正，`b.eq` 只决定要不要先记日志 —— 见更正 2。
     *
     * 真显式栈区**必须原样转发**：那种调用方自己管内存，
     * 我们替它换栈会破坏它的语义（它可能已经把栈指针/映射交给别处）。
     */
    if (region != 0 && (uintptr_t)addr + region != 0)
        return real_fn(thread, attr, start_routine, arg);

    /*
     * 下限 = max(2 × PTHREAD_STACK_MIN, 256K)，与官方 10650~10668 一致。
     * sysconf 失败（返回 -1）时只用 256K —— 不能拿 -1 去乘。
     */
    psm = sysconf(_SC_THREAD_STACK_MIN);
    want = 262144;
    if (psm > 0 && (size_t)psm * 2 > want)
        want = (size_t)psm * 2;

    /* 已经够大 → 直通（官方 10674 的 b.ls 就是这条） */
    if (size >= want)
        return real_fn(thread, attr, start_routine, arg);

    /*
     * ★ 用**副本**，不能就地改调用方的 attr ★
     * 形参是 `const pthread_attr_t *`，就地改是 UB。
     *
     * ★ 这里曾经写成 `pthread_attr_init(&clean)` + `setstacksize`，
     *   实测**与官方不等价**：官方在 10678~10690 是把调用方的
     *   整个 64 字节**逐字节复制**到栈上再改 stacksize，因此
     *   **guardsize 等其它字段被原样保留**；而 init 会把 guardsize
     *   重置成默认 4096。
     *
     *   实测（thredge，请求 stacksize=128K + guardsize=16384）：
     *     官方   : 真实栈=524288  guard=**16384**  ← 保留调用方的设置
     *     旧 init: 真实栈=524288  guard=**4096**   ← 把它改掉了
     *
     *   这正是"修一个边缘情况而破坏正常路径"的典型：
     *   调用方特意放大 guard（防栈溢出）会被我们静默改回默认。
     *   所以改为与官方同构的 memcpy 复制。
     *
     * memcpy 而不是直接传 `attr`：必须能改 stacksize 字段。
     * 复制的是 pthread_attr_t（POD，64 字节），没有需要 destory 的资源，
     * 故本路径**不需要**（也不应该）调用 pthread_attr_destroy。
     */
    memcpy(&clean, attr, sizeof(clean));
    if (pthread_attr_setstacksize(&clean, want) != 0) {
        /* setstacksize 失败：clean 是副本，无资源可释放，直通即可 */
        return real_fn(thread, attr, start_routine, arg);   /* 保守直通 */
    }

    rc = real_fn(thread, &clean, start_routine, arg);
    return rc;
}

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

    /*
     * ★ 顺序很重要：**先校验长度，再读 sa_family**。
     *
     * 内核的 `move_addr_to_kernel()` 就是这个顺序 —— 它先确认
     * `addrlen` 落在 [sizeof(sa_family_t), sizeof(struct sockaddr_storage)]
     * 区间内，才去 copy_from_user。
     *
     * 曾经把 `addr->sa_family != AF_UNIX` 写在长度检查**之前**：
     * 客户传 `addrlen = 0`（或极小值）时，我们已经在读 addr 的第一个
     * 字节了。若那个地址恰好落在映射边界上（客户从一个页末尾传指针、
     * 或干脆是野指针），这一读就是 SIGSEGV —— 而内核本来只会
     * 优雅地返回 EINVAL。
     *
     * 即：**我们比内核更严格地解引用客户指针**，这是不该有的行为。
     */
    if (addr == NULL)
        return 0;

    /* 至少要能装下 sun_family + 1 字节路径。这一步必须在读 sa_family 之前。 */
    if (len <= (socklen_t)offsetof(struct sockaddr_un, sun_path) + 1)
        return 0;

    if (addr->sa_family != AF_UNIX)
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
             bxroot_next_symbol("bind");
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
             bxroot_next_symbol("connect");
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
        fn = (int (*)(int, int, int))bxroot_next_symbol("socket");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(domain, type, protocol);
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    static int (*fn)(int, struct sockaddr *, socklen_t *) = NULL;
    if (fn == NULL)
        fn = (int (*)(int, struct sockaddr *, socklen_t *))
             bxroot_next_symbol("getsockname");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(sockfd, addr, addrlen);
}

int getsockopt(int sockfd, int level, int optname, void *optval,
               socklen_t *optlen) {
    static int (*fn)(int, int, int, void *, socklen_t *) = NULL;
    if (fn == NULL)
        fn = (int (*)(int, int, int, void *, socklen_t *))
             bxroot_next_symbol("getsockopt");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(sockfd, level, optname, optval, optlen);
}

int setsockopt(int sockfd, int level, int optname, const void *optval,
               socklen_t optlen) {
    static int (*fn)(int, int, int, const void *, socklen_t) = NULL;
    if (fn == NULL)
        fn = (int (*)(int, int, int, const void *, socklen_t))
             bxroot_next_symbol("setsockopt");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(sockfd, level, optname, optval, optlen);
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    static ssize_t (*fn)(int, const struct msghdr *, int) = NULL;
    if (fn == NULL)
        fn = (ssize_t (*)(int, const struct msghdr *, int))
             bxroot_next_symbol("sendmsg");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(sockfd, msg, flags);
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
    static ssize_t (*fn)(int, struct msghdr *, int) = NULL;
    if (fn == NULL)
        fn = (ssize_t (*)(int, struct msghdr *, int))
             bxroot_next_symbol("recvmsg");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(sockfd, msg, flags);
}

/* getifaddrs —— node 用它枚举网络接口（官方有 FORCE_FAKE_GETIFADDRS 开关） */
int getifaddrs(struct ifaddrs **ifap) {
    static int (*fn)(struct ifaddrs **) = NULL;
    if (fn == NULL)
        fn = (int (*)(struct ifaddrs **))bxroot_next_symbol("getifaddrs");
    if (fn == NULL) { errno = ENOSYS; return -1; }
    return fn(ifap);
}

void freeifaddrs(struct ifaddrs *ifa) {
    static void (*fn)(struct ifaddrs *) = NULL;
    if (fn == NULL)
        fn = (void (*)(struct ifaddrs *))bxroot_next_symbol("freeifaddrs");
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
        fn = (int (*)(char *))bxroot_next_symbol("mkstemp64");
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
        fn = (int (*)(char *, int))bxroot_next_symbol("mkostemp64");
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
        fn = (int (*)(char *, int))bxroot_next_symbol("mkstemps64");
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
        fn = (int (*)(char *, int, int))bxroot_next_symbol("mkostemps");
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
        fn = (int (*)(char *, int, int))bxroot_next_symbol("mkostemps64");
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
             bxroot_next_symbol("scandir64");
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

/*
 * Hook: freopen / freopen64 —— fopen 的"换目标"版本，**同样必须翻译**。
 *
 * 【为什么需要】实测 A/B（同一个探针，只换 --preload 的运行时）：
 *
 *     fopen("/fr-in.txt","w") 成功 → freopen("/fr-out.txt","w",f)
 *
 *       参考实现：freopen 返回原 FILE* ，errno=0        ✅
 *       bxroot(改前)：freopen 返回 NULL，errno=30 EROFS     ❌
 *
 * 连续两轮复现一致；且与 setrlimit/SIGSYS 那两处无关（改动前同样如此）。
 *
 * 【根因】freopen 没被 hook。glibc 的 freopen **不经 fopen 的 PLT**
 * （它是独立实现，内部直接走 _IO_file_fopen），所以已有的 fopen /
 * fopen64 钩子一条都收不到。用 BXROOT_VERBOSE 构建可以直观看到：
 * 探针打印了 `translate: /fr-in.txt` 与 `fopen: /fr-in.txt` 两行，
 * 而 freopen 那一步**一行日志都没有** —— 路径原样交给内核，
 * 于是内核去开容器里的 `/fr-out.txt`，即宿主真实根目录下的
 * `/fr-out.txt`（只读），返回 EROFS。
 *
 * 【参考计数】freopen 被 rootfs 内 15 个二进制引用、freopen64 被 4 个
 * （diff3、perl 等；统计口径见 parity 报告）。
 *
 * 【为什么官方导出列表里没有 freopen】官方只导出了 fopen/fopen64
 * （与 bxroot 相同）。它的 freopen 之所以能用，是因为官方的路径翻译
 * 覆盖面更广（例如它在 syscall 层与更底层的 open 路径上也做了处理），
 * 而不是靠一个 freopen 符号。bxroot 的翻译钩子是按符号逐个落的，
 * 所以这里必须**显式补上**这个符号 —— 这正是"符号数不是目的，
 * 覆盖到的调用路径才是"的一个实例。
 *
 * 语义注意：freopen 失败时**原 stream 已被关闭**（C 标准如此），
 * 所以失败路径不需要（也不能）恢复原 stream，直接返回真实实现的
 * 结果即可，切勿自己造一个 FILE*。
 */
FILE *freopen(const char *path, const char *mode, FILE *stream) {
    static FILE *(*fn)(const char *, const char *, FILE *) = NULL;

    if (fn == NULL)
        fn = (FILE *(*)(const char *, const char *, FILE *))
             bxroot_next_symbol("freopen");
    if (fn == NULL) { errno = ENOSYS; return NULL; }

    /* path == NULL 时 freopen 用于"改 mode"，没有路径可翻译 */
    if (path != NULL) {
        char translated[MAX_PATH_LEN];
        if (translate_path(path, translated, sizeof(translated)) > 0) {
            LOG("freopen: %s -> %s", path, translated);
            return fn(translated, mode, stream);
        }
    }
    return fn(path, mode, stream);
}

/* Hook: freopen64 —— 与 freopen 同构，只是 FILE 走 LFS 变体 */
FILE *freopen64(const char *path, const char *mode, FILE *stream) {
    static FILE *(*fn)(const char *, const char *, FILE *) = NULL;

    if (fn == NULL)
        fn = (FILE *(*)(const char *, const char *, FILE *))
             bxroot_next_symbol("freopen64");
    if (fn == NULL) { errno = ENOSYS; return NULL; }

    if (path != NULL) {
        char translated[MAX_PATH_LEN];
        if (translate_path(path, translated, sizeof(translated)) > 0) {
            LOG("freopen64: %s -> %s", path, translated);
            return fn(translated, mode, stream);
        }
    }
    return fn(path, mode, stream);
}

/*
 * ★ 这里**曾经**有一个 getpid 钩子，已删除。不要加回来。★
 *
 * 原实现（错误）：
 *     pid_t getpid(void) {
 *         ensure_real_functions();
 *         pid_t pid = real_getpid();
 *         if (g_config.fakeroot) {
 *             return 1;      /＊ 伪装为 root 进程 ＊/
 *         }
 *         return pid;
 *     }
 *
 * 【官方行为是什么】
 *   参考实现/proot **从不**导出 getpid，也从不改它的返回值。
 *   proot 自己的注释写得很直白（src/extension/fake_id0/sendmsg.c:164-165）：
 *       "Set uid and gid of SCM_CREDENTIALS to ones that proot really has.
 *        Pid is not changed as we don't fiddle with getpid()"
 *   实测核对两份动态符号表（nm -D --defined-only，去版本号）：
 *       官方 libproroot-runtime.so : 无 getpid
 *       bxroot （本次修复前）      : 有 getpid      ← 唯一的偏离
 *   fakeroot 只伪装 **uid/gid**（getuid/getgid/geteuid/getegid），
 *   与 pid 毫无关系 —— 那是两件不相干的事。
 *
 * 【原来错在哪】
 *   在 BXROOT_FAKEROOT=1 下把 getpid() 硬编码成 1，于是**同一条**命令的
 *   每个进程都自称 pid 1。shell 的 `$$` 就是 getpid()，而 `$$` 是脚本里
 *   进程唯一性的常规手段：
 *       D=/tmp/build-$$ ; mkdir -p "$D"
 *   所有并发进程都落进同一个 /tmp/build-1，互相删对方的中间文件。
 *   portage / dpkg / npm 这类会 fork 并发的工具因此会莫名失败。
 *   实测（同一探针，见 docs/getpid伪造缺陷.md）：
 *       官方  : PID=10664  CHILD_A pid=10665  CHILD_B pid=10666  DIRS=2
 *       bxroot: PID=1      CHILD_A pid=1      CHILD_B pid=1      DIRS=1  ← 撞车
 *
 * 【为什么这样改：直接删掉，而不是「保留钩子但返回真 pid」】
 *   两种写法语义等价（都返回真实 pid），但删掉更强：
 *     1. 与官方**逐符号一致** —— 这是本项目 work/parity 的目标本身；
 *     2. 不再有调用开销：原钩子每次调用都要过 ensure_real_functions()
 *        再间接转发，而 getpid 是热路径（libuv/shell/进程管理都会走）；
 *     3. 消灭整类缺陷：钩子没了，就没有任何分支可能再把它改回 1。
 *        留一个只会原样转发的钩子，等于给下一个人留了个改错的地方。
 *
 * 【删除它会破坏什么：已逐点排查，结论是「什么都不破坏」】
 *   - D4 进程管理层**不依赖**本钩子：proc.c 一律用
 *     syscall(SYS_getpid) 取自身 pid（px_self_pid / PX_SYSOPS），
 *     刻意绕开 libc 包装，所以删掉钩子对它毫无影响。
 *   - crash.c 的 `kill(getpid(), sig)` 反而**需要**真实 pid：
 *     修复前它拿到 1，被 D4 白名单当成「容器外进程」拒绝
 *     （实测日志「proc: kill(1, 11) 被拒绝」），重抛失败；删掉钩子后
 *     命中 px_check_kill 的 protect_self 分支正常放行。这是**同源**的
 *     第二个缺陷，一并被这次修改修掉。
 *   - bridge.c 的 socket 路径 "/tmp/.bxroot-bridge-<pid>.sock"
 *     要的也是真实 pid。
 *   - 全仓搜索确认：**没有任何代码判断 `getpid() == 1`**。
 *     docs/P0-3-D4集成报告.md:51-52 那句「getpid 在 fakeroot 下被伪装成 1，
 *     这个自伤场景是常态」只是对当时现象的**描述**，并据此加了
 *     px_runtime_register_self() 这道补丁；它并不是一个依赖，
 *     而是一个「绕开错误行为」的规避手段。真实 pid 下该补丁无害
 *     （把自己记进账本仍然正确），故保留不动。
 *
 * 参考实现里的 real_getpid 静态指针与它在 ensure_real_functions() 里的
 * 初始化也已一并删除 —— 否则会触发本仓库零告警门禁的未使用变量告警。
 */

/*
 * Hook: getuid / getgid / geteuid / getegid (fakeroot)
 *
 * ★ 必须读**账本**，不能硬编码 0 ★
 *
 * 【缺陷（实测，2026-09-17）】这四个原先写的是：
 *
 *     if (g_config.fakeroot) { return 0; }
 *
 * 即"只要 fakeroot 开着就永远是 0"。这在**没有 setter 之前**看不出问题，
 * 但官方是**有状态**的 —— setter 生效后回读会变：
 *
 *     ########## 官方 ##########            ########## bxroot（修前）##########
 *     BEFORE: getuid=0 getgid=0              BEFORE: getuid=0 getgid=0
 *     setgid(999) rc=0  setuid(999) rc=0     setgid(999) rc=0（已可模拟）
 *     AFTER : getuid=999 getgid=999          AFTER : getuid=0   ❌ 账本没被读
 *
 * 也就是"setter 写了账本、getter 不读账本"——正是本项目反复出现的
 * **两层给出不同答案**。账本就在 `g_fakeroot_state` 里，读它即可。
 *
 * 【判据用哪个】
 * 用 `g_fakeroot_on`（不是 `g_config.fakeroot`）：`init_fakeroot()` 在
 * 记账表创建失败时会**整体关掉** fakeroot（半残的 fakeroot 比没有更危险）。
 * 这与 `bxroot_fakeroot_ids()` 的判据必须**同一个** —— 否则会出现
 * "符号层读账本、裸 syscall 层硬编码 0"这种新的两层矛盾。
 *
 * 注：`real_getuid` 等指针仍保留（未启用时透传），见上面的
 * ensure_real_functions()。
 */
uid_t getuid(void) {
    ensure_real_functions();

    if (g_fakeroot_on) {
        return g_fakeroot_state.ruid;
    }

    return real_getuid();
}

gid_t getgid(void) {
    ensure_real_functions();

    if (g_fakeroot_on) {
        return g_fakeroot_state.rgid;
    }

    return real_getgid();
}

uid_t geteuid(void) {
    ensure_real_functions();

    if (g_fakeroot_on) {
        return g_fakeroot_state.euid;
    }

    return real_geteuid();
}

gid_t getegid(void) {
    ensure_real_functions();

    if (g_fakeroot_on) {
        return g_fakeroot_state.egid;
    }

    return real_getegid();
}

/*
 * ==================================================================
 * 缺口 C（符号层）：setuid / setgid / setreuid / ... 的钩子
 * ==================================================================
 *
 * 【为什么必须有这一层 —— 实测证据】
 *
 * 先前修了 `syscall(143/144/...)` 这一层，但 `chage` **仍然失败**：
 *
 *     $ BXROOT_SIGSYS_LOG=1 chage -l root
 *     [bxroot] sigsys: 模拟 syscall 143 -> ENOSYS
 *     chage: failed to drop privileges (Function not implemented)
 *
 * 而 `readelf --dyn-syms chage` 显示它引用的是 **`setreuid` 符号**
 * （不是裸 svc；`objdump -d chage | grep -c svc` = **0**）。
 * 也就是说 glibc 的 `setreuid` **包装函数**自己发 svc —— 它既不经过
 * libc 的 `syscall()` 符号（我们上轮修的那层），也不经过我们的任何钩子，
 * 直接撞上 宿主 loader 的 seccomp 过滤器。
 *
 * ┌──────────────────────────────────────────────────────────┐
 * │ 三种发起方式，各自需要不同的拦截点：                      │
 * │   ① 程序调 setreuid(2) 符号   -> 需要**符号层**钩子（本组）│
 * │   ② 程序调 syscall(143,...)   -> 需要 syscall() 钩子（上轮）│
 * │   ③ 程序内联 svc #0           -> **两侧都拦不到**（官方也不拦）│
 * └──────────────────────────────────────────────────────────┘
 *
 * 这正是本项目反复出现的「同一功能在不同路径上覆盖不全」模式 ——
 * 修了 ② 就以为修完了，而真实程序（chage）走的是 ①。
 *
 * 【为什么调用 fakeroot_set* 而不是自己改字段】
 * 与桥接层同一理由：账本逻辑只有一份，改字段会与纯逻辑层的闸门
 * （caps_active / keep_caps / MAYBE_DROP_CAPS）脱钩。
 *
 * 【setgroups 为什么走桥接而不是 fakeroot_setgroups】
 * 见 preload.c 末尾 `bxroot_fakeroot_setter` 的 case 7 长注释：
 * 上游 参考实现 对 setgroups 是**无条件成功**（fake_id0.c:1016），
 * 而纯逻辑层带一条 CAP_SETGID 闸门。为与官方可观测行为一致，
 * 这一层与 syscall 层**共用**同一个桥接实现（单一来源）。
 */
int setuid(uid_t uid) {
    long r; int e;
    if (bxroot_fakeroot_setter(1, (unsigned long)uid, 0, 0, &r, &e) == 1) {
        errno = e;
        return (int)r;
    }
    errno = ENOSYS;
    return -1;
}

int setgid(gid_t gid) {
    long r; int e;
    if (bxroot_fakeroot_setter(2, (unsigned long)gid, 0, 0, &r, &e) == 1) {
        errno = e;
        return (int)r;
    }
    errno = ENOSYS;
    return -1;
}

int setreuid(uid_t r_, uid_t e_) {
    long r; int e;
    if (bxroot_fakeroot_setter(3, (unsigned long)r_, (unsigned long)e_, 0,
                               &r, &e) == 1) {
        errno = e;
        return (int)r;
    }
    errno = ENOSYS;
    return -1;
}

int setregid(gid_t r_, gid_t e_) {
    long r; int e;
    if (bxroot_fakeroot_setter(4, (unsigned long)r_, (unsigned long)e_, 0,
                               &r, &e) == 1) {
        errno = e;
        return (int)r;
    }
    errno = ENOSYS;
    return -1;
}

int setresuid(uid_t r_, uid_t e_, uid_t s_) {
    long r; int e;
    if (bxroot_fakeroot_setter(5, (unsigned long)r_, (unsigned long)e_,
                               (unsigned long)s_, &r, &e) == 1) {
        errno = e;
        return (int)r;
    }
    errno = ENOSYS;
    return -1;
}

int setresgid(gid_t r_, gid_t e_, gid_t s_) {
    long r; int e;
    if (bxroot_fakeroot_setter(6, (unsigned long)r_, (unsigned long)e_,
                               (unsigned long)s_, &r, &e) == 1) {
        errno = e;
        return (int)r;
    }
    errno = ENOSYS;
    return -1;
}

int setgroups(size_t n, const gid_t *list) {
    long r; int e;
    if (bxroot_fakeroot_setter(7, (unsigned long)n,
                               (unsigned long)(uintptr_t)list, 0,
                               &r, &e) == 1) {
        errno = e;
        return (int)r;
    }
    errno = ENOSYS;
    return -1;
}

/*
 * setfsuid / setfsgid 的返回值是**旧值**（man 明确），所以桥接直接
 * 把旧值放在 `r` 里给我们，不能当成"0 = 成功"处理。
 */
uid_t setfsuid(uid_t fsuid) {
    long r; int e;
    if (bxroot_fakeroot_setter(8, (unsigned long)fsuid, 0, 0, &r, &e) == 1) {
        errno = e;
        return (uid_t)r;
    }
    errno = ENOSYS;
    return (uid_t)-1;
}

gid_t setfsgid(gid_t fsgid) {
    long r; int e;
    if (bxroot_fakeroot_setter(9, (unsigned long)fsgid, 0, 0, &r, &e) == 1) {
        errno = e;
        return (gid_t)r;
    }
    errno = ENOSYS;
    return (gid_t)-1;
}

/* Hook: uname (伪装为 Linux) */
/*
 * 有界字符串长度（供 uname 的定长字段拷贝使用）。
 *
 * ★ 为什么必须 `noinline` ★
 * `strnlen(literal, 64)` 会被 gcc 13 判 `-Wstringop-overread`：
 * 它看到源是 6 字节字面量、而界限是 64，就认为可能越界读。
 * 实际上 strnlen 遇到 NUL 即停，字面量必然有 NUL，**不会越界** ——
 * 这是该模式下的已知误报。但告警门禁要求零告警，不能靠 `-Wno-` 掩盖。
 *
 * 包一层 `noinline` 之后，gcc 在调用点看不到源对象的尺寸，
 * 无法做这项推断，误报消失；函数本身仍是"遇到 NUL 即停"，
 * 语义与直接调用 strnlen 完全一致。
 */
__attribute__((noinline))
static size_t bxroot_bounded_strlen(const char *s, size_t cap) {
    return strnlen(s, cap);
}

int uname(struct utsname *buf) {
    ensure_real_functions();

    int ret = real_uname(buf);
    if (ret == 0) {
        /*
         * ★ 定长字段写入必须显式补 NUL ★
         *
         * `struct utsname` 的字段是**定长数组**（`_UTSNAME_LENGTH`，本平台 65），
         * 不是指针。原来的写法 `strncpy(dst, "6.1.0", sizeof(dst))` 对**固定
         * 字面量**是安全的（源串远短于目标），但一旦源变成**用户输入**就
         * 会踩 `strncpy` 的经典陷阱：
         *
         *   源串长度 >= sizeof(dst) 时，strncpy **不写结尾 NUL**，
         *   于是字段没有终止符 —— 调用方 `printf("%s", buf->release)`
         *   会越界读到相邻字段，直到偶然遇到一个 0 字节。
         *
         * `-k/--kernel-release` 正是把用户输入接到这里，所以必须改。
         * 下面的 `copy_field()` 统一处理三类字段，避免三处各写一遍。
         */
        #define UNAME_COPY_FIELD(dst, src)                        \
            do {                                                  \
                size_t cap_ = sizeof(dst);                        \
                size_t n_ = bxroot_bounded_strlen((src), cap_ - 1); \
                memset((dst), 0, cap_);        /* 先清零 → 必定 NUL */ \
                memcpy((dst), (src), n_);                         \
            } while (0)

        /* 确保显示为 Linux 而不是 Android */
        if (strstr(buf->sysname, "Android") != NULL) {
            UNAME_COPY_FIELD(buf->sysname, "Linux");
        }

        /*
         * 伪装 kernel release。
         *
         * 取值优先级：`BXROOT_KERNEL_RELEASE`（由 launcher 从
         * `-k/--kernel-release` 派生）→ 默认 `"6.1.0"`。
         *
         * ★ 默认值不能变 ★
         * 未设该变量时必须仍是 `6.1.0` —— 这是长期以来的既有行为，
         * 改了会让所有"没传 -k"的场景出现内核版本变化，属无谓回归。
         *
         * 每次调用都 getenv 而不是缓存：uname 不是热路径（正常程序启动
         * 时调几次），而缓存会引入"环境在运行中被改"的一致性问题。
         */
        {
            const char *rel = getenv("BXROOT_KERNEL_RELEASE");
            if (rel == NULL || rel[0] == '\0') {
                rel = "6.1.0";
            }
            UNAME_COPY_FIELD(buf->release, rel);
        }

        UNAME_COPY_FIELD(buf->machine, "aarch64");

        #undef UNAME_COPY_FIELD
    }

    return ret;
}

/* 构造函数：库加载时执行 */
/* ------------------------------------------------------------------ */
/* Hook: libaudit 桩家族（audit_open / audit_close / audit_log_*）      */
/* ------------------------------------------------------------------ */

/*
 * ====================================================================
 * 为什么需要这 5 个符号
 * ====================================================================
 *
 * rootfs 里**大量**程序是动态链接 libaudit.so.1 的，而它们在动态未定义
 * 符号表里引用 audit_*。以 rootfs 为准的实测统计（readelf -sW --dyn-syms）：
 *
 *     usr/bin/passwd  usr/bin/gpasswd  usr/bin/chsh   usr/bin/chfn
 *     usr/bin/chage   usr/bin/login    usr/bin/newgrp usr/bin/lastlog
 *     usr/bin/dbus-daemon              usr/sbin/{faillock,groupadd,
 *     groupdel,groupmod,useradd,userdel,usermod,pam_extrausers_chkpwd,
 *     unix_chkpwd}                     —— 共 20 个程序引用 audit_open
 *
 * ====================================================================
 * 官方把这一族做成了**桩**
 * ====================================================================
 *
 * 反汇编官方 `work/parity/off/libproroot-runtime.so`（符号表给的地址）：
 *
 *   audit_open @0x239ec（48 字节）
 *       239ec: stp  x29, x30, [sp, #-16]!
 *       239f0: mov  w3, #0x0                  ; arg4 = 0
 *       239f4: mov  w2, #0x1                  ; arg3 = 1 == O_WRONLY
 *       239f8: mov  x29, sp
 *       239fc: adrp x1, 0x36000               ; 字符串常量页基址
 *       23a00: add  x1, x1, #0xda8            ; → 0x36da8
 *       23a04: mov  w0, #0xffffff9c           ; AT_FDCWD == -100
 *       23a08: bl   0x27f80                   ; → 内部 syscall(56=openat,...)
 *       23a0c: cmp  w0, #0x0
 *       23a10: csinv w0, w0, wzr, ge
 *       23a14: ldp  x29, x30, [sp], #16
 *       23a18: ret
 *
 *   ★ 0x36da8 处的字符串常量 —— 实测核实过程（不采信任何推断）★
 *       readelf -SW 给出 .rodata vaddr=0x33d10 fileoff=0x33d10（恒等映射），
 *       故 0x36da8 直接对应文件偏移 0x36da8。用 python 读原始字节：
 *           b'/dev/null\x00\x00\x00\x00\x00\x00\x00'
 *       objdump -s -j .rodata 同一位置的 ASCII 转写亦为 `2f6465762f6e756c`
 *       = "/dev/nul" + "l"。**确认为 "/dev/null"**。
 *
 *   ★★ `csinv w0, w0, wzr, ge` 的真实语义 ★★
 *
 *   本文件作者最初的推断是「失败返回 0」。**这个推断是错的**，实测判定如下
 *   （用本机 aarch64 gcc 13.3.0 编译候选 C 表达式，看它生成哪条指令）：
 *
 *       C 表达式                      -O2 生成         与官方是否一致
 *       ----------------------------  ---------------  --------------
 *       return fd >= 0 ? fd : 0;      csel  w0,w0,wzr  ✗（csel，不是 csinv）
 *       return fd >= 0 ? fd : -1;     csinv w0,w0,wzr  ✅ 完全一致
 *       if (fd >= 0) return fd;       csel  w0,w0,wzr  ✗
 *       return 0;
 *
 *   逐条验证命令与原始输出见 docs/audit符号桩实现.md。
 *
 *   原理：`CSINV w0, w0, wzr, ge` = 「条件成立(ge)取 w0；否则取 ~wzr = ~0 = -1」。
 *   即 **成功返回 fd，失败返回 -1** —— 与 C 的 `fd >= 0 ? fd : -1` 等价。
 *
 *   所以官方 audit_open 的语义与**真实 libaudit 一致**（失败回 -1），
 *   唯一与真实 libaudit 不同的是它**不做多路径回退**：真实 libaudit 会依次
 *   尝试 /var/run/auditd.pid 等多个目标，官方只对 `/dev/null` 调一次 openat。
 *
 *   audit_close @0x23a20（40 字节）
 *       23a20: tbz  w0, #31, 23a28        ; fd >= 0 才继续
 *       23a24: ret                        ; fd < 0 → 直接返回
 *       23a28: sxtw x1, w0                ; fd 符号扩展到 64 位
 *       23a2c..23a3c: x2..x6 = 0          ; 其余参数清零
 *       23a40: mov  x0, #0x39             ; 57 == __NR_close
 *       23a44: b    0x8740                ; 尾调用内部 syscall shim
 *
 *   audit_log_acct_message @0x23a48（8 字节）
 *   audit_log_user_command @0x23a50（8 字节）
 *   audit_log_user_message @0x23a60（8 字节）
 *       三者形状完全相同：`mov w0, #1; ret` —— 恒返回 1。
 *       （1 == 真实 libaudit 的 "success"；调用方据此认为审计消息已投递。）
 *
 * ====================================================================
 * bxroot 为什么要逐条照抄
 * ====================================================================
 *
 * 1. **符号存在性**是硬需求。LD_PRELOAD 只能插入**已导出**的符号；这 5 个
 *    符号一旦缺一个，引用它的程序就在符号解析阶段失败，进程根本起不来。
 *    这正是本任务的全部理由。
 *
 * 2. **行为必须逐字节等价**，不是"合理即可"。上面那处 `-1 vs 0` 就是反例：
 *    两者在"打开审计 socket 失败"这一条路径上给出不同返回值，而
 *    `dbus-daemon` 之类的调用方对返回值有分支（它把 0 当"无审计 fd"，
 *    把 -1 当"审计不可用"）。照抄官方 = 与官方跑出同样的分支，
 *    否则就是"bxroot 下能跑但这个程序行为变了"，属于隐性回归。
 *
 * 3. **不能转发给 rootfs 里的真 libaudit.so.1**。实测确认 rootfs 里
 *    `/usr/lib/aarch64-linux-gnu/libaudit.so.1.0.0` **确实导出了**这 5 个
 *    符号（audit_open @0x4314、audit_close @0x4420、…）。但真版本的
 *    audit_open 会**真的去连 netlink 审计套接字**、失败后逐级回退到
 *    `/var/run/auditd.pid` 等真实文件。在 Android 沙箱里那是**副作用**：
 *    既可能拿到一个真的 fd（于是程序真的去写审计日志），也可能因为
 *    内核审计子系统被 selinux 挡住而长时间阻塞。官方选择"发一个
 *    /dev/null 就返回"，本实现照抄 —— 这是**刻意的行为对齐**，
 *    不是偷懒。
 *
 * 4. 注意这三个 log 函数**恒返回 1 而不真发消息**：照抄官方，所以
 *    审计日志在 bxroot 容器里同样是"报告成功但不落盘"。这与官方
 *    完全一致；反过来若我们真去发，就会引入官方没有的副作用。
 *
 * 【实现口径】
 *   audit_open / audit_close 走 `syscall(...)` 而不是 libc 的 `openat()` /
 *   `close()`。理由按重要性排序：
 *
 *   1. **绕开本文件自己的钩子层。** 走 libc 的 `openat()` 会进本文件的
 *      `openat` hook，那条路上叠着 translate_path / bind / l2s / fakeroot
 *      多层逻辑；走 libc 的 `close()` 会进本文件的 `close` hook，
 *      那层带**资源清理记账**（l2s / 座位 / netlink 的 on_close）——
 *      都不是官方 audit 桩的行为。官方这里是裸 `svc #0`，
 *      照抄 raw 是与官方对齐最短、最没有意外的路径。
 *
 *   2. **顺带与官方的错误路径一致。** 官方 shim 在 `cmn x20,#0xfff`
 *      判出负 errno 后跳到 0x8908，那里
 *      `bl __errno_location; neg w1,w20; str w1,[x0]; x20 = -1`
 *      —— 即**官方同样设置 errno 并返回 -1**。
 *      实测两侧一致：fd 耗尽时都是 `= -1 errno=24`。
 *      （`-ENOSYS` 走 0x8924 的另一条分支，本桩不涉及。）
 *
 *   实测澄清（避免后人误判）：`syscall()` 垫片对 **56/57 两个号是透传** ——
 *   56 虽然在 `path_arg_mask` 表里（`case 56: return 1u << 1`）会触发路径
 *   翻译，但 `translate_path()` 对 `/dev` 前缀有**透传特例**
 *   （源码里 `special[] = {"/proc","/sys","/dev"}` 那段），
 *   所以 "/dev/null" 翻译前后都是 "/dev/null"。实测两条路都落到真 /dev/null：
 *
 *       syscall(openat,AT_FDCWD,"/dev/null",O_WRONLY) = 11 → /dev/null
 *       openat() via libc                            = 12 → /dev/null
 *
 *   也就是说：**即使这里改用 libc，`/dev/null` 本身也不会被翻错**；
 *   真正让 raw syscall 成为正确选择的是上面的理由 1（绕开记账层），
 *   而不是"路径会被翻坏"。
 */
int audit_open(const char *path, int flags, int mode)
{
    /*
     * 参数名与真实 libaudit 对齐（libaudit.h: `int audit_open(const char *path)`），
     * 但官方桩**只认第一个参数**：flags 被硬编码成 O_WRONLY、mode 硬编码 0，
     * 路径被硬编码成 "/dev/null"。所以这里显式忽略后两个入参 ——
     * 这是照抄官方，不是为了省事。
     */
    (void)flags;
    (void)mode;
    (void)path;   /* 官方同样忽略调用方给的 path */

    long fd = syscall(SYS_openat, AT_FDCWD, "/dev/null", O_WRONLY, 0);

    /*
     * 与官方 `csinv w0, w0, wzr, ge` 逐位等价：fd >= 0 保留，否则 -1。
     * 写成 `fd >= 0 ? (int)fd : -1` 而不是 `fd < 0 ? -1 : (int)fd`，
     * 是为了让 gcc 生成同一条 csinv（见文件上方注释里的编译验证）。
     */
    return (int)(fd >= 0 ? fd : -1);
}

/*
 * audit_close：fd < 0 直接返回（官方 `tbz w0, #31`），否则 close(fd)。
 *
 * 官方是**尾调用**（`b 0x8740` 而不是 `bl`），即不复用返回地址、
 * 自身不产生栈帧 —— 语义上完全等价于 `close(fd); return;`。
 * 这里同样用 raw syscall：走 libc 的 close 会进本文件的 close hook，
 * 而那层带资源清理记账，既非官方行为也带来无谓开销。
 */
void audit_close(int fd)
{
    if (fd < 0)
        return;
    syscall(SYS_close, fd);
}

/*
 * 三个 log 函数：恒返回 1，不看任何入参、不产生任何副作用。
 * 官方三个桩的机器码完全一样（`mov w0, #1; ret`），这里也保持参数
 * 全忽略 —— 用可变参数/固定参数都无所谓，因为一个都不会被读。
 */
int audit_log_acct_message(int type, int pid, const char *user,
                           const char *operation, const char *acct,
                           int result, const char *hostname, ...)
{
    (void)type; (void)pid; (void)user; (void)operation;
    (void)acct; (void)result; (void)hostname;
    return 1;
}

int audit_log_user_command(int type, int pid, const char *cmd,
                           int result, const char *hostname, int tbl)
{
    (void)type; (void)pid; (void)cmd; (void)result; (void)hostname; (void)tbl;
    return 1;
}

int audit_log_user_message(int type, int pid, const char *message,
                           const char *hostname, const char *addr,
                           const char *tty, int result)
{
    (void)type; (void)pid; (void)message; (void)hostname;
    (void)addr; (void)tty; (void)result;
    return 1;
}

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
/*
 * 真正启用 l2s 的核心。init_l2s()（构造期，读环境变量）与
 * link()/linkat() 的"自动回退"（见两处钩子内的注释）共用这一段，
 * 保证两种启用方式的配置语义**完全一致** —— 这正是
 * "同一套规则不写两处"的落点。
 */
static void l2s_enable_core(void) {
    l2s_config cfg;

    cfg = (l2s_config)L2S_CONFIG_DEFAULT;
    /*
     * 集中目录布局。DSHA 生产走这条路径（PROOT_L2S_DIR）。
     * 不设时留在 NULL，中间层会生成在客户文件旁边。
     */
    cfg.l2s_dir = getenv("BXROOT_L2S_DIR");
    if (cfg.l2s_dir != NULL && cfg.l2s_dir[0] == '\0')
        cfg.l2s_dir = NULL;

    /*
     * ★ 集中目录必须存在，否则 l2s 会**静默失效** —— 所以这里自建 ★
     *
     * 【实测缺陷（2026-09-17，由 RUN_L2S_E2E.sh 变红暴露）】
     *
     * 把 BXROOT_L2S_DIR 指向一个**不存在**的目录时，l2s 不是报错也不是
     * 回退到散落布局，而是**整条链失效**：
     *
     *     link(a, b)  → 失败
     *     stat(a)     → nlink=1（伪装没生效）
     *     客户的 link() 调用直接 ENOENT
     *
     * 原因：`l2s_make_paths_ex()` 只按 l2s_dir 拼中间层路径，不去建它；
     * 真正创建中间层的那次 symlink/rename 落在不存在的目录里 → ENOENT。
     * 而且 link() 返回失败时**没有明确指向"目录不存在"**，排查者会以为
     * 是 l2s 本身坏了。
     *
     * 【为什么必须在这里建，而不是指望调用方】
     *
     * launcher 会默认设 `BXROOT_L2S_DIR=<rootfs>/.l2s`（launcher.c:999），
     * **但它自己不建那个目录** —— 生产环境靠 DSHA 的 Java 侧
     * `l2s.mkdirs()`（ContainerRuntime.java）兜底。于是：
     *
     *     经 DSHA 启动   : 目录已由 Java 建好 → 正常
     *     经 launcher 直启: 目录不存在       → 静默失效   ❌
     *     测试脚本直调 bridge: 同上           → 静默失效   ❌
     *
     * 三条入口里两条是坏的，且坏得无声无息。运行时是**唯一**知道
     * l2s_dir 会被真正用到的地方，由它保证目录存在最可靠。
     *
     * 【为什么不是"目录不存在就报错退出"】
     *
     * 那会让"用户配错一个路径"升级成"整个容器起不来"。建一个目录是
     * 无副作用的幂等操作（EEXIST 直接忽略），比中断启动合理。
     *
     * 【为什么不是"回退到散落布局"】
     *
     * 散落布局会把 `.l2s.*` 中间文件撒进客户的目录，客户 `ls -a` /
     * `tar .` 全都能看到（见 docs/两处控制实验缺陷更正.md）。生产
     * 已经明确选择集中布局，回退等于悄悄改变了用户可见行为。
     *
     * 用 syscall 直接调 mkdir（构造函数阶段 dlsym 尚不可用，且现在
     * 正处于 ensure_real_functions 之前的窗口）。EEXIST 视为成功。
     */
    if (cfg.l2s_dir != NULL) {
        char mkdir_path[MAX_PATH_LEN];
        const char *target = cfg.l2s_dir;

        /*
         * 集中目录在 rootfs 内时要做正向翻译 —— 否则会把目录建到
         * 宿主视角的路径上（容器视角与内核视角的经典分歧）。
         * 翻译失败就退回原样：宁可在原路径上建，也不要什么都不建。
         */
        if (translate_path(cfg.l2s_dir, mkdir_path, sizeof(mkdir_path)) > 0)
            target = mkdir_path;

        /*
         * 用 `mkdirat` 而不是 `mkdir`：**aarch64 上没有 mkdir 系统调用**，
         * 只有 mkdirat（`SYS_mkdir` 在此平台未定义，实测编译报
         * "'SYS_mkdir' undeclared; did you mean 'SYS_mkdirat'?"）。
         * 这正是本项目反复出现的"同一功能在不同路径上覆盖不全"的又一例 ——
         * x86_64 上两种都有，照搬那边的写法在这里编不过。
         */
        if (syscall(SYS_mkdirat, AT_FDCWD, target, 0700) < 0 && errno != EEXIST) {
            /*
             * 建不出来就**明确说出来**。静默失效正是本缺陷最难查的地方：
             * 用户看到的是"link() 莫名其妙失败"，而不是"目录建不出来"。
             */
            LOG("l2s: 无法创建集中目录 %s: %s —— link() 将失效",
                target, strerror(errno));
        }
    }

    /*
     * 用 bxroot 方案（哈希键控元数据树 + .cnt 旁路计数），而不是
     * proot 的「链接数编进文件名」方案。
     *
     * 这不是偏好，是必须：proot 方案每次加链长都要 rename 数据文件，
     * 而参考实现 运行时的路径缓存在目标改名后会失效，导致已打开过
     * 的路径永久 ENOENT。详见
     * agents/_shared/官方运行时缺陷-符号链接改名后失效.md。
     */
    cfg.scheme = L2S_SCHEME_PROROOT;

    l2s_rt_init(&L2S_OPS, &cfg);
    LOG("l2s enabled: dir=%s", cfg.l2s_dir ? cfg.l2s_dir : "(beside file)");
}

/*
 * 构造期入口：读环境变量决定是否启用。
 *
 * 注意这里**只**负责"显式开关"路径；"自动回退"路径由 link()/linkat()
 * 钩子在真实调用失败后调用 l2s_enable_core() 完成。
 */
static void init_l2s(void) {
    const char *on = getenv("BXROOT_LINK2SYMLINK");

    /*
     * -L 的开关独立于 l2s：proot 的 -L 与 --link2symlink 是两个各自
     * 独立的选项，可以只开一个。所以这一行放在下面的提前 return **之前**。
     */
    {
        const char *fss = getenv("BXROOT_FIX_SYMLINK_SIZE");
        g_fix_symlink_size = (fss != NULL && fss[0] != '\0' && fss[0] != '0');
    }

    if (on == NULL || on[0] == '\0' || on[0] == '0') {
        LOG("l2s not enabled by env (link() 失败时会自动回退启用)");
        return;
    }

    l2s_enable_core();
}

static int l2s_autostart_on_link_failure(void) {
    if (l2s_rt_enabled())
        return 1;                       /* 已经启用 */
    LOG("link() 被内核拒绝 —— 自动启用 l2s（与参考实现 行为对齐）");
    l2s_enable_core();
    return l2s_rt_enabled();
}

/*
 * ★ link 自动回退启用（2026-09-17）★
 *
 * 【实测差异】本容器里 宿主 loader 的 seccomp 过滤器**禁止 linkat(265)**：
 *     官方  : 裸 svc linkat = -38 (ENOSYS)，但 link() 符号返回成功
 *             ——官方运行时在用户态模拟了 link（磁盘上留下的是真实文件，
 *             两个路径各一份，用复写实现，不是符号链接）
 *     bxroot: link() 透传到被禁的 linkat → EACCES，pnpm/npm 全挂
 *
 * 【为什么不能只在显式开关时启用 l2s】
 * DSHA 生产走 --link2symlink 没问题；但"直接经 bridge 跑一个没带开关的
 * 客户"（测试探针、用户手敲命令）link() 必失败。官方在**同样的环境**
 * 下不需要开关就成功 —— 所以 bxroot 也应当自动启用，否则就是与官方
 * 的可观测行为差异。
 *
 * 【为什么放在钩子里而不是构造函数】
 * 构造期无法预知"内核是否真的禁了 linkat"（那是 ldso 装的过滤器，
 * bxroot 读不到它的白名单）。只有真实调用失败才是权威信号。
 *
 * 【幂等】l2s_enable_core() 里 l2s_rt_init 可重复调用；g_enabled 置位后
 * l2s_rt_enabled() 为真，后续 link() 直接走 l2s 分支，不再回到这里。
 */


__attribute__((constructor))
static void constructor(void) {
    /*
     * BXROOT_NO_AUTORUN=1：静态链接本库（源码级单元测试等）时的逃生门。
     * 完整跳过构造链 —— 单元探针只需要内部纯函数（如 readlink_fixup），
     * 不需要 hook 安装/livepatch/崩溃处理器。正常运行时勿设。
     */
    if (getenv("BXROOT_NO_AUTORUN") != NULL)
        return;

    init_config();
    init_l2s();
    init_fakeroot();

    /*
     * ★ SIGPIPE 复位兜底（上游同等处理，评估报告 D5）★
     *
     * SIG_IGN 跨 fork/exec 存活：Android zygote 留下的 SIGPIPE=SIG_IGN
     * 会让 guest 里 `yes | head -1` 打印 "Broken pipe" 而不是被静默杀死，
     * 破坏脚本对管道退出的判断（PIPESTATUS 期望 141）。
     *
     * launcher 的 execve 前已复位一次；这里再兜一次，覆盖
     * "经 bridge 链直接加载 runtime、绕过 launcher" 的路径。
     * 上游在 src/tracee/event.c:111 做同样的事。
     */
    signal(SIGPIPE, SIG_DFL);

    /*
     * 崩溃现场捕获。
     *
     * 参考实现 有一个 3116 字节的 SIGSEGV 处理器（还配 340 字节的
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
     * 为什么必须有：宿主 loader 用 seccomp 以 KILL_PROCESS 方式禁止
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
     * 否则 kill(getpid(), ...) 会被我们**自己的**白名单拒绝
     * （shell 的自杀、node 的 process.kill(pid,0) 探活都会踩到）。
     *
     * ★ 2026-09-17 更正 ★
     * 这里原先接着说「而 getpid 在 fakeroot 下被伪装成 1，所以这个自伤
     * 场景在容器里是常态而不是边缘情况」。那句话描述的**不是依赖，而
     * 正是缺陷本身**：当时 getpid 钩子在 fakeroot 下返回 1，于是
     * kill(getpid()) 打到 pid 1 → 被 D4 白名单当容器外进程拒绝，
     * 才不得不靠这道登记来绕开。getpid 钩子已删除（见其原址处的长注释），
     * getpid() 现在返回真实 pid，命中 px_check_kill 的 protect_self
     * 分支即可放行。
     *
     * 这道登记**保留不动**：真实 pid 下它依然正确（把自己记进账本本就
     * 是应有的行为），且删除它对本轮缺陷没有任何收益、只有回归风险。
     */
    px_runtime_register_self();

    bxroot_crash_install("bxroot");
    LOG("runtime library loaded");

    /*
     * ================================================================
     * 工作目录：**只在容器首个进程生效**，不要每次 exec 都重置
     * ================================================================
     *
     * 【缺陷（实测，2026-09-16）】
     *
     * `BXROOT_WORKDIR` 表达的是「容器启动时把 cwd 设到哪里」。但本构造
     * 函数在**每个**加载了本 .so 的进程里都会跑 —— 包括客户 fork/exec
     * 出来的每一个子进程。于是子进程一启动就把 cwd 重置回 workdir，
     * **父进程的 cwd 变更全部丢失**。
     *
     * 实测（/root/fsize/cdinherit.c，父 chdir("/tmp") 后 fork+exec /bin/pwd）：
     *     官方  : 父 getcwd=/tmp  子 getcwd=/tmp  /bin/pwd → /tmp   ✅
     *     bxroot: 父 getcwd=/tmp  子 getcwd=/tmp  /bin/pwd → /       ❌
     *
     * 注意"子进程 getcwd"那一步是**对的** —— 因为子进程在 exec 前用的是
     * 父进程已经加载好的 .so，构造函数已经跑完了。真正出错的是 exec 之
     * 后：新进程重新加载 .so，构造函数把 cwd 重置成了 workdir。
     *
     * 【真实后果（shell 里最明显）】
     *     cd /tmp/d; ls      → 列出的是 **rootfs 根**（bin boot data ...）
     *     stat ./a           → ENOENT
     * 而 `pwd`（dash 内建，用自己的记账）看上去是对的 —— 所以现象是
     * "pwd 对但 ls 错"，极易误判成 getcwd 的问题。
     *
     * 【修法】
     * 用一个环境变量标记"首进程已经设过工作目录了"。环境变量会被
     * fork/exec 继承，正是我们需要的"跨 exec 传递"语义：
     *     首个进程（launcher 起的）：没有标记 → 设 cwd → 打标记
     *     子进程（exec 出来的）：有标记 → **不动 cwd**（继承父进程的）
     *
     * 这与参考实现一致：proot 只在启动 tracee 时应用 -w，不会在每次
     * execve 时重置子进程的工作目录。
     */
    if (g_config.workdir && getenv(BXROOT_WORKDIR_DONE_ENV) == NULL) {
        char translated[MAX_PATH_LEN];
        const char *target = NULL;

        if (translate_path(g_config.workdir, translated, sizeof(translated)) > 0) {
            LOG("workdir: %s -> %s", g_config.workdir, translated);
            target = translated;
        } else {
            target = g_config.workdir;
        }

        /* 使用 syscall 直接调用 chdir（ctor 中 dlsym 不可用） */
        long ret = syscall(SYS_chdir, target);
        if (ret < 0) {
            LOG("workdir chdir failed: %s", strerror(errno));
        } else {
            LOG("workdir chdir OK");
            /*
             * 打标记。放在成功之后：若 chdir 失败（workdir 不存在），
             * 下次 exec 仍会再试一次 —— 那时目录可能已经建好了。
             * 注意 libc 的 setenv 在本阶段可用（它不依赖 dlsym）。
             */
            setenv(BXROOT_WORKDIR_DONE_ENV, "1", 1);
        }
    }
}

/* ------------------------------------------------------------------ */
/* 给 syscall_guard.c 的身份查询入口                                   */
/*                                                                    */
/* ★ 本段是**纯追加**：不改动本文件上方任何既有逻辑 ★                 */
/* ------------------------------------------------------------------ */

/*
 * ★ 为什么需要这个函数 ★
 *
 * fakeroot 的伪装此前只在 **libc 符号层**生效（getuid/geteuid/getgid/
 * getegid/getresuid/getresgid/getgroups 这几个钩子）。而 `syscall_guard.c`
 * 的 `syscall()` 接管层只做了"路径翻译"和"statx 结果补丁"，没有身份那
 * 一半 —— 于是绕过 libc 直接 `syscall(174)` 的程序看到的是**真实 uid**。
 *
 * 实测（三层探针，详见 docs/裸syscall身份伪造修复.md）：
 *
 *     官方 : libc getuid=0   syscall(174)=0        ← 伪造覆盖到 syscall() 符号层
 *     bxroot(修前): libc getuid=0   syscall(174)=10655   ← 只到 libc 符号层
 *
 * syscall_guard.c 是**独立编译单元**（单独链进 test_syscall_argpos.c /
 * test_rename_link_argpos.c，那两个测试不链本文件），所以它对本函数的
 * 声明必须是 `__attribute__((weak))`，未链接本文件时解析为 NULL 并跳过。
 *
 * ★ 为什么不直接让 guard 读 getuid() ★
 * guard 的职责是"拦在 libc 之前"，它自己去调 libc 的 getuid() 会把符号层
 * 钩子重新卷进调用链 —— 而且那两个既有测试不链 preload.c，会立刻链接
 * 失败。查询状态必须走这个显式的、可 weak 解析的入口。
 *
 * ★ 为什么返回"两个出参 + 返回值"而不是只返回 bool ★
 * 伪造身份当前恒为 0/0（见 fakeroot_state_set_enabled），但**判据属于
 * fakeroot 层**，不该在这里或 guard 里复制一份"假身份就是 0"的假设 ——
 * 那正是本文件注释反复警告的"同一套规则写两处，两边迟早漂移"。
 * 所以这里把 fakeroot 状态里的 uid/gid 原样交出去，guard 只负责搬运。
 */
int bxroot_fakeroot_ids(unsigned int *uid, unsigned int *gid)
{
    /*
     * 与 preload.c 的 getuid/getgid 钩子用**同一个**判据（g_fakeroot_on），
     * 不是 g_config.fakeroot：init_fakeroot() 在记账表创建失败时会整体
     * 关掉 fakeroot（半残的 fakeroot 比没有更危险，见那里的注释）。
     * 若这里改用 g_config.fakeroot，就会出现"符号层不伪装、裸 syscall 层
     * 伪装"的新矛盾 —— 与本次要修的缺陷方向相反、更难查。
     */
    if (!g_fakeroot_on)
        return 0;

    if (uid != NULL) *uid = (unsigned int)g_fakeroot_state.ruid;
    if (gid != NULL) *gid = (unsigned int)g_fakeroot_state.rgid;
    return 1;
}

/*
 * 缺口 B 的两个入口 —— 给 syscall_guard.c 的 `syscall(148/150/158)` 用。
 *
 * 【为什么不复用上面的单值入口】
 *
 * `getresuid` 要写**三个各不相同**的值，`getgroups` 要写**一整个数组**。
 * 用 bxroot_fakeroot_ids 填三个字段会让 getgid 也拿到 uid 的值 ——
 * 本项目刚在 statx 的 stx_mode 宽度、fakeroot 初始化顺序上踩过
 * "同一套规则写两处、两边漂移"。所以**并列新增**，不改旧的。
 *
 * 【取值来源与符号层钩子完全同源】
 *
 * 与上面 getresuid/getresgid/getgroups 三个**符号钩子**读的是同一份
 * g_fakeroot_state 字段。这是硬要求：符号层与 syscall 层若各读一处，
 * 就会出现"同一个程序用两种方式问出两个不同答案"—— 正是本轮要消灭的
 * 那类缺陷。
 */
int bxroot_fakeroot_res_ids(unsigned int *ruid, unsigned int *euid,
                            unsigned int *suid, unsigned int *rgid,
                            unsigned int *egid, unsigned int *sgid)
{
    if (!g_fakeroot_on)
        return 0;

    if (ruid != NULL) *ruid = (unsigned int)g_fakeroot_state.ruid;
    if (euid != NULL) *euid = (unsigned int)g_fakeroot_state.euid;
    if (suid != NULL) *suid = (unsigned int)g_fakeroot_state.suid;
    if (rgid != NULL) *rgid = (unsigned int)g_fakeroot_state.rgid;
    if (egid != NULL) *egid = (unsigned int)g_fakeroot_state.egid;
    if (sgid != NULL) *sgid = (unsigned int)g_fakeroot_state.sgid;
    return 1;
}

/*
 * getgroups 的伪造组表。
 *
 * `groups == NULL` 或 `cap <= 0` → 只回数量（写 `*count`）。
 * 否则把组表填进 `groups`（最多 `cap` 个），`*count` 是**真实组数**。
 *
 * ★ `*count` 恒为真实组数，不因 cap 不足而截断 ★
 * 因为调用方（syscall_guard）要据此判断"容量够不够"并按内核语义回
 * EINVAL。若这里返回截断后的数量，guard 就无法区分"组本来就这么少"
 * 与"客户缓冲区太小"—— 那会让 `getgroups(1, buf)` 静默返回 1 而不是
 * EINVAL，与内核行为不符（实测内核回 -22）。
 */
int bxroot_fakeroot_groups(unsigned int *groups, int cap, int *count)
{
    int n;
    int k;

    if (!g_fakeroot_on)
        return 0;

    n = g_fakeroot_state.ngroups;
    if (n < 0)
        n = 0;
    if (count != NULL)
        *count = n;
    if (groups != NULL && cap > 0) {
        for (k = 0; k < n && k < cap; k++)
            groups[k] = (unsigned int)g_fakeroot_state.groups[k];
    }
    return 1;
}

/*
 * ==================================================================
 * 缺口 C：裸 syscall 层的身份变更桥（setuid/setgid/setgroups/...）
 * ==================================================================
 *
 * 【为什么需要它】
 *
 * preload.c 的 getuid/getresuid/... 是**符号层**查询钩子；
 * fakeroot.c 的 setuid/setgid/... 是**符号层**变更钩子 —— 但那一层被
 * `-DFAKEROOT_PURE_LOGIC` **排除在运行时之外**（BUILD_RUNTIME.sh:92），
 * 所以运行时里根本没有符号层的 setter。程序若绕过 libc 直接发
 * `syscall(144 setgid, ...)`（静态链接的 Go/Rust、安全自检代码），
 * 就完全碰不到任何拦截：
 *
 *     官方 : syscall(144) = 0，且**账本被更新**（回读 getuid 变成新值）
 *     bxroot(修前): syscall(144) = -38 (ENOSYS，sigsys.c 统一回绝)
 *
 * 现场后果（实测）：`chage -l root` 官方 rc=0、bxroot rc=1
 * （`failed to drop privileges (Function not implemented)`）。
 *
 * 【为什么不"让这几个号直接返回 0"】
 *
 * 实测官方**有用户态身份账本** —— setter 生效后回读 getter 会变：
 *
 *     ########## 官方 ##########            ########## bxroot ##########
 *     BEFORE: getuid=0 getgid=0              BEFORE: getuid=0 getgid=0
 *     setgid(999) rc=0  setuid(999) rc=0     setgid(999) rc=-1 errno=38
 *     AFTER : getuid=999 getgid=999          AFTER : getuid=0 getgid=0
 *
 * 只返回 0 会让程序看到**自相矛盾**的世界（"降权成功"但回读仍是原身份），
 * 比报错更难查。所以这里复用 fakeroot 的**纯逻辑** setter
 * （fakeroot_setuid/setgid/setgroups…），它们已经在维护账本。
 *
 * 【op 为什么用数字】
 * `syscall_guard.c` 是独立编译单元（会被 test_syscall_argpos.c 单独链接），
 * 拖进 fakeroot.h 会引入一堆依赖。用数字让两侧只共享一个约定，
 * 不必各自定义枚举（本项目在号码表上出过两次事故）。
 *   1=setuid 2=setgid 3=setreuid 4=setregid 5=setresuid
 *   6=setresgid 7=setgroups 8=setfsuid 9=setfsgid
 *
 * 【★ 真实性副作用，必须写清 ★】
 * 这些调用"成功"后内核身份**没有**真的改变。对 `chage`/`passwd` 这类
 * 工具，这意味着它们会跳过后续权限检查却仍以原身份执行 —— 这是
 * **与官方一致**，不是"正确"。官方就是这么做的（实测 9 个 setter 全返回 0）。
 */
int bxroot_fakeroot_setter(int op, unsigned long a0, unsigned long a1,
                           unsigned long a2, long *out_ret, int *out_errno)
{
    int rc;

    if (out_ret != NULL)   *out_ret = 0;
    if (out_errno != NULL) *out_errno = 0;

    if (!g_fakeroot_on)
        return 0;               /* 未启用：guard 必须原样透传 */

    switch (op) {
    case 1:  rc = fakeroot_setuid (&g_fakeroot_state, (uid_t)a0);             break;
    case 2:  rc = fakeroot_setgid (&g_fakeroot_state, (gid_t)a0);             break;
    case 3:  rc = fakeroot_setreuid(&g_fakeroot_state, (uid_t)a0, (uid_t)a1); break;
    case 4:  rc = fakeroot_setregid(&g_fakeroot_state, (gid_t)a0, (gid_t)a1); break;
    case 5:  rc = fakeroot_setresuid(&g_fakeroot_state, (uid_t)a0, (uid_t)a1,
                                     (uid_t)a2);                             break;
    case 6:  rc = fakeroot_setresgid(&g_fakeroot_state, (gid_t)a0, (gid_t)a1,
                                     (gid_t)a2);                             break;
    case 7:
        /*
         * setgroups(n, list)：n == 0 且 list == NULL 表示清空。
         *
         * ★ 上限校验是必须的 ★
         * 客户传的 list 是我们要**读**的指针。n 超过 FR_NGROUPS_MAX 时
         * 按内核语义回 EINVAL（实测内核也是 EINVAL，不是截断），
         * 既避免读越界，也与内核行为一致。
         *
         * ★★ 为什么这里**绕过** fakeroot_setgroups 的 CAP_SETGID 闸门 ★★
         *
         * 【实测差异（2026-09-17）】
         * fakeroot_setgroups() 带一条权限闸门：
         *     if (!(fs->euid == 0 || fs->caps_active)) return FR_EPERM;
         * 于是 `setuid(999)` 之后再 `setgroups` 会得到 EPERM。而**官方允许**：
         *
         *     官方 : setuid(999) -> 999/999/999，然后 setgroups rc=0
         *     bxroot(修前): 同样状态，setgroups rc=-1 EPERM   ← 不一致
         *
         * 【上游 参考实现 的做法】
         * `src/extension/fake_id0/fake_id0.c:1011-1017` 对 setgroups 是
         * **无条件** `poke_reg(tracee, SYSARG_RESULT, 0)` —— 注释写着
         * "TODO: need to really emulate"，即**根本没做权限检查**，
         * 一律"假装成功"。
         *
         * 【为什么不改 fakeroot_setgroups() 本身】
         * 那条闸门是**纯逻辑层**的既有行为，`test_fakeroot` 有断言钉着它
         * （fake_id0.c:112 的 `allowed = ...` 模型）。改它会让纯逻辑测试
         * 与 参考实现 的 setuid 族语义脱钩。所以**只在本桥接层**放宽：
         * 桥接的职责就是"让 syscall 层与官方可观测行为一致"。
         *
         * 【为什么这是安全的】
         * fakeroot 本来就是"假装" —— 内核身份并未改变。官方把这条做成
         * 无条件成功，我们跟它，可观测行为才一致。
         */
        if (a0 > (unsigned long)FR_NGROUPS_MAX) {
            rc = FR_EINVAL;
        } else {
            size_t n = (size_t)a0;
            const gid_t *list = (n == 0) ? NULL
                                         : (const gid_t *)(uintptr_t)a1;
            size_t i;

            if (n > 0 && list == NULL) {
                rc = FR_EINVAL;
            } else {
                for (i = 0; i < n; i++)
                    g_fakeroot_state.groups[i] = list[i];
                g_fakeroot_state.ngroups = (int)n;
                rc = FR_OK;
            }
        }
        break;
    case 8:
        /* setfsuid 返回**旧值**（man 明确），不是 0 */
        if (out_ret != NULL)
            *out_ret = (long)fakeroot_setfsuid(&g_fakeroot_state, (uid_t)a0);
        return 1;
    case 9:
        if (out_ret != NULL)
            *out_ret = (long)fakeroot_setfsgid(&g_fakeroot_state, (gid_t)a0);
        return 1;
    default:
        /*
         * 未知 op：**不能**假装成功 —— 那等于对一张没定义的表给出"成功"。
         * 返回 -1 让 guard 原样透传（由内核报出真实错误）。
         */
        return -1;
    }

    if (rc != FR_OK) {
        if (out_errno != NULL)
            *out_errno = (rc == FR_EINVAL) ? EINVAL : EPERM;
        if (out_ret != NULL)
            *out_ret = -1;
        return 1;
    }
    return 1;
}
