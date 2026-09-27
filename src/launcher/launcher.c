/*
 * libbxroot.so 入口 launcher
 *
 * 解析 CLI 参数，设置环境变量，设置 LD_PRELOAD，execve guest 程序。
 * libbxroot.so / bxroot。
 * 入口库。
 *
 * 用法:
 *   bxroot [options] <command> [args...]
 *
 * 选项:
 *   -r <rootfs>          rootfs 路径 (必须)
 *   -w <dir>             工作目录 (默认 /)
 *   -b <host>:<guest>    bind mount (可多次)
 *   -0                   fakeroot 模式
 *   -v / --verbose       调试模式
 *   -h / --help          帮助
 */

#ifndef _GNU_SOURCE   /* Makefile 已用 -D_GNU_SOURCE 定义；单独编译时仍需要 */
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>   /* signal(SIGPIPE, SIG_DFL)：见 execve 前的说明 */
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <limits.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>

/*
 * ★ 早期 SIGSYS 处理器（2026-09-27 真机新增）★
 * launcher 是静态 glibc 程序：Android app 沙箱里它在 main 之前就会因
 * set_robust_list 被 seccomp TRAP 杀掉（Termux 实测 `bxroot -V` rc=159）。
 * 链接时须 `-Wl,-e,bx_early_start`，详见该头文件。
 */
#include "../ldr/early_sigsys.h"

/*
 * 版本号。
 *
 * 用 `-V` / `--version` 打印。参考实现用 `-V`（大写），
 * 与 `-v`（verbose）**只差大小写但语义完全不同** —— 这是
 * 既有设计，兼容层必须照做，不能"统一"成同一个小写选项。
 */
#ifndef BXROOT_VERSION
#define BXROOT_VERSION "0.1.4"
#endif

/*
 * 最大 bind mount 数量。
 *
 * 从 16 提到 48：参考实现的 `-R` 别名一次会加 **18 条** bind（见
 * PROOT_RECOMMENDED_BINDS），若上限仍是 16，`-R` 必然在中途失败。
 * 这是"兼容性不能只加选项名、还要够容量"的一个实例 ——
 * 只把 `-R` 认下来却让它因容量不足而半途报错，比不支持更糟。
 */
#define MAX_BINDS 48

/* 默认 rootfs */
#ifndef BXROOT_DEFAULT_ROOTFS
#define BXROOT_DEFAULT_ROOTFS "/data/local/tmp/rootfs"
#endif

/*
 * ===================================================================
 * `-R` / `-S` 的推荐 bind 清单（与参考实现兼容）
 * ===================================================================
 *
 * 这两份清单**与参考实现保持一致**（其 CLI 定义中
 * `recommended_bindings[]` 与 `recommended_su_bindings[]`），
 * 不是我自己归纳的 —— 兼容性判断必须以对方源码为准。
 *
 * 【为什么必须抄准】
 * `-R` 的语义是"`-r <path>` + 一组推荐 bind"，用户之所以用它，正是
 * 为了少写十几条 `-b`。清单少一条、或路径写错，表现是"程序在容器里
 * 读不到 /etc/resolv.conf 之类"，而错误现场离原因很远（DNS 失败、
 * 用户名显示成 uid）。所以这里逐字对齐。
 *
 * 【`*path*` 与 `$HOME` 是占位符，不是字面路径】
 *   `*path*` —— 替换为 `-r` 给的 rootfs 路径（即"把 rootfs 自己
 *               也 bind 到自身"，用于让 guest 内路径自洽）
 *   `$HOME`  —— 替换为环境变量 HOME 的值，为空则**跳过该条**
 * 解析时按此展开。
 *
 * 【路径不存在的处理】
 * 参考实现对不存在的路径是**警告后跳过**，不是失败。
 * 这里同样处理 —— 因为推荐清单里包含 `/var/run/dbus/system_bus_socket`
 * 这类在精简系统上本来就没有的东西，若因它失败则 `-R` 在多数环境下
 * 直接不可用。
 */
static const char *const PROOT_RECOMMENDED_BINDS[] = {
    "/etc/host.conf",
    "/etc/hosts",
    "/etc/hosts.equiv",
    "/etc/mtab",
    "/etc/netgroup",
    "/etc/networks",
    "/etc/passwd",
    "/etc/group",
    "/etc/nsswitch.conf",
    "/etc/resolv.conf",
    "/etc/localtime",
    "/dev/",
    "/sys/",
    "/proc/",
    "/tmp/",
    "/run/",
    "/var/run/dbus/system_bus_socket",
    /* 参考实现里被注释掉的一条，此处同样不启用：
     *   /var/tmp/kdecache-$LOGNAME */
    "$HOME",
    "*path*",
    NULL,
};

/*
 * `-S` 的清单。注释说明它用于"安全地在 guest 里装包"：
 * 比 `-R` 少绑定若干**可能被 guest 意外改动**的宿主文件
 * （如 /etc/passwd、/etc/group、/run/ 整个目录），
 * 并且**隐含 `-0`**（fakeroot）。
 */
static const char *const PROOT_SU_BINDS[] = {
    "/etc/host.conf",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/resolv.conf",
    "/dev/",
    "/sys/",
    "/proc/",
    "/tmp/",
    "/run/shm",
    "$HOME",
    "*path*",
    NULL,
};

/* runtime 库文件名（相对于本程序 dirname） */
#define LIBBXROOT_RUNTIME "libbxroot-runtime.so"
#define LIBBXROOT_LINKER "libbxroot-linker.so"
#define LIBBXROOT_STUB_LOADER "libbxroot-stub-loader.so"
#define LIBBXROOT_ULX "libbxroot-ulx.so"

/* 配置结构 */
typedef struct {
    char *rootfs;
    char *workdir;
    char *guest_exe;
    char **guest_argv;
    int guest_argc;
    char *binds[2 * MAX_BINDS]; /* [src, dst, src, dst, ...] */
    int bind_readonly[MAX_BINDS]; /* 平行数组：该 bind 是否只读（-b h:g:ro） */
    int bind_count;
    int fakeroot;
    int verbose;
    /*
     * quiet：上游 `-v <负数>` 的语义（cli/note.c:54）——
     * verbose_level < 0 时**压制除 ERROR 外的一切输出**。
     * 上游用例用它让容器输出与宿主逐字节一致（如 test-dddddddd 的 cmp）。
     * 我们据此静默所有 [bxroot-launcher]/[bxroot] 诊断信息。
     */
    int quiet;
    int link2symlink;
    /*
     * CLI 兼容字段。
     *
     * `kill_on_exit`：`--kill-on-exit`，退出时杀光容器内进程。
     *   语义：`killall_on_exit = true`。
     * `kernel_release`：`-k/--kernel-release`，伪造 uname 的
     *   release 字段。经 BXROOT_KERNEL_RELEASE 交给运行时 uname 钩子
     *   改写 buf->release（见 preload.c 的 uname 钩子）。
     */
    int kill_on_exit;
    char *kernel_release;
    /*
     * `-L`：参考实现的 fix_symlink_size 语义开关。默认 0（与参考实现一致）。
     * 语义见解析处的长注释 —— 它修的是**真符号链接**的 st_size，
     * 与 l2s 的 size 补丁是两件独立的事。
     */
    int fix_symlink_size;
    int change_id_set;      /* -i/--change-id 是否被显式指定 */
    /*
     * `-i <uid>:<gid>` 解析出的目标身份。仅当 change_id_set 为真时有意义。
     * 交给 runtime 的 BXROOT_FAKE_UID/BXROOT_FAKE_GID —— runtime 的
     * fakeroot 层据此伪装 guest 内看到的 uid/gid（见 preload.c 的
     * init_fakeroot 读取处）。0:0 时与 -0 完全等价（fakeroot 默认身份即 0）。
     */
    unsigned long fake_uid;
    unsigned long fake_gid;
    char *runtime_lib;  /* 从 BXROOT_LIB_PATH 或自动探测 */
    char *linker_lib;
    char *stub_loader;
} launcher_config_t;

static void usage(const char *prog) {
    fprintf(stderr,
        "用法: %s [选项] <command> [args...]\n\n"
        "基本选项:\n"
        "  -r, --rootfs <path>   rootfs 路径\n"
        "  -w, --cwd <dir>       工作目录 (默认 /)\n"
        "  -b, --bind <h>:<g>    bind mount (可多次)\n"
        "  -m, --mount <h>:<g>   同 -b\n"
        "  -0, --root-id         fakeroot 模式\n"
        "  -l, --link2symlink    硬链接模拟为符号链接\n"
        "  -v, --verbose         调试模式\n"
        "  -V, --version         打印版本\n"
        "  -h, --help            帮助\n\n"
        "proot 兼容别名:\n"
        "  -R <path>             -r <path> + 一组推荐 bind\n"
        "  -S <path>             -0 -r <path> + 精简推荐 bind\n"
        "  -i, --change-id <uid>:<gid>  伪装 guest 内的 uid/gid（0:0 等价 -0）\n"
        "  -k, --kernel-release <r>  伪造内核版本（uname 的 release 字段）\n"
        "      --kill-on-exit    退出时结束容器内进程（清理 pid 账本）\n"
        "  -L                    修正 lstat 对符号链接返回的 size"
                                  "（参考实现的 fix_symlink_size）\n"
        "      --about / --usage 打印信息\n\n"
        "明确未实现（传入会报错，不会静默忽略）:\n"
        "  -H -p -q/--qemu --sysvipc --ashmem-memfd\n\n"
        "示例:\n"
        "  %s -r /data/rootfs -b /sdcard:/sdcard /bin/sh\n"
        "  %s -R /data/rootfs -0 /usr/bin/node --version\n",
        prog, prog, prog);
}

static void free_config(launcher_config_t *cfg) {
    if (!cfg) return;
    free(cfg->rootfs);
    free(cfg->workdir);
    free(cfg->guest_exe);
    if (cfg->guest_argv) {
        for (int i = 0; i < cfg->guest_argc; i++)
            free(cfg->guest_argv[i]);
        free(cfg->guest_argv);
    }
    for (int i = 0; i < cfg->bind_count * 2; i++)
        free(cfg->binds[i]);
    free(cfg->runtime_lib);
    free(cfg->linker_lib);
    free(cfg->stub_loader);
}

/* 前向声明：辅助函数定义在 parse_args 之后（那里的注释更连贯，
 * 且它们依赖 PATH_MAX 等已就位的头文件）。 */
static int add_bind(launcher_config_t *cfg, const char *host, const char *guest);
static int add_bind_ro(launcher_config_t *cfg, const char *host,
                       const char *guest, int readonly);
static int expand_bind_list(launcher_config_t *cfg,
                            const char *const *list,
                            const char *rootfs,
                            const char *host_rootfs);

/*
 * 解析 guest 路径中的**符号链接链**（launcher 侧受限版，上游同语义）。
 *
 * 【为什么需要，上游用例 test-713b6910】
 *     ln -s /tmp/A /tmp/B; proot /tmp/B
 * guest 视角 /tmp/B 是合法可执行文件。launcher 把它加 rootfs 前缀成
 * $ROOTFS/tmp/B 后，若 /tmp/B 是指向 guest 路径的 symlink，内核在
 * **宿主视角**解引用 → /tmp/A 不存在 → execve ENOENT。guest 里极常见
 * （/bin -> usr/bin 的 usr-merge、 alternatives、self-bundles）。
 *
 * 上游 proot 用 ptrace 在 execve 时做完整 canonicalize（含 symlink
 * 展开），这里在 launcher 侧做**受限等价**：
 *   - 只解析「宿主视角存在性」需要的部分（链接字面目标 + rootfs 前缀）；
 *   - 循环上限 40（内核 MAXSYMLINKS 同量级），防死循环；
 *   - 目标为 guest 绝对路径（以 / 开头且不带 rootfs 前缀）→ 加前缀；
 *     相对目标 → 相对当前链接目录拼接。
 *
 * 解析成功返回 0 并把最终宿主路径写入 resolved；解析中途消失/循环
 * 返回 -1（调用方保留原路径继续走，让内核给出真实 errno）。
 */
static int resolve_guest_symlinks(char *resolved, const char *rootfs)
{
    char cur[PATH_MAX];
    char target[PATH_MAX];
    char tmp[PATH_MAX];
    int links = 0;

    if (resolved == NULL || rootfs == NULL)
        return -1;
    snprintf(cur, sizeof(cur), "%s", resolved);

    for (links = 0; links < 40; links++) {
        struct stat sb;
        ssize_t n;
        const char *tp;
        char *slash;

        if (lstat(cur, &sb) != 0)
            return -1;                       /* 中途消失：交内核报错 */
        if (!S_ISLNK(sb.st_mode)) {
            /* 解析完成：cur 即最终宿主路径，写回给调用方 */
            snprintf(resolved, PATH_MAX, "%s", cur);
            return 0;
        }

        n = readlink(cur, target, sizeof(target) - 1);
        if (n <= 0)
            return -1;
        target[n] = '\0';
        tp = target;

        if (tp[0] == '/') {
            /* guest 绝对目标：若已带 rootfs 前缀（宿主路径）直接用 */
            size_t rl = strlen(rootfs);
            if (rl > 0 && strncmp(tp, rootfs, rl) == 0 &&
                (tp[rl] == '/' || tp[rl] == '\0')) {
                snprintf(tmp, sizeof(tmp), "%s", tp);
            } else {
                snprintf(tmp, sizeof(tmp), "%s%s", rootfs, tp);
            }
        } else {
            /* 相对目标：相对当前链接所在目录 */
            slash = strrchr(cur, '/');
            if (slash == NULL)
                return -1;
            {
                /* 拼接改用手工拷贝（目录部分 + '/' + 目标），
                 * 精确控制长度 —— gcc 的 -Wformat-truncation 对
                 * "%.*s/%s" 三段动态宽度的推算过于保守，无法靠
                 * 简单 clamp 压下去。语义与 snprintf 版一致。 */
                size_t dlen = (size_t)(slash - cur);
                size_t tlen = strlen(tp);
                size_t pos = 0;

                if (dlen > sizeof(tmp) - 2)
                    dlen = sizeof(tmp) - 2;
                memcpy(tmp, cur, dlen);
                pos = dlen;
                tmp[pos++] = '/';
                if (tlen > sizeof(tmp) - pos - 1)
                    tlen = sizeof(tmp) - pos - 1;
                memcpy(tmp + pos, tp, tlen);
                pos += tlen;
                tmp[pos] = '\0';
            }
        }
        snprintf(cur, sizeof(cur), "%s", tmp);
    }
    return -1;                               /* 超过内核同量级循环上限 */
}

static int parse_args(int argc, char **argv, launcher_config_t *cfg) {
    cfg->rootfs = strdup(BXROOT_DEFAULT_ROOTFS);

    /*
     * ★ workdir 默认值：继承宿主 cwd（上游语义，评估报告 D2）★
     *
     * 上游 proot 未给 -w/--cwd 时的默认是 "."（cli/proot.c:384-388），
     * 再由 initialize_cwd() 用宿主 getcwd 解析成绝对路径并规范化
     * （cli/cli.c:219-262）；若该目录在 guest rootfs 中不可用，才回落到
     * "/"。其自带用例 test-eddeba0e.sh 断言：
     *     ${PROOT} pwd -P | grep "^$PWD$"
     *
     * bxroot 原先硬编码 "/"，于是 `cd /some/dir && bxroot -r R pwd -P`
     * 得到 "/" —— 与上游不一致，且真实脚本里"在哪个目录启动就在哪个
     * 目录工作"的直觉被破坏（Makefile/构建脚本大量依赖）。
     *
     * 这里用宿主 getcwd 取绝对路径（等价上游 getcwd2 + canonicalize 的
     * 起点）。若取不到（cwd 已被删除），退回 "/" 与上游的容错一致。
     * 显式 -w 仍然覆盖此默认值。
     */
    {
        char hcwd[4096];
        if (getcwd(hcwd, sizeof(hcwd)) != NULL)
            cfg->workdir = strdup(hcwd);
        else
            cfg->workdir = strdup("/");
    }
    cfg->bind_count = 0;
    cfg->fakeroot = 0;
    cfg->verbose = 0;
    cfg->quiet   = 0;
    cfg->link2symlink = 0;
    cfg->fix_symlink_size = 0;
    cfg->runtime_lib = NULL;
    cfg->linker_lib = NULL;
    cfg->stub_loader = NULL;

    /*
     * ===============================================================
     * proot CLI 兼容层
     * ===============================================================
     *
     * 目标：**凡是 proot 能接受的命令行，bxroot 也要能接受**。
     *
     * 为什么这很重要：DSHA 这类上层应用是按 proot 的接口写的
     * （它传的是 `-r` / `-b` / `-0` 等等），一个只想"换个运行时"的
     * 用户不应该被迫改上层代码。缺一个选项就是一次静默降级 ——
     * 上层照发，我们报错退出，用户看到的是"容器起不来"。
     *
     * 对照基准是 proot 源码（`src/cli/proot.h` 的选项表），
     * 逐条核对其 name / separator / 语义，**不靠记忆**。
     *
     * 【三类处理，语义要区分清楚】
     *   ① 长选项别名：与短选项**完全等价**，直接归一到同一分支。
     *   ② 别名组合（-R / -S）：展开成"设 rootfs + 一批推荐 bind"。
     *   ③ 本实现暂无对应能力的：**明确报错**，不静默接受。
     *      静默接受比报错糟得多 —— 用户以为生效了，实际没有。
     */
    /*
     * 宿主 rootfs 前缀：proot 的推荐 bind 清单里写的是**宿主视角**的
     * 路径（如 /etc/passwd 指宿主那个文件），而 bxroot 自己跑在容器里，
     * 所以判断"宿主上存不存在"要用这个前缀去看。未设则按容器视角判断。
     */
    const char *host_rootfs = getenv("BXROOT_HOST_ROOTFS");

    int i = 1;
    while (i < argc) {
        if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--rootfs") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "错误: -r 需要参数\n");
                return -1;
            }
            free(cfg->rootfs);
            cfg->rootfs = strdup(argv[++i]);
        } else if (strcmp(argv[i], "-w") == 0 || strcmp(argv[i], "--cwd") == 0 ||
                   strcmp(argv[i], "--pwd") == 0) {
            /* --cwd 是 proot 的规范名；--pwd 是它的**旧名**（proot 仍接受）。
             * 两者都归一到 -w。 */
            if (i + 1 >= argc) {
                fprintf(stderr, "错误: -w 需要参数\n");
                return -1;
            }
            free(cfg->workdir);
            cfg->workdir = strdup(argv[++i]);
        } else if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--bind") == 0 ||
                   strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--mount") == 0) {
            int is_bind_opt = strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--bind") == 0;
            const char *optname = is_bind_opt ? "-b/--bind" : "-m/--mount";
            if (i + 1 >= argc) {
                fprintf(stderr, "错误: %s 需要参数\n", optname);
                return -1;
            }
            char *spec = strdup(argv[++i]);
            if (spec == NULL) {
                return -1;
            }
            char *colon = strchr(spec, ':');
            if (colon == NULL) {
                /*
                 * 上游 proot 对「不带冒号的单路径」的语义是
                 * `-b <path>` == `-b <path>:<path>`（同一来源路径按
                 * 原样映射到 rootfs 内相同位置）。保持一致，不再报错。
                 */
                if (add_bind(cfg, spec, spec) != 0) {
                    fprintf(stderr, "错误: bind 数量已达上限 %d\n", MAX_BINDS);
                    free(spec);
                    return -1;
                }
            } else {
                *colon = '\0';
                /*
                 * 只读 bind：第三段显式 `:ro` 表示该挂载点在 guest 内
                 * 只读（写返回 EROFS）。语法 `-b host:guest:ro`。
                 * 只有字面量 "ro" 才置只读；无第三段或其它值 = 可写
                 * （向后兼容旧的两段格式）。
                 *
                 * ★ 只切第三段的冒号，不影响 guest 路径 ★ 在 guest
                 * 部分再找一个冒号；找到且尾段为 "ro" 才截断并置标志。
                 */
                int ro = 0;
                char *guest = colon + 1;
                char *colon2 = strchr(guest, ':');
                if (colon2 != NULL && strcmp(colon2 + 1, "ro") == 0) {
                    *colon2 = '\0';
                    ro = 1;
                }
                if (add_bind_ro(cfg, spec, guest, ro) != 0) {
                    fprintf(stderr, "错误: bind 数量已达上限 %d\n", MAX_BINDS);
                    free(spec);
                    return -1;
                }
            }
            free(spec);
        } else if (strcmp(argv[i], "-0") == 0 ||
                   strcmp(argv[i], "--root-id") == 0) {
            cfg->fakeroot = 1;
        } else if (strcmp(argv[i], "--link2symlink") == 0 ||
                   strcmp(argv[i], "-l") == 0) {
            /*
             * `-l` 是 `--link2symlink` 的**官方短别名**：上游选项表里
             * 两者同属一个 arguments[] 组、共用同一个 handler，所以
             * "只支持长名"不算兼容。
             *
             * 缺它的后果不是"报错"而是**静默不生效** —— 用户的启动脚本
             * 写 `-l`，参数落进未识别分支，l2s 全程没开，之后所有硬链接
             * 在 f2fs/SELinux 上失败，而错误现场离原因很远（tar 解包
             * 报 EPERM、pnpm install 崩在无关步骤）。
             *
             * ★ 大小写必须分开 ★ `-L`（大写）是**另一个**扩展
             * （fix_symlink_size，修正 lstat 的符号链接 size），语义
             * 完全不同。绝不能把这两个判断合并成大小写不敏感匹配。
             */
            cfg->link2symlink = 1;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            /*
             * ★ 上游 -v 是「带整数值」的选项，不是布尔开关 ★
             *
             * 上游选项表（cli/proot.h）：
             *     { .name = "-v",        .separator = ' ', .value = "value" }
             *     { .name = "--verbose", .separator = '=', .value = "value" }
             *     description: "Set the level of debug information to *value*."
             * handler（cli/proot.c:handle_option_v）用 parse_integer_option
             * 解析，接受任意整数（含负数，如 `-v -1`）。
             *
             * 【缺陷】bxroot 原先把 -v 当布尔开关（`cfg->verbose = 1`），
             * 于是 `-v -1` 里的 `-1` 落进未知选项分支被拒绝：
             *     错误: 未知选项 '-1'
             * 而上游用例大量使用 `-v <level>` 形态（test-dddddddd 等）。
             *
             * 【修法】吃掉后面的整数值。语义映射到 bxroot 的布尔 verbose：
             * 级别 > 0 视为开启（上游 0 = 关闭、>=1 = 递增详略）；
             * 负数也开启 —— 上游对负数不报错，我们保持"接受且不崩"，
             * 这是兼容性优先的取舍（verbose 只影响日志详略，不影响语义）。
             * 缺值时报错（上游同样会报 "expects an integer value"）。
             *
             * 兼容 `--verbose=N`（= 分隔）已在下面单独处理。
             */
            /*
             * 【兼容双模式】上游要求 `-v <int>`；但**裸 `-v` 是极常见的
             * 用法**（本项目自己的 CLI 兼容测试、大量用户脚本、以及
             * 我们在测试里的自检都用裸 `-v`）。上游对裸 `-v` 报
             * "missing value"，我们选择**宽松接受**：
             *
             *   - 下一个 argv 是合法整数 → 按上游语义取级别
             *     （>0 verbose、<0 静默 quiet、=0 都不开）；
             *   - 否则（下一项是选项/命令/不存在）→ 视作 `-v 1`，
             *     只把 verbose 打开，不消费下一个 argv。
             *
             * 为什么不严格照抄上游的报错：`-v` 只影响日志详略，
             * 不影响任何语义；为它拒绝一次容器启动，代价远大于收益，
             * 而兼容性是本项目的首要目标（见目标陈述）。
             * 真正需要"精确复现上游报错"的场合（上游测试套件）用的是
             * `-v <int>` 显式形态，两种都能满足。
             */
            cfg->verbose = 1;
            if (i + 1 < argc && argv[i + 1][0] != '\0') {
                char *endp = NULL;
                long lvl = strtol(argv[i + 1], &endp, 10);
                if (endp != NULL && endp != argv[i + 1] && *endp == '\0') {
                    i++;                            /* 消费级别值 */
                    cfg->verbose = (lvl > 0) ? 1 : 0;
                    cfg->quiet   = (lvl < 0) ? 1 : 0;   /* 上游语义：负值静默 */
                }
            }
        } else if (strncmp(argv[i], "--verbose=", 10) == 0) {
            /* --verbose=<int>：上游用 '=' 分隔 */
            char *endp = NULL;
            long lvl = strtol(argv[i] + 10, &endp, 10);
            if (endp != NULL && *endp == '\0' && endp != argv[i] + 10) {
                cfg->verbose = (lvl > 0) ? 1 : 0;
                cfg->quiet   = (lvl < 0) ? 1 : 0;
            }
            else {
                fprintf(stderr, "错误: --verbose 需要整数值（上游语义）\n");
                return -1;
            }
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            exit(0);
        } else if (strcmp(argv[i], "-V") == 0 || strcmp(argv[i], "--version") == 0) {
            /* proot 的 -V/--version：打印版本后退出 0。
             * 注意与 `-v/--verbose` 大小写区分 —— proot 就是这么设计的，
             * 两者语义完全不同，不能合并。 */
            printf("bxroot %s\n", BXROOT_VERSION);
            exit(0);
        } else if (strcmp(argv[i], "--about") == 0) {
            printf("bxroot %s\n", BXROOT_VERSION);
            printf("开源容器运行时（proroot 接口兼容实现）\n");
            printf("机制: LD_PRELOAD 用户态路径翻译，无 ptrace 开销\n");
            printf("许可: MIT\n");
            exit(0);
        } else if (strcmp(argv[i], "--usage") == 0) {
            usage(argv[0]);
            exit(0);
        } else if (strcmp(argv[i], "-R") == 0) {
            /*
             * `-R <path>` = `-r <path>` + 一组推荐 bind。
             * 清单逐条抄自 proot 源码，见 PROOT_RECOMMENDED_BINDS。
             */
            if (i + 1 >= argc) {
                fprintf(stderr, "错误: -R 需要 <path> 参数\n");
                return -1;
            }
            free(cfg->rootfs);
            cfg->rootfs = strdup(argv[++i]);
            if (!cfg->rootfs) {
                return -1;
            }
            int sk = expand_bind_list(cfg, PROOT_RECOMMENDED_BINDS,
                                      cfg->rootfs, host_rootfs);
            if (sk < 0) {
                fprintf(stderr, "错误: -R 的推荐 bind 超出上限 %d\n", MAX_BINDS);
                return -1;
            }
            if (sk > 0) {
                fprintf(stderr, "[bxroot] -R: %d 条推荐 bind 在宿主上不存在，已跳过\n", sk);
            }
        } else if (strcmp(argv[i], "-S") == 0) {
            /*
             * `-S <path>` = `-0 -r <path>` + 一组**精简**推荐 bind。
             * 与 -R 的差别有实质意义：少绑定若干可能被 guest 改动的
             * 宿主文件（/etc/passwd、/etc/group、/run/ 整个目录），
             * 用于"安全地在 guest 里装包"。
             */
            if (i + 1 >= argc) {
                fprintf(stderr, "错误: -S 需要 <path> 参数\n");
                return -1;
            }
            free(cfg->rootfs);
            cfg->rootfs = strdup(argv[++i]);
            if (!cfg->rootfs) {
                return -1;
            }
            cfg->fakeroot = 1;          /* -S 隐含 -0 */
            int sk = expand_bind_list(cfg, PROOT_SU_BINDS,
                                      cfg->rootfs, host_rootfs);
            if (sk < 0) {
                fprintf(stderr, "错误: -S 的推荐 bind 超出上限 %d\n", MAX_BINDS);
                return -1;
            }
            if (sk > 0) {
                fprintf(stderr, "[bxroot] -S: %d 条推荐 bind 在宿主上不存在，已跳过\n", sk);
            }
        } else if (strcmp(argv[i], "--kill-on-exit") == 0) {
            /*
             * `--kill-on-exit`：proot 语义是"退出时杀掉容器内所有进程"。
             *
             * 本实现的进程管理在 **runtime 层**（`src/proc/proc.c` 的
             * pid 账本），launcher 只负责组装参数并 execve ——
             * 它自己没有能力枚举/终止 guest 进程树。
             *
             * 所以 launcher 这一侧的动作是**把开关交给 runtime**
             * （下面 setenv BXROOT_KILL_ON_EXIT=1），实际清理由 runtime
             * 在退出路径上遍历账本完成。launcher 不再打印"未接通"。
             */
            cfg->kill_on_exit = 1;
        } else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--change-id") == 0) {
            /*
             * `-i <uid>:<gid>` —— proot 改 guest 内看到的 uid/gid。
             *
             * 语义（对齐上游 proot 的 -i）：让 guest 内的身份查询
             * （getuid/geteuid/getresuid/getgroups、裸 syscall、
             * /proc/self/status 的 Uid/Gid 行、id/whoami）都看到指定的
             * A:B，而不是宿主内核给的真实 uid/gid。
             *
             * 实现分两半：
             *   launcher（本处）：解析 A、B 两个整数，记进 cfg，稍后
             *     setenv BXROOT_FAKE_UID=A / BXROOT_FAKE_GID=B，并同时
             *     开启 fakeroot 记账机制（cfg->fakeroot=1）—— runtime 的
             *     身份伪装总开关是 BXROOT_FAKEROOT，非 0:0 的映射也必须
             *     经它进入伪装模式，只是伪装成 A:B 而非默认的 0:0。
             *   runtime（src/runtime/preload.c 的 init_fakeroot）：读
             *     BXROOT_FAKE_UID/GID 覆盖假身份，身份查询钩子统一取该值。
             *
             * "0:0" 与 -0 完全等价（fakeroot 默认身份即 uid=gid=0，
             * 此时不必 setenv FAKE_UID/GID，留给 runtime 用默认 0）。
             */
            if (i + 1 >= argc) {
                fprintf(stderr, "错误: -i/--change-id 需要 <uid>:<gid> 参数\n");
                return -1;
            }
            const char *spec = argv[++i];
            {
                /*
                 * 解析 "A:B"：两段都必须是非空的十进制无符号整数，
                 * 中间恰好一个冒号。严格校验而非 atoi 静默吞错 ——
                 * `-i abc`、`-i 1000`、`-i 1000:`、`-i :1000`、
                 * `-i 1000:1000:0` 一律报错，否则用户以为映射生效了
                 * 而实际落到一个垃圾身份，后续所有权限判断都错。
                 */
                const char *colon = strchr(spec, ':');
                char *end_u = NULL;
                char *end_g = NULL;
                unsigned long uid_v;
                unsigned long gid_v;

                if (colon == NULL || colon == spec || colon[1] == '\0' ||
                    strchr(colon + 1, ':') != NULL) {
                    fprintf(stderr,
                            "错误: -i/--change-id 需要 <uid>:<gid> 形式的"
                            "两个非负整数，收到 \"%s\"。\n", spec);
                    return -1;
                }
                errno = 0;
                uid_v = strtoul(spec, &end_u, 10);
                if (errno != 0 || end_u != colon) {
                    fprintf(stderr,
                            "错误: -i/--change-id 的 uid 段不是合法整数："
                            "\"%s\"。\n", spec);
                    return -1;
                }
                errno = 0;
                gid_v = strtoul(colon + 1, &end_g, 10);
                if (errno != 0 || end_g == colon + 1 || *end_g != '\0') {
                    fprintf(stderr,
                            "错误: -i/--change-id 的 gid 段不是合法整数："
                            "\"%s\"。\n", spec);
                    return -1;
                }

                cfg->fakeroot = 1;          /* 任意映射都启用身份伪装 */
                cfg->change_id_set = 1;
                cfg->fake_uid = uid_v;
                cfg->fake_gid = gid_v;
            }
        } else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--kernel-release") == 0) {
            /*
             * `-k/--kernel-release <release>`：伪造 `uname` 的 release 字段。
             *
             * 分两半，各归各的层：
             *   launcher（本处）：解析并记进 cfg，稍后 setenv 交给运行时；
             *   runtime（src/runtime/preload.c 的 uname 钩子）：读
             *   BXROOT_KERNEL_RELEASE 并改写 buf->release。
             *
             * ★ 为什么这里不再无条件打"不生效" ★
             *
             * 那句话是**未实现时期**的诚实标注，如今已成事实错误 ——
             * 留着它会让用户以为设置被忽略，从而去别处找原因。但它也
             * 不能直接消失：排障时"到底传进去没有"是个真问题，
             * 所以改成**只在 -v 时**回显实际交给运行时的值。
             */
            if (i + 1 >= argc) {
                fprintf(stderr, "错误: -k/--kernel-release 需要 <release> 参数\n");
                return -1;
            }
            free(cfg->kernel_release);
            cfg->kernel_release = strdup(argv[++i]);
        } else if (strcmp(argv[i], "-H") == 0) {
            fprintf(stderr,
                    "错误: -H 未实现。\n"
                    "      proot 的 -H 是「隐藏 .proot.* 文件」扩展；\n"
                    "      本实现没有该扩展。明确拒绝而非静默忽略 ——\n"
                    "      静默忽略会让用户以为隐藏已生效。\n");
            return -1;
        } else if (strcmp(argv[i], "-L") == 0) {
            /*
             * `-L`：proot 的「修正 lstat 对符号链接返回的 size」扩展。
             *
             * ★ 它到底修什么（参考实现确认，不是推测）★
             *
             * `cli/proot.c:322` 的 handle_option_L() 初始化 fix_symlink_size
             * 扩展；该扩展只 filter PR_lstat/PR_lstat64（SYSEXIT），逻辑是：
             *     if (!S_ISLNK(statl.st_mode)) return 0;   // 不是链接就不管
             *     size = readlink(path, buf, PATH_MAX);
             *     st_size = (off_t)size;                  // = 目标字符串长度
             *
             * 即：**对真符号链接，把 st_size 钉成 readlink 返回的长度**。
             * 内核对符号链接本来给的就是这个值，所以它常常是恒等操作；
             * 它的注释写明「l2s 应当已经解链完毕」，说明它排在
             * link2symlink 之后，管的是 l2s **没**接管的普通符号链接
             * （典型是 /proc 下的魔法链接：st_size 有时是 0，而 readlink
             * 返回实际长度）。
             *
             * ★ 它与 l2s 的 size 缺陷是两件事，不要混为一谈 ★
             *
             * 本项目的「伪造链接 lstat 的 size 不对」由 l2s 层**无条件**
             * 修正（官方默认就如此，与 -L 无关，已实测：官方不传 -L 时
             * lstat 的 size 正确）。传不传 -L 都该对。早前把两者当成同一
             * 件事，是看到 -L 的说明里写着 "lstat 的 size" 就下了结论 ——
             * 实测证明那是两回事。
             *
             * 所以这里只置一个环境变量，**不改变任何默认行为**：
             * 与参考实现一致，默认不开。
             */
            cfg->fix_symlink_size = 1;
        } else if (strcmp(argv[i], "-p") == 0) {
            fprintf(stderr,
                    "错误: -p 未实现。\n"
                    "      proot 的 -p 是「端口保护」扩展（把 bind 到受保护\n"
                    "      端口的请求改到高位端口）；本实现没有该扩展。\n");
            return -1;
        } else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--qemu") == 0) {
            fprintf(stderr,
                    "错误: -q/--qemu 未实现（跨架构模拟）。\n"
                    "      本实现只做同架构路径翻译，不含 QEMU 用户态模拟。\n");
            return -1;
        } else if (strcmp(argv[i], "--sysvipc") == 0) {
            fprintf(stderr,
                    "错误: --sysvipc 未实现。\n"
                    "      proot 的该选项用于让不同 IPC namespace 的进程\n"
                    "      共享 SysV IPC；本实现没有该能力。\n");
            return -1;
        } else if (strcmp(argv[i], "--ashmem-memfd") == 0) {
            fprintf(stderr,
                    "错误: --ashmem-memfd 未实现。\n"
                    "      proot 在 Android 上用 ashmem 模拟 memfd_create；\n"
                    "      本实现没有该模拟。\n");
            return -1;
        } else {
            /*
             * ★ 以 '-' 开头但不是我们认识的选项 → **必须报错**，不能当 guest 命令 ★
             *
             * 实测过的真实缺陷：`bxroot --definitely-not-an-option` 原先会
             * 把它当成要执行的程序，报出
             *     "错误: rootfs 内找不到命令 --definitely-not-an-option"
             * —— 用户看到的是"命令找不到"，而真实原因是"选项名拼错了"。
             * 排查方向被引偏。
             *
             * proot 的做法是 `unknown option '%s'`（见其 src/cli/cli.c:389）。
             * 这里照做，并且**顺带提示最可能的原因** —— 本项目刚加了 proot
             * 兼容层，用户很可能用的是我们明确未实现的某个选项（-H/-L/-p/-q
             * 等），而那些选项会各自给出更具体的错误。
             *
             * 例外：单独的 "-" 按惯例表示 stdin，仍当作 guest 命令处理。
             */
            if (argv[i][0] == '-' && argv[i][1] != '\0') {
                fprintf(stderr,
                        "错误: 未知选项 '%s'\n"
                        "      用 -h/--help 看支持的选项；\n"
                        "      若这是 proot 的选项，本实现可能明确未支持它\n"
                        "      （-H / -p / -q / --sysvipc / --ashmem-memfd）。\n",
                        argv[i]);
                return -1;
            }

            /* 第一个非选项参数就是 guest 命令 */
            cfg->guest_exe = strdup(argv[i]);
            cfg->guest_argc = argc - i;
            cfg->guest_argv = malloc(sizeof(char *) * (cfg->guest_argc + 1));
            for (int j = i; j < argc; j++)
                cfg->guest_argv[j - i] = strdup(argv[j]);
            cfg->guest_argv[cfg->guest_argc] = NULL;  // NULL 终止
            break;
        }
        i++;
    }

    if (!cfg->guest_exe) {
        fprintf(stderr, "错误: 必须指定要执行的命令\n\n");
        usage(argv[0]);
        return -1;
    }

    return 0;
}

/*
 * 加一条 bind。成功返回 0，容量满/格式错返回 -1。
 *
 * 抽成函数是因为 proot 的 `-R` / `-S` 要成批加十几条，
 * 每处都手写一遍"检查容量 + 解析冒号 + 存两个指针"必然漏掉某处检查。
 * 注意 `host:guest` 里的冒号是**第一个** —— guest 侧路径本身可以再含
 * 冒号（少见但合法），用 strchr 而非 strrchr 与参考实现一致。
 */
static int add_bind(launcher_config_t *cfg, const char *host, const char *guest)
{
    return add_bind_ro(cfg, host, guest, 0);
}

/*
 * add_bind 的带只读标志版本。readonly!=0 时该 bind 的 guest 挂载点在
 * 容器内只读（编码进 BXROOT_BINDS 的第三段 `:ro`，runtime 强制 EROFS）。
 */
static int add_bind_ro(launcher_config_t *cfg, const char *host,
                       const char *guest, int readonly)
{
    if (cfg->bind_count >= MAX_BINDS) {
        return -1;
    }
    cfg->binds[cfg->bind_count * 2] = strdup(host);
    cfg->binds[cfg->bind_count * 2 + 1] = strdup(guest);
    if (cfg->binds[cfg->bind_count * 2] == NULL ||
        cfg->binds[cfg->bind_count * 2 + 1] == NULL) {
        return -1;
    }
    cfg->bind_readonly[cfg->bind_count] = readonly ? 1 : 0;
    cfg->bind_count++;
    return 0;
}

/*
 * 展开 proot 的推荐 bind 清单。
 *
 * `rootfs` 用于替换清单里的 `*path*` 占位符；`$HOME` 取环境变量，
 * 为空则跳过该条（与 proot 行为一致）。
 *
 * ★ 路径不存在的处理：**跳过并计数，不算失败** ★
 * 见清单上方的说明 —— `/var/run/dbus/system_bus_socket` 在精简系统上
 * 十有八九不存在，若因它整体失败，`-R` 在多数环境下根本用不了。
 * 但"跳过"必须是**可见的**（proot 也是打 warning），所以返回跳过条数
 * 供调用方打印，而不是静默吞掉。
 *
 * 返回跳过的条数；-1 表示 bind 容量不足（这是**真错误**，必须报）。
 */
static int expand_bind_list(launcher_config_t *cfg,
                            const char *const *list,
                            const char *rootfs,
                            const char *host_rootfs)
{
    int skipped = 0;

    for (int i = 0; list[i] != NULL; i++) {
        const char *item = list[i];
        char expanded[PATH_MAX];

        if (strcmp(item, "*path*") == 0) {
            /*
             * `*path*` → 把 rootfs 自己 bind 到自身。
             *
             * 两侧都用**宿主路径**：proot 此处传的是 -r 的值，
             * 而 guest 侧写同样的字符串即可（翻译层看到它已在 rootfs
             * 内不会再套前缀）。
             */
            if (rootfs == NULL || rootfs[0] == '\0') {
                skipped++;
                continue;
            }
            if (add_bind(cfg, rootfs, rootfs) != 0) {
                return -1;
            }
            continue;
        }

        if (strcmp(item, "$HOME") == 0) {
            const char *home = getenv("HOME");
            if (home == NULL || home[0] == '\0') {
                skipped++;          /* 与参考实现一致：为空则跳过 */
                continue;
            }
            item = home;
        }

        /*
         * 展开到宿主路径：清单里的路径是**宿主**视角（如 /etc/passwd
         * 指宿主的那个），而我们要判断它在宿主上存不存在。
         * proot 直接在宿主命名空间里 stat，这里同理 —— 但 bxroot 自身
         * 运行在容器里，所以要用 host_rootfs 前缀去看宿主的真实文件。
         */
        if (host_rootfs != NULL && item[0] == '/') {
            int n = snprintf(expanded, sizeof(expanded), "%s%s", host_rootfs, item);
            if (n < 0 || (size_t)n >= sizeof(expanded)) {
                skipped++;
                continue;
            }
        } else {
            int n = snprintf(expanded, sizeof(expanded), "%s", item);
            if (n < 0 || (size_t)n >= sizeof(expanded)) {
                skipped++;
                continue;
            }
        }

        if (access(expanded, F_OK) != 0) {
            skipped++;              /* 宿主上不存在 → 跳过（proot 同） */
            continue;
        }

        if (add_bind(cfg, item, item) != 0) {
            return -1;
        }
    }
    return skipped;
}

/*
 * 把 `dir` 与 `name` 拼成 `dir/name` 写进 `out`。
 *
 * ★ 为什么不用一行 snprintf ★
 *
 * `snprintf(out, sizeof(out), "%s/%s", dir, name)` 在 dir 与 out 同宽
 * （都是 PATH_MAX = 4096）时**必然**触发 -Wformat-truncation：编译器
 * 无法证明 dir 的实际长度，只能按最坏情况（4095 字节）推演，于是得出
 * "可能截断"的结论。
 *
 * 那个警告不是误报 —— 超长时 snprintf 会**静默截断**，得到一个指向
 * 别处的路径（例如 `.../libbxroot-runtim`），随后 access() 失败、
 * 功能静默降级。所以正确的做法不是关掉警告，而是**显式检查长度**：
 * 超长就报错退出，让配置问题可见。
 *
 * 返回 0 成功，-1 表示放不下（不写 out 的内容，调用方据此报错）。
 */
static int join_dir_name(char *out, size_t out_size,
                         const char *dir, const char *name)
{
    size_t dl, nl;

    if (out == NULL || dir == NULL || name == NULL || out_size == 0) {
        return -1;
    }
    dl = strlen(dir);
    nl = strlen(name);

    /* dir + '/' + name + '\0' */
    if (dl > out_size - 1) {
        return -1;
    }
    if (nl > out_size - 2 - dl) {
        return -1;
    }

    memcpy(out, dir, dl);
    out[dl] = '/';
    memcpy(out + dl + 1, name, nl);
    out[dl + 1 + nl] = '\0';
    return 0;
}

/* ------------------------------------------------------------------ */
/* --kill-on-exit 监督进程（行动清单 #3）                              */
/* ------------------------------------------------------------------ */
/*
 * 【缺口（2026-09-25 实测）】runtime 侧的 kill-on-exit 挂在 atexit 上
 * （proc.c），只覆盖 return/exit()。六种退出方式实测（guest fork 2 个
 * 长睡子进程后退出）：
 *     exit()      → 孤儿 0/2      _exit()     → 孤儿 2/2
 *     exit_group  → 孤儿 2/2      SIGSEGV     → 孤儿 2/2
 *     SIGKILL     → 孤儿 2/2      abort()     → 孤儿 2/2
 * 进程死了就没有代码能在它里面跑 —— 只能由**活得比它久**的进程清理。
 *
 * 【方案】launcher 不再 exec 成 guest，而是：
 *   1. 自己设 PR_SET_CHILD_SUBREAPER —— 其后代里的孤儿（含 double-fork
 *      + setsid 的守护进程）一律改挂到它名下，而不是 init；
 *   2. fork 出 guest（照原路径 exec）；
 *   3. 等 guest 退出，然后反复「枚举自己的子进程 → SIGKILL → 回收」，
 *      直到 waitpid 报 ECHILD（= 再无任何后代）；
 *   4. 以 guest 的退出状态退出（被信号杀的就用同一信号自杀，
 *      shell 看到的 $? 与直接跑 guest 一致）。
 *
 * 【安全（docs/杀进程安全规则.md）】只对「ppid == 自己」的 pid 发信号。
 * 这些是**尚未回收**的直接子进程：在我们 waitpid 之前内核不会复用它们
 * 的 pid，所以「读 /proc → kill」之间不存在 pid 复用竞态。不按名字、
 * 不按进程组、不广播。
 *
 * 【只在 --kill-on-exit 时生效】默认路径仍是 launcher 直接 exec 成
 * guest，进程树、getppid、信号语义与之前完全一致。
 *
 * 【信号】SIGTERM/SIGHUP/SIGUSR1/SIGUSR2 转发给 guest（发给 launcher
 * pid 的停止请求要落到 guest 上）。SIGINT/SIGQUIT 监督者自己忽略：
 * 终端产生的这两个信号投递给整个前台进程组，guest 已经直接收到，
 * 再转发会让 guest 收到两次。
 *
 * 【边界】监督者本身被 SIGKILL 时无法清理整棵树；给 guest 设了
 * PR_SET_PDEATHSIG(SIGKILL)，至少 guest 主进程会随之结束。
 */
static volatile pid_t g_sup_child = 0;

static void sup_forward(int sig)
{
    pid_t c = g_sup_child;
    if (c > 0)
        kill(c, sig);
}

/* 读 /proc/<pid>/stat 的 ppid（第 4 字段；comm 可含空格与括号，从最后一个 ')' 起数） */
static pid_t sup_read_ppid(const char *pidstr)
{
    char path[64], buf[512], *q;
    int fd;
    ssize_t n;
    long ppid;

    if (snprintf(path, sizeof(path), "/proc/%s/stat", pidstr) >= (int)sizeof(path))
        return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = '\0';
    q = strrchr(buf, ')');
    if (q == NULL || q[1] != ' ' || q[2] == '\0' || q[3] != ' ')
        return -1;
    ppid = strtol(q + 4, NULL, 10);   /* ") S <ppid>" */
    return (pid_t)ppid;
}

/* SIGKILL 所有 ppid == self 的进程，返回发出的数量 */
static int sup_kill_children(pid_t self)
{
    DIR *d = opendir("/proc");
    struct dirent *e;
    int n = 0;

    if (d == NULL)
        return 0;
    while ((e = readdir(d)) != NULL) {
        const char *s = e->d_name;
        pid_t pid;
        if (*s < '1' || *s > '9')
            continue;
        pid = (pid_t)strtol(s, NULL, 10);
        if (pid <= 1 || pid == self)
            continue;
        if (sup_read_ppid(s) != self)
            continue;
        if (kill(pid, SIGKILL) == 0)
            n++;
    }
    closedir(d);
    return n;
}

/*
 * 清理：直到再无后代（waitpid 报 ECHILD）。
 *
 * 每轮先杀光当前能看到的子进程，再**非阻塞**回收。被杀进程的孩子在它
 * 退出时已改挂到我们名下（subreaper），下一轮扫描就能看到。
 *
 * ★ 不能用阻塞 waitpid ★ 若某个子进程在 /proc 里看不到（hidepid、
 * /proc 未挂载），我们杀不到它，阻塞等待就会让监督者**永远挂住**，
 * 连带用户的 shell。所以：连续一段时间既没杀到也没收到任何进程时，
 * 放弃并明确告警 —— 留下进程比卡死更好。
 */
static void sup_reap_all(pid_t self, int verbose)
{
    int st, idle = 0;
    for (;;) {
        int killed = sup_kill_children(self);
        int reaped = 0;
        pid_t w;
        while ((w = waitpid(-1, &st, WNOHANG)) > 0)
            reaped++;
        if (w < 0 && errno == ECHILD)
            return;             /* 清理完毕 */
        if (killed || reaped) {
            idle = 0;
        } else if (++idle > 200) {  /* 约 2 秒无进展 */
            fprintf(stderr, "[bxroot-launcher] 警告: kill-on-exit 仍有后代无法"
                    "枚举（/proc 不可见？），放弃清理\n");
            return;
        }
        {
            struct timespec ts = { 0, 10 * 1000 * 1000 };
            nanosleep(&ts, NULL);
        }
        (void)verbose;
    }
}

/*
 * fork + 监督。子进程里返回 0（调用方继续走原 exec 路径）；
 * 父进程里永不返回（以 guest 的状态退出）。fork 失败返回 -1。
 */
static int supervise_or_return_in_child(int verbose)
{
    pid_t self = getpid(), c;
    int st = 0;

    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0 && verbose)
        fprintf(stderr, "[bxroot-launcher] 警告: PR_SET_CHILD_SUBREAPER 失败: %s"
                "（脱离的孙进程将无法清理）\n", strerror(errno));
    /* 继承来的 SIGCHLD=SIG_IGN 会让内核自动回收，waitpid 拿不到状态 */
    signal(SIGCHLD, SIG_DFL);

    c = fork();
    if (c < 0)
        return -1;
    if (c == 0) {
        /* guest：监督者死了就跟着死；fork 与 prctl 之间监督者已死则自行退出 */
        prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
        if (getppid() != self)
            _exit(137);
        return 0;
    }

    g_sup_child = c;
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = sup_forward;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGHUP,  &sa, NULL);
        sigaction(SIGUSR1, &sa, NULL);
        sigaction(SIGUSR2, &sa, NULL);
        signal(SIGINT,  SIG_IGN);
        signal(SIGQUIT, SIG_IGN);
    }
    if (verbose)
        fprintf(stderr, "[bxroot-launcher] kill-on-exit 监督: guest pid=%d\n", (int)c);

    for (;;) {
        pid_t w = waitpid(-1, &st, 0);
        if (w == c)
            break;
        if (w < 0 && errno != EINTR) {
            st = 0;             /* 不应发生：guest 还没回收就 ECHILD */
            break;
        }
        /* 其它 w：先于 guest 退出、改挂过来的孤儿，顺手回收 */
    }
    g_sup_child = 0;

    sup_reap_all(self, verbose);

    if (WIFSIGNALED(st)) {
        int sig = WTERMSIG(st);
        signal(sig, SIG_DFL);
        {
            sigset_t m;
            sigemptyset(&m);
            sigaddset(&m, sig);
            sigprocmask(SIG_UNBLOCK, &m, NULL);
        }
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);   /* guest 已按需产生过 core，这里不重复 */
        kill(self, sig);
        _exit(128 + sig);
    }
    _exit(WIFEXITED(st) ? WEXITSTATUS(st) : 1);
}

/* ------------------------------------------------------------------ */
/* exec 失败诊断（行动清单 #8，上游 #402/#21）                          */
/* ------------------------------------------------------------------ */
/*
 * 上游 proot 在 execve 失败时打印 5 条"可能原因"（cli.c print_execve_help），
 * bxroot 原先只有一行 strerror —— 而 Android 上 exec 失败几乎全是 EACCES，
 * 这一行对定位毫无帮助（实测：缺解释器的脚本、纯文本文件、无执行位的文件、
 * x86 二进制，四种完全不同的原因全都只报 "Permission denied"）。
 *
 * 这里不照抄上游的"可能原因"列表，而是**读文件头判定具体是哪一条**，
 * 只打印命中的那一条；判不出来时才退回上游式的通用列表。
 * 全部是只读检查，不改变任何行为；quiet（-v 负数）时不打印。
 */
static void guest_to_host(char *out, size_t sz, const char *rootfs, const char *g)
{
    size_t rl = rootfs ? strlen(rootfs) : 0;
    if (g[0] == '/' && rl > 0 && !(strncmp(g, rootfs, rl) == 0 && (g[rl] == '/' || g[rl] == '\0')))
        snprintf(out, sz, "%s%s", rootfs, g);
    else
        snprintf(out, sz, "%s", g);
}

static void explain_exec_failure(const char *exe, const char *rootfs, int err);

/*
 * 读 ELF 的 PT_INTERP（仅 64 位 LE、程序头在首 4K 内）。
 * 返回 1 = 有解释器（写入 out），0 = 不是 ELF / 无 INTERP，-1 = 读失败。
 */
static int read_elf_interp(const char *path, char *out, size_t outsz)
{
    unsigned char buf[4096];
    unsigned long phoff = 0;
    unsigned phentsize, phnum, k;
    ssize_t m;
    int fd = open(path, O_RDONLY | O_CLOEXEC);

    if (fd < 0)
        return -1;
    m = read(fd, buf, sizeof(buf));
    close(fd);
    if (m < 64 || memcmp(buf, "\177ELF", 4) != 0 || buf[4] != 2)
        return 0;
    memcpy(&phoff, buf + 32, 8);
    phentsize = buf[54] | (buf[55] << 8);
    phnum = buf[56] | (buf[57] << 8);
    for (k = 0; k < phnum && phentsize >= 56; k++) {
        unsigned long off = phoff + (unsigned long)k * phentsize, poff, psz;
        unsigned type;
        if (off + 56 > (unsigned long)m)
            break;
        memcpy(&type, buf + off, 4);
        if (type != 3 /* PT_INTERP */)
            continue;
        memcpy(&poff, buf + off + 8, 8);
        memcpy(&psz, buf + off + 32, 8);
        if (psz == 0 || psz > outsz || poff + psz > (unsigned long)m)
            return 0;
        memcpy(out, buf + poff, psz);
        out[psz - 1] = '\0';
        return 1;
    }
    return 0;
}

/*
 * ★ 经 libbxroot-ulx.so（用户态 exec）启动 guest（2026-09-27 真机新增）★
 *
 * 【为什么】Android app 沙箱的 seccomp 对 set_robust_list / rseq 是 TRAP。
 * 内核 execve 会把信号处置重置为默认，guest 的 ld.so 在 __libc_early_init
 * 里发这两个调用时 runtime 还没加载 → 进程被 SIGSYS 杀死（Termux 实测：
 * 所有 guest 命令 rc=159）。ulx 在本进程内装载 ld.so，处理器全程有效。
 *
 * 【何时走】launcher 目录里有 libbxroot-ulx.so、guest 是动态 ELF、
 * 其 PT_INTERP 在 rootfs 内存在；且外层没有提供 PROROOT_TRAMPOLINE_PATH
 * （嵌套在 proroot/DSHA 里时维持原路径不变）。BXROOT_NO_ULX=1 可强制关闭。
 *
 * 同时导出 BXROOT_ULX_PATH / BXROOT_ULX_LDSO，runtime 的 exec 钩子据此让
 * 子进程也经 ulx（proc.c px_tramp_cfg）。
 *
 * 成功不返回；返回即表示不适用或失败（调用方继续走原来的 execve）。
 */
static void try_exec_via_ulx(const launcher_config_t *cfg, const char *lib_dir,
                             const char *caller_guest_path)
{
    char ulx[PATH_MAX], interp[PATH_MAX], ldso[PATH_MAX * 2];
    char sb_interp[PATH_MAX], sb_host[PATH_MAX * 2], sb_arg[PATH_MAX];
    const char *exe_host = cfg->guest_exe;   /* 交给 ld.so 的程序（宿主路径） */
    int is_script = 0, sb_has_arg = 0;
    const char *v = getenv("BXROOT_NO_ULX");
    char **nv;
    int n = 0, i;

    if (v != NULL && v[0] != '\0' && v[0] != '0')
        return;
    v = getenv("PROROOT_TRAMPOLINE_PATH");
    if (v != NULL && v[0] != '\0')
        return;
    if (join_dir_name(ulx, sizeof(ulx), lib_dir, LIBBXROOT_ULX) != 0 ||
        access(ulx, X_OK) != 0)
        return;
    /*
     * shebang 脚本：内核语义是 exec 解释器、argv = [interp, (arg), 脚本, ...]。
     * 不在这里处理的话会落到直接 execve —— 内核按宿主视角解析 `#!/bin/sh`，
     * 在 Android 上跑起来的是**系统的** /system/bin/sh（bionic），再被
     * LD_PRELOAD 的 glibc runtime 拖死（真机实测 "CANNOT LINK EXECUTABLE"）。
     * 只处理一层（解释器本身是脚本时放弃，交回原路径）。
     */
    {
        char line[PATH_MAX];
        ssize_t m;
        int fd = open(cfg->guest_exe, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            return;
        m = read(fd, line, sizeof(line) - 1);
        close(fd);
        if (m >= 2 && line[0] == '#' && line[1] == '!') {
            char *s = line + 2, *e, *a;
            line[m] = '\0';
            e = strchr(s, '\n');
            if (e == NULL)
                return;                  /* 行过长：交内核处理 */
            *e = '\0';
            if (e > s && e[-1] == '\r')
                return;                  /* CRLF：交原路径，explain_exec_failure 会解释 */
            while (*s == ' ' || *s == '\t')
                s++;
            a = s;
            while (*a && *a != ' ' && *a != '\t')
                a++;
            if (*a) {
                *a++ = '\0';
                while (*a == ' ' || *a == '\t')
                    a++;
                /* 与 Linux 相同：解释器之后的**整段**（去尾空白）是单个参数 */
                e = a + strlen(a);
                while (e > a && (e[-1] == ' ' || e[-1] == '\t'))
                    *--e = '\0';
                if (*a) {
                    snprintf(sb_arg, sizeof(sb_arg), "%s", a);
                    sb_has_arg = 1;
                }
            }
            if (s[0] != '/')
                return;
            snprintf(sb_interp, sizeof(sb_interp), "%s", s);
            guest_to_host(sb_host, sizeof(sb_host), cfg->rootfs, sb_interp);
            if (resolve_guest_symlinks(sb_host, cfg->rootfs) != 0)
                return;
            exe_host = sb_host;
            is_script = 1;
        }
    }
    if (read_elf_interp(exe_host, interp, sizeof(interp)) != 1)
        return;
    guest_to_host(ldso, sizeof(ldso), cfg->rootfs, interp);
    if (access(ldso, R_OK) != 0)
        return;

    setenv("BXROOT_ULX_PATH", ulx, 1);
    setenv("BXROOT_ULX_LDSO", ldso, 1);

    nv = calloc((size_t)cfg->guest_argc + 10, sizeof(char *));
    if (nv == NULL)
        return;
    nv[n++] = ulx;
    nv[n++] = ldso;
    nv[n++] = (char *)"--argv0";
    if (is_script)
        nv[n++] = sb_interp;
    else
        nv[n++] = cfg->guest_argv[0] != NULL ? cfg->guest_argv[0] : cfg->guest_exe;
    nv[n++] = (char *)"--preload";
    nv[n++] = cfg->runtime_lib;
    nv[n++] = (char *)exe_host;
    if (is_script) {
        if (sb_has_arg)
            nv[n++] = sb_arg;
        /* 脚本路径用 guest 视角（$0 / B1 期望 "HELLO /tmp/sg"）；
         * 解释器打开它时由 runtime 翻译 */
        nv[n++] = (char *)(caller_guest_path != NULL && caller_guest_path[0] == '/'
                           ? caller_guest_path : cfg->guest_exe);
    }
    for (i = 1; i < cfg->guest_argc && cfg->guest_argv[i] != NULL; i++)
        nv[n++] = cfg->guest_argv[i];
    nv[n] = NULL;

    if (cfg->verbose)
        fprintf(stderr, "[bxroot-launcher] 经 ulx 启动: %s %s\n", ulx, ldso);
    syscall(SYS_execve, ulx, nv, environ);
    if (cfg->verbose)
        fprintf(stderr, "[bxroot-launcher] ulx exec 失败（%s），回退直接 execve\n",
                strerror(errno));
    unsetenv("BXROOT_ULX_PATH");
    unsetenv("BXROOT_ULX_LDSO");
    free(nv);
}

static void explain_exec_failure(const char *exe, const char *rootfs, int err)
{
    unsigned char h[128];
    struct stat st;
    ssize_t n;
    int fd;

    fprintf(stderr, "可能原因：\n");
    if (stat(exe, &st) != 0) {
        fprintf(stderr, "  * 文件不存在（或路径中某一级不是目录）：%s\n", exe);
        return;
    }
    if (S_ISDIR(st.st_mode)) {
        fprintf(stderr, "  * 这是一个目录，不能执行\n");
        return;
    }
    if ((st.st_mode & 0111) == 0) {
        fprintf(stderr, "  * 文件没有执行权限（mode=%o）—— 试试 chmod +x，"
                "或用解释器显式运行（如 sh %s）\n", st.st_mode & 07777, exe);
        return;
    }
    fd = open(exe, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "  * 文件无法读取（%s）\n", strerror(errno));
        return;
    }
    n = read(fd, h, sizeof(h) - 1);
    close(fd);
    if (n < 0)
        n = 0;
    h[n] = '\0';

    if (n >= 2 && h[0] == '#' && h[1] == '!') {
        /* 脚本：取解释器路径（跳过空白，到空白/换行为止） */
        char interp[PATH_MAX], host[PATH_MAX * 2];
        size_t i = 2, j = 0;
        while (i < (size_t)n && (h[i] == ' ' || h[i] == '\t'))
            i++;
        while (i < (size_t)n && h[i] != ' ' && h[i] != '\t' && h[i] != '\n' &&
               h[i] != '\r' && j + 1 < sizeof(interp))
            interp[j++] = (char)h[i++];
        interp[j] = '\0';
        if (j == 0) {
            fprintf(stderr, "  * 脚本的 #! 行没有写解释器\n");
            return;
        }
        if (i < (size_t)n && h[i] == '\r') {
            fprintf(stderr, "  * 脚本是 Windows 换行（CRLF）：内核找的解释器是 \"%s\\r\"，"
                    "用 dos2unix 或 sed -i 's/\\r$//' 转换\n", interp);
            return;
        }
        guest_to_host(host, sizeof(host), rootfs, interp);
        if (stat(host, &st) != 0) {
            fprintf(stderr, "  * 脚本的解释器 %s 在 rootfs 内不存在"
                    "（需要安装它，或改 #! 行）\n", interp);
            return;
        }
        fprintf(stderr, "  * 脚本解释器 %s 存在，但它本身无法执行（见其自身的错误）\n", interp);
        return;
    }
    if (n >= 4 && h[0] == 0x7f && h[1] == 'E' && h[2] == 'L' && h[3] == 'F') {
        if (n >= 20) {
            unsigned mach = (unsigned)h[18] | ((unsigned)h[19] << 8);
            if (mach != 183 /* EM_AARCH64 */) {
                const char *nm = mach == 62 ? "x86_64" : mach == 3 ? "i386" :
                                 mach == 40 ? "ARM 32 位" : mach == 243 ? "RISC-V" : "非 aarch64";
                fprintf(stderr, "  * 这是 %s 架构的二进制（e_machine=%u），本机是 aarch64，"
                        "无法直接运行（bxroot 不做 qemu 转译）\n", nm, mach);
                return;
            }
            if (h[4] != 2) {
                fprintf(stderr, "  * 这是 32 位 ELF，本机 rootfs 是 64 位 aarch64\n");
                return;
            }
        }
        /* ELF 解释器（PT_INTERP）：只看 64 位 LE，程序头在首 4K 内的常见布局 */
        {
            unsigned char buf[4096];
            int f2 = open(exe, O_RDONLY | O_CLOEXEC);
            ssize_t m = f2 >= 0 ? read(f2, buf, sizeof(buf)) : -1;
            if (f2 >= 0)
                close(f2);
            if (m >= 64) {
                unsigned long phoff = 0; unsigned phentsize, phnum, k;
                memcpy(&phoff, buf + 32, 8);
                phentsize = buf[54] | (buf[55] << 8);
                phnum = buf[56] | (buf[57] << 8);
                for (k = 0; k < phnum && phentsize >= 56; k++) {
                    unsigned long off = phoff + (unsigned long)k * phentsize;
                    unsigned type; unsigned long poff, psz;
                    if (off + 56 > (unsigned long)m)
                        break;
                    memcpy(&type, buf + off, 4);
                    if (type != 3 /* PT_INTERP */)
                        continue;
                    memcpy(&poff, buf + off + 8, 8);
                    memcpy(&psz, buf + off + 32, 8);
                    if (psz > 0 && psz < PATH_MAX && poff + psz <= (unsigned long)m) {
                        char interp[PATH_MAX], host[PATH_MAX * 2];
                        memcpy(interp, buf + poff, psz);
                        interp[psz - 1] = '\0';
                        guest_to_host(host, sizeof(host), rootfs, interp);
                        if (stat(host, &st) != 0) {
                            fprintf(stderr, "  * 这是动态链接的 ELF，但它的加载器 %s 在 rootfs 内"
                                    "不存在（缺 libc6 / 架构不符的 rootfs）\n", interp);
                            return;
                        }
                    }
                    break;
                }
            }
        }
        fprintf(stderr, "  * aarch64 ELF 本身格式正常；若 errno 为 EACCES，多半是宿主"
                "策略（SELinux app_data_file）禁止直接 exec —— 经 DSHA/bridge 启动可绕过\n");
        return;
    }
    if (n == 0) {
        fprintf(stderr, "  * 文件是空的\n");
        return;
    }
    {
        size_t k, bin = 0;
        for (k = 0; k < (size_t)n; k++)
            if (h[k] == 0)
                bin++;
        if (bin == 0) {
            fprintf(stderr, "  * 这是没有 #! 行的文本文件：内核不知道用什么解释器"
                    "（加上 #!/bin/sh 之类的首行，或用 sh %s 运行）\n", exe);
            return;
        }
    }
    (void)err;
    fprintf(stderr, "  * 文件格式无法识别（既不是 ELF 也不是 #! 脚本）\n"
            "  * （通用）程序的解释器/加载器缺失，或是外部架构的二进制\n");
}

int main(int argc, char **argv) {
    launcher_config_t cfg = {0};

    if (parse_args(argc, argv, &cfg) < 0) {
        free_config(&cfg);
        return 1;
    }

    /* 获取本程序所在目录（用于查找 runtime .so） */
    char exe_path[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (n <= 0) {
        fprintf(stderr, "错误: 无法确定程序路径\n");
        free_config(&cfg);
        return 1;
    }
    exe_path[n] = '\0';

    /* 获取目录部分 */
    char *last_slash = strrchr(exe_path, '/');
    char lib_dir[PATH_MAX];
    if (last_slash) {
        size_t len = last_slash - exe_path;
        if (len < sizeof(lib_dir)) {
            memcpy(lib_dir, exe_path, len);
            lib_dir[len] = '\0';
        } else {
            snprintf(lib_dir, sizeof(lib_dir), "/");
        }
    } else {
        snprintf(lib_dir, sizeof(lib_dir), ".");
    }


    /* 构建 runtime 库路径：优先使用 BXROOT_LIB_PATH（DSHA 设置），否则用本目录同名文件 */
    const char *env_lib_path = getenv("BXROOT_LIB_PATH");
    char runtime_lib[PATH_MAX];
    if (env_lib_path && env_lib_path[0] && access(env_lib_path, F_OK) == 0) {
        snprintf(runtime_lib, sizeof(runtime_lib), "%s", env_lib_path);
        cfg.runtime_lib = strdup(runtime_lib);
    } else {
        if (join_dir_name(runtime_lib, sizeof(runtime_lib),
                          lib_dir, LIBBXROOT_RUNTIME) != 0) {
            fprintf(stderr, "[bxroot-launcher] 运行时库路径过长（%s + %s > %d）\n",
                    lib_dir, LIBBXROOT_RUNTIME, (int)sizeof(runtime_lib));
            return 1;
        }
        cfg.runtime_lib = strdup(runtime_lib);
    }

    /* 构建 linker 和 stub-loader 路径（如果存在） */
    char linker_lib[PATH_MAX], stub_lib[PATH_MAX];
    /*
     * linker / stub-loader 是**可选**组件：放不下就跳过（不致命），
     * 但要让用户看见，不能静默。
     */
    if (join_dir_name(linker_lib, sizeof(linker_lib),
                      lib_dir, LIBBXROOT_LINKER) == 0) {
        if (access(linker_lib, F_OK) == 0)
            cfg.linker_lib = strdup(linker_lib);
    } else {
        fprintf(stderr, "[bxroot-launcher] 跳过 linker：路径过长\n");
    }

    if (join_dir_name(stub_lib, sizeof(stub_lib),
                      lib_dir, LIBBXROOT_STUB_LOADER) == 0) {
        if (access(stub_lib, F_OK) == 0)
            cfg.stub_loader = strdup(stub_lib);
    } else {
        fprintf(stderr, "[bxroot-launcher] 跳过 stub-loader：路径过长\n");
    }

    /* 设置环境变量 */
    setenv("BXROOT_ROOTFS", cfg.rootfs, 1);
    /* BXROOT_TMP_DIR: 使用已有的环境变量值，否则用 /tmp */
    if (!getenv("BXROOT_TMP_DIR"))
        setenv("BXROOT_TMP_DIR", "/tmp", 1);
    setenv("BXROOT_GUEST_EXE", cfg.guest_exe, 1);
    setenv("BXROOT_WORKDIR", cfg.workdir, 1);

    /*
     * ★ $PWD 必须与 guest 视角的 workdir 一致（上游 #64，v4.0.1 解法）★
     *
     * bash/dash 启动时若 $PWD 存在且 stat($PWD) 与 stat(".") 同 inode，
     * 就**直接沿用 $PWD 字符串**作为当前目录名，不再 getcwd。于是：
     * launcher 从宿主目录 H 启动、-w /x 且 /x 被 -b 绑到 H 时，shell
     * 继承的 $PWD 仍是宿主路径 H，`pwd` 回显的就是宿主路径 —— 路径视角
     * 泄漏。runtime 的 getcwd 钩子在这条路上根本没被问到。
     *
     * 上游 proot 在 cli/cli.c 的 initialize_cwd() 末尾无条件
     * setenv("PWD", cwd) 修掉此事。这里同样：workdir 已是 guest 视角
     * 绝对路径（默认继承宿主 cwd 时，runtime 端 translate 后 chdir，
     * 而 guest 看到的名字仍是这个字符串），直接写 $PWD 即可。
     * runtime 侧 chdir 失败（目录不存在）时 stat 校验会失败，shell 会
     * 回退 getcwd，不会因此拿到错值。
     */
    setenv("PWD", cfg.workdir, 1);

    /*
     * ★ BXROOT_ORIG_COMM：容器**首命令**的名字（上游 /proc/pid/comm 语义）★
     *
     * 上游 proot 用 execve 的 raw user path 修正 /proc/pid/comm
     * （src/execve/enter.c:620 注释）。经 bridge 链启动时 comm 会是
     * bridge.so 的名字，需要把「首命令 basename」带进来修正。
     *
     * 【为什么独立于 BXROOT_GUEST_EXE】guest_exe 会被 proc.c 在**每次
     * exec 时更新**（子进程要正确回答 /proc/self/exe），而 comm 语义
     * 不同：上游只对**容器首命令**做修正，子进程各自 exe 的 basename
     * 本来就正确。原始名只需在此设一次，runtime 侧用一次性标记防
     * 子进程误用。
     */
    {
        const char *b = strrchr(cfg.guest_exe, '/');
        b = (b != NULL) ? b + 1 : cfg.guest_exe;
        if (b[0] != '\0')
            setenv("BXROOT_ORIG_COMM", b, 1);
    }

    /*
     * ===============================================================
     * proot 环境变量兼容层
     * ===============================================================
     *
     * 与 CLI 兼容层同样的问题：**用户从 proot 迁移过来时，环境变量也带着**。
     * 我们不认 `PROOT_*` 的名字，它们就静默失效 —— 用户设了
     * `PROOT_VERBOSE=1` 却看不到日志、设了 `PROOT_TMP_DIR` 却发现临时文件
     * 仍在别处，而没有任何报错。
     *
     * 语义逐条对照 proot 源码，不靠猜：
     *
     *   PROOT_TMP_DIR                     → src/path/temp.c:25
     *   PROOT_VERBOSE                     → src/cli/cli.c:472
     *   PROOT_IGNORE_MISSING_BINDINGS     → src/path/binding.c:335
     *   PROOT_NO_SECCOMP                  → src/cli/cli.c:140（仅影响提示文案）
     *
     * ★ 迁移方向：PROOT_* → BXROOT_* ★
     * **只在新名字未设时**才从旧名字取值。这样显式设了 BXROOT_* 的用户
     * （我们自己的文档推荐的写法）不会被环境里的旧 PROOT_* 覆盖。
     */
    {
        /*
         * PROOT_TMP_DIR —— 临时目录。
         *
         * ★ 必须保留原值不做规范化 ★
         * proot 会 realpath() 一次，失败时**退回原字符串**并打 warning。
         * 我们不做 realpath：launcher 眼里的路径是**容器视角**，而运行
         * 时用的是内核视角 —— 在这里 realpath 会得到错误的基准（本项目
         * 反复踩的双视角坑）。原样透传，由运行时按自己的视角解释。
         */
        const char *ptmp = getenv("PROOT_TMP_DIR");
        if (ptmp != NULL && ptmp[0] != '\0' && getenv("BXROOT_TMP_DIR") == NULL) {
            setenv("BXROOT_TMP_DIR", ptmp, 1);
        }

        /*
         * PROOT_VERBOSE —— 详细程度。
         *
         * ★ 它是**数字**不是布尔 ★
         * proot 用 `strtol(verbose_env, NULL, 10)`（cli.c:472），
         * 所以 `PROOT_VERBOSE=0` 与 `PROOT_VERBOSE=2` 不同：
         * 前者关日志，后者是更高级别。
         * 本实现的 BXROOT_VERBOSE 用 atoi 判定（非零即开），能容纳这个语义；
         * 但**不能**把 `PROOT_VERBOSE=0` 当成"设过了"而跳过 —— 那样
         * 用户显式关日志的意图会丢失。
         */
        const char *pverb = getenv("PROOT_VERBOSE");
        if (pverb != NULL && pverb[0] != '\0' && getenv("BXROOT_VERBOSE") == NULL) {
            setenv("BXROOT_VERBOSE", pverb, 1);
        }

        /*
         * PROOT_IGNORE_MISSING_BINDINGS —— bind 路径缺失时不警告。
         *
         * proot 的语义（binding.c:335）：**仅在 verbose>0 时**才有区别 ——
         * 它控制的是「重复 bind 覆盖时是否打 warning」。本实现默认就不打
         * 这类 warning，所以此变量**在当前实现下无行为差异**。
         *
         * 记录它（透传下去）而不是假装支持：将来若加了 bind 冲突警告，
         * 运行时可以直接读这个变量，不必再改 launcher。
         */
        const char *pign = getenv("PROOT_IGNORE_MISSING_BINDINGS");
        if (pign != NULL && pign[0] != '\0' &&
            getenv("BXROOT_IGNORE_MISSING_BINDINGS") == NULL) {
            setenv("BXROOT_IGNORE_MISSING_BINDINGS", pign, 1);
        }
    }

    /*
     * 内核版本伪造（-k/--kernel-release）。
     *
     * launcher 侧能做的只有「把用户给的值交给运行时」—— uname 钩子在
     * src/runtime/preload.c 里，改 release 字段由它完成。
     *
     * ★ 必须成对 unsetenv ★
     *
     * 与 BXROOT_FAKEROOT 同一条约定：这些值一律**由 launcher 从 argv 派生**
     * （见 docs/DSHA-适配说明.md 的对外契约）。若 DSHA 环境里恰好残留了
     * 一个 BXROOT_KERNEL_RELEASE，而用户这次没传 -k，只在「传了才 setenv」
     * 会让那个残留值生效 —— 于是「以 argv 为准」失效，容器里出现一个
     * 用户从未要求过的内核版本。所以没传时必须显式 unset。
     */
    if (cfg.kernel_release)
        setenv("BXROOT_KERNEL_RELEASE", cfg.kernel_release, 1);
    else
        unsetenv("BXROOT_KERNEL_RELEASE");

    /*
     * --kill-on-exit：交给 runtime 的进程账本执行（launcher 无法枚举
     * guest 进程树）。同样成对 unset，理由同上。
     */
    if (cfg.kill_on_exit)
        setenv("BXROOT_KILL_ON_EXIT", "1", 1);
    else
        unsetenv("BXROOT_KILL_ON_EXIT");

    if (cfg.fakeroot)
        setenv("BXROOT_FAKEROOT", "1", 1);
    else
        unsetenv("BXROOT_FAKEROOT");

    /*
     * -i <uid>:<gid> 的身份映射交给 runtime 的 fakeroot 层。
     *
     * ★ 必须成对 setenv/unsetenv（与 BXROOT_KERNEL_RELEASE 同一约定）★
     * 这两个值一律由 launcher 从 argv 派生：只有用户显式传了非 0:0 的
     * -i 才 setenv；否则显式 unset，避免 DSHA 环境残留的旧值让容器出现
     * 用户从未要求过的身份。0:0（含 -0）不设，runtime 用默认假身份 0。
     */
    if (cfg.change_id_set && (cfg.fake_uid != 0 || cfg.fake_gid != 0)) {
        char idbuf[32];
        snprintf(idbuf, sizeof(idbuf), "%lu", cfg.fake_uid);
        setenv("BXROOT_FAKE_UID", idbuf, 1);
        snprintf(idbuf, sizeof(idbuf), "%lu", cfg.fake_gid);
        setenv("BXROOT_FAKE_GID", idbuf, 1);
    } else {
        unsetenv("BXROOT_FAKE_UID");
        unsetenv("BXROOT_FAKE_GID");
    }

    /* quiet 优先级高于 verbose：上游 -v <负数> 就是"压低输出"，
     * 此时绝不能同时把 verbose 打开（那会自相矛盾）。 */
    if (cfg.verbose && !cfg.quiet)
        setenv("BXROOT_VERBOSE", "1", 1);
    else
        unsetenv("BXROOT_VERBOSE");

    /*
     * quiet（上游 `-v <负数>`）要传到 runtime 侧：proc.c 的
     * `[bxroot] proc: ...` 诊断与 runtime 的其它非 ERROR 输出都需抑制，
     * 否则容器输出仍与宿主不一致。runtime 读 BXROOT_QUIET。
     */
    if (cfg.quiet)
        setenv("BXROOT_QUIET", "1", 1);
    else
        unsetenv("BXROOT_QUIET");

    /* 设置 linker / stub-loader 环境变量（供 runtime 库查找） */
    if (cfg.linker_lib)
        setenv("BXROOT_LINKER_PATH", cfg.linker_lib, 1);
    if (cfg.stub_loader)
        setenv("BXROOT_STUB_LOADER", cfg.stub_loader, 1);

    /*
     * 设置 bind mount 环境变量。
     *
     * 【为什么不用固定 64 KiB + strcat】
     * 曾经写成 `malloc(65536)` 然后无界 strcat —— 而 `-b` 只校验了
     * **条数**（最多 16），不校验**每条的路径长度**。16 条各 3 KB 的
     * 路径就是 96 KB，直接堆溢出：
     *     带 _FORTIFY_SOURCE 的构建 → "buffer overflow detected" + abort
     *     不带 FORTIFY 的构建     → 静默越界写（更危险）
     * 触发条件只是"bind 数量合法、路径较长"，不需要恶意构造。
     *
     * 【修法】先精确算出所需长度再分配。
     * 同时把 max_binds 的上限也用上，避免长度计算本身溢出。
     */
    if (cfg.bind_count > 0) {
        size_t need = 1;                    /* 结尾 NUL */

        for (int i = 0; i < cfg.bind_count; i++) {
            const char *a = cfg.binds[i * 2];
            const char *b = cfg.binds[i * 2 + 1];
            if (a == NULL || b == NULL)
                continue;
            need += strlen(a) + 1 + strlen(b);   /* +1 是中间的 ':' */
            if (cfg.bind_readonly[i])
                need += 3;                        /* ":ro" */
            if (i > 0)
                need += 1;                        /* 分隔符 ';' */
            if (need > (size_t)1 << 20) {         /* 1 MiB 上限，防御性 */
                fprintf(stderr, "错误: bind 列表过长（%zu 字节）\n", need);
                free_config(&cfg);
                return 1;
            }
        }

        char *bind_env = malloc(need);
        if (bind_env == NULL) {
            fprintf(stderr, "错误: 内存不足（bind 列表需要 %zu 字节）\n", need);
            free_config(&cfg);
            return 1;
        }

        {
            char *w = bind_env;
            for (int i = 0; i < cfg.bind_count; i++) {
                const char *a = cfg.binds[i * 2];
                const char *b = cfg.binds[i * 2 + 1];
                if (a == NULL || b == NULL)
                    continue;
                if (i > 0)
                    *w++ = ';';
                w = stpcpy(w, a);
                *w++ = ':';
                w = stpcpy(w, b);
                if (cfg.bind_readonly[i])
                    w = stpcpy(w, ":ro");
            }
            *w = '\0';
        }

        setenv("BXROOT_BINDS", bind_env, 1);
        free(bind_env);
    }

    /*
     * 硬链接模拟开关。
     *
     * 这是 P0 缺陷的修复：原先第 144 行把 --link2symlink 解析进
     * cfg.link2symlink 之后，全代码再无一处引用它，运行时也从不读它 ——
     * 参数被静默吞掉。DSHA 无条件传 --link2symlink（app 私有目录禁
     * link(2)），因此生产的每一次 pnpm/dpkg/tar 都在失去模拟的情况下运行，
     * 失败还是静默的。
     *
     * 现在把它导出给运行时，由运行时初始化 l2s 层。
     */
    if (cfg.link2symlink) {
        const char *l2s_dir = getenv("BXROOT_L2S_DIR");
        setenv("BXROOT_LINK2SYMLINK", "1", 1);
        /*
         * 集中目录布局：中间层与数据文件都放进 rootfs 内的一个目录，
         * 而不是散落在客户文件旁边。DSHA 生产走这条路径。
         *
         * 不设时默认用 <rootfs>/.l2s —— 与 DSHA 的 PROOT_L2S_DIR 对齐。
         */
        if (!l2s_dir || !l2s_dir[0]) {
            static char fallback[4096];
            int n = snprintf(fallback, sizeof(fallback), "%s/.l2s",
                             cfg.rootfs ? cfg.rootfs : "");
            if (n > 0 && (size_t)n < sizeof(fallback))
                setenv("BXROOT_L2S_DIR", fallback, 1);
        }
    } else {
        unsetenv("BXROOT_LINK2SYMLINK");
    }

    /* 设置 LD_PRELOAD（替换已有值，避免与系统原有 proroot 冲突） */
    setenv("LD_PRELOAD", cfg.runtime_lib, 1);

    /*
     * `-L`（fix_symlink_size）。
     *
     * ★ 必须成对 setenv/unsetenv ★
     *
     * 与 -k/--kernel-release 同一个理由：环境变量会被子进程继承，
     * 若只在"传了才设"，用户上一次传过 -L 而这次没传时，旧值还留在
     * 环境里 —— 表现为"选项关了却仍生效"。所以没传时显式清掉。
     */
    if (cfg.fix_symlink_size)
        setenv("BXROOT_FIX_SYMLINK_SIZE", "1", 1);
    else
        unsetenv("BXROOT_FIX_SYMLINK_SIZE");

    if (cfg.verbose) {
        fprintf(stderr, "[bxroot-launcher] rootfs=%s\n", cfg.rootfs);
        fprintf(stderr, "[bxroot-launcher] workdir=%s\n", cfg.workdir);
        fprintf(stderr, "[bxroot-launcher] PWD=%s\n", getenv("PWD"));
        fprintf(stderr, "[bxroot-launcher] guest=%s\n", cfg.guest_exe);
        fprintf(stderr, "[bxroot-launcher] runtime_lib=%s\n", cfg.runtime_lib);
        fprintf(stderr, "[bxroot-launcher] LD_PRELOAD=%s\n", getenv("LD_PRELOAD"));
        if (cfg.bind_count > 0)
            fprintf(stderr, "[bxroot-launcher] binds=%s\n", getenv("BXROOT_BINDS"));
        if (cfg.link2symlink)
            fprintf(stderr, "[bxroot-launcher] link2symlink=1 l2s_dir=%s\n",
                    getenv("BXROOT_L2S_DIR") ? getenv("BXROOT_L2S_DIR") : "(none)");
        if (cfg.kernel_release)
            fprintf(stderr, "[bxroot-launcher] kernel_release=%s\n",
                    cfg.kernel_release);
        if (cfg.kill_on_exit)
            fprintf(stderr, "[bxroot-launcher] kill_on_exit=1\n");
    }

    /* 注意: 不在 launcher 中 chdir
     * 工作目录由 runtime 库在 guest 加载后处理
     * 因为 launcher 的 chdir 会改变宿主文件系统的工作目录，
     * 而不是 rootfs 内的工作目录
     */

    /* 解析命令路径：绝对路径加 rootfs 前缀，相对路径搜索 rootfs 内的 PATH */
    char resolved_path[PATH_MAX];
    struct stat st_buf;   /* symlink 兜底检查用（见下） */
    const char *cmd = cfg.guest_exe;
    /*
     * guest_guest_path：**调用者视角**的 guest 完整路径（不含 symlink
     * 链解析）。上游语义里 /proc/self/exe、argv[0]、comm 都用它 ——
     * 即使内核实际 exec 的是 symlink 解析后的目标（见
     * resolve_guest_symlinks 处的说明与 test-713b6910）。
     */
    char caller_guest_path[PATH_MAX];

    if (cmd[0] == '/') {
        /* 绝对路径：加上 rootfs 前缀 */
        snprintf(resolved_path, sizeof(resolved_path), "%s%s", cfg.rootfs, cmd);
        /*
         * ★ 存在性检查：access 失败时再看 lstat（symlink 兜底）★
         *
         * access() 会**跟随符号链接**。guest 视角下的 symlink
         * （如 /tmp/b -> /tmp/a，两个都是 guest 路径）在宿主视角里
         * 目标可能不存在 —— access(\$RF/tmp/b) 跟随到 /tmp/a → ENOENT，
         * 但链接本体明明在（上游用例 test-713b6910 第 20 行：
         * ln -s \${TMP1} \${TMP2}; \${PROOT} \${TMP2} 应能执行）。
         *
         * 修法：lstat 只看链接本体。lstat 也失败才真的不存在。
         * 放行后由内核 execve + runtime 路径翻译接管（symlink 目标
         * 在内核解析时若失败，会由 runtime 对 guest 路径做翻译兜底）。
         *
         * 上游 test-713b6910 正是这条：ln -s 脚本A 脚本B 后 exec 脚本B，
         * 输出 \$0 应为脚本B 的路径。
         */
        if (access(resolved_path, F_OK) != 0 &&
            lstat(resolved_path, &st_buf) != 0) {
            /*
             * 注意：这里必须给足 4 个实参。
             * 曾经只传了 2 个（格式串里却要 4 个），于是 va_arg 从栈上
             * 读垃圾当 %d/%s —— 用户敲错一条命令行就 SIGSEGV，
             * 而且**连这条错误消息本身都打不出来**（崩溃在打印过程中），
             * 现象是"什么都没输出就退出 139"，极难排查。
             */
            fprintf(stderr, "错误: rootfs 内找不到命令 %s (实际路径: %s) errno=%d %s\n",
                    cmd, resolved_path, errno, strerror(errno));
            free_config(&cfg);
            return 127;     /* shell 约定：命令不存在 = 127 */
        }
        cfg.guest_exe = strdup(resolved_path);
        snprintf(caller_guest_path, sizeof(caller_guest_path), "%s", cmd);
    } else {
        /* 相对路径：搜索 rootfs 内的 PATH */
        const char *path_env = getenv("PATH");
        if (!path_env) path_env = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

        char *path_copy = strdup(path_env);
        char *saveptr = NULL;
        char *dir = strtok_r(path_copy, ":", &saveptr);
        int found = 0;

        while (dir && !found) {
            snprintf(resolved_path, sizeof(resolved_path), "%s%s/%s", cfg.rootfs, dir, cmd);
            if (access(resolved_path, X_OK) == 0) {
                found = 1;
                cfg.guest_exe = strdup(resolved_path);
                snprintf(caller_guest_path, sizeof(caller_guest_path),
                         "%s/%s", dir, cmd);
            }
            dir = strtok_r(NULL, ":", &saveptr);
        }
        free(path_copy);

        if (!found) {
            fprintf(stderr, "错误: rootfs 内找不到命令 %s\n", cmd);
            free_config(&cfg);
            return 127;     /* shell 约定：命令不存在 = 127 */
        }
    }
    
    /*
     * ★ 解析 guest 路径里的符号链接链（上游 canonicalize 等价，受限版）★
     *
     * 放在两个解析分支之后统一处理：无论绝对路径还是 PATH 搜索，
     * resolved_path 都可能是 guest 视角 symlink（usr-merge 的
     * /bin -> usr/bin、alternatives、用户自建链接）。不解析的话
     * 内核在宿主视角解引用会 ENOENT（上游 test-713b6910）。
     */
    if (resolve_guest_symlinks(resolved_path, cfg.rootfs) == 0) {
        free(cfg.guest_exe);
        cfg.guest_exe = strdup(resolved_path);
    } else if (cfg.verbose) {
        fprintf(stderr,
                "[bxroot-launcher] symlink 解析失败，保留原路径继续: %s\n",
                resolved_path);
    }

    /*
     * ★ 重设 BXROOT_GUEST_EXE 为 **guest 视角的完整路径**（上游语义）★
     *
     * 【缺陷，上游 test-99999999 暴露】
     * 上面把 cfg.guest_exe 解析成了**宿主路径**（$ROOTFS/usr/bin/readlink）
     * 供 execve 使用 —— 这是对的。但 `BXROOT_GUEST_EXE` 早在此前（约
     * 826 行）就已 setenv，用的还是**用户输入的原始串**（可能是裸名
     * `readlink`、或相对名 `./x`）。
     *
     * runtime 用 guest_exe 回答客户的 `readlink("/proc/self/exe")`：
     *   - 上游：`/usr/bin/readlink`（完整 guest 路径）—— 其用例
     *     test-99999999 断言 `grep ^${WHICH_READLINK}$`；
     *   - bxroot 实测：返回 `readlink`（裸名），断言失败。
     *
     * 【真实影响】裸名会让客户对"我是谁"的判断出错。DSHA 里 koffi
     * 模块就是拿 process.execPath 去推导 libc 类型与同级路径 ——
     * Node 的 execPath 必须是绝对路径（其文档明确要求），拿到裸名
     * 会走错分支。这正是此前 dsh web 段错误那条链的上游环节。
     *
     * 修法（本轮，覆盖首进程）：在 execve 前把 BXROOT_GUEST_EXE 更新为
     * **去掉 $ROOTFS 前缀**的绝对 guest 路径（= 容器内视角的完整路径）。
     *
     * ★ 已知残留：子进程 exec 场景尚未覆盖 ★
     * 本修复只处理 launcher 启动的**首进程**。`sh -c 'readlink
     * /proc/self/exe'` 这类场景里，sh 会 fork+exec 出 readlink，而
     * runtime 的 exec 钩子（proc.c）目前**不更新** BXROOT_GUEST_EXE，
     * 子进程于是继承父进程的值（`/usr/bin/sh`），readlink 会自称 sh。
     * 上游 test-99999999 的第 8/9 行即断言此场景，当前仍失败。
     * 正确修法是在 px_do_execve 的环境构建里按当次 exec 目标更新该变量
     * （proc.c 的 px_build_forced 需扩槽位并把 guest 路径传入）；因涉及
     * exec 核心路径且本容器无法端到端验证，留作待办。
     */
    {
        /*
         * ★ 用 caller_guest_path（调用者视角），不用 symlink 解析后的 ★
         *
         * 上游语义（execve/enter.c:620 raw_path + test-713b6910）：
         *   /proc/self/exe、argv[0]、/proc/pid/comm 一律是**调用者给的
         *   guest 路径** —— 即便内核实际 exec 的是 symlink 解析后的目标
         *   （test-713b6910 要求 ln -s A B 后 exec B，\$0=/tmp/B 且
         *   输出不含 A）。symlink 解析只用于「找到可执行文件」。
         *
         * caller_guest_path 已是 guest 视角完整路径（裸名经 PATH 搜索
         * 补全成 /usr/bin/xxx，满足 test-99999999 的完整路径断言）。
         */
        const char *ge = caller_guest_path;
        size_t rl = strlen(cfg.rootfs);

        if (ge != NULL && ge[0] == '/' &&
            strncmp(ge, cfg.rootfs, rl) == 0 && ge[rl] == '/') {
            ge = ge + rl;
        }
        if (cfg.verbose)
            fprintf(stderr, "[bxroot-launcher] guest_exe: %s -> %s\n",
                    getenv("BXROOT_GUEST_EXE"), ge);
        setenv("BXROOT_GUEST_EXE", ge, 1);
        {
            const char *b = strrchr(ge, '/');
            b = (b != NULL) ? b + 1 : ge;
            if (b[0] != '\0')
                setenv("BXROOT_ORIG_COMM", b, 1);
        }
    }

    /*
     * 检查路径是否存在。
     *
     * ★ 诊断输出必须受 quiet/verbose 门控 ★
     * 原先这条**无条件**打印，于是每次运行都在 stderr 留一行
     * `[bxroot-launcher] stat(...) OK` —— 破坏与上游的输出一致性
     * （上游默认静默，上游用例 test-dddddddd 用 cmp 逐字节比对）。
     */
    /*
     * ★ 门控是 verbose，不是 !quiet ★（2026-09-25 修）
     * 上面注释说的"受 quiet/verbose 门控"原先落成了 `if (!cfg.quiet)`，
     * 而 quiet 默认 0 —— 于是**默认就打印**，正是注释要消灭的行为
     * （实测：`libbxroot.so -r / /bin/true` 每次 stderr 多一行 stat OK）。
     */
    if (cfg.verbose && !cfg.quiet) {
        struct stat st;
        if (stat(cfg.guest_exe, &st) < 0) {
            fprintf(stderr, "[bxroot-launcher] stat(%s) failed: %s\n", cfg.guest_exe, strerror(errno));
        } else {
            fprintf(stderr, "[bxroot-launcher] stat(%s) OK, mode=%o, size=%ld\n", cfg.guest_exe, st.st_mode & 07777, (long)st.st_size);
        }
    }
    /*
     * ★ 复位 SIGPIPE（上游同等处理，评估报告 D5）★
     *
     * 【为什么必须做】SIG_IGN 会**跨 fork/exec 存活**。Android 的 zygote
     * 把 SIGPIPE 设成 SIG_IGN 并一直传下来，于是 guest 里所有进程都继承
     * 了"忽略"：`yes | head -1` 不会静默被杀，而是打印
     * "yes: standard output: Broken pipe" 并继续跑 —— 脚本里判断管道
     * 退出的逻辑全错（PIPESTATUS 期望 141，实得 1）。
     *
     * 上游 proot 专门修过这一条（src/tracee/event.c:111），理由与容器
     * 运行时一致：**给 guest 一个正常系统上该有的处置**，而不是宿主
     * 进程组的遗留状态。
     *
     * 【放在 execve 前】与上游同位置：复位后立即 exec，中间不再有
     * 机会被重新置位。runtime 的构造函数也会再兜一次（防止经 bridge
     * 链直接加载、绕过 launcher 的路径）。
     */
    signal(SIGPIPE, SIG_DFL);

    /*
     * --kill-on-exit：launcher 留下来当监督者，guest 在子进程里照常 exec。
     * 见 supervise_or_return_in_child() 的说明。fork 失败时退回直接 exec
     * （不清理，但至少 guest 能跑）并明确告警。
     */
    if (cfg.kill_on_exit) {
        if (supervise_or_return_in_child(cfg.verbose) < 0)
            fprintf(stderr, "[bxroot-launcher] 警告: fork 失败（%s），"
                    "--kill-on-exit 仅剩 atexit 路径\n", strerror(errno));
    }

    /* execve guest 程序 */
    if (cfg.verbose)
        fprintf(stderr, "[bxroot-launcher] execve: %s\n", cfg.guest_exe);

    /*
     * ★ 用裸 syscall 执行 guest，绕过外层容器对 libc execve 的符号 hook ★
     *
     * 某些外层容器（实测：proroot）通过 LD_PRELOAD 挂钩 libc 的 `execve`
     * 符号，把每一次 exec 都改写成它自己的加载器链
     * （bridge + linker + --preload <外层 runtime>）。后果是 bxroot 自己
     * 的 runtime 从未被加载 —— **路径翻译完全失效**，guest 实际跑在外层
     * 容器的翻译下（实测：guest 里读到的是宿主的 /etc/os-release）。
     *
     * 裸 syscall 不经 PLT，外层符号钩子拦不到（已用最小探针实测：libc
     * execve 被改写，syscall(SYS_execve) 不被改写）。失败时回退到 libc
     * execve，保持原来的行为与错误信息。
     */
    try_exec_via_ulx(&cfg, lib_dir, caller_guest_path);   /* 成功不返回 */
    syscall(SYS_execve, cfg.guest_exe, cfg.guest_argv, environ);
    execve(cfg.guest_exe, cfg.guest_argv, environ);

    /* 如果到这里说明 execve 失败了 */
    {
        int e = errno;   /* 先存：下面的诊断会调 stat/open，改写 errno */
        fprintf(stderr, "错误: execve(%s) 失败: %s\n", cfg.guest_exe, strerror(e));
        if (!cfg.quiet)
            explain_exec_failure(cfg.guest_exe, cfg.rootfs, e);
        free_config(&cfg);
        /*
         * 与 shell 约定一致：找不到 127，找到但不能执行 126
         * （原先一律 1，脚本无法区分"命令不存在"与"命令自己失败返回 1"）。
         */
        return (e == ENOENT) ? 127 : 126;
    }
}
