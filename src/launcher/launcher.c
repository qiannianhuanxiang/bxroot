/*
 * libbxroot.so 入口 launcher
 *
 * 解析 CLI 参数，设置环境变量，设置 LD_PRELOAD，execve guest 程序。
 * 原名 libproroot.so / proroot-clone，现更名 libbxroot.so / bxroot。
 * 对标上游闭源项目 proroot 的同名入口库。
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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <limits.h>

/*
 * 版本号。
 *
 * 用 `-V` / `--version` 打印。proot 的对应选项是 `-V`（大写），
 * 与 `-v`（verbose）**只差大小写但语义完全不同** —— 这是 proot 的
 * 既有设计，兼容层必须照做，不能"统一"成同一个小写选项。
 */
#ifndef BXROOT_VERSION
#define BXROOT_VERSION "0.1.0"
#endif

/*
 * 最大 bind mount 数量。
 *
 * 从 16 提到 48：proot 的 `-R` 别名一次会加 **18 条** bind（见
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
 * proot 兼容：`-R` / `-S` 的推荐 bind 清单
 * ===================================================================
 *
 * 这两份清单**逐条抄自 proot 源码**（`src/cli/proot.h` 的
 * `recommended_bindings[]` 与 `recommended_su_bindings[]`），
 * 不是我自己归纳的 —— 兼容性判断必须以对方源码为准。
 *
 * 【为什么必须抄准】
 * `-R` 的语义是"`-r <path>` + 一组推荐 bind"，用户之所以用它，正是
 * 为了少写十几条 `-b`。清单少一条、或路径写错，表现是"程序在容器里
 * 读不到 /etc/resolv.conf 之类"，而错误现场离原因很远（DNS 失败、
 * 用户名显示成 uid）。所以这里逐字对齐。
 *
 * 【`*path*` 与 `$HOME` 是 proot 的占位符，不是字面路径】
 *   `*path*` —— 替换为 `-r` 给的 rootfs 路径（即"把 rootfs 自己
 *               也 bind 到自身"，用于让 guest 内路径自洽）
 *   `$HOME`  —— 替换为环境变量 HOME 的值，为空则**跳过该条**
 * 解析时按此展开。
 *
 * 【路径不存在的处理】
 * proot 的 `new_bindings()` 对不存在的路径是**警告后跳过**，不是失败。
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
    /* proot 源码里被注释掉的一条，此处同样不启用：
     *   /var/tmp/kdecache-$LOGNAME */
    "$HOME",
    "*path*",
    NULL,
};

/*
 * `-S` 的清单。proot 注释说明它用于"安全地在 guest 里装包"：
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

/* 配置结构 */
typedef struct {
    char *rootfs;
    char *workdir;
    char *guest_exe;
    char **guest_argv;
    int guest_argc;
    char *binds[2 * MAX_BINDS]; /* [src, dst, src, dst, ...] */
    int bind_count;
    int fakeroot;
    int verbose;
    int link2symlink;
    /*
     * proot 兼容字段。
     *
     * `kill_on_exit`：proot 的 `--kill-on-exit`，退出时杀光容器内进程。
     *   语义见 proot 源码 `tracee->killall_on_exit = true`。
     * `kernel_release`：proot 的 `-k/--kernel-release`，伪造 uname 的
     *   release 字段。**本实现只记录不生效** —— 见解析处的诚实标注。
     */
    int kill_on_exit;
    char *kernel_release;
    int change_id_set;      /* -i/--change-id 是否被显式指定 */
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
        "  -m, --mount <h>:<g>   同 -b（proot 别名）\n"
        "  -0, --root-id         fakeroot 模式\n"
        "      --link2symlink    硬链接模拟为符号链接\n"
        "  -v, --verbose         调试模式\n"
        "  -V, --version         打印版本\n"
        "  -h, --help            帮助\n\n"
        "proot 兼容别名:\n"
        "  -R <path>             -r <path> + 一组推荐 bind\n"
        "  -S <path>             -0 -r <path> + 精简推荐 bind\n"
        "  -i, --change-id 0:0   等价于 -0（其它取值未实现）\n"
        "  -k, --kernel-release <r>  记录内核版本（暂未生效）\n"
        "      --kill-on-exit    退出时结束容器内进程\n"
        "      --about / --usage 打印信息\n\n"
        "明确未实现（传入会报错，不会静默忽略）:\n"
        "  -H -L -p -q/--qemu --sysvipc --ashmem-memfd\n\n"
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
static int expand_bind_list(launcher_config_t *cfg,
                            const char *const *list,
                            const char *rootfs,
                            const char *host_rootfs);

static int parse_args(int argc, char **argv, launcher_config_t *cfg) {
    cfg->rootfs = strdup(BXROOT_DEFAULT_ROOTFS);
    cfg->workdir = strdup("/");
    cfg->bind_count = 0;
    cfg->fakeroot = 0;
    cfg->verbose = 0;
    cfg->link2symlink = 0;
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
        } else if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--bind") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "错误: -b 需要参数\n");
                return -1;
            }
            if (cfg->bind_count >= MAX_BINDS) {
                fprintf(stderr, "错误: 最多 %d 个 bind mount\n", MAX_BINDS);
                return -1;
            }
            cfg->binds[cfg->bind_count * 2] = strdup(argv[++i]);
            /* 解析 src:dst */
            char *colon = strchr(cfg->binds[cfg->bind_count * 2], ':');
            if (!colon) {
                fprintf(stderr, "错误: -b 需要 <host>:<guest> 格式\n");
                return -1;
            }
            *colon = '\0';
            cfg->binds[cfg->bind_count * 2 + 1] = strdup(colon + 1);
            cfg->bind_count++;
        } else if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--mount") == 0) {
            /*
             * `-m` / `--mount` 与 `-b` **完全同义**（proot 的选项表里
             * 两者 handler 相同），所以复用同一段逻辑。
             *
             * 注意：不能简单 `goto` 到 -b 分支 —— 大小写敏感的
             * 字符串比较已经消费了 argv[i]，直接在此重复解析更清晰。
             */
            if (i + 1 >= argc) {
                fprintf(stderr, "错误: -m/--mount 需要 <host>:<guest> 参数\n");
                return -1;
            }
            {
                char *spec = strdup(argv[++i]);
                if (spec == NULL) {
                    return -1;
                }
                char *colon = strchr(spec, ':');
                if (colon == NULL) {
                    fprintf(stderr, "错误: -m/--mount 需要 <host>:<guest> 格式\n");
                    free(spec);
                    return -1;
                }
                *colon = '\0';
                if (add_bind(cfg, spec, colon + 1) != 0) {
                    fprintf(stderr, "错误: bind 数量已达上限 %d\n", MAX_BINDS);
                    free(spec);
                    return -1;
                }
                free(spec);
            }
        } else if (strcmp(argv[i], "-0") == 0 ||
                   strcmp(argv[i], "--root-id") == 0) {
            cfg->fakeroot = 1;
        } else if (strcmp(argv[i], "--link2symlink") == 0) {
            cfg->link2symlink = 1;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            cfg->verbose = 1;
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
             * 所以这里如实告知"已接受但尚未接通"，而不是装作设置成功。
             * 接通它需要 runtime 侧在退出路径上遍历账本，属独立工作量。
             */
            cfg->kill_on_exit = 1;
            fprintf(stderr,
                    "[bxroot] 注意: --kill-on-exit 已接受，但**当前版本未接通**\n"
                    "          （需要在 runtime 的进程账本上实现退出清理，尚未实现）。\n");
        } else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--change-id") == 0) {
            /*
             * `-i <id>:<id>` —— proot 改 guest 内看到的 uid/gid。
             *
             * 本实现只支持 `0:0`（即 fakeroot）。其他取值**明确报错**，
             * 不静默忽略：用户传 `-i 1000:1000` 是想要那个身份，
             * 我们做不到却装作接受，会让后续所有权限判断都错。
             */
            if (i + 1 >= argc) {
                fprintf(stderr, "错误: -i/--change-id 需要 <id>:<id> 参数\n");
                return -1;
            }
            const char *spec = argv[++i];
            if (strcmp(spec, "0:0") == 0) {
                cfg->fakeroot = 1;
                cfg->change_id_set = 1;
            } else {
                fprintf(stderr,
                        "错误: -i/--change-id 只支持 \"0:0\"（等价于 -0）。"
                        "收到 \"%s\"。\n"
                        "      本实现不做任意 uid/gid 映射 —— 那需要完整的\n"
                        "      setuid/getuid 语义拦截，当前没有实现，\n"
                        "      与其静默忽略不如明确拒绝。\n", spec);
                return -1;
            }
        } else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--kernel-release") == 0) {
            /*
             * ★ 这是"接受但不生效"的一类，必须**明确告知** ★
             *
             * proot 的 `-k` 会伪造 `uname` 的 release 字段。本实现没有
             * uname 钩子，所以这个选项**不会**改变容器里看到的内核版本。
             *
             * 为什么不干脆像 -H/-L 那样拒绝？因为它的**失败模式很温和**：
             * 依赖 uname 版本做判断的程序（如某些安装脚本的版本检查）
             * 最多是走错分支，不会静默产生错误数据。而拒绝它会让
             * "从 proot 迁移过来"的命令行直接不可用 —— 代价更大。
             *
             * 但"接受"必须伴随**可见的告知**，否则就成了我最反对的
             * 静默降级：用户以为内核版本被改了，实际没有，
             * 然后在别处看到真实版本时一头雾水。
             */
            if (i + 1 >= argc) {
                fprintf(stderr, "错误: -k/--kernel-release 需要 <release> 参数\n");
                return -1;
            }
            free(cfg->kernel_release);
            cfg->kernel_release = strdup(argv[++i]);
            fprintf(stderr,
                    "[bxroot] 注意: -k/--kernel-release 已接受，但**当前版本不生效**\n"
                    "          （需要 uname 钩子伪造 release 字段，尚未实现）。\n"
                    "          容器内 uname 仍返回宿主真实版本。\n");
        } else if (strcmp(argv[i], "-H") == 0) {
            fprintf(stderr,
                    "错误: -H 未实现。\n"
                    "      proot 的 -H 是「隐藏 .proot.* 文件」扩展；\n"
                    "      本实现没有该扩展。明确拒绝而非静默忽略 ——\n"
                    "      静默忽略会让用户以为隐藏已生效。\n");
            return -1;
        } else if (strcmp(argv[i], "-L") == 0) {
            fprintf(stderr,
                    "错误: -L 未实现。\n"
                    "      proot 的 -L 是「修正 lstat 对符号链接返回的 size」\n"
                    "      扩展；本实现没有该扩展。明确拒绝而非静默忽略。\n");
            return -1;
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
                        "      （-H / -L / -p / -q / --sysvipc / --ashmem-memfd）。\n",
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
 * 冒号（少见但合法），用 strchr 而非 strrchr 与 proot 一致。
 */
static int add_bind(launcher_config_t *cfg, const char *host, const char *guest)
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
                skipped++;          /* 与 proot 一致：为空则跳过 */
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

    if (cfg.fakeroot)
        setenv("BXROOT_FAKEROOT", "1", 1);
    else
        unsetenv("BXROOT_FAKEROOT");

    if (cfg.verbose)
        setenv("BXROOT_VERBOSE", "1", 1);
    else
        unsetenv("BXROOT_VERBOSE");

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

    if (cfg.verbose) {
        fprintf(stderr, "[bxroot-launcher] rootfs=%s\n", cfg.rootfs);
        fprintf(stderr, "[bxroot-launcher] workdir=%s\n", cfg.workdir);
        fprintf(stderr, "[bxroot-launcher] guest=%s\n", cfg.guest_exe);
        fprintf(stderr, "[bxroot-launcher] runtime_lib=%s\n", cfg.runtime_lib);
        fprintf(stderr, "[bxroot-launcher] LD_PRELOAD=%s\n", getenv("LD_PRELOAD"));
        if (cfg.bind_count > 0)
            fprintf(stderr, "[bxroot-launcher] binds=%s\n", getenv("BXROOT_BINDS"));
        if (cfg.link2symlink)
            fprintf(stderr, "[bxroot-launcher] link2symlink=1 l2s_dir=%s\n",
                    getenv("BXROOT_L2S_DIR") ? getenv("BXROOT_L2S_DIR") : "(none)");
    }

    /* 注意: 不在 launcher 中 chdir
     * 工作目录由 runtime 库在 guest 加载后处理
     * 因为 launcher 的 chdir 会改变宿主文件系统的工作目录，
     * 而不是 rootfs 内的工作目录
     */

    /* 解析命令路径：绝对路径加 rootfs 前缀，相对路径搜索 rootfs 内的 PATH */
    char resolved_path[PATH_MAX];
    const char *cmd = cfg.guest_exe;

    if (cmd[0] == '/') {
        /* 绝对路径：加上 rootfs 前缀 */
        snprintf(resolved_path, sizeof(resolved_path), "%s%s", cfg.rootfs, cmd);
        if (access(resolved_path, F_OK) != 0) {
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
            return 1;
        }
        cfg.guest_exe = strdup(resolved_path);
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
            }
            dir = strtok_r(NULL, ":", &saveptr);
        }
        free(path_copy);

        if (!found) {
            fprintf(stderr, "错误: rootfs 内找不到命令 %s\n", cmd);
            free_config(&cfg);
            return 1;
        }
    }
    
    /* 检查路径是否存在 */
    {
        struct stat st;
        if (stat(cfg.guest_exe, &st) < 0) {
            fprintf(stderr, "[bxroot-launcher] stat(%s) failed: %s\n", cfg.guest_exe, strerror(errno));
        } else {
            fprintf(stderr, "[bxroot-launcher] stat(%s) OK, mode=%o, size=%ld\n", cfg.guest_exe, st.st_mode & 07777, (long)st.st_size);
        }
    }
    /* execve guest 程序 */
    if (cfg.verbose)
        fprintf(stderr, "[bxroot-launcher] execve: %s\n", cfg.guest_exe);

    execve(cfg.guest_exe, cfg.guest_argv, environ);

    /* 如果到这里说明 execve 失败了 */
    fprintf(stderr, "错误: execve(%s) 失败: %s\n", cfg.guest_exe, strerror(errno));
    free_config(&cfg);
    return 1;
}
