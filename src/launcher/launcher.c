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

/* 最大 bind mount 数量 */
#define MAX_BINDS 16

/* 默认 rootfs */
#ifndef BXROOT_DEFAULT_ROOTFS
#define BXROOT_DEFAULT_ROOTFS "/data/local/tmp/rootfs"
#endif

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
    char *runtime_lib;  /* 从 BXROOT_LIB_PATH 或自动探测 */
    char *linker_lib;
    char *stub_loader;
} launcher_config_t;

static void usage(const char *prog) {
    fprintf(stderr,
        "用法: %s [选项] <command> [args...]\n\n"
        "选项:\n"
        "  -r <rootfs>          rootfs 路径\n"
        "  -w <dir>             工作目录 (默认 /)\n"
        "  -b <host>:<guest>    bind mount (可多次)\n"
        "  -0                   fakeroot 模式\n"
        "  --link2symlink       硬链接模拟为符号链接\n"
        "  -v / --verbose       调试模式\n"
        "  -h / --help          帮助\n\n"
        "示例:\n"
        "  %s -r /data/rootfs -b /sdcard:/sdcard /bin/sh\n"
        "  %s -r /data/rootfs -0 /usr/bin/node --version\n",
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

    int i = 1;
    while (i < argc) {
        if (strcmp(argv[i], "-r") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "错误: -r 需要参数\n");
                return -1;
            }
            free(cfg->rootfs);
            cfg->rootfs = strdup(argv[++i]);
        } else if (strcmp(argv[i], "-w") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "错误: -w 需要参数\n");
                return -1;
            }
            free(cfg->workdir);
            cfg->workdir = strdup(argv[++i]);
        } else if (strcmp(argv[i], "-b") == 0) {
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
        } else if (strcmp(argv[i], "-0") == 0) {
            cfg->fakeroot = 1;
        } else if (strcmp(argv[i], "--link2symlink") == 0) {
            cfg->link2symlink = 1;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            cfg->verbose = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            exit(0);
        } else {
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
        snprintf(runtime_lib, sizeof(runtime_lib), "%s/%s", lib_dir, LIBBXROOT_RUNTIME);
        cfg.runtime_lib = strdup(runtime_lib);
    }

    /* 构建 linker 和 stub-loader 路径（如果存在） */
    char linker_lib[PATH_MAX], stub_lib[PATH_MAX];
    snprintf(linker_lib, sizeof(linker_lib), "%s/%s", lib_dir, LIBBXROOT_LINKER);
    snprintf(stub_lib, sizeof(stub_lib), "%s/%s", lib_dir, LIBBXROOT_STUB_LOADER);
    if (access(linker_lib, F_OK) == 0)
        cfg.linker_lib = strdup(linker_lib);
    if (access(stub_lib, F_OK) == 0)
        cfg.stub_loader = strdup(stub_lib);

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
