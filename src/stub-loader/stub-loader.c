/*
 * libbxroot-stub-loader.so
 *
 * 静态程序加载器：为静态链接二进制添加 ELF 解释器，
 * 使其可以通过 LD_PRELOAD 拦截系统调用。
 *
 * 设计意图（注意：这是**目标设计**，不是当前行为）
 * ---------------------------------------------------
 * 1. runtime 的 execve hook 检测到静态二进制（无 PT_INTERP）
 * 2. 将二进制复制到临时目录
 * 3. 修补 ELF header，添加 PT_INTERP 段指向本库
 * 4. execve 修补后的副本
 * 5. 内核调用本库作为解释器
 * 6. 本库加载 runtime .so，然后调用目标程序的 _start
 *
 * ★ 当前实现状态：第 1～4 步**没有接线**，第 6 步**未实现** ★
 *
 * 实测（不要凭上面的注释以为它可用）：
 *
 *   $ grep -rn 'patch_static_elf' src/ | grep -v stub-loader.c
 *   （无输出）                       ← 第 3 步的实现在本文件内，但无调用者
 *   $ grep -rn 'BXROOT_STUB_LOADER' src/ | grep -v stub-loader.c
 *   （仅 launcher.c 探测存在性后 setenv；runtime 侧只把它当"嵌套容器
 *     标记"列在字符串表里，**没有任何消费者去调用本库**）
 *
 * main() 实际走到的是末尾的**回退方案**：打印一行 TODO，然后
 * `execve(target, &argv[1], envp)` 并依赖 LD_PRELOAD。
 *
 * 所以：本 .so 目前是"构建得出、被 launcher 探测到、但功能未启用"的
 * 状态。README 的产出表据此描述为"PT_INTERP 修补器（**非独立 ELF
 * 加载器**）"，见 docs/已知限制与架构能力边界.md 的对应条目。
 * 验证命令与后果见 docs/issue扫描/汇总-行动清单.md 第 6 项
 * （正确顺序是**先接线，再修 /tmp 硬编码**，否则修了也无人走到）。
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <limits.h>

/*
 * 当本库被内核当作 ELF 解释器调用时，
 * 它接收的参数格式与动态链接器相同：
 *   argv[0] = 解释器路径
 *   argv[1] = 目标程序路径
 *   argv[2..] = 目标程序参数
 */

/*
 * patch_static_elf() 接受的 program header 数量上限。
 *
 * e_phnum 是 16 位字段（理论上限 65535），不能拿它直接做分配尺寸。
 * 128 是 docs/指针安全审计.md 对 M3 的建议值：真实 ELF 的 program
 * header 数是个位到几十（内核自身约 10 个），128 足够宽松而把
 * 损坏/恶意输入挡在外面。
 */
#define STUB_MAX_PHNUM 128

/* 获取本库所在目录 */
static int get_lib_dir(char *dir, size_t dir_size) {
    char exe[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n <= 0) return -1;
    exe[n] = '\0';
    char *slash = strrchr(exe, '/');
    if (!slash) return -1;
    size_t len = slash - exe;
    if (len >= dir_size) return -1;
    memcpy(dir, exe, len);
    dir[len] = '\0';
    return 0;
}

/* 获取环境变量 */
static const char *getenv_safe(const char *name) {
    const char *val = getenv(name);
    return val && val[0] ? val : NULL;
}

/*
 * 取 runtime .so 的路径。
 *
 * ★ 必须由调用方提供缓冲区 ★
 *
 * 原先 load_runtime() 里是这么写的：
 *
 *     const char *runtime_path = getenv("BXROOT_RUNTIME_LIB");
 *     if (!runtime_path) {
 *         char path[PATH_MAX];                 ← 块内局部数组
 *         snprintf(path, sizeof(path), "%s/libbxroot-runtime.so", lib_dir);
 *         runtime_path = path;                 ← 指向块内数组
 *     }
 *     dlopen(runtime_path, ...);               ← 出块后已悬空
 *     fprintf(..., runtime_path);              ← 二次使用悬空指针
 *
 * `path` 的生命周期在 `if` 块结束时就终止了，而 `runtime_path` 在块外
 * 仍被 dlopen 与 fprintf 使用 —— 读到的是**已被回收的栈**。gcc 在
 * -Wdangling-pointer 下直接报出（该告警此前被漏检，见下文"为什么本
 * 文件终于被门禁覆盖"）。改成把结果写进调用方给的缓冲区，生命周期
 * 与调用方一致。
 *
 * 返回：0 成功；-1 路径过长（原先 snprintf 截断是静默的，会 dlopen 一个
 * 被截断的路径）。
 */
static int get_runtime_lib_path(char *out, size_t outsz, const char *lib_dir)
{
    const char *env = getenv_safe("BXROOT_RUNTIME_LIB");
    int n;

    if (env != NULL) {
        n = snprintf(out, outsz, "%s", env);
    } else {
        n = snprintf(out, outsz, "%s/libbxroot-runtime.so", lib_dir);
    }
    if (n < 0 || (size_t)n >= outsz)
        return -1;      /* 截断即失败，不把半截路径交给 dlopen */
    return 0;
}

/* 加载 runtime .so */
static void load_runtime(const char *lib_dir) {
    char runtime_path[PATH_MAX];

    if (get_runtime_lib_path(runtime_path, sizeof(runtime_path), lib_dir) != 0) {
        fprintf(stderr, "[stub-loader] runtime lib path too long\n");
        return;
    }

    void *handle = dlopen(runtime_path, RTLD_LAZY | RTLD_GLOBAL);
    if (!handle) {
        fprintf(stderr, "[stub-loader] dlopen failed: %s\n", dlerror());
        return;
    }

    fprintf(stderr, "[stub-loader] runtime loaded: %s\n", runtime_path);
}

/*
 * 修补静态 ELF 二进制，添加 PT_INTERP 段。
 * 返回修补后的临时文件路径，失败返回 NULL。
 *
 * ★ 本函数当前**未被任何代码调用**（整条 PT_INTERP 修补路径未接线，
 *   main 走的是下面"回退方案：execve + LD_PRELOAD"）。这是已知状态：
 *   见 docs/指针安全审计.md 的 M3 条与 docs/已知限制与架构能力边界.md
 *   对 stub-loader 的定位说明（"非独立 ELF 加载器"）。保留实现是为了
 *   让未来的接线工作有基础，**不要**因为"没有调用者"就删掉它。
 *
 *   也正因为没有调用者，它此前的告警（VLA 尺寸、unused）在构建里
 *   一直没被暴露 —— 本文件此前**整体不在告警门禁的 UNITS 清单里**。
 */
/*
 * ★ 函数上挂 unused 属性是**如实标注**，不是压制告警 ★
 *
 * 本函数当前没有任何调用者（PT_INTERP 修补这条路径整体未接线，
 * main 走的是下面的 execve + LD_PRELOAD 回退）。但它是**有意保留**的：
 * 见 docs/指针安全审计.md M3 条（该文档要求"接线时同时修掉"这些缺陷，
 * 已在本函数内修好）与 docs/已知限制与架构能力边界.md 对 stub-loader
 * 的定位说明。项目的既定约束是"不删软件"。
 *
 * 所以正确做法不是删掉它（会让未来的接线工作失去基础），也不是让
 * -Wunused-function 静默存在（本项目要求零告警，且该告警真实反映了
 * "这段代码没被任何测试覆盖"这一事实），而是显式声明"我知道它没被
 * 调用"。将来接线后**必须删掉这个属性**，让编译器重新接管检查。
 */
__attribute__((unused))
static char *patch_static_elf(const char *original_path, const char *interpreter_path) {
    struct stat st;
    off_t phdr_off_t, phdr_bytes;

    /* 打开原始文件 */
    int fd = open(original_path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "[stub-loader] open failed: %s\n", original_path);
        return NULL;
    }

    /* 读取 ELF header */
    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        close(fd);
        return NULL;
    }

    /* 检查是否是 64-bit ELF */
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        close(fd);
        return NULL;
    }

    /* 检查是否已经有 PT_INTERP */
    if (ehdr.e_phoff == 0 || ehdr.e_phentsize < sizeof(Elf64_Phdr)) {
        close(fd);
        return NULL;
    }

    /* 读取 program headers
     *
     * ★ 不能用 VLA：`Elf64_Phdr phdr[ehdr.e_phnum]` ★
     *
     * `e_phnum` 是 **16 位**字段（Elf64_Ehdr 里是 Elf64_Half），所以这个
     * 数组最大 65535 × 56 ≈ 3.6 MB —— 一次性要 3.6 MB 的**栈**，是
     * 未检查的栈分配；常见的损坏/恶意 ELF 给出 e_phnum=1000 就有 56 KB。
     * 这是 docs/指针安全审计.md 的 M3（该文档建议 e_phnum 上限取 128）。
     *
     * 改成"校验数量上限 → 堆分配 → 校验 phdr 表落在文件内"：
     */
    if (ehdr.e_phnum == 0 || ehdr.e_phnum > STUB_MAX_PHNUM) {
        close(fd);
        return NULL;
    }
    phdr_off_t = ehdr.e_phoff;
    phdr_bytes = (off_t)ehdr.e_phnum * (off_t)sizeof(Elf64_Phdr);

    /* phdr 表必须完整落在文件内（否则下面的 read 拿到的就是短读/垃圾） */
    if (fstat(fd, &st) < 0 || phdr_off_t < 0 ||
        phdr_bytes <= 0 ||
        phdr_off_t + phdr_bytes > st.st_size) {
        close(fd);
        return NULL;
    }

    Elf64_Phdr *phdr = malloc((size_t)ehdr.e_phnum * sizeof(Elf64_Phdr));
    if (phdr == NULL) {
        close(fd);
        return NULL;
    }
    if (lseek(fd, phdr_off_t, SEEK_SET) < 0) {
        free(phdr);
        close(fd);
        return NULL;
    }
    if (read(fd, phdr, (size_t)phdr_bytes) != (ssize_t)phdr_bytes) {
        free(phdr);
        close(fd);
        return NULL;
    }

    int has_interp = 0;
    for (int i = 0; i < ehdr.e_phnum; i++) {
        if (phdr[i].p_type == PT_INTERP) {
            has_interp = 1;
            break;
        }
    }

    if (has_interp) {
        /* 已经是动态链接，不需要修补 */
        free(phdr);
        close(fd);
        return NULL;
    }

    /* 创建临时文件 */
    char tmp_path[PATH_MAX];
    {
        /* 原名可能很长：必须检查截断，否则会静默用错文件名 */
        const char *slash = strrchr(original_path, '/');
        const char *base = slash ? slash + 1 : "binary";
        int n = snprintf(tmp_path, sizeof(tmp_path), "/tmp/.bxroot_stub_%ld_%s",
                         (long)getpid(), base);
        if (n < 0 || (size_t)n >= sizeof(tmp_path)) {
            free(phdr);
            close(fd);
            return NULL;
        }
    }

    int tmp_fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (tmp_fd < 0) {
        free(phdr);
        close(fd);
        return NULL;
    }

    /* 读取整个文件到内存（`st` 已在上面的 phdr 表校验里填好） */
    char *file_data = malloc(st.st_size);
    if (!file_data) {
        free(phdr);
        close(fd);
        close(tmp_fd);
        return NULL;
    }

    lseek(fd, 0, SEEK_SET);
    if (read(fd, file_data, st.st_size) != st.st_size) {
        free(file_data);
        free(phdr);
        close(fd);
        close(tmp_fd);
        return NULL;
    }
    close(fd);

    /* 在文件末尾添加解释器路径字符串 */
    char interp_str[PATH_MAX];
    strncpy(interp_str, interpreter_path, sizeof(interp_str));
    interp_str[sizeof(interp_str) - 1] = '\0';
    size_t interp_len = strlen(interp_str) + 1;

    /* 写入修补后的文件 */
    write(tmp_fd, file_data, st.st_size);

    /* 添加 PT_INTERP 段 */
    Elf64_Phdr interp_phdr;
    memset(&interp_phdr, 0, sizeof(interp_phdr));
    interp_phdr.p_type = PT_INTERP;
    interp_phdr.p_flags = PF_R;
    interp_phdr.p_offset = st.st_size;  /* 解释器路径在文件末尾 */
    interp_phdr.p_vaddr = 0;
    interp_phdr.p_paddr = 0;
    interp_phdr.p_filesz = interp_len;
    interp_phdr.p_memsz = interp_len;
    interp_phdr.p_align = 1;
    write(tmp_fd, &interp_phdr, sizeof(interp_phdr));

    /* 写入解释器路径字符串 */
    write(tmp_fd, interp_str, interp_len);

    /* 更新 ELF header */
    Elf64_Ehdr new_ehdr;
    memcpy(&new_ehdr, &ehdr, sizeof(ehdr));
    new_ehdr.e_phnum++;  /* 增加一个 program header */

    /* 需要重写 ELF header 和所有 program headers */
    lseek(tmp_fd, 0, SEEK_SET);
    write(tmp_fd, &new_ehdr, sizeof(ehdr));

    /* 重写 program headers（需要跳过被移动的） */
    lseek(tmp_fd, new_ehdr.e_phoff, SEEK_SET);
    for (int i = 0; i < ehdr.e_phnum; i++) {
        write(tmp_fd, &phdr[i], sizeof(Elf64_Phdr));
    }

    close(tmp_fd);
    free(file_data);
    free(phdr);

    fprintf(stderr, "[stub-loader] patched: %s -> %s\n", original_path, tmp_path);

    return strdup(tmp_path);
}

/*
 * 本库的主入口点。
 * 当被内核作为 ELF 解释器调用时，这是入口。
 * 参数与 ld-linux.so 相同。
 */
int main(int argc, char **argv, char **envp) {
    fprintf(stderr, "[stub-loader] main: argc=%d\n", argc);

    if (argc < 2) {
        fprintf(stderr, "[stub-loader] usage: %s <binary>\n", argv[0]);
        return 1;
    }

    /* argv[0] 是解释器路径，argv[1] 是目标程序 */
    const char *target = argv[1];
    fprintf(stderr, "[stub-loader] target: %s\n", target);

    /* 获取本库目录 */
    char lib_dir[PATH_MAX];
    if (get_lib_dir(lib_dir, sizeof(lib_dir)) < 0) {
        fprintf(stderr, "[stub-loader] cannot determine lib dir\n");
        return 1;
    }

    /* 加载 runtime .so */
    load_runtime(lib_dir);

    /* 设置环境变量让 runtime 知道路径 */
    setenv("BXROOT_STUB_LOADER", "1", 1);

    /* 调用目标程序的 _start */
    /* 注意：这里需要加载目标程序并跳转到其入口点 */
    /* 完整实现需要 mmap + 符号解析，这里简化处理 */

    /* 简化实现：直接 execve 目标程序（带 LD_PRELOAD） */
    /* 由于我们是通过 ELF interpreter 调用的，目标程序已经被映射 */
    /* 但我们需要跳转到目标程序的 _start */

    /* 完整的实现需要：
     * 1. 解析目标程序的 ELF header
     * 2. 加载目标程序的段到内存
     * 3. 找到 _start 入口点
     * 4. 跳转到 _start
     * 5. 在返回时处理信号和清理
     *
     * 这是一个复杂的实现，涉及 ELF 加载器逻辑。
     */

    fprintf(stderr, "[stub-loader] TODO: implement ELF loader and jump to _start\n");
    fprintf(stderr, "[stub-loader] fallback: execve with LD_PRELOAD\n");

    /* 回退方案：直接 execve，依赖 LD_PRELOAD */
    const char *preload = getenv("LD_PRELOAD");
    if (!preload) {
        char preload_path[PATH_MAX];
        /* 与 load_runtime 共用取路径逻辑，避免两处各写一遍 snprintf
         * （两处原先都无截断检查，-Wformat-truncation 会各报一条） */
        if (get_runtime_lib_path(preload_path, sizeof(preload_path), lib_dir) != 0) {
            fprintf(stderr, "[stub-loader] runtime lib path too long\n");
            return 1;
        }
        setenv("LD_PRELOAD", preload_path, 1);
    }

    execve(target, &argv[1], envp);

    /* 如果到这里说明 execve 失败了 */
    fprintf(stderr, "[stub-loader] execve failed: %s\n", strerror(errno));
    return 1;
}
