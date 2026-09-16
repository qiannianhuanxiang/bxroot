/*
 * libbxroot-stub-loader.so
 *
 * 静态程序加载器：为静态链接二进制添加 ELF 解释器，
 * 使其可以通过 LD_PRELOAD 拦截系统调用。
 *
 * 工作原理：
 * 1. runtime 的 execve hook 检测到静态二进制（无 PT_INTERP）
 * 2. 将二进制复制到临时目录
 * 3. 修补 ELF header，添加 PT_INTERP 段指向本库
 * 4. execve 修补后的副本
 * 5. 内核调用本库作为解释器
 * 6. 本库加载 runtime .so，然后调用目标程序的 _start
 *
 * 参考：上游 proroot 的 stub-loader 实现
 */

#define _GNU_SOURCE
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

/* 加载 runtime .so */
static void load_runtime(const char *lib_dir) {
    const char *runtime_path = getenv("BXROOT_RUNTIME_LIB");
    if (!runtime_path) {
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/libbxroot-runtime.so", lib_dir);
        runtime_path = path;
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
 */
static char *patch_static_elf(const char *original_path, const char *interpreter_path) {
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

    /* 读取 program headers */
    Elf64_Phdr phdr[ehdr.e_phnum];
    if (lseek(fd, ehdr.e_phoff, SEEK_SET) < 0) {
        close(fd);
        return NULL;
    }
    if (read(fd, phdr, ehdr.e_phnum * sizeof(Elf64_Phdr)) !=
        ehdr.e_phnum * sizeof(Elf64_Phdr)) {
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
        close(fd);
        return NULL;
    }

    /* 创建临时文件 */
    char tmp_path[PATH_MAX];
    snprintf(tmp_path, sizeof(tmp_path), "/tmp/.bxroot_stub_%ld_%s",
             (long)getpid(), strrchr(original_path, '/') ?
             strrchr(original_path, '/') + 1 : "binary");

    int tmp_fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (tmp_fd < 0) {
        close(fd);
        return NULL;
    }

    /* 获取文件大小 */
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        close(tmp_fd);
        return NULL;
    }

    /* 读取整个文件到内存 */
    char *file_data = malloc(st.st_size);
    if (!file_data) {
        close(fd);
        close(tmp_fd);
        return NULL;
    }

    lseek(fd, 0, SEEK_SET);
    if (read(fd, file_data, st.st_size) != st.st_size) {
        free(file_data);
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

    /* 计算新文件大小 */
    size_t new_size = st.st_size + interp_len + sizeof(Elf64_Phdr);

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
        snprintf(preload_path, sizeof(preload_path), "%s/libbxroot-runtime.so", lib_dir);
        setenv("LD_PRELOAD", preload_path, 1);
    }

    execve(target, &argv[1], envp);

    /* 如果到这里说明 execve 失败了 */
    fprintf(stderr, "[stub-loader] execve failed: %s\n", strerror(errno));
    return 1;
}
