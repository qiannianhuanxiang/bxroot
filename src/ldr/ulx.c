/*
 * bxroot-ulx —— 用户态 exec：在「SIGSYS→ENOSYS 处理器已装好」的进程里
 *               装载并跳进 guest 的 ELF 解释器（ld.so）
 *
 * 产物名 libbxroot-ulx.so（与 launcher 同理伪装成 .so，便于随 APK 的
 * nativeLibraryDir 分发——那是 app 唯一可执行的目录），实际是静态可执行文件。
 *
 * ★ 为什么需要（2026-09-27 Termux 真机实测，vivo / Android 16 / 6.1 内核）★
 *
 * app 沙箱的 seccomp 对 set_robust_list / rseq 是 RET_TRAP。guest 的 ld.so
 * 在 __libc_early_init 里就发这两个调用 —— 早于 --preload 进来的 runtime
 * 的任何代码。内核 execve 之后信号处置被重置，没有处理器 → 进程被杀：
 *
 *     ld-linux-aarch64.so.1 --preload libbxroot-runtime.so /usr/bin/echo hi
 *     → killed by SIGSYS (set_robust_list)          ← runtime 构造函数还没跑
 *
 * 做法：不经内核 execve，而是本进程自己 mmap ld.so、搭好初始栈与 auxv、
 * 直接跳到它的入口。信号处置在同一进程内保留，所以 early_sigsys.h 装的
 * 处理器一直有效；runtime 构造函数随后接管（sigsys_install + livepatch）。
 *
 * 用法（与 proc.c px_trampoline_exec 的 argv 约定一致，可直接当
 * PROROOT_TRAMPOLINE_PATH 使用）：
 *
 *     libbxroot-ulx.so <ld.so 宿主路径> [ld.so 选项...] <程序> [参数...]
 *
 * 若调用方没给 --library-path，且环境里有 BXROOT_ROOTFS，则自动补上
 * rootfs 的标准库目录 —— ld.so 在 runtime 装上之前只认宿主路径，而宿主
 * （Android）没有 /lib、没有 /etc/ld.so.cache。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/stat.h>   /* fstat：校验 p_offset+p_filesz <= 文件大小 */
#include <sys/syscall.h>
#include <unistd.h>

#include "early_sigsys.h"
#include "ulx-libpath.h"

#define ULX_MAX_PHDR   64
#define ULX_STACK_SIZE (8UL << 20)

static void die(int rc, const char *what, const char *arg)
{
    fprintf(stderr, "bxroot-ulx: %s%s%s\n", what, arg ? ": " : "", arg ? arg : "");
    _exit(rc);
}

typedef struct {
    unsigned long base;     /* 装载偏移（ET_EXEC 为 0） */
    unsigned long entry;
    unsigned long phdr;     /* 程序头在内存中的地址 */
    unsigned phnum;
} ulx_image;

static int load_elf(const char *path, ulx_image *img)
{
    Elf64_Ehdr eh;
    Elf64_Phdr ph[ULX_MAX_PHDR];
    unsigned long lo = ~0UL, hi = 0, align = 4096, ps = (unsigned long)getpagesize();
    unsigned long fsize = 0;
    struct stat fst;
    int fd, i;
    char *res;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    /*
     * ★ 取文件大小：后面要校验 p_offset+p_filesz <= fsize（缺陷修复，2026-10-18）★
     * 截断的 ELF 若映射越过 EOF，首次访问就是 SIGBUS —— 必须在映射前拒绝。
     */
    if (fstat(fd, &fst) != 0 || fst.st_size < 0) {
        close(fd);
        errno = ENOEXEC;
        return -1;
    }
    fsize = (unsigned long)fst.st_size;
    if (pread(fd, &eh, sizeof eh, 0) != (ssize_t)sizeof eh ||
        memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 || eh.e_ident[EI_CLASS] != ELFCLASS64 ||
        eh.e_machine != EM_AARCH64 || (eh.e_type != ET_DYN && eh.e_type != ET_EXEC) ||
        eh.e_phentsize != sizeof(Elf64_Phdr) || eh.e_phnum == 0 || eh.e_phnum > ULX_MAX_PHDR ||
        pread(fd, ph, sizeof(Elf64_Phdr) * eh.e_phnum, (off_t)eh.e_phoff) !=
            (ssize_t)(sizeof(Elf64_Phdr) * eh.e_phnum)) {
        close(fd);
        errno = ENOEXEC;
        return -1;
    }
    for (i = 0; i < eh.e_phnum; i++) {
        if (ph[i].p_type == PT_INTERP) {     /* 只装解释器/静态程序，不做两级装载 */
            close(fd);
            errno = ENOEXEC;
            return -1;
        }
        if (ph[i].p_type != PT_LOAD)
            continue;
        /*
         * ★ 坏/恶意 ELF 一律在**任何映射之前**拒绝（缺陷修复，2026-10-18）★
         *
         * 本文件原先只校验 ELF 头，直接按 p_memsz 算预留区、按 p_filesz
         * 做 MAP_FIXED。三条后果（与 static_exec.c:485-491 同源，那边
         * 早已加固，这里漏了）：
         *
         *   ① p_filesz > p_memsz → 映射长度越过 PROT_NONE 预留区，
         *      MAP_FIXED 会把**相邻映射**直接撕掉（不是失败，是静默破坏）；
         *   ② p_vaddr + p_memsz 回绕 → hi 被算小，`hi <= lo` 兜不住，
         *      段内偏移 me-a 再回绕 → 从 base-0x1000 起映射；
         *   ③ p_offset + p_filesz 越过文件末尾 → 映射成功但首次访问
         *      SIGBUS；p_offset < 页内偏移时 off-d 下溢成负 offset →
         *      好 ELF 被误判失败。
         *
         * 判据与 static_exec.c 保持一致，便于两处同改同测。
         *
         * 【漏点（实测，2026-10-20）】下面这段只查了 `hi + ps < hi`，
         * 漏了 **`hi - lo + align` 自身的回绕**（static_exec.c:494 早就有
         * 后一条判据）。ET_DYN 分支用 `hi - lo + align` 做预留，构造
         * p_vaddr 正常 + 一个 p_vaddr 贴近 2^64 的 PT_LOAD 就能让
         * `hi - lo ≈ 2^64 - align + K`：
         *
         *     hi=0xFFFFFFFFFFFF1000, lo=0, align=0x10000
         *     hi - lo + align = 0x1000        ← 只预留 1 页，mmap 成功
         *
         * 随后段按 `img->base + p_vaddr` 做 **MAP_FIXED**，落在预留区
         * **之外**的相邻映射上 —— 不是失败，是静默覆盖别人的页
         * （与 static_exec.c 修掉的是同一类缺陷）。判据补上后该 ELF
         * 直接 ENOEXEC，不做任何映射。
         */
        if (ph[i].p_filesz > ph[i].p_memsz ||
            ph[i].p_vaddr + ph[i].p_memsz < ph[i].p_vaddr ||
            ph[i].p_offset + ph[i].p_filesz < ph[i].p_offset ||
            ph[i].p_offset + ph[i].p_filesz > fsize ||
            (ph[i].p_align != 0 &&
             (ph[i].p_align & (ph[i].p_align - 1)) != 0) ||
            ph[i].p_align > (1UL << 30) ||
            (ph[i].p_align > 1 &&
             (ph[i].p_vaddr % ph[i].p_align) != (ph[i].p_offset % ph[i].p_align))) {
            close(fd);
            errno = ENOEXEC;
            return -1;
        }
        if (ph[i].p_align > align)
            align = ph[i].p_align;
        if ((ph[i].p_vaddr & ~(ps - 1)) < lo)
            lo = ph[i].p_vaddr & ~(ps - 1);
        if (ph[i].p_vaddr + ph[i].p_memsz > hi)
            hi = ph[i].p_vaddr + ph[i].p_memsz;
    }
    if (hi <= lo || hi + ps < hi ||   /* ps 取整后可能回绕，一并查 */
        hi - lo + align < hi - lo) {  /* ET_DYN 预留长度 = hi-lo+align 自身回绕 */
        close(fd);
        errno = ENOEXEC;
        return -1;
    }
    if (eh.e_type == ET_EXEC) {
        res = mmap((void *)lo, hi - lo, PROT_NONE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (res == MAP_FAILED) {
            close(fd);
            return -1;
        }
        img->base = 0;
    } else {
        /* 按最大 p_align 对齐保留整段地址空间（16K/64K 页的库都能装） */
        res = mmap(NULL, hi - lo + align, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (res == MAP_FAILED) {
            close(fd);
            return -1;
        }
        img->base = (((unsigned long)res + align - 1) & ~(align - 1)) - lo;
    }
    img->phdr = 0;
    for (i = 0; i < eh.e_phnum; i++) {
        unsigned long va, off, a, d, fe, fpe, me;
        int prot;

        if (ph[i].p_type != PT_LOAD)
            continue;
        va = ph[i].p_vaddr;
        off = ph[i].p_offset;
        a = va & ~(ps - 1);
        d = va - a;
        prot = ((ph[i].p_flags & PF_R) ? PROT_READ : 0) |
               ((ph[i].p_flags & PF_W) ? PROT_WRITE : 0) |
               ((ph[i].p_flags & PF_X) ? PROT_EXEC : 0);
        if (ph[i].p_filesz > 0 &&
            mmap((void *)(img->base + a), ph[i].p_filesz + d, prot,
                 MAP_PRIVATE | MAP_FIXED, fd, (off_t)(off - d)) == MAP_FAILED) {
            close(fd);
            return -1;
        }
        fe = va + ph[i].p_filesz;
        fpe = (fe + ps - 1) & ~(ps - 1);
        me = va + ph[i].p_memsz;
        if (ph[i].p_memsz > ph[i].p_filesz) {
            /* .bss：文件页尾部清零 + 其余匿名映射 */
            if (ph[i].p_filesz > 0 && fpe > fe) {
                if (!(prot & PROT_WRITE))
                    mprotect((void *)(img->base + (fe & ~(ps - 1))), ps, prot | PROT_WRITE);
                memset((void *)(img->base + fe), 0, fpe - fe);
                if (!(prot & PROT_WRITE))
                    mprotect((void *)(img->base + (fe & ~(ps - 1))), ps, prot);
            }
            if (me > fpe &&
                mmap((void *)(img->base + (ph[i].p_filesz > 0 ? fpe : a)),
                     me - (ph[i].p_filesz > 0 ? fpe : a), prot,
                     MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0) == MAP_FAILED) {
                close(fd);
                return -1;
            }
        }
        if (eh.e_phoff >= off && eh.e_phoff + sizeof(Elf64_Phdr) * eh.e_phnum <= off + ph[i].p_filesz)
            img->phdr = img->base + va + (eh.e_phoff - off);
    }
    close(fd);
    img->entry = img->base + eh.e_entry;
    img->phnum = eh.e_phnum;
    return 0;
}

static int has_opt(char **argv, int from, const char *opt)
{
    int i;
    for (i = from; argv[i] != NULL && argv[i][0] == '-'; i++) {
        if (strcmp(argv[i], opt) == 0)
            return 1;
        /* 带值的 ld.so 选项跳过其值 */
        if (!strcmp(argv[i], "--library-path") || !strcmp(argv[i], "--preload") ||
            !strcmp(argv[i], "--argv0") || !strcmp(argv[i], "--audit") ||
            !strcmp(argv[i], "--inhibit-rpath"))
            i++;
        if (argv[i] == NULL)
            break;
    }
    return 0;
}

int main(int argc, char **argv, char **envp)
{
    static const char *const libdirs[] = {
        "/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu",
        "/usr/local/lib/aarch64-linux-gnu", "/lib", "/usr/lib", "/usr/local/lib",
        /* Ubuntu keeps systemd's private shared object beside its helpers. */
        "/usr/lib/aarch64-linux-gnu/systemd",
    };
    char libpath[BXROOT_ULX_LIBPATH_SIZE];
    const char *rf = getenv("BXROOT_ROOTFS");
    /*
     * ★ rootfs 兜底（2026-10-26，真机 ulx 失败根因）★
     *
     * 下面的 --library-path 是 ld.so 找到 guest libc 的唯一来源：
     *     add_lp = (rf != NULL && rf[0] == '/' && !has_opt(...))
     * 若 rf 为空则 add_lp=0，ld.so 直接报
     *     "libc.so.6: cannot open shared object file"
     * （实测：不设 BXROOT_ROOTFS → 失败；设了 → 成功；手动加
     *  --library-path → 也成功。三者一一对应。）
     *
     * 而 PTC 会把所有非启动环境变量设成 undefined，BXROOT_ROOTFS
     * 也在其中 —— 于是 worker 里 rf 恒为 NULL，ULX 必然失败。
     * 这正是「trampoline 配置明明对、却仍然跑不起来」的原因。
     *
     * 兜底：从 argv[1]（ld.so 的宿主绝对路径）反推 rootfs。
     * ld.so 一定在 <rootfs>/lib/ 或 <rootfs>/usr/lib/ 下，
     * 找到这两个片段就截断。argv[1] 是调度方给的绝对路径，
     * 不受环境变量影响。
     */
    if (rf == NULL || rf[0] != '/') {
        static char s_rf[4096];
        const char *p;
        if (argc >= 2 && argv[1] != NULL && argv[1][0] == '/') {
            p = strstr(argv[1], "/usr/lib/");
            if (p == NULL)
                p = strstr(argv[1], "/lib/");
            if (p != NULL && (size_t)(p - argv[1]) < sizeof(s_rf)) {
                memcpy(s_rf, argv[1], (size_t)(p - argv[1]));
                s_rf[p - argv[1]] = '\0';
                if (s_rf[0] == '/')
                    rf = s_rf;
            }
        }
    }
    if (rf == NULL || rf[0] != '/') {
        /* 最后兜底：PROROOT_ROOTFS（嵌套场景里外层可能设过） */
        const char *alt = getenv("PROROOT_ROOTFS");
        if (alt != NULL && alt[0] == '/')
            rf = alt;
    }
    char **nargv, **p;
    int nargc = 0, nenv = 0, i, add_lp;
    ulx_image img;
    unsigned long av[64], *sp, *w;
    int na = 0;
    char *stk, *top, *rnd, *execfn;
    sigset_t none;

    if (argc < 3)
        die(2, "用法: libbxroot-ulx.so <ld.so> [ld.so 选项...] <程序> [参数...]", NULL);

    if (load_elf(argv[1], &img) != 0) {
        int e = errno;
        fprintf(stderr, "bxroot-ulx: 装载 %s 失败: %s\n", argv[1], strerror(e));
        _exit(e == ENOENT ? 127 : 126);
    }

    /* ULX's explicit --library-path overrides LD_LIBRARY_PATH in glibc.
     * Build one translated guest path so package-private directories and a
     * caller-provided path both remain visible to the guest loader. */
    add_lp = (rf != NULL && rf[0] == '/' && !has_opt(argv, 2, "--library-path"));
    if (add_lp) {
        size_t n = 0;
        const char *env_lp = bxroot_ulx_env_value(envp, "LD_LIBRARY_PATH");

        for (i = 0; i < (int)(sizeof libdirs / sizeof libdirs[0]); i++) {
            if (bxroot_ulx_append_libdir(libpath, sizeof libpath, &n, rf, libdirs[i]) != 0)
                die(126, "库搜索路径过长", NULL);
        }
        if (bxroot_ulx_append_env_libpath(libpath, sizeof libpath, &n, rf, env_lp) != 0)
            die(126, "LD_LIBRARY_PATH 过长", NULL);
    }

    nargv = calloc((size_t)argc + 4, sizeof(char *));
    if (nargv == NULL)
        die(126, "内存不足", NULL);
    nargv[nargc++] = argv[1];
    if (add_lp) {
        nargv[nargc++] = (char *)"--library-path";
        nargv[nargc++] = libpath;
    }
    for (i = 2; i < argc; i++)
        nargv[nargc++] = argv[i];
    for (p = envp; *p; p++)
        nenv++;

    /* 新栈：字符串 → AT_RANDOM → 指针区（16 字节对齐） */
    stk = mmap(NULL, ULX_STACK_SIZE, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK | MAP_GROWSDOWN, -1, 0);
    if (stk == MAP_FAILED)
        die(126, "栈分配失败", NULL);
    top = stk + ULX_STACK_SIZE;
#define PUSHSTR(dst, s) do { size_t _l = strlen(s) + 1; top -= _l; memcpy(top, (s), _l); (dst) = top; } while (0)
    {
        char **sa = calloc((size_t)nargc + 1, sizeof(char *));
        char **se = calloc((size_t)nenv + 1, sizeof(char *));
        if (sa == NULL || se == NULL)
            die(126, "内存不足", NULL);
        for (i = nargc - 1; i >= 0; i--)
            PUSHSTR(sa[i], nargv[i]);
        for (i = nenv - 1; i >= 0; i--)
            PUSHSTR(se[i], envp[i]);
        PUSHSTR(execfn, argv[1]);
        top = (char *)((unsigned long)top & ~15UL) - 16;
        rnd = top;
        memcpy(rnd, (void *)getauxval(AT_RANDOM), 16);

#define AUX(k, v) do { av[na++] = (unsigned long)(k); av[na++] = (unsigned long)(v); } while (0)
        if (getauxval(AT_SYSINFO_EHDR))
            AUX(AT_SYSINFO_EHDR, getauxval(AT_SYSINFO_EHDR));
        AUX(AT_HWCAP, getauxval(AT_HWCAP));
        AUX(AT_HWCAP2, getauxval(AT_HWCAP2));
        AUX(AT_PAGESZ, getauxval(AT_PAGESZ));
        AUX(AT_CLKTCK, getauxval(AT_CLKTCK));
        AUX(AT_PHDR, img.phdr);
        AUX(AT_PHENT, sizeof(Elf64_Phdr));
        AUX(AT_PHNUM, img.phnum);
        AUX(AT_BASE, 0);
        AUX(AT_FLAGS, 0);
        AUX(AT_ENTRY, img.entry);
        AUX(AT_UID, getuid());
        AUX(AT_EUID, geteuid());
        AUX(AT_GID, getgid());
        AUX(AT_EGID, getegid());
        AUX(AT_SECURE, 0);
        AUX(AT_RANDOM, rnd);
        AUX(AT_EXECFN, execfn);
        AUX(AT_NULL, 0);

        sp = (unsigned long *)(((unsigned long)top -
                                (size_t)(1 + nargc + 1 + nenv + 1 + na) * 8) & ~15UL);
        w = sp;
        *w++ = (unsigned long)nargc;
        for (i = 0; i < nargc; i++)
            *w++ = (unsigned long)sa[i];
        *w++ = 0;
        for (i = 0; i < nenv; i++)
            *w++ = (unsigned long)se[i];
        *w++ = 0;
        memcpy(w, av, (size_t)na * 8);
    }

    /* 交出控制权前清空信号掩码（内核 execve 语义是保留掩码，但我们自己
     * 不应多屏蔽任何东西；SIGSYS 被屏蔽时 TRAP 会直接杀进程） */
    sigemptyset(&none);
    sigprocmask(SIG_SETMASK, &none, NULL);

    __asm__ volatile("mov sp, %0\n"
                     "mov x0, #0\n"      /* rtld_fini = NULL */
                     "br %1\n"
                     :: "r"(sp), "r"(img.entry) : "memory");
    __builtin_unreachable();
}
