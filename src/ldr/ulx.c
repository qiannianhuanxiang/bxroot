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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "early_sigsys.h"

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
    int fd, i;
    char *res;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
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
        if (ph[i].p_align > align)
            align = ph[i].p_align;
        if ((ph[i].p_vaddr & ~(ps - 1)) < lo)
            lo = ph[i].p_vaddr & ~(ps - 1);
        if (ph[i].p_vaddr + ph[i].p_memsz > hi)
            hi = ph[i].p_vaddr + ph[i].p_memsz;
    }
    if (hi <= lo) {
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
    };
    char libpath[8192];
    const char *rf = getenv("BXROOT_ROOTFS");
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

    /* --library-path：调用方没给就按 rootfs 补 */
    add_lp = (rf != NULL && rf[0] == '/' && !has_opt(argv, 2, "--library-path"));
    if (add_lp) {
        size_t n = 0;
        for (i = 0; i < (int)(sizeof libdirs / sizeof libdirs[0]); i++) {
            int k = snprintf(libpath + n, sizeof libpath - n, "%s%s%s",
                             n ? ":" : "", rf, libdirs[i]);
            if (k < 0 || (size_t)k >= sizeof libpath - n)
                break;
            n += (size_t)k;
        }
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
