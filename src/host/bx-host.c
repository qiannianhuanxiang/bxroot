/*
 * bx-host -- 在 bxroot guest 中进入 Android bionic world
 *
 * 这是第一版的显式入口，不修改现有 guest exec 热路径：
 *
 *   bx-host /system/bin/getprop ro.product.model
 *   bx-host toybox uname -a
 *   bx-host /system/bin/sh -c 'getprop ro.product.model'
 *
 * 目标必须是 Android aarch64 ELF（PT_INTERP 为 /system 或 /apex 下的
 * linker64），或是 /system、/apex、/vendor 等宿主树下的静态 ELF。
 * 进程本身是无 libc 的静态程序，所有检查和 exec 都走 raw svc：这样它
 * 可以在 guest 的 static-exec 路径中运行，也不会被 bxroot 自己的 exec hook
 * 再次拦截。
 *
 * SPDX-License-Identifier: MIT
 */

#include <stddef.h>
#include <stdint.h>
#include "host-common.h"

#define SYS_read       63
#define SYS_write      64
#define SYS_close      57
#define SYS_exit       93
#define SYS_openat     56
#define SYS_pread64    67
#define SYS_execve     221
#define AT_FDCWD       (-100)
#define O_RDONLY       0
#define O_CLOEXEC      02000000

#define ELFCLASS64     2
#define ELFDATA2LSB    1
#define EM_AARCH64     183
#define ET_EXEC        2
#define ET_DYN         3
#define PT_INTERP      3

#define BX_MAX_PATH    4096
#define BX_MAX_ENV     128
#define BX_MAX_INTERP  256

static long bx_raw6(long nr, long a0, long a1, long a2,
                    long a3, long a4, long a5)
{
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;

    __asm__ volatile("svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
        : "memory", "cc");
    return x0;
}

static long bx_pread(int fd, void *buf, size_t n, uint64_t off)
{
    return bx_raw6(SYS_pread64, fd, (long)buf, (long)n, (long)off, 0, 0);
}

static long bx_open(const char *path)
{
    return bx_raw6(SYS_openat, AT_FDCWD, (long)path,
                   O_RDONLY | O_CLOEXEC, 0, 0, 0);
}

static long bx_exec(const char *path, char *const argv[], char *const envp[])
{
    return bx_raw6(SYS_execve, (long)path, (long)argv, (long)envp, 0, 0, 0);
}

static void bx_write_all(int fd, const char *s, size_t n)
{
    while (n != 0) {
        long r = bx_raw6(SYS_write, fd, (long)s, (long)n, 0, 0, 0);
        if (r <= 0)
            return;
        s += (size_t)r;
        n -= (size_t)r;
    }
}

static size_t bx_strlen(const char *s)
{
    size_t n = 0;
    if (s == NULL)
        return 0;
    while (s[n] != '\0')
        n++;
    return n;
}

static int bx_streq(const char *a, const char *b)
{
    size_t i = 0;
    if (a == NULL || b == NULL)
        return 0;
    while (a[i] != '\0' && b[i] != '\0') {
        if (a[i] != b[i])
            return 0;
        i++;
    }
    return a[i] == '\0' && b[i] == '\0';
}

static int bx_copy(char *out, size_t cap, const char *s)
{
    size_t n = bx_strlen(s);
    size_t i;
    if (n + 1 > cap)
        return -1;
    for (i = 0; i <= n; i++)
        out[i] = s[i];
    return 0;
}

static int bx_join(char *out, size_t cap, const char *dir, const char *name)
{
    size_t a = bx_strlen(dir);
    size_t b = bx_strlen(name);
    size_t i;
    if (a == 0 || b == 0 || a + 1 + b + 1 > cap)
        return -1;
    for (i = 0; i < a; i++)
        out[i] = dir[i];
    if (out[a - 1] == '/')
        a--;
    out[a++] = '/';
    for (i = 0; i < b; i++)
        out[a + i] = name[i];
    out[a + b] = '\0';
    return 0;
}

static int bx_classify_elf(const char *path)
{
    long fd = bx_open(path);
    int kind;
    if (fd < 0) return 0;
    kind = bxhc_elf((int)fd, path, bx_pread);
    bx_raw6(SYS_close, fd, 0, 0, 0, 0, 0);
    return kind ? kind : -1;
}

static void bx_env_push(char **out, size_t *n, size_t cap, char *value)
{
    if (*n + 1 < cap)
        out[(*n)++] = value;
}

static size_t bx_host_env(char **out, size_t cap, char *const envp[])
{
    static char *const fixed[] = {
        (char *)"PATH=/system/bin:/system/xbin:/vendor/bin",
        (char *)"ANDROID_ROOT=/system",
        (char *)"ANDROID_DATA=/data",
        (char *)"ANDROID_RUNTIME_ROOT=/apex/com.android.runtime",
        (char *)"ANDROID_ART_ROOT=/apex/com.android.art",
        (char *)"ANDROID_I18N_ROOT=/apex/com.android.i18n",
        (char *)"ANDROID_TZDATA_ROOT=/apex/com.android.tzdata",
        (char *)"HOME=/data/local/tmp",
        (char *)"TMPDIR=/data/local/tmp",
        NULL
    };
    size_t n = 0, i, k;
    for (k = 0; fixed[k] != NULL; k++)
        bx_env_push(out, &n, cap, fixed[k]);
    for (i = 0; envp != NULL && envp[i] != NULL; i++) {
        const char *e = envp[i];
        if (bxhc_keep_env(e))
            bx_env_push(out, &n, cap, envp[i]);
    }
    out[n] = NULL;
    return n;
}

static void bx_error(const char *s)
{
    bx_write_all(2, "bx-host: ", 9);
    bx_write_all(2, s, bx_strlen(s));
    bx_write_all(2, "\n", 1);
}

static void bx_usage(void)
{
    const char *s =
        "usage: bx-host <android-bionic-command> [args...]\n"
        "       bx-host /system/bin/getprop ro.product.model\n"
        "       bx-host toybox uname -a\n";
    bx_write_all(2, s, bx_strlen(s));
}

static int bx_resolve(const char *name, char *path, size_t cap)
{
    static const char default_path[] = BX_HOST_DEFAULT_PATH;
    const char *search = default_path;
    size_t start = 0, i;
    int c;

    if (name == NULL || name[0] == '\0')
        return -1;
    for (i = 0; name[i] != '\0'; i++)
        if (name[i] == '/')
            return bx_copy(path, cap, name) == 0 ? 1 : -1;
    for (i = 0;; i++) {
        if (search[i] == ':' || search[i] == '\0') {
            size_t len = i - start;
            char dir[BX_MAX_PATH];
            if (len != 0 && len < sizeof(dir)) {
                size_t j;
                for (j = 0; j < len; j++)
                    dir[j] = search[start + j];
                dir[len] = '\0';
                if (bx_join(path, cap, dir, name) == 0) {
                    c = bx_classify_elf(path);
                    if (c == 1 || c == 2)
                        return c;
                    if (c < 0)
                        return -2;
                }
            }
            if (search[i] == '\0')
                break;
            start = i + 1;
        }
    }
    return 0;
}

static int bx_main(long argc, char **argv, char **envp)
{
    char path[BX_MAX_PATH];
    char *host_env[BX_MAX_ENV];
    int kind, rc;

    if (argc < 2 || bx_streq(argv[1], "--help") || bx_streq(argv[1], "-h")) {
        bx_usage();
        return argc < 2 ? 2 : 0;
    }
    if (bx_streq(argv[1], "--version")) {
        bx_write_all(1, "bx-host 0.1.0\n", 14);
        return 0;
    }
    rc = bx_resolve(argv[1], path, sizeof(path));
    if (rc == 0) {
        bx_error("Android host command not found");
        return 127;
    }
    if (rc == -1) {
        bx_error("host command path is too long or empty");
        return 126;
    }
    if (rc == -2) {
        bx_error("host command is not a supported Android ELF");
        return 126;
    }
    kind = bx_classify_elf(path);
    if (kind != 1 && kind != 2) {
        bx_error("target is not a bionic ELF");
        return 126;
    }
    (void)bx_host_env(host_env, BX_MAX_ENV, envp);
    /* argv[0] 保留调用者写的名字，toybox 的多调用分派依赖这一点。 */
    (void)bx_exec(path, &argv[1], host_env);
    bx_error("execve failed");
    return 126;
}

void bx_host_entry(long *sp)
{
    long argc = sp[0];
    char **argv = (char **)(sp + 1);
    char **envp = argv + argc + 1;
    long rc = bx_main(argc, argv, envp);
    bx_raw6(SYS_exit, rc & 255, 0, 0, 0, 0, 0);
    for (;;)
        ;
}

__asm__(
    ".global _start\n"
    "_start:\n"
    "mov x0, sp\n"
    "bl bx_host_entry\n"
    "mov x8, #93\n"
    "svc #0\n"
);
