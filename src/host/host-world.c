/* Android bionic execution backend. SPDX-License-Identifier: MIT */
#include "host-world.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

extern char **environ;
static long hw_raw6(long nr, long a, long b, long c, long d, long e, long f)
{
#if defined(__aarch64__)
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a, x1 __asm__("x1") = b, x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d, x4 __asm__("x4") = e, x5 __asm__("x5") = f;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2),
                      "r"(x3), "r"(x4), "r"(x5) : "memory", "cc");
    return x0;
#else
    /* Non-Android classifier tests. These do not load the bxroot hooks. */
    long r = syscall(nr, a, b, c, d, e, f);
    return r == -1 ? -errno : r;
#endif
}
static long hw_pread(int fd, void *buf, size_t n, uint64_t off)
{
    return hw_raw6(SYS_pread64, fd, (long)buf, (long)n, (long)off, 0, 0);
}
static long hw_open(const char *p)
{
    return hw_raw6(SYS_openat, AT_FDCWD, (long)p, O_RDONLY | O_CLOEXEC, 0, 0, 0);
}
static void hw_close(long fd) { (void)hw_raw6(SYS_close, fd, 0, 0, 0, 0, 0); }
static int hw_copy(char *out, size_t cap, const char *s)
{
    size_t n = strlen(s);
    if (n >= cap) { errno = ENAMETOOLONG; return -1; }
    memcpy(out, s, n + 1);
    return 0;
}
/* Parse only an absolute interpreter. One optional argument follows Linux's
 * shebang convention (the entire remainder, including internal spaces). */
static int hw_shebang(const char *p, char *interp, char *arg)
{
    char b[256];
    size_t i, end, begin;
    long fd = hw_open(p), n;
    if (fd < 0) return 0;
    n = hw_pread((int)fd, b, sizeof(b), 0);
    hw_close(fd);
    if (n < 3 || b[0] != '#' || b[1] != '!') return 0;
    for (end = 2; end < (size_t)n && b[end] != '\n' && b[end] != '\0'; end++);
    if (end == sizeof(b)) return 0; /* truncated interpreter line */
    while (end > 2 && (b[end - 1] == ' ' || b[end - 1] == '\t')) end--;
    i = 2;
    while (i < end && (b[i] == ' ' || b[i] == '\t')) i++;
    begin = i;
    while (i < end && b[i] != ' ' && b[i] != '\t') i++;
    if (i == begin || b[begin] != '/') return 0;
    memcpy(interp, b + begin, i - begin);
    interp[i - begin] = '\0';
    while (i < end && (b[i] == ' ' || b[i] == '\t')) i++;
    memcpy(arg, b + i, end - i);
    arg[end - i] = '\0';
    return 1;
}
static int hw_elf(const char *p)
{
    long fd = hw_open(p);
    int k;
    if (fd < 0) return BX_HOST_WORLD_NO;
    k = bxhc_elf((int)fd, p, hw_pread);
    hw_close(fd);
    return k;
}
static int hw_script_interpreter(const char *path, bx_host_world_mapper mapper,
                                  char *backing, char *arg)
{
    char literal[BX_HOST_PATH_MAX];
    int rc;
    if (!hw_shebang(path, literal, arg) || !bxhc_native_tree(literal)) return 0;
    if (mapper) {
        rc = mapper(literal, backing, BX_HOST_PATH_MAX);
        if (rc < 0) return -1;
        if (rc > 0) return hw_elf(backing) == BX_HOST_WORLD_BIONIC;
    }
    if (hw_copy(backing, BX_HOST_PATH_MAX, literal) != 0) return -1;
    return hw_elf(backing) == BX_HOST_WORLD_BIONIC;
}
int bx_host_world_classify_mapped(const char *p, bx_host_world_mapper mapper)
{
    char interp[BX_HOST_PATH_MAX], arg[256];
    int saved = errno, k;
    if (!p || !*p) return BX_HOST_WORLD_NO;
    k = hw_elf(p);
    if (!k && hw_script_interpreter(p, mapper, interp, arg) > 0)
        k = BX_HOST_WORLD_SCRIPT;
    errno = saved;
    return k;
}
int bx_host_world_classify(const char *p)
{
    return bx_host_world_classify_mapped(p, NULL);
}
static const char *hw_env_value(char *const env[], const char *name)
{
    size_t i, n = strlen(name);
    for (i = 0; env && env[i]; i++)
        if (bxhc_env_name(env[i], name)) return env[i] + n + 1;
    return NULL;
}
int bx_host_world_enabled(void)
{
    return bxhc_equal(hw_env_value(environ, "BXROOT_AUTO_HOST"), "1");
}
static const char *hw_path(void)
{
    const char *p = hw_env_value(environ, "BXROOT_HOST_PATH");
    /* unset => default; empty => disable name fallback */
    return p ? p : BX_HOST_DEFAULT_PATH;
}
int bx_host_world_resolve(const char *name, char *out, size_t cap)
{
    const char *path = hw_path(), *p;
    size_t n = name ? strlen(name) : 0;
    int denied = 0;
    if (!n || strchr(name, '/')) { errno = ENOENT; return -1; }
    for (p = path; *p;) {
        const char *end = strchr(p, ':');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (len && p[0] == '/' && len + n + 2 <= cap) {
            memcpy(out, p, len);
            out[len] = '/';
            memcpy(out + len + 1, name, n + 1);
            if (bx_host_world_classify(out)) {
                long r = hw_raw6(SYS_faccessat, AT_FDCWD, (long)out, X_OK, 0, 0, 0);
                if (r == 0) return 0;
                if (r == -EACCES) denied = 1;
            }
        }
        if (!end) break;
        p = end + 1;
    }
    errno = denied ? EACCES : ENOENT;
    return -1;
}
int bx_host_world_script_access(const char *host)
{
    long r;
    if (!host) { errno = EFAULT; return -1; }
    r = hw_raw6(SYS_faccessat, AT_FDCWD, (long)host, X_OK, 0, 0, 0);
    if (r == 0) return 0;
    errno = r < 0 && r >= -4095 ? (int)-r : EIO;
    return -1;
}
int bx_host_world_prepare_mapped(const char *host, char *const argv[],
                                  bx_host_world_mapper mapper, bx_host_plan *plan)
{
    int kind, rc;
    size_t argc = 0, n = 0, i;
    memset(plan, 0, sizeof(*plan));
    kind = bx_host_world_classify_mapped(host, mapper);
    if (!kind) return 0;
    plan->target = host;
    plan->argv = argv;
    if (kind != BX_HOST_WORLD_SCRIPT) return 1;
    if (bx_host_world_script_access(host) != 0) return -1;
    /* Recheck the mapping and backing ELF after classification. Never use
     * the literal /system path when the guest bind maps it elsewhere. */
    rc = hw_script_interpreter(host, mapper, plan->interpreter, plan->argument);
    if (rc <= 0) return rc;
    if (argv) while (argv[argc]) argc++;
    if (argc > SIZE_MAX / sizeof(char *) - 4) { errno = E2BIG; return -1; }
    plan->rewritten = malloc((argc + 4) * sizeof(char *));
    if (!plan->rewritten) return -1;
    plan->rewritten[n++] = plan->interpreter;
    if (plan->argument[0]) plan->rewritten[n++] = plan->argument;
    /* The bionic interpreter sees HOST backing paths, not guest /tmp paths. */
    plan->rewritten[n++] = (char *)host;
    for (i = 1; i < argc; i++) plan->rewritten[n++] = argv[i];
    plan->rewritten[n] = NULL;
    plan->target = plan->interpreter;
    plan->argv = plan->rewritten;
    return 1;
}
int bx_host_world_prepare(const char *host, char *const argv[], bx_host_plan *plan)
{
    return bx_host_world_prepare_mapped(host, argv, NULL, plan);
}
void bx_host_world_dispose(bx_host_plan *plan)
{
    free(plan->rewritten);
    plan->rewritten = NULL;
}
int bx_host_world_build_env(char *const input[], char ***out)
{
    static const char *const fixed[] = {
        "ANDROID_ROOT=/system", "ANDROID_DATA=/data",
        "ANDROID_RUNTIME_ROOT=/apex/com.android.runtime", "ANDROID_ART_ROOT=/apex/com.android.art",
        "ANDROID_I18N_ROOT=/apex/com.android.i18n", "ANDROID_TZDATA_ROOT=/apex/com.android.tzdata", NULL
    };
    char *const *src = input ? input : environ;
    const char *home = hw_env_value(environ, "BXROOT_HOST_HOME");
    const char *tmp = hw_env_value(environ, "BXROOT_HOST_TMPDIR");

    char cwd[BX_HOST_PATH_MAX], *s, **env;
    size_t keep = 0, i, n = 0, bytes;
    if (!out) { errno = EINVAL; return -1; }
    *out = NULL;
    for (i = 0; src && src[i]; i++) {
        if (bxhc_keep_env(src[i])) keep++;
        if (i >= 131072) { errno = E2BIG; return -1; }
    }
    if (hw_raw6(SYS_getcwd, (long)cwd, sizeof(cwd), 0, 0, 0, 0) < 0)
        (void)hw_copy(cwd, sizeof(cwd), "/");
    if (!home || home[0] != '/') home = cwd;
    if (!tmp || tmp[0] != '/') tmp = cwd;
    bytes = strlen(hw_path()) + strlen(home) + strlen(tmp) + 32;
    env = calloc(1, (keep + 10) * sizeof(char *) + bytes);
    if (!env) return -1;
    s = (char *)(env + keep + 10);
#define HW_ENV(key, value) do { \
    env[n++] = s; memcpy(s, key "=", sizeof(key)); s += sizeof(key); \
    memcpy(s, value, strlen(value) + 1); s += strlen(value) + 1; \
} while (0)
    HW_ENV("PATH", hw_path());
    HW_ENV("HOME", home);
    HW_ENV("TMPDIR", tmp);
#undef HW_ENV
    for (i = 0; fixed[i]; i++) env[n++] = (char *)fixed[i];
    for (i = 0; src && src[i]; i++) if (bxhc_keep_env(src[i])) env[n++] = src[i];
    env[n] = NULL;
    *out = env;
    return 0;
}
void bx_host_world_free_env(char **env) { free(env); }
int bx_host_world_exec_mapped(const char *path, char *const argv[],
                               char *const envp[], bx_host_world_mapper mapper)
{
    bx_host_plan plan;
    char **env = NULL;
    long r;
    int e, k = bx_host_world_prepare_mapped(path, argv, mapper, &plan);
    if (k <= 0) { if (!k) errno = ENOEXEC; return -1; }
    if (bx_host_world_build_env(envp, &env)) {
        e = errno; bx_host_world_dispose(&plan); errno = e; return -1;
    }
    r = hw_raw6(SYS_execve, (long)plan.target, (long)plan.argv, (long)env, 0, 0, 0);
    e = r < 0 && r >= -4095 ? (int)-r : EIO;
    free(env); bx_host_world_dispose(&plan); errno = e;
    return -1;
}
int bx_host_world_exec(const char *path, char *const argv[], char *const envp[])
{
    return bx_host_world_exec_mapped(path, argv, envp, NULL);
}
/* Component equality (not substring matching); preserve guest empty entries. */
static int hw_path_has(const char *path, const char *part, size_t len)
{
    const char *p = path;
    for (;;) {
        const char *end = strchr(p, ':');
        size_t n = end ? (size_t)(end - p) : strlen(p);
        if (n == len && memcmp(p, part, len) == 0) return 1;
        if (!end) return 0;
        p = end + 1;
    }
}
int bx_host_world_guest_path(const char *guest_path, const char *host_path,
                              char **out)
{
    const char *gp = guest_path ? guest_path : BX_HOST_GUEST_DEFAULT_PATH;
    const char *hp = host_path ? host_path : BX_HOST_DEFAULT_PATH;
    const char *p;
    size_t gl, hl, n;
    char *joined;
    if (!out) { errno = EINVAL; return -1; }
    *out = NULL;
    gl = strlen(gp);
    hl = strlen(hp);
    if (hl > SIZE_MAX - 2 || gl > SIZE_MAX - hl - 2) {
        errno = EOVERFLOW;
        return -1;
    }
    joined = malloc(gl + hl + 2);
    if (!joined) return -1;
    memcpy(joined, gp, gl + 1);
    n = gl;
    for (p = hp; *p;) {
        const char *end = strchr(p, ':');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (len && p[0] == '/' && !hw_path_has(joined, p, len)) {
            /* Always append the separator: PATH="" or a trailing ':' must
             * retain its explicit current-directory search component. */
            joined[n++] = ':';
            memcpy(joined + n, p, len);
            n += len;
            joined[n] = '\0';
        }
        if (!end) break;
        p = end + 1;
    }
    *out = joined;
    return 0;
}
int bx_host_world_init_path(void)
{
    char **env = environ, **slot;
    const char *gp = NULL, *hp = hw_env_value(env, "BXROOT_HOST_PATH");
    char *joined, *entry;
    size_t n;
    if (!bxhc_equal(hw_env_value(env, "BXROOT_AUTO_HOST"), "1") ||
        (hp && !*hp)) return 0;
    for (slot = env; slot && *slot; slot++) {
        if (bxhc_env_name(*slot, "PATH")) {
            gp = *slot + 5;
            break;
        }
    }
    /* A loader's envp NULL can be immediately followed by auxv. Adding PATH
     * belongs to the launcher/parent before exec, never this ctor helper. */
    if (!gp) return BX_HOST_PATH_MISSING;
    if (bx_host_world_guest_path(gp, hp, &joined) != 0) return -1;
    if (strcmp(gp, joined) == 0) { free(joined); return 0; }
    n = strlen(joined);
    if (n > SIZE_MAX - 6) { free(joined); errno = EOVERFLOW; return -1; }
    entry = malloc(n + 6);
    if (!entry) { free(joined); return -1; }
    memcpy(entry, "PATH=", 5);
    memcpy(entry + 5, joined, n + 1);
    /* Replace an EXISTING pointer in the same vector bash imports. The old
     * entry is libc/loader-owned; do not free it. New entry lives for process
     * lifetime. This helper is for startup, not concurrent environment edits. */
    *slot = entry;
    free(joined);
    return 0;
}
