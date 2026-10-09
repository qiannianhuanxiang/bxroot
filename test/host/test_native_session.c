/* V3 native-session regression: actual backend, fresh exec for each case.
 * No runtime preload, Android bridge, network, or native entry execution.
 * SPDX-License-Identifier: MIT */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "../../src/host/session.h"
#include "../../src/runtime/config.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
bxroot_config_t g_config;
static const char *case_name;
static int checks;
static char physical_root[BX_SESSION_PATH];
static char *bind_hosts[BX_SESSION_MAX_BINDS], *bind_guests[BX_SESSION_MAX_BINDS];
static int bind_ro[BX_SESSION_MAX_BINDS];
static char **initial_env;
static size_t initial_count;
#define SENTINEL_ONE ((char *)(uintptr_t)0x51a7)
#define SENTINEL_TWO ((char *)(uintptr_t)0x62b8)
#define CHECK(expr) do { \
    checks++; \
    if (!(expr)) { \
        int saved = errno; \
        fprintf(stderr, "FAIL case=%s line=%d: %s (errno=%d: %s)\n", \
                case_name, __LINE__, #expr, saved, strerror(saved)); \
        return 1; \
    } \
} while (0)

/* The production module uses this only for backing-path lookup. Test loader
 * paths are /proc/self/exe, whose readability/X_OK is checked, never executed. */
int bxroot_translate_path(const char *path, char *out, size_t cap)
{
    int n;
    if (!strncmp(path, "/proc/", 6)) {
        n = snprintf(out, cap, "%s", path);
        if (n < 0 || (size_t)n >= cap) return -1;
        return 0;
    }
    n = snprintf(out, cap, "%s%s", g_config.rootfs, path);
    return n < 0 || (size_t)n >= cap ? -1 : 1;
}
static const char *lookup(char *const *env, const char *name)
{
    size_t len = strlen(name), i;
    for (i = 0; env && env[i]; i++)
        if (!strncmp(env[i], name, len) && env[i][len] == '=') return env[i] + len + 1;
    return NULL;
}
static int same_string(const char *a, const char *b)
{ return a && b && !strcmp(a, b); }
static int fixture(void)
{
    static const char *const values[] = {
        "PATH=/guest/bin:/guest tools", "HOME=/guest/home", "TMPDIR=/guest/tmp",
        "LD_LIBRARY_PATH=/guest/lib", "BXROOT_REENTRY=1", "BXROOT_SESSION_FD=",
        "BXROOT_ENTER=/proc/self/exe", "BXROOT_GUEST_PATH=/guest/bin:/guest tools",
        "PROROOT_LIB_PATH=/proc/self/exe", "PROROOT_TRAMPOLINE_PATH=/proc/self/exe",
        "PROROOT_LINKER_PATH=/proc/self/exe", "BXROOT_HOST_PATH=/system/bin",
        "BXROOT_FAKE_UID=1234", "BXROOT_FAKE_GID=2345", NULL
    };
    char tmp[BX_SESSION_PATH]; size_t i; long rc;
    CHECK(bx_session_raw(SYS_getcwd, (long)physical_root, sizeof(physical_root), 0, 0, 0, 0) > 0);
    memset(&g_config, 0, sizeof(g_config));
    g_config.rootfs = physical_root;
    g_config.tmp_dir = (char *)"/tmp";
    g_config.fakeroot = 1;
    g_config.bind_sources = bind_hosts;
    g_config.bind_targets = bind_guests;
    g_config.bind_readonly = bind_ro;
    CHECK(snprintf(tmp, sizeof(tmp), "%s/tmp", physical_root) < (int)sizeof(tmp));
    rc = bx_session_raw(SYS_mkdirat, AT_FDCWD, (long)tmp, 0700, 0, 0, 0);
    CHECK(rc == 0 || (rc < 0 && errno == EEXIST));
    for (initial_count = 0; values[initial_count]; initial_count++) { }
    initial_env = calloc(initial_count + 3, sizeof(char *));
    CHECK(initial_env != NULL);
    for (i = 0; i < initial_count; i++) {
        initial_env[i] = strdup(values[i]);
        CHECK(initial_env[i] != NULL);
    }
    initial_env[initial_count + 1] = SENTINEL_ONE;
    initial_env[initial_count + 2] = SENTINEL_TWO;
    environ = initial_env;
    /* No assertion about ELF identity: these paths are stand-ins for config,
       not executed payloads. Real native entry shape is tested elsewhere. */
    CHECK(bx_session_raw(SYS_faccessat, AT_FDCWD, (long)"/proc/self/exe", X_OK, 0, 0, 0) == 0);
    return 0;
}
static int add_config_bind(const char *host, const char *guest, int ro)
{
    int n = g_config.bind_count;
    CHECK(n < BX_SESSION_MAX_BINDS);
    bind_hosts[n] = strdup(host); bind_guests[n] = strdup(guest); bind_ro[n] = ro;
    CHECK(bind_hosts[n] != NULL && bind_guests[n] != NULL);
    g_config.bind_count++;
    return 0;
}
static int seed_session(bx_session *s, const char *root)
{
    int i;
    bx_session_init(s);
    CHECK(bx_session_set(s, "BXROOT_ROOTFS", root) == 0);
    CHECK(bx_session_set(s, "BXROOT_ENTER", "/proc/self/exe") == 0);
    CHECK(bx_session_set(s, "_GUEST_PATH", "/attached/bin") == 0);
    CHECK(bx_session_set(s, "_GUEST_HOME", "/attached/home") == 0);
    CHECK(bx_session_set(s, "_GUEST_TMPDIR", "/attached/tmp") == 0);
    CHECK(bx_session_set(s, "_TRAMP", "/proc/self/exe") == 0);
    CHECK(bx_session_set(s, "_LINKER", "/proc/self/exe") == 0);
    CHECK(bx_session_set(s, "_RUNTIME", "/proc/self/exe") == 0);
    for (i = 0; i < g_config.bind_count; i++)
        CHECK(bx_session_add_bind(s, bind_hosts[i], bind_guests[i], (unsigned)bind_ro[i]) == 0);
    return 0;
}
static int install_fd(int fd)
{
    char number[32];
    CHECK(fd >= 3);
    CHECK(snprintf(number, sizeof(number), "%d", fd) < (int)sizeof(number));
    CHECK(setenv("BXROOT_SESSION_FD", number, 1) == 0);
    return 0;
}
static int active_snapshot(bx_session *s)
{
    const char *number = bx_native_session_value("BXROOT_SESSION_FD"); int fd;
    CHECK(number != NULL);
    fd = bx_session_fd_number(number);
    CHECK(fd >= 3);
    bx_session_init(s);
    CHECK(bx_session_read(fd, s) == 0);
    return 0;
}
static int run_case(const char *name)
{
    bx_session s; const char *value; int fd, second, rc, i; char expected[BX_SESSION_PATH], path[BX_SESSION_PATH];
    if (fixture()) return 1;
    if (!strcmp(name, "disabled-default") || !strcmp(name, "disabled-zero")) {
        if (!strcmp(name, "disabled-default")) CHECK(unsetenv("BXROOT_REENTRY") == 0);
        else CHECK(setenv("BXROOT_REENTRY", "0", 1) == 0);
        bx_native_session_capture();
        CHECK(bx_native_session_init() == 0);
        CHECK(bx_native_session_value("BXROOT_SESSION_FD") == NULL);
        CHECK(same_string(getenv("BXROOT_SESSION_FD"), ""));
        return 0;
    }
    if (!strcmp(name, "capture-publish")) {
        /* Capture the original vector, then force setenv to create a different
           environ. Bash imports the old vector; it must see replaced slots. */
        CHECK(unsetenv("BXROOT_GUEST_PATH") == 0);
        initial_count--;
        /* unsetenv compacts the original vector; preserve its actual boundary. */
        initial_env[initial_count] = NULL;
        initial_env[initial_count + 1] = SENTINEL_ONE;
        initial_env[initial_count + 2] = SENTINEL_TWO;
        bx_native_session_capture();
        CHECK(setenv("POST_CAPTURE_NEW_VARIABLE", "forces environ copy", 1) == 0);
        CHECK(environ != initial_env);
        CHECK(setenv("PATH", "/system/bin:/vendor/bin", 1) == 0);
        CHECK(setenv("HOME", "/host/home", 1) == 0);
        CHECK(setenv("TMPDIR", "/host/tmp", 1) == 0);
        CHECK(bx_native_session_init() == 0);
        if (active_snapshot(&s)) return 1;
        CHECK(same_string(bx_session_get(&s, "_GUEST_PATH"), "/guest/bin:/guest tools"));
        CHECK(same_string(bx_session_get(&s, "_GUEST_HOME"), "/guest/home"));
        CHECK(same_string(bx_session_get(&s, "_GUEST_TMPDIR"), "/guest/tmp"));
        CHECK(same_string(bx_session_get(&s, "_LIBRARY_PATH"), "/guest/lib"));
        CHECK(same_string(lookup(initial_env, "BXROOT_SESSION_FD"), bx_native_session_value("BXROOT_SESSION_FD")));
        CHECK(same_string(lookup(initial_env, "BXROOT_ENTER"), bx_native_session_value("BXROOT_ENTER")));
        CHECK(initial_env[initial_count] == NULL);
        CHECK(initial_env[initial_count + 1] == SENTINEL_ONE && initial_env[initial_count + 2] == SENTINEL_TWO);
        bx_session_dispose(&s); return 0;
    }
    if (!strcmp(name, "empty-fd-init")) {
        bx_native_session_capture();
        CHECK(bx_native_session_init() == 0);
        CHECK(bx_session_fd_number(getenv("BXROOT_SESSION_FD")) >= 3);
        CHECK(bx_native_session_init() == 0);
        CHECK(same_string(bx_native_session_value("BXROOT_SESSION_FD"), getenv("BXROOT_SESSION_FD")));
        CHECK(initial_env[initial_count] == NULL && initial_env[initial_count + 1] == SENTINEL_ONE);
        return 0;
    }
    if (!strcmp(name, "explicit-guest-path")) {
        CHECK(setenv("BXROOT_GUEST_PATH", "/explicit/guest/bin", 1) == 0);
        CHECK(setenv("PATH", "/system/bin", 1) == 0);
        bx_native_session_capture();
        CHECK(bx_native_session_init() == 0);
        if (active_snapshot(&s)) return 1;
        CHECK(same_string(bx_session_get(&s, "_GUEST_PATH"), "/explicit/guest/bin"));
        bx_session_dispose(&s); return 0;
    }
    if (!strcmp(name, "attach-same-bind") || !strcmp(name, "attach-extra-bind") ||
        !strcmp(name, "attach-root-diff") || !strcmp(name, "attach-ro-diff") || !strcmp(name, "attach-cloexec")) {
        if (add_config_bind(physical_root, "/work", 1)) return 1;
        if (seed_session(&s, !strcmp(name, "attach-root-diff") ? "/different/rootfs" : physical_root)) return 1;
        if (!strcmp(name, "attach-extra-bind")) CHECK(bx_session_add_bind(&s, physical_root, "/extra", 0) == 0);
        if (!strcmp(name, "attach-ro-diff")) s.binds[0].ro = 0;
        fd = bx_session_create_fd(&s); bx_session_dispose(&s);
        if (install_fd(fd)) return 1;
        if (!strcmp(name, "attach-cloexec")) CHECK(fcntl(fd, F_SETFD, FD_CLOEXEC) == 0);
        bx_native_session_capture(); rc = bx_native_session_init();
        if (!strcmp(name, "attach-same-bind") || !strcmp(name, "attach-cloexec")) {
            CHECK(rc == 0);
            CHECK(bx_session_fd_number(bx_native_session_value("BXROOT_SESSION_FD")) == fd);
            CHECK(!(fcntl(fd, F_GETFD) & FD_CLOEXEC));
            CHECK(same_string(bx_native_session_value("BXROOT_GUEST_PATH"), "/attached/bin"));
        } else {
            CHECK(rc == -1 && errno == ESTALE);
            CHECK(bx_native_session_value("BXROOT_SESSION_FD") == NULL);
            CHECK(fcntl(fd, F_GETFD) >= 0); /* Rejection must not close caller's fd. */
        }
        close(fd); return 0;
    }
    if (!strcmp(name, "fd-close") || !strcmp(name, "fd-reuse") || !strcmp(name, "active-cloexec")) {
        bx_native_session_capture(); CHECK(bx_native_session_init() == 0);
        value = bx_native_session_value("BXROOT_SESSION_FD"); CHECK(value != NULL);
        fd = bx_session_fd_number(value); CHECK(fd >= 3);
        if (!strcmp(name, "active-cloexec")) {
            CHECK(fcntl(fd, F_SETFD, FD_CLOEXEC) == 0);
            CHECK(bx_native_session_value("BXROOT_SESSION_FD") != NULL);
            CHECK(!(fcntl(fd, F_GETFD) & FD_CLOEXEC));
            return 0;
        }
        if (!strcmp(name, "fd-reuse")) {
            if (seed_session(&s, "/different/session")) return 1;
            second = bx_session_create_fd(&s); bx_session_dispose(&s);
            CHECK(second >= 3 && second != fd);
            CHECK(close(fd) == 0);
            CHECK(dup2(second, fd) == fd);
            CHECK(bx_native_session_value("BXROOT_SESSION_FD") == NULL);
            CHECK(bx_native_session_value("BXROOT_ENTER") == NULL);
            close(second); close(fd);
        } else {
            CHECK(close(fd) == 0);
            CHECK(bx_native_session_value("BXROOT_SESSION_FD") == NULL);
            CHECK(bx_native_session_value("BXROOT_ENTER") == NULL);
        }
        return 0;
    }
    if (!strcmp(name, "ordinary-env-300")) {
        bx_native_session_capture();
        for (i = 0; i < 300; i++) {
            char key[32], data[64];
            snprintf(key, sizeof(key), "ORDINARY_%03d", i);
            snprintf(data, sizeof(data), "ordinary value %d", i);
            CHECK(setenv(key, data, 1) == 0);
        }
        CHECK(bx_native_session_init() == 0);
        if (active_snapshot(&s)) return 1;
        CHECK(s.nkv < BX_SESSION_MAX_KV);
        for (i = 0; i < 300; i++) {
            char key[32]; snprintf(key, sizeof(key), "ORDINARY_%03d", i);
            CHECK(bx_session_get(&s, key) == NULL);
            CHECK(getenv(key) != NULL);
        }
        bx_session_dispose(&s); return 0;
    }
    if (!strcmp(name, "shm-with-16-binds")) {
        for (i = 0; i < BX_SESSION_MAX_BINDS; i++) {
            char guest[32]; snprintf(guest, sizeof(guest), "/bound-%02d", i);
            if (add_config_bind(physical_root, guest, i & 1)) return 1;
        }
        bx_native_session_capture(); CHECK(bx_native_session_init() == 0);
        if (active_snapshot(&s)) return 1;
        CHECK(s.nb == BX_SESSION_MAX_BINDS);
        CHECK(same_string(bx_session_get(&s, "_SHM_GUEST"), "/dev/shm"));
        CHECK(snprintf(expected, sizeof(expected), "%s/tmp/.bxroot-shm", physical_root) < (int)sizeof(expected));
        CHECK(same_string(bx_session_get(&s, "_SHM_HOST"), expected));
        CHECK(bx_session_to_host(&s, "/dev/shm", "/", path, sizeof(path)) == 0);
        CHECK(!strcmp(path, expected));
        bx_session_dispose(&s); return 0;
    }
    if (!strcmp(name, "missing-loader")) {
        CHECK(unsetenv("PROROOT_TRAMPOLINE_PATH") == 0);
        CHECK(unsetenv("PROROOT_LINKER_PATH") == 0);
        bx_native_session_capture();
        CHECK(bx_native_session_init() == -1 && errno == ENOTSUP);
        CHECK(bx_native_session_value("BXROOT_SESSION_FD") == NULL); return 0;
    }
    if (!strcmp(name, "missing-entry")) {
        CHECK(setenv("BXROOT_ENTER", "/proc/self/fd/2147483647", 1) == 0);
        bx_native_session_capture();
        CHECK(bx_native_session_init() == -1 && errno == ENOENT);
        CHECK(bx_native_session_value("BXROOT_SESSION_FD") == NULL); return 0;
    }
    if (!strcmp(name, "relative-entry")) {
        CHECK(setenv("BXROOT_ENTER", "relative-entry", 1) == 0);
        bx_native_session_capture();
        CHECK(bx_native_session_init() == -1 && errno == EINVAL);
        CHECK(bx_native_session_value("BXROOT_SESSION_FD") == NULL); return 0;
    }
    errno = EINVAL; CHECK(!"unknown case"); return 1;
}
int main(int argc, char **argv)
{
    static const char *const cases[] = {
        "disabled-default", "disabled-zero", "capture-publish", "empty-fd-init",
        "explicit-guest-path", "attach-same-bind", "attach-extra-bind", "attach-root-diff",
        "attach-ro-diff", "attach-cloexec", "fd-close", "fd-reuse", "active-cloexec",
        "ordinary-env-300", "shm-with-16-binds", "missing-loader", "missing-entry", "relative-entry"
    };
    size_t i; int failed = 0;
    if (argc == 3 && !strcmp(argv[1], "--case")) {
        int rc;
        case_name = argv[2]; rc = run_case(case_name);
        printf("CASE: %s %s checks=%d\n", case_name, rc ? "FAIL" : "PASS", checks);
        return rc;
    }
    if (argc != 2 || chdir(argv[1])) { perror("native-session fixture cwd"); return 2; }
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        pid_t child; int status;
        fflush(NULL); child = fork();
        if (child < 0) { perror("fork"); return 2; }
        if (!child) {
            char *next[] = {argv[0], (char *)"--case", (char *)cases[i], NULL};
            execv(argv[0], next); perror("case exec"); _exit(2);
        }
        if (waitpid(child, &status, 0) != child) { perror("waitpid"); return 2; }
        if (!WIFEXITED(status) || WEXITSTATUS(status)) {
            failed++;
            fprintf(stderr, "SUBPROCESS: %s raw_status=%d\n", cases[i], status);
        }
    }
    printf("RESULT: %s native-session cases=%zu failures=%d (fresh exec per case)\n",
           failed ? "FAIL" : "PASS", sizeof(cases) / sizeof(cases[0]), failed);
    return failed ? 1 : 0;
}
