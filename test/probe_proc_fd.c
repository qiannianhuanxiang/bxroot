/*
 * proc fd runtime regression probe.
 *
 * This is a source-level probe for the two real static resolvers in
 * src/runtime/preload.c. It drives their real_readlink slot with a
 * deterministic fake first, then repeats proc-fd cases with raw Linux
 * syscalls against real memfd, pipe, and regular descriptors.
 *
 * Scope: Linux resolver behavior only. This does not claim to exercise the
 * Android loader/interposition chain; that remains a device-side check.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

/* Keep the source-included runtime's private handle distinct from crtbegin. */
#define __dso_handle bxroot_internal_dso_handle
#include "../src/runtime/preload.c"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

static int g_ok;
static int g_fail;
static int g_fake_calls;

static void pass_case(const char *name)
{
    g_ok++;
    printf("  [PASS] %s\n", name);
}

static void fail_case(const char *name, const char *detail)
{
    g_fail++;
    printf("  [FAIL] %s%s%s\n", name,
           detail != NULL ? ": " : "", detail != NULL ? detail : "");
}

static int expect_int(const char *name, long got, long want)
{
    char detail[128];

    if (got == want) {
        pass_case(name);
        return 1;
    }
    snprintf(detail, sizeof(detail), "got=%ld want=%ld", got, want);
    fail_case(name, detail);
    return 0;
}

static int expect_string(const char *name, const char *got, const char *want)
{
    char detail[MAX_PATH_LEN + 96];

    if (strcmp(got, want) == 0) {
        pass_case(name);
        return 1;
    }
    snprintf(detail, sizeof(detail), "got=%s want=%s", got, want);
    fail_case(name, detail);
    return 0;
}

/* This fake models ordinary links used by the deterministic resolver matrix. */
static ssize_t fake_real_readlink(const char *path, char *buf, size_t size)
{
    const char *target = NULL;

    g_fake_calls++;
    if (strcmp(path, "/bxroot-proc-fd-root/absolute-link") == 0)
        target = "/absolute-target";
    else if (strcmp(path, "/bxroot-proc-fd-root/relative-link") == 0)
        target = "relative-target";
    else if (strcmp(path, "/bxroot-proc-fd-root/absolute-target") == 0 ||
             strcmp(path, "/bxroot-proc-fd-root/relative-target") == 0)
        target = NULL;             /* ordinary file: readlink -> EINVAL */

    if (target == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (strlen(target) >= size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(buf, target, strlen(target));
    return (ssize_t)strlen(target);
}

/* Guest symlink -> proc fd: the second readlink must never happen. */
static ssize_t fake_guest_fd_readlink(const char *path, char *buf, size_t size)
{
    const char *target;

    g_fake_calls++;
    if (strcmp(path, "/bxroot-proc-fd-root/guest-to-fd") == 0)
        target = "/proc/self/fd/7";
    else
        return fake_real_readlink(path, buf, size);
    if (strlen(target) >= size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(buf, target, strlen(target));
    return (ssize_t)strlen(target);
}

/* Raw readlinkat for the real-fd phase; never enters the probe's readlink hook. */
static ssize_t raw_probe_readlink(const char *path, char *buf, size_t size)
{
    long r = prcfg_sys(SYS_readlinkat, AT_FDCWD, (long)path,
                       (long)buf, (long)size);

    if (r < 0 && r >= -4095) {
        errno = (int)-r;
        return -1;
    }
    return (ssize_t)r;
}

/* Convert the included runtime's raw svc convention (-errno) to libc style. */
static long raw_probe_sys(long nr, long a0, long a1, long a2, long a3)
{
    long r = prcfg_sys(nr, a0, a1, a2, a3);

    if (r < 0 && r >= -4095) {
        errno = (int)-r;
        return -1;
    }
    return r;
}

static int raw_probe_stat_fd(int fd, struct stat *st)
{
    return raw_probe_sys(SYS_fstat, fd, (long)st, 0, 0) < 0 ? -1 : 0;
}

static int raw_probe_stat_path(const char *path, struct stat *st)
{
    return raw_probe_sys(SYS_newfstatat, AT_FDCWD, (long)path,
                         (long)st, 0) < 0 ? -1 : 0;
}

static int raw_probe_close(int fd)
{
    return raw_probe_sys(SYS_close, fd, 0, 0, 0) < 0 ? -1 : 0;
}

static int metadata_equal(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev &&
           a->st_ino == b->st_ino &&
           a->st_mode == b->st_mode &&
           a->st_nlink == b->st_nlink &&
           a->st_uid == b->st_uid &&
           a->st_gid == b->st_gid &&
           a->st_size == b->st_size;
}

static int resolver_preserves(const char *name, const char *path,
                              int (*resolver)(const char *, char *, size_t))
{
    char out[MAX_PATH_LEN];
    const char *sentinel = "/sentinel/proc-fd-output";
    int rc;

    snprintf(out, sizeof(out), "%s", sentinel);
    rc = resolver(path, out, sizeof(out));
    if (rc == 0 && strcmp(out, sentinel) == 0) {
        pass_case(name);
        return 1;
    }

    {
        char detail[256];
        snprintf(detail, sizeof(detail), "path=%s rc=%d out=%s",
                 path, rc, out);
        fail_case(name, detail);
    }
    return 0;
}

static void check_proc_fd_shape(void)
{
    static const char *const valid[] = {
        "/proc/self/fd/0",
        "/proc/thread-self/fd/0",
        "/proc/1234/fd/0",
    };
    static const char *const invalid[] = {
        "/proc/self/fd",
        "/proc/self/fd/",
        "/proc/self/fd/x",
        "/proc/self/fd/1x",
        "/proc/self/fd/-1",
        "/proc/self/fd/1/extra",
        "/proc/selfx/fd/1",
        "/proc/thread-selfx/fd/1",
        "/proc/12a/fd/1",
        "/proc/net/fd/1",
        "/proc/self/cwd/1",
    };
    size_t i;

    printf("=== A. proc fd leaf recognition and invalid paths ===\n");
    g_config.rootfs = "/bxroot-proc-fd-root";
    g_fake_calls = 0;
    /* proc_magic_link_target() lazily initializes the real table for /proc
     * inputs; do that once before installing the deterministic fake. */
    ensure_real_functions();
    real_readlink = fake_real_readlink;
    for (i = 0; i < sizeof(valid) / sizeof(valid[0]); i++) {
        char name[128];

        snprintf(name, sizeof(name), "recognized %s", valid[i]);
        expect_int(name, proc_fd_magic_leaf(valid[i]), 1);
        resolver_preserves("resolve_symlink_full preserves recognized fd",
                           valid[i], resolve_symlink_full);
        resolver_preserves("resolve_abs_symlink preserves recognized fd",
                           valid[i], resolve_abs_symlink);
    }
    for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        char name[128];

        snprintf(name, sizeof(name), "reject invalid %s", invalid[i]);
        expect_int(name, proc_fd_magic_leaf(invalid[i]), 0);
        resolver_preserves("resolve_symlink_full preserves invalid path",
                           invalid[i], resolve_symlink_full);
        resolver_preserves("resolve_abs_symlink preserves invalid path",
                           invalid[i], resolve_abs_symlink);
    }

    if (g_fake_calls != 0)
        pass_case("fake readlink is reached for rejected shapes");
    else
        fail_case("fake readlink is reached for rejected shapes", "no calls");
}

static void check_fake_resolvers(void)
{
    char out[MAX_PATH_LEN];
    int rc;

    printf("=== B. fake readlink resolver regression ===\n");
    g_fake_calls = 0;
    g_config.rootfs = "/bxroot-proc-fd-root";
    real_readlink = fake_real_readlink;

    snprintf(out, sizeof(out), "/sentinel");
    rc = resolve_symlink_full("/bxroot-proc-fd-root/absolute-link",
                              out, sizeof(out));
    if (rc == 1)
        pass_case("absolute ordinary symlink still expands");
    else
        fail_case("absolute ordinary symlink still expands", "rc != 1");
    expect_string("absolute ordinary symlink target",
                  out, "/bxroot-proc-fd-root/absolute-target");

    snprintf(out, sizeof(out), "/sentinel");
    rc = resolve_abs_symlink("/bxroot-proc-fd-root/absolute-link",
                             out, sizeof(out));
    if (rc == 1)
        pass_case("absolute resolver still expands ordinary symlink");
    else
        fail_case("absolute resolver still expands ordinary symlink", "rc != 1");
    expect_string("absolute resolver ordinary target",
                  out, "/bxroot-proc-fd-root/absolute-target");

    snprintf(out, sizeof(out), "/sentinel");
    rc = resolve_symlink_full("/bxroot-proc-fd-root/relative-link",
                              out, sizeof(out));
    if (rc == 1)
        pass_case("relative ordinary symlink still expands");
    else
        fail_case("relative ordinary symlink still expands", "rc != 1");
    expect_string("relative ordinary symlink target",
                  out, "/bxroot-proc-fd-root/relative-target");
}

static void check_guest_fd_link(void)
{
    char out[MAX_PATH_LEN];
    int rc;

    printf("=== C. guest symlink target remains a proc fd handle ===\n");
    g_config.rootfs = "/bxroot-proc-fd-root";
    g_fake_calls = 0;
    real_readlink = fake_guest_fd_readlink;
    snprintf(out, sizeof(out), "/sentinel");
    rc = resolve_symlink_full("/bxroot-proc-fd-root/guest-to-fd",
                              out, sizeof(out));
    if (rc == 1 && strcmp(out, "/proc/self/fd/7") == 0 && g_fake_calls == 1)
        pass_case("guest symlink -> proc fd is not expanded");
    else {
        char detail[256];
        snprintf(detail, sizeof(detail), "rc=%d out=%s calls=%d",
                 rc, out, g_fake_calls);
        fail_case("guest symlink -> proc fd is not expanded", detail);
    }
}

static int check_one_real_fd(const char *kind, int fd, const char *target_prefix,
                             int require_regular)
{
    char path[64];
    char raw_target[MAX_PATH_LEN];
    char name[192];
    struct stat by_fd;
    struct stat by_path;
    ssize_t n;
    int rc;
    int before;

    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    n = raw_probe_readlink(path, raw_target, sizeof(raw_target) - 1);
    if (n < 0) {
        snprintf(name, sizeof(name), "%s readlink", kind);
        fail_case(name, strerror(errno));
        return 0;
    }
    raw_target[n] = '\0';
    snprintf(name, sizeof(name), "%s target shape", kind);
    if (target_prefix != NULL &&
        strncmp(raw_target, target_prefix, strlen(target_prefix)) == 0 &&
        (strcmp(kind, "memfd") != 0 || strstr(raw_target, " (deleted)") != NULL))
        pass_case(name);
    else {
        char detail[MAX_PATH_LEN + 32];
        snprintf(detail, sizeof(detail), "target=%s", raw_target);
        fail_case(name, detail);
    }

    if (raw_probe_stat_fd(fd, &by_fd) != 0 ||
        raw_probe_stat_path(path, &by_path) != 0) {
        snprintf(name, sizeof(name), "%s stat metadata available", kind);
        fail_case(name, strerror(errno));
        return 0;
    }
    snprintf(name, sizeof(name), "%s fd/stat metadata equal", kind);
    if (metadata_equal(&by_fd, &by_path))
        pass_case(name);
    else
        fail_case(name, "fstat differs from stat(/proc/self/fd/N)");

    real_readlink = raw_probe_readlink;
    before = g_fake_calls;
    snprintf(name, sizeof(name), "%s resolve_symlink_full preserves fd", kind);
    rc = resolver_preserves(name, path, resolve_symlink_full);
    if (rc && g_fake_calls != before)
        fail_case("real fd full resolver called fake readlink", "unexpected call");
    snprintf(name, sizeof(name), "%s resolve_abs_symlink preserves fd", kind);
    rc = resolver_preserves(name, path, resolve_abs_symlink);
    if (rc && g_fake_calls != before)
        fail_case("real fd abs resolver called fake readlink", "unexpected call");

    if (require_regular && !S_ISREG(by_fd.st_mode)) {
        snprintf(name, sizeof(name), "%s is regular", kind);
        fail_case(name, "opened object is not S_IFREG");
    } else if (require_regular) {
        snprintf(name, sizeof(name), "%s is regular", kind);
        pass_case(name);
    }
    return 1;
}

static void check_real_fds(void)
{
    int memfd;
    int pipefd[2] = { -1, -1 };
    int regular;

    printf("=== D. real memfd/pipe/regular fd metadata and resolver behavior ===\n");

    memfd = (int)raw_probe_sys(SYS_memfd_create, (long)"bxroot-proc-fd",
                               MFD_CLOEXEC, 0, 0);
    if (memfd < 0) {
        fail_case("create real memfd", strerror(errno));
    } else {
        (void)raw_probe_sys(SYS_write, memfd, (long)"proc-fd", 7, 0);
        check_one_real_fd("memfd", memfd, "/memfd:", 0);
        raw_probe_close(memfd);
    }

    if (raw_probe_sys(SYS_pipe2, (long)pipefd, O_CLOEXEC, 0, 0) < 0) {
        fail_case("create real pipe", strerror(errno));
    } else {
        check_one_real_fd("pipe", pipefd[0], "pipe:[", 0);
        raw_probe_close(pipefd[0]);
        raw_probe_close(pipefd[1]);
    }

    regular = (int)raw_probe_sys(SYS_openat, AT_FDCWD, (long)"/etc/hosts",
                                 O_RDONLY | O_CLOEXEC, 0);
    if (regular < 0) {
        fail_case("open regular metadata fixture /etc/hosts", strerror(errno));
    } else {
        check_one_real_fd("regular", regular, "/etc/hosts", 1);
        raw_probe_close(regular);
    }
}

int main(void)
{
    /* The runner sets this too; keep the source-level contract explicit. */
    if (getenv("BXROOT_NO_AUTORUN") == NULL)
        printf("warning: BXROOT_NO_AUTORUN is not set; constructor was not skipped\n");

    check_proc_fd_shape();
    check_fake_resolvers();
    check_guest_fd_link();
    check_real_fds();

    printf("\n=== result: %d passed / %d failed ===\n", g_ok, g_fail);
    return g_fail != 0;
}
