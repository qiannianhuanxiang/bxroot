/* Focused host-world regression tests. SPDX-License-Identifier: MIT */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "host-common.h"
#include "host-world.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

extern char **environ;

#define IMAGE_MAX 4096
#define PT_LOAD 1u
#define PT_INTERP 3u
#define EM_AARCH64 183u
#define ET_EXEC 2u
#define ET_DYN 3u
#define EM_WRONG 62u

struct mem_image {
    unsigned char data[IMAGE_MAX];
    size_t len;
};

static struct mem_image *g_mem;
static unsigned g_checks;
static unsigned g_failures;

#define CHECK(cond, fmt, ...) do { \
    g_checks++; \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: " fmt "\n", ##__VA_ARGS__); \
        g_failures++; \
    } \
} while (0)

static long mem_pread(int fd, void *out, size_t n, uint64_t off)
{
    (void)fd;
    if (!g_mem || off > g_mem->len || n > g_mem->len - (size_t)off)
        return -1;
    memcpy(out, g_mem->data + (size_t)off, n);
    return (long)n;
}

static void put16(unsigned char *p, uint16_t v)
{
    p[0] = (unsigned char)v;
    p[1] = (unsigned char)(v >> 8);
}

static void put32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)v;
    p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16);
    p[3] = (unsigned char)(v >> 24);
}

static void put64(unsigned char *p, uint64_t v)
{
    put32(p, (uint32_t)v);
    put32(p + 4, (uint32_t)(v >> 32));
}

static void image_base(struct mem_image *m, uint16_t machine, uint16_t type,
                       uint64_t phoff, uint16_t entsize, uint16_t count,
                       uint64_t entry)
{
    memset(m, 0, sizeof(*m));
    m->len = IMAGE_MAX;
    m->data[0] = 0x7f;
    m->data[1] = 'E';
    m->data[2] = 'L';
    m->data[3] = 'F';
    m->data[4] = 2;                 /* ELFCLASS64 */
    m->data[5] = 1;                 /* ELFDATA2LSB */
    m->data[6] = 1;                 /* EV_CURRENT */
    put16(m->data + 16, type);
    put16(m->data + 18, machine);
    put64(m->data + 24, entry);
    put64(m->data + 32, phoff);
    put16(m->data + 52, 64);        /* e_ehsize */
    put16(m->data + 54, entsize);
    put16(m->data + 56, count);
}

static void phdr(struct mem_image *m, unsigned index, uint32_t type,
                 uint64_t offset, uint64_t filesz)
{
    size_t off = 64u + (size_t)index * 56u;
    put32(m->data + off, type);
    put32(m->data + off + 4, 5);     /* executable LOAD-like flags */
    put64(m->data + off + 8, offset);
    put64(m->data + off + 16, 0x400000);
    put64(m->data + off + 24, 0x400000);
    put64(m->data + off + 32, filesz);
    put64(m->data + off + 40, filesz);
    put64(m->data + off + 48, 0x1000);
}

static void interp(struct mem_image *m, uint64_t offset, const unsigned char *s,
                   size_t n)
{
    memcpy(m->data + offset, s, n);
}

static int classify(struct mem_image *m, const char *path)
{
    g_mem = m;
    return bxhc_elf(7, path, mem_pread);
}

static void test_elf_classifier(void)
{
    struct mem_image m;
    static const unsigned char bionic[] =
        "/system/bin/linker64";
    static const unsigned char bionic_apex[] =
        "/apex/com.android.runtime/bin/linker64";
    static const unsigned char glibc[] =
        "/lib/ld-linux-aarch64.so.1";
    unsigned char bad_nul[] = "/system/bin/linker64";
    unsigned char embedded_nul[] = "/system/bin/linker64\0junk\0";
    int got;

    image_base(&m, EM_AARCH64, ET_DYN, 64, 56, 1, 0x400000);
    phdr(&m, 0, PT_INTERP, 512, sizeof(bionic));
    interp(&m, 512, bionic, sizeof(bionic));
    got = classify(&m, "/tmp/copied-bionic");
    CHECK(got == BX_HOST_WORLD_BIONIC,
          "normal bionic classified as %d", got);

    image_base(&m, EM_AARCH64, ET_EXEC, 64, 56, 1, 0x400000);
    phdr(&m, 0, PT_INTERP, 512, sizeof(bionic_apex));
    interp(&m, 512, bionic_apex, sizeof(bionic_apex));
    got = classify(&m, "/system/bin/apex-tool");
    CHECK(got == BX_HOST_WORLD_BIONIC,
          "apex bionic classified as %d", got);

    image_base(&m, EM_AARCH64, ET_DYN, 64, 56, 1, 0x400000);
    phdr(&m, 0, PT_INTERP, 512, sizeof(glibc));
    interp(&m, 512, glibc, sizeof(glibc));
    got = classify(&m, "/system/bin/glibc-tool");
    CHECK(got == BX_HOST_WORLD_NO, "glibc accepted as %d", got);

    image_base(&m, EM_AARCH64, ET_EXEC, 64, 56, 1, 0x400000);
    phdr(&m, 0, PT_LOAD, 512, 0);
    got = classify(&m, "/usr/bin/static-guest");
    CHECK(got == BX_HOST_WORLD_NO, "static guest accepted as %d", got);

    image_base(&m, EM_AARCH64, ET_EXEC, 64, 56, 1, 0x400000);
    phdr(&m, 0, PT_LOAD, 512, 0);
    got = classify(&m, "/system/bin/static-host");
    CHECK(got == BX_HOST_WORLD_STATIC, "static host rejected as %d", got);

    image_base(&m, EM_AARCH64, ET_DYN, 64, 56, 1, 0x400000);
    phdr(&m, 0, PT_INTERP, 512, sizeof(bad_nul) - 1);
    interp(&m, 512, bad_nul, sizeof(bad_nul) - 1);
    got = classify(&m, "/system/bin/non-nul");
    CHECK(got == BX_HOST_WORLD_NO, "non-NUL PT_INTERP accepted as %d", got);

    image_base(&m, EM_AARCH64, ET_DYN, 64, 56, 1, 0x400000);
    phdr(&m, 0, PT_INTERP, 512, sizeof(embedded_nul));
    interp(&m, 512, embedded_nul, sizeof(embedded_nul));
    got = classify(&m, "/system/bin/embedded-nul");
    CHECK(got == BX_HOST_WORLD_NO,
          "embedded-NUL PT_INTERP accepted as %d", got);

    image_base(&m, EM_AARCH64, ET_DYN, UINT64_MAX, 56, 1, 0x400000);
    got = classify(&m, "/system/bin/bad-phoff");
    CHECK(got == BX_HOST_WORLD_NO, "overflowing phoff accepted as %d", got);

    image_base(&m, EM_AARCH64, ET_DYN, 64, 56, 1, 0x400000);
    phdr(&m, 0, PT_INTERP, UINT64_MAX, sizeof(bionic));
    got = classify(&m, "/system/bin/bad-poff");
    CHECK(got == BX_HOST_WORLD_NO, "overflowing PT_INTERP offset accepted as %d", got);

    image_base(&m, EM_AARCH64, ET_DYN, 64, 56, 2, 0x400000);
    phdr(&m, 0, PT_INTERP, 512, sizeof(bionic));
    phdr(&m, 1, PT_INTERP, 512, sizeof(bionic));
    interp(&m, 512, bionic, sizeof(bionic));
    got = classify(&m, "/system/bin/repeated-interp");
    CHECK(got == BX_HOST_WORLD_NO, "repeated PT_INTERP accepted as %d", got);

    image_base(&m, EM_AARCH64, ET_DYN, 64, 56, 1, 0x400000);
    m.len = 64 + 56 - 1;
    got = classify(&m, "/system/bin/truncated-phdr");
    CHECK(got == BX_HOST_WORLD_NO, "truncated phdr accepted as %d", got);

    image_base(&m, EM_WRONG, ET_DYN, 64, 56, 1, 0x400000);
    phdr(&m, 0, PT_INTERP, 512, sizeof(bionic));
    interp(&m, 512, bionic, sizeof(bionic));
    got = classify(&m, "/system/bin/wrong-arch");
    CHECK(got == BX_HOST_WORLD_NO, "wrong architecture accepted as %d", got);
}

static char *find_env(char *const env[], const char *name)
{
    size_t i, n = strlen(name);
    for (i = 0; env && env[i]; i++)
        if (!strncmp(env[i], name, n) && env[i][n] == '=')
            return env[i] + n + 1;
    return NULL;
}

static int has_exact_env(char *const env[], const char *name,
                         const char *value)
{
    char *got = find_env(env, name);
    return got && !strcmp(got, value);
}

static int has_prefix_env(char *const env[], const char *prefix)
{
    size_t i;
    for (i = 0; env && env[i]; i++)
        if (!strncmp(env[i], prefix, strlen(prefix)))
            return 1;
    return 0;
}

static void test_build_env(void)
{
    enum { MANY = 300 };
    char **input;
    char **out = NULL;
    char **owned;
    size_t i, out_count = 0, foo_count = 0;
    char home[128], tmp[128], host_path[256];

    snprintf(home, sizeof(home), "/tmp/bx-host-world-home-%ld", (long)getpid());
    snprintf(tmp, sizeof(tmp), "/tmp/bx-host-world-tmp-%ld", (long)getpid());
    snprintf(host_path, sizeof(host_path), "/system/bin:/custom/native/bin");
    CHECK(setenv("BXROOT_HOST_HOME", home, 1) == 0,
          "setenv BXROOT_HOST_HOME failed");
    CHECK(setenv("BXROOT_HOST_TMPDIR", tmp, 1) == 0,
          "setenv BXROOT_HOST_TMPDIR failed");
    CHECK(setenv("BXROOT_HOST_PATH", host_path, 1) == 0,
          "setenv BXROOT_HOST_PATH failed");

    input = calloc((size_t)MANY + 12, sizeof(*input));
    owned = calloc(MANY, sizeof(*owned));
    CHECK(input != NULL && owned != NULL, "environment allocation failed");
    if (!input || !owned) {
        free(input);
        free(owned);
        return;
    }
    input[0] = (char *)"FOO=bar";
    input[1] = (char *)"TERM=xterm-256color";
    input[2] = (char *)"LD_PRELOAD=/guest/lib.so";
    input[3] = (char *)"LD_LIBRARY_PATH=/guest/lib";
    input[4] = (char *)"BXROOT_ROOTFS=/guest/rootfs";
    input[5] = (char *)"BXROOT_AUTO_HOST=1";
    input[6] = (char *)"PROROOT_ROOTFS=/guest/rootfs";
    input[7] = (char *)"PROOT_TMP_DIR=/guest/tmp";
    input[8] = (char *)"PWD=/guest";
    input[9] = (char *)"HOME=/guest-home";
    input[10] = (char *)"TMPDIR=/guest-tmp";
    for (i = 0; i < MANY; i++) {
        char buf[64];
        snprintf(buf, sizeof(buf), "FOO_%03zu=value-%03zu", i, i);
        owned[i] = strdup(buf);
        input[11 + i] = owned[i];
    }
    input[11 + MANY] = NULL;

    CHECK(bx_host_world_build_env(input, &out) == 0,
          "bx_host_world_build_env failed errno=%d", errno);
    CHECK(out != NULL, "build-env returned NULL");
    if (out) {
        for (i = 0; out[i]; i++) {
            out_count++;
            if (!strncmp(out[i], "FOO_", 4))
                foo_count++;
        }
        CHECK(has_exact_env(out, "FOO", "bar"), "ordinary FOO was not retained");
        CHECK(has_exact_env(out, "TERM", "xterm-256color"), "TERM was not retained");
        CHECK(has_exact_env(out, "PATH", host_path),
              "custom BXROOT_HOST_PATH did not become PATH");
        CHECK(has_exact_env(out, "HOME", home),
              "HOME is not the configured absolute host path");
        CHECK(has_exact_env(out, "TMPDIR", tmp),
              "TMPDIR is not the configured absolute host path");
        CHECK(home[0] == '/' && tmp[0] == '/',
              "test host paths are not absolute");
        CHECK(foo_count == MANY,
              "environment was truncated: FOO_ entries=%zu expected=%d",
              foo_count, MANY);
        CHECK(out_count > 256, "environment output unexpectedly <=256 entries: %zu",
              out_count);
        CHECK(!has_prefix_env(out, "LD_PRELOAD="), "LD_PRELOAD survived");
        CHECK(!has_prefix_env(out, "LD_LIBRARY_PATH="),
              "LD_LIBRARY_PATH survived");
        CHECK(!has_prefix_env(out, "BXROOT_"), "BXROOT_* survived");
        CHECK(!has_prefix_env(out, "PROROOT_"), "PROROOT_* survived");
        CHECK(!has_prefix_env(out, "PROOT_"), "PROOT_* survived");
        bx_host_world_free_env(out);
    }
    for (i = 0; i < MANY; i++)
        free(owned[i]);
    free(owned);
    free(input);
    unsetenv("BXROOT_HOST_HOME");
    unsetenv("BXROOT_HOST_TMPDIR");
    unsetenv("BXROOT_HOST_PATH");
}

static void path_case(const char *guest, const char *host, const char *want)
{
    char *out = NULL, *again = NULL;
    int rc = bx_host_world_guest_path(guest, host, &out);
    CHECK(rc == 0 && out && !strcmp(out, want),
          "guest-path got [%s], want [%s], rc=%d", out ? out : "NULL", want, rc);
    if (out) {
        rc = bx_host_world_guest_path(out, host, &again);
        CHECK(rc == 0 && again && !strcmp(out, again), "guest PATH is not idempotent");
    }
    free(out); free(again);
}
static void test_guest_path(void)
{
    char *out = (char *)(uintptr_t)1;
    char **saved = environ;
    char *normal[] = { (char *)"BXROOT_AUTO_HOST=1",
        (char *)"BXROOT_HOST_PATH=/system/bin:/system/bin:/vendor/bin",
        (char *)"PATH=/usr/bin::/bin:", (char *)"FOO=bar", NULL,
        (char *)(uintptr_t)0xfeed };
    char *missing[] = { (char *)"BXROOT_AUTO_HOST=1", NULL, (char *)(uintptr_t)0xbeef };
    char *empty[] = { (char *)"BXROOT_AUTO_HOST=1", (char *)"PATH=", NULL };
    char *disabled[] = { (char *)"BXROOT_AUTO_HOST=0", (char *)"PATH=/bin", NULL };
    char *no_fallback[] = { (char *)"BXROOT_AUTO_HOST=1", (char *)"BXROOT_HOST_PATH=", NULL };
    char *entry, *old_entry = normal[2], *old_empty = empty[1], *old_disabled = disabled[1];
    int rc;
    path_case(NULL, NULL, BX_HOST_GUEST_DEFAULT_PATH ":" BX_HOST_DEFAULT_PATH);
    path_case("", NULL, ":" BX_HOST_DEFAULT_PATH);
    path_case("", "", "");
    path_case("/bin::/usr/bin:", "/system/bin:/system/bin:/vendor/bin",
              "/bin::/usr/bin::/system/bin:/vendor/bin");
    path_case("/system/bin:/bin", "/system/bin:/vendor/bin", "/system/bin:/bin:/vendor/bin");
    path_case("/system/bin-extra:/bin", "/system/bin", "/system/bin-extra:/bin:/system/bin");
    path_case("/bin", ":relative:./native::/system/bin:", "/bin:/system/bin");
    path_case("/bin", "", "/bin");
    path_case(NULL, "", BX_HOST_GUEST_DEFAULT_PATH);
    errno = 0;
    CHECK(bx_host_world_guest_path("/bin", NULL, NULL) == -1 && errno == EINVAL,
          "NULL PATH output did not reject EINVAL");
    rc = bx_host_world_guest_path("/bin", "/system/bin", &out);
    CHECK(rc == 0 && out, "caller cannot construct a missing PATH before exec");
    free(out);

    /* This array represents the original envp that bash imports. No spare
     * slots are usable: after NULL is an auxv-like guard that must not change. */
    environ = normal;
    rc = bx_host_world_init_path();
    CHECK(rc == 0 && environ == normal, "init replaced original environ vector");
    CHECK(normal[2] != old_entry && !strcmp(normal[2],
          "PATH=/usr/bin::/bin::/system/bin:/vendor/bin"), "initial PATH slot not updated correctly");
    CHECK(!strcmp(old_entry, "PATH=/usr/bin::/bin:"), "old loader-owned PATH string was changed");
    CHECK(normal[4] == NULL && normal[5] == (char *)(uintptr_t)0xfeed,
          "init wrote beyond original envp terminator");
    entry = normal[2];
    CHECK(bx_host_world_init_path() == 0 && normal[2] == entry,
          "idempotent init replaced PATH again");
    environ = saved;
    if (entry != old_entry) free(entry);

    environ = missing;
    CHECK(bx_host_world_init_path() == BX_HOST_PATH_MISSING, "missing PATH not reported to parent");
    CHECK(environ == missing && missing[1] == NULL && missing[2] == (char *)(uintptr_t)0xbeef,
          "missing PATH grew loader's envp vector");
    environ = empty;
    CHECK(bx_host_world_init_path() == 0 && !strcmp(empty[1], "PATH=:" BX_HOST_DEFAULT_PATH),
          "explicit empty PATH lost current-directory component");
    entry = empty[1];
    environ = saved;
    if (entry != old_empty) free(entry);
    environ = disabled;
    CHECK(bx_host_world_init_path() == 0 && disabled[1] == old_disabled,
          "AUTO_HOST=0 altered initial PATH");
    environ = no_fallback;
    CHECK(bx_host_world_init_path() == 0 && no_fallback[2] == NULL,
          "empty host PATH requested insertion into a missing PATH");
    environ = saved;
}

static char mapped_interpreter[4096];
static int script_mapper(const char *guest, char *backing, size_t cap)
{
    size_t n = strlen(mapped_interpreter);
    if (strcmp(guest, "/system/bin/sh")) { errno = EINVAL; return -1; }
    if (n >= cap) { errno = ENAMETOOLONG; return -1; }
    memcpy(backing, mapped_interpreter, n + 1);
    return 1;
}
static void write_fixture(int fd, const void *data, size_t len)
{
    const unsigned char *p = data;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n <= 0) { perror("write fixture"); exit(2); }
        p += n; len -= (size_t)n;
    }
}
static void test_script_prepare(void)
{
    char script[] = "/tmp/bx-host-script.XXXXXX";
    char native[] = "/tmp/bx-host-interpreter.XXXXXX";
    static const char line[] = "#!/system/bin/sh -e\necho fixture\n";
    static const unsigned char bionic[] = "/system/bin/linker64";
    static const unsigned char glibc[] = "/lib/ld-linux-aarch64.so.1";
    struct mem_image m;
    bx_host_plan plan;
    char *argv[] = { (char *)"caller-name", (char *)"argument with spaces", NULL };
    int fd = mkstemp(script), interp_fd = mkstemp(native), rc;
    CHECK(fd >= 0 && interp_fd >= 0, "cannot create script fixtures");
    if (fd < 0 || interp_fd < 0) exit(2);
    write_fixture(fd, line, sizeof(line) - 1);
    image_base(&m, EM_AARCH64, ET_DYN, 64, 56, 1, 0x400000);
    phdr(&m, 0, PT_INTERP, 512, sizeof(bionic));
    interp(&m, 512, bionic, sizeof(bionic));
    write_fixture(interp_fd, m.data, m.len);
    snprintf(mapped_interpreter, sizeof(mapped_interpreter), "%s", native);
    CHECK(fchmod(fd, 0644) == 0, "cannot set readable nonexecutable script");
    errno = 0;
    CHECK(bx_host_world_script_access(script) == -1 && errno == EACCES,
          "raw X_OK accepted a mode0644 script");
    CHECK(bx_host_world_classify_mapped(script, script_mapper) == BX_HOST_WORLD_SCRIPT,
          "mapped bionic interpreter not recognized");
    errno = 0;
    rc = bx_host_world_prepare_mapped(script, argv, script_mapper, &plan);
    CHECK(rc == -1 && errno == EACCES && !plan.rewritten,
          "prepare accepted nonexecutable script, rc=%d errno=%d", rc, errno);
    errno = 0;
    CHECK(bx_host_world_exec_mapped(script, argv, NULL, script_mapper) == -1 && errno == EACCES,
          "exec_mapped did not reject nonexecutable script before spawning interpreter");
    CHECK(fchmod(fd, 0755) == 0, "cannot enable script execute bits");
    CHECK(bx_host_world_script_access(script) == 0, "raw X_OK rejected executable script");
    rc = bx_host_world_prepare_mapped(script, argv, script_mapper, &plan);
    CHECK(rc == 1 && plan.rewritten, "mapped script plan not prepared");
    if (rc == 1 && plan.rewritten) {
        CHECK(!strcmp(plan.target, native), "script plan ignored bind-mapped interpreter");
        CHECK(!strcmp(plan.argv[0], native) && !strcmp(plan.argv[1], "-e") &&
              !strcmp(plan.argv[2], script) && !strcmp(plan.argv[3], argv[1]) && !plan.argv[4],
              "script plan lost backing path, optional argument, or argv boundary");
        bx_host_world_dispose(&plan);
    }
    /* The same literal /system/bin/sh now binds to glibc: stay in guest world. */
    image_base(&m, EM_AARCH64, ET_DYN, 64, 56, 1, 0x400000);
    phdr(&m, 0, PT_INTERP, 512, sizeof(glibc));
    interp(&m, 512, glibc, sizeof(glibc));
    CHECK(lseek(interp_fd, 0, SEEK_SET) == 0, "cannot rewrite bound interpreter");
    write_fixture(interp_fd, m.data, m.len);
    CHECK(bx_host_world_classify_mapped(script, script_mapper) == BX_HOST_WORLD_NO,
          "glibc bind override was bypassed by literal host interpreter");
    CHECK(bx_host_world_prepare_mapped(script, argv, script_mapper, &plan) == 0,
          "prepare bypassed glibc bind override");
    close(fd); close(interp_fd);
    /* These absolute targets came directly from mkstemp and are checked here. */
    CHECK(!strncmp(script, "/tmp/bx-host-script.", 20) && unlink(script) == 0,
          "cannot clean verified script fixture");
    CHECK(!strncmp(native, "/tmp/bx-host-interpreter.", 25) && unlink(native) == 0,
          "cannot clean verified interpreter fixture");
}

int main(void)
{
    printf("host-world: classifier\n");
    test_elf_classifier();
    printf("host-world: build-env\n");
    test_build_env();
    printf("host-world: startup-path\n");
    test_guest_path();
    printf("host-world: mapped-script / raw X_OK\n");
    test_script_prepare();
    if (g_failures) {
        fprintf(stderr, "RESULT: FAIL checks=%u failures=%u\n",
                g_checks, g_failures);
        return 1;
    }
    printf("RESULT: PASS host-world checks=%u\n", g_checks);
    return 0;
}
