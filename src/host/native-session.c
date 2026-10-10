/* Runtime-side export of effective native session. SPDX-License-Identifier: MIT */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "session.h"
#include "../runtime/config.h"
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>
extern char **environ;
static bx_session active;
static int active_fd = -1;
static struct stat active_identity;
static char active_num[32];
static char *guest_path, *guest_home, *guest_tmp, *guest_libs;
static int captured;
static char **original_env;
static const char *native_env(const char *key)
{
    size_t n = strlen(key), i;
    for (i = 0; environ && environ[i]; i++)
        if (!strncmp(environ[i], key, n) && environ[i][n] == '=') return environ[i] + n + 1;
    return NULL;
}
void bx_native_session_capture(void)
{
    const char *p;
    if (captured || !native_env("BXROOT_REENTRY") || strcmp(native_env("BXROOT_REENTRY"), "1")) return;
    captured = 1;
    original_env = environ;
    p = native_env("BXROOT_GUEST_PATH"); if (!p) p = native_env("PATH");
    guest_path = strdup(p ? p : "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    p = native_env("HOME"); guest_home = strdup(p ? p : "/root");
    p = native_env("TMPDIR"); guest_tmp = strdup(p ? p : "/tmp");
    p = native_env("LD_LIBRARY_PATH"); if (p) guest_libs = strdup(p);
}
static int active_alive(void)
{
    unsigned char h[12]; struct stat st; long flags;
    if (active_fd < 3 || (flags = bx_session_raw(SYS_fcntl, active_fd, F_GETFD, 0, 0, 0, 0)) < 0 ||
        bx_session_raw(SYS_fstat, active_fd, (long)&st, 0, 0, 0, 0) < 0 ||
        st.st_dev != active_identity.st_dev || st.st_ino != active_identity.st_ino) return 0;
    if ((flags & FD_CLOEXEC) && bx_session_raw(SYS_fcntl, active_fd, F_SETFD, flags & ~FD_CLOEXEC, 0, 0, 0) < 0) return 0;
    return bx_session_raw(SYS_pread64, active_fd, (long)h, sizeof(h), 0, 0, 0) == (long)sizeof(h) &&
        !memcmp(h, "BXSESS3\0", 8) && h[8] == 1 && !h[9] && !h[10] && !h[11];
}
static int publish_slot(const char *name, const char *value)
{
    size_t n = strlen(name), i;
    if (!value) { errno = EPROTO; return -1; }
    for (i = 0; original_env && original_env[i]; i++) {
        if (!strncmp(original_env[i], name, n) && original_env[i][n] == '=') {
            char *entry = malloc(n + strlen(value) + 2);
            if (!entry) return -1;
            memcpy(entry, name, n); entry[n] = '='; strcpy(entry + n + 1, value);
            original_env[i] = entry; break;
        }
    }
    /* Never append beyond the original NULL: auxv may follow it. */
    return setenv(name, value, 1);
}
const char *bx_native_session_value(const char *name)
{
    if (!name || !active_alive()) return NULL;
    if (!strcmp(name, "BXROOT_SESSION_FD")) return active_num;
    if (!strcmp(name, "BXROOT_ENTER")) return bx_session_get(&active, name);
    if (!strcmp(name, "BXROOT_REENTRY")) return "1";
    if (!strcmp(name, "BXROOT_GUEST_PATH")) return bx_session_get(&active, "_GUEST_PATH");
    return bx_session_get(&active, name);
}
static int session_value(bx_session *s, const char *key, const char *value)
{ return value ? bx_session_set(s, key, value) : 0; }
static int runtime_path(char *out, size_t cap, const char *value)
{
    char guest[BX_SESSION_PATH]; int n;
    extern int bxroot_translate_path(const char *, char *, size_t);
    if (!value || value[0] != '/') { errno = EINVAL; return -1; }
    if (!strncmp(value, "/proc/", 6) || bx_session_raw(SYS_faccessat, AT_FDCWD, (long)value, R_OK, 0, 0, 0) == 0)
        n = snprintf(out, cap, "%s", value);
    else {
        int rc = bxroot_translate_path(value, guest, sizeof(guest));
        if (rc < 0) { errno = ENAMETOOLONG; return -1; }
        n = snprintf(out, cap, "%s", rc > 0 ? guest : value);
    }
    if (n < 0 || (size_t)n >= cap) { errno = ENAMETOOLONG; return -1; }
    return 0;
}
int bx_native_session_init(void)
{
    static const char *const settings[] = {
        "BXROOT_AUTO_HOST", "BXROOT_HOST_PATH", "BXROOT_HOST_HOME", "BXROOT_HOST_TMPDIR",
        "BXROOT_FAKE_UID", "BXROOT_FAKE_GID", "BXROOT_FAKE_ALL", "BXROOT_FAKE_OFF", "BXROOT_FAKE_SLOTS",
        "BXROOT_LINK2SYMLINK", "BXROOT_L2S_DIR", "PROOT_L2S_DIR", "BXROOT_NO_LIVEPATCH",
        "BXROOT_RAW_SYSCALL", "BXROOT_NO_CRASH", "BXROOT_CRASH_CHAIN", "BXROOT_NO_PATHRELAY",
        "BXROOT_INJECT_ENV", "BXROOT_VERBOSE", "BXROOT_FORCE_NO_LDSO_SERVICE",
        "BXROOT_ULX_PATH", "BXROOT_ULX_LDSO", "BXROOT_STUB_LOADER_EXEC",
        "PROROOT_TRAMPOLINE_PATH", "PROROOT_LINKER_PATH", "PROROOT_LIB_PATH",
        "PROROOT_STUB_LOADER", "PROROOT_CFG_FD", "PROROOT_ESCAPE_FD", "PROROOT_TMP_DIR"
    };
    const char *entry = native_env("BXROOT_ENTER"), *fdtext = native_env("BXROOT_SESSION_FD");
    const char *tramp, *linker, *runtime, *v;
    bx_session s; char buf[BX_SESSION_PATH], libs[BX_SESSION_PATH * 4 + 128];
    int fd = -1, e; size_t i; Dl_info info;
    if (!native_env("BXROOT_REENTRY") || strcmp(native_env("BXROOT_REENTRY"), "1")) return 0;
    if (active_alive()) return 0;
    bx_native_session_capture();
    if (!guest_path || !guest_home || !guest_tmp) { errno = ENOMEM; return -1; }
    bx_session_init(&s);
    if (fdtext && *fdtext) {
        fd = bx_session_fd_number(fdtext);
        if (fd < 0 || bx_session_read(fd, &s)) goto fail;
        v = bx_session_get(&s, "BXROOT_ROOTFS");
        if (!v || strcmp(v, g_config.rootfs) ||
            !bx_session_get(&s, "BXROOT_ENTER") || !bx_session_get(&s, "_GUEST_PATH")) { errno = ESTALE; goto fail; }
        /* DSHA 的 PROROOT_CFG_FD 与 BXROOT_BINDS 可能同时携带同一条 bind。
           配置解析会去重/重排，不能用原始记录数判断会话过期；按有效
           (host, guest, ro) 集合逐项核对，仍拒绝任何实际路径或只读属性漂移。 */
        for (i = 0; i < (size_t)s.nb; i++) {
            size_t j; int found = 0;
            for (j = 0; j < (size_t)g_config.bind_count; j++)
                if (!strcmp(s.binds[i].host, g_config.bind_sources[j]) &&
                    !strcmp(s.binds[i].guest, g_config.bind_targets[j]) &&
                    s.binds[i].ro == (unsigned)(g_config.bind_readonly && g_config.bind_readonly[j])) {
                    found = 1; break;
                }
            if (!found) { errno = ESTALE; goto fail; }
        }
        for (i = 0; i < (size_t)g_config.bind_count; i++) {
            size_t j; int found = 0;
            for (j = 0; j < s.nb; j++)
                if (!strcmp(s.binds[j].host, g_config.bind_sources[i]) &&
                    !strcmp(s.binds[j].guest, g_config.bind_targets[i]) &&
                    s.binds[j].ro == (unsigned)(g_config.bind_readonly && g_config.bind_readonly[i])) {
                    found = 1; break;
                }
            if (!found) { errno = ESTALE; goto fail; }
        }
        if (bx_session_raw(SYS_fcntl, fd, F_SETFD, 0, 0, 0, 0) < 0) goto fail;
        goto publish;
    }
    runtime = native_env("PROROOT_LIB_PATH"); if (!runtime || !*runtime) runtime = native_env("BXROOT_LIB_PATH");
    if (!runtime && dladdr((void *)bx_native_session_init, &info) && info.dli_fname) runtime = info.dli_fname;
    if (!entry || !*entry) {
        if (runtime_path(buf, sizeof(buf), runtime)) goto fail;
        char *slash = strrchr(buf, '/');
        if (!slash || (size_t)(slash - buf) + 32 >= sizeof(buf)) { errno = ENAMETOOLONG; goto fail; }
        strcpy(slash + 1, "libbxroot-enter.so"); entry = buf;
    }
    if (entry[0] != '/') { errno = EINVAL; goto fail; }
    if (strncmp(entry, "/proc/", 6)) {
        if (snprintf(libs, sizeof(libs), "/proc/self/root%s", entry) >= (int)sizeof(libs)) { errno = ENAMETOOLONG; goto fail; }
        entry = libs;
    }
    if (bx_session_raw(SYS_faccessat, AT_FDCWD, (long)entry, X_OK, 0, 0, 0) < 0 ||
        bx_session_set(&s, "BXROOT_ENTER", entry)) goto fail;
    tramp = native_env("PROROOT_TRAMPOLINE_PATH"); linker = native_env("PROROOT_LINKER_PATH");
    if (!tramp || !*tramp || !linker || !*linker) { tramp = native_env("BXROOT_ULX_PATH"); linker = native_env("BXROOT_ULX_LDSO"); }
    if (!tramp || !linker) { errno = ENOTSUP; goto fail; }
    if (runtime_path(buf, sizeof(buf), tramp) || bx_session_set(&s, "_TRAMP", buf) ||
        runtime_path(buf, sizeof(buf), linker) || bx_session_set(&s, "_LINKER", buf) ||
        runtime_path(buf, sizeof(buf), runtime) || bx_session_set(&s, "_RUNTIME", buf)) goto fail;
    if (bx_session_set(&s, "BXROOT_ROOTFS", g_config.rootfs) ||
        bx_session_set(&s, "BXROOT_REENTRY", "1") ||
        bx_session_set(&s, "BXROOT_FAKEROOT", g_config.fakeroot ? "1" : "0") ||
        bx_session_set(&s, "BXROOT_TMP_DIR", g_config.tmp_dir ? g_config.tmp_dir : "/tmp") ||
        bx_session_set(&s, "_GUEST_PATH", guest_path) || bx_session_set(&s, "BXROOT_GUEST_PATH", guest_path) ||
        bx_session_set(&s, "_GUEST_HOME", guest_home) || bx_session_set(&s, "_GUEST_TMPDIR", guest_tmp)) goto fail;
    for (i = 0; i < sizeof(settings) / sizeof(settings[0]); i++)
        if (session_value(&s, settings[i], native_env(settings[i]))) goto fail;
    if (guest_libs) {
        if (bx_session_set(&s, "_LIBRARY_PATH", guest_libs)) goto fail;
    } else {
        if (snprintf(libs, sizeof(libs), "%s/usr/lib/aarch64-linux-gnu:%s/lib/aarch64-linux-gnu:%s/lib:%s/usr/lib",
                     g_config.rootfs, g_config.rootfs, g_config.rootfs, g_config.rootfs) >= (int)sizeof(libs)) { errno = ENAMETOOLONG; goto fail; }
        if (bx_session_set(&s, "_LIBRARY_PATH", libs)) goto fail;
    }
    for (i = 0; i < (size_t)g_config.bind_count; i++)
        if (bx_session_add_bind(&s, g_config.bind_sources[i], g_config.bind_targets[i],
                               g_config.bind_readonly ? (unsigned)g_config.bind_readonly[i] : 0)) goto fail;
    /* Make the implicit shm redirection visible to the native path helper,
       without modifying effective bind order or exceeding runtime limits. */
    {
        int covered = 0;
        for (i = 0; i < s.nb; i++) {
            size_t n = strlen(s.binds[i].guest);
            if (n <= 8 && !strcmp(s.binds[i].guest, "/")) continue;
            if (n <= 8 && !strncmp("/dev/shm", s.binds[i].guest, n) && (!"/dev/shm"[n] || "/dev/shm"[n] == '/')) covered = 1;
        }
        if (!covered) {
            if (snprintf(libs, sizeof(libs), "%s/.bxroot-shm", g_config.tmp_dir ? g_config.tmp_dir : "/tmp") >= (int)sizeof(libs) ||
                bx_session_to_host(&s, libs, "/", buf, sizeof(buf)) ||
                bx_session_set(&s, "_SHM_HOST", buf) || bx_session_set(&s, "_SHM_GUEST", "/dev/shm")) goto fail;
        }
    }
    fd = bx_session_create_fd(&s); if (fd < 0) goto fail;
publish:
    if (bx_session_raw(SYS_fstat, fd, (long)&active_identity, 0, 0, 0, 0) < 0) goto fail;
    active = s; active_fd = fd;
    snprintf(active_num, sizeof(active_num), "%d", fd);
    if (publish_slot("BXROOT_SESSION_FD", active_num) ||
        publish_slot("BXROOT_ENTER", bx_session_get(&active, "BXROOT_ENTER")) ||
        publish_slot("BXROOT_GUEST_PATH", bx_session_get(&active, "_GUEST_PATH"))) return -1;
    return 0;
fail:
    e = errno; bx_session_dispose(&s); errno = e; return -1;
}
