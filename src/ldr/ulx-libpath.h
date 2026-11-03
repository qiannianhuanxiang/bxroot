#ifndef BXROOT_ULX_LIBPATH_H
#define BXROOT_ULX_LIBPATH_H

#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define BXROOT_ULX_LIBPATH_SIZE (32UL << 10)

static const char *bxroot_ulx_env_value(char *const *envp, const char *name)
{
    size_t n = strlen(name);
    int i;

    for (i = 0; envp != NULL && envp[i] != NULL; i++) {
        if (strncmp(envp[i], name, n) == 0 && envp[i][n] == '=')
            return envp[i] + n + 1;
    }
    return NULL;
}

static int bxroot_ulx_append_libdir(char *dst, size_t cap, size_t *used,
                                    const char *rootfs, const char *guest_dir)
{
    char item[PATH_MAX * 2];
    size_t n, start, root_len;
    int already_host_path;

    if (guest_dir == NULL || guest_dir[0] == '\0')
        return 0;
    root_len = rootfs == NULL ? 0 : strlen(rootfs);
    if (root_len == 1 && rootfs[0] == '/')
        root_len = 0;
    already_host_path = root_len > 0 && rootfs[0] == '/' &&
        strncmp(guest_dir, rootfs, root_len) == 0 &&
        (guest_dir[root_len] == '\0' || guest_dir[root_len] == '/');
    if (guest_dir[0] == '/' && rootfs != NULL && rootfs[0] == '/' &&
        root_len != 0 && !already_host_path) {
        if (snprintf(item, sizeof(item), "%s%s", rootfs, guest_dir) >=
            (int)sizeof(item))
            return -1;
    } else if (snprintf(item, sizeof(item), "%s", guest_dir) >=
               (int)sizeof(item)) {
        return -1;
    }
    n = strlen(item);
    start = 0;
    while (start < *used) {
        size_t end = start;
        while (end < *used && dst[end] != ':')
            end++;
        if (end - start == n && memcmp(dst + start, item, n) == 0)
            return 0;
        start = end + 1;
    }
    if (*used != 0) {
        if (*used + 1 >= cap)
            return -1;
        dst[(*used)++] = ':';
    }
    if (*used + n >= cap)
        return -1;
    memcpy(dst + *used, item, n);
    *used += n;
    dst[*used] = '\0';
    return 0;
}

static int bxroot_ulx_append_env_libpath(char *dst, size_t cap, size_t *used,
                                         const char *rootfs, const char *value)
{
    const char *p = value;
    const char *q;
    char entry[PATH_MAX * 2];
    size_t n;

    if (value == NULL)
        return 0;
    while (*p != '\0') {
        q = strchr(p, ':');
        n = q == NULL ? strlen(p) : (size_t)(q - p);
        if (n >= sizeof(entry))
            return -1;
        memcpy(entry, p, n);
        entry[n] = '\0';
        if (bxroot_ulx_append_libdir(dst, cap, used, rootfs, entry) != 0)
            return -1;
        if (q == NULL)
            break;
        p = q + 1;
    }
    return 0;
}

#endif
