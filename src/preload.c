#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>

#include "config.h"

/* 缓存 rootfs 路径 */
static char *rootfs_path = NULL;

/* 获取 rootfs 路径 */
static char *get_rootfs(void) {
    if (!rootfs_path) {
        const char *env = getenv("BXROOT_ROOTFS");
        if (env && env[0]) {
            rootfs_path = strdup(env);
        } else {
            rootfs_path = strdup(BXROOT_ROOTFS);
        }
        LOG("rootfs: %s", rootfs_path);
    }
    return rootfs_path;
}

/* 翻译路径：绝对路径加上 rootfs 前缀 */
static int translate_path(const char *path, char *out, size_t out_size) {
    if (!path || !out || out_size == 0) {
        return -1;
    }

    /* 相对路径，不翻译 */
    if (path[0] != '/') {
        strncpy(out, path, out_size - 1);
        out[out_size - 1] = '\0';
        return 0;
    }

    /* 绝对路径，加上 rootfs 前缀 */
    char *rootfs = get_rootfs();
    int ret = snprintf(out, out_size, "%s%s", rootfs, path);
    if (ret < 0 || (size_t)ret >= out_size) {
        LOG("path too long: %s", path);
        return -1;
    }

    LOG("translate: %s -> %s", path, out);
    return 1;
}

/* Hook: open */
int open(const char *path, int flags, ...) {
    static int (*real_open)(const char *, int, ...) = NULL;
    if (!real_open) {
        real_open = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT, "open");
    }

    char translated[MAX_PATH_LEN];
    int result;

    if (translate_path(path, translated, sizeof(translated)) > 0) {
        /* 处理变参 */
        mode_t mode = 0;
        if (flags & O_CREAT) {
            va_list args;
            va_start(args, flags);
            mode = va_arg(args, mode_t);
            va_end(args);
        }
        result = real_open(translated, flags, mode);
    } else {
        result = real_open(path, flags);
    }

    return result;
}

/* Hook: openat */
int openat(int dirfd, const char *path, int flags, ...) {
    static int (*real_openat)(int, const char *, int, ...) = NULL;
    if (!real_openat) {
        real_openat = (int (*)(int, const char *, int, ...))dlsym(RTLD_NEXT, "openat");
    }

    char translated[MAX_PATH_LEN];
    int result;

    if (translate_path(path, translated, sizeof(translated)) > 0) {
        mode_t mode = 0;
        if (flags & O_CREAT) {
            va_list args;
            va_start(args, flags);
            mode = va_arg(args, mode_t);
            va_end(args);
        }
        result = real_openat(dirfd, translated, flags, mode);
    } else {
        result = real_openat(dirfd, path, flags);
    }

    return result;
}

/* Hook: stat */
int stat(const char *path, struct stat *buf) {
    static int (*real_stat)(const char *, struct stat *) = NULL;
    if (!real_stat) {
        real_stat = (int (*)(const char *, struct stat *))dlsym(RTLD_NEXT, "stat");
    }

    char translated[MAX_PATH_LEN];

    if (translate_path(path, translated, sizeof(translated)) > 0) {
        return real_stat(translated, buf);
    } else {
        return real_stat(path, buf);
    }
}

/* Hook: newfstatat (glibc 2.33+ 使用这个) */
int newfstatat(int dirfd, const char *path, struct stat *buf, int flags) {
    static int (*real_newfstatat)(int, const char *, struct stat *, int) = NULL;
    if (!real_newfstatat) {
        real_newfstatat = (int (*)(int, const char *, struct stat *, int))dlsym(RTLD_NEXT, "newfstatat");
    }

    char translated[MAX_PATH_LEN];

    if (translate_path(path, translated, sizeof(translated)) > 0) {
        return real_newfstatat(dirfd, translated, buf, flags);
    } else {
        return real_newfstatat(dirfd, path, buf, flags);
    }
}

/* Hook: lstat */
int lstat(const char *path, struct stat *buf) {
    static int (*real_lstat)(const char *, struct stat *) = NULL;
    if (!real_lstat) {
        real_lstat = (int (*)(const char *, struct stat *))dlsym(RTLD_NEXT, "lstat");
    }

    char translated[MAX_PATH_LEN];

    if (translate_path(path, translated, sizeof(translated)) > 0) {
        return real_lstat(translated, buf);
    } else {
        return real_lstat(path, buf);
    }
}

/* Hook: access */
int access(const char *path, int mode) {
    static int (*real_access)(const char *, int) = NULL;
    if (!real_access) {
        real_access = (int (*)(const char *, int))dlsym(RTLD_NEXT, "access");
    }

    char translated[MAX_PATH_LEN];

    if (translate_path(path, translated, sizeof(translated)) > 0) {
        return real_access(translated, mode);
    } else {
        return real_access(path, mode);
    }
}

/* Hook: readlink */
ssize_t readlink(const char *path, char *buf, size_t buf_size) {
    static ssize_t (*real_readlink)(const char *, char *, size_t) = NULL;
    if (!real_readlink) {
        real_readlink = (ssize_t (*)(const char *, char *, size_t))dlsym(RTLD_NEXT, "readlink");
    }

    char translated[MAX_PATH_LEN];

    if (translate_path(path, translated, sizeof(translated)) > 0) {
        return real_readlink(translated, buf, buf_size);
    } else {
        return real_readlink(path, buf, buf_size);
    }
}

/* Hook: realpath */
char *realpath(const char *path, char *resolved) {
    static char *(*real_realpath)(const char *, char *) = NULL;
    if (!real_realpath) {
        real_realpath = (char * (*)(const char *, char *))dlsym(RTLD_NEXT, "realpath");
    }

    char translated[MAX_PATH_LEN];

    if (translate_path(path, translated, sizeof(translated)) > 0) {
        return real_realpath(translated, resolved);
    } else {
        return real_realpath(path, resolved);
    }
}

/* Hook: execve (关键：处理程序执行) */
int execve(const char *path, char *const argv[], char *const envp[]) {
    static int (*real_execve)(const char *, char *const [], char *const []) = NULL;
    if (!real_execve) {
        real_execve = (int (*)(const char *, char *const [], char *const []))dlsym(RTLD_NEXT, "execve");
    }

    char translated[MAX_PATH_LEN];

    if (translate_path(path, translated, sizeof(translated)) > 0) {
        LOG("execve: %s", path);
        return real_execve(translated, argv, envp);
    } else {
        LOG("execve (relative): %s", path);
        return real_execve(path, argv, envp);
    }
}
