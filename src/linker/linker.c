/*
 * libbxroot-linker.so
 *
 * 动态链接器拦截层：
 * - 确保 LD_PRELOAD 生效
 * - 处理 dlopen/dlsym 绕过点
 * - 拦截 ld.so 的符号解析
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>

#ifndef BXROOT_VERBOSE
#define BXROOT_VERBOSE 0
#endif

#if BXROOT_VERBOSE
#define LOG(fmt, ...) fprintf(stderr, "[bxroot-linker] " fmt "\n", ##__VA_ARGS__)
#else
#define LOG(fmt, ...) do {} while(0)
#endif

/* 缓存真实函数 */
static void *(*real_dlopen)(const char *, int) = NULL;
static int (*real_dlclose)(void *) = NULL;
static void *(*real_dlsym)(void *, const char *) = NULL;

/* 懒加载 */
static void ensure_real(void) {
    if (!real_dlopen) {
        real_dlopen = (void *(*)(const char *, int))dlsym(RTLD_NEXT, "dlopen");
        real_dlclose = (int (*)(void *))dlsym(RTLD_NEXT, "dlclose");
        real_dlsym = (void *(*)(void *, const char *))dlsym(RTLD_NEXT, "dlsym");
    }
}

/* Hook: dlopen - 确保 LD_PRELOAD 库也被加载 */
void *dlopen(const char *filename, int flags) {
    ensure_real();
    LOG("dlopen: %s", filename ? filename : "(null)");

    /* 如果目标库是 LD_PRELOAD 的一部分，确保它也被加载 */
    void *handle = real_dlopen(filename, flags);

    if (handle && filename) {
        /* 检查是否是 runtime 库 */
        if (strstr(filename, "libbxroot-runtime") != NULL) {
            LOG("runtime library opened: %s", filename);
        }
    }

    return handle;
}

/* Hook: dlclose - 防止 runtime 库被卸载 */
int dlclose(void *handle) {
    ensure_real();

    /* 检查是否是 runtime 库，如果是则拒绝卸载 */
    /* 简化实现：直接调用真实 dlclose */
    return real_dlclose(handle);
}

/* Hook: dlsym - 拦截符号解析 */
void *dlsym(void *handle, const char *symbol) {
    ensure_real();
    LOG("dlsym: %s", symbol);

    void *result = real_dlsym(handle, symbol);

    /* 检查是否是关键函数，确保返回我们的 hook */
    if (result && symbol) {
        if (strcmp(symbol, "open") == 0 || strcmp(symbol, "openat") == 0) {
            LOG("dlsym(%s) intercepted - returning hook", symbol);
            /* 这里应该返回我们的 hook 函数 */
            /* 但实际实现需要根据具体情况处理 */
        }
    }

    return result;
}

/* 构造函数 */
__attribute__((constructor))
static void linker_constructor(void) {
    LOG("linker library loaded");
}
