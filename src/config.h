#ifndef CONFIG_H
#define CONFIG_H

#define _GNU_SOURCE
#include <limits.h>

/* 默认 rootfs 路径 */
#ifndef BXROOT_ROOTFS
#define BXROOT_ROOTFS "/data/local/tmp/rootfs"
#endif

/* 最大路径长度 */
#define MAX_PATH_LEN (PATH_MAX * 2)

/* 调试模式 */
#ifndef BXROOT_VERBOSE
#define BXROOT_VERBOSE 0
#endif

#if BXROOT_VERBOSE
#include <stdio.h>
#define LOG(fmt, ...) fprintf(stderr, "[bxroot] " fmt "\n", ##__VA_ARGS__)
#else
#define LOG(fmt, ...) do {} while(0)
#endif

#endif /* CONFIG_H */
