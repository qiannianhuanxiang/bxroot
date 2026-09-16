#ifndef CONFIG_H
#define CONFIG_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <limits.h>
#include <stdbool.h>

/* 默认 rootfs 路径 */
#ifndef BXROOT_ROOTFS
#define BXROOT_ROOTFS "/data/local/tmp/rootfs"
#endif

/* 最大路径长度 */
#define MAX_PATH_LEN (PATH_MAX * 2)

/* 最大 bind mount 数量 */
#define MAX_BINDS 16

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

/* 全局配置结构 */
typedef struct {
    char *rootfs;           /* rootfs 路径 */
    char *tmp_dir;          /* 临时目录 */
    char *guest_exe;        /* guest 路径伪装 */
    char *workdir;          /* 工作目录 */
    bool verbose;           /* 调试模式 */
    bool fakeroot;          /* 伪装 uid=0 */
    /* bind mount 列表 */
    char **bind_sources;    /* host 路径 */
    char **bind_targets;    /* guest 路径 */
    int bind_count;
} bxroot_config_t;

/* 全局配置实例 */
extern bxroot_config_t g_config;

#endif /* CONFIG_H */
