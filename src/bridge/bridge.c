/*
 * libbxroot-bridge.so
 *
 * Host/Guest 桥接层：
 * - 与宿主系统通信
 * - 文件操作代理（当 rootfs 外路径需要访问时）
 * - 信号传递
 *
 * 注意：此层在大多数情况下不是必需的。
 * 当 bind mount 映射覆盖了所有需要的外部路径时，
 * 不需要桥接层。桥接层主要用于：
 * 1. 动态路径映射（bind mount 无法预定义的路径）
 * 2. 与宿主 Android 系统的特殊通信
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>

#ifndef BXROOT_VERBOSE
#define BXROOT_VERBOSE 0
#endif

#if BXROOT_VERBOSE
#define LOG(fmt, ...) fprintf(stderr, "[bxroot-bridge] " fmt "\n", ##__VA_ARGS__)
#else
#define LOG(fmt, ...) do {} while(0)
#endif

/* Unix socket 路径（用于与宿主通信） */
#define BRIDGE_SOCKET "/tmp/.bxroot-bridge-%d.sock"

/* 桥接状态 */
static int bridge_fd = -1;

/*
 * 连接到宿主桥接服务。
 * 返回 socket fd，失败返回 -1。
 */
static int connect_bridge(void) {
    if (bridge_fd >= 0) return bridge_fd;

    char sock_path[256];
    snprintf(sock_path, sizeof(sock_path), BRIDGE_SOCKET, getpid());

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG("socket failed: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG("connect failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    LOG("bridge connected: %s", sock_path);
    bridge_fd = fd;
    return fd;
}

/*
 * 通过桥接层打开文件。
 * 当 rootfs 外路径需要访问时使用。
 */
int bridge_open(const char *path, int flags, mode_t mode) {
    LOG("bridge_open: %s", path);

    int fd = connect_bridge();
    if (fd < 0) {
        return -1;
    }

    /* 发送请求 */
    struct {
        uint32_t cmd;
        uint32_t flags;
        uint32_t mode;
        char path[4096];
    } req;

    req.cmd = 1; /* CMD_OPEN */
    req.flags = flags;
    req.mode = mode;
    strncpy(req.path, path, sizeof(req.path) - 1);
    req.path[sizeof(req.path) - 1] = '\0';

    if (write(fd, &req, sizeof(req)) < 0) {
        LOG("write failed: %s", strerror(errno));
        return -1;
    }

    /* 读取响应 */
    int result_fd;
    if (read(fd, &result_fd, sizeof(result_fd)) < 0) {
        LOG("read failed: %s", strerror(errno));
        return -1;
    }

    return result_fd;
}

/*
 * 通过桥接层读取文件。
 */
ssize_t bridge_read(int fd, void *buf, size_t count) {
    LOG("bridge_read: fd=%d, count=%zu", fd, count);

    int bridge_fd = connect_bridge();
    if (bridge_fd < 0) return -1;

    struct {
        uint32_t cmd;
        int32_t fd;
        size_t count;
    } req;

    req.cmd = 2; /* CMD_READ */
    req.fd = fd;
    req.count = count;

    if (write(bridge_fd, &req, sizeof(req)) < 0) {
        return -1;
    }

    ssize_t nread;
    if (read(bridge_fd, &nread, sizeof(nread)) < 0) {
        return -1;
    }

    if (nread > 0 && nread <= (ssize_t)count) {
        if (read(bridge_fd, buf, nread) < 0) {
            return -1;
        }
    }

    return nread;
}

/* 构造函数 */
__attribute__((constructor))
static void bridge_constructor(void) {
    LOG("bridge library loaded");
}
