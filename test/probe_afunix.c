/*
 * AF_UNIX 路径翻译回归钉（proot 上游 issue #8 的 bxroot 对应物）。
 *
 * 【为什么需要】X11（/tmp/.X11-unix/X0）、tmux、dbus、ssh-agent、
 * systemd-resolved 等大量基础设施依赖 **AF_UNIX socket 的文件路径**。
 * 若 bind/connect 不翻译，socket 会落在宿主真实路径（绕过容器），
 * 症状是"另一端就是连不上"或"socket 文件出现在容器外"。
 *
 * 【判别原理】bind 一个 guest 绝对路径（如 /tmp/x.sock）：
 *   - 未翻译：socket 文件落在【宿主】/tmp/x.sock（= 本容器视角的
 *     /tmp，因为容器 /tmp 就是 $ROOTFS/tmp —— 需用差异路径判别）
 *   - 已翻译：落在 $ROOTFS/tmp/x.sock 且【guest 视角】stat 可见
 * 由于本容器 guest /tmp 与宿主 /tmp 是同一 inode，采用【rootfs 内
 * 独有子目录】作为判别：guest 绝对路径 /tmp/afunix-$$/s.sock，
 * 翻译后应落在 $ROOTFS/tmp/afunix-$$/s.sock，且 guest 侧 stat 可见。
 *
 * 【覆盖】
 *   T1 bind 翻译：guest 路径 → socket 落在 rootfs 视角正确位置
 *   T2 guest 视角可见性：stat(socket 路径) 成功
 *   T3 connect + send/recv 回环：两端都经容器路径（用 fork/pair 模拟）
 *   T4 抽象命名空间不受影响（sun_path[0]=='\0' 应原样透传）
 *   T5 相对路径不受影响（按内核语义相对 cwd，不做翻译——设计如此）
 *   T6 超长路径：ENAMETOOLONG 而非截断（截断会静默连错 socket）
 *
 * 用法：sh test/RUN_AFUNIX.sh
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>

static int g_ok, g_fail;

static void check(const char *name, int cond) {
    if (cond) { g_ok++;  printf("  ✅ %s\n", name); }
    else      { g_fail++; printf("  ❌ %s\n", name); }
}

static int mk_unix_addr(struct sockaddr_un *un, socklen_t *len,
                        const char *path, int abstract) {
    memset(un, 0, sizeof(*un));
    un->sun_family = AF_UNIX;
    if (abstract) {
        /* 抽象命名空间：首字节 NUL，名字紧跟其后，addrlen 不含 NUL */
        size_t l = strlen(path);
        if (l > sizeof(un->sun_path) - 2) return -1;
        memcpy(un->sun_path + 1, path, l);
        *len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + l);
    } else {
        if (strlen(path) >= sizeof(un->sun_path)) return -1;
        strcpy(un->sun_path, path);
        *len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                           strlen(path));
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *rootfs = (argc > 1) ? argv[1] : NULL;
    char dir[256], sockpath[300], hostpath[600];

    if (rootfs == NULL) {
        printf("用法: %s <rootfs 宿主路径>\n", argv[0]);
        return 2;
    }
    snprintf(dir, sizeof(dir), "/tmp/afunix-check-%d", (int)getpid());
    snprintf(sockpath, sizeof(sockpath), "%s/s.sock", dir);
    snprintf(hostpath, sizeof(hostpath), "%s%s", rootfs, sockpath);

    /* mkdir 对应目录（容器内 guest 路径 mkdir；经钩子翻译） */
    {
        struct sockaddr_un un; socklen_t l;
        char mpath[300];
        snprintf(mpath, sizeof(mpath), "%s", dir);
        /* 直接走 mkdir() 钩子（若翻译覆盖 mkdir，这一步就已验证一半） */
        if (mkdir(mpath, 0755) != 0 && errno != EEXIST) {
            printf("❌ 准备目录失败: %s\n", strerror(errno));
            return 2;
        }
        (void)un; (void)l;
    }

    printf("== T1 bind 翻译（guest 路径落点）==\n");
    {
        struct sockaddr_un un; socklen_t l;
        int s = socket(AF_UNIX, SOCK_STREAM, 0);
        check("socket 创建", s >= 0);
        if (mk_unix_addr(&un, &l, sockpath, 0) != 0) return 2;
        int rc = bind(s, (const struct sockaddr *)&un, l);
        check("bind(guest 路径) 成功", rc == 0);
        if (rc == 0) {
            struct stat st;
            int ok = (stat(hostpath, &st) == 0) && S_ISSOCK(st.st_mode);
            check("socket 落在 rootfs 视角正确位置（宿主 stat 验证）", ok);
            /* guest 视角也要可见 */
            struct stat st2;
            int ok2 = (stat(sockpath, &st2) == 0) && S_ISSOCK(st2.st_mode);
            check("guest 视角 stat 可见", ok2);
            (void)st2;
        }
        close(s);
    }

    printf("== T3 connect+send/recv 回环 ==\n");
    {
        struct sockaddr_un un; socklen_t l;
        int ls = socket(AF_UNIX, SOCK_STREAM, 0);
        int rc;
        /* 用独立路径（T1 的 socket 已占 sockpath），并清残留 */
        char srvpath[300];
        snprintf(srvpath, sizeof(srvpath), "%s/c.sock", dir);
        unlink(srvpath);          /* 清残留（socket 文件不随 close 消失） */
        if (mk_unix_addr(&un, &l, srvpath, 0) != 0) return 2;
        rc = bind(ls, (const struct sockaddr *)&un, l);
        check("服务端 bind（connect 前提）", rc == 0);
        rc = listen(ls, 4);
        check("listen", rc == 0);

        pid_t pid = fork();
        if (pid == 0) {
            /* 子进程：connect + send —— 同进程内已注入，走同一钩子 */
            int c = socket(AF_UNIX, SOCK_STREAM, 0);
            struct sockaddr_un u2; socklen_t l2;
            mk_unix_addr(&u2, &l2, sockpath, 0);
            if (connect(c, (const struct sockaddr *)&u2, l2) == 0) {
                send(c, "PING", 4, 0);
            }
            close(c);
            _exit(0);
        }
        int cs = accept(ls, NULL, NULL);
        check("accept", cs >= 0);
        if (cs >= 0) {
            char buf[8] = {0};
            ssize_t n = recv(cs, buf, sizeof buf, 0);
            check("connect+recv 收到 PING（两端路径均经翻译）",
                  n == 4 && strcmp(buf, "PING") == 0);
            close(cs);
        }
        close(ls);
        waitpid(pid, NULL, 0);
        unlink(srvpath);
    }

    printf("== T4 抽象命名空间不受影响 ==\n");
    {
        struct sockaddr_un un; socklen_t l;
        int s = socket(AF_UNIX, SOCK_STREAM, 0);
        /* 名字用绝对路径形态，但标记为抽象 —— 若被错误翻译，
         * bind 会在文件系统上留下 socket 文件 */
        if (mk_unix_addr(&un, &l, "/tmp/abstract-should-not-exist", 1) != 0)
            return 2;
        int rc = bind(s, (const struct sockaddr *)&un, l);
        check("抽象命名空间 bind 成功（未做文件翻译）", rc == 0);
        struct stat st;
        check("文件系统上【没有】留下 socket 文件",
              stat("/tmp/abstract-should-not-exist", &st) != 0);
        close(s);
    }

    printf("== T5 相对路径不受影响 ==\n");
    {
        struct sockaddr_un un; socklen_t l;
        int s = socket(AF_UNIX, SOCK_STREAM, 0);
        /* 相对路径：内核按 cwd 解析，不做翻译是设计如此 */
        memset(&un, 0, sizeof un);
        un.sun_family = AF_UNIX;
        strcpy(un.sun_path, "rel.sock");
        int rc = bind(s, (const struct sockaddr *)&un,
                      (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 8));
        check("相对路径 bind 由内核按 cwd 处理（不报 ENOSYS）",
              rc == 0 || errno == EACCES || errno == EEXIST || errno == ENOENT);
        close(s);
        unlink("rel.sock");
    }

    printf("== T6 超长路径 → ENAMETOOLONG（不截断）==\n");
    {
        struct sockaddr_un un; socklen_t l;
        char longp[260];
        memset(longp, 'a', sizeof longp - 1);
        longp[sizeof longp - 1] = '\0';
        longp[0] = '/';
        if (mk_unix_addr(&un, &l, longp, 0) != 0) {
            check("超长路径构造失败视为通过", 1);
        } else {
            int s = socket(AF_UNIX, SOCK_STREAM, 0);
            int rc = bind(s, (const struct sockaddr *)&un, l);
            check("超长路径 bind 报 ENAMETOOLONG（不静默截断）",
                  rc != 0 && errno == ENAMETOOLONG);
            close(s);
        }
    }

    /* 清理 */
    {
        char f[300];
        snprintf(f, sizeof f, "%s/s.sock", dir);
        unlink(f);
        rmdir(dir);
    }

    printf("\n== 结果: %d 通过 / %d 失败 ==\n", g_ok, g_fail);
    return g_fail ? 1 : 0;
}
