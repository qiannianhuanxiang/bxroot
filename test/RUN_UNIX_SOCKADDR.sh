#!/bin/sh
# ---------------------------------------------------------------------
# AF_UNIX sockaddr 双向翻译（上游 proot #8 残留面 · 行动清单 #5）
#
# 【缺口】bind/connect 早已翻译 sun_path，但 AF_UNIX **数据报**的目标
# 地址走 sendto 的 dest_addr / sendmsg 的 msg_name，此前**纯转发**：
# 容器内 `sendto("/tmp/x.sock")` 直接打到宿主的 /tmp/x.sock。
# 另一面：内核回填给 getsockname/getpeername/accept/recvfrom/recvmsg 的
# 地址是宿主视角 `<rootfs>/tmp/x.sock`，客户拿去做字符串比较、或喂回
# connect/sendto 会双重翻译。
#
# 【判据】在 bxroot 下，一个进程内：
#   1. DGRAM 服务端 bind(guest 路径)，getsockname 回读 == 原 guest 路径
#   2. 客户端 sendto(guest 路径) 成功；服务端 recvfrom 收到，且
#      回填的源地址 == 客户端 bind 的 guest 路径（客户端也 bind 了）
#   3. sendmsg(msg_name=guest 路径) 同样成功；recvmsg 回填同样是 guest 路径
#   4. STREAM：connect + accept 后 getpeername/accept 回填 == guest 路径
#   5. **旁证翻译真发生了**：guest 路径对应的 socket 文件在 rootfs 内
#      （用 stat 看 —— 若没翻译，文件会落在宿主的同名路径上；本容器
#      内 /tmp 与 rootfs/tmp 同 inode，所以这条只在非默认 rootfs 下有
#      判别力，默认 rootfs 时退化为 1-4）
#
# 探针通过 tools/bxroot-run 注入（本容器唯一可用的注入链路）。
# ---------------------------------------------------------------------

set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PROBE_C=${TMPDIR:-/tmp}/unix_sockaddr_probe.c
PROBE=${TMPDIR:-/tmp}/unix_sockaddr_probe
WORK=/tmp/unix_sockaddr_work.$$

[ -f "$ROOT/build/libbxroot-runtime.so" ] || {
    echo "⏭️  跳过：没有 build/libbxroot-runtime.so（先 sh BUILD_RUNTIME.sh）"
    exit 2
}
[ -x "$ROOT/tools/bxroot-run" ] || { echo "❌ 缺 tools/bxroot-run"; exit 1; }
command -v gcc >/dev/null 2>&1 || { echo "⏭️  跳过：没有 gcc"; exit 2; }

cat > "$PROBE_C" <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/time.h>

/* 接收必须带超时：sendto 未翻译时报文根本没发出，阻塞 recv 会永久挂起
 * （2026-09-25 实测：官方 proroot 基线就这样卡死） */
static void rcvtimeo(int fd) {
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

static int bad = 0;
#define CHECK(cond, ...) do { if (!(cond)) { bad = 1; printf("  ❌ "); printf(__VA_ARGS__); printf(" (errno=%d %s)\n", errno, strerror(errno)); } else { printf("  ✅ "); printf(__VA_ARGS__); printf("\n"); } } while (0)

static void mkaddr(struct sockaddr_un *a, const char *p) {
    memset(a, 0, sizeof(*a)); a->sun_family = AF_UNIX;
    strncpy(a->sun_path, p, sizeof(a->sun_path) - 1);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *dir = argc > 1 ? argv[1] : "/tmp/unix_sockaddr_work";
    char srv[108], cli[108], stm[108], buf[64];
    struct sockaddr_un a, back; socklen_t bl;
    int s, c, l, p, acc; ssize_t n;
    struct stat st;

    snprintf(srv, sizeof(srv), "%s/srv.sock", dir);
    snprintf(cli, sizeof(cli), "%s/cli.sock", dir);
    snprintf(stm, sizeof(stm), "%s/stm.sock", dir);
    unlink(srv); unlink(cli); unlink(stm);

    /* --- DGRAM --- */
    s = socket(AF_UNIX, SOCK_DGRAM, 0);
    rcvtimeo(s);
    mkaddr(&a, srv);
    CHECK(bind(s, (struct sockaddr *)&a, sizeof(a)) == 0, "dgram bind(%s)", srv);
    bl = sizeof(back); memset(&back, 0, sizeof(back));
    CHECK(getsockname(s, (struct sockaddr *)&back, &bl) == 0 &&
          strcmp(back.sun_path, srv) == 0,
          "getsockname 回填 guest 路径: got '%s'", back.sun_path);
    CHECK(stat(srv, &st) == 0 && S_ISSOCK(st.st_mode), "stat(%s) 是 socket 文件", srv);

    c = socket(AF_UNIX, SOCK_DGRAM, 0);
    mkaddr(&a, cli);
    CHECK(bind(c, (struct sockaddr *)&a, sizeof(a)) == 0, "dgram client bind(%s)", cli);

    mkaddr(&a, srv);
    n = sendto(c, "ping1", 5, 0, (struct sockaddr *)&a, sizeof(a));
    CHECK(n == 5, "sendto(dest=%s) n=%zd", srv, n);
    bl = sizeof(back); memset(&back, 0, sizeof(back));
    n = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&back, &bl);
    CHECK(n == 5 && memcmp(buf, "ping1", 5) == 0, "recvfrom 收到 n=%zd", n);
    CHECK(strcmp(back.sun_path, cli) == 0,
          "recvfrom 回填源地址为 guest 路径: got '%s'", back.sun_path);

    /* sendmsg / recvmsg 走 msg_name */
    {
        struct iovec iov = { .iov_base = "ping2", .iov_len = 5 };
        struct msghdr m; memset(&m, 0, sizeof(m));
        mkaddr(&a, srv);
        m.msg_name = &a; m.msg_namelen = sizeof(a); m.msg_iov = &iov; m.msg_iovlen = 1;
        n = sendmsg(c, &m, 0);
        CHECK(n == 5, "sendmsg(msg_name=%s) n=%zd", srv, n);

        struct iovec riov = { .iov_base = buf, .iov_len = sizeof(buf) };
        struct msghdr rm; memset(&rm, 0, sizeof(rm)); memset(&back, 0, sizeof(back));
        rm.msg_name = &back; rm.msg_namelen = sizeof(back); rm.msg_iov = &riov; rm.msg_iovlen = 1;
        n = recvmsg(s, &rm, 0);
        CHECK(n == 5 && memcmp(buf, "ping2", 5) == 0, "recvmsg 收到 n=%zd", n);
        CHECK(strcmp(back.sun_path, cli) == 0,
              "recvmsg 回填 msg_name 为 guest 路径: got '%s'", back.sun_path);
    }

    /* --- STREAM: accept / getpeername --- */
    l = socket(AF_UNIX, SOCK_STREAM, 0);
    rcvtimeo(l);
    mkaddr(&a, stm);
    CHECK(bind(l, (struct sockaddr *)&a, sizeof(a)) == 0 && listen(l, 1) == 0, "stream bind+listen(%s)", stm);
    p = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(connect(p, (struct sockaddr *)&a, sizeof(a)) == 0, "stream connect(%s)", stm);
    bl = sizeof(back); memset(&back, 0, sizeof(back));
    acc = accept(l, (struct sockaddr *)&back, &bl);
    CHECK(acc >= 0, "accept");
    /* 未 bind 的客户端 peer 是匿名的（sun_path 空或 len==2），不在此判 */
    bl = sizeof(back); memset(&back, 0, sizeof(back));
    CHECK(getpeername(p, (struct sockaddr *)&back, &bl) == 0 &&
          strcmp(back.sun_path, stm) == 0,
          "getpeername 回填 guest 路径: got '%s'", back.sun_path);

    close(s); close(c); close(l); close(p); if (acc >= 0) close(acc);
    unlink(srv); unlink(cli); unlink(stm);
    printf("RESULT: %s\n", bad ? "FAIL" : "PASS");
    return bad;
}
EOF

if ! gcc -O0 -Wall -o "$PROBE" "$PROBE_C" 2>"$WORK.cc"; then
    echo "❌ 探针编译失败"; cat "$WORK.cc"; rm -f "$WORK.cc"; exit 1
fi
rm -f "$WORK.cc"
mkdir -p "$WORK"

# 对照组：外层官方 proroot 下直接跑。**不要求通过** —— 2026-09-25 实测
# 官方同样有这个缺口（getsockname 泄漏宿主路径、sendto ENOENT）。
# 它只用来证明探针有判别力：若对照组也全绿，说明本环境下缺口不可观测，
# 本测试就不能证明任何事，按 rc=2 如实上报。
echo "--- 对照：官方 proroot（预期暴露缺口）---"
timeout 30 "$PROBE" "$WORK"
rc0=$?

echo
echo "--- bxroot 下 ---"
timeout 30 "$ROOT/tools/bxroot-run" -- "$PROBE" "$WORK"
rc=$?

if [ "$rc" -eq 0 ] && [ "$rc0" -eq 0 ]; then
    echo "⏭️  对照组也全部通过：本环境下该缺口不可观测，无法判定"
    rc=2
elif [ "$rc" -eq 0 ]; then
    echo "RESULT: PASS —— bxroot 修复了官方存在的 AF_UNIX 地址翻译缺口（对照 rc=$rc0）"
else
    echo "RESULT: FAIL —— bxroot 下 AF_UNIX 地址翻译契约不成立（rc=$rc）"
fi

rm -rf "$WORK" "$PROBE" "$PROBE_C"
exit "$rc"
