/* probe_resinit.c —— res_init 是否从 guest 的 /etc/resolv.conf 读到 nameserver。
 *
 * 背景（BUG-D1，2026-09-28 网络/DNS 压测）：glibc resolver（res_ninit）用
 * **库内内联 svc openat** 读 /etc/resolv.conf，走 livepatch 的 path-relay。
 * 当 /etc/resolv.conf 是**指向绝对路径的符号链接**（systemd-resolved 布局
 * /etc/resolv.conf -> /run/systemd/resolve/stub-resolv.conf）时，path-relay
 * 修前只做前缀拼接、不重定向绝对符号链接目标 → 从外层内核根解析 link 目标
 * → ENOENT → res_init 退化成 nscount=1/ns[0]=127.0.0.1（读不到任何 ns）。
 *
 * 关键：这条路是**内联 svc**，绕过 exported open/fopen 钩子，所以 cat 文件
 * "看起来正常"却唯独 resolver 挂。用 res_init 探针才能精准命中。
 *
 * 判据：打印 res_init 解析出的第一个 nameserver。若绝对符号链接被正确
 * 重定向进 rootfs，应打印我们埋的 198.18.0.246；否则打印 127.0.0.1（退化）。
 */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <resolv.h>

int main(void) {
    if (res_init() != 0) {
        printf("RESINIT-FAIL\n");
        return 2;
    }
    printf("nscount=%d\n", _res.nscount);
    if (_res.nscount > 0) {
        char ip[64];
        inet_ntop(AF_INET, &_res.nsaddr_list[0].sin_addr, ip, sizeof ip);
        printf("ns0=%s\n", ip);
    }
    return 0;
}
