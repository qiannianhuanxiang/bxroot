/*
 * probe_termux_compat.c —— Termux 路径兼容（src/runtime/termux_compat.h）的单测
 *
 * 只测纯函数；translate_path 里的接法（映射后再走常规翻译）由 RUN_TERMUX_COMPAT.sh
 * 在真实 runtime 下端到端验证。
 *
 *   T1 Termux 布局映射：$PREFIX→/usr，$PREFIX/{tmp,etc,var}→/{tmp,etc,var}，
 *      files/home→/root；两种前缀写法都认。
 *   T2 组件边界：…/files/usrx、…/files、…/homer、com.termuxx 不映射。
 *   T3 不相关路径不映射。
 *   T4 超长：返回 -1，调用方按原路径继续常规翻译。
 *   T5 开关：rootfs 在 com.termux 下（真 Termux 宿主）或 opt-out=1 时关闭。
 *
 * 构建：gcc -O1 -I src/runtime -o /tmp/ptc test/probe_termux_compat.c
 */
#include <stdio.h>
#include <string.h>
#include "termux_compat.h"

static int fails;

static void map_ok(const char *in, const char *want)
{
    char out[4096];
    int r = bx_termux_compat_map(in, out, sizeof out);

    if (r != 1 || strcmp(out, want) != 0) {
        fails++;
        printf("  FAIL: %s -> (%d) %s, want %s\n", in, r, r == 1 ? out : "-", want);
    } else {
        printf("  ok:   %s -> %s\n", in, out);
    }
}

static void map_none(const char *in)
{
    char out[4096] = "";
    int r = bx_termux_compat_map(in, out, sizeof out);

    if (r != 0) {
        fails++;
        printf("  FAIL: %s mapped (%d) %s\n", in ? in : "NULL", r, out);
    } else {
        printf("  ok:   %s (unchanged)\n", in ? in : "NULL");
    }
}

static void enabled(const char *rootfs, const char *opt, int want)
{
    int r = bx_termux_compat_enabled(rootfs, opt);

    if (r != want) {
        fails++;
        printf("  FAIL: enabled(%s, %s) = %d, want %d\n",
               rootfs ? rootfs : "NULL", opt ? opt : "NULL", r, want);
    } else {
        printf("  ok:   enabled(%s, %s) = %d\n",
               rootfs ? rootfs : "NULL", opt ? opt : "NULL", r);
    }
}

int main(void)
{
    printf("T1 mapping\n");
    map_ok("/data/data/com.termux/files/usr/bin/bash", "/usr/bin/bash");
    map_ok("/data/data/com.termux/files/usr", "/usr");
    map_ok("/data/data/com.termux/files/usr/", "/usr/");
    map_ok("/data/data/com.termux/files/usr/lib/python3.12", "/usr/lib/python3.12");
    map_ok("/data/data/com.termux/files/usr/tmp", "/tmp");
    map_ok("/data/data/com.termux/files/usr/tmp/x.sock", "/tmp/x.sock");
    map_ok("/data/data/com.termux/files/usr/etc/bash.bashrc", "/etc/bash.bashrc");
    map_ok("/data/data/com.termux/files/usr/var/log", "/var/log");
    map_ok("/data/data/com.termux/files/home", "/root");
    map_ok("/data/data/com.termux/files/home/.bashrc", "/root/.bashrc");
    map_ok("/data/user/0/com.termux/files/usr/bin/env", "/usr/bin/env");
    map_ok("/data/user/0/com.termux/files/home/proj", "/root/proj");
    map_ok("/data/data/com.termux/files/home/../usr/bin/sh", "/root/../usr/bin/sh");

    printf("T2 component boundaries\n");
    map_none("/data/data/com.termux/files/usrx/bin");
    map_none("/data/data/com.termux/files/usr-local");
    map_none("/data/data/com.termux/files");
    map_none("/data/data/com.termux/files/");
    map_none("/data/data/com.termux/files/homer");
    map_ok("/data/data/com.termux/files/usr/tmpx", "/usr/tmpx");  /* 不得命中 /tmp 规则 */
    map_none("/data/data/com.termuxx/files/usr/bin");
    map_none("/data/data/com.termux/cache/x");
    map_none("/data/user/10/com.termux/files/usr/bin");

    printf("T3 unrelated paths\n");
    map_none("/usr/bin/bash");
    map_none("/data/local/tmp/a");
    map_none("relative/data/data/com.termux/files/usr");
    map_none("");
    map_none(NULL);

    printf("T4 overflow\n");
    {
        char small[6];
        int r = bx_termux_compat_map("/data/data/com.termux/files/usr/bin/bash",
                                     small, sizeof small);
        if (r != -1) { fails++; printf("  FAIL: overflow returned %d\n", r); }
        else printf("  ok:   overflow -> -1\n");
    }

    printf("T5 enable switch\n");
    enabled("/data/data/dsh.android.bxroot/files/linux/ubuntu", NULL, 1);
    enabled("/data/data/dsh.android.bxroot/files/linux/ubuntu", "0", 1);
    enabled("/data/data/dsh.android.bxroot/files/linux/ubuntu", "1", 0);
    enabled("/data/data/com.termux/files/home/ubuntu", NULL, 0);
    enabled("/data/user/0/com.termux/files/usr/var/lib/proot-distro", NULL, 0);
    enabled("/data/data/com.termux", NULL, 0);
    enabled("/data/data/com.termuxfoo/rootfs", NULL, 1);
    enabled("/", NULL, 1);
    enabled(NULL, NULL, 1);

    printf("%s (%d failures)\n", fails ? "FAILED" : "PASSED", fails);
    return fails ? 1 : 0;
}
