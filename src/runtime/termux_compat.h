/*
 * termux_compat.h —— Termux 路径布局 → Ubuntu 布局（纯函数，无 libc 钩子依赖）
 *
 * 很多「专为 Termux」的项目把前缀写死：shebang
 * `#!/data/data/com.termux/files/usr/bin/bash`、`$PREFIX/etc/...`、`~/` 展开成
 * `/data/data/com.termux/files/home`。guest 是标准 Ubuntu，这些路径不存在。
 * translate_path 先用本函数把 Termux 路径改写成 guest 路径，再走常规翻译
 * （bind / rootfs 前缀 / `..` 夹紧都照旧生效）。
 *
 *   $PREFIX/tmp → /tmp      $PREFIX/etc → /etc      $PREFIX/var → /var
 *   $PREFIX     → /usr      （bin/lib/share/include 与 Ubuntu 同名）
 *   files/home  → /root
 *
 * $PREFIX = /data/data/com.termux/files/usr 或 /data/user/0/com.termux/files/usr。
 *
 * 只做路径映射，不设 PREFIX / TERMUX_VERSION：设了会让通用脚本误判自己在
 * Termux 上而改走 pkg / bionic 分支。
 */
#ifndef BXROOT_TERMUX_COMPAT_H
#define BXROOT_TERMUX_COMPAT_H

#include <stdio.h>
#include <string.h>

/*
 * rootfs 本身位于 com.termux 之下 = bxroot 正跑在**真 Termux** 里：那时 Termux 路径
 * 就是真实宿主路径（rootfs、bind 源、runtime 自身），必须整体关闭。
 * 返回 1 = 应启用映射。
 */
static inline int bx_termux_compat_enabled(const char *rootfs, const char *opt_out)
{
    static const char tail[] = "/com.termux";
    size_t rl, tl = sizeof(tail) - 1;

    if (opt_out != NULL && opt_out[0] == '1')
        return 0;
    if (rootfs == NULL)
        return 1;
    if (strstr(rootfs, "/com.termux/") != NULL)
        return 0;
    rl = strlen(rootfs);
    return !(rl >= tl && strcmp(rootfs + rl - tl, tail) == 0);
}

/*
 * 命中则把映射后的 guest 路径写进 out 并返回 1；不是 Termux 路径返回 0；
 * 是 Termux 路径但 out 放不下返回 -1（调用方应**按原路径**继续常规翻译，
 * 不得把原串交给内核）。
 */
static inline int bx_termux_compat_map(const char *path, char *out, size_t out_size)
{
    static const char *const bases[] = {
        "/data/data/com.termux/files", "/data/user/0/com.termux/files" };
    /* 最长优先：tmp/etc/var 必须先于 $PREFIX 本身 */
    static const struct { const char *from, *to; } map[] = {
        { "/usr/tmp", "/tmp" }, { "/usr/etc", "/etc" }, { "/usr/var", "/var" },
        { "/usr", "/usr" }, { "/home", "/root" } };
    size_t b, m;

    if (path == NULL || out == NULL || out_size == 0)
        return 0;
    for (b = 0; b < sizeof(bases) / sizeof(bases[0]); b++) {
        size_t bl = strlen(bases[b]);
        const char *rest;

        if (strncmp(path, bases[b], bl) != 0 || path[bl] != '/')
            continue;
        rest = path + bl;
        for (m = 0; m < sizeof(map) / sizeof(map[0]); m++) {
            size_t fl = strlen(map[m].from);
            int w;

            if (strncmp(rest, map[m].from, fl) != 0 ||
                (rest[fl] != '\0' && rest[fl] != '/'))
                continue;
            w = snprintf(out, out_size, "%s%s", map[m].to, rest + fl);
            return (w < 0 || (size_t)w >= out_size) ? -1 : 1;
        }
    }
    return 0;
}

#endif /* BXROOT_TERMUX_COMPAT_H */
