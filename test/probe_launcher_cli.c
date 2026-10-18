/*
 * 真机探针：launcher 的 CLI 参数校验（2026-10-18 修复 L3 / L4 / L5）
 *
 * --- 三条缺陷 ---
 * L3  launcher 允许 48 条 bind，runtime 只消费 16 条 → 第 17 条起**静默丢弃**
 * L4  `-i uid:gid` 只校验格式不校验范围 → `-i 4294967296:0` 截断成 uid 0
 *     （静默变成 root）；`-i -1:0` → 4294967295
 * L5  `-r` / `-b` 宿主侧路径不绝对化 → 相对 rootfs 让所有翻译路径变相对名
 *     → cwd 上二次拼接 → 全面 ENOENT
 *
 * --- 本探针 ---
 * 通过**运行 launcher 的 `-V`**（它只做参数解析到版本输出，不 exec guest）
 * 来观察这些参数是否被正确处置。判据是 stderr/stdout 文本 + 退出码。
 *
 * 判别力：修复前 L3 在第 17 条不会报错、L4 的越界值会被接受、
 * L5 不会出现"已绝对化"提示。
 *
 * --- 追加（第二轮，2026-10-18）---
 * L6  `-b` 畸形规格（空 host/guest、路径含 ';'、未知第三段）全部**静默
 *     接受**：空路径被 runtime 跳过 → 少一条 bind 且无提示；路径含 ';'
 *     被当成两条 bind 切开 → 目的地错位；未知第三段被直接截断丢弃。
 * L7  未传 `-b` 时不清理继承的 BXROOT_BINDS → 父进程的 bind 表泄漏进
 *     子容器的 guest（隔离失效方向）。
 *
 * 判别力：修复前 L6 的四种畸形输入都会"正常"退出、L7 会把父进程的
 * `/host:/guest` 原样打印出来。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fails, checks;

/* 跑 launcher，把输出收进 buf，返回退出码 */
/*
 * 跑 launcher，把**全部**输出收进 buf，返回退出码。
 *
 * ★ 必须读到底，不能只 fgets 一行 ★
 * `-v` 的详单有七八行（rootfs / workdir / PWD / guest / runtime_lib /
 * LD_PRELOAD / binds），而 binds 在**第 7 行**。原先只读一行，于是
 * "能不能看到 bind 表"的判据永远为假 —— 探针自己先失灵，修复看起来
 * 像没生效。这类"探针比被测代码更容易错"的坑，靠的是每次都验证
 * 探针本身能测出修复前的行为。
 */
static int run_launcher(const char *launcher, const char *args, char *buf, size_t n)
{
    char cmd[4096];
    FILE *f;
    size_t got;

    snprintf(cmd, sizeof cmd, "%s %s 2>&1", launcher, args);
    f = popen(cmd, "r");
    if (f == NULL) {
        buf[0] = '\0';
        return -1;
    }
    got = fread(buf, 1, n - 1, f);
    buf[got] = '\0';
    return pclose(f);
}

static void ck(const char *what, int cond)
{
    checks++;
    if (!cond) {
        fails++;
        printf("  [FAIL] %s\n", what);
    } else {
        printf("  [ok]   %s\n", what);
    }
}

int main(int argc, char **argv)
{
    const char *L;
    char out[1024];
    char args[4096];
    int i;

    if (argc < 2) {
        printf("用法: %s <libbxroot.so 路径>\n", argv[0]);
        return 0;
    }
    L = argv[1];

    printf("=== launcher CLI 参数校验 探针 ===\n");
    printf("launcher: %s\n\n", L);

    /* --- L4: -i 越界必须被拒 --- */
    run_launcher(L, "-r / -i 4294967296:0 -V", out, sizeof out);
    ck("-i 4294967296:0 被拒（不再静默变成 uid 0）",
       strstr(out, "超出范围") != NULL);

    run_launcher(L, "-r / -i -1:0 -V", out, sizeof out);
    ck("-i -1:0 被拒（不再变成 4294967295）",
       strstr(out, "不接受负数") != NULL);

    run_launcher(L, "-r / -i 1000:1000 -V", out, sizeof out);
    ck("-i 1000:1000 正常接受", strstr(out, "bxroot") != NULL);

    /* --- L3: 第 17 条 bind 必须报错 --- */
    args[0] = '\0';
    strcat(args, "-r /");
    for (i = 1; i <= 17; i++) {
        char one[64];
        snprintf(one, sizeof one, " -b /tmp:/m%d", i);
        strcat(args, one);
    }
    strcat(args, " -V");
    run_launcher(L, args, out, sizeof out);
    ck("第 17 条 bind 报错（不再静默丢弃）",
       strstr(out, "上限 16") != NULL);

    /* --- L5: 相对 -r 必须被绝对化并提示 --- */
    run_launcher(L, "-r . -V", out, sizeof out);
    ck("相对 -r 被绝对化并提示",
       strstr(out, "已绝对化") != NULL);

    /* ================= L6：畸形 bind 规格必须报错 ================= */
    printf("\n--- L6 畸形 bind 规格 ---\n");

    run_launcher(L, "-r / -b :/dst -V", out, sizeof out);
    ck("空宿主路径被拒（原先静默丢一条 bind）",
       strstr(out, "宿主路径为空") != NULL);

    run_launcher(L, "-r / -b /src: -V", out, sizeof out);
    ck("空 guest 路径被拒（原先静默丢一条 bind）",
       strstr(out, "guest 路径为空") != NULL);

    run_launcher(L, "-r / -b /src:/dst:bogus -V", out, sizeof out);
    ck("未知第三段被拒（原先直接截断丢弃）",
       strstr(out, "不是 ro/rw") != NULL);

    run_launcher(L, "-r / -b '/a:/d;st' -V", out, sizeof out);
    ck("含 ';' 的路径被拒（原先被切成两条 bind）",
       strstr(out, "含 ';'") != NULL);

    run_launcher(L, "-r / -b /src:/dst: -V", out, sizeof out);
    ck("guest 后多余 ':' 被拒",
       strstr(out, "多余的 ':'") != NULL);

    /* 合法形态必须继续可用，不能收紧过头 */
    run_launcher(L, "-r / -b /src:/dst -V", out, sizeof out);
    ck("两段式 bind 仍正常", strstr(out, "bxroot") != NULL);

    run_launcher(L, "-r / -b /src:/dst:rw -V", out, sizeof out);
    ck("显式 :rw 仍正常", strstr(out, "bxroot") != NULL);

    /*
     * 注意：不能用 `-V` 观察 bind 表 —— `-V` 在 parse_args 内就打印版本
     * 并退出，走不到 main() 的 -v 详单。这里用一个不存在的 guest 命令，
     * 让 launcher 走到"exec 前打印详单、exec 失败后报错"的路径。
     */
    run_launcher(L, "-r / -b /src:/dst:RO -v /nonexistent_probe_cmd", out, sizeof out);
    ck(":RO 大写仍按只读（保留既有修复）",
       strstr(out, "/src:/dst:ro") != NULL);

    run_launcher(L, "-r / -b /only -V", out, sizeof out);
    ck("单路径 bind 仍正常（等价 path:path）",
       strstr(out, "bxroot") != NULL);

    /* ================= L7：继承的 BXROOT_BINDS 必须被清掉 ============ */
    printf("\n--- L7 继承 BXROOT_BINDS ---\n");
    {
        /*
         * 场景：外层 bxroot 已经导出了 BXROOT_BINDS，内层只给 `-r`。
         * 正确行为：内层没有 -b → 有效 bind 表为空 → 详单打印 (none)。
         * 修复前：父进程的 /host:/guest 被原样继承并打印出来。
         */
        char cmd[2048];
        FILE *f;
        size_t n = 0;

        snprintf(cmd, sizeof cmd,
                 "BXROOT_BINDS=/host:/guest %s -r / -v /nonexistent_probe_cmd 2>&1", L);
        f = popen(cmd, "r");
        out[0] = '\0';
        if (f != NULL) {
            n = fread(out, 1, sizeof out - 1, f);
            out[n] = '\0';
            pclose(f);
        }
        ck("未传 -b 时继承的 BXROOT_BINDS 被清空（打印 none）",
           strstr(out, "binds=(none)") != NULL);
        ck("父进程的 /host:/guest 没有泄漏进本次启动",
           strstr(out, "/host:/guest") == NULL);
    }

    printf("\n----------------------------------------\n");
    printf("checks: %d  failed: %d\n", checks, fails);
    printf("RESULT: %s\n", fails == 0 ? "PASS" : "FAIL");
    return fails == 0 ? 0 : 1;
}
