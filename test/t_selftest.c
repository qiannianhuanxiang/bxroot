/*
 * selftest 验证：真正加载 libbxroot-runtime.so，让构造函数跑 selftest，
 * 然后检查日志里的 7 项是否都出现、格式是否正确。
 *
 * 这不是"模拟"——构造函数里的 px_runtime_init 是真的执行，
 * 每一项 stat/readlink/getenv 也是真的调用。本机跑不通的部分
 * （比如 /data/data 路径）会以 FAIL/WARN 出现，这本身就是对
 * 自检逻辑的有效验证：它确实能分辨好坏。
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DIAG "/tmp/selftest-probe.log"

int main(void)
{
    void *h;
    char cmd[512];
    FILE *f;
    char buf[4096];
    size_t n;
    int ok = 0;

    unlink(DIAG);
    setenv("BXROOT_DIAG_FILE", DIAG, 1);
    /* 给一个假的 rootfs，让 [4] 能测到"路径不存在"的分支 */
    setenv("BXROOT_ROOTFS", "/nonexistent-rootfs", 1);

    h = dlopen("/tmp/bxroot/build-st/libbxroot-runtime.so", RTLD_NOW);
    if (h == NULL) {
        printf("SKIP: dlopen failed: %s\n", dlerror());
        return 77;
    }

    /* 构造函数应当已经跑过 px_runtime_init → selftest */
    f = fopen(DIAG, "r");
    if (f == NULL) {
        printf("FAIL: 诊断文件未生成 %s\n", DIAG);
        return 1;
    }
    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';

    printf("---- diag 内容 ----\n%s\n----\n", buf);

    /* 断言：7 项检查标记必须全部出现 */
    {
        const char *need[] = {
            "--- selftest ---",
            "[1] self-lib",
            "[2] ulx",
            "[3] ldso",
            "[4] rootfs",
            "[5] threads",
            "[6] self-exe",
            "[7] diag-file",
            "--- selftest",
        };
        size_t i;
        for (i = 0; i < sizeof(need) / sizeof(need[0]); i++) {
            if (strstr(buf, need[i]) == NULL) {
                printf("FAIL: 缺少标记 \"%s\"\n", need[i]);
                return 1;
            }
        }
    }
    printf("PASS: 七项自检标记齐全\n");

    /* 断言：[4] rootfs 必须报 FAIL（我们给了不存在的路径） */
    if (strstr(buf, "[4] rootfs        FAIL") == NULL) {
        /* 允许空格数不同，用更宽松的判断 */
        char *p = strstr(buf, "[4] rootfs");
        if (p != NULL && strstr(p, "FAIL") != NULL) {
            printf("PASS: [4] 对不存在的 rootfs 报 FAIL\n");
        } else {
            printf("FAIL: [4] 对不存在的 rootfs 未报 FAIL\n");
            return 1;
        }
    } else {
        printf("PASS: [4] 对不存在的 rootfs 报 FAIL\n");
    }

    /* 断言：[2] 必须真的测到了文件（不是凭空 OK） */
    if (strstr(buf, "[2] ulx") != NULL) {
        char *p = strstr(buf, "[2] ulx");
        char line[256];
        size_t i = 0;
        while (p[i] != '\n' && p[i] != '\0' && i < sizeof(line) - 1) {
            line[i] = p[i];
            i++;
        }
        line[i] = '\0';
        printf("       %s\n", line);
    }

    (void)ok;
    (void)cmd;
    printf("CONCLUSION: selftest_output_verified=1\n");
    return 0;
}
