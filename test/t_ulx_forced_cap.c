#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "proc.c"

int main(void) {
    px_rtconfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.have_rootfs = 1;
    snprintf(cfg.rootfs, sizeof(cfg.rootfs), "%s", "/data/data/test/files/linux/ubuntu");
    cfg.have_preload = 1;
    snprintf(cfg.preload, sizeof(cfg.preload), "%s", "/data/app/lib/libbxroot-runtime.so");
    setenv("BXROOT_ULX_PATH", "/data/app/lib/libbxroot-ulx.so", 1);
    setenv("BXROOT_ULX_LDSO", "/data/data/test/files/linux/ubuntu/lib/ld.so", 1);

    /* 关键：模拟真实调用点的 cap 值 */
    px_env_kv kv[PX_FORCED_MAX];
    memset(kv, 0, sizeof(kv));
    int n7 = px_build_forced(&cfg, kv, 7, "/bin/sh", "/bin/sh");
    printf("cap=7  -> returned %d\n", n7);
    int fu7 = 0, fl7 = 0;
    for (int i = 0; i < n7 && i < PX_FORCED_MAX; i++) {
        if (kv[i].name && strcmp(kv[i].name, "BXROOT_ULX_PATH") == 0) fu7 = 1;
        if (kv[i].name && strcmp(kv[i].name, "BXROOT_ULX_LDSO") == 0) fl7 = 1;
    }
    printf("cap=7  -> ulx_path=%d ulx_ldso=%d\n", fu7, fl7);

    memset(kv, 0, sizeof(kv));
    int n32 = px_build_forced(&cfg, kv, PX_FORCED_MAX, "/bin/sh", "/bin/sh");
    printf("cap=%d -> returned %d\n", PX_FORCED_MAX, n32);
    int fu32 = 0, fl32 = 0;
    for (int i = 0; i < n32 && i < PX_FORCED_MAX; i++) {
        if (kv[i].name && strcmp(kv[i].name, "BXROOT_ULX_PATH") == 0) fu32 = 1;
        if (kv[i].name && strcmp(kv[i].name, "BXROOT_ULX_LDSO") == 0) fl32 = 1;
    }
    printf("cap=%d -> ulx_path=%d ulx_ldso=%d\n", PX_FORCED_MAX, fu32, fl32);
    printf("CONCLUSION: cap7_injects=%d cap32_injects=%d\n", fu7 && fl7, fu32 && fl32);
    return 0;
}