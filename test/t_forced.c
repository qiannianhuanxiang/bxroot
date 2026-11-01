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

    px_env_kv kv[PX_FORCED_MAX];
    memset(kv, 0, sizeof(kv));
    int n = px_build_forced(&cfg, kv, PX_FORCED_MAX, "/bin/sh", "/bin/sh");
    printf("px_build_forced returned %d\n", n);
    int fu = 0, fl = 0;
    for (int i = 0; i < n && i < PX_FORCED_MAX; i++) {
        printf("  [%d] %s=%s\n", i, kv[i].name ? kv[i].name : "(null)",
               kv[i].value ? kv[i].value : "(null)");
        if (kv[i].name && strcmp(kv[i].name, "BXROOT_ULX_PATH") == 0) fu = 1;
        if (kv[i].name && strcmp(kv[i].name, "BXROOT_ULX_LDSO") == 0) fl = 1;
    }
    printf("RESULT: ulx_path=%d ulx_ldso=%d\n", fu, fl);
    return (fu && fl) ? 0 : 1;
}