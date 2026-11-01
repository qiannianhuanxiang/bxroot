#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "proc.c"

int main(void) {
    px_rtconfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.have_rootfs = 1;
    snprintf(cfg.rootfs, sizeof(cfg.rootfs), "%s", "/data/data/x/files/linux/ubuntu");
    cfg.have_preload = 1;
    snprintf(cfg.preload, sizeof(cfg.preload), "%s", "/data/app/lib/libbxroot-runtime.so");

    px_env_kv kv[PX_FORCED_MAX];
    memset(kv, 0, sizeof(kv));
    int n = px_build_forced(&cfg, kv, PX_FORCED_MAX, "/usr/local/bin/node", "/usr/local/bin/node");
    printf("returned %d entries\n", n);
    int has_ldpreload = 0;
    for (int i = 0; i < n; i++) {
        printf("  [%d] %s = %s (mode=%d)\n", i,
               kv[i].name ? kv[i].name : "(null)",
               kv[i].value ? kv[i].value : "(null)", kv[i].mode);
        if (kv[i].name && strcmp(kv[i].name, "LD_PRELOAD") == 0) has_ldpreload = 1;
    }
    printf("RESULT: LD_PRELOAD injected = %d\n", has_ldpreload);
    return has_ldpreload ? 0 : 1;
}