#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/ldr/ulx-libpath.h"

static void test_paths(void)
{
    char out[BXROOT_ULX_LIBPATH_SIZE];
    size_t used = 0;
    const char *env[] = {"LD_LIBRARY_PATH=/opt/guest/lib:/usr/lib/aarch64-linux-gnu/systemd:/opt/guest/lib", NULL};
    const char *lp;

    out[0] = '\0';
    assert(bxroot_ulx_append_libdir(out, sizeof out, &used, "/rootfs", "/usr/lib/aarch64-linux-gnu/systemd") == 0);
    assert(strcmp(out, "/rootfs/usr/lib/aarch64-linux-gnu/systemd") == 0);
    assert(bxroot_ulx_append_env_libpath(out, sizeof out, &used, "/rootfs", "/opt/guest/lib:/usr/lib/aarch64-linux-gnu/systemd:/opt/guest/lib") == 0);
    assert(strcmp(out, "/rootfs/usr/lib/aarch64-linux-gnu/systemd:/rootfs/opt/guest/lib") == 0);
    lp = bxroot_ulx_env_value((char *const *)env, "LD_LIBRARY_PATH");
    assert(lp != NULL && strcmp(lp, "/opt/guest/lib:/usr/lib/aarch64-linux-gnu/systemd:/opt/guest/lib") == 0);
    assert(bxroot_ulx_env_value((char *const *)env, "PATH") == NULL);
    puts("ULX_LIBPATH_OK");
}

static void test_host_path(void)
{
    char out[BXROOT_ULX_LIBPATH_SIZE];
    size_t used = 0;
    out[0] = '\0';
    assert(bxroot_ulx_append_libdir(out, sizeof out, &used, "/rootfs", "/rootfs/usr/lib") == 0);
    assert(strcmp(out, "/rootfs/usr/lib") == 0);

    used = 0;
    out[0] = '\0';
    assert(bxroot_ulx_append_libdir(out, sizeof out, &used, "/", "/usr/lib") == 0);
    assert(strcmp(out, "/usr/lib") == 0);
}

int main(void)
{
    test_paths();
    test_host_path();
    return 0;
}
