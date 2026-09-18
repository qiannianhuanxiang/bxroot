#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <link.h>
#include <unistd.h>

static void where(const char *label, void *p)
{
    Dl_info di;
    memset(&di, 0, sizeof di);
    if (p && dladdr(p, &di))
        printf("  %-28s %p  <- %s  (%s)\n", label, p,
               di.dli_fname ? di.dli_fname : "(null)",
               di.dli_sname ? di.dli_sname : "(no sym)");
    else
        printf("  %-28s %p  (dladdr 失败/空)\n", label, p);
}

int main(void)
{
    printf("== 被测函数指针（本程序 PLT 解析到的实现）==\n");
    where("dlsym", (void *)dlsym);
    where("dlopen", (void *)dlopen);
    where("dlerror", (void *)dlerror);
    where("dladdr", (void *)dladdr);
    where("dl_iterate_phdr", (void *)dl_iterate_phdr);
    where("malloc", (void *)malloc);
    where("readlink", (void *)readlink);

    printf("== RTLD_DEFAULT 查找 ==\n");
    printf("  dlsym(DEFAULT,\"malloc\")  = %p\n", dlsym(RTLD_DEFAULT, "malloc"));
    printf("  dlsym(DEFAULT,\"dlsym\")   = %p\n", dlsym(RTLD_DEFAULT, "dlsym"));
    printf("  dlsym(NEXT,\"malloc\")     = %p\n", dlsym(RTLD_NEXT, "malloc"));

    printf("== 先 dlopen libc 再查 ==\n");
    void *lc = dlopen("libc.so.6", RTLD_NOW | RTLD_GLOBAL);
    printf("  dlopen(libc.so.6) = %p  %s\n", lc, lc ? "" : (dlerror() ? dlerror() : ""));
    printf("  dlsym(DEFAULT,\"malloc\")  = %p\n", dlsym(RTLD_DEFAULT, "malloc"));
    if (lc) printf("  dlsym(libc,\"malloc\")     = %p\n", dlsym(lc, "malloc"));
    return 0;
}
