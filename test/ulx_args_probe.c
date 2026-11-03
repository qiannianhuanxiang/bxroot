#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>

static size_t c_len(const char *s)
{
    size_t n = 0;
    while (s[n] != '\0') n++;
    return n;
}

static int c_eq(const char *a, const char *b)
{
    size_t i = 0;
    while (a[i] && b[i] && a[i] == b[i]) i++;
    return a[i] == '\0' && b[i] == '\0';
}

static void raw_write(const char *s, size_t n)
{
    register long x0 __asm__("x0") = 1;
    register const char *x1 __asm__("x1") = s;
    register size_t x2 __asm__("x2") = n;
    register long x8 __asm__("x8") = 64;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
}

__attribute__((noreturn)) static void raw_exit(int status)
{
    register long x0 __asm__("x0") = status;
    register long x8 __asm__("x8") = 93;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x8) : "memory");
    __builtin_unreachable();
}

__attribute__((noreturn)) void _start(uintptr_t *sp)
{
    uintptr_t argc = sp[0];
    char **argv = (char **)&sp[1];
    const char *library_path = 0;
    uintptr_t i;

    for (i = 0; i + 1 < argc; i++) {
        if (c_eq(argv[i], "--library-path")) {
            library_path = argv[i + 1];
            break;
        }
    }
    if (library_path == 0) {
        raw_write("NO_LIBRARY_PATH\n", 16);
        raw_exit(1);
    }
    raw_write(library_path, c_len(library_path));
    raw_write("\n", 1);
    raw_exit(0);
}
