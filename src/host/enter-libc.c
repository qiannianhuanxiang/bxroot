/* bx-enter-only, single-threaded pre-exec bootstrap. SPDX-License-Identifier: MIT
 * Compile -DBX_ENTER_NATIVE -ffreestanding -fno-builtin -fno-stack-protector
 * -fPIE; disable header FORTIFY with -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0.
 * Link -nostdlib -pie -e bx_native_start. System linker only relocates
 * this PIE: no libc startup, TLS or libc DSO. Headers supply prototypes only.
 * FILE pointers are private tokens. This is not a general-purpose libc.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#if !defined(BX_ENTER_NATIVE) || !defined(__aarch64__)
#error "enter-libc.c is only for the AArch64 BX_ENTER_NATIVE executable"
#endif
#include "session.h"
#include <elf.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

static int bx_errno;
int *__errno_location(void) { return &bx_errno; }
char **environ;

void *memcpy(void *restrict dst, const void *restrict src, size_t n)
{
    unsigned char *d = dst;
    const unsigned char *s = src;
    while (n--) *d++ = *s++;
    return dst;
}
void *memset(void *dst, int c, size_t n)
{
    unsigned char *d = dst;
    while (n--) *d++ = (unsigned char)c;
    return dst;
}
void *memmove(void *dst, const void *src, size_t n)
{
    unsigned char *d = dst;
    const unsigned char *s = src;
    if ((uintptr_t)d <= (uintptr_t)s) {
        while (n--) *d++ = *s++;
    } else {
        d += n; s += n;
        while (n--) *--d = *--s;
    }
    return dst;
}
int memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *x = a, *y = b;
    while (n--) { if (*x != *y) return (int)*x - (int)*y; x++; y++; }
    return 0;
}
size_t strlen(const char *s)
{
    const char *p = s;
    while (*p) p++;
    return (size_t)(p - s);
}
char *strcpy(char *restrict dst, const char *restrict src)
{
    char *d = dst;
    do { *d++ = *src; } while (*src++);
    return dst;
}
int strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}
int strncmp(const char *a, const char *b, size_t n)
{
    while (n--) {
        if (*a != *b || !*a) return (int)(unsigned char)*a - (int)(unsigned char)*b;
        a++; b++;
    }
    return 0;
}
char *strchr(const char *s, int c)
{
    unsigned char ch = (unsigned char)c;
    do { if ((unsigned char)*s == ch) return (char *)s; } while (*s++);
    return NULL;
}
char *strrchr(const char *s, int c)
{
    const char *last = NULL;
    unsigned char ch = (unsigned char)c;
    do { if ((unsigned char)*s == ch) last = s; } while (*s++);
    return (char *)last;
}

/* One anonymous mapping per allocation, max_align_t-aligned. The header
 * records mapping extent and requested size. AT_PAGESZ handles 4/16 KiB. */
typedef union {
    struct { size_t mapped, requested; } size;
    max_align_t alignment;
} bx_allocation;
static size_t bx_pagesize = 4096;
void *malloc(size_t n)
{
    size_t used = n ? n : 1, total;
    long p;
    bx_allocation *h;
    if (used > SIZE_MAX - sizeof(*h) - (bx_pagesize - 1)) {
        errno = ENOMEM; return NULL;
    }
    total = (used + sizeof(*h) + bx_pagesize - 1) & ~(bx_pagesize - 1);
    if (total > (size_t)LONG_MAX) { errno = ENOMEM; return NULL; }
    p = bx_session_raw(SYS_mmap, 0, (long)total, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == -1) return NULL;
    h = (bx_allocation *)p;
    h->size.mapped = total; h->size.requested = n;
    return h + 1;
}
/* Keep the header access behind a call boundary: glibc's malloc prototype
 * carries alloc_size, which otherwise makes GCC diagnose the private header
 * before the returned object as an out-of-bounds inlined free. */
__attribute__((noinline)) void free(void *p)
{
    if (p) {
        bx_allocation *h = (bx_allocation *)p - 1;
        int saved = errno;
        bx_session_raw(SYS_munmap, (long)h, (long)h->size.mapped, 0, 0, 0, 0);
        errno = saved;
    }
}
void *calloc(size_t n, size_t size)
{
    if (size && n > SIZE_MAX / size) { errno = ENOMEM; return NULL; }
    /* mmap already zeroes the mapping, including malloc(0)'s single byte. */
    return malloc(n * size);
}
void *realloc(void *p, size_t n)
{
    void *q;
    bx_allocation *h;
    if (!p) return malloc(n);
    if (!n) { free(p); return NULL; }
    h = (bx_allocation *)p - 1;
    if (n <= h->size.mapped - sizeof(*h)) { h->size.requested = n; return p; }
    q = malloc(n);
    if (!q) return NULL;
    memcpy(q, p, h->size.requested < n ? h->size.requested : n);
    free(p);
    return q;
}
char *strdup(const char *s)
{
    size_t n = strlen(s);
    char *p;
    if (n == SIZE_MAX) { errno = ENOMEM; return NULL; }
    p = malloc(n + 1);
    if (p) memcpy(p, s, n + 1);
    return p;
}

/* Caller can replace environ while filtering. Never free the original stack
 * vector or borrowed strings. Replaced strings live until exec/exit; there
 * is deliberately no putenv/unsetenv and no general ownership registry. */
static char **bx_env_owned;
static int bx_env_match(const char *entry, const char *name, size_t n)
{
    return !strncmp(entry, name, n) && entry[n] == '=';
}
char *getenv(const char *name)
{
    size_t n = strlen(name), i;
    if (!n || strchr(name, '=')) return NULL;
    for (i = 0; environ && environ[i]; i++)
        if (bx_env_match(environ[i], name, n)) return environ[i] + n + 1;
    return NULL;
}
int setenv(const char *name, const char *value, int overwrite)
{
    size_t n, v, count = 0, slot = SIZE_MAX;
    char *entry;
    char **next;
    if (!name || !*name || strchr(name, '=')) { errno = EINVAL; return -1; }
    n = strlen(name); v = strlen(value);
    while (environ && environ[count]) {
        if (slot == SIZE_MAX && bx_env_match(environ[count], name, n)) slot = count;
        count++;
    }
    if (slot != SIZE_MAX && !overwrite) return 0;
    if (n > SIZE_MAX - 2 || v > SIZE_MAX - n - 2) { errno = ENOMEM; return -1; }
    entry = malloc(n + v + 2);
    if (!entry) return -1;
    memcpy(entry, name, n); entry[n] = '='; memcpy(entry + n + 1, value, v + 1);
    if (slot != SIZE_MAX) { environ[slot] = entry; return 0; }
    if (count > SIZE_MAX / sizeof(*next) - 2) { free(entry); errno = ENOMEM; return -1; }
    next = malloc((count + 2) * sizeof(*next));
    if (!next) { free(entry); return -1; }
    if (count) memcpy(next, environ, count * sizeof(*next));
    next[count] = entry; next[count + 1] = NULL;
    if (environ == bx_env_owned) free(bx_env_owned);
    bx_env_owned = next; environ = next;
    return 0;
}

/* Supported: %% %s %c %p and %[l|ll|z]{d,i,u,o,x,X}. Width/precision/flags,
 * floats, %n and positional arguments return EINVAL/-1 and NUL-terminate
 * partial output. Successful truncation returns the complete length. */
typedef struct { char *dst; size_t cap, length; int error; } bx_output;
static void bx_emit(bx_output *o, char c)
{
    if (o->length == INT_MAX) { o->error = EOVERFLOW; return; }
    if (o->cap && o->length < o->cap - 1) o->dst[o->length] = c;
    o->length++;
}
static void bx_number(bx_output *o, unsigned long long v, unsigned base, int upper)
{
    char digits[sizeof(v) * CHAR_BIT];
    const char *alphabet = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    size_t n = 0;
    do { digits[n++] = alphabet[v % base]; v /= base; } while (v);
    while (n) bx_emit(o, digits[--n]);
}
int vsnprintf(char *restrict dst, size_t cap, const char *restrict fmt, va_list ap)
{
    bx_output o = {dst, cap, 0, 0};
    while (*fmt && !o.error) {
        int length = 0;
        char spec;
        unsigned long long u;
        long long signed_value;
        if (*fmt != '%') { bx_emit(&o, *fmt++); continue; }
        fmt++;
        if (*fmt == 'l') { length = 1; fmt++; if (*fmt == 'l') { length = 2; fmt++; } }
        else if (*fmt == 'z') { length = 3; fmt++; }
        spec = *fmt;
        if (!spec) { o.error = EINVAL; break; }
        fmt++;
        if (spec == '%' && !length) bx_emit(&o, '%');
        else if (spec == 's' && !length) {
            const char *s = va_arg(ap, const char *);
            if (!s) s = "(null)";
            while (*s && !o.error) bx_emit(&o, *s++);
        } else if (spec == 'c' && !length) bx_emit(&o, (char)va_arg(ap, int));
        else if (spec == 'p' && !length) {
            bx_emit(&o, '0'); bx_emit(&o, 'x');
            bx_number(&o, (uintptr_t)va_arg(ap, void *), 16, 0);
        } else if (spec == 'd' || spec == 'i') {
            if (length == 1) signed_value = va_arg(ap, long);
            else if (length == 2) signed_value = va_arg(ap, long long);
            else if (length == 3) signed_value = va_arg(ap, ssize_t);
            else signed_value = va_arg(ap, int);
            u = (unsigned long long)signed_value;
            if (signed_value < 0) { bx_emit(&o, '-'); u = 0ULL - u; }
            bx_number(&o, u, 10, 0);
        } else if (spec == 'u' || spec == 'o' || spec == 'x' || spec == 'X') {
            if (length == 1) u = va_arg(ap, unsigned long);
            else if (length == 2) u = va_arg(ap, unsigned long long);
            else if (length == 3) u = va_arg(ap, size_t);
            else u = va_arg(ap, unsigned int);
            bx_number(&o, u, spec == 'o' ? 8 : spec == 'u' ? 10 : 16, spec == 'X');
        } else o.error = EINVAL;
    }
    if (cap) dst[o.length < cap ? o.length : cap - 1] = '\0';
    if (o.error) { errno = o.error; return -1; }
    return (int)o.length;
}
int snprintf(char *restrict dst, size_t cap, const char *restrict fmt, ...)
{
    va_list ap;
    int n;
    va_start(ap, fmt); n = vsnprintf(dst, cap, fmt, ap); va_end(ap);
    return n;
}

char *strerror(int e)
{
    switch (e) {
    case 0: return "Success";
    case EPERM: return "Operation not permitted";
    case ENOENT: return "No such file or directory";
    case ESRCH: return "No such process";
    case EINTR: return "Interrupted system call";
    case EIO: return "Input/output error";
    case ENXIO: return "No such device or address";
    case E2BIG: return "Argument list too long";
    case ENOEXEC: return "Exec format error";
    case EBADF: return "Bad file descriptor";
    case ECHILD: return "No child processes";
    case EAGAIN: return "Resource temporarily unavailable";
    case ENOMEM: return "Cannot allocate memory";
    case EACCES: return "Permission denied";
    case EFAULT: return "Bad address";
    case EBUSY: return "Device or resource busy";
    case EEXIST: return "File exists";
    case EXDEV: return "Invalid cross-device link";
    case ENODEV: return "No such device";
    case ENOTDIR: return "Not a directory";
    case EISDIR: return "Is a directory";
    case EINVAL: return "Invalid argument";
    case ENFILE: return "Too many open files in system";
    case EMFILE: return "Too many open files";
    case ENOTTY: return "Inappropriate ioctl for device";
    case EFBIG: return "File too large";
    case ENOSPC: return "No space left on device";
    case ESPIPE: return "Illegal seek";
    case EROFS: return "Read-only file system";
    case EMLINK: return "Too many links";
    case EPIPE: return "Broken pipe";
    case ERANGE: return "Numerical result out of range";
    case ENAMETOOLONG: return "File name too long";
    case ENOSYS: return "Function not implemented";
    case ENOTEMPTY: return "Directory not empty";
    case ELOOP: return "Too many levels of symbolic links";
    case EOVERFLOW: return "Value too large for defined data type";
    case EPROTO: return "Protocol error";
    case ENOTSUP: return "Operation not supported";
    case ENOTUNIQ: return "Name not unique on network";
    default: return "Unknown error";
    }
}

/* Only our stdout/stderr and unbuffered output exist. */
static max_align_t bx_stdout_token, bx_stderr_token;
FILE *stdout = (FILE *)&bx_stdout_token;
FILE *stderr = (FILE *)&bx_stderr_token;
static int bx_write_all(int fd, const char *s, size_t n)
{
    while (n) {
        long r = bx_session_raw(SYS_write, fd, (long)s,
                                n > (size_t)LONG_MAX ? LONG_MAX : (long)n, 0, 0, 0);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (!r) { errno = EIO; return -1; }
        s += r; n -= (size_t)r;
    }
    return 0;
}
int fprintf(FILE *restrict stream, const char *restrict fmt, ...)
{
    char local[512], *buf = local;
    int n, result, fd;
    va_list ap, copy;
    if (stream == (FILE *)&bx_stdout_token) fd = STDOUT_FILENO;
    else if (stream == (FILE *)&bx_stderr_token) fd = STDERR_FILENO;
    else { errno = EBADF; return -1; }
    va_start(ap, fmt); va_copy(copy, ap);
    n = vsnprintf(local, sizeof(local), fmt, copy); va_end(copy);
    if (n < 0) { va_end(ap); return -1; }
    if ((size_t)n >= sizeof(local)) {
        buf = malloc((size_t)n + 1);
        if (!buf) { va_end(ap); return -1; }
        result = vsnprintf(buf, (size_t)n + 1, fmt, ap);
        if (result < 0) { va_end(ap); free(buf); return -1; }
    }
    va_end(ap);
    result = bx_write_all(fd, buf, (size_t)n) ? -1 : n;
    if (buf != local) free(buf);
    return result;
}
int puts(const char *s)
{
    if (bx_write_all(STDOUT_FILENO, s, strlen(s)) ||
        bx_write_all(STDOUT_FILENO, "\n", 1)) return EOF;
    return 0;
}

extern int main(int argc, char **argv);
void bx_native_entry(uintptr_t *initial_sp) __attribute__((noreturn));
void bx_native_entry(uintptr_t *initial_sp)
{
    size_t argc = initial_sp[0];
    char **argv = (char **)(initial_sp + 1);
    char **end;
    uintptr_t *aux, interpreter_base = 0;
    int status, have_interpreter_base = 0;
    /* Locate envp using the original stack argc, before any argv adjustment. */
    environ = argv + argc + 1;
    end = environ;
    while (*end) end++;
    for (aux = (uintptr_t *)(end + 1); aux[0] != AT_NULL; aux += 2) {
        if (aux[0] == AT_PAGESZ && aux[1] && !(aux[1] & (aux[1] - 1)) &&
            aux[1] <= (uintptr_t)LONG_MAX) bx_pagesize = (size_t)aux[1];
        if (aux[0] == AT_BASE) {
            have_interpreter_base = 1; interpreter_base = aux[1];
        }
    }
    /* Android's explicitly invoked linker leaves its own argv[0] on the
     * stack. A kernel PT_INTERP launch has nonzero AT_BASE, so even a caller
     * choosing a linker-looking argv[0] must remain untouched in that case. */
    if (argc >= 2 && have_interpreter_base && !interpreter_base &&
        (!strcmp(argv[0], "/system/bin/linker64") ||
         !strcmp(argv[0], "/apex/com.android.runtime/bin/linker64"))) {
        argc--; argv++;
    }
    status = main((int)argc, argv);
    bx_session_raw(SYS_exit_group, status, 0, 0, 0, 0, 0);
    for (;;) __asm__ volatile("brk #0");
}
__asm__(
    ".text\n"
    ".globl bx_native_start\n"
    ".type bx_native_start,%function\n"
    "bx_native_start:\n"
    "  mov x0, sp\n"
    "  b bx_native_entry\n"
    ".size bx_native_start, .-bx_native_start\n");
