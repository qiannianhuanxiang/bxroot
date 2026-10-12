/* Build "${TMPDIR:-/tmp}/<name>" so tests also run where /tmp is unwritable (Termux). */
#ifndef BX_TMPDIR_H
#define BX_TMPDIR_H
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static inline int bx_tmppath(char *out, size_t n, const char *name)
{
    const char *t = getenv("TMPDIR");
    int r;
    if (t == NULL || t[0] == '\0')
        t = "/tmp";
    r = snprintf(out, n, "%s/%s", t, name);
    return (r < 0 || (size_t)r >= n) ? -1 : 0;
}
#endif
