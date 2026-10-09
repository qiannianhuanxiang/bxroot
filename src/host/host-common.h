/* Shared freestanding ELF classifier and environment policy. SPDX-License-Identifier: MIT */
#ifndef BXROOT_HOST_COMMON_H
#define BXROOT_HOST_COMMON_H
#include <stddef.h>
#include <stdint.h>

enum { BX_HOST_WORLD_NO = 0, BX_HOST_WORLD_BIONIC = 1,
       BX_HOST_WORLD_STATIC = 2, BX_HOST_WORLD_SCRIPT = 3 };
#define BX_HOST_DEFAULT_PATH "/system/bin:/system/xbin:/vendor/bin"

static inline size_t bxhc_len(const char *s)
{
    size_t n = 0;
    if (s) while (s[n]) n++;
    return n;
}
static inline int bxhc_prefix(const char *s, const char *p)
{
    if (!s || !p) return 0;
    while (*p) if (*s++ != *p++) return 0;
    return 1;
}
static inline int bxhc_equal(const char *s, const char *p)
{
    if (!s || !p) return 0;
    while (*s && *s == *p) { s++; p++; }
    return *s == *p;
}
static inline int bxhc_native_tree(const char *p)
{
    return bxhc_prefix(p, "/system/") || bxhc_prefix(p, "/system_ext/") ||
           bxhc_prefix(p, "/apex/") || bxhc_prefix(p, "/vendor/") ||
           bxhc_prefix(p, "/product/") || bxhc_prefix(p, "/odm/");
}
static inline int bxhc_bionic_interp(const char *p)
{
    return bxhc_equal(p, "/system/bin/linker64") ||
           bxhc_equal(p, "/apex/com.android.runtime/bin/linker64");
}
static inline uint16_t bxhc_u16(const unsigned char *p)
{ return (uint16_t)p[0] | ((uint16_t)p[1] << 8); }
static inline uint32_t bxhc_u32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline uint64_t bxhc_u64(const unsigned char *p)
{ return (uint64_t)bxhc_u32(p) | ((uint64_t)bxhc_u32(p + 4) << 32); }

typedef long (*bxhc_pread_fn)(int, void *, size_t, uint64_t);
/* Inspect exactly the opened file. No guest->host path guessing. */
static inline int bxhc_elf(int fd, const char *path, bxhc_pread_fn pread_fn)
{
    unsigned char eh[64], ph[56];
    char interp[256];
    uint64_t phoff;
    unsigned entsize, count, i;
    int kind = BX_HOST_WORLD_NO, have_interp = 0;
    if (pread_fn(fd, eh, sizeof(eh), 0) != (long)sizeof(eh) ||
        eh[0] != 0x7f || eh[1] != 'E' || eh[2] != 'L' || eh[3] != 'F' ||
        eh[4] != 2 || eh[5] != 1 || eh[6] != 1 || bxhc_u16(eh + 18) != 183 ||
        (bxhc_u16(eh + 16) != 2 && bxhc_u16(eh + 16) != 3) ||
        bxhc_u16(eh + 52) != 64)
        return BX_HOST_WORLD_NO;
    phoff = bxhc_u64(eh + 32);
    entsize = bxhc_u16(eh + 54);
    count = bxhc_u16(eh + 56);
    if (entsize < sizeof(ph) || !count || count > 128 ||
        phoff > INT64_MAX - (uint64_t)count * entsize)
        return BX_HOST_WORLD_NO;
    for (i = 0; i < count; i++) {
        uint64_t off, len;
        if (pread_fn(fd, ph, sizeof(ph), phoff + (uint64_t)i * entsize) != (long)sizeof(ph))
            return BX_HOST_WORLD_NO;
        if (bxhc_u32(ph) != 3) continue;
        if (have_interp++) return BX_HOST_WORLD_NO;
        off = bxhc_u64(ph + 8);
        len = bxhc_u64(ph + 32);
        if (len < 2 || len > sizeof(interp) || off > INT64_MAX - len ||
            pread_fn(fd, interp, (size_t)len, off) != (long)len ||
            interp[len - 1] != '\0' || bxhc_len(interp) != len - 1)
            return BX_HOST_WORLD_NO;
        kind = bxhc_bionic_interp(interp) ? BX_HOST_WORLD_BIONIC : BX_HOST_WORLD_NO;
    }
    if (have_interp) return kind;
    return bxhc_u64(eh + 24) && bxhc_native_tree(path) ? BX_HOST_WORLD_STATIC : BX_HOST_WORLD_NO;
}
static inline int bxhc_guest_elf(int fd, bxhc_pread_fn pread_fn)
{
    unsigned char eh[64], ph[56];
    char interp[256];
    uint64_t phoff;
    unsigned entsize, count, i;
    int have = 0;
    if (pread_fn(fd, eh, sizeof(eh), 0) != (long)sizeof(eh) ||
        eh[0] != 0x7f || eh[1] != 'E' || eh[2] != 'L' || eh[3] != 'F' ||
        eh[4] != 2 || eh[5] != 1 || eh[6] != 1 || bxhc_u16(eh + 18) != 183 ||
        (bxhc_u16(eh + 16) != 2 && bxhc_u16(eh + 16) != 3) || bxhc_u16(eh + 52) != 64)
        return 0;
    phoff = bxhc_u64(eh + 32); entsize = bxhc_u16(eh + 54); count = bxhc_u16(eh + 56);
    if (entsize < sizeof(ph) || !count || count > 128 || phoff > INT64_MAX - (uint64_t)count * entsize) return 0;
    for (i = 0; i < count; i++) {
        uint64_t off, len;
        if (pread_fn(fd, ph, sizeof(ph), phoff + (uint64_t)i * entsize) != (long)sizeof(ph)) return 0;
        if (bxhc_u32(ph) != 3) continue;
        if (have++) return 0;
        off = bxhc_u64(ph + 8); len = bxhc_u64(ph + 32);
        if (len < 2 || len > sizeof(interp) || off > INT64_MAX - len ||
            pread_fn(fd, interp, (size_t)len, off) != (long)len ||
            interp[len - 1] != '\0' || bxhc_len(interp) != len - 1) return 0;
        if (!bxhc_equal(interp, "/lib/ld-linux-aarch64.so.1") &&
            !bxhc_equal(interp, "/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1") &&
            !bxhc_equal(interp, "/lib64/ld-linux-aarch64.so.1")) return 0;
    }
    return have == 1;
}
static inline int bxhc_env_name(const char *e, const char *name)
{
    size_t i = 0;
    if (!e || !name) return 0;
    while (name[i]) { if (e[i] != name[i]) return 0; i++; }
    return e[i] == '=';
}
static inline int bxhc_keep_env(const char *e)
{
    return e && !bxhc_prefix(e, "LD_") && !bxhc_prefix(e, "BXROOT_") &&
           !bxhc_prefix(e, "PROROOT_") && !bxhc_prefix(e, "PROOT_") &&
           !bxhc_env_name(e, "PATH") && !bxhc_env_name(e, "HOME") &&
           !bxhc_env_name(e, "TMPDIR") && !bxhc_env_name(e, "PWD") &&
           !bxhc_env_name(e, "OLDPWD") && !bxhc_env_name(e, "ANDROID_ROOT") &&
           !bxhc_env_name(e, "ANDROID_DATA") && !bxhc_env_name(e, "ANDROID_RUNTIME_ROOT") &&
           !bxhc_env_name(e, "ANDROID_ART_ROOT") && !bxhc_env_name(e, "ANDROID_I18N_ROOT") &&
           !bxhc_env_name(e, "ANDROID_TZDATA_ROOT");
}
#endif
