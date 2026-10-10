/* Shared by the runtime and static native bx-enter. SPDX-License-Identifier: MIT */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "session.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#ifndef ENOTUNIQ
#define ENOTUNIQ 76
#endif
long bx_session_raw(long nr, long a, long b, long c, long d, long e, long f)
{
#if defined(__aarch64__)
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a, x1 __asm__("x1") = b, x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d, x4 __asm__("x4") = e, x5 __asm__("x5") = f;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2),
                     "r"(x3), "r"(x4), "r"(x5) : "memory", "cc");
    if (x0 < 0 && x0 >= -4095) { errno = (int)-x0; return -1; }
    return x0;
#else
    return syscall(nr, a, b, c, d, e, f);
#endif
}
void bx_session_init(bx_session *s) { memset(s, 0, sizeof(*s)); }
void bx_session_dispose(bx_session *s)
{
    size_t i;
    for (i = 0; i < s->nkv; i++) { free(s->kv[i].name); free(s->kv[i].value); }
    for (i = 0; i < s->nb; i++) { free(s->binds[i].host); free(s->binds[i].guest); }
    bx_session_init(s);
}
static int valid_name(const char *p)
{
    size_t n = 0;
    if (!p || !*p) return 0;
    for (; *p; p++, n++)
        if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
              (*p >= '0' && *p <= '9') || *p == '_') || n >= 127) return 0;
    return 1;
}
const char *bx_session_get(const bx_session *s, const char *name)
{
    size_t i;
    for (i = 0; i < s->nkv; i++) if (!strcmp(s->kv[i].name, name)) return s->kv[i].value;
    return NULL;
}
int bx_session_set(bx_session *s, const char *name, const char *value)
{
    size_t i; char *n, *v;
    if (!valid_name(name) || !value || strlen(value) > 131071) { errno = EINVAL; return -1; }
    v = strdup(value); if (!v) return -1;
    for (i = 0; i < s->nkv; i++) if (!strcmp(s->kv[i].name, name)) {
        free(s->kv[i].value); s->kv[i].value = v; return 0;
    }
    if (s->nkv == BX_SESSION_MAX_KV) { free(v); errno = E2BIG; return -1; }
    n = strdup(name); if (!n) { free(v); return -1; }
    s->kv[s->nkv++] = (bx_session_kv){n, v}; return 0;
}
static int copy_path(char *o, size_t cap, const char *p)
{
    size_t n = strlen(p);
    if (n >= cap) { errno = ENAMETOOLONG; return -1; }
    memcpy(o, p, n + 1); return 0;
}
static int prefix(const char *p, const char *base)
{
    size_t n = strlen(base);
    return !strcmp(base, "/") || (!strncmp(p, base, n) && (!p[n] || p[n] == '/'));
}
static int normalized(const char *path, const char *cwd, char *out, size_t cap)
{
    char buf[BX_SESSION_PATH]; const char *p; size_t n = 0;
    if (!path || !*path || (!cwd && path[0] != '/')) { errno = EINVAL; return -1; }
    if (path[0] == '/') {
        if (copy_path(buf, sizeof(buf), path)) return -1;
    } else if (snprintf(buf, sizeof(buf), "%s/%s", cwd, path) >= (int)sizeof(buf)) {
        errno = ENAMETOOLONG; return -1;
    }
    out[0] = '/'; out[1] = 0; n = 1;
    for (p = buf; *p;) {
        const char *a; size_t l;
        while (*p == '/') p++;
        a = p; while (*p && *p != '/') p++; l = (size_t)(p-a);
        if (!l || (l == 1 && *a == '.')) continue;
        if (l == 2 && a[0] == '.' && a[1] == '.') {
            while (n > 1 && out[n-1] != '/') n--;
            if (n > 1) n--;
            out[n] = 0;
            continue;
        }
        if (n + l + 2 > cap) { errno = ENAMETOOLONG; return -1; }
        if (n > 1) out[n++] = '/';
        memcpy(out+n, a, l); n += l; out[n] = 0;
    }
    return 0;
}
int bx_session_add_bind(bx_session *s, const char *host, const char *guest, unsigned ro)
{
    char h[BX_SESSION_PATH], g[BX_SESSION_PATH]; char *hp, *gp;
    if (!host || !guest || host[0] != '/' || guest[0] != '/' || ro > 1) { errno = EINVAL; return -1; }
    if (s->nb >= BX_SESSION_MAX_BINDS) { errno = E2BIG; return -1; }
    if (copy_path(h, sizeof(h), host) || copy_path(g, sizeof(g), guest)) return -1;
    { size_t n = strlen(h); while (n > 1 && h[n-1] == '/') h[--n] = 0;
      n = strlen(g); while (n > 1 && g[n-1] == '/') g[--n] = 0; }
    hp = strdup(h); gp = strdup(g);
    if (!hp || !gp) { free(hp); free(gp); return -1; }
    s->binds[s->nb++] = (bx_session_bind){hp, gp, ro}; return 0;
}
static int join_map(const char *base, const char *suffix, char *o, size_t cap)
{
    while (*suffix == '/') suffix++;
    if (!*suffix) return copy_path(o, cap, base);
    if (snprintf(o, cap, "%s%s%s", base, !strcmp(base,"/") ? "" : "/", suffix) >= (int)cap) {
        errno = ENAMETOOLONG; return -1;
    }
    return 0;
}
static int map_plain(const bx_session *s, const char *g, char *o, size_t cap)
{
    const char *root = bx_session_get(s, "BXROOT_ROOTFS"); size_t i, best = 0; int bi = -1;
    static const char *const special[] = {"/proc", "/sys", "/dev"};
    for (i = 0; i < s->nb; i++) {
        size_t n = strlen(s->binds[i].guest);
        if (prefix(g, s->binds[i].guest) &&
            (strcmp(s->binds[i].guest, "/") || !strcmp(g, "/")) &&
            (bi < 0 || n > best)) { best = n; bi = (int)i; }
    }
    if (bi >= 0) return join_map(s->binds[bi].host, !strcmp(s->binds[bi].guest,"/") ? g : g+best, o, cap);
    {
        const char *sh = bx_session_get(s, "_SHM_HOST"), *sg = bx_session_get(s, "_SHM_GUEST");
        if (sh && sg && prefix(g, sg)) return join_map(sh, g + strlen(sg), o, cap);
    }
    for (i = 0; i < sizeof(special)/sizeof(special[0]); i++)
        if (prefix(g, special[i])) return copy_path(o, cap, g);
    if (!root || root[0] != '/') { errno = EINVAL; return -1; }
    return join_map(root, g, o, cap);
}
int bx_session_to_host(const bx_session *s, const char *path, const char *cwd, char *out, size_t cap)
{
    char rest[BX_SESSION_PATH], cur[BX_SESSION_PATH] = "/", backing[BX_SESSION_PATH], target[BX_SESSION_PATH];
    unsigned links = 0; const char *r;
    if (!path || !*path) { errno = ENOENT; return -1; }
    /* Preserve .. until AFTER preceding links have been resolved. */
    if (path[0] == '/') { if (copy_path(rest, sizeof(rest), path)) return -1; }
    else if (!cwd || cwd[0] != '/' || snprintf(rest,sizeof(rest),"%s/%s",cwd,path) >= (int)sizeof(rest)) {
        errno = ENAMETOOLONG; return -1;
    }
    r = rest;
    while (*r) {
        char next[BX_SESSION_PATH]; const char *a; size_t l, cl; long n;
        while (*r == '/') r++;
        a = r; while (*r && *r != '/') r++; l = (size_t)(r-a);
        if (!l || (l == 1 && *a == '.')) continue;
        if (l == 2 && a[0] == '.' && a[1] == '.') {
            char *slash = strrchr(cur, '/'); if (slash == cur) cur[1] = 0; else if (slash) *slash=0;
            continue;
        }
        cl = strlen(cur);
        if (cl + l + 2 >= sizeof(cur)) { errno = ENAMETOOLONG; return -1; }
        if (cl > 1) cur[cl++]='/';
        memcpy(cur+cl,a,l);
        cur[cl+l]=0;
        if (map_plain(s, cur, backing, sizeof(backing))) return -1;
        /* proc magic targets are kernel handles, never memfd display names. */
        if (prefix(cur,"/proc")) continue;
        {
            int mount_root = 0;
            for (size_t bi = 0; bi < s->nb; bi++)
                if (!strcmp(cur, s->binds[bi].guest)) { mount_root = 1; break; }
            if (mount_root) {
                struct stat st;
                if (*r && bx_session_raw(SYS_newfstatat, AT_FDCWD, (long)backing, (long)&st, 0, 0, 0) < 0) return -1;
                if (*r && !S_ISDIR(st.st_mode)) { errno = ENOTDIR; return -1; }
                continue;
            }
        }
        n = bx_session_raw(SYS_readlinkat, AT_FDCWD, (long)backing, (long)target, sizeof(target)-1,0,0);
        if (n < 0) {
            int saved = errno;
            struct stat st;
            if (saved == ENOTDIR || (saved == ENOENT && *r)) { errno = saved; return -1; }
            if (saved != EINVAL && saved != ENOENT) return -1;
            if (*r) {
                if (bx_session_raw(SYS_newfstatat, AT_FDCWD, (long)backing, (long)&st, 0, 0, 0) < 0) return -1;
                if (!S_ISDIR(st.st_mode)) { errno = ENOTDIR; return -1; }
            }
            continue;
        }
        if (++links > 40) { errno=ELOOP; return -1; }
        target[n]=0;
        if (snprintf(next,sizeof(next),"%s%s",target,r) >= (int)sizeof(next)) { errno=ENAMETOOLONG; return -1; }
        if (target[0]=='/') strcpy(cur,"/");
        else { char *slash = strrchr(cur,'/'); if (slash == cur) cur[1]=0; else *slash=0; }
        strcpy(rest,next); r=rest;
    }
    return map_plain(s, cur, out, cap);
}
static int same_path(const char *a, const char *b)
{
    struct stat sa, sb;
    if (!strcmp(a,b)) return 1;
    if (bx_session_raw(SYS_newfstatat, AT_FDCWD,(long)a,(long)&sa,0,0,0) ||
        bx_session_raw(SYS_newfstatat, AT_FDCWD,(long)b,(long)&sb,0,0,0)) return 0;
    return sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
}
static int physical_path(const char *path, char *out, size_t cap)
{
    char proc[96]; long fd, n;
    fd = bx_session_raw(SYS_openat, AT_FDCWD, (long)path, O_PATH | O_CLOEXEC, 0, 0, 0);
    if (fd < 0) return -1;
    snprintf(proc, sizeof(proc), "/proc/%ld/fd/%ld", bx_session_raw(SYS_getpid, 0, 0, 0, 0, 0, 0), fd);
    n = bx_session_raw(SYS_readlinkat, AT_FDCWD, (long)proc, (long)out, cap - 1, 0, 0);
    { int saved = errno; bx_session_raw(SYS_close, fd, 0, 0, 0, 0, 0); errno = saved; }
    if (n < 0) return -1;
    if ((size_t)n >= cap - 1) { errno = ENAMETOOLONG; return -1; }
    out[n] = 0;
    if (out[0] != '/') { errno = ENOENT; return -1; }
    return 0;
}
int bx_session_to_guest(const bx_session *s, const char *path, char *out, size_t cap)
{
    char h[BX_SESSION_PATH], cand[BX_SESSION_PATH], fwd[BX_SESSION_PATH], found[BX_SESSION_PATH]="";
    const char *root=bx_session_get(s,"BXROOT_ROOTFS"); size_t i;
    static const char *const special[]={"/proc","/sys","/dev"};
    if (!path || path[0]!='/') { errno=EINVAL; return -1; }
    if (physical_path(path,h,sizeof(h))) {
        if (errno != ENOENT) return -1;
        if (normalized(path,NULL,h,sizeof(h))) return -1;
    }
    for (i=0; i<s->nb+5; i++) {
        const char *src, *dst; char physical[BX_SESSION_PATH];
        if (i<s->nb) { src=s->binds[i].host; dst=s->binds[i].guest; }
        else if (i==s->nb) { src=root; dst="/"; }
        else if (i==s->nb+1) { src=bx_session_get(s,"_SHM_HOST"); dst=bx_session_get(s,"_SHM_GUEST"); }
        else { src=special[i-s->nb-2]; dst=src; }
        if (!src || !dst) continue;
        if (physical_path(src,physical,sizeof(physical)) == 0) src=physical;
        if (!prefix(h,src)) continue;
        if (join_map(dst,!strcmp(src,"/") ? h : h+strlen(src),cand,sizeof(cand)) ||
            bx_session_to_host(s,cand,"/",fwd,sizeof(fwd)) || !same_path(fwd,h)) continue;
        if (*found && strcmp(found,cand)) { errno=ENOTUNIQ; return -1; }
        strcpy(found,cand);
    }
    if (!*found) { errno=ENOENT; return -1; }
    return copy_path(out,cap,found);
}
int bx_session_fd_number(const char *p)
{
    unsigned v=0;
    if (!p || !*p) { errno=EINVAL; return -1; }
    for (; *p; p++) {
        if (*p<'0' || *p>'9' || v>214748364u || (v==214748364u && *p>'7')) { errno=EINVAL; return -1; }
        v=v*10+(unsigned)(*p-'0');
    }
    if (v<3) { errno=EINVAL; return -1; } return (int)v;
}
/* Little-endian wire format: magic[8], version,size,nkv,nb (u32), then
 * {kind,flags,lenA,lenB}+two NUL-terminated strings. No pointers or padding. */
static void put32(unsigned char *p,uint32_t v) { p[0]=(unsigned char)v; p[1]=(unsigned char)(v>>8); p[2]=(unsigned char)(v>>16); p[3]=(unsigned char)(v>>24); }
static uint32_t get32(const unsigned char *p) { return p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
int bx_session_create_fd(const bx_session *s)
{
    size_t len=24,i,pos=24; unsigned char *buf; int fd=-1, ro=-1, e; char path[64];
    for(i=0;i<s->nkv;i++) len+=16+strlen(s->kv[i].name)+strlen(s->kv[i].value)+2;
    for(i=0;i<s->nb;i++) len+=16+strlen(s->binds[i].host)+strlen(s->binds[i].guest)+2;
    if(len>BX_SESSION_MAX_BYTES) { errno=E2BIG; return -1; }
    buf=calloc(1,len); if(!buf) return -1;
    memcpy(buf,"BXSESS3\0",8); put32(buf+8,1); put32(buf+12,(uint32_t)len);
    put32(buf+16,(uint32_t)s->nkv); put32(buf+20,(uint32_t)s->nb);
    for(i=0;i<s->nkv+s->nb;i++) {
        const char *a,*b; size_t la,lb; unsigned kind=1,flags=0;
        if(i<s->nkv) { a=s->kv[i].name; b=s->kv[i].value; }
        else { size_t j=i-s->nkv; a=s->binds[j].host; b=s->binds[j].guest; kind=2; flags=s->binds[j].ro; }
        la=strlen(a)+1; lb=strlen(b)+1;
        put32(buf+pos,kind); put32(buf+pos+4,flags); put32(buf+pos+8,(uint32_t)la); put32(buf+pos+12,(uint32_t)lb); pos+=16;
        memcpy(buf+pos,a,la); pos+=la; memcpy(buf+pos,b,lb); pos+=lb;
    }
    fd=(int)bx_session_raw(SYS_memfd_create,(long)"bxroot-session-v3",3,0,0,0,0);
    if(fd<0) goto fail;
    pos=0; while(pos<len) {
        long n=bx_session_raw(SYS_write,fd,(long)(buf+pos),(long)(len-pos),0,0,0);
        if(n<0) { if(errno==EINTR) continue; goto fail; } if(!n) {errno=EIO;goto fail;} pos+=(size_t)n;
    }
    /* F_SEAL_SEAL|SHRINK|GROW|WRITE. Immutable across concurrent readers. */
    if(bx_session_raw(SYS_fcntl,fd,F_ADD_SEALS,15,0,0,0)<0) goto fail;
    snprintf(path,sizeof(path),"/proc/self/fd/%d",fd);
    ro=(int)bx_session_raw(SYS_openat,AT_FDCWD,(long)path,O_RDONLY,0,0,0);
    if(ro<0) goto fail;
    if(ro<3) { int dup=(int)bx_session_raw(SYS_fcntl,ro,F_DUPFD,3,0,0,0); bx_session_raw(SYS_close,ro,0,0,0,0,0);ro=dup; }
    if(ro<0) goto fail;
    bx_session_raw(SYS_close,fd,0,0,0,0,0); free(buf); return ro;
fail:
    e=errno; if(fd>=0) bx_session_raw(SYS_close,fd,0,0,0,0,0); if(ro>=0) bx_session_raw(SYS_close,ro,0,0,0,0,0);free(buf);errno=e;return -1;
}
static int pread_all(int fd, unsigned char *p,size_t n,size_t off)
{
    while(n) { long r=bx_session_raw(SYS_pread64,fd,(long)p,(long)n,(long)off,0,0);
        if(r<0) { if(errno==EINTR) continue;return -1;} if(!r) {errno=EPROTO;return -1;} p+=r;n-=(size_t)r;off+=(size_t)r; }
    return 0;
}
int bx_session_read(int fd,bx_session *s)
{
    unsigned char header[24],*b=NULL; uint32_t len,nk,nb;size_t pos=24,i;bx_session tmp; int e, seals;
    /* Session 内容包含宿主路径、加载器路径和环境配置。只校验 wire
       格式不足以建立信任：调用者可用普通可写 memfd 伪造同样内容，随后
       在 re-entry 前改写它。创建端固定加这四个 seal，读取端必须强制验证。 */
    seals = (int)bx_session_raw(SYS_fcntl, fd, F_GET_SEALS, 0, 0, 0, 0);
    if (seals < 0 || (seals & (F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE)) !=
                     (F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE)) {
        errno = EPROTO;
        return -1;
    }
    bx_session_init(&tmp);
    if(pread_all(fd,header,24,0)) return -1;
    len=get32(header+12);nk=get32(header+16);nb=get32(header+20);
    if(memcmp(header,"BXSESS3\0",8) || get32(header+8)!=1 || len<24 || len>BX_SESSION_MAX_BYTES || nk>BX_SESSION_MAX_KV || nb>BX_SESSION_MAX_BINDS) {errno=EPROTO;return -1;}
    b=malloc(len);if(!b)return -1;
    if(pread_all(fd,b,len,0))goto fail;
    for(i=0;i<(size_t)nk+nb;i++) {
        uint32_t k,fl,la,lb;const char *a,*v;
        if(pos>len || len-pos<16)goto bad;
        k=get32(b+pos);fl=get32(b+pos+4);la=get32(b+pos+8);lb=get32(b+pos+12);pos+=16;
        if(!la || !lb || la>len-pos || lb>len-pos-la)goto bad;
        a=(const char*)b+pos;v=a+la;
        if(a[la-1] || v[lb-1] || strlen(a)!=la-1 || strlen(v)!=lb-1)goto bad;
        if(i<nk) {if(k!=1 || fl || !valid_name(a) || bx_session_get(&tmp,a))goto bad; if(bx_session_set(&tmp,a,v))goto fail;}
        else {if(k!=2 || fl>1 || a[0]!='/' || v[0]!='/')goto bad; if(bx_session_add_bind(&tmp,a,v,fl))goto fail;}
        pos+=(size_t)la+lb;
    }
    if(pos!=len || !bx_session_get(&tmp,"BXROOT_ROOTFS") || bx_session_get(&tmp,"BXROOT_ROOTFS")[0]!='/')goto bad;
    free(b);bx_session_dispose(s);*s=tmp;return 0;
bad:errno=EPROTO;
fail:e=errno;free(b);bx_session_dispose(&tmp);errno=e;return -1;
}
