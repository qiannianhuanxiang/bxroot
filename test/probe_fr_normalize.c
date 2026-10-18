/*
 * probe_fr_normalize.c —— fr_normalize_path 的边界与差分探针（F9）
 *
 * 缺陷：路径归一化遇到结尾的 "/" 时，仍先为它在输出里占一个字节再等
 * 函数末尾剔除。于是归一化后恰好 out_size-1 字符的路径，只要多带一个
 * 尾部 "/"（或 "/."、"/.//"）就被误报 FR_ENAMETOOLONG：
 *     "/aaaa…"（共 4095 字符）→ 可记账
 *     "/aaaa…/"             → 失败（二者语义上是同一个键）
 * 后果：fakeroot 的 chown/chmod 记账对这类路径静默丢失（hook 层按
 * 返回值吞掉错误），属性读回与实际不符。
 *
 * 判据分两部分：
 *   1. 边界扫描：4090..4098 字符 × 有无尾斜杠，可容纳性必须与
 *      "归一化长度 <= 4095" 一致；
 *   2. 差分：30 万条随机路径（"/" "." ".." ".x" "x." 等片段拼接）
 *      与一个独立写的参考实现逐字节比对，且缓冲区放在 PROT_NONE
 *      保护页紧前方，越界即 SIGSEGV；同时 need-1 字节的缓冲区不得
 *      返回 >= 缓冲区的长度。
 *
 * 反向对照：用上游原版 fakeroot.c 编同一探针，边界扫描在
 * len=4096+尾斜杠 处 MISMATCH（rc=-4 而应成功）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include "fakeroot.c"   /* 直接包含 .c 才能测 static 函数 */

static unsigned long long rs = 0x9E3779B97F4A7C15ULL;
static unsigned rnd(void)
{
    rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17;
    return (unsigned)(rs >> 11);
}

static void *g_base[4];
static size_t g_len[4];
static int g_n;

static void grel(void)
{
    while (g_n > 0) {
        g_n--;
        munmap(g_base[g_n], g_len[g_n]);
    }
}

/* 恰好 n 字节、紧贴 PROT_NONE 页之前的缓冲区 */
static char *guard(size_t n)
{
    long ps = sysconf(_SC_PAGESIZE);
    size_t pages = (n + (size_t)ps - 1) / (size_t)ps + 1;
    char *b = mmap(NULL, (pages + 1) * (size_t)ps, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (b == MAP_FAILED) { perror("mmap"); exit(2); }
    mprotect(b + pages * (size_t)ps, (size_t)ps, PROT_NONE);
    g_base[g_n] = b;
    g_len[g_n] = (pages + 1) * (size_t)ps;
    g_n++;
    return b + pages * (size_t)ps - n;
}

/* 参考实现：按 '/' 切段，丢弃空段与 "."，绝对路径保留首部 '/'，无尾斜杠 */
static void ref(const char *in, char *out)
{
    int abs_ = (in[0] == '/');
    size_t o = 0;
    const char *p = in;

    if (abs_) out[o++] = '/';
    while (*p) {
        size_t l;
        while (*p == '/') p++;
        if (!*p) break;
        l = strcspn(p, "/");
        if (!(l == 1 && p[0] == '.')) {
            if (o > 0 && out[o - 1] != '/') out[o++] = '/';
            memcpy(out + o, p, l);
            o += l;
        }
        p += l;
    }
    out[o] = 0;
}

int main(void)
{
    static char in[8192];
    char out[4096];
    int bad = 0, L, tr;
    long it;
    const char *al[] = { "/", "/", "a", "b", ".", "..", ".x", "x." };

    /* 1. 边界扫描 */
    for (L = 4090; L <= 4098; L++) {
        for (tr = 0; tr <= 1; tr++) {
            size_t n = 0;
            int rc, should_fit = (L <= 4095);   /* 4096 字节缓冲最多 4095 字符 */
            in[n++] = '/';
            memset(in + n, 'a', (size_t)L - 1);
            n += (size_t)L - 1;
            if (tr) in[n++] = '/';
            in[n] = 0;
            rc = fr_normalize_path(in, out, sizeof out);
            if ((rc >= 0) != should_fit) {
                printf("MISMATCH 边界: 归一化长度=%d 尾斜杠=%d rc=%d（应%s）\n",
                       L, tr, rc, should_fit ? "成功" : "失败");
                bad++;
            }
        }
    }

    /* 2. 差分 + 保护页 */
    for (it = 0; it < 300000; it++) {
        char buf[256], want[256];
        size_t n = rnd() % 24, i, pos = 0, need;
        char *o, *e;
        int rc, re;

        buf[0] = 0;
        for (i = 0; i < n && pos < 100; i++)
            pos += (size_t)snprintf(buf + pos, sizeof buf - pos, "%s", al[rnd() % 8]);
        grel();
        ref(buf, want);
        need = strlen(want) + 1;

        o = guard(need + 2);
        rc = fr_normalize_path(buf, o, need + 2);
        if (rc < 0 || strcmp(o, want) != 0) {
            if (bad++ < 10)
                printf("MISMATCH 内容: in=[%s] want=[%s] got=[%s] rc=%d\n",
                       buf, want, rc < 0 ? "(err)" : o, rc);
        }

        e = guard(need);                       /* 恰好装下 */
        re = fr_normalize_path(buf, e, need);
        if (re < 0 || strcmp(e, want) != 0) {
            if (bad++ < 10)
                printf("MISMATCH 恰好装下: in=[%s] want=[%s] rc=%d\n", buf, want, re);
        }

        if (need > 1) {                        /* 少 1 字节：不得声称成功 */
            char *s = guard(need - 1);
            int rs2 = fr_normalize_path(buf, s, need - 1);
            if (rs2 >= 0 && (size_t)rs2 >= need - 1) {
                if (bad++ < 10) printf("OVERRUN in=[%s]\n", buf);
            }
        }
    }

    printf("bad=%d\n", bad);
    return bad != 0;
}
