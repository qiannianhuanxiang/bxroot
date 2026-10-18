/*
 * 真机探针：launcher 的 ELF 程序头解析（2026-10-18 修复 L8）
 *
 * --- 缺陷 ---
 * `read_elf_interp()` 与 `explain_exec_failure()` 里的第二处内联解析
 * 都直接用文件里的 64 位值做**加法**边界判断：
 *
 *     off = phoff + k * phentsize;
 *     if (off + 56 > m) break;
 *     ...
 *     if (psz == 0 || psz > outsz || poff + psz > m) return 0;
 *
 * `phoff` / `poff` / `psz` 全部来自待执行的二进制文件，攻击者（或只是
 * 一个损坏的 ELF）可以让它们接近 ULONG_MAX。加法回绕后判据变成
 * "在范围内"，接着就是
 *
 *     memcpy(&type, buf + off, 4);      // 栈缓冲区外任意地址读
 *     memcpy(out,  buf + poff, psz);    // 同上，且长度也不可信
 *
 * 后果：SIGSEGV（launcher 崩溃，用户只看到"容器起不来"），
 * 或者读到相邻栈内容并当作**解释器路径**继续 stat —— 一条从"损坏的
 * 输入文件"通往"未定义行为"的路径，而这条路径的全部目的只是
 * **打印一条错误提示**。
 *
 * --- 本探针 ---
 * 直接把 launcher.c 编进探针（改掉它的 main），构造畸形 ELF：
 *   ① phoff = 2^64-48、phnum=3、phentsize=56
 *      → k=1 时 off 回绕到 8，k=2 时回绕到 **64**（正好是真实表项）
 *   ② poff  = ULONG_MAX-16（psz 正常）→ poff+psz 回绕成小值
 *   ③ psz   = ULONG_MAX-4（已被 psz>outsz 拦住，防回归用）
 * 检查 `read_elf_interp()` 必须返回 0（= 没有可信的 INTERP），
 * 而不是 1（= 把越界/回绕读到的内容当解释器）。
 *
 * 判别力（已实测的对照实验）：
 *   用修复前的 launcher.c 编同一探针：
 *     ① ret=1 —— 回绕后把 buf+64 处**真实表项**当成了第 2 个表项，
 *        于是"程序头表在 2^64-48"这种畸形输入被读成了合法输入；
 *     ② ret=1 —— 从 buf+ULONG_MAX-16 读 64 字节当解释器路径，
 *        内容是栈上的垃圾，随后会被拿去 stat。
 *   修复后三者全部返回 0。
 *
 * ★ ①为什么不用"看起来更狠"的 ULONG_MAX-8 ★
 *   那种写法只是越界读，读到的字节碰巧不是 3 就"通过"了 —— 探针
 *   测的是运气而不是逻辑。上面对照里 ① 一开始正是这么写的，修复前
 *   也返回 0，等于**没测出修复**。改成"回绕到真实表项"之后，
 *   修复前的错误行为（把畸形输入读成合法）才稳定复现。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <stdint.h>

/*
 * 把 launcher 整个编进来，只为了拿到 static 的 read_elf_interp()。
 * 它的 main 改名后不参与链接；bx_host_world_* 是 weak 符号，
 * 未定义时不影响。
 */
#define main bx_launcher_main_disabled
#include "../src/launcher/launcher.c"
#undef main

static int fails, checks;

static void ck(const char *what, int cond)
{
    checks++;
    if (!cond) {
        fails++;
        printf("  [FAIL] %s\n", what);
    } else {
        printf("  [ok]   %s\n", what);
    }
}

/* 写一个 64 位 LE ELF 头 + 一个程序头的骨架 */
static void put64(unsigned char *p, unsigned long v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (unsigned char)((v >> (8 * i)) & 0xff);
}

static void put32(unsigned char *p, unsigned v)
{
    for (int i = 0; i < 4; i++)
        p[i] = (unsigned char)((v >> (8 * i)) & 0xff);
}

/*
 * 造文件：magic/class 合法，程序头表在 off=64 处，1 个表项，
 * 表项 type=PT_INTERP，poff/psz 由调用方给。
 */
static int make_elf(const char *path, unsigned long phoff, unsigned phnum,
                    unsigned long poff, unsigned long psz)
{
    unsigned char buf[1024];
    FILE *f;

    memset(buf, 0, sizeof buf);
    memcpy(buf, "\177ELF", 4);
    buf[4] = 2;                     /* ELFCLASS64 */
    put64(buf + 32, phoff);         /* e_phoff */
    buf[54] = 56; buf[55] = 0;      /* e_phentsize */
    put32(buf + 56, phnum);         /* e_phnum */

    /* 程序头表项（结构固定 56 字节） */
    put32(buf + 64 + 0, 3);         /* p_type = PT_INTERP */
    put64(buf + 64 + 8, poff);      /* p_offset */
    put64(buf + 64 + 32, psz);      /* p_filesz */

    f = fopen(path, "wb");
    if (f == NULL)
        return -1;
    fwrite(buf, 1, sizeof buf, f);
    fclose(f);
    return 0;
}

int main(void)
{
    char out[PATH_MAX];
    const char *p1 = "/tmp/probe_elf_phoff.bin";
    const char *p2 = "/tmp/probe_elf_poff.bin";
    const char *p3 = "/tmp/probe_elf_psz.bin";
    const char *ok = "/tmp/probe_elf_good.bin";
    int r1, r2, r3, r4;

    printf("=== launcher ELF 程序头解析 探针 ===\n\n");

    /* ---------- 基线：一个完全正常的 INTERP ---------- */
    if (make_elf(ok, 64, 1, 512, 16) != 0) {
        printf("  [SKIP] 无法创建测试文件\n");
        return 0;
    }
    {
        /* 在 512 处放一个以 NUL 结尾的假解释器路径 */
        FILE *f = fopen(ok, "r+b");
        if (f != NULL) {
            fseek(f, 512, SEEK_SET);
            fwrite("/lib/ld-x\0", 1, 11, f);
            fclose(f);
        }
    }
    r4 = read_elf_interp(ok, out, sizeof out);
    printf("  [info] 正常 INTERP: ret=%d interp=\"%s\"\n", r4, r4 == 1 ? out : "");
    ck("正常 INTERP 仍返回 1（不能因为加固而误判）", r4 == 1);
    ck("正常 INTERP 内容正确", r4 == 1 && strcmp(out, "/lib/ld-x") == 0);

    /* ---------- ① phoff 回绕 ---------- */
    make_elf(p1, ULONG_MAX - 47, 3, 512, 16);
    r1 = read_elf_interp(p1, out, sizeof out);
    printf("  [info] phoff=2^64-48 (回绕到 64): ret=%d\n", r1);
    ck("phoff 回绕不被当成合法表项（修复前误返回 1）", r1 == 0);

    /* ---------- ② poff 回绕 ---------- */
    make_elf(p2, 64, 1, ULONG_MAX - 16, 64);
    r2 = read_elf_interp(p2, out, sizeof out);
    printf("  [info] poff=ULONG_MAX-16 : ret=%d\n", r2);
    ck("poff+psz 回绕不把栈垃圾当解释器（修复前误返回 1）", r2 == 0);

    /* ---------- ③ psz 回绕 ---------- */
    make_elf(p3, 64, 1, 128, ULONG_MAX - 4);
    r3 = read_elf_interp(p3, out, sizeof out);
    printf("  [info] psz=ULONG_MAX-4   : ret=%d\n", r3);
    ck("psz 巨大时返回 0（防回归：本就由 psz>outsz 拦住）", r3 == 0);

    unlink(p1); unlink(p2); unlink(p3); unlink(ok);

    printf("\n----------------------------------------\n");
    printf("checks: %d  failed: %d\n", checks, fails);
    printf("RESULT: %s\n", fails == 0 ? "PASS" : "FAIL");
    return fails == 0 ? 0 : 1;
}
