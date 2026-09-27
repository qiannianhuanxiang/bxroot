/*
 * probe_livepatch_audit.c —— 对抗性审计探针
 *
 * 把 livepatch.c 以 -DLP_TEST_HOOK 编入，用它暴露的**真实**扫描函数
 * bxroot_livepatch_scan_buffer_for_test()，直接跑在从磁盘读入的**真实
 * libc.so.6 可执行段字节**上（不是合成码），报告扫描到底改写了哪些偏移。
 *
 * 这样审计的是生产代码本身：同一份 lp_scan_and_patch、同一套窗口/中断
 * 判据。shell 侧再用 nm/objdump 交叉核对每个被改地址所属的函数与系统
 * 调用号，断言：
 *   - 命中数与预期一致（每个 libc 恰好 3 处：99 / 293 / _Fork-99）
 *   - 每个被中和的 svc 之前近距离确是 mov x8,#99 或 mov x8,#293
 *   - 没有落在与 99/293 无关的函数里
 *
 * 用法：
 *   probe_livepatch_audit <libc路径> <exec段文件偏移(hex)> <exec段vaddr(hex)> <exec段字节数(hex)>
 * 输出（stdout，每行一个命中）：
 *   HIT <vaddr_hex> <old_insn_hex>
 * 末行：
 *   COUNT <n>
 *
 * 另外对窗口中断判据做形态断言（movk / 条件分支 / BR-RET 都应中断），
 * 用 bxroot_livepatch_is_scan_barrier_for_test() 直接问生产函数。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

int bxroot_livepatch_scan_buffer_for_test(uint32_t *buf, size_t words);
int bxroot_livepatch_is_scan_barrier_for_test(uint32_t ins);

#define SVC      0xd4000001u
#define MOV_X0_0 0xd2800000u

static int barrier_checks(void)
{
    /* 期望能中断的形态（真实 aarch64 编码样本）。 */
    struct { const char *tag; uint32_t ins; int want; } cases[] = {
        { "movz x8,#99 (hw0)",        0xd2800c68u, 1 },
        { "movz x8,#1,lsl#16 (hw1)",  0xd2a00028u, 1 },
        { "movk x8,#1,lsl#16",        0xf2a00028u, 1 },
        { "movk x8,#0xd428,lsl#16",   0xf2ba8508u, 1 },
        { "B (0x14000000)",           0x14000000u, 1 },
        { "BL (0x94000000)",          0x94000000u, 1 },
        { "B.ls (cond)",              0x54ffeac9u, 1 },
        { "CBZ w0",                   0x34000060u, 1 },
        { "CBNZ w0",                  0x35000060u, 1 },
        { "TBZ",                      0x36080060u, 1 },
        { "TBNZ",                     0x37080060u, 1 },
        { "RET",                      0xd65f03c0u, 1 },
        { "BR x0",                    0xd61f0000u, 1 },
        { "BLR x0",                   0xd63f0000u, 1 },
        /* 不该中断的（普通指令，扫描应继续找 svc）。 */
        { "ldr x0,[x0,#..]",          0xf95f6400u, 0 },
        { "add x0,x0,#0xe0",          0x91038000u, 0 },
        { "mov x1,#24",              0xd2800301u, 0 },
        { "svc #0 本身（不算barrier）", SVC,        0 },
        { "stp x0,x0,[x6,#216]",      0xa90d80c0u, 0 },
    };
    int n = (int)(sizeof(cases)/sizeof(cases[0]));
    int bad = 0, i;
    for (i = 0; i < n; i++) {
        int got = bxroot_livepatch_is_scan_barrier_for_test(cases[i].ins);
        int ok = (got != 0) == (cases[i].want != 0);
        printf("%s barrier[%s] ins=%#010x got=%d want=%d\n",
               ok ? "OK" : "FAIL", cases[i].tag, cases[i].ins, got, cases[i].want);
        if (!ok) bad = 1;
    }
    /* 关键回归：mov x8,#99; movk x8,#1,lsl#16; svc —— 加固后必须不改写。 */
    {
        uint32_t buf[8];
        size_t k; for (k = 0; k < 8; k++) buf[k] = 0xd503201fu; /* nop */
        buf[0] = 0xd2800c68u;   /* mov x8,#99 */
        buf[1] = 0xf2a00028u;   /* movk x8,#1,lsl#16 */
        buf[2] = SVC;
        int chg = bxroot_livepatch_scan_buffer_for_test(buf, 8);
        int ok = (chg == 0 && buf[2] == SVC);
        printf("%s movk误配防护: 改写=%d svc=%#010x（期望 改写=0 svc未动）\n",
               ok ? "OK" : "FAIL", chg, buf[2]);
        if (!ok) bad = 1;
    }
    return bad;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--barrier") == 0) {
        int bad = barrier_checks();
        printf(bad ? "RESULT: FAIL\n" : "RESULT: PASS\n");
        return bad;
    }
    if (argc != 5) {
        fprintf(stderr, "用法: %s <libc> <off_hex> <vaddr_hex> <size_hex>\n"
                        "   或: %s --barrier\n", argv[0], argv[0]);
        return 2;
    }
    const char *path = argv[1];
    unsigned long off  = strtoul(argv[2], NULL, 16);
    unsigned long vaddr = strtoul(argv[3], NULL, 16);
    unsigned long size = strtoul(argv[4], NULL, 16);

    FILE *f = fopen(path, "rb");
    if (!f) { perror("fopen"); return 2; }
    if (fseek(f, (long)off, SEEK_SET) != 0) { perror("fseek"); fclose(f); return 2; }

    size_t words = size / 4;
    uint32_t *buf = malloc(words * 4);
    if (!buf) { fprintf(stderr, "OOM\n"); fclose(f); return 2; }
    if (fread(buf, 4, words, f) != words) { fprintf(stderr, "短读\n"); free(buf); fclose(f); return 2; }
    fclose(f);

    /* 保留原始副本以报告被改位置的“原指令”。 */
    uint32_t *orig = malloc(words * 4);
    memcpy(orig, buf, words * 4);

    int n = bxroot_livepatch_scan_buffer_for_test(buf, words);

    size_t i;
    int reported = 0;
    for (i = 0; i < words; i++) {
        if (buf[i] != orig[i]) {
            /* 只应从 svc -> mov x0,#0。断言这一点。 */
            printf("HIT %#lx %#010x->%#010x\n",
                   vaddr + i * 4, orig[i], buf[i]);
            if (!(orig[i] == SVC && buf[i] == MOV_X0_0)) {
                printf("BADCHANGE %#lx 非 svc->mov x0,#0\n", vaddr + i * 4);
            }
            reported++;
        }
    }
    printf("COUNT %d\n", n);
    if (reported != n)
        printf("MISMATCH 报告改写 %d != 返回 %d\n", reported, n);

    free(buf); free(orig);
    return 0;
}
