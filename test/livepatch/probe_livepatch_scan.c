/*
 * probe_livepatch_scan.c —— livepatch 运行期扫描的判别性探针
 *
 * 直接把 livepatch.c 以 -DLP_TEST_HOOK 编入，调用它暴露的
 * bxroot_livepatch_scan_buffer_for_test()，对一段**合成机器码**跑真正的
 * 扫描逻辑（同一份 lp_scan_and_patch，不是复刻），断言：
 *   - glibc 里 set_robust_list(99)/rseq(293) 形态的内联 svc 被改成 mov x0,#0
 *   - 与扫描目标无关的号（如 exit_group 94）后面的 svc **不动**
 *   - mov x8 与 svc 之间夹了别的写 x8 时，窗口正确中断（不误改后面的 svc）
 *   - 超出窗口距离的 svc 不动
 *
 * 判据来自真实 glibc 反汇编：mov x8,#99 = 0xd2800c68，svc #0 = 0xd4000001，
 * 补丁值 mov x0,#0 = 0xd2800000。
 */
#include <stdio.h>
#include <stdint.h>

#define MOV_X0_0 0xd2800000u
#define SVC      0xd4000001u
static uint32_t movx8(int nr) { return 0xd2800008u | ((uint32_t)(nr & 0xffff) << 5); }
static const uint32_t NOP = 0xd503201fu;

int bxroot_livepatch_scan_buffer_for_test(uint32_t *buf, size_t words);

static int fail;
static void expect(const char *tag, uint32_t got, uint32_t want)
{
    if (got != want) { printf("FAIL %s = %#x 期望 %#x\n", tag, got, want); fail = 1; }
    else printf("OK %s = %#x\n", tag, got);
}

int main(void)
{
    /* 布局（每格一条指令）：
     * [0] mov x8,#99   [1] nop [2] nop [3] svc   ← 应改：99 站点，窗口内
     * [4] mov x8,#293  [5] svc                    ← 应改：rseq 站点
     * [6] mov x8,#94   [7] svc                    ← 不改：94 不在扫描名单
     * [8] mov x8,#99   [9] mov x8,#94 [10] svc    ← 不改：夹了写 x8，窗口断
     * [11] mov x8,#99  ...13 条 nop... svc         ← 不改：超出窗口(12)
     */
    uint32_t buf[64];
    size_t k;
    for (k = 0; k < 64; k++) buf[k] = NOP;
    buf[0] = movx8(99);  buf[3] = SVC;
    buf[4] = movx8(293); buf[5] = SVC;
    buf[6] = movx8(94);  buf[7] = SVC;
    buf[8] = movx8(99);  buf[9] = movx8(94); buf[10] = SVC;
    buf[11] = movx8(99); buf[11 + 13] = SVC;  /* 距离 13 > 窗口 12 */

    int n = bxroot_livepatch_scan_buffer_for_test(buf, 64);
    printf("扫描改写 %d 处\n", n);

    expect("99+3 站点", buf[3], MOV_X0_0);
    expect("293+1 站点", buf[5], MOV_X0_0);
    expect("94 号不动", buf[7], SVC);
    expect("夹写x8后不动", buf[10], SVC);
    expect("超窗口不动", buf[11 + 13], SVC);
    if (n != 2) { printf("FAIL 改写数 %d 期望 2\n", n); fail = 1; }
    else printf("OK 改写数 = 2\n");

    printf(fail ? "RESULT: FAIL\n" : "RESULT: PASS\n");
    return fail;
}
