/*
 * 真机探针：livepatch 版本表打补丁前的**形态校验**（2026-10-18 修复）
 *
 * --- 缺陷 ---
 * patch_one() 原来只校验落点那一个字是不是 `svc #0`：
 *
 *     if (*p != SVC_INSN) return 0;
 *     *p = s->patch;
 *
 * 而 libc 的可执行段里 `svc` **极其密集**（每个系统调用封装一条）。
 * 版本表里的偏移是版本精确绑定的（文件自己记过"表按 2.39-8.9 登记、
 * 真机是 8.5"的错位），一旦漂移，落点往往**仍然是某条 svc** ——
 * 于是会把这**无关**的系统调用改写成站点指定的指令（147/149 是
 * `mov x0,#0`，即"恒成功"）。这是 fail-open 的安全失效，且完全静默。
 *
 * --- 修复 ---
 * 往前找 `mov x8, #imm` 取出系统调用号，与站点声明的 s->nr 比对，
 * 不一致就**不打**（并计数 + 打印告警）。
 *
 * --- 本探针 ---
 * 直接构造几段“小型指令序列”，调用内部判据，验证：
 *   1. 正确的 `mov x8,#99; svc` → 号识别为 99，会打
 *   2. 号为 99 但站点声明 293（模拟偏移漂移）→ **拒绝**
 *   3. 窗口内遇到障碍（B 跳转）→ 号不可知 → 拒绝
 *   4. `movk x8`（多段拼号）→ 判为形态不明 → 拒绝
 *   5. 落点不是 svc → 不动
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>

#include "livepatch.c"

static int fails, checks;

static void ck(const char *what, int got, int want)
{
    checks++;
    if (got != want) {
        fails++;
        printf("  [FAIL] %-52s got=%d want=%d\n", what, got, want);
    } else {
        printf("  [ok]   %-52s = %d\n", what, got);
    }
}

/* 构造 movz x8, #imm */
static uint32_t mk_movz_x8(unsigned imm)
{
    return 0xd2800008u | ((imm & 0xffffu) << 5);
}

int main(void)
{
    printf("=== livepatch 站点形态校验 探针 ===\n\n");

    /* 1) 正常形态：mov x8,#99; svc  → 号 = 99 */
    {
        uint32_t code[2];
        code[0] = mk_movz_x8(99);
        code[1] = SVC_INSN;
        ck("mov x8,#99; svc 识别为 99",
           (int)lp_find_syscall_nr_before(&code[1]), 99);
    }

    /* 2) 号是 99，但站点声明 293 → patch_one 必须拒绝 */
    {
        uint32_t code[2];
        lp_site s;
        code[0] = mk_movz_x8(99);
        code[1] = SVC_INSN;
        s.off = 0;
        s.patch = MOV_X0_0;
        s.what = "fake";
        s.nr = 293;
        g_form_mismatch = 0;
        ck("形态不符（站点 293 / 实际 99）→ 不补",
           patch_one(&code[1], &s), 0);
        ck("  站点未被改动", code[1] == SVC_INSN ? 1 : 0, 1);
        ck("  已计入 g_form_mismatch", g_form_mismatch, 1);
    }

    /* 3) 号一致 → 正常打补丁 */
    {
        uint32_t code[2];
        lp_site s;
        code[0] = mk_movz_x8(99);
        code[1] = SVC_INSN;
        s.off = 0;
        s.patch = MOV_X0_0;
        s.what = "fake";
        s.nr = 99;
        ck("形态一致（99）→ 打补丁", patch_one(&code[1], &s), 1);
        ck("  站点已改为 MOV_X0_0", code[1] == MOV_X0_0 ? 1 : 0, 1);
    }

    /* 4) 紧邻 svc 之前就是障碍（B 跳转）→ 号不可知 → 拒绝 */
    {
        uint32_t code[2];
        lp_site s;
        code[0] = 0x14000000u;      /* b .+0 -- 紧邻 svc 的障碍 */
        code[1] = SVC_INSN;
        s.off = 0;
        s.patch = MOV_X0_0;
        s.what = "fake";
        s.nr = 99;
        ck("紧邻障碍 → 号不可知(-1)",
           (int)lp_find_syscall_nr_before(&code[1]), -1);
        ck("  因此拒绝打补丁", patch_one(&code[1], &s), 0);
    }

    /* 4b) 障碍在更远处：近端已找到 mov x8 → 正常识别（不算障碍） */
    {
        uint32_t code[3];
        code[0] = 0x14000000u;      /* b .+0 -- 远处的障碍 */
        code[1] = mk_movz_x8(99);
        code[2] = SVC_INSN;
        ck("障碍在 mov 之外 → 仍识别为 99",
           (int)lp_find_syscall_nr_before(&code[2]), 99);
    }

    /* 5) movk x8（多段拼号）→ 形态不明 → 拒绝 */
    {
        uint32_t code[2];
        lp_site s;
        code[0] = 0xf2800008u;      /* movk x8, #0 */
        code[1] = SVC_INSN;
        s.off = 0;
        s.patch = MOV_X0_0;
        s.what = "fake";
        s.nr = 0;
        ck("movk x8 → 形态不明(-1)",
           (int)lp_find_syscall_nr_before(&code[1]), -1);
        ck("  因此拒绝打补丁", patch_one(&code[1], &s), 0);
    }

    /* 6) 落点不是 svc → 原样不动（既有行为） */
    {
        uint32_t code[2];
        lp_site s;
        code[0] = mk_movz_x8(99);
        code[1] = 0xd503201fu;      /* nop */
        s.off = 0;
        s.patch = MOV_X0_0;
        s.what = "fake";
        s.nr = 99;
        ck("落点非 svc → 不动", patch_one(&code[1], &s), 0);
    }

    printf("\n----------------------------------------\n");
    printf("checks: %d  failed: %d\n", checks, fails);
    printf("RESULT: %s\n", fails == 0 ? "PASS" : "FAIL");
    return fails == 0 ? 0 : 1;
}
