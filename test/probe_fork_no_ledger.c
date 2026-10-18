#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include "proc.h"

/*
 * 真机探针：账本不可用时 fork 不得被中止（2026-10-18 修复 P2）
 *
 * 缺陷：px_fork_should_abort() 只看 `reg_rc != PX_OK`，无法区分
 * 「账本不存在」(PX_EINVAL) 与「登记失败」。于是账本创建失败（OOM）时，
 * **每一次** fork 都被判成失败：先白 clone 一个子进程、再 SIGKILL、
 * 最后返回 -1/EAGAIN。用户看到「fork 永久 EAGAIN」，而日志说是优雅降级
 * —— 最坏组合：既不能 fork，kill 保护又已 fail-open。
 *
 * 修复：把「账本为 NULL」与「真登记失败」区分开。没有账本就当没有保护，
 * 正常 fork；真正表满（PX_EFULL）仍然中止。
 *
 * 判别力：修复前第 2 项断言 FAIL（返回 1 = 中止）。
 */

/* 被测：px_fork_should_abort（proc.c） */
int px_fork_should_abort(int reg_rc);
int px_ledger_add(px_ledger *l, pid_t pid, pid_t ppid, uint32_t tag);

static int fails, checks;
static void ck(const char *w, int got, int want)
{
    checks++;
    if (got != want) { fails++; printf("  [FAIL] %-52s got=%d want=%d\n", w, got, want); }
    else printf("  [ok]   %-52s = %d\n", w, got);
}

int main(void)
{
    px_ledger *l;
    int rc_null;

    printf("=== 账本缺失时 fork 不应中止 探针 ===\n\n");

    /* 1) 账本为 NULL 时 add 返回的错误码 */
    rc_null = px_ledger_add(NULL, 1234, 0, 0);
    printf("  px_ledger_add(NULL,...) = %d\n", rc_null);

    /* 2) 关键：账本缺失**不得**导致 fork 中止 */
    ck("账本为 NULL 的 reg_rc → 不中止 fork",
       px_fork_should_abort(rc_null), 0);

    /* 3) 对照：真正的表满仍然必须中止 */
    ck("PX_EFULL（表满）→ 仍然中止", px_fork_should_abort(PX_EFULL), 1);

    /* 4) 对照：其它真实错误仍中止 */
    ck("PX_ENOMEM（OOM）→ 仍然中止", px_fork_should_abort(PX_ENOMEM), 1);

    /* 5) 成功码不中止 */
    ck("PX_OK → 不中止", px_fork_should_abort(PX_OK), 0);

    /* 6) 正常账本：add 成功 → 不中止 */
    l = px_ledger_create(16, NULL);
    if (l != NULL) {
        ck("正常账本 add 成功 → 不中止",
           px_fork_should_abort(px_ledger_add(l, 4321, 0, 0)), 0);
        px_ledger_destroy(l);
    }

    printf("\n----------------------------------------\n");
    printf("checks: %d  failed: %d\n", checks, fails);
    printf("RESULT: %s\n", fails == 0 ? "PASS" : "FAIL");
    return fails == 0 ? 0 : 1;
}
