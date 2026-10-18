#define _GNU_SOURCE
#include <stdio.h>
#include "proc.h"

/*
 * 真机探针：新 fork 出的子进程复用 REAPED 的 pid 时必须复活（P5 修复）
 *
 * 缺陷：账本的"刷新"分支对所有 tag 一律保留 life=PX_REAPED。于是
 * pid 回绕后（Android pid_max 常 32768），自己新 fork 的子进程恰好
 * 拿到一个已回收的 pid → 该条目永远 REAPED → kill 被拒 EPERM、
 * kill-on-exit 跳过 → 子进程不可杀 + 泄漏。
 *
 * 修复：tag 为 PX_TAG_FORK / PX_TAG_SPAWN 时置回 PX_LIVE。
 */
int px_ledger_add(px_ledger *l, pid_t pid, pid_t ppid, uint32_t tag);
int px_ledger_reap(px_ledger *l, pid_t pid);
int px_ledger_get(const px_ledger *l, pid_t pid, px_entry_kind kind, px_procinfo *out);

static int fails, checks;
static void ck(const char *w, int got, int want)
{
    checks++;
    if (got != want) { fails++; printf("  [FAIL] %-50s got=%d want=%d\n", w, got, want); }
    else printf("  [ok]   %-50s = %d\n", w, got);
}

/* 把 add 成某个 tag 后读回的 life 取出来 */
static int life_after(px_ledger *l, pid_t pid, uint32_t tag)
{
    px_procinfo info;
    if (px_ledger_get(l, pid, PX_ENTRY_PID, &info) != PX_OK)
        return -1;
    return (int)info.life;
}

int main(void)
{
    px_ledger *l = px_ledger_create(16, NULL);
    const pid_t P = 4242;

    printf("=== REAPED pid 复用后应复活 探针 ===\n\n");
    if (l == NULL) { printf("  [SKIP] 账本创建失败\n"); return 0; }

    /* 1) 登记并回收 */
    px_ledger_add(l, P, 0, PX_TAG_SELF);
    px_ledger_reap(l, P);
    ck("回收后 life == REAPED", life_after(l, P, 0), (int)PX_REAPED);

    /* 2) 普通 add（同 tag）**不得**复活 —— 保留保护 */
    px_ledger_add(l, P, 0, PX_TAG_SELF);
    ck("普通 add 不复活（仍是 REAPED）", life_after(l, P, 0), (int)PX_REAPED);

    /* 3) 关键：新 fork 出来的子进程复用该 pid → 必须复活 */
    px_ledger_add(l, P, 0, PX_TAG_FORK);
    ck("PX_TAG_FORK 复用后复活为 LIVE", life_after(l, P, 0), (int)PX_LIVE);

    /* 4) spawn 同理 */
    px_ledger_reap(l, P);
    px_ledger_add(l, P, 0, PX_TAG_SPAWN);
    ck("PX_TAG_SPAWN 复用后复活为 LIVE", life_after(l, P, 0), (int)PX_LIVE);

    px_ledger_destroy(l);
    printf("\n----------------------------------------\n");
    printf("checks: %d  failed: %d\n", checks, fails);
    printf("RESULT: %s\n", fails == 0 ? "PASS" : "FAIL");
    return fails == 0 ? 0 : 1;
}
