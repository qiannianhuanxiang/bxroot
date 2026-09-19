#!/bin/sh
# =====================================================================
# 自动同步守护：开发树改动 → GitHub（轮询式）
# =====================================================================
#
# 为什么是轮询而不是 inotify
# --------------------------
# 本容器是 proroot 容器（外层还有一层闭源 proroot），inotify 在跨层绑定
# 与容器边界上行为不可靠（实测 inotify_add_watch 对部分 bind 挂载点
# 收不到事件）。轮询 120 秒一次、只看 mtime 与 size，代价可忽略。
#
# 为什么必须"内容变了才提交"
# --------------------------
# sync-to-github.sh 本身会回写权限位等元数据；无条件提交会每轮产生一个
# 空提交，把历史读成一堆噪声。这里用 `git status --porcelain` 判空。
#
# 用法
# ----
#   sh tools/autosync-daemon.sh            # 前台跑（调试用）
#   nohup sh tools/autosync-daemon.sh > log 2>&1 &   # 后台跑
#   BXROOT_AUTOSYNC_INTERVAL=60 sh ...      # 改轮询间隔（秒）
#
# 停止：只 kill 你自己记下的 PID，不要用 pkill/killall
#      （本项目发生过 3 次按名字杀进程的自杀事故）
# =====================================================================

set -u

SRC="${BXROOT_SRC:-/root/proroot-work/agents/rename-bxroot}"
DST="${BXROOT_GIT:-/tmp/bxroot-git}"
INTERVAL="${BXROOT_AUTOSYNC_INTERVAL:-120}"
LOG="${BXROOT_AUTOSYNC_LOG:-/tmp/bxroot-autosync.log}"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

log "自动同步守护启动"
log "  源     : $SRC"
log "  目标   : $DST"
log "  间隔   : ${INTERVAL}s"
log "  my pid : $$"

# 记录自己的 pid，便于人工停止（不要用 pkill）
echo $$ > /tmp/bxroot-autosync.pid

while :; do
    if [ ! -d "$DST/.git" ]; then
        log "⚠ 推送克隆消失，跳过本轮"
        sleep "$INTERVAL"; continue
    fi

    # 先看开发树有没有比上次同步更新的源码
    CHANGED=$(find "$SRC/docs" "$SRC/src" "$SRC/test" "$SRC/tools" \
                   -type f \( -name "*.c" -o -name "*.h" -o -name "*.md" \
                              -o -name "*.sh" -o -name "*.py" \) \
                   -newer "$DST/.git/index" 2>/dev/null | head -5)

    if [ -z "$CHANGED" ]; then
        sleep "$INTERVAL"; continue
    fi

    log "检测到改动，开始同步："
    echo "$CHANGED" | sed 's/^/    /' | tee -a "$LOG"

    # --dry-run 先看会不会带进二进制；有可疑则跳过，交人工判断
    OUT=$(sh "$DST/tools/sync-to-github.sh" --dry-run 2>&1)
    if echo "$OUT" | grep -q '^?? \|^ M '; then
        RES=$(sh "$DST/tools/sync-to-github.sh" 2>&1)
        if echo "$RES" | grep -q "RESULT: PASS"; then
            log "✅ 同步并推送成功: $(cd "$DST" && git log -1 --format='%h %s')"
        elif echo "$RES" | grep -q "RESULT: NOCHANGE"; then
            log "ℹ 无实质改动"
        else
            log "❌ 同步失败，尾部输出："
            echo "$RES" | tail -12 | sed 's/^/    /' | tee -a "$LOG"
        fi
    fi

    sleep "$INTERVAL"
done
