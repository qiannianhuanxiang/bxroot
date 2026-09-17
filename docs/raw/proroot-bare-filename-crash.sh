#!/bin/sh
# =====================================================================
# proroot「裸相对文件名 + 原地改写」堆溢出缺陷 —— 可复现脚本
# =====================================================================
#
# 配套报告：docs/proroot容器裸文件名堆溢出缺陷.md
#
# 用法：sh proroot-bare-filename-crash.sh
# 退出码：0 = 缺陷复现成功（说明确实有这个 bug）
#         1 = 没复现出来（可能环境不同，或已修）
#
# ★ 本脚本只在自己建的私有目录里操作，不碰任何既有文件 ★
# =====================================================================

set -u

WORK=$(mktemp -d "${TMPDIR:-/tmp}/proroot-bare-XXXXXX") || exit 2
trap 'rm -rf "$WORK"' EXIT INT TERM

cd "$WORK" || exit 2

# 造一个最小的可执行文件（不需要 ELF，纯文本也复现 —— 这正是缺陷特征）
printf 'int main(void){return 0;}\n' > hello.c
if command -v gcc >/dev/null 2>&1; then
    gcc -O0 -o bin hello.c 2>/dev/null || printf 'plain text\n' > bin
else
    printf 'plain text\n' > bin
fi

run_case() {
    # $1=标签  $2=传给 objcopy 的路径
    rm -f tgt
    cp bin tgt
    objcopy "$2" >/dev/null 2>"$WORK/err.txt"
    rc=$?
    if [ "$rc" -eq 0 ]; then
        printf '  ✅ %-24s rc=0\n' "$1"
    else
        printf '  ❌ %-24s rc=%s   %s\n' "$1" "$rc" "$(head -1 "$WORK/err.txt")"
    fi
    return "$rc"
}

echo "工作目录：$WORK"
echo
echo "== 唯一自变量：路径形态 =="
run_case "裸文件名   objcopy tgt"    "tgt";      BARE=$?
run_case "./ 前缀    objcopy ./tgt"  "./tgt";    DOT=$?
run_case "绝对路径   objcopy \$PWD/tgt" "$WORK/tgt"; ABS=$?

echo
echo "== 第二个自变量：是否原地改写 =="
rm -f tgt; cp bin tgt
objcopy tgt out.bin >/dev/null 2>&1
printf '  %-24s rc=%s %s\n' "带 -o 输出到别处" "$?" \
    "$([ $? -eq 0 ] && echo '（正常）')"

echo
echo "== 结论 =="
if [ "$BARE" -ne 0 ] && [ "$DOT" -eq 0 ] && [ "$ABS" -eq 0 ]; then
    echo "  ✅ 缺陷复现：裸文件名崩溃，带目录分量正常"
    echo "     → 这是 proroot 的路径翻译缺陷，不是被调用工具的缺陷"
    exit 0
elif [ "$BARE" -eq 0 ]; then
    echo "  ℹ️  裸文件名未崩溃 —— 本环境无此缺陷（或已修复）"
    echo "     注意：只有「在 proroot 容器内」运行才会触发"
    exit 1
else
    echo "  ⚠️  结果不符合已知模式，请人工查看上方输出"
    exit 1
fi
