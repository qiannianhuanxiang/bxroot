#!/bin/bash
# probe_seccomp_bpf.sh — 提取并归纳本进程继承到的 seccomp 过滤器规则
#
# 用法:
#   test/probe_seccomp_bpf.sh            # 完整流程（编译 + 全量枚举 0..560 + 静态提取 + 报告）
#   test/probe_seccomp_bpf.sh quick      # 只跑关键号（约 2 秒）
#   test/probe_seccomp_bpf.sh static     # 只做静态提取（不跑探针）
#
# 产出（默认落在 mktemp -d 出来的目录，脚本结束前打印路径）:
#   probe_raw.txt     探针原始输出
#   allowed.txt       放行集合
#   trapped.txt       被 SECCOMP_RET_TRAP 拦截的号
#   errno_rule.txt    返回固定错误码的号
#   report.txt        归纳报告（含 syscall 名字）
#
# 依赖: gcc（本容器有间歇性 ICE，编译重试 10 次）、python3、binutils

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
MODE="${1:-full}"

WORK="$(mktemp -d)"
trap 'echo "[probe_seccomp_bpf] 工作目录保留在: $WORK"' EXIT

# ---------------------------------------------------------------- 工具函数

# 编译（最多 10 次；用产物文件是否存在判定成功，不用 grep "error:"）
build() {
    local src="$1" out="$2"; shift 2
    local i
    for i in $(seq 1 10); do
        gcc -O0 -o "$out" "$src" "$@" 2>"$WORK/gcc.log"
        if [ -f "$out" ]; then
            echo "[build] $out 编译成功（第 $i 次尝试）"
            return 0
        fi
        if grep -q 'internal compiler error' "$WORK/gcc.log" 2>/dev/null; then
            echo "[build] 第 $i 次尝试命中 gcc ICE，重试…"
        else
            echo "[build] 第 $i 次尝试失败（非 ICE）："
            sed -n '1,10p' "$WORK/gcc.log"
        fi
    done
    echo "[build] 放弃：$out 编译 10 次仍未产出产物" >&2
    return 1
}

# ---------------------------------------------------------------- 静态提取
# 从官方库中提取"内联在代码里的" seccomp 相关常量与静态表。
# 这些是 proroot 自己会安装/依赖的过滤器，与 Android 沙箱继承下来的那一层是两回事。
static_extract() {
    local out="$WORK/static.txt"
    : > "$out"

    local libs=""
    for f in \
        /root/proroot-work/backup/libproroot-linker.so \
        /root/proroot-work/backup/libproroot-runtime.so \
        /root/proroot-work/backup/libproroot-bridge.so \
        /root/proroot-work/backup/libproroot-stub-loader.so \
        /root/proroot-work/backup/libproroot.so ; do
        [ -f "$f" ] && libs="$libs $f"
    done
    if [ -z "$libs" ]; then
        echo "（未找到官方库副本，跳过静态提取）" >> "$out"
        return 0
    fi

    python3 - "$out" $libs <<'PY'
import sys, re, struct

out_path = sys.argv[1]
libs = sys.argv[2:]
f = open(out_path, 'a')

def w(s=''):
    f.write(s + "\n")

# BPF 返回值常量（小端字节序）
BPF_CONSTS = {
    'SECCOMP_RET_KILL_PROCESS 0x80000000': bytes.fromhex('00000080'),
    'SECCOMP_RET_TRAP         0x00030000': bytes.fromhex('00000300'),
    'SECCOMP_RET_ERRNO        0x00050000': bytes.fromhex('00000500'),
    'SECCOMP_RET_ALLOW        0x7fff0000': bytes.fromhex('0000ff7f'),
    'SECCOMP_RET_LOG          0x7ffc0000': bytes.fromhex('0000fc7f'),
    'SECCOMP_RET_KILL_THREAD  0x00000000': b'\x00\x00\x00\x00',
}

def movz(reg, imm, hw=0, sf=1):
    base = 0xD2800000 if sf else 0x52800000
    return struct.pack('<I', base | (hw << 21) | (imm << 5) | reg)

w("=== A. BPF 返回值常量在库文件中的出现位置（文件偏移） ===")
for lib in libs:
    d = open(lib, 'rb').read()
    w("-- %s (%d bytes)" % (lib, len(d)))
    for name, pat in BPF_CONSTS.items():
        if name.startswith('SECCOMP_RET_KILL_THREAD'):
            continue  # 全零，无意义
        offs = [m.start() for m in re.finditer(re.escape(pat), d)]
        if offs:
            w("   %-36s %d 处: %s" % (name, len(offs), ' '.join(hex(o) for o in offs[:12])))

w("")
w("=== B. 直接发起的 prctl(167) / seccomp(277) 调用点 ===")
for lib in libs:
    d = open(lib, 'rb').read()
    hits = []
    for reg, tag in ((8, 'mov x8'), (8, 'mov w8')):
        for sf in (1, 0):
            pat = movz(reg, 167, 0, sf)
            for m in re.finditer(re.escape(pat), d):
                hits.append("prctl   @0x%x (%s sf=%d)" % (m.start(), tag, sf))
    for sf in (1, 0):
        pat = movz(8, 277, 0, sf)
        for m in re.finditer(re.escape(pat), d):
            hits.append("seccomp @0x%x (mov %s sf=%d)" % (m.start(), 'x8' if sf else 'w8', sf))
    if hits:
        w("-- %s" % lib)
        for h in sorted(set(hits)):
            w("   " + h)

w("")
w("=== C. libproroot-stub-loader.so 的静态 trap_nrs 表 ===")
stub = '/root/proroot-work/backup/libproroot-stub-loader.backup.so'
alt  = '/root/proroot-work/backup/libproroot-stub-loader.so'
import os
src = stub if os.path.exists(stub) else alt
if os.path.exists(src):
    d = open(src, 'rb').read()
    # 从符号表拿地址（.rodata 的 vaddr == file offset 在这个库里成立）
    import subprocess
    syms = subprocess.run(['readelf', '-sW', src], capture_output=True, text=True).stdout
    for line in syms.splitlines():
        m = re.search(r'^\s*\d+:\s+([0-9a-f]{16})\s+(\d+)\s+OBJECT\s+\w+\s+\w+\s+\d+\s+(trap_nrs\.\d+)', line)
        if not m:
            continue
        va, size, name = int(m.group(1), 16), int(m.group(2)), m.group(3)
        vals = struct.unpack_from('<%dI' % (size // 4), d, va)
        w("-- %s (%d 项, .rodata offset 0x%x)" % (name, len(vals), va))
        w("   " + ' '.join(str(v) for v in vals))
else:
    w("（未找到 libproroot-stub-loader.so 副本）")

w("")
w("=== D. 各库是否含 seccomp 相关符号 ===")
for lib in libs:
    import subprocess
    syms = subprocess.run(['readelf', '-sW', lib], capture_output=True, text=True).stdout
    names = sorted(set(re.findall(r'\b(\w*seccomp\w*)\b', syms)))
    w("-- %-52s %s" % (os.path.basename(lib), ', '.join(names) if names else '(无)'))
f.close()
PY
    cat "$out"
}

# ---------------------------------------------------------------- 探针
run_probe() {
    local bin="$WORK/probe_seccomp_bpf"
    build "$HERE/probe_seccomp_bpf.c" "$bin" || return 1

    local raw="$WORK/probe_all.txt"
    if [ "$MODE" = quick ]; then
        local nrs="17 18 34 35 36 37 38 39 40 42 48 49 51 53 56 58 63 64 78 79 88 89 93 94 99 100 104 105 106 112 116 134 142 143 144 145 146 149 151 152 159 161 162 167 170 171 178 180 215 221 222 224 225 234 245 265 276 277 281 291 293 412 425 426 427 437 439 444 446 452 462 500 9999"
        : > "$raw"
        local n
        for n in $nrs; do
            "$bin" "$n" "$n" >> "$raw"
        done
    else
        "$bin" 0 451 > "$raw"
        "$bin" 452 560 >> "$raw"
    fi
    # 探针逐条输出 "<nr> <KIND> ..."；把 proroot 自己打的诊断噪声分离出去，
    # 否则混在原始输出里会让人误以为是被探测系统调用的结果。
    grep -E '^[0-9]+ (TRAP|RET|SIGNAL) ' "$raw" > "$WORK/probe_raw.txt"
    grep -vE '^[0-9]+ (TRAP|RET|SIGNAL) ' "$raw" > "$WORK/probe_noise.txt"
}

# ---------------------------------------------------------------- 归纳
summarize() {
    local raw="$WORK/probe_raw.txt"
    awk '$2=="TRAP"{print $1}' "$raw" | sort -n > "$WORK/trapped.txt"
    awk '$2=="RET" && $3 ~ /^-/ {print $1, -$3}' "$raw" | sort -n > "$WORK/errno_rule.txt"
    awk '$2=="RET" && $3 !~ /^-/ {print $1, $3}' "$raw" | sort -n > "$WORK/ret_ok.txt"
    awk '$2=="SIGNAL"{print $1, $3}' "$raw" | sort -n > "$WORK/signals.txt"

    python3 - "$WORK" <<'PY'
import sys, re, os
W = sys.argv[1]

# 从内核头文件构造 aarch64 系统调用号 -> 名字表
nr2name = {}
hdr = '/usr/include/asm-generic/unistd.h'
if os.path.exists(hdr):
    for line in open(hdr):
        m = re.match(r'#define __NR_(\w+)\s+(\d+)', line)
        if m:
            nr2name[int(m.group(2))] = m.group(1)
        m = re.match(r'#define __NR3264_(\w+)\s+(\d+)', line)
        if m:
            nr2name.setdefault(int(m.group(2)), m.group(1))

def load(name):
    p = os.path.join(W, name)
    out = []
    if os.path.exists(p):
        for line in open(p):
            parts = line.split()
            if parts:
                out.append(int(parts[0]))
    return out

def load_pairs(name):
    p = os.path.join(W, name)
    out = []
    if os.path.exists(p):
        for line in open(p):
            parts = line.split()
            if len(parts) >= 2:
                out.append((int(parts[0]), int(parts[1])))
    return out

trapped = load('trapped.txt')
errno_rule = load_pairs('errno_rule.txt')
ret_ok = load_pairs('ret_ok.txt')
signals = load_pairs('signals.txt')
allseen = set(trapped) | {n for n, _ in errno_rule} | {n for n, _ in ret_ok} | {n for n, _ in signals}

def nm(n):
    return nr2name.get(n, '<空号>')

r = []
r.append("================ seccomp 过滤器行为归纳 ================")
r.append("")
r.append("[统计] 已探测 %d 个系统调用号" % len(allseen))
r.append("       放行(正常返回)      : %d" % len(ret_ok))
r.append("       TRAP (SIGSYS)       : %d" % len(trapped))
r.append("       固定错误码(ERRNO类) : %d" % len(errno_rule))
r.append("       死于其它信号        : %d" % len(signals))
r.append("")

r.append("---- 1. 被放行的系统调用（= 过滤器的允许集合） ----")
for n, v in ret_ok:
    r.append("  %3d  %-24s 返回 %d" % (n, nm(n), v))
r.append("")

r.append("---- 2. 被 SECCOMP_RET_TRAP 拦截的系统调用 ----")
r.append("     共 %d 个；编号区间与连续性：" % len(trapped))
# 压缩成区间
if trapped:
    start = prev = trapped[0]
    runs = []
    for n in trapped[1:]:
        if n == prev + 1:
            prev = n
        else:
            runs.append((start, prev)); start = prev = n
    runs.append((start, prev))
    for a, b in runs:
        if a == b:
            r.append("    %d (%s)" % (a, nm(a)))
        else:
            r.append("    %d..%d (%s .. %s)  共 %d 个" % (a, b, nm(a), nm(b), b - a + 1))
r.append("")

r.append("---- 3. 返回固定错误码的规则 ----")
for n, e in errno_rule:
    r.append("  %3d  %-24s 恒返回 -%d" % (n, nm(n), e))
r.append("")

r.append("---- 4. 死于非 SIGSYS 信号的号 ----")
for n, s in signals:
    r.append("  %3d  %-24s 信号 %d" % (n, nm(n), s))

open(os.path.join(W, 'report.txt'), 'w').write("\n".join(r) + "\n")
print("\n".join(r))
PY
}

# ---------------------------------------------------------------- main
echo "=============================================="
echo " probe_seccomp_bpf.sh  模式=$MODE"
echo " 工作目录=$WORK"
echo " 本进程 seccomp 状态:"
grep -E '^(Seccomp|Seccomp_filters|NoNewPrivs|Uid)' /proc/self/status | sed 's/^/   /'
echo "=============================================="
echo

echo "########## 一、静态提取（官方库里的 seccomp 常量/表） ##########"
static_extract
echo

if [ "$MODE" = static ]; then
    exit 0
fi

echo "########## 二、运行时行为枚举 ##########"
if run_probe; then
    echo
    summarize
else
    echo "探针不可用 —— 只保留静态结果。" >&2
    exit 1
fi
