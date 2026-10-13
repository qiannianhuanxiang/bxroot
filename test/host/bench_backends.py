#!/usr/bin/env python3
"""三后端对照基准：proot(ptrace) / 官方 proroot / bxroot。

必须在原生 Termux 里跑，不要在 PRoot 容器里跑（外层 ptrace 会污染所有结果）。

设计原则（来自 README 里记录的两次失败）：
  1. 每个计时循环前先断言操作"真的成功"，失败则整项作废，绝不拿失败路径的耗时当结果。
  2. proot 后端必须自证 TracerPid != 0，否则说明对照组没在 ptrace，结果无意义。
  3. 官方用 PROROOT_* 环境变量，bxroot 用 BXROOT_*，不混用。
  4. 同一设备、同一 rootfs、同样 bind，交替顺序跑，取中位数而不是均值。
"""
import json, os, shutil, statistics, subprocess, sys, time

HOME = os.path.expanduser('~')
L = os.environ.get('BENCH_LIBDIR', HOME + '/bxoff')
OFF = os.environ.get('BENCH_OFFDIR', L + '/offdir')
ROOTFS = os.environ.get('BENCH_ROOTFS', HOME + '/dsharf')
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _default_runtime():
    # 优先包内 lib/（发行打包放这里），其次本地 build/，最后才是设备上遗留的旧文件
    for c in (REPO + '/lib/libbxroot-runtime.so', REPO + '/build/libbxroot-runtime.so',
              L + '/runtime-v3.so'):
        if os.path.exists(c):
            return c
    return L + '/runtime-v3.so'


BX_RT = os.environ.get('BENCH_BX_RUNTIME') or _default_runtime()
ROUNDS = int(os.environ.get('BENCH_ROUNDS', '5'))
TMP = os.environ.get('TMPDIR', os.environ.get('PREFIX', '') + '/tmp')


def base_env():
    # Termux 默认带 LD_PRELOAD=libtermux-exec，会让 proot 的 execve 失败，必须剔除。
    e = {k: v for k, v in os.environ.items()
         if not k.startswith(('PROROOT_', 'BXROOT_', 'LD_PRELOAD'))}
    e.update({'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/root',
              'TERM': 'xterm', 'TMPDIR': '/tmp'})
    return e


def backend_proot(cmd):
    exe = shutil.which('proot')
    if not exe:
        return None
    return [exe, '-0', '-l', '-r', ROOTFS, '-b', '/dev', '-b', '/proc', '-b', '/sys',
            '-w', '/root'] + cmd, base_env()


def _libpath():
    return ROOTFS + '/usr/lib/aarch64-linux-gnu:' + ROOTFS + '/lib/aarch64-linux-gnu'


def _make_cfg_blob():
    """官方 runtime 读 launcher 写的配置块，不读 PROROOT_* 环境变量里的 bind。
    偏移取自 src/runtime/preload.c 的 PRCFG_*（反汇编交叉验证）。"""
    import struct
    b = bytearray(0x43130)
    raw = ROOTFS.encode()[:4095]
    b[0:len(raw)] = raw
    binds = [('/dev', '/dev'), ('/proc', '/proc'), ('/sys', '/sys')]
    struct.pack_into('<I', b, 0x42108, len(binds))
    for i, (host, guest) in enumerate(binds):
        o = 0x2008 + i * 0x2008
        b[o:o + len(guest)] = guest.encode()
        b[o + 0x1000:o + 0x1000 + len(host)] = host.encode()
    struct.pack_into('<I', b, 0x4210c, 1)   # -0
    struct.pack_into('<I', b, 0x42110, 1)   # --link2symlink
    os.makedirs(TMP, exist_ok=True)
    path = os.path.join(TMP, f'.bench-proroot-config-{os.getpid()}')
    with open(path, 'wb') as f:
        f.write(b)
    return path


def backend_official(cmd):
    d = OFF
    for f in ('libproroot-bridge.so', 'libproroot-linker.so', 'libproroot-runtime.so'):
        if not os.path.exists(f'{d}/{f}'):
            return None
    e = base_env()
    e.update({
        'PROROOT_TMP_DIR': L + '/tmp', 'PROROOT_LIB_PATH': f'{d}/libproroot-runtime.so',
        'PROROOT_LINKER_PATH': f'{d}/libproroot-linker.so',
        'PROROOT_STUB_LOADER': f'{d}/libproroot-stub-loader.so',
        'PROROOT_TRAMPOLINE_PATH': f'{d}/libproroot-bridge.so',
        'PROROOT_ROOTFS': ROOTFS, 'PROROOT_WORKDIR': '/root', 'PROROOT_FAKEROOT': '1',
        'PROROOT_BINDS': '/dev:/dev;/proc:/proc;/sys:/sys',
        'PROROOT_CFG_FD': _make_cfg_blob(),
        'LD_LIBRARY_PATH': _libpath(),
    })
    return [f'{d}/libproroot-bridge.so', f'{d}/libproroot-linker.so', '--argv0', cmd[0],
            '--preload', f'{d}/libproroot-runtime.so', ROOTFS + cmd[0]] + cmd[1:], e


def backend_bxroot(cmd):
    if not os.path.exists(BX_RT):
        return None
    e = base_env()
    e.update({
        'PROROOT_TMP_DIR': L + '/tmp', 'PROROOT_LIB_PATH': BX_RT,
        'PROROOT_LINKER_PATH': L + '/libproroot-linker.so',
        'PROROOT_STUB_LOADER': L + '/libproroot-stub-loader.so',
        'PROROOT_TRAMPOLINE_PATH': L + '/libproroot-bridge.so',
        'BXROOT_ROOTFS': ROOTFS, 'BXROOT_WORKDIR': '/root', 'BXROOT_FAKEROOT': '1',
        'BXROOT_BINDS': '/dev:/dev;/proc:/proc;/sys:/sys',
        'BXROOT_LINK2SYMLINK': '1',
        'LD_LIBRARY_PATH': _libpath(),
    })
    return [L + '/libproroot-bridge.so', L + '/libproroot-linker.so', '--argv0', cmd[0],
            '--preload', BX_RT, ROOTFS + cmd[0]] + cmd[1:], e


BACKENDS = {'proot': backend_proot, 'official': backend_official, 'bxroot': backend_bxroot}


def run(name, cmd, timeout=120):
    b = BACKENDS[name](cmd)
    if b is None:
        return None
    argv, env = b
    t = time.monotonic()
    p = subprocess.run(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       text=True, timeout=timeout)
    return time.monotonic() - t, p.returncode, p.stdout, p.stderr


# 每个工作负载：guest 内执行的 shell 片段，成功时最后一行必须是 WANT。
# 循环次数固定，且循环体里任一步失败整体就非 0 / 不打印 WANT。
WORKLOADS = {
    # stat 吞吐：先 stat 一个确定存在的文件，失败立即退出（吸取 ok=0 bad=30000 的教训）
    'stat_x2000': ('test -e /etc/passwd || exit 9; i=0; while [ $i -lt 2000 ]; do '
                   'stat /etc/passwd >/dev/null || exit 8; i=$((i+1)); done; echo DONE', 'DONE'),
    # fork+exec 风暴：bash 子进程每次 exec /bin/true
    'forkexec_x300': ('i=0; while [ $i -lt 300 ]; do /bin/true || exit 8; i=$((i+1)); done; echo DONE', 'DONE'),
    # 小文件读写：写后读回比对，内容不对立即失败
    'smallfile_x300': ('d=$(mktemp -d /tmp/bb.XXXXXX) || exit 9; i=0; '
                       'while [ $i -lt 300 ]; do echo "v$i" >"$d/f$i" || exit 8; '
                       '[ "$(cat "$d/f$i")" = "v$i" ] || exit 7; i=$((i+1)); done; rm -rf "$d"; echo DONE', 'DONE'),
    # 目录遍历：/usr 下 find 计数，必须大于 0
    'find_usr': ('n=$(find /usr -xdev 2>/dev/null | wc -l); [ "$n" -gt 1000 ] || exit 8; echo DONE', 'DONE'),
    # 硬链接模拟（l2s 路径）：建链后 nlink 必须为 2
    'link_x200': ('d=$(mktemp -d /tmp/bl.XXXXXX) || exit 9; echo x >"$d/a"; i=0; '
                  'while [ $i -lt 200 ]; do ln "$d/a" "$d/l$i" || exit 8; i=$((i+1)); done; '
                  '[ "$(stat -c %h "$d/a")" -ge 2 ] || exit 7; rm -rf "$d"; echo DONE', 'DONE'),
}


def prepare_guest_tmp():
    d = os.path.join(ROOTFS, 'tmp')
    os.makedirs(d, exist_ok=True)
    try:
        os.chmod(d, 0o1777)
    except OSError:
        pass


def selfcheck():
    """每个后端先自检：能跑通 echo；proot 还必须有 tracer。"""
    ok = {}
    counts = {}
    for n in BACKENDS:
        r = run(n, ['/bin/bash', '-c',
                    'echo SELF; while IFS= read -r l; do case $l in TracerPid:*) echo "$l";; esac; '
                    'done </proc/self/status'])
        if r is None:
            print(f'[skip] {n}: 缺少库/二进制', flush=True)
            continue
        dt, rc, out, err = r
        if rc != 0 or 'SELF' not in out:
            print(f'[FAIL] {n}: 自检失败 rc={rc} err={err[-200:]!r}', flush=True)
            continue
        tr = '?'
        for ln in out.splitlines():
            if ln.startswith('TracerPid:'):
                tr = ln.split()[-1]
        if n == 'proot':
            # guest 看到的 TracerPid 是被 proot 的 ptrace 附着者，应非 0
            if tr in ('0', '?'):
                print(f'[FAIL] proot: guest TracerPid={tr}，对照组没在 ptrace，作废', flush=True)
                continue
        # 路径翻译探针：/usr 下必须有足够条目，否则这个后端看到的不是 rootfs
        pr = run(n, ['/bin/bash', '-c', 'find /usr -xdev 2>/dev/null | wc -l'])
        cnt = -1
        if pr and pr[1] == 0 and pr[2].strip().isdigit():
            cnt = int(pr[2].strip())
        if cnt < 1000:
            print(f'[FAIL] {n}: 路径翻译探针失败，find /usr 只有 {cnt} 项，作废', flush=True)
            continue
        counts[n] = cnt
        print(f'[ok]   {n}: 自检通过 TracerPid={tr} find_usr={cnt}', flush=True)
        ok[n] = True
    # 各后端 find 条目数必须一致，否则它们遍历的不是同一棵树，比较无意义
    if len(set(counts.values())) > 1:
        print(f'[WARN] 各后端 find /usr 条目数不一致: {counts}，只保留与多数一致者', flush=True)
        from collections import Counter
        major = Counter(counts.values()).most_common(1)[0][0]
        for n in list(ok):
            if counts.get(n) != major:
                print(f'[void] {n}: 条目数 {counts.get(n)} != {major}', flush=True)
                ok.pop(n)
    return ok


def main():
    if os.path.exists('/proc/self/status'):
        for line in open('/proc/self/status'):
            if line.startswith('TracerPid:') and line.split()[1] != '0':
                sys.exit('REFUSED: 本进程被 ptrace，不能在 PRoot 容器内跑基准')
    if not os.path.isdir(ROOTFS):
        sys.exit(f'REFUSED: rootfs 不存在 {ROOTFS}')
    prepare_guest_tmp()
    alive = selfcheck()
    if len(alive) < 2:
        sys.exit('REFUSED: 可用后端不足 2 个，无法对照')
    results = {}
    for w, (script, want) in WORKLOADS.items():
        # 先各跑一次预热并校验成功；任一后端校验失败，只作废该后端该项
        valid = {}
        for n in alive:
            r = run(n, ['/bin/bash', '-c', script])
            if r is None or r[1] != 0 or want not in r[2]:
                print(f'[void] {w} / {n}: 校验失败 rc={None if r is None else r[1]} '
                      f'err={None if r is None else r[3][-160:]!r}', flush=True)
                continue
            valid[n] = []
        # 交替顺序多轮，抵消热降频/缓存的单向偏置
        for rd in range(ROUNDS):
            order = list(valid) if rd % 2 == 0 else list(reversed(list(valid)))
            for n in order:
                r = run(n, ['/bin/bash', '-c', script])
                if r is None or r[1] != 0 or want not in r[2]:
                    print(f'[void-round] {w} / {n} 第 {rd} 轮失败，丢弃该后端该项', flush=True)
                    valid.pop(n, None)
                    break
                valid[n].append(r[0])
        results[w] = {n: {'median_s': round(statistics.median(v), 3),
                          'min_s': round(min(v), 3), 'max_s': round(max(v), 3), 'n': len(v)}
                      for n, v in valid.items() if v}
        print(json.dumps({w: results[w]}, ensure_ascii=False), flush=True)
    import hashlib
    sha = lambda f: hashlib.sha256(open(f, 'rb').read()).hexdigest() if os.path.exists(f) else None
    out = {'rootfs': ROOTFS, 'rounds': ROUNDS, 'backends': sorted(alive), 'results': results,
           'bxroot_runtime': BX_RT, 'bxroot_runtime_sha256': sha(BX_RT),
           'official_runtime_sha256': sha(OFF + '/libproroot-runtime.so')}
    print('bxroot runtime:', BX_RT, out['bxroot_runtime_sha256'], flush=True)
    path = os.path.join(TMP, 'bench-backends.json')
    json.dump(out, open(path, 'w'), ensure_ascii=False, indent=1)
    print('BENCH_RESULT_FILE', path)


if __name__ == '__main__':
    main()
