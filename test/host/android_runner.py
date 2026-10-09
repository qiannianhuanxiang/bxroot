#!/usr/bin/env python3
"""Android regression harness. Downloads artifacts into anonymous memfd only.
Run from Termux with --base http://127.0.0.1:37691. No Android filesystem writes.
"""
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
import pty
import select
import signal
import struct
import termios
import time
import urllib.request


def main():
    p = argparse.ArgumentParser()
    home = '/data/data/com.termux/files/home'
    p.add_argument('--base', default='http://127.0.0.1:37691')
    p.add_argument('--rootfs', default=home + '/dsharf')
    p.add_argument('--libdir', default=home + '/bxoff')
    a = p.parse_args()
    keep = []
    def mem(name):
        data = urllib.request.urlopen(a.base + '/' + name, timeout=10).read()
        if hasattr(os, 'memfd_create'):
            fd = os.memfd_create('bxroot-native-v2-' + name, 0)
        else:
            libc = ctypes.CDLL(None, use_errno=True)
            create = libc.memfd_create
            create.argtypes = [ctypes.c_char_p, ctypes.c_uint]
            create.restype = ctypes.c_int
            fd = create(('bxroot-native-v2-' + name).encode(), 0)
            if fd < 0:
                raise OSError(ctypes.get_errno(), 'memfd_create')
        os.set_inheritable(fd, True)
        pos = 0
        while pos < len(data):
            pos += os.write(fd, data[pos:])
        keep.append(fd)
        return '/proc/%d/fd/%d' % (os.getpid(), fd), hashlib.sha256(data).hexdigest()
    runtime, digest = mem('runtime.so')
    probe, _ = mem('probe')
    script, _ = mem('script.sh')
    results = []
    def run(name, cmd, expected=0, needles=(), auto=True, input_after=None, input_text=b'', extra=None):
        env = os.environ.copy()
        env.pop('LD_PRELOAD', None)
        env.update(PATH='/usr/local/bin:/usr/bin:/bin', HOME='/root', TMPDIR='/tmp', TERM='xterm-256color',
                   PROROOT_TMP_DIR=a.libdir + '/tmp', PROROOT_LIB_PATH=runtime,
                   PROROOT_LINKER_PATH=a.libdir + '/libproroot-linker.so',
                   PROROOT_STUB_LOADER=a.libdir + '/libproroot-stub-loader.so',
                   BXROOT_AUTO_HOST='1' if auto else '0', BXROOT_HOST_PATH='/system/bin:/system/xbin:/vendor/bin')
        if extra:
            env.update(extra)
        env.update(BXROOT_ROOTFS=a.rootfs,
                   LD_LIBRARY_PATH=a.rootfs + '/usr/lib/aarch64-linux-gnu:' + a.rootfs + '/lib/aarch64-linux-gnu',
                   BXROOT_WORKDIR='/root', BXROOT_FAKEROOT='1',
                   BXROOT_BINDS='/dev:/dev;/proc:/proc;/sys:/sys;/system:/system;/apex:/apex;' + a.libdir + '/shm:/dev/shm;' + script + ':/tmp/bx-native-script',
                   PROROOT_TRAMPOLINE_PATH=a.libdir + '/libproroot-bridge.so')
        target = cmd[0]
        if target == '/tmp/bx-native-probe':
            target = probe
        else:
            target = a.rootfs + target
        argv = [a.libdir + '/libproroot-bridge.so', a.libdir + '/libproroot-linker.so',
                '--argv0', cmd[0], '--preload', runtime, target] + cmd[1:]
        pid, master = pty.fork()
        if pid == 0:
            os.execvpe(argv[0], argv, env)
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack('HHHH', 31, 89, 0, 0))
        out = bytearray()
        status = None
        sent = False
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], .1)
            if ready:
                try:
                    block = os.read(master, 65536)
                except OSError:
                    block = b''
                out.extend(block)
                if input_after and not sent and input_after.encode() in out:
                    os.write(master, input_text)
                    sent = True
                if not block:
                    _, status = os.waitpid(pid, 0)
                    break
            got, st = os.waitpid(pid, os.WNOHANG)
            if got:
                status = st
                # Drain bytes already buffered before closing the PTY.
                while select.select([master], [], [], 0)[0]:
                    try:
                        block = os.read(master, 65536)
                    except OSError:
                        break
                    if not block:
                        break
                    out.extend(block)
                break
        if status is None:
            os.kill(pid, signal.SIGKILL)
            _, status = os.waitpid(pid, 0)
        os.close(master)
        text = out.decode(errors='replace').replace('\r\n', '\n')
        rc = os.waitstatus_to_exitcode(status)
        ok = rc == expected and all(n in text for n in needles)
        result = dict(name=name, ok=ok, rc=rc, output=text)
        results.append(result)
        print(json.dumps(result, ensure_ascii=False), flush=True)

    run('shell-path-and-map', ['/bin/bash', '-c', 'echo "PATH:$PATH"; /usr/bin/grep bxroot-native-v2 /proc/$$/maps; getprop ro.product.model'], needles=('PATH:', 'bxroot-native-v2', 'V2352A'))
    run('probe-path', ['/tmp/bx-native-probe', 'path'], needles=('AUTO:1', 'UPDATED:'))
    for mode in ('exec', 'syscall', 'execveat', 'fexecve'):
        run(mode, ['/tmp/bx-native-probe', mode], expected=17, needles=('EXEC:custom-host-argv0:retained',))
    for mode in ('execvp', 'execvpe', 'spawnp', 'system'):
        run(mode, ['/tmp/bx-native-probe', mode], needles=('V2352A',))
    run('spawn-file-actions-env', ['/tmp/bx-native-probe', 'spawn'], needles=('SPAWN:custom-host-argv0:retained STATUS=23',))
    run('popen', ['/tmp/bx-native-probe', 'popen'], needles=('POPEN:V2352A',))
    run('host-to-host', ['/bin/bash', '-c', '/system/bin/sh -c "getprop ro.product.model"'], needles=('V2352A',))
    node = '/usr/local/bin/node'
    run('node-spawn-host-and-guest', [node, '-e', "const c=require('child_process'); for(const [p,a] of [['getprop',['ro.product.model']],['/usr/bin/true',[]]]) {const r=c.spawnSync(p,a,{encoding:'utf8'}); console.log(JSON.stringify([p,r.status,r.stdout?.trim(),r.error?.code])); if(r.status!==0)process.exitCode=1;}"], needles=('\"getprop\",0,\"V2352A\"', '\"/usr/bin/true\",0'))
    run('guest-priority', ['/bin/bash', '-c', 'command -v sh; sh -c "head -1 /etc/os-release"'], needles=('/bin/sh', 'Ubuntu'))
    run('auto-off', ['/bin/bash', '-c', 'getprop ro.product.model'], expected=127, auto=False, needles=('command not found',))
    run('missing-command', ['/bin/bash', '-c', 'bx_no_such_native_command'], expected=127, needles=('command not found',))
    run('pty-size', ['/bin/bash', '-c', '/system/bin/toybox stty size'], needles=('31 89',))
    run('pty-input-exit', ['/bin/bash', '-c', '/system/bin/sh -c \'echo READY; read v; echo "INPUT:$v"; exit 7\''], expected=7, needles=('INPUT:hello-host',), input_after='READY', input_text=b'hello-host\n')
    run('pty-ctrl-c', ['/bin/bash', '-c', 'echo READY; exec /system/bin/toybox sleep 10'], expected=-signal.SIGINT, input_after='READY', input_text=b'\x03')
    run('native-shebang-exec', ['/tmp/bx-native-probe', 'script-exec'], expected=29, needles=('SCRIPT:arg-value:retained', 'V2352A'))
    run('native-shebang-spawn', ['/tmp/bx-native-probe', 'script-spawn'], expected=29, needles=('SCRIPT:arg-value:retained', 'V2352A'))
    print(json.dumps(dict(skipped='non-executable-script', reason='Android denied memfd chmod; raw X_OK verified by RUN_HOST_WORLD.sh')), flush=True)
    run('guest-clean-env', ['/tmp/bx-native-probe', 'guest-clean-env'], needles=('V2352A',))
    run('host-env-home', ['/bin/bash', '-c', '/system/bin/sh -c \'echo HOME=$HOME TMPDIR=$TMPDIR; test -w "$HOME"; test -w "$TMPDIR"\''], needles=('HOME=/data/', 'TMPDIR=/data/'))
    run('auto-guest-ldconfig', ['/bin/bash', '-c', '/sbin/ldconfig; rc=$?; echo ldconfig=$rc; exit $rc'], needles=('ldconfig=0',))
    summary = dict(runtime_sha256=digest, passed=sum(r['ok'] for r in results), total=len(results))
    print(json.dumps(summary), flush=True)
    for fd in keep:
        os.close(fd)
    raise SystemExit(0 if all(r['ok'] for r in results) else 1)

if __name__ == '__main__':
    main()
