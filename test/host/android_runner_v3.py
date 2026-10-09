#!/usr/bin/env python3
"""Native v3 regression; downloads only to anonymous memory in Termux."""
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
    p.add_argument('--base', default='http://127.0.0.1:37692')
    p.add_argument('--rootfs', default='/data/data/com.termux/files/home/dsharf')
    p.add_argument('--libdir', default='/data/data/com.termux/files/home/bxoff')
    p.add_argument('--diagnostics', action='store_true')
    a = p.parse_args()
    fds = []
    def mem(name):
        data = urllib.request.urlopen(a.base + '/' + name, timeout=10).read()
        c = ctypes.CDLL(None, use_errno=True)
        c.memfd_create.argtypes = [ctypes.c_char_p, ctypes.c_uint]
        c.memfd_create.restype = ctypes.c_int
        fd = c.memfd_create(('bxroot-v3-' + name).encode(), 0)
        if fd < 0:
            raise OSError(ctypes.get_errno(), 'memfd_create')
        pos = 0
        while pos < len(data):
            pos += os.write(fd, data[pos:])
        os.set_inheritable(fd, True)
        fds.append(fd)
        return '/proc/%d/fd/%d' % (os.getpid(), fd), hashlib.sha256(data).hexdigest()
    runtime, digest = mem('runtime.so')
    entry, entry_digest = mem('bx-enter-native')
    script, _ = mem('script.sh')
    probe, _ = mem('probe')
    results = []
    def run(name, target, args, expected=0, needles=(), extra=None, input_after=None, input_text=b''):
        env = os.environ.copy()
        env.pop('LD_PRELOAD', None)
        env.update(PATH='/usr/local/bin:/usr/bin:/bin', HOME='/root', TMPDIR='/tmp', TERM='xterm-256color',
                   BXROOT_GUEST_PATH='/usr/local/bin:/usr/bin:/bin', BXROOT_REENTRY='1',
                   BXROOT_SESSION_FD='', BXROOT_ENTER=entry, ENTRY_LOADER='/system/bin/linker64',
                   PROROOT_TMP_DIR=a.libdir + '/tmp', PROROOT_LIB_PATH=runtime,
                   PROROOT_LINKER_PATH=a.libdir + '/libproroot-linker.so',
                   PROROOT_STUB_LOADER=a.libdir + '/libproroot-stub-loader.so',
                   PROROOT_TRAMPOLINE_PATH=a.libdir + '/libproroot-bridge.so',
                   BXROOT_AUTO_HOST='1', BXROOT_HOST_PATH='/system/bin:/system/xbin:/vendor/bin',
                   BXROOT_ROOTFS=a.rootfs, BXROOT_WORKDIR='/root', BXROOT_FAKEROOT='1',
                   LD_LIBRARY_PATH=a.rootfs + '/usr/lib/aarch64-linux-gnu:' + a.rootfs + '/lib/aarch64-linux-gnu',
                   BXROOT_BINDS='/dev:/dev;/proc:/proc;/sys:/sys;/system:/system;/apex:/apex;' +
                   a.libdir + '/shm:/dev/shm;' + script + ':/tmp/bx-v3-script;' +
                   a.rootfs + '/root:/workspace:ro', FOO='initial')
        if extra:
            env.update(extra)
        host = probe if target == '/tmp/probe' else a.rootfs + target
        argv = [a.libdir + '/libproroot-bridge.so', a.libdir + '/libproroot-linker.so',
                '--argv0', target, '--preload', runtime, host] + args
        pid, master = pty.fork()
        if pid == 0:
            os.execve(argv[0], argv, env)
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack('HHHH', 31, 89, 0, 0))
        output = bytearray()
        status = None
        sent = False
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if select.select([master], [], [], .1)[0]:
                try:
                    block = os.read(master, 65536)
                except OSError:
                    block = b''
                output.extend(block)
                if input_after and not sent and input_after.encode() in output:
                    os.write(master, input_text)
                    sent = True
                if not block:
                    _, status = os.waitpid(pid, 0)
                    break
            got, st = os.waitpid(pid, os.WNOHANG)
            if got:
                status = st
                while select.select([master], [], [], 0)[0]:
                    try:
                        block = os.read(master, 65536)
                    except OSError:
                        break
                    if not block:
                        break
                    output.extend(block)
                break
        if status is None:
            os.kill(pid, signal.SIGKILL)
            _, status = os.waitpid(pid, 0)
        os.close(master)
        text = output.decode(errors='replace').replace('\r\n', '\n')
        rc = os.waitstatus_to_exitcode(status)
        ok = rc == expected and all(n in text for n in needles)
        result = dict(name=name, ok=ok, rc=rc, output=text)
        results.append(result)
        print(json.dumps(result, ensure_ascii=False), flush=True)
    # Alias /workspace intentionally creates a cwd ambiguity for /root.
    enter = '"$ENTRY_LOADER" "$BXROOT_ENTER" --cwd /root'
    if a.diagnostics:
        run('script-open-probe', '/tmp/probe', ['script-open'])
        for shell in ('bash', 'dash'):
            run('direct-script-' + shell, '/bin/bash', ['-c', '/bin/' + shell + ' /tmp/bx-v3-script value'], expected=29, needles=('SCRIPT=value', 'V2352A'))
            run('reentry-script-' + shell, '/bin/bash', ['-c', '/system/bin/sh -c \'' + enter + ' -- /bin/' + shell + ' /tmp/bx-v3-script value\''], expected=29, needles=('SCRIPT=value', 'V2352A'))
        run('persistent-script-ldd', '/bin/bash', ['-c', '/system/bin/sh -c \'' + enter + ' -- /usr/bin/ldd --version\''], needles=('ldd',))
        run('anonymous-shebang', '/bin/bash', ['-c', '/system/bin/sh -c \'' + enter + ' -- /tmp/bx-v3-script value\''], expected=29, needles=('SCRIPT=value', 'V2352A'))
        print(json.dumps(dict(diagnostics=True, passed=sum(r['ok'] for r in results), total=len(results))), flush=True)
        for fd in fds:
            os.close(fd)
        raise SystemExit(0 if all(r['ok'] for r in results) else 1)
    run('session-fd-mode', '/tmp/probe', ['fd'], needles=('SEALS=15 WRITE=-9', 'GUEST_UID=0 REAL_UID='))
    run('proc-fd-script-open', '/tmp/probe', ['script-open'], needles=('RESOLVE=0:', 'OPEN='))
    run('initial-bash-slots', '/bin/bash', ['-c', 'echo "FD=$BXROOT_SESSION_FD ENTER=$BXROOT_ENTER"; test -n "$BXROOT_SESSION_FD"; ' + enter + ' -- /usr/bin/printf "REENTER_OK\\n"'], needles=('FD=', 'REENTER_OK'))
    run('native-shell-reentry', '/bin/bash', ['-c', '/system/bin/sh -c \'' + enter + ' -- /usr/bin/printf "HOST_BACK\\n"\''], needles=('HOST_BACK',))
    run('node-host-guest-native', '/usr/local/bin/node', ['-e', 'const c=require("child_process");const code="const c=require(\\\"child_process\\\");const r=c.spawnSync(\\\"getprop\\\",[\\\"ro.product.model\\\"],{encoding:\\\"utf8\\\"});console.log(\\\"MODEL=\\\"+r.stdout.trim());process.exit(r.status);";const r=c.spawnSync("/system/bin/sh",["-c",\'exec "$ENTRY_LOADER" "$BXROOT_ENTER" --cwd /root -- /usr/local/bin/node -e "$1"\',"sh",code],{encoding:"utf8"});console.log(r.stdout);console.error(r.stderr);process.exit(r.status??1);'], needles=('MODEL=V2352A',))
    run('host-env-change', '/bin/bash', ['-c', '/system/bin/sh -c \'export FOO=updated; ' + enter + ' -- /bin/bash -c "echo FOO=\\$FOO HOME=\\$HOME TMPDIR=\\$TMPDIR; getprop ro.product.model"\''], needles=('FOO=updated HOME=/root TMPDIR=/tmp', 'V2352A'))
    run('path-to-host', '/bin/bash', ['-c', '"$ENTRY_LOADER" "$BXROOT_ENTER" --to-host /etc/os-release'], needles=(a.rootfs + '/usr/lib/os-release',))
    run('native-reads-guest', '/bin/bash', ['-c', 'p=$("$ENTRY_LOADER" "$BXROOT_ENTER" --to-host /etc/os-release) && /system/bin/toybox head -1 "$p"'], needles=('Ubuntu',))
    run('guest-cwd-tmp', '/bin/bash', ['-c', 'cd /tmp; /system/bin/sh -c \'"$ENTRY_LOADER" "$BXROOT_ENTER" -- /bin/pwd\''], needles=('/tmp',))
    run('host-cwd-change', '/bin/bash', ['-c', '/system/bin/sh -c \'p=$(/system/bin/linker64 "$BXROOT_ENTER" --to-host /tmp); cd "$p"; "$ENTRY_LOADER" "$BXROOT_ENTER" -- /bin/pwd\''], needles=('/tmp',))
    run('ambiguous-cwd', '/bin/bash', ['-c', '/system/bin/sh -c \'"$ENTRY_LOADER" "$BXROOT_ENTER" -- /usr/bin/true\''], expected=126, needles=('ambiguous',))
    run('readonly-bind-preserved', '/bin/bash', ['-c', '/system/bin/sh -c \'' + enter + ' -- /usr/local/bin/node -e "try{require(\\\"fs\\\").openSync(\\\"/workspace\\\",\\\"w\\\");process.exit(1)}catch(e){console.log(e.code);process.exit(e.code===\\\"EROFS\\\"?0:2)}"\''], needles=('EROFS',))
    run('reentry-bind-env', '/bin/bash', ['-c', '/system/bin/sh -c \'"$ENTRY_LOADER" "$BXROOT_ENTER" --cwd /root -- /bin/bash -c "printf BINDS=\\$BXROOT_BINDS\\\\n"\''], needles=('/tmp/bx-v3-script',))
    run('script-to-host', '/bin/bash', ['-c', 'p=$("$ENTRY_LOADER" "$BXROOT_ENTER" --cwd /root --to-host /tmp/bx-v3-script); echo P=$p; /system/bin/toybox head -1 "$p"'], needles=('P=/proc/', '#!/bin/sh'))
    run('guest-script', '/bin/bash', ['-c', '/system/bin/sh -c \'' + enter + ' -- /tmp/bx-v3-script value\''], expected=29, needles=('SCRIPT=value', 'V2352A'))
    run('persistent-script-ldd', '/bin/bash', ['-c', '/system/bin/sh -c \'' + enter + ' -- /usr/bin/ldd --version\''], needles=('ldd',))
    run('guest-path-search', '/bin/bash', ['-c', '/system/bin/sh -c \'' + enter + ' -- printf "NAME_OK\\n"\''], needles=('NAME_OK',))
    run('pty-reentry-size', '/bin/bash', ['-c', '/system/bin/sh -c \'' + enter + ' -- /bin/bash -c "/system/bin/toybox stty size"\''], needles=('31 89',))
    run('pty-reentry-input', '/bin/bash', ['-c', 'exec /system/bin/sh -c \'exec ' + enter + ' -- /bin/bash -c "echo READY; read v; echo INPUT=\\$v; exit 7"\''], expected=7, needles=('INPUT=hello',), input_after='READY', input_text=b'hello\n')
    run('pty-reentry-ctrl-c', '/bin/bash', ['-c', 'exec /system/bin/sh -c \'exec ' + enter + ' -- /bin/bash -c "echo READY; exec /system/bin/toybox sleep 10"\''], expected=-signal.SIGINT, input_after='READY', input_text=b'\x03')
    run('clean-env-explicit-fd', '/bin/bash', ['-c', '/system/bin/sh -c \'exec /system/bin/toybox env -i "$ENTRY_LOADER" "$BXROOT_ENTER" --session-fd "$BXROOT_SESSION_FD" --cwd /root -- /usr/bin/printf "CLEAN_OK\\n"\''], needles=('CLEAN_OK',))
    print(json.dumps(dict(runtime_sha256=digest, entry_sha256=entry_digest,
                          passed=sum(r['ok'] for r in results), total=len(results))), flush=True)
    for fd in fds:
        os.close(fd)
    raise SystemExit(0 if all(r['ok'] for r in results) else 1)


if __name__ == '__main__':
    main()
