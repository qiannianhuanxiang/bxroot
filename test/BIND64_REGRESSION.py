#!/usr/bin/env python3
"""Workspace-only source regression. No device shell, nested container or APK claim.
Extract actual parser/serializer/bind-lookup code; compile it with the actual
launcher translation unit and proc pure-logic layer. Output directory must exist.
"""
import os, pathlib, subprocess, sys
root = pathlib.Path(__file__).resolve().parents[1]
out = pathlib.Path(sys.argv[1]).resolve()
assert out.is_dir() and out != root / 'build'
launcher = (root / 'src/launcher/launcher.c').read_text()
runtime = (root / 'src/runtime/preload.c').read_text()
def between(s, a, b):
    return s[s.index(a):s.index(b, s.index(a))]
parse = between(runtime, '/* config.h retains a legacy default;', '\n/*\n * ==================================================================')
serialize = between(launcher, '    if (cfg.bind_count > 0) {', '\n    /*\n     * 硬链接模拟开关。')
pos = runtime.index('    if (g_config.bind_count > 0)', runtime.index('static int translate_path(const char *path, char *out, size_t out_size) {'))
end = runtime.index('\n    /*\n     * ★ /dev/shm', pos)
lookup = runtime[pos:end]
source = '#include "' + str(root / 'src/runtime/config.h') + '"\n#undef MAX_BINDS\n#define main unused_launcher_main\n#include "' + str(root / 'src/launcher/launcher.c') + '"\n#undef main\n#include <assert.h>\n#include "' + str(root / 'src/proc/proc.h') + '"\nbxroot_config_t g_config;\n' + parse
source += '\nstatic int map_bind(const char *path, char *out, size_t out_size) {\n' + lookup + '\nreturn 0;\n}\n'
prcfg_defs = between(runtime, '#define PRCFG_SIZE_MIN', '/* 裸系统调用')
prcfg_helpers = between(runtime, 'static unsigned int prcfg_u32(', 'static void load_proroot_cfg(')
prcfg_binds = between(runtime, '    nb = prcfg_u32(b, PRCFG_OFF_NBINDS);', '    /*\n     * rootfs。')
source += prcfg_defs + prcfg_helpers + '\n#define LOG(...) ((void)0)\nstatic void parse_prcfg_data(unsigned char *b) { unsigned int nb,i;\n' + prcfg_binds + '\n}\n'
source += r'''
static int fail_setenv(const char *a, const char *b, int c) {
    if (getenv("TEST_SETENV_FAIL")) { errno = ENOMEM; return -1; }
    return setenv(a,b,c);
}
#define setenv fail_setenv
static int serialize_config(launcher_config_t cfg) {
''' + serialize + r'''
    return 0;
}
#undef setenv
int main(int argc, char **argv) {
    launcher_config_t cfg = {0};
    if (getenv("TEST_PRCFG_COUNT")) {
        unsigned int n = atoi(getenv("TEST_PRCFG_COUNT"));
        unsigned char *b = calloc(1, PRCFG_SIZE_MIN);
        memcpy(b + PRCFG_OFF_NBINDS, &n, sizeof(n));
        for (unsigned int i=0; i<n && i<PRCFG_MAX_ENTRIES; i++) {
            snprintf((char *)b+PRCFG_OFF_SRC(i), PRCFG_FIELD_LEN, "/source/%u", i);
            snprintf((char *)b+PRCFG_OFF_DST(i), PRCFG_FIELD_LEN, "/guest/%u", i);
        }
        parse_prcfg_data(b);
        char translated[1024];
        if (g_config.bind_count != (int)n || map_bind("/guest/31/probe", translated, sizeof(translated)) != 1 || strcmp(translated,"/source/31/probe")) return 11;
        printf("PRCFG count=%d last=%s\n",g_config.bind_count,translated);
        free(b); return 0;
    }
    if (!getenv("TEST_RUNTIME_ONLY")) {
        if (parse_args(argc, argv, &cfg) != 0) return 2;
        if (serialize_config(cfg) != 0) return 3;
    }
    const char *value = getenv("BXROOT_BINDS");
    if (!value) { puts("EMPTY"); return 0; }
    parse_binds();
    if (!g_config.bind_count) return 4;
    int last = g_config.bind_count - 1;
    char guest[8192], translated[8192];
    snprintf(guest, sizeof(guest), "%s/probe", g_config.bind_targets[last]);
    if (map_bind(guest, translated, sizeof(translated)) != 1) return 5;
    if (strncmp(translated, g_config.bind_sources[last], strlen(g_config.bind_sources[last]))) return 6;
    size_t bytes = strlen("BXROOT_BINDS=") + strlen(value) + 1;
    char *full = malloc(bytes);
    snprintf(full, bytes, "BXROOT_BINDS=%s", value);
    const char *env[] = {full, NULL};
    px_envout result;
    if (px_env_build(env, NULL, &result, NULL) != PX_OK) return 7;
    if (result.n != 1 || strcmp(result.v[0], full)) return 8;
    px_env_dispose(&result);
    px_env_kv forced = {"BXROOT_BINDS", value, PX_ENV_SET};
    px_envpolicy policy = {.forced=&forced, .forced_n=1};
    if (px_env_build(NULL, &policy, &result, NULL) != PX_OK) return 9;
    if (result.n != 1 || strcmp(result.v[0], full)) return 10;
    px_env_dispose(&result);
    printf("PASS count=%d bytes=%zu last=%s ro=%d translated=%s\n",
           g_config.bind_count, bytes, g_config.bind_targets[last],
           g_config.bind_readonly[last], translated);
    free(full);
    return 0;
}
'''
(out / 'bind64-driver.c').write_text(source)
cmd = [os.environ.get('CC', 'gcc'), '-O0', '-D_GNU_SOURCE', '-DPX_PURE_LOGIC=1', '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections', str(out/'bind64-driver.c'), str(root/'src/proc/proc.c'), '-o', str(out/'bind64-driver')]
r = subprocess.run(cmd, capture_output=True, text=True)
(out/'test-build.log').write_text(r.stdout+r.stderr)
if r.returncode:
    raise SystemExit('test compile failed: '+r.stderr[-2000:])
base = dict(os.environ)
for k in ['BXROOT_BINDS', 'TEST_RUNTIME_ONLY', 'TEST_SETENV_FAIL']:
    base.pop(k, None)
checks = 0
def check(name, specs=(), rc=0, contains='', extra=None, args=None):
    global checks
    argv = [str(out/'bind64-driver'), '-r', '/']
    for s in specs: argv += ['-b', s]
    if args: argv += args
    argv += ['/bin/true']
    e = base | (extra or {})
    r = subprocess.run(argv, env=e, capture_output=True, text=True, timeout=15)
    text = r.stdout+r.stderr
    assert r.returncode == rc and contains in text, (name,r.returncode,text)
    print('PASS',name, text.strip()[:230], flush=True)
    checks += 1
for n in (16,17,32,64):
    check('roundtrip-'+str(n), [f'/source/{i}:/guest/{i}'+(':RO' if i==n-1 else '') for i in range(n)], contains=f'count={n}')
check('cli-65-rejected', [f'/s/{i}:/g/{i}' for i in range(65)], rc=2, contains='64')
check('runtime-65-rejected',rc=127,contains='too many',extra={'TEST_RUNTIME_ONLY':'1','BXROOT_BINDS':';'.join(f'/s/{i}:/g/{i}' for i in range(65))})
# Exactly 16384 full environment bytes, each individual path under PATH_MAX.
specs = ['/s'+str(i)+':/'+('x'*4000)+str(i) for i in range(4)]
size = 14+len(';'.join(specs))
specs[-1] += 'x'*(16384-size)
check('env-exact-16384', specs, contains='bytes=16384')
check('env-16385-rejected', specs[:-1]+[specs[-1]+'x'],rc=3,contains='列表过长')
check('runtime-env-16385-rejected',rc=127,contains='16 KiB',extra={'TEST_RUNTIME_ONLY':'1','BXROOT_BINDS':';'.join(specs)+'x'})
check('setenv-failure', ['/s:/g'],rc=3,contains='setenv BXROOT_BINDS',extra={'TEST_SETENV_FAIL':'1'})
for invalid in ('/s:/g;;/s:/h', '/s:', ':/g', '/s:/g:bad', '/s', '/s:/g;'):
    check('malformed-'+invalid,rc=127,contains='invalid bind',extra={'TEST_RUNTIME_ONLY':'1','BXROOT_BINDS':invalid})
check('zero-clears-inherited', contains='EMPTY',extra={'BXROOT_BINDS':'/s:/g'})
check('R-full-refuses', ['/s:/g']*64,rc=2,contains='64',args=['-R','/'])
check('S-full-refuses', ['/s:/g']*64,rc=2,contains='64',args=['-S','/'])
check('prcfg-32-final-map',contains='PRCFG count=32 last=/source/31/probe',extra={'TEST_PRCFG_COUNT':'32'})
for n in (33,65):
    check('prcfg-'+str(n)+'-rejected',rc=127,contains='32-entry ABI',extra={'TEST_PRCFG_COUNT':str(n)})
print(f'TOTAL {checks} PASS; workspace source-level only; NOT Android acceptance')
