/* Real proc.c + host-world.c integration; only final execution is captured.
 * SPDX-License-Identifier: MIT */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define PX_PURE_LOGIC 0
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <spawn.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../../src/host/host-world.c"
static int capture_host_exec_mapped(const char *, char *const[], char *const[], bx_host_world_mapper);
/* Disable only automatic startup. Main installs an isolated runtime config. */
#define bx_host_world_exec_mapped capture_host_exec_mapped
#define constructor unused
#include "../../src/proc/proc.c"
#undef constructor
#undef bx_host_world_exec_mapped

#define TP 4096
#define AV 16
#define EV 128
static struct {
    int host, guest, spawn;
    char path[TP];
    char *argv[AV], *env[EV];
    const posix_spawn_file_actions_t *fa;
    const posix_spawnattr_t *attr;
    pid_t *pid;
} seen;
static char root[TP], host1[TP], host2[TP], override[TP], host_path[TP];
static char gnative[TP], gsame[TP], honly[TP], hsame[TP], bound[TP];
static char shadow_raw[TP], shadow_guest[TP], denied_raw[TP], denied_guest[TP];
static char cross_link[TP], prefixed_link[TP];
static char script_native[TP], script_denied[TP], script_interp[TP];
static int script_guest_interp;
static unsigned checks, failures, translations;
static int exec_error = EACCES, spawn_error;
static const pid_t child = 424242;
static char *const inenv[] = {
    "PATH=/usr/bin:/bin", "HOME=/root", "TMPDIR=/tmp", "PWD=/root", "OLDPWD=/",
    "LD_PRELOAD=/guest-extra.so", "LD_LIBRARY_PATH=/guest/lib", "LD_AUDIT=/audit.so",
    "BXROOT_ROOTFS=/stale", "BXROOT_LD_PRELOAD=/stale.so", "PROROOT_ROOTFS=/stale",
    "PROOT_TMP_DIR=/guest/tmp", "FOO=bar", "TERM=xterm", "ANDROID_ROOT=/guest", NULL
};
static void ck(int ok, const char *label) {
    checks++; if (!ok) { failures++; fprintf(stderr, "FAIL: %s\n", label); }
}
static void die(const char *s) { perror(s); exit(2); }
static void join(char *out, const char *a, const char *b) {
    int n = snprintf(out, TP, "%s/%s", a, b);
    if (n < 0 || n >= TP) { errno = ENAMETOOLONG; die("fixture path"); }
}
static void md(const char *p) { if (mkdir(p, 0700) && errno != EEXIST) die("mkdir"); }
static void put(unsigned char *p, uint64_t v, unsigned bytes) {
    unsigned i; for (i = 0; i < bytes; i++) p[i] = (unsigned char)(v >> (8*i));
}
/* A real ELF64/AArch64 header with PT_INTERP; never executed by this test. */
static void elf(const char *p, int bionic, mode_t mode) {
    unsigned char b[256] = {0};
    const char *it = bionic ? "/system/bin/linker64" : "/lib/ld-linux-aarch64.so.1";
    int fd; size_t n = strlen(it) + 1;
    memcpy(b, "\177ELF", 4); b[4] = 2; b[5] = 1; b[6] = 1;
    put(b+16, 3, 2); put(b+18, 183, 2); put(b+20, 1, 4);
    put(b+24, 0x1000, 8); put(b+32, 64, 8);
    put(b+52, 64, 2); put(b+54, 56, 2); put(b+56, 1, 2);
    put(b+64, 3, 4); put(b+72, 120, 8); put(b+96, n, 8); memcpy(b+120, it, n);
    fd = open(p, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, mode);
    if (fd < 0 || write(fd, b, sizeof(b)) != sizeof(b)) die("ELF fixture");
    if (close(fd) || chmod(p, mode)) die("ELF permissions");
}
static int prefix(const char *p, const char *a) {
    size_t n = strlen(a); return !strncmp(p,a,n) && (!p[n] || p[n]=='/');
}
/* Inject rootfs/bind mapping through the production translator interface. */
static int translate(void *ud, const char *p, char *out, size_t cap) {
    int n; (void)ud; translations++;
    if (!p) return -1;
    if (!strcmp(p,"/system/bin/sh")) {
        n=snprintf(out,cap,"%s",script_guest_interp ? bound : script_interp);
        return n>=0 && (size_t)n<cap ? 1 : -1;
    }
    if (!strcmp(p,shadow_raw)) {
        n=snprintf(out,cap,"%s",shadow_guest); return n>=0 && (size_t)n<cap ? 1 : -1;
    }
    if (!strcmp(p,denied_raw)) {
        n=snprintf(out,cap,"%s",denied_guest); return n>=0 && (size_t)n<cap ? 1 : -1;
    }
    if (!strcmp(p,"/native-alias")) {
        n=snprintf(out,cap,"%s",cross_link); return n>=0 && (size_t)n<cap ? 1 : -1;
    }
    if (!strcmp(p,"/prefixed-alias")) {
        n=snprintf(out,cap,"%s",prefixed_link); return n>=0 && (size_t)n<cap ? 1 : -1;
    }
    if (prefix(p,root) || prefix(p,host1) || prefix(p,host2) || prefix(p,override) || *p!='/') {
        n=snprintf(out,cap,"%s",p); return n>=0 && (size_t)n<cap ? 0 : -1;
    }
    if (!strcmp(p,"/system/bin/getprop")) n=snprintf(out,cap,"%s",bound);
    else if (!strcmp(p,"/bound/native")) n=snprintf(out,cap,"%s",honly);
    else n=snprintf(out,cap,"%s%s",root,p);
    return n>=0 && (size_t)n<cap ? 1 : -1;
}
static void freev(char **v) { size_t i; for (i=0;v[i];i++) { free(v[i]);v[i]=NULL; } }
static void copyv(char **out, size_t cap, char *const in[]) {
    size_t i=0; while (in && in[i]) {
        if (i+1>=cap) { errno=E2BIG;die("capture vector"); }
        out[i]=strdup(in[i]); if (!out[i]) die("strdup"); i++;
    } out[i]=NULL;
}
static void record(const char *p, char *const av[], char *const ev[]) {
    if (strlen(p)>=TP) { errno=ENAMETOOLONG;die("capture path"); }
    strcpy(seen.path,p);freev(seen.argv);freev(seen.env);
    copyv(seen.argv,AV,av);copyv(seen.env,EV,ev);
}
static const char *val(const char *name) {
    size_t i,n=strlen(name); for(i=0;seen.env[i];i++)
        if(!strncmp(seen.env[i],name,n) && seen.env[i][n]=='=') return seen.env[i]+n+1;
    return NULL;
}
static int eq(const char *a,const char *b) { return a && b && !strcmp(a,b); }
static int capture_host_exec_mapped(const char *p,char *const av[],char *const ev[],bx_host_world_mapper mapper) {
    bx_host_plan plan;char **clean=NULL;int k=bx_host_world_prepare_mapped(p,av,mapper,&plan);
    if(k<=0) { if(!k) errno=ENOEXEC;return -1; }
    if(bx_host_world_build_env(ev,&clean)) {
        int e=errno;bx_host_world_dispose(&plan);errno=e;return -1;
    }
    seen.host++;record(plan.target,(char *const*)plan.argv,clean);
    bx_host_world_free_env(clean);bx_host_world_dispose(&plan);errno=exec_error;return -1;
}
static int guest_exec(const char *p,char *const av[],char *const ev[]) {
    seen.guest++;record(p,av,ev);errno=exec_error;return -1;
}
static int spawn_spy(pid_t *pid,const char *p,const posix_spawn_file_actions_t *fa,
                     const posix_spawnattr_t *attr,char *const av[],char *const ev[]) {
    seen.spawn++;seen.pid=pid;seen.fa=fa;seen.attr=attr;record(p,av,ev);
    if(!spawn_error && pid) *pid=child;
    return spawn_error;
}
static void reset(void) {
    freev(seen.argv);freev(seen.env);memset(&seen,0,sizeof(seen));translations=0;
    exec_error=EACCES;spawn_error=0;script_guest_interp=0;px_ledger_clear(g_rt_ledger);
}
static void mode(const char *m) {
    reset();if(setenv("BXROOT_AUTO_HOST",m,1) || setenv("PATH","/usr/bin:/bin",1) ||
       setenv("BXROOT_HOST_PATH",host_path,1)) die("test configuration");
}
static void host_env(void) {
    ck(eq(val("FOO"),"bar"),"host preserves FOO");ck(eq(val("TERM"),"xterm"),"host preserves TERM");
    ck(eq(val("PATH"),host_path),"host PATH matches search configuration");
    ck(eq(val("ANDROID_ROOT"),"/system"),"host restores Android root");
    ck(eq(val("HOME"),getenv("BXROOT_HOST_HOME")),"host configured HOME");
    ck(eq(val("TMPDIR"),getenv("BXROOT_HOST_TMPDIR")),"host configured TMPDIR");
    ck(!val("LD_PRELOAD") && !val("LD_LIBRARY_PATH") && !val("LD_AUDIT"),"host drops loader env");
    ck(!val("BXROOT_ROOTFS") && !val("BXROOT_LD_PRELOAD") && !val("PROROOT_ROOTFS") &&
       !val("PROOT_TMP_DIR"),"host drops guest runtime env");
    ck(!val("PWD") && !val("OLDPWD"),"host drops fake cwd env");
}
static void guest_env(void) {
    const char *p=val("LD_PRELOAD");
    ck(p && strstr(p,"/test/guest-runtime.so"),"guest retains runtime preload");
    ck(p && strstr(p,"/guest-extra.so"),"guest retains caller preload");
    ck(eq(val("BXROOT_ROOTFS"),root),"guest retains rootfs identity");ck(eq(val("FOO"),"bar"),"guest retains FOO");
    if (px_auto_host()) {
        ck(eq(val("BXROOT_AUTO_HOST"),"1"),"guest inherits native auto mode even with clean env");
        ck(eq(val("BXROOT_HOST_PATH"),getenv("BXROOT_HOST_PATH")),"guest inherits native search configuration");
        ck(val("PATH") && strstr(val("PATH"),host1),"guest PATH prebuilt before startup");
    } else ck(!val("BXROOT_AUTO_HOST"),"disabled native mode injects no new auto configuration");
}
static void runtime_env_cases(void) {
    px_envout out={0};int r;
    char *clean[]={"FOO=clean-child",NULL};
    char *empty_path[]={"FOO=clean-child","PATH=",NULL};
    mode("1");r=px_runtime_build_env(clean,&out);
    ck(r==0 && out.v,"clean guest environment builds with native mode");
    if(r==0) {
        const char *v=px_env_lookup((const char *const*)out.v,"PATH");
        ck(eq(px_env_lookup((const char *const*)out.v,"BXROOT_AUTO_HOST"),"1"),"parent mode retained across caller's clean env");
        ck(v && strstr(v,BX_HOST_GUEST_DEFAULT_PATH)==v,"missing child PATH gains guest-first default");
        ck(eq(px_env_lookup((const char *const*)out.v,"BXROOT_HOST_PATH"),host_path),"clean child inherits parent host PATH");
        ck(eq(px_env_lookup((const char *const*)out.v,"FOO"),"clean-child"),"clean child ordinary env retained");
        px_env_dispose(&out);
    }
    mode("1");r=px_runtime_build_env(empty_path,&out);
    ck(r==0 && out.v,"explicit empty child PATH builds");
    if(r==0) {
        const char *v=px_env_lookup((const char *const*)out.v,"PATH");
        ck(v && v[0]==':' && strstr(v,host1),"explicit empty guest PATH retains cwd then host dirs");
        px_env_dispose(&out);
    }
    mode("1");if(setenv("BXROOT_HOST_PATH","",1)) die("empty parent HOST_PATH");
    r=px_runtime_build_env(clean,&out);
    ck(r==0 && out.v,"empty host PATH clean child builds");
    if(r==0) {
        ck(eq(px_env_lookup((const char *const*)out.v,"BXROOT_HOST_PATH"),""),"empty host PATH preserved, not reset to default");
        ck(eq(px_env_lookup((const char *const*)out.v,"PATH"),BX_HOST_GUEST_DEFAULT_PATH),"empty host PATH appends nothing");
        px_env_dispose(&out);
    }
    mode("0");r=px_runtime_build_env(clean,&out);
    ck(r==0 && out.v,"disabled mode clean child builds");
    if(r==0) {
        ck(!px_env_lookup((const char *const*)out.v,"PATH") && !px_env_lookup((const char *const*)out.v,"BXROOT_AUTO_HOST"),"AUTO0 preserves prior clean environment semantics");
        px_env_dispose(&out);
    }
    puts("CHECKED: guest initial env PATH / empty values / opt-in config lifetime");
}
static void exec_cases(void) {
    char *av[]={"CALLER-ARGV0","argument with spaces",NULL};int r;
    mode("1");r=px_do_execve(NULL,av,inenv,NULL,0);
    ck(r==-1 && errno==EFAULT && !seen.host && !seen.guest,"NULL path remains EFAULT before dispatch");
    mode("0");r=px_do_execve("/usr/bin/native",av,inenv,NULL,0);
    ck(r==-1 && errno==EACCES,"disabled exec preserves errno");
    ck(!seen.host && seen.guest==1,"AUTO_HOST=0 does not dispatch bionic");
    ck(eq(seen.path,gnative),"disabled exec keeps backing path");guest_env();
    mode("1");r=px_do_execve("/usr/bin/native",av,inenv,NULL,0);
    ck(r==-1 && errno==EACCES,"host exec preserves error errno");
    ck(seen.host==1 && !seen.guest,"AUTO_HOST=1 dispatches bionic");
    ck(eq(seen.path,gnative),"host exec preserves translated rootfs backing path");
    ck(eq(seen.argv[0],av[0]) && eq(seen.argv[1],av[1]) && !seen.argv[2],"host exec keeps argv0/argc/boundaries");host_env();
    mode("1");exec_error=ENOEXEC;r=px_do_execve(gnative,av,inenv,NULL,0);
    ck(r==-1 && errno==ENOEXEC,"host exec preserves ENOEXEC");
    ck(seen.host==1 && eq(seen.path,gnative),"already-prefixed backing path is not stripped/doubled");
    mode("true");(void)px_do_execve("/usr/bin/native",av,inenv,NULL,0);
    ck(!seen.host && seen.guest==1,"only exact AUTO_HOST=1 enables dispatch");
    mode("1");r=px_do_execve("collision",av,inenv,"/usr/bin",1);
    ck(r==-1 && !seen.host && seen.guest==1,"guest same-name program wins");
    ck(eq(seen.path,gsame),"guest PATH selects guest file");guest_env();
    mode("1");r=px_do_execve("only-native",av,inenv,"/usr/bin",1);
    ck(r==-1 && seen.host==1 && !seen.guest,"guest miss uses host PATH");
    ck(eq(seen.path,honly) && eq(seen.argv[0],av[0]),"host fallback keeps target and argv0");host_env();
    mode("0");r=px_do_execve("only-native",av,inenv,"/usr/bin",1);
    ck(r==-1 && errno==ENOENT && !seen.host && !seen.guest,"disabled exec does not search host PATH");
    mode("1");r=px_do_execve("/not-there/only-native",av,inenv,"/usr/bin",1);
    ck(r==-1 && errno==ENOENT && !seen.host && !seen.guest,"slash target never falls back by basename");
    mode("1");(void)px_do_execve("/system/bin/getprop",av,inenv,NULL,0);
    ck(translations && !seen.host && seen.guest==1,"glibc bind override remains guest");
    ck(eq(seen.path,bound),"bind override uses mapped file");guest_env();
    mode("1");(void)px_do_execve("/bound/native",av,inenv,NULL,0);
    ck(seen.host==1 && eq(seen.path,honly),"bionic bind uses mapped backing file");
    mode("1");if(setenv("BXROOT_HOST_PATH","",1)) die("empty PATH");
    r=px_do_execve("only-native",av,inenv,"/usr/bin",1);
    ck(r==-1 && errno==ENOENT && !seen.host && !seen.guest,"empty host PATH disables fallback");
    mode("1");r=px_do_execve("skip-denied",av,inenv,"/usr/bin",1);
    { char p[TP];join(p,host2,"skip-denied");ck(r==-1 && seen.host==1 && eq(seen.path,p),"host PATH skips non-executable ELF"); }
    mode("1");r=px_do_execve("denied-only",av,inenv,"/usr/bin",1);
    ck(r==-1 && errno==EACCES && !seen.host && !seen.guest,"denied-only host PATH returns EACCES");
    mode("1");r=px_do_execve("bind-shadow",av,inenv,"/usr/bin",1);
    ck(r==-1 && errno==ENOENT && !seen.host && !seen.guest,"host fallback never bypasses a glibc bind override");
    mode("1");r=px_do_execve("bind-denied",av,inenv,"/usr/bin",1);
    ck(r==-1 && errno==EACCES && !seen.host && !seen.guest,"host fallback checks mapped X_OK instead of raw namesake");
    mode("1");r=px_do_execve("cross-link",av,inenv,"/usr/bin",1);
    ck(r==-1 && seen.host==1 && eq(seen.path,honly),"fallback absolute link resolves cross-bind native backing");
    mode("1");r=px_do_execve("/native-alias",av,inenv,NULL,0);
    ck(r==-1 && seen.host==1 && eq(seen.path,honly),"explicit absolute link resolves cross-bind native backing");
    mode("1");r=px_do_execve("/prefixed-alias",av,inenv,NULL,0);
    ck(r==-1 && seen.host==1 && eq(seen.path,gnative),"absolute link already-prefixed target remains idempotent");
    mode("1");r=px_do_execve(prefixed_link,av,inenv,NULL,0);
    ck(r==-1 && seen.host==1 && eq(seen.path,gnative),"already-prefixed link path does not duplicate rootfs");
    mode("1");r=px_do_execve("/usr/bin/native-script",av,inenv,NULL,0);
    ck(r==-1 && seen.host==1 && eq(seen.path,script_interp),"native script uses mapped bionic interpreter");
    ck(eq(seen.argv[1],"-e") && eq(seen.argv[2],script_native) && eq(seen.argv[3],av[1]),"native script argv preserves option, backing script and caller tail");
    mode("1");script_guest_interp=1;r=px_do_execve("/usr/bin/native-script",av,inenv,NULL,0);
    ck(r==-1 && !seen.host && seen.guest==1 && eq(seen.path,bound),"glibc interpreter bind keeps script in guest world");guest_env();
    mode("1");r=px_do_execve("/usr/bin/denied-script",av,inenv,NULL,0);
    ck(r==-1 && errno==EACCES && !seen.host && !seen.guest,"0644 native script cannot bypass execution permission");
    puts("CHECKED: real px_do_execve backing paths, guest priority, fallback, env and errors");
}
static void spawn_cases(void) {
    posix_spawn_file_actions_t fa;posix_spawnattr_t attr;
    char *av[]={"SPAWN-ARGV0","spawn argument",NULL};pid_t pid;int r;
    if(posix_spawn_file_actions_init(&fa) || posix_spawnattr_init(&attr) ||
       posix_spawn_file_actions_addclose(&fa,99) || posix_spawnattr_setflags(&attr,POSIX_SPAWN_SETPGROUP) ||
       posix_spawnattr_setpgroup(&attr,0)) die("spawn fixtures");
    mode("1");pid=-77;r=px_do_spawn(&pid,"/usr/bin/native",&fa,&attr,av,inenv,0);
    ck(r==0 && pid==child && seen.spawn==1,"host spawn returns successful pid");
    ck(seen.pid==&pid && seen.fa==&fa && seen.attr==&attr,"spawn forwards actions/attr/pid unchanged");
    ck(eq(seen.path,gnative) && eq(seen.argv[0],av[0]) && eq(seen.argv[1],av[1]) && !seen.argv[2],"spawn preserves backing path and argv");
    ck(px_ledger_has(g_rt_ledger,child,PX_ENTRY_PID),"spawn registers successful child");host_env();
    mode("0");pid=-77;r=px_do_spawn(&pid,"/usr/bin/native",&fa,&attr,av,inenv,0);
    ck(r==0 && seen.spawn==1 && eq(seen.path,gnative),"disabled spawn keeps guest path");guest_env();
    mode("1");pid=-77;spawn_error=EAGAIN;r=px_do_spawn(&pid,"/usr/bin/native",&fa,&attr,av,inenv,0);
    ck(r==EAGAIN && pid==-77 && seen.spawn==1,"spawn returns error number and leaves pid alone");
    ck(!px_ledger_has(g_rt_ledger,child,PX_ENTRY_PID),"failed spawn not registered");
    mode("1");pid=-77;r=px_do_spawn(&pid,gnative,NULL,NULL,av,inenv,0);
    ck(r==0 && eq(seen.path,gnative) && !seen.fa && !seen.attr,"spawn supports prefixed path and NULL attr/actions");host_env();
    mode("1");pid=-77;r=px_do_spawn(&pid,"collision",&fa,&attr,av,inenv,1);
    ck(r==0 && seen.spawn==1 && eq(seen.path,gsame),"spawnp prefers guest namesake");guest_env();
    mode("1");pid=-77;r=px_do_spawn(&pid,"only-native",&fa,&attr,av,inenv,1);
    ck(r==0 && seen.spawn==1 && eq(seen.path,honly),"spawnp uses host fallback");
    ck(seen.fa==&fa && seen.attr==&attr && eq(seen.argv[0],av[0]),"spawnp fallback keeps actions/attr/argv0");host_env();
    mode("1");pid=-77;r=px_do_spawn(&pid,"/system/bin/getprop",&fa,&attr,av,inenv,0);
    ck(r==0 && eq(seen.path,bound),"spawn honors glibc bind override");guest_env();
    mode("0");pid=-77;r=px_do_spawn(&pid,"only-native",&fa,&attr,av,inenv,1);
    ck(r==ENOENT && pid==-77 && !seen.spawn,"disabled spawnp does not use host fallback");
    mode("1");pid=-77;r=px_do_spawn(&pid,"denied-only",&fa,&attr,av,inenv,1);
    ck(r==EACCES && pid==-77 && !seen.spawn,"spawnp returns EACCES error number");
    mode("1");pid=-77;r=px_do_spawn(&pid,"bind-shadow",&fa,&attr,av,inenv,1);
    ck(r==ENOENT && pid==-77 && !seen.spawn,"spawnp fallback honors glibc bind override");
    mode("1");pid=-77;r=px_do_spawn(&pid,"bind-denied",&fa,&attr,av,inenv,1);
    ck(r==EACCES && pid==-77 && !seen.spawn,"spawnp fallback checks mapped execution permissions");
    mode("1");pid=-77;r=px_do_spawn(&pid,"cross-link",&fa,&attr,av,inenv,1);
    ck(r==0 && seen.spawn==1 && eq(seen.path,honly),"spawnp fallback resolves cross-bind absolute link");
    mode("1");pid=-77;r=px_do_spawn(&pid,"/native-alias",&fa,&attr,av,inenv,0);
    ck(r==0 && seen.spawn==1 && eq(seen.path,honly),"explicit spawn resolves cross-bind absolute link");
    mode("1");pid=-77;r=px_do_spawn(&pid,prefixed_link,&fa,&attr,av,inenv,0);
    ck(r==0 && seen.spawn==1 && eq(seen.path,gnative),"spawn already-prefixed absolute link remains idempotent");
    mode("1");pid=-77;r=px_do_spawn(&pid,"/usr/bin/native-script",&fa,&attr,av,inenv,0);
    ck(r==0 && seen.spawn==1 && eq(seen.path,script_interp),"spawn native script uses mapped bionic interpreter");
    ck(eq(seen.argv[1],"-e") && eq(seen.argv[2],script_native),"spawn native script uses correct option and backing file");
    mode("1");script_guest_interp=1;pid=-77;r=px_do_spawn(&pid,"/usr/bin/native-script",&fa,&attr,av,inenv,0);
    ck(r==0 && seen.spawn==1 && eq(seen.path,bound),"spawn honors glibc interpreter bind override");guest_env();
    mode("1");pid=-77;r=px_do_spawn(&pid,"/usr/bin/denied-script",&fa,&attr,av,inenv,0);
    ck(r==EACCES && pid==-77 && !seen.spawn,"spawn rejects 0644 native script before interpreter launch");
    {
        char original[TP], dir[TP];posix_spawn_file_actions_t cwd_actions;
        if(!getcwd(original,sizeof(original))) die("original cwd");
        strcpy(dir,gnative);*strrchr(dir,'/')='\0';
        if(chdir(dir) || posix_spawn_file_actions_init(&cwd_actions) ||
           posix_spawn_file_actions_addchdir_np(&cwd_actions,"./different-child-cwd")) die("relative spawn cwd fixture");
        mode("1");pid=-77;r=px_do_spawn(&pid,"native",&cwd_actions,NULL,av,inenv,0);
        ck(r==0 && seen.spawn==1 && eq(seen.path,"native"),"relative spawn target is not parent-cwd native routed");
        guest_env();
        if(chdir(original) || posix_spawn_file_actions_destroy(&cwd_actions)) die("restore cwd");
    }
    if(posix_spawn_file_actions_destroy(&fa) || posix_spawnattr_destroy(&attr)) die("spawn destroy");
    puts("CHECKED: real px_do_spawn/spawnp actions, backing paths, env, ledger and rc");
}
int main(int argc,char **argv) {
    char p[TP],d[TP];size_t i;
    static const char *const clear[]={"PROROOT_TRAMPOLINE_PATH","PROROOT_LINKER_PATH",
        "PROROOT_LIB_PATH","PROROOT_STUB_LOADER","BXROOT_STUB_LOADER_EXEC",
        "BXROOT_ULX_PATH","BXROOT_ULX_LDSO","BXROOT_KILL_ON_EXIT",NULL};
    if(argc!=2 || argv[1][0]!='/') { fprintf(stderr,"usage: probe_proc_host <absolute temporary dir>\n");return 2; }
    for(i=0;clear[i];i++) if(unsetenv(clear[i])) die("clear trampoline");
    join(root,argv[1],"guest-root");md(root);join(d,root,"usr");md(d);join(p,d,"bin");md(p);
    join(gnative,p,"native");elf(gnative,1,0700);join(gsame,p,"collision");elf(gsame,0,0700);
    join(host1,argv[1],"host-one");md(host1);join(host2,argv[1],"host-two");md(host2);
    join(override,argv[1],"bind-override");md(override);join(bound,override,"getprop");elf(bound,0,0700);
    join(honly,host1,"only-native");elf(honly,1,0700);join(hsame,host1,"collision");elf(hsame,1,0700);
    join(p,host1,"getprop");elf(p,1,0700);join(p,host1,"skip-denied");elf(p,1,0600);
    join(p,host2,"skip-denied");elf(p,1,0700);join(p,host1,"denied-only");elf(p,1,0600);
    join(script_interp,host1,"native-shell");elf(script_interp,1,0700);
    join(script_native,root,"usr/bin/native-script");
    join(script_denied,root,"usr/bin/denied-script");
    {
        const char script[]="#!/system/bin/sh -e\nignored-by-spy\n";
        int fd=open(script_native,O_WRONLY|O_CREAT|O_TRUNC,0700);
        if(fd<0 || write(fd,script,sizeof(script)-1)!=(ssize_t)sizeof(script)-1 || close(fd)) die("native script fixture");
        fd=open(script_denied,O_WRONLY|O_CREAT|O_TRUNC,0600);
        if(fd<0 || write(fd,script,sizeof(script)-1)!=(ssize_t)sizeof(script)-1 || close(fd)) die("denied script fixture");
    }
    join(shadow_raw,host1,"bind-shadow");elf(shadow_raw,1,0700);
    join(shadow_guest,override,"bind-shadow");elf(shadow_guest,0,0700);
    join(denied_raw,host1,"bind-denied");elf(denied_raw,1,0700);
    join(denied_guest,override,"bind-denied");elf(denied_guest,1,0600);
    join(cross_link,host1,"cross-link");
    if (symlink("/bound/native",cross_link)) die("cross-bind absolute symlink");
    join(prefixed_link,host1,"prefixed-link");
    if (symlink(gnative,prefixed_link)) die("prefixed absolute symlink");
    if(snprintf(host_path,sizeof(host_path),"%s:%s",host1,host2)>=(int)sizeof(host_path)) { errno=ENAMETOOLONG;die("host PATH"); }
    if(setenv("BXROOT_HOST_HOME",argv[1],1) || setenv("BXROOT_HOST_TMPDIR",argv[1],1)) die("host dirs");
    memset(&g_rt_cfg,0,sizeof(g_rt_cfg));g_rt_ready=1;g_rt_cfg.inject=1;
    g_rt_cfg.have_rootfs=g_rt_cfg.have_preload=1;
    px_cfg_str(g_rt_cfg.rootfs,sizeof(g_rt_cfg.rootfs),root);
    px_cfg_str(g_rt_cfg.preload,sizeof(g_rt_cfg.preload),"/test/guest-runtime.so");
    g_rt_ledger=px_ledger_create(64,NULL);if(!g_rt_ledger) die("ledger");
    px_runtime_set_translator(translate,NULL);real_execve=guest_exec;real_posix_spawn=spawn_spy;
    ck(bx_host_world_classify(gnative)==BX_HOST_WORLD_BIONIC,"real classifier reads bionic fixture");
    ck(bx_host_world_classify(gsame)==BX_HOST_WORLD_NO,"real classifier rejects glibc fixture");
    exec_cases();spawn_cases();runtime_env_cases();reset();px_ledger_destroy(g_rt_ledger);g_rt_ledger=NULL;
    printf("RESULT: %s (%u checks, %u failures)\n",failures?"FAIL":"PASS",checks,failures);
    return failures?1:0;
}
