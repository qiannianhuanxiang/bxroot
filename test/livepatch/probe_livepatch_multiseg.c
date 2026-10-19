/*
 * probe_livepatch_multiseg.c —— livepatch 对"多段 r-x 的 libc"的判别性探针
 *
 * 【钉住的缺陷（2026-10-09 真机，DSHA 的 glibc 2.39-0ubuntu8.5）】
 * 版本表按 8.9 登记，对 8.5 一个站点都没命中，却把相关页 mprotect 成 RWX
 * 且不复位，libc 的 r-x 映射被劈成多段。旧的运行期扫描只取 /proc/self/maps
 * 里 libc.so.6 的**第一个** r-x 段，99/293 站点恰在后段 → 扫描 0 命中 →
 * 新线程里 rseq/set_robust_list 撞 seccomp，SIGSYS(159) 杀进程。
 *
 * 本探针造一个自称 "libc.so.6" 的多段映射：
 *   段 A（先出现，r-x）：全是 nop，没有站点
 *   段 B（后出现，r-x）：放 mov x8,#99 + svc、mov x8,#293 + svc
 * 然后调用真实的 bxroot_livepatch_apply()，断言 B 段里的两个 svc 被改成
 * mov x0,#0。旧实现只扫段 A，B 段原样不动 → 本探针变红。
 *
 * 做法：把一个以 "libc.so.6" 结尾的临时文件 mmap 成两段相邻的 r-x（中间用
 * 不同的文件偏移，使内核在 maps 里分成两行），再让 livepatch 去扫。
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <unistd.h>

int bxroot_livepatch_apply(void);
int bxroot_livepatch_scan_hits(void);

#define MOV_X0_0 0xd2800000u
#define SVC      0xd4000001u
#define NOP      0xd503201fu
static uint32_t movx8(int nr) { return 0xd2800008u | ((uint32_t)(nr & 0xffff) << 5); }

static int fail;
static void expect(const char *tag, uint32_t got, uint32_t want)
{
    if (got != want) { printf("FAIL %s = %#x 期望 %#x\n", tag, got, want); fail = 1; }
    else printf("OK %s = %#x\n", tag, got);
}

int main(void)
{
    char dir[64];
    char libc_path[128];
    long pg = sysconf(_SC_PAGESIZE);
    size_t seg = (size_t)pg;
    uint8_t *page;
    int fd;
    uint32_t *a, *b;
    size_t k;

    if (mkdtemp(strcpy(dir, "/tmp/bxroot-ms-XXXXXX")) == NULL) { perror("mkdtemp"); return 2; }
    snprintf(libc_path, sizeof libc_path, "%s/libc.so.6", dir);

    fd = open(libc_path, O_RDWR | O_CREAT | O_TRUNC, 0755);
    if (fd < 0) { perror("open"); return 2; }
    page = calloc(1, seg * 3);
    if (page == NULL) return 2;
    /* 文件布局：[0,seg) 段A=nop  [seg,2seg) 空洞(不映射)  [2seg,3seg) 段B=站点 */
    for (k = 0; k < seg / 4; k++) ((uint32_t *)page)[k] = NOP;
    {
        uint32_t *w = (uint32_t *)(page + 2 * seg);
        for (k = 0; k < seg / 4; k++) w[k] = NOP;
        w[0] = movx8(99);  w[1] = NOP; w[2] = NOP; w[3] = SVC;     /* set_robust_list */
        w[8] = movx8(293); w[9] = SVC;                              /* rseq */
    }
    if (write(fd, page, seg * 3) != (ssize_t)(seg * 3)) { perror("write"); return 2; }

    /* 先占一块连续地址，再用 MAP_FIXED 分别把文件的两个不同偏移映射进去，
     * 两段之间隔一页空洞 → maps 里是两行 libc.so.6 的 r-x。 */
    {
        uint8_t *base = mmap(NULL, seg * 3, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (base == MAP_FAILED) { perror("mmap base"); return 2; }
        a = mmap(base, seg, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED, fd, 0);
        b = mmap(base + 2 * seg, seg, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED, fd, 2 * seg);
        if (a == MAP_FAILED || b == MAP_FAILED) { perror("mmap seg"); return 2; }
    }
    printf("段A=%p 段B=%p\n", (void *)a, (void *)b);

    /*
     * ★ 本探针必须自己装一个 seccomp 过滤器（缺陷修复，2026-10-20）★
     *
     * bxroot_livepatch_apply() 的门控③是"有 seccomp 过滤器才干活"：没有
     * 白名单要绕，这一层没有收益，直接返回 LP_SKIP_NO_SECCOMP。这对生产
     * 是正确取舍（非 Android 环境不必改 libc 代码页）。
     *
     * 但本探针此前**假设运行环境自带过滤器**：开发容器里跑在外层 proroot
     * 下，/proc/self/status 显示 Seccomp:2，于是恒 PASS；GitHub 的
     * ubuntu-24.04-arm runner 没有过滤器（Seccomp:0），apply() 直接跳过，
     * scan_hits=0，两段 svc 原样不动 → 测试红。同一份源码、同一架构，
     * 结果却取决于宿主，这正是"测试泄漏了环境前提"的典型。
     *
     * 装一个什么都不拦的允许型过滤器即可满足门控，且不改变探针语义：
     * 被测的是"扫描是否覆盖全部 r-x 段"，不是过滤器本身。
     */
    /*
     * 只在确实没有过滤器时装：已有过滤器的宿主（如本仓库开发容器）保持
     * 原状，测试结果不受这只探针干扰；没有的宿主补上，门控③才能通过。
     */
    if (prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != 2) {
        struct sock_filter allow_all[] = {
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog prog;
        int ok = 1;

        prog.len = (unsigned short)(sizeof allow_all / sizeof allow_all[0]);
        prog.filter = allow_all;
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
            perror("PR_SET_NO_NEW_PRIVS");
            ok = 0;
        } else if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
            perror("PR_SET_SECCOMP");
            ok = 0;
        }
        if (!ok) {
            /*
             * 装不上就**明确跳过**，不要报 FAIL。
             *
             * 判据：门控③在无过滤器时会直接跳过扫描，此时两段 svc 必然
             * 原样不动 —— 那是环境不满足，不是产品缺陷。报 FAIL 会让
             * 真正想看的"多段扫描"信号被环境噪声淹没。
             * 退出码 2 是本仓库约定的"前置条件不满足"。
             */
            printf("SKIP: 无法安装 seccomp 过滤器，livepatch 门控③不会启用\n");
            return 2;
        }
    }
    printf("seccomp 就绪（Seccomp=%ld）\n", prctl(PR_GET_SECCOMP, 0, 0, 0, 0));

    /*
     * 先在失败机器上把判决依据打出来。
     *
     * 本探针在开发容器里稳定 PASS，但在 GitHub 的 ubuntu-24.04-arm runner
     * 上 scan_hits=0 —— 同一份源码、同样 aarch64，差别只可能落在
     * /proc/self/maps 的呈现（设备/路径/行内字段）或 mprotect 是否允许。
     * 只报 "FAIL 段B ... 期望 0xd2800000" 无法区分这两类，所以这里把
     * 解析器实际看到的 libc r-x 段数、以及 apply() 的返回值都打印出来。
     */
    {
        FILE *mf = fopen("/proc/self/maps", "r");
        int segs = 0, v6 = 0;
        char ln[1024];
        if (mf != NULL) {
            while (fgets(ln, sizeof ln, mf) != NULL) {
                if (strstr(ln, "libc.so.6") == NULL) continue;
                v6++;
                if (strstr(ln, " r-x") != NULL || strstr(ln, "-") == ln) segs++;
            }
            fclose(mf);
        }
        printf("maps: libc.so.6 行=%d r-x 行≈%d\n", v6, segs);
    }

    {
        int rc = bxroot_livepatch_apply();
        printf("livepatch_apply=%d\n", rc);
    }

    expect("段B set_robust_list svc", b[3], MOV_X0_0);
    expect("段B rseq svc", b[9], MOV_X0_0);
    printf("scan_hits=%d\n", bxroot_livepatch_scan_hits());

    unlink(libc_path);
    rmdir(dir);
    printf(fail ? "RESULT: FAIL\n" : "RESULT: PASS\n");
    return fail;
}
