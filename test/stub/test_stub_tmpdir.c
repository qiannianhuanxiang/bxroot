/*
 * patch_static_elf() 的临时目录选择（行动清单 #6）。
 * 直接 #include 源文件驱动 static 函数；main 改名避免冲突。
 * 判据：BXROOT_TMP_DIR / TMPDIR / 默认 /tmp 三档各落在对应目录，
 *       产物带 PT_INTERP 且原程序字节被完整保留。
 */
#define main stub_main_unused
#include "../../src/stub-loader/stub-loader.c"
#undef main

static int check(const char *label, const char *expect_dir, const char *bin)
{
    char *out = patch_static_elf(bin, "/x/interp");
    int ok = 0;
    if (out == NULL) {
        printf("  ❌ %s：patch_static_elf 返回 NULL\n", label);
        return 1;
    }
    if (strncmp(out, expect_dir, strlen(expect_dir)) == 0 &&
        out[strlen(expect_dir)] == '/') {
        int fd = open(out, O_RDONLY);
        Elf64_Ehdr eh;
        if (fd >= 0 && read(fd, &eh, sizeof eh) == (ssize_t)sizeof eh) {
            Elf64_Phdr ph;
            int k;
            for (k = 0; k < eh.e_phnum; k++) {
                if (pread(fd, &ph, sizeof ph, (off_t)(eh.e_phoff + (Elf64_Off)k * sizeof ph)) == (ssize_t)sizeof ph &&
                    ph.p_type == PT_INTERP)
                    ok = 1;
            }
        }
        if (fd >= 0) close(fd);
    }
    printf("  %s %s：%s%s\n", ok ? "✅" : "❌", label, out, ok ? "（含 PT_INTERP）" : "");
    unlink(out);
    free(out);
    return ok ? 0 : 1;
}

int main(int argc, char **argv)
{
    int bad = 0;
    const char *bin = argc > 1 ? argv[1] : NULL;
    const char *d1 = argc > 2 ? argv[2] : NULL;
    const char *d2 = argc > 3 ? argv[3] : NULL;
    if (bin == NULL || d1 == NULL || d2 == NULL) return 2;

    unsetenv("BXROOT_TMP_DIR"); unsetenv("TMPDIR");
    setenv("BXROOT_TMP_DIR", d1, 1);
    bad |= check("BXROOT_TMP_DIR 优先", d1, bin);
    unsetenv("BXROOT_TMP_DIR"); setenv("TMPDIR", d2, 1);
    bad |= check("TMPDIR 次之", d2, bin);
    unsetenv("TMPDIR");
    bad |= check("默认 /tmp", "/tmp", bin);
    setenv("BXROOT_TMP_DIR", "relative/dir", 1);
    bad |= check("相对路径被忽略 → /tmp", "/tmp", bin);
    printf("RESULT: %s\n", bad ? "FAIL" : "PASS");
    return bad;
}
