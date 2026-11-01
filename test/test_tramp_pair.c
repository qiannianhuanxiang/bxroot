#include <stdio.h>
#include <string.h>
#include "../src/proc/tramp-config.h"

static int failures;

static int same(const char *actual, const char *expected)
{
    return actual != 0 && expected != 0 && strcmp(actual, expected) == 0;
}

static void check(int condition, const char *name)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", name);
        failures++;
    }
}

int main(void)
{
    const char *tramp = 0, *linker = 0;
    int kind;

    kind = bxroot_tramp_pair_select("own-ulx", "own-ldso", 1, 0, 0,
                                    "derived-ulx", "derived-ldso",
                                    "outer-bridge", "outer-ldso", &tramp, &linker);
    check(kind == BXROOT_TRAMP_OWN && same(tramp, "own-ulx") &&
          same(linker, "own-ldso"), "complete own pair wins");

    kind = bxroot_tramp_pair_select("own-ulx", 0, 1, 0, 0,
                                    "derived-ulx", "derived-ldso",
                                    "outer-bridge", "outer-ldso", &tramp, &linker);
    check(kind == BXROOT_TRAMP_DERIVED && same(tramp, "own-ulx") &&
          same(linker, "derived-ldso"), "partial own config completes from own derivation");

    kind = bxroot_tramp_pair_select("own-ulx", 0, 1, 0, 0,
                                    0, 0,
                                    "outer-bridge", "outer-ldso", &tramp, &linker);
    check(kind == BXROOT_TRAMP_NONE && same(tramp, "own-ulx") && linker == 0,
          "partial own config never mixes outer pair");

    kind = bxroot_tramp_pair_select(0, 0, 0, 0, 0,
                                    0, 0,
                                    "outer-bridge", "outer-ldso", &tramp, &linker);
    check(kind == BXROOT_TRAMP_OUTER && same(tramp, "outer-bridge") &&
          same(linker, "outer-ldso"), "complete outer pair remains supported");

    kind = bxroot_tramp_pair_select(0, 0, 0, 0, 0,
                                    "derived-ulx", "derived-ldso",
                                    "outer-bridge", "outer-ldso", &tramp, &linker);
    check(kind == BXROOT_TRAMP_DERIVED && same(tramp, "derived-ulx") &&
          same(linker, "derived-ldso"), "derived own pair beats outer pair");

    kind = bxroot_tramp_pair_select(0, 0, 0, 0, 0,
                                    0, 0,
                                    "outer-bridge", 0, &tramp, &linker);
    check(kind == BXROOT_TRAMP_NONE && tramp == 0 && linker == 0,
          "partial outer pair is rejected");

    puts(failures == 0 ? "TRAMP_PAIR_PASS" : "TRAMP_PAIR_FAIL");
    return failures == 0 ? 0 : 1;
}
