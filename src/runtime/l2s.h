/*
 * l2s.h -- link-to-symlink (l2s) hard-link emulation, pure-logic core.
 *
 * On filesystems that refuse link(2) (Android FUSE, app-private dirs under
 * SELinux), a runtime fakes hard links with a three-level structure:
 *
 *      guest path  --symlink-->  intermediate  --symlink-->  final (real data)
 *
 * This module contains ONLY the naming algebra of that structure.  It never
 * calls into the filesystem: every function is a pure function of its
 * arguments.  Creating the links, deciding which generation number is free,
 * renaming on unlink and detecting dangling chains all need real syscalls and
 * are deliberately out of scope (see REPORT.md, section "what pure logic
 * cannot do").
 *
 * The rules implemented here are transcribed from the upstream 参考实现
 * extension src/extension/link2symlink/link2symlink.c, and cross-checked
 * against a live artifact of the 参考实现 instance this container runs under
 * (see L2S_GROUND_TRUTH_* below and test_l2s.c).
 *
 * Reference (upstream 参考实现, GPL-2.0+), the lines this module mirrors:
 *
 *   #define PREFIX ".proot.l2s."   (USERLAND build)
 *   #define PREFIX ".l2s."         (normal build)
 *
 *   // move_and_symlink_path(), first link:
 *   sprintf(new_intermediate, "%s%04d", intermediate, intermediate_suffix);
 *   strcpy(final, intermediate);
 *   strcat(final, ".0002");
 *   l2s_rename(original, final);          // data moves to `final`
 *   l2s_symlink(final, intermediate);     // intermediate -> final
 *   symlink(intermediate, original);      // guest path  -> intermediate
 *
 *   // move_and_symlink_path(), subsequent links:
 *   link_count = atoi(final + strlen(final) - 4);
 *   link_count++;
 *   strncpy(new_final, final, strlen(final) - 4);
 *   sprintf(new_final + strlen(final) - 4, "%04d", link_count);
 *   l2s_rename(final, new_final);         // the DATA FILE is renamed
 *   l2s_unlink(intermediate);
 *   l2s_symlink(new_final, intermediate); // only this symlink is repointed
 *
 *   // handle_sysexit_end(): faked st_nlink
 *   finalStat.st_nlink = atoi(final + strlen(final) - 4);
 *
 *   // is_l2s_file()
 *   name has PREFIX, and name[len-5] == '.', and the last 4 are digits
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef L2S_H
#define L2S_H

#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Limits and constants                                                */
/* ------------------------------------------------------------------ */

/* Same value as PATH_MAX on Linux; a path of exactly this length has no
 * room for the terminating NUL, so buffers are L2S_PATH_MAX bytes and the
 * longest usable string is L2S_PATH_MAX - 1. */
#define L2S_PATH_MAX 4096

/* Longest single path component we will handle, incl. the NUL.  NAME_MAX
 * is 255 on Linux; the l2s prefix and suffixes are added on top only when
 * the intermediate lives next to the original, and that case is rejected
 * with L2S_ENAMETOOLONG rather than truncated. */
#define L2S_NAME_MAX 256

/* Number of decimal digits 参考实现 uses for the generation and for the link
 * count: "%04d" in both places. */
#define L2S_DIGITS 4

/* Generation search bounds, from the do/while in move_and_symlink_path():
 *     intermediate_suffix = 1;
 *     do { sprintf(..., "%04d", intermediate_suffix++); }
 *     while (l2s_access(...) != -1 && intermediate_suffix < 1000);
 * so the searched range is 1..999 and 1000 is reachable only as the
 * give-up value. */
#define L2S_GEN_FIRST 1
#define L2S_GEN_LAST 999
#define L2S_GEN_GIVEUP 1000

/* Largest link count the 4-digit field can hold. */
#define L2S_NLINK_MAX 9999

/* The two spellings of the 参考实现 prefix.  A normal 参考实现 build uses
 * ".l2s."; the USERLAND build uses ".proot.l2s.".  Both are recognised on
 * input so that a rootfs written by either build can be read back. */
#define L2S_PREFIX ".l2s."
#define L2S_PREFIX_USERLAND ".proot.l2s."

/* Directory 参考实现 keeps its intermediates in when PROOT_L2S_DIR is set.
 * The entries inside are named PREFIX + basename + generation, and the
 * final data file is that name plus "." + 4 digits. */
#define L2S_DEFAULT_DIR "/.l2s"

/*
 * 参考实现的元数据树.
 *
 * All of the following was read out of the compiled
 * libproroot-runtime.so v1.2.8 (sha256 8c47a0a7db32d84c179ebb5bf3640f65
 * 5a3181860ece5886ae44d92858730c34, byte-identical to the published
 * release asset) and is reported here as STRUCTURE ONLY.  proroot's
 * scheme is not proot's: it is a hash-keyed metadata tree, and the two
 * are mutually unintelligible -- see REPORT.md.
 *
 *   <rootfs>/.proroot-meta/          flat, mode 0755, no subdirectories
 *     g_<16hex>                      a "symlink group": newline-separated
 *                                    records, anchor first, then members
 *     m_<16hex>                      legacy: a per-member marker file
 *     <16hex>[_<k>]                  legacy: bare key, k = 1-based member
 *     <entry>.cnt                    legacy: decimal refcount sidecar
 */
#define L2S_PROROOT_META_DIR "/.proroot-meta"
#define L2S_PROROOT_KEY_LEN 16
#define L2S_PROROOT_PREFIX_GROUP "g_"
#define L2S_PROROOT_PREFIX_MEMBER "m_"
/* from the ".cnt" literal at .rodata:0x38358, used by
 * legacy_write_refcount() / legacy_read_refcount() */
#define L2S_PROROOT_CNT_SUFFIX ".cnt"
/* MAX_MEMBERS: the gate at 0x32598 is `cmp w0, #0x1f; b.gt -> reject`,
 * i.e. 32 records total = 1 anchor + 31 members, and the reject path
 * returns -ENOSPC (-28).  That is the bug the v1.2.8 release note
 * describes as "ENOSPC despite ample free space".  Not enforced here --
 * it belongs to the group store, not to the naming algebra. */
#define L2S_PROROOT_MAX_MEMBERS 32

/* ------------------------------------------------------------------ */
/* Error codes                                                         */
/* ------------------------------------------------------------------ */

/*
 * All of them are negative and distinct from -1, so that l2s_ERR can be
 * told apart from a real errno value and so that callers can use the
 * standard `if (rc < 0)` idiom.  They are deliberately NOT errno values:
 * this module makes no syscalls, and a caller that wants to surface
 * ENAMETOOLONG should map it explicitly.
 */
#define L2S_OK 0
#define L2S_ERR (-1)          /* generic / malformed input            */
#define L2S_ENAMETOOLONG (-2) /* result would not fit the buffers      */
#define L2S_ENOTL2S (-3)      /* input is not an l2s name              */
#define L2S_ERANGE (-4)       /* generation or link count out of range */
#define L2S_EBADNAME (-5)     /* component is "." / ".." / empty       */

/* ------------------------------------------------------------------ */
/* Schemes                                                             */
/* ------------------------------------------------------------------ */

typedef enum {
    /* 参考实现, the format this module is written against. */
    L2S_SCHEME_PROOT = 0,

    /* 参考实现在 /.proroot-meta 下的元数据树: one 16-hex-char key
     * per anchor, with "g_"/"m_" prefixed entries and, in the older
     * ("legacy") revision of the same tree, an optional "_<digits>" member
     * suffix plus a "<entry>.cnt" refcount sidecar.  Recognised and decoded
     * structurally; the key derivation is a hash we have not recovered, so
     * this module never invents a key -- see l2s_meta_entry(). */
    L2S_SCHEME_PROROOT = 1
} l2s_scheme;

/* What an l2s name turned out to be. */
typedef enum {
    L2S_KIND_NONE = 0,
    L2S_KIND_INTERMEDIATE = 1, /* <dir>/.l2s.<name><GGGG>            */
    L2S_KIND_FINAL = 2,        /* <dir>/.l2s.<name><GGGG>.<NNNN>     */
    L2S_KIND_GROUP = 3,        /* <meta>/g_<16hex>                   */
    L2S_KIND_MEMBER = 4,       /* <meta>/m_<16hex>                   */
    L2S_KIND_LEGACY_KEY = 5,   /* <meta>/<16hex>[_<digits>]          */
    L2S_KIND_REFCOUNT = 6      /* <anything>.cnt                     */
} l2s_kind;

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

/*
 * Everything the naming algebra needs to know about the process it runs in.
 * Zero-initialise and then override what applies:
 *
 *     l2s_config cfg = L2S_CONFIG_DEFAULT;   // no PROOT_L2S_DIR
 *     cfg.l2s_dir = "/.l2s";                 // PROOT_L2S_DIR=/.l2s
 *     cfg.prefix  = L2S_PREFIX_USERLAND;     // USERLAND build
 */
typedef struct {
    /* PROOT_L2S_DIR, or NULL when unset.  When set, every intermediate is
     * created inside this directory (flat namespace) instead of next to
     * the file it stands for.  Must not have a trailing slash: 参考实现 strips
     * them in get_l2s_directory() and then matches with
     *     strncmp(path, l2s_directory, l2s_directory_length)
     *     && path[l2s_directory_length] == '/'
     * so "/.l2s/" would never match. */
    const char *l2s_dir;

    /* L2S_PREFIX or L2S_PREFIX_USERLAND.  NULL means L2S_PREFIX. */
    const char *prefix;

    /* Which family of names to produce / accept. */
    l2s_scheme scheme;

    /* Mirror 参考实现's is_l2s_file() exactly, including its misclassification
     * of an intermediate whose original name ends with '.' (see REPORT.md).
     * 0 (the default) uses the strict classifier, which requires the
     * generation field to be followed by ".<4 digits>" before a name is
     * accepted as a final file. */
    int lenient_classify;
} l2s_config;

#define L2S_CONFIG_DEFAULT { NULL, L2S_PREFIX, L2S_SCHEME_PROOT, 0 }

/* ------------------------------------------------------------------ */
/* Results                                                             */
/* ------------------------------------------------------------------ */

/* Everything that can be recovered from one l2s path. */
typedef struct {
    l2s_kind kind;      /* INTERMEDIATE / FINAL / GROUP / MEMBER / ...   */
    l2s_scheme scheme;

    /* The original basename, without any l2s decoration.  For
     * ".l2s.report.md0001.0002" this is "report.md". */
    char orig_name[L2S_NAME_MAX];

    /* The directory the original file lived in.  Recovered only when the
     * intermediate sits next to the original (no PROOT_L2S_DIR): with an
     * l2s directory the encoding is lossy, the directory is simply not
     * recorded anywhere, and `dir_known` is 0. */
    char orig_dir[L2S_PATH_MAX];
    int dir_known;

    /* The directory that holds the intermediate.  Equals orig_dir when the
     * layout is "next to the original", and the l2s directory otherwise. */
    char mid_dir[L2S_PATH_MAX];

    unsigned int generation; /* the GGGG field, 0 when not applicable */
    unsigned int nlink;      /* the NNNN field, 0 when not applicable */
} l2s_info;

/* The two computed paths plus the pieces they were built from. */
typedef struct {
    char orig[L2S_PATH_MAX];      /* input, echoed back                */
    char mid[L2S_PATH_MAX];       /* intermediate symlink              */
    char final[L2S_PATH_MAX];     /* real data file                    */
    char dir[L2S_PATH_MAX];       /* directory holding mid and final   */
    char name[L2S_NAME_MAX];      /* basename of orig                  */
    unsigned int generation;
    unsigned int nlink;
    l2s_config cfg;               /* a copy; cfg.l2s_dir is re-pointed
                                   * into `l2s_dir_storage`              */
    char l2s_dir_storage[L2S_PATH_MAX];
} l2s_paths;

/* ------------------------------------------------------------------ */
/* Required API                                                        */
/* ------------------------------------------------------------------ */

/*
 * l2s_make_paths() -- compute the l2s paths for `orig`.
 *
 * Equivalent to 参考实现's first-link branch with an empty l2s directory:
 * the intermediate and the final both live in dirname(orig), and the link
 * count starts at 1.  This is the whole of the "given one original path,
 * what are the intermediate and final paths" question.
 *
 * On success returns L2S_OK and writes NUL-terminated strings to out_mid
 * and out_final (each must have room for L2S_PATH_MAX bytes; NULL is
 * allowed for either if the caller only wants one of them).
 *
 * Fails with:
 *   L2S_EBADNAME      orig is empty, or its basename is "." or ".."
 *   L2S_ENAMETOOLONG  the result would not fit L2S_PATH_MAX
 */
int l2s_make_paths(const char *orig, char *out_mid, char *out_final);

/*
 * l2s_make_paths_ex() -- the same, with an explicit configuration and an
 * explicit generation / link count, and the pieces broken out.
 *
 * `generation` is the GGGG field; pass 1 for a fresh chain.  `nlink` is the
 * NNNN field tacked to the final name; pass 1 for a freshly created chain
 * (参考实现's literal ".0002" is only reachable through a chain of two
 * link() calls, see l2s_chain_nlink_max() and the tests).
 *
 * `out` may be NULL when only the paths are wanted; otherwise every field
 * is filled, including a private copy of the configuration so that the
 * result does not dangle if the caller's config was on the stack.
 */
int l2s_make_paths_ex(const l2s_config *cfg, const char *orig,
                      unsigned int generation, unsigned int nlink,
                      l2s_paths *out, char *out_mid, char *out_final);

/*
 * l2s_is_emulated() -- does `path` name an l2s artifact?
 *
 * Pure name test: true when the last component is
 *   - an intermediate  ".l2s.<name><GGGG>"          -> L2S_KIND_INTERMEDIATE
 *   - a final          ".l2s.<name><GGGG>.<NNNN>"   -> L2S_KIND_FINAL
 *   - 参考实现的元数据条目 "g_<16hex>" / "m_<16hex>"/"<16hex>[_<digits>]"
 *
 * It does NOT answer "is this guest path a faked hard link": that needs
 * lstat() + readlink() and cannot be a pure function.  Use
 * l2s_is_emulated_target() on the result of the readlink for that half.
 *
 * Returns 1 / 0 / L2S_ERR on a NULL argument.
 */
int l2s_is_emulated(const char *path);

/* l2s_is_emulated() with an explicit scheme (proroot meta names only). */
int l2s_is_emulated_cfg(const l2s_config *cfg, const char *path);

/*
 * l2s_decode() -- recover the original name from an l2s path.
 *
 * Writes the original basename into out_orig (L2S_PATH_MAX bytes).  When the
 * intermediate lives next to the original, dirname(path) IS the original
 * directory, so the full original path is recovered; when an l2s directory
 * is in use it is not, and only the basename is written.
 *
 *   ".l2s.report.md0001.0002"  ->  "report.md"
 *   "/.l2s/.l2s.<uuid>0001"    ->  "<uuid>"       (l2s dir in use)
 *
 * Returns L2S_OK, or L2S_ENOTL2S when the name is not an l2s artifact.
 */
int l2s_decode(const char *path, char *out_orig);

/* l2s_decode() with the configuration and the full breakdown. */
int l2s_decode_ex(const l2s_config *cfg, const char *path,
                  char *out_orig, l2s_info *out);

/*
 * l2s_patch_nlink() -- make a faked hard link look like a real one.
 *
 * 参考实现 computes the faked count from the *file name*
 *     finalStat.st_nlink = atoi(final + strlen(final) - 4);
 * so a bare struct stat carries nothing to patch with: the path is an
 * argument of the operation, not of the structure.  Hence the two-argument
 * form, which mirrors proroot's link2symlink_patch_stat_nlink().  The
 * one-argument primitive is l2s_patch_nlink_value().
 *
 * Returns 1 when st_nlink was changed, 0 when the path carries no l2s link
 * count (nothing to do), a negative L2S_* code on error.  st is left
 * untouched unless the count was recovered successfully.
 */
int l2s_patch_nlink(struct stat *st, const char *path);

/* Set st_nlink from an already-known count.  Returns 1 / 0 / L2S_ERANGE. */
int l2s_patch_nlink_value(struct stat *st, unsigned long nlink);

/* The same pair for statx, mirroring link2symlink_patch_statx_nlink().
 * Kept free of <linux/stat.h> so the module stays portable: the caller
 * passes a pointer to the stx_nlink field and to the STATX_NLINK bit. */
int l2s_patch_statx_nlink(unsigned int *stx_nlink, unsigned int *stx_mask,
                          unsigned int statx_nlink_bit, const char *path);

/* ------------------------------------------------------------------ */
/* Building blocks                                                     */
/* ------------------------------------------------------------------ */

/* Split `path` into dir and base, without touching ".." or "." beyond
 * reporting them through L2S_EBADNAME.  `dir` is "" ... see the tests:
 * a path with no '/' has an empty dir; dir is never given a trailing '/'. */
int l2s_split(const char *path, char *dir, size_t dirsz,
              char *base, size_t basesz);

/* Join `dir` and `base` with exactly one '/', or no '/' when dir is empty
 * or is exactly "/".  Returns L2S_ENAMETOOLONG when it would not fit. */
int l2s_join(const char *dir, const char *base, char *out, size_t outsz);

/* Is `name` a bare (no '/') l2s artifact?  Fills `out` when non-NULL. */
int l2s_classify(const l2s_config *cfg, const char *name, l2s_info *out);

/* Given what readlink() returned for a guest path, is that a faked hard
 * link?  This is the pure half of proroot's
 * link2symlink_is_emulated_link().  On success the recovered original
 * basename is written to out_orig (L2S_PATH_MAX bytes, may be NULL).
 * Returns 1 (yes) / 0 (no) / negative on error. */
int l2s_is_emulated_target(const l2s_config *cfg, const char *link_target,
                           char *out_orig);

/* Recover the original basename from a bare artifact name.  Returns
 * L2S_OK, L2S_ENOTL2S, or L2S_ENAMETOOLONG. */
int l2s_decode_name(const l2s_config *cfg, const char *name,
                    l2s_info *out);

/* Bump the trailing 4-digit link count of a final name:
 *     ".l2s.x0001.0001" -> ".l2s.x0001.0002"
 * Returns L2S_OK, L2S_ENOTL2S, L2S_ERANGE (count would exceed 9999), or
 * L2S_ENAMETOOLONG.  `out` must have room for strlen(name) + 2. */
int l2s_next_final(const char *name, char *out, size_t outsz);

/* Decrement, for the unlink path.  Returns L2S_OK with *out_count == 0
 * when this was the last link (both the intermediate and the final must
 * then be removed). */
int l2s_prev_final(const char *name, char *out, size_t outsz,
                   unsigned int *out_count);

/* The first free generation, given a predicate over candidate
 * intermediates.  参考实现 probes with access(F_OK), which FOLLOWS symlinks,
 * so a dangling intermediate counts as a free slot -- `exists` must
 * reproduce that (i.e. it must answer "does this path resolve to
 * something", not "is this name taken").
 *
 * Returns the generation (1..999) or L2S_ERANGE when all are taken. */
typedef int (*l2s_exists_fn)(const char *candidate, void *ctx);
int l2s_pick_generation(const l2s_config *cfg, const char *orig,
                        l2s_exists_fn exists, void *ctx,
                        unsigned int *out_generation);

/* The l2s link count implied by a chain of `links` link() calls:
 * the first call creates the chain with 1, every later call adds 1. */
unsigned int l2s_chain_nlink(unsigned int links);

/* proroot's group/member key derivation, verified against the released
 * libproroot-runtime.so v1.2.8: djb2 (seed 5381, 32-bit, no finalizer)
 * over the BASENAME, rendered as 16 lowercase hex characters. */
uint32_t l2s_djb2(const char *s);
void l2s_key16(const char *basename, char out[L2S_PROROOT_KEY_LEN + 1]);

/* proroot's metadata entry name: <meta_dir>/<prefix2><key16>, where key16
 * is 16 lowercase hex characters.  The function validates the shape and
 * refuses anything else; build `key16` with l2s_key16(). */
int l2s_meta_entry(const char *meta_dir, const char *prefix2,
                   const char *key16, char *out, size_t outsz);

/* proroot's refcount sidecar name: `<path>.cnt`. */
int l2s_refcount_path(const char *path, char *out, size_t outsz);

/* Read / write a 16-hex-char key or a decimal count, as proroot does with
 * write_small_file() / read_small_file(): no newline, no padding.  These
 * are pure string<->value conversions; the I/O is the caller's job. */
int l2s_format_count(unsigned long count, char *out, size_t outsz);
int l2s_parse_count(const char *text, size_t len, unsigned long *out);

/* Validate a 16-character lowercase hex key.  Returns 1 / 0. */
int l2s_is_key16(const char *s);

const char *l2s_strerror(int rc);
const char *l2s_kind_name(l2s_kind kind);

/* ------------------------------------------------------------------ */
/* Ground truth                                                        */
/* ------------------------------------------------------------------ */

/*
 * A real artifact produced by the 参考实现 instance this container runs
 * under, captured from the live filesystem and hard-coded here so that the
 * unit tests stay pure:
 *
 *   $ ls -la /.l2s/
 *   lrwxrwxrwx .l2s.d85aae78-3590-4929-9e58-2ed35b6d9eff0001
 *        -> /.l2s/.l2s.d85aae78-3590-4929-9e58-2ed35b6d9eff0001.0001
 *   -r-------- .l2s.d85aae78-3590-4929-9e58-2ed35b6d9eff0001.0001
 *
 * PROOT_L2S_DIR was "/.l2s", the original basename was the bare UUID, the
 * generation is 0001 and the link count is 1.
 */
#define L2S_GROUND_TRUTH_DIR "/.l2s"
#define L2S_GROUND_TRUTH_NAME \
    "d85aae78-3590-4929-9e58-2ed35b6d9eff"
#define L2S_GROUND_TRUTH_MID \
    "/.l2s/.l2s.d85aae78-3590-4929-9e58-2ed35b6d9eff0001"
#define L2S_GROUND_TRUTH_FINAL \
    "/.l2s/.l2s.d85aae78-3590-4929-9e58-2ed35b6d9eff0001.0001"

/* A real artifact of the "intermediate next to the original" layout, from
 * the DSHA write-tool bug report (docs-independent, quoted in REPORT.md):
 *   /root/reports/bug-repro-test.txt
 *       -> /root/reports/.bug-repro-test.txt.27836.xxx.tmpdir/
 *              .l2s.bug-repro-test.txt.tmp0001
 * Here the original basename was "bug-repro-test.txt.tmp", the generation
 * 0001, and the data was left at ".l2s.bug-repro-test.txt.tmp0001.0001". */
#define L2S_GROUND_TRUTH2_DIR \
    "/root/reports/.bug-repro-test.txt.27836.xxx.tmpdir"
#define L2S_GROUND_TRUTH2_NAME "bug-repro-test.txt.tmp"
#define L2S_GROUND_TRUTH2_MID \
    "/root/reports/.bug-repro-test.txt.27836.xxx.tmpdir/" \
    ".l2s.bug-repro-test.txt.tmp0001"
#define L2S_GROUND_TRUTH2_FINAL \
    "/root/reports/.bug-repro-test.txt.27836.xxx.tmpdir/" \
    ".l2s.bug-repro-test.txt.tmp0001.0001"

#ifdef __cplusplus
}
#endif

#endif /* L2S_H */
