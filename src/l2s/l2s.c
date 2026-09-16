/*
 * l2s.c -- link-to-symlink (l2s) hard-link emulation, pure-logic core.
 *
 * The naming algebra follows the on-disk convention established by PRoot's
 * link2symlink extension (src/extension/link2symlink/link2symlink.c), so that
 * a rootfs prepared by either runtime is readable by the other.  What is
 * shared is the **file naming scheme** -- a format, not an implementation:
 * upstream is a 1342-line ptrace-based extension using talloc and PRoot's
 * internal tracee API, whereas this file is a 1170-line pure-function module
 * with no syscalls, no filesystem access and no shared code.
 *
 * This file makes no syscalls and opens no files: every function below is a
 * pure function of its arguments, so the whole module is unit-testable
 * without a filesystem.
 *
 * See l2s.h for the doc comments and REPORT.md for the upstream references
 * and for the parts that cannot be pure logic.
 *
 * SPDX-License-Identifier: MIT
 */

#include "l2s.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

static int is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static int is_hex_lower(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

const char *l2s_strerror(int rc)
{
    switch (rc) {
    case L2S_OK:            return "ok";
    case L2S_ERR:           return "invalid argument";
    case L2S_ENAMETOOLONG:  return "l2s path too long";
    case L2S_ENOTL2S:       return "not an l2s path";
    case L2S_ERANGE:        return "l2s count out of range";
    case L2S_EBADNAME:      return "invalid path component";
    default:                return "unknown l2s error";
    }
}

const char *l2s_kind_name(l2s_kind kind)
{
    switch (kind) {
    case L2S_KIND_NONE:         return "none";
    case L2S_KIND_INTERMEDIATE: return "intermediate";
    case L2S_KIND_FINAL:        return "final";
    case L2S_KIND_GROUP:        return "proroot-group";
    case L2S_KIND_MEMBER:       return "proroot-member";
    case L2S_KIND_LEGACY_KEY:   return "proroot-legacy-key";
    case L2S_KIND_REFCOUNT:     return "refcount";
    default:                    return "unknown";
    }
}

static const char *cfg_prefix(const l2s_config *cfg)
{
    if (cfg != NULL && cfg->prefix != NULL)
        return cfg->prefix;
    return L2S_PREFIX;
}

static l2s_scheme cfg_scheme(const l2s_config *cfg)
{
    return (cfg != NULL) ? cfg->scheme : L2S_SCHEME_PROOT;
}

static int cfg_lenient(const l2s_config *cfg)
{
    return (cfg != NULL) ? cfg->lenient_classify : 0;
}

/* The effective l2s directory, or NULL.  A configured directory must be
 * absolute, non-empty and free of trailing slashes -- exactly what
 * get_l2s_directory() produces after it strips them.  Anything else is
 * treated as unset rather than silently mis-matched, because PRoot's own
 * matcher would never match such a value either. */
static const char *cfg_l2s_dir(const l2s_config *cfg)
{
    const char *d;
    size_t n;

    if (cfg == NULL || cfg->l2s_dir == NULL || cfg->l2s_dir[0] != '/')
        return NULL;

    d = cfg->l2s_dir;
    n = strlen(d);
    while (n > 1 && d[n - 1] == '/')
        n--;

    /* d has a trailing slash (e.g. "/.l2s/") -> not a canonical value. */
    if (n != strlen(d) || n < 2)
        return NULL;

    return d;
}

/* Re-point a copied config's l2s_dir at caller-owned storage so that an
 * l2s_paths result never contains a dangling pointer. */
static void cfg_embed(l2s_config *dst, char *storage, size_t storage_sz,
                      const l2s_config *src)
{
    const char *d = cfg_l2s_dir(src);

    if (d != NULL && strlen(d) < storage_sz) {
        memcpy(storage, d, strlen(d) + 1);
        dst->l2s_dir = storage;
    } else {
        storage[0] = '\0';
        dst->l2s_dir = NULL;
    }
}

/* ------------------------------------------------------------------ */
/* Splitting and joining                                               */
/* ------------------------------------------------------------------ */

int l2s_split(const char *path, char *dir, size_t dirsz,
              char *base, size_t basesz)
{
    const char *slash;
    const char *name;
    size_t dlen, blen;

    if (path == NULL || base == NULL || basesz == 0)
        return L2S_ERR;

    slash = strrchr(path, '/');
    name = (slash == NULL) ? path : slash + 1;

    /* PRoot does not split at all: it copies the first
     * strlen(original) - strlen(name) bytes of the original, i.e. the
     * directory INCLUDING its trailing slash.  For "/a.txt" that is the
     * single byte "/", for "a.txt" it is nothing.  We keep the directory
     * without its trailing slash, except for the root, which is exactly
     * "/" -- otherwise "/a.txt" and "a.txt" would be indistinguishable
     * and the "next to the original" layout would drop the leading
     * slash. */
    if (slash == NULL) {
        dlen = 0;
    } else if (slash == path) {
        dlen = 1;   /* "/a.txt" -> dir is the root, "/" */
    } else {
        dlen = (size_t)(slash - path);
    }
    blen = strlen(name);

    if (blen == 0)
        return L2S_EBADNAME;
    if (blen + 1 > basesz)
        return L2S_ENAMETOOLONG;

    if (dir != NULL) {
        if (dlen + 1 > dirsz)
            return L2S_ENAMETOOLONG;
        memcpy(dir, path, dlen);
        dir[dlen] = '\0';
    }

    /* "." and ".." are never linkable: PRoot's move_and_symlink_path()
     * rejects directories outright (lstat + S_ISDIR -> -EPERM), and a
     * basename of ".." would escape the directory the caller named. */
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
        return L2S_EBADNAME;

    memcpy(base, name, blen + 1);
    return L2S_OK;
}

/*
 * l2s_join(dir, base, out):
 *     ""   + base -> base
 *     "/"  + base -> "/" base          (one slash, never "//")
 *     "/d" + base -> "/d/" base
 *
 * This mirrors PRoot, which builds the intermediate with
 *     strncpy(intermediate, original, strlen(original) - strlen(name));
 * i.e. it copies the directory INCLUDING its trailing slash and then
 * appends PREFIX, so "/a.txt" becomes "/" + ".l2s." + "a.txt".
 *
 * Note that there is no "empty base means give me the directory back"
 * special case: l2s_join(dir, "", out) yields "<dir>/", which is exactly
 * what PRoot's strncpy would have produced and is what the builder below
 * expects before it appends the prefix.
 */
int l2s_join(const char *dir, const char *base, char *out, size_t outsz)
{
    size_t dlen;
    int need_slash;

    if (out == NULL || outsz == 0 || base == NULL)
        return L2S_ERR;

    dlen = (dir == NULL) ? 0 : strlen(dir);
    if (dlen == 1 && dir[0] == '/')
        need_slash = 0;         /* the root already ends in a slash */
    else
        need_slash = (dlen > 0);

    if (dlen + (need_slash ? 1u : 0u) + strlen(base) + 1 > outsz)
        return L2S_ENAMETOOLONG;

    memcpy(out, dir == NULL ? "" : dir, dlen);
    if (need_slash)
        out[dlen] = '/';
    strcpy(out + dlen + (need_slash ? 1 : 0), base);

    return L2S_OK;
}

/* ------------------------------------------------------------------ */
/* Formatting                                                         */
/* ------------------------------------------------------------------ */

/* Write `value` as exactly `digits` decimal digits, zero padded.  PRoot
 * uses sprintf("%04d"), which does NOT truncate but happily writes more
 * than 4 digits; callers here reject out-of-range values first. */
static int format_fixed(unsigned int value, unsigned int digits,
                        char *out, size_t outsz)
{
    if (outsz < (size_t)digits + 1)
        return L2S_ENAMETOOLONG;
    if (snprintf(out, outsz, "%0*u", (int)digits, value) >= (int)outsz)
        return L2S_ENAMETOOLONG;
    return L2S_OK;
}

/* strtoul restricted to exactly `digits` characters, no sign, no space. */
static int parse_fixed(const char *s, unsigned int digits, unsigned int *out)
{
    unsigned int i;
    unsigned long v = 0;

    if (s == NULL || out == NULL)
        return L2S_ERR;

    for (i = 0; i < digits; i++) {
        if (!is_digit(s[i]))
            return L2S_ERR;
        v = v * 10 + (unsigned long)(s[i] - '0');
    }

    *out = (unsigned int)v;
    return L2S_OK;
}

int l2s_format_count(unsigned long count, char *out, size_t outsz)
{
    int n;

    if (out == NULL || outsz == 0)
        return L2S_ERR;

    n = snprintf(out, outsz, "%lu", count);
    if (n < 0 || (size_t)n >= outsz)
        return L2S_ENAMETOOLONG;

    return L2S_OK;
}

int l2s_parse_count(const char *text, size_t len, unsigned long *out)
{
    size_t i;
    unsigned long v = 0;

    if (text == NULL || out == NULL || len == 0)
        return L2S_ERR;

    /* zero-padded on disk ("%04d"), so leading zeros are expected */
    for (i = 0; i < len; i++) {
        if (!is_digit(text[i]))
            return L2S_ERR;
        if (v > (0xffffffffUL - 9) / 10)
            return L2S_ERANGE;
        v = v * 10 + (unsigned long)(text[i] - '0');
    }

    *out = v;
    return L2S_OK;
}

int l2s_is_key16(const char *s)
{
    int i;

    if (s == NULL)
        return 0;
    for (i = 0; i < L2S_PROROOT_KEY_LEN; i++) {
        if (!is_hex_lower(s[i]))
            return 0;
    }
    return s[L2S_PROROOT_KEY_LEN] == '\0';
}

/* ------------------------------------------------------------------ */
/* Classification                                                     */
/* ------------------------------------------------------------------ */

/*
 * Parse "<prefix><orig><GGGG>[.<NNNN>]".
 *
 * Whatever `cfg` says the prefix is, both spellings are accepted on the
 * way in: a rootfs written by a USERLAND build (".proot.l2s.") can be
 * handed to a normal build and vice versa, and PRoot's own
 * is_l2s_file()/is_l2s_name() predicates are compiled with exactly one
 * prefix but are also used to recognise leftovers from the other.  The
 * generated name always uses cfg's prefix.
 *
 * The 4-digit fields are anchored at the END of the name.  PRoot never
 * stores the length of <orig>; it recovers everything by looking at the
 * tail, which is exactly why `atoi(name + strlen(name) - 4)` works without
 * knowing where the original name ended.  Consequences, all reproduced
 * here and covered by the tests:
 *
 *   - <orig> may itself contain digits, dots and further ".l2s." runs;
 *     the parse is unambiguous only because the tail is fixed width;
 *   - a final name must therefore carry 10 trailing characters,
 *     ".GGGG.NNNN", and <orig> must be non-empty;
 *   - a name that is not PREFIX-shaped at all is reported as ENOTL2S
 *     rather than guessed at.
 */
static const char *match_prefix(const char *name, size_t *out_plen)
{
    static const char *const prefixes[] = {
        L2S_PREFIX,
        L2S_PREFIX_USERLAND,
    };
    size_t i;

    if (name == NULL)
        return NULL;

    /* Longest first, so that ".proot.l2s.x" is not mistaken for a
     * ".l2s."-prefixed name whose <orig> starts with "proot.l2s.x". */
    for (i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        size_t plen = strlen(prefixes[i]);
        if (strncmp(name, prefixes[i], plen) == 0) {
            if (out_plen != NULL)
                *out_plen = plen;
            return prefixes[i];
        }
    }

    return NULL;
}

static int parse_l2s_name(const l2s_config *cfg, const char *name,
                          l2s_info *out)
{
    size_t plen = 0;
    size_t nlen;
    const char *body;
    size_t bodylen;
    unsigned int gen = 0, link = 0;
    l2s_kind kind = L2S_KIND_NONE;

    if (name == NULL || strlen(name) == 0)
        return L2S_ERR;

    if (match_prefix(name, &plen) == NULL)
        return L2S_ENOTL2S;

    nlen = strlen(name);

    /* "<prefix>" alone: nothing to decode. */
    if (nlen <= plen)
        return L2S_ENOTL2S;

    body = name + plen;
    bodylen = nlen - plen;

    /*
     * Try the final form first: <orig><GGGG>.<NNNN>.  The tail is at fixed
     * offsets from the END of the name:
     *     body[len-1 .. len-4]  = NNNN
     *     body[len-5]           = '.'
     *     body[len-6 .. len-9]  = GGGG
     *     body[0 .. len-10]     = <orig>   (must be non-empty)
     */
    if (bodylen > L2S_DIGITS + 1 + L2S_DIGITS &&
        body[bodylen - 5] == '.' &&
        parse_fixed(body + bodylen - L2S_DIGITS,
                    L2S_DIGITS, &link) == L2S_OK &&
        parse_fixed(body + bodylen - L2S_DIGITS - 1 - L2S_DIGITS,
                    L2S_DIGITS, &gen) == L2S_OK) {
        kind = L2S_KIND_FINAL;
        bodylen -= (size_t)(L2S_DIGITS + 1 + L2S_DIGITS);
    }

    /* Otherwise the intermediate form: <orig><GGGG>. */
    if (kind == L2S_KIND_NONE) {
        if (bodylen > L2S_DIGITS &&
            parse_fixed(body + bodylen - L2S_DIGITS,
                        L2S_DIGITS, &gen) == L2S_OK) {
            kind = L2S_KIND_INTERMEDIATE;
            bodylen -= L2S_DIGITS;
        } else if (cfg_lenient(cfg)) {
            /*
             * PRoot's is_l2s_file() only checks the shape
             *   name starts with PREFIX
             *   name[len-5] == '.'
             *   name[len-4 .. len-1] are digits
             * so a name whose <orig> ends with '.' (e.g. the intermediate
             * for an original named "x.") is reported as an l2s file even
             * though its generation field is not numeric.  It cannot be
             * decoded without inventing a generation, so mirroring it is
             * opt-in and still refuses to guess.
             */
            return L2S_ENOTL2S;
        } else {
            return L2S_ENOTL2S;
        }
    }

    if (bodylen == 0)
        return L2S_ENOTL2S;

    if (out != NULL) {
        if (bodylen + 1 > sizeof(out->orig_name))
            return L2S_ENAMETOOLONG;

        memset(out, 0, sizeof(*out));
        memcpy(out->orig_name, body, bodylen);
        out->orig_name[bodylen] = '\0';
        out->kind = kind;
        out->scheme = L2S_SCHEME_PROOT;
        out->generation = gen;
        out->nlink = (kind == L2S_KIND_FINAL) ? link : 0;
    }

    return L2S_OK;
}

/* proroot's /.proroot-meta entry names.
 *
 * build_meta_entry(meta_dir, prefix2, key, out) writes
 *     <meta_dir> "/" <prefix2[0]> <prefix2[1]> <16 bytes of key>
 * with prefix2 being "g_" or "m_".  is_legacy_meta_path() accepts those,
 * and additionally a bare 16-hex-char key with an optional
 * "_<digit 1-9><digits>" member suffix. */
static int parse_proroot_meta_name(const char *name, l2s_info *out)
{
    const char *key;
    l2s_kind kind = L2S_KIND_NONE;
    size_t keylen;
    size_t i;

    if (name == NULL)
        return L2S_ERR;

    if (strlen(name) >= 2 && (name[0] == 'g' || name[0] == 'm') &&
        name[1] == '_') {
        kind = (name[0] == 'g') ? L2S_KIND_GROUP : L2S_KIND_MEMBER;
        key = name + 2;
    } else {
        kind = L2S_KIND_LEGACY_KEY;
        key = name;
    }

    keylen = strlen(key);
    if (keylen < L2S_PROROOT_KEY_LEN)
        return L2S_ENOTL2S;

    /* The 16 hex characters of the key come first and are fixed width. */
    for (i = 0; i < L2S_PROROOT_KEY_LEN; i++) {
        if (!is_hex_lower(key[i]))
            return L2S_ENOTL2S;
    }

    /*
     * Everything after the key must be the optional member suffix that
     * is_legacy_meta_path() accepts: '_' followed by a digit in 1..9 and
     * then any number of digits up to the end of the string.
     */
    if (keylen > L2S_PROROOT_KEY_LEN) {
        if (key[L2S_PROROOT_KEY_LEN] != '_')
            return L2S_ENOTL2S;
        if (key[L2S_PROROOT_KEY_LEN + 1] < '1' ||
            key[L2S_PROROOT_KEY_LEN + 1] > '9')
            return L2S_ENOTL2S;
        for (i = L2S_PROROOT_KEY_LEN + 2; i < keylen; i++) {
            if (!is_digit(key[i]))
                return L2S_ENOTL2S;
        }
    }

    if (out != NULL) {
        memset(out, 0, sizeof(*out));
        out->kind = kind;
        out->scheme = L2S_SCHEME_PROROOT;
        memcpy(out->orig_name, key, L2S_PROROOT_KEY_LEN);
        out->orig_name[L2S_PROROOT_KEY_LEN] = '\0';
    }

    return L2S_OK;
}

int l2s_classify(const l2s_config *cfg, const char *name, l2s_info *out)
{
    int rc;

    if (name == NULL)
        return L2S_ERR;
    if (strchr(name, '/') != NULL)
        return L2S_ERR;

    if (cfg_scheme(cfg) == L2S_SCHEME_PROOT) {
        rc = parse_l2s_name(cfg, name, out);
        if (rc == L2S_OK)
            return L2S_OK;
    }

    return parse_proroot_meta_name(name, out);
}

int l2s_is_emulated_cfg(const l2s_config *cfg, const char *path)
{
    char base[L2S_NAME_MAX];

    if (path == NULL)
        return L2S_ERR;
    if (l2s_split(path, NULL, 0, base, sizeof(base)) != L2S_OK)
        return 0;

    return l2s_classify(cfg, base, NULL) == L2S_OK;
}

int l2s_is_emulated(const char *path)
{
    l2s_config cfg = L2S_CONFIG_DEFAULT;
    return l2s_is_emulated_cfg(&cfg, path);
}

int l2s_is_emulated_target(const l2s_config *cfg, const char *link_target,
                           char *out_orig)
{
    char base[L2S_NAME_MAX];
    l2s_info info;
    int rc;

    if (link_target == NULL)
        return L2S_ERR;

    /* An empty readlink() result is not a link. */
    if (link_target[0] == '\0')
        return 0;

    if (l2s_split(link_target, NULL, 0, base, sizeof(base)) != L2S_OK)
        return 0;

    rc = l2s_classify(cfg, base, &info);
    if (rc != L2S_OK)
        return 0;

    /* Only the intermediate form makes a guest path a faked hard link:
     * the guest path points at the intermediate, the intermediate points
     * at the final.  A guest path that points straight at a final (or at
     * a proroot meta entry) is not a faked hard link. */
    if (info.kind != L2S_KIND_INTERMEDIATE)
        return 0;

    if (out_orig != NULL)
        memcpy(out_orig, info.orig_name, strlen(info.orig_name) + 1);

    return 1;
}

/* ------------------------------------------------------------------ */
/* Decoding                                                           */
/* ------------------------------------------------------------------ */

int l2s_decode_name(const l2s_config *cfg, const char *name, l2s_info *out)
{
    int rc;

    if (name == NULL)
        return L2S_ERR;
    if (strchr(name, '/') != NULL)
        return L2S_ERR;

    rc = l2s_classify(cfg, name, out);
    if (rc != L2S_OK)
        return L2S_ENOTL2S;

    return L2S_OK;
}

int l2s_decode_ex(const l2s_config *cfg, const char *path,
                  char *out_orig, l2s_info *out)
{
    char dir[L2S_PATH_MAX];
    char base[L2S_NAME_MAX];
    const char *l2s_dir = cfg_l2s_dir(cfg);
    l2s_info info;
    int dir_is_orig = 0;
    int rc;

    if (path == NULL)
        return L2S_ERR;

    rc = l2s_split(path, dir, sizeof(dir), base, sizeof(base));
    if (rc != L2S_OK)
        return L2S_ENOTL2S;

    rc = l2s_classify(cfg, base, &info);
    if (rc != L2S_OK)
        return L2S_ENOTL2S;

    /*
     * Is dirname(path) the directory the original lived in, or the l2s
     * directory that merely holds the intermediate?
     *
     * Without PROOT_L2S_DIR it is always the former.  With one it is the
     * latter -- but by construction those two are the same string for an
     * entry of the l2s directory, and PRoot itself cannot tell the two
     * layouts apart in that case either (its is_l2s_file() looks only at
     * the basename).  Preferring the l2s directory there is what PRoot's
     * own prefix test does, so do that and say the original directory is
     * unknown only when the answer would be ambiguous or wrong.
     */
    if (l2s_dir == NULL)
        dir_is_orig = 1;
    else if (strcmp(dir, l2s_dir) != 0)
        dir_is_orig = 1;   /* some other directory: not PRoot's l2s dir */
    else
        dir_is_orig = 0;   /* exactly the l2s dir: the original dir is lost */

    if (out_orig != NULL) {
        if (dir_is_orig &&
            (info.kind == L2S_KIND_INTERMEDIATE || info.kind == L2S_KIND_FINAL)) {
            /* next to the original: the full original path is recoverable */
            if (l2s_join(dir, info.orig_name, out_orig, L2S_PATH_MAX) != L2S_OK)
                return L2S_ENAMETOOLONG;
        } else {
            memcpy(out_orig, info.orig_name, strlen(info.orig_name) + 1);
        }
    }

    if (out != NULL) {
        size_t dlen = strlen(dir);

        *out = info;
        if (dlen + 1 > sizeof(out->mid_dir))
            return L2S_ENAMETOOLONG;
        memcpy(out->mid_dir, dir, dlen + 1);

        if (dir_is_orig &&
            (info.kind == L2S_KIND_INTERMEDIATE || info.kind == L2S_KIND_FINAL)) {
            memcpy(out->orig_dir, dir, dlen + 1);
            out->dir_known = 1;
        } else {
            out->orig_dir[0] = '\0';
            out->dir_known = 0;
        }
    }

    return L2S_OK;
}

int l2s_decode(const char *path, char *out_orig)
{
    l2s_config cfg = L2S_CONFIG_DEFAULT;
    return l2s_decode_ex(&cfg, path, out_orig, NULL);
}

/* ------------------------------------------------------------------ */
/* Building                                                           */
/* ------------------------------------------------------------------ */

int l2s_make_paths_ex(const l2s_config *cfg, const char *orig,
                      unsigned int generation, unsigned int nlink,
                      l2s_paths *out, char *out_mid, char *out_final)
{
    const char *prefix = cfg_prefix(cfg);
    const char *l2s_dir = cfg_l2s_dir(cfg);
    char dir[L2S_PATH_MAX];
    char base[L2S_NAME_MAX];
    char head[L2S_PATH_MAX];
    char mid[L2S_PATH_MAX];
    char final[L2S_PATH_MAX];
    char tail[L2S_DIGITS + 1];
    size_t need;
    int rc;

    if (orig == NULL)
        return L2S_ERR;

    if (generation < L2S_GEN_FIRST || generation > L2S_GEN_LAST)
        return L2S_ERANGE;
    if (nlink < 1 || nlink > L2S_NLINK_MAX)
        return L2S_ERANGE;

    rc = l2s_split(orig, dir, sizeof(dir), base, sizeof(base));
    if (rc != L2S_OK)
        return rc;

    /* The final name is the intermediate name plus ".<NNNN>". */
    rc = format_fixed(generation, L2S_DIGITS, tail, sizeof(tail));
    if (rc != L2S_OK)
        return rc;

    /*
     * Where does the intermediate live?
     *
     * With PROOT_L2S_DIR set, move_and_symlink_path() builds
     *     intermediate = <l2s_dir> "/" PREFIX <basename>
     * and then appends the generation, i.e. a FLAT namespace keyed on the
     * basename only.  Without it, it builds
     *     intermediate = <dirname(orig)> "/" PREFIX <basename>
     * by strncpy()-ing the first strlen(original) - strlen(name) bytes of
     * the original path, which is dirname plus its trailing slash.
     *
     * `head` is that directory plus its separator, exactly as PRoot's
     * strncpy would leave it, and is also what bounds the total length.
     */
    if (l2s_dir != NULL) {
        /* PRoot's own bound, transcribed from the strlen form so that no
         * size_t underflow is possible:
         *   l2s_dir_length + strlen(PREFIX) + strlen(name) + 11 >= PATH_MAX
         * where 11 = 4 (generation) + 1 ('.') + 4 (link count) + 2. */
        need = strlen(l2s_dir) + strlen(prefix) + strlen(base) + 11;
        if (need >= L2S_PATH_MAX)
            return L2S_ENAMETOOLONG;

        rc = l2s_join(l2s_dir, prefix, head, sizeof(head));
        if (rc != L2S_OK)
            return rc;
    } else {
        /* PRoot checks only strlen(PREFIX) + strlen(original) + 5 >= PATH_MAX,
         * the 5 being room for the ".%04d" it writes over the generation.
         * That budget ignores the basename it is about to append, so we
         * bound the real result instead.  Final length is
         *   head + base + 4 + 1 + 4
         * where head is dirname(orig) + '/' (or "" for a bare name). */
        need = strlen(dir) + (dir[0] != '\0' ? 1 : 0) +
               strlen(prefix) + strlen(base) + L2S_DIGITS + 1 + L2S_DIGITS;
        if (need >= L2S_PATH_MAX)
            return L2S_ENAMETOOLONG;

        rc = l2s_join(dir, prefix, head, sizeof(head));
        if (rc != L2S_OK)
            return rc;
    }

    /*
     * NAME_MAX applies to the ARTIFACT too, and the artifact is the
     * original basename plus 9 bytes ("PREFIX" = 5, generation = 4) plus
     * ".NNNN" = 5 more for the final.  PRoot never checks this -- it
     * builds the name and lets symlink()/rename() fail with
     * ENAMETOOLONG -- but a naming layer that hands back a path the
     * filesystem can never accept is not doing its job, so refuse early
     * with the same error.  See REPORT.md, "deliberate divergences".
     */
    if (strlen(base) + strlen(prefix) + L2S_DIGITS + 1 + L2S_DIGITS >
        L2S_NAME_MAX - 1)
        return L2S_ENAMETOOLONG;

    /* mid = head + base + "%04u" */
    if (strlen(head) + strlen(base) + L2S_DIGITS + 1 > sizeof(mid))
        return L2S_ENAMETOOLONG;

    strcpy(mid, head);
    strcat(mid, base);
    strcat(mid, tail);

    /* final = mid + "." + "%04u" */
    if (strlen(mid) + 1 + L2S_DIGITS + 1 > sizeof(final))
        return L2S_ENAMETOOLONG;

    strcpy(final, mid);
    strcat(final, ".");
    if (format_fixed(nlink, L2S_DIGITS, tail, sizeof(tail)) != L2S_OK)
        return L2S_ERANGE;
    strcat(final, tail);

    if (out_mid != NULL)
        memcpy(out_mid, mid, strlen(mid) + 1);
    if (out_final != NULL)
        memcpy(out_final, final, strlen(final) + 1);
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
        memcpy(out->orig, orig, strlen(orig) + 1);
        memcpy(out->mid, mid, strlen(mid) + 1);
        memcpy(out->final, final, strlen(final) + 1);
        memcpy(out->dir, dir, strlen(dir) + 1);
        memcpy(out->name, base, strlen(base) + 1);
        out->generation = generation;
        out->nlink = nlink;

        if (cfg != NULL)
            out->cfg = *cfg;
        else
            memset(&out->cfg, 0, sizeof(out->cfg));
        cfg_embed(&out->cfg, out->l2s_dir_storage,
                  sizeof(out->l2s_dir_storage), cfg);
    }

    return L2S_OK;
}

int l2s_make_paths(const char *orig, char *out_mid, char *out_final)
{
    /* No l2s directory: the intermediates sit next to their file, which is
     * what happens when PROOT_L2S_DIR is unset.  Generation 1, one link --
     * the state right after the first link() on a plain file. */
    return l2s_make_paths_ex(NULL, orig, L2S_GEN_FIRST, 1,
                             NULL, out_mid, out_final);
}

/* ------------------------------------------------------------------ */
/* Link counts                                                        */
/* ------------------------------------------------------------------ */

int l2s_next_final(const char *name, char *out, size_t outsz)
{
    unsigned int count;
    l2s_info info;
    char base[L2S_NAME_MAX];
    size_t stemlen;
    int rc;

    if (name == NULL || out == NULL)
        return L2S_ERR;
    if (strchr(name, '/') != NULL)
        return L2S_ERR;

    rc = parse_l2s_name(NULL, name, &info);
    if (rc != L2S_OK || info.kind != L2S_KIND_FINAL)
        return L2S_ENOTL2S;

    count = info.nlink + 1;
    if (count > L2S_NLINK_MAX)
        return L2S_ERANGE;

    /* Everything up to the final '.' is kept verbatim: PRoot does
     *     strncpy(new_final, final, strlen(final) - 4);
     *     sprintf(new_final + strlen(final) - 4, "%04d", link_count);
     * which, unlike a re-encode through the prefix, also works when the
     * name carries the USERLAND prefix or an original name containing
     * dots and digits. */
    memcpy(base, name, strlen(name) + 1);
    stemlen = strlen(name) - L2S_DIGITS;
    if (stemlen + 1 > outsz)
        return L2S_ENAMETOOLONG;

    memcpy(out, base, stemlen);
    out[stemlen] = '\0';
    rc = format_fixed(count, L2S_DIGITS, out + stemlen, outsz - stemlen);
    if (rc != L2S_OK)
        return L2S_ENAMETOOLONG;

    return L2S_OK;
}

int l2s_prev_final(const char *name, char *out, size_t outsz,
                   unsigned int *out_count)
{
    unsigned int count;
    l2s_info info;
    size_t stemlen;
    int rc;

    if (name == NULL)
        return L2S_ERR;

    rc = parse_l2s_name(NULL, name, &info);
    if (rc != L2S_OK || info.kind != L2S_KIND_FINAL)
        return L2S_ENOTL2S;

    if (info.nlink == 0)
        return L2S_ERANGE;

    count = info.nlink - 1;
    if (out_count != NULL)
        *out_count = count;

    /* PRoot's decrement_link_count(): when the count reaches 0 both the
     * intermediate and the final are unlinked, so there is no name left to
     * build and `out` is left alone. */
    if (count == 0)
        return L2S_OK;

    if (out == NULL)
        return L2S_ERR;

    stemlen = strlen(name) - L2S_DIGITS;
    if (stemlen + 1 > outsz)
        return L2S_ENAMETOOLONG;

    memcpy(out, name, stemlen);
    out[stemlen] = '\0';
    rc = format_fixed(count, L2S_DIGITS, out + stemlen, outsz - stemlen);
    if (rc != L2S_OK)
        return L2S_ENAMETOOLONG;

    return L2S_OK;
}

/* PRoot's atoi(final + strlen(final) - 4): the count is the last four
 * characters of the real data file's name, and the file name always ends
 * in those four digits, so there is no need to know where the original
 * name stopped. */
static int nlink_from_path(const char *path, unsigned int *out)
{
    char base[L2S_NAME_MAX];
    l2s_info info;
    int rc;

    if (path == NULL || out == NULL)
        return L2S_ERR;

    /* PRoot accepts either the final file itself or the intermediate that
     * points at it: handle_sysexit_end() has an `intermediate_proc:` label
     * reached after one readlink, and a `final_proc:` label reached when
     * the path already starts with PREFIX and is not a symlink. */
    if (l2s_split(path, NULL, 0, base, sizeof(base)) != L2S_OK)
        return L2S_ERR;

    rc = parse_l2s_name(NULL, base, &info);
    if (rc != L2S_OK)
        return L2S_ENOTL2S;

    if (info.kind == L2S_KIND_FINAL) {
        *out = info.nlink;
        return L2S_OK;
    }

    if (info.kind == L2S_KIND_INTERMEDIATE) {
        /* The intermediate's own name carries the generation, not the
         * count.  Without a readlink() there is nothing to read here: the
         * count lives in the *target's* name, which is exactly why this
         * cannot be a one-argument pure function. */
        return L2S_ENOTL2S;
    }

    return L2S_ENOTL2S;
}

int l2s_patch_nlink_value(struct stat *st, unsigned long nlink)
{
    if (st == NULL)
        return L2S_ERR;
    if (nlink < 1 || nlink > L2S_NLINK_MAX)
        return L2S_ERANGE;

    st->st_nlink = (nlink_t)nlink;
    return 1;
}

int l2s_patch_nlink(struct stat *st, const char *path)
{
    unsigned int nlink;
    int rc;

    if (st == NULL || path == NULL)
        return L2S_ERR;

    rc = nlink_from_path(path, &nlink);
    if (rc == L2S_ENOTL2S)
        return 0; /* nothing to emulate */
    if (rc != L2S_OK)
        return rc;

    return l2s_patch_nlink_value(st, nlink);
}

int l2s_patch_statx_nlink(unsigned int *stx_nlink, unsigned int *stx_mask,
                          unsigned int statx_nlink_bit, const char *path)
{
    unsigned int nlink;
    int rc;

    if (stx_nlink == NULL || stx_mask == NULL || path == NULL)
        return L2S_ERR;

    /* proroot's link2symlink_patch_statx_nlink() bails out first if the
     * kernel did not report STATX_NLINK; proot's handler always writes. */
    if ((*stx_mask & statx_nlink_bit) == 0)
        return 0;

    rc = nlink_from_path(path, &nlink);
    if (rc == L2S_ENOTL2S)
        return 0;
    if (rc != L2S_OK)
        return rc;

    *stx_nlink = nlink;
    return 1;
}

/* ------------------------------------------------------------------ */
/* Generation selection and chain arithmetic                          */
/* ------------------------------------------------------------------ */

int l2s_pick_generation(const l2s_config *cfg, const char *orig,
                        l2s_exists_fn exists, void *ctx,
                        unsigned int *out_generation)
{
    char candidate[L2S_PATH_MAX];
    unsigned int gen;

    if (orig == NULL || exists == NULL || out_generation == NULL)
        return L2S_ERR;

    /*
     *    intermediate_suffix = 1;
     *    do {
     *        sprintf(new_intermediate, "%s%04d", intermediate,
     *                intermediate_suffix);
     *        intermediate_suffix++;
     *    } while ((l2s_access(new_intermediate) != -1)
     *             && (intermediate_suffix < 1000));
     *
     * i.e. probe the generations in order and take the first one that is
     * free, where "free" is what access(F_OK) says -- and access() follows
     * symlinks, so a dangling intermediate counts as free.  That is the
     * caller's `exists` to reproduce.
     */
    for (gen = L2S_GEN_FIRST; gen <= L2S_GEN_LAST; gen++) {
        if (l2s_make_paths_ex(cfg, orig, gen, 1, NULL, candidate, NULL) != L2S_OK)
            return L2S_ERANGE;

        if (exists(candidate, ctx) == 0) {
            *out_generation = gen;
            return L2S_OK;
        }
    }

    /* PRoot leaves intermediate_suffix at 1000 and then strcpy()s the
     * 1000-suffixed name it just formatted, so it proceeds with a
     * generation PRoot itself considers occupied.  Report the exhaustion
     * instead of reproducing that. */
    *out_generation = L2S_GEN_GIVEUP;
    return L2S_ERANGE;
}

unsigned int l2s_chain_nlink(unsigned int links)
{
    if (links == 0)
        return 0;
    if (links > L2S_NLINK_MAX)
        return L2S_NLINK_MAX;
    return links;
}

/* ------------------------------------------------------------------ */
/* proroot metadata names                                             */
/* ------------------------------------------------------------------ */

/*
 * proroot's group/member key.
 *
 * Verified against the compiled libproroot-runtime.so v1.2.8 (sha256
 * 8c47a0a7db32d84c179ebb5bf3640f655a3181860ece5886ae44d92858730c34,
 * byte-identical to the published release asset): the four identical
 * hashing loops at 0x31028, 0x314d8, 0x31a64 and 0x326e0 are
 *
 *     h = 5381;                                  // mov x4, #0x1505
 *     for (p = <basename>; *p; p++)
 *         h = h + (h << 5) + (unsigned char)*p;  // 32-bit w accumulator
 *
 * i.e. plain djb2 with no finalizer and no cryptographic step -- there is
 * no MD5/SHA1 call and none of the usual FNV constants in the binary.
 * The hashed string is the BASENAME, computed as (path + length of the
 * meta root + 1), and the result is rendered as exactly 16 lowercase hex
 * nibbles, most significant first, from the table at .rodata:0x38340.
 *
 * Two consequences worth stating out loud:
 *   - the key is path-derived, not inode-derived, and it is unsalted, so
 *     two different basenames can collide in 32 bits.  proroot does not
 *     check for that;
 *   - because the key is only 32 bits, the top 8 of the 16 hex characters
 *     are always zero.  That is what proroot produces, so it is what we
 *     produce; it is not a bug in this transcription.
 */
uint32_t l2s_djb2(const char *s)
{
    uint32_t h = 5381;

    if (s == NULL)
        return h;

    for (; *s != '\0'; s++)
        h = h + (h << 5) + (uint32_t)(unsigned char)*s;

    return h;
}

void l2s_key16(const char *basename, char out[L2S_PROROOT_KEY_LEN + 1])
{
    static const char hex[] = "0123456789abcdef";
    uint32_t h;
    int i;

    if (basename == NULL)
        basename = "";

    h = l2s_djb2(basename);

    for (i = L2S_PROROOT_KEY_LEN - 1; i >= 0; i--) {
        out[i] = hex[h & 0xf];
        h >>= 4;
    }
    out[L2S_PROROOT_KEY_LEN] = '\0';
}

int l2s_meta_entry(const char *meta_dir, const char *prefix2,
                   const char *key16, char *out, size_t outsz)
{
    size_t dlen, plen;
    int rc;

    if (out == NULL || outsz == 0 || key16 == NULL)
        return L2S_ERR;
    if (!l2s_is_key16(key16))
        return L2S_EBADNAME;

    if (prefix2 == NULL)
        prefix2 = "";
    plen = strlen(prefix2);
    if (plen > 2)
        return L2S_EBADNAME;
    if (plen == 2 && !((prefix2[0] == 'g' || prefix2[0] == 'm') &&
                       prefix2[1] == '_'))
        return L2S_EBADNAME;
    if (plen == 1)
        return L2S_EBADNAME;

    dlen = (meta_dir == NULL) ? strlen(L2S_PROROOT_META_DIR)
                              : strlen(meta_dir);
    if (dlen == 0)
        return L2S_EBADNAME;

    /* <meta_dir>/<prefix2>, then the key: l2s_join inserts exactly one
     * separator, so the result is never "<dir>//g_..." or "<dir>g_...". */
    rc = l2s_join(meta_dir == NULL ? L2S_PROROOT_META_DIR : meta_dir, prefix2,
                  out, outsz);
    if (rc != L2S_OK)
        return rc;

    if (strlen(out) + L2S_PROROOT_KEY_LEN + 1 > outsz)
        return L2S_ENAMETOOLONG;

    /* l2s_join already appended prefix2 and its separator */
    strcat(out, key16);

    return L2S_OK;
}

int l2s_refcount_path(const char *path, char *out, size_t outsz)
{
    if (path == NULL || out == NULL || outsz == 0)
        return L2S_ERR;

    /* legacy_write_refcount() appends ".cnt" (5 bytes, from .rodata:0x38358
     * where the literal is a 4-byte load plus a 1-byte load) to the entry
     * name and writes the decimal count into it. */
    if (strlen(path) + strlen(L2S_PROROOT_CNT_SUFFIX) + 1 > outsz)
        return L2S_ENAMETOOLONG;

    strcpy(out, path);
    strcat(out, L2S_PROROOT_CNT_SUFFIX);
    return L2S_OK;
}
