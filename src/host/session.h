/* Versioned native reentry session. SPDX-License-Identifier: MIT */
#ifndef BXROOT_SESSION_H
#define BXROOT_SESSION_H
#include <stddef.h>
#define BX_SESSION_PATH 4096
#define BX_SESSION_MAX_KV 128
#define BX_SESSION_MAX_BINDS 16
#define BX_SESSION_MAX_BYTES (2u * 1024u * 1024u)
typedef struct { char *name, *value; } bx_session_kv;
typedef struct { char *host, *guest; unsigned ro; } bx_session_bind;
typedef struct {
    bx_session_kv kv[BX_SESSION_MAX_KV];
    bx_session_bind binds[BX_SESSION_MAX_BINDS];
    size_t nkv, nb;
} bx_session;
long bx_session_raw(long nr, long a, long b, long c, long d, long e, long f);
void bx_session_init(bx_session *s);
void bx_session_dispose(bx_session *s);
int bx_session_set(bx_session *s, const char *name, const char *value);
const char *bx_session_get(const bx_session *s, const char *name);
int bx_session_add_bind(bx_session *s, const char *host, const char *guest, unsigned ro);
/* Returns a sealed, read-only inherited fd >= 3, or -1. */
int bx_session_create_fd(const bx_session *s);
/* Requires an initialized empty destination; pread does not change fd offset. */
int bx_session_read(int fd, bx_session *s);
int bx_session_fd_number(const char *text);
/* Resolve guest links using guest semantics; missing final components allowed. */
int bx_session_to_host(const bx_session *s, const char *path, const char *cwd,
                       char *out, size_t cap);
/* Reject ambiguous mappings with ENOTUNIQ; verifies every candidate forward. */
int bx_session_to_guest(const bx_session *s, const char *path, char *out, size_t cap);
/* Runtime constructor only; optional weak dependency for isolated tests. */
void bx_native_session_capture(void);
int bx_native_session_init(void);
const char *bx_native_session_value(const char *name);
#endif
