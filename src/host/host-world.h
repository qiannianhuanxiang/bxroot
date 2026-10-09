/* Android native execution plan. Paths are resolved HOST backing paths. SPDX-License-Identifier: MIT */
#ifndef BXROOT_HOST_WORLD_H
#define BXROOT_HOST_WORLD_H
#include <stddef.h>
#include "host-common.h"
#define BX_HOST_PATH_MAX 4096

typedef struct {
    char interpreter[BX_HOST_PATH_MAX];
    char argument[256];
    char **rewritten;
    const char *target;
    char *const *argv;
} bx_host_plan;

/* Mapper follows bxroot_translate_path / px_runtime_translate: >0 writes
 * backing path; 0 keeps the input; <0 rejects the mapping. NULL is identity.
 * The main target is ALREADY a backing path; only shebang interpreter is mapped. */
typedef int (*bx_host_world_mapper)(const char *guest, char *backing, size_t cap);
int bx_host_world_classify_mapped(const char *path, bx_host_world_mapper mapper);
int bx_host_world_prepare_mapped(const char *host, char *const argv[],
                                  bx_host_world_mapper mapper, bx_host_plan *plan);
int bx_host_world_exec_mapped(const char *path, char *const argv[],
                               char *const envp[], bx_host_world_mapper mapper);
/* Legacy wrappers use NULL mapper (literal host interpreter). Production
 * guest exec dispatch must pass px_runtime_translate to the mapped APIs. */
int bx_host_world_enabled(void);
int bx_host_world_classify(const char *path);
int bx_host_world_resolve(const char *name, char *out, size_t cap);
int bx_host_world_prepare(const char *host, char *const argv[], bx_host_plan *plan);
void bx_host_world_dispose(bx_host_plan *plan);
int bx_host_world_build_env(char *const input[], char ***out);
void bx_host_world_free_env(char **env);
int bx_host_world_exec(const char *path, char *const argv[], char *const envp[]);
/* Check the script itself before exec'ing its interpreter. Raw host X_OK:
 * 0 = executable, -1 = rejected (errno retained), including readable 0644. */
int bx_host_world_script_access(const char *host);

#define BX_HOST_GUEST_DEFAULT_PATH "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
/* Shared by launcher and parent-side guest env construction. NULL selects the
 * respective default; an explicit empty guest PATH retains its current-dir
 * component; an explicit empty host PATH disables appending. Guest components
 * and ordering are unchanged; absolute host dirs are appended once.
 * Return 0 with a malloc-owned *out (caller free), or -1 with errno. */
int bx_host_world_guest_path(const char *guest_path, const char *host_path,
                              char **out);

/* Never grow the loader's original envp vector (auxv may follow its NULL).
 * Existing PATH slots are replaced in place to support bash's original envp.
 * Missing PATH returns BX_HOST_PATH_MISSING without modifying any slot: the
 * launcher/parent must add PATH using guest_path before starting the guest.
 * 0 = disabled/unchanged/updated; 1 = missing PATH; -1 = allocation error. */
#define BX_HOST_PATH_MISSING 1
int bx_host_world_init_path(void);
#endif
