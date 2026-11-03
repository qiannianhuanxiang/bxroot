/* Select a trampoline/linker pair without mixing nested-container worlds. */
#ifndef BXROOT_TRAMP_CONFIG_H
#define BXROOT_TRAMP_CONFIG_H

enum bxroot_tramp_pair_kind {
    BXROOT_TRAMP_NONE = 0,
    BXROOT_TRAMP_OWN = 1,
    BXROOT_TRAMP_DERIVED = 2,
    BXROOT_TRAMP_OUTER = 3
};

static inline int bxroot_tramp_value_present(const char *value)
{
    return value != 0 && value[0] != '\0';
}

static inline int bxroot_tramp_pair_select(
    const char *own_tramp, const char *own_linker, int own_hint,
    const char *bxroot_tramp, const char *bxroot_linker,
    const char *derived_tramp, const char *derived_linker,
    const char *outer_tramp, const char *outer_linker,
    const char **out_tramp, const char **out_linker)
{
    const char *own_t = bxroot_tramp_value_present(own_tramp) ? own_tramp : bxroot_tramp;
    const char *own_l = bxroot_tramp_value_present(own_linker) ? own_linker : bxroot_linker;
    int have_own = own_hint || bxroot_tramp_value_present(own_t) ||
                   bxroot_tramp_value_present(own_l);

    if (out_tramp == 0 || out_linker == 0) return BXROOT_TRAMP_NONE;
    *out_tramp = 0;
    *out_linker = 0;

    if (bxroot_tramp_value_present(own_t) && bxroot_tramp_value_present(own_l)) {
        *out_tramp = own_t;
        *out_linker = own_l;
        return BXROOT_TRAMP_OWN;
    }
    if (bxroot_tramp_value_present(derived_tramp) &&
        bxroot_tramp_value_present(derived_linker)) {
        *out_tramp = bxroot_tramp_value_present(own_t) ? own_t : derived_tramp;
        *out_linker = bxroot_tramp_value_present(own_l) ? own_l : derived_linker;
        return BXROOT_TRAMP_DERIVED;
    }

    /* A partial own configuration must never be completed by outer values. */
    if (have_own) {
        *out_tramp = own_t;
        *out_linker = own_l;
        return BXROOT_TRAMP_NONE;
    }
    if (bxroot_tramp_value_present(outer_tramp) &&
        bxroot_tramp_value_present(outer_linker)) {
        *out_tramp = outer_tramp;
        *out_linker = outer_linker;
        return BXROOT_TRAMP_OUTER;
    }
    return BXROOT_TRAMP_NONE;
}

#endif
