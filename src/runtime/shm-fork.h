#ifndef BXROOT_SHM_FORK_H
#define BXROOT_SHM_FORK_H

/*
 * Fork handoff between preload's pthread_atfork callbacks and sysvshm.
 * Implementations must not wait, allocate, log, unlock a parent's OFD lock,
 * or clear inherited ACTIVE attach entries in these callbacks.
 */
/* The exported fork wrapper MUST begin before libc fork; busy returns -EAGAIN.
 * Both parent and child end after libc returns. Notification callbacks cannot
 * cancel fork, so they do not provide protection for raw clone/_Fork. */
int bxroot_sysvshm_fork_begin(void);
void bxroot_sysvshm_fork_end(void);
void bxroot_sysvshm_fork_prepare(void);
void bxroot_sysvshm_fork_parent(void);
void bxroot_sysvshm_fork_child(void);

#endif
