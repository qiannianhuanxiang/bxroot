# Random shmid ABA reservation test

`RUN_SHM_ID_ABA.sh` tests the current allocator using a private copy of its source.
Only the allocator's single `getrandom` expression is replaced with a controlled
candidate sequence; production source has no random-override hook. All actual
reservation/segment opens, truncation, close, and RMID paths run unchanged.

Every fresh bxroot candidate reserves an empty `0400` `.id-ID` file atomically
with `O_CREAT|O_EXCL`, before creating the existing decimal `seg-ID` file. The
reservation is never deleted by RMID or allocation-error cleanup. Existing tokens
are not opened, overwritten, or deleted. Failed allocation after reservation may
leave a permanent token; that is intentional. Collisions consume at most 64
attempts and exhausted candidates return `ENOSPC`.

The guarantee is directory-lifetime uniqueness for IDs allocated by this version
of bxroot, assuming reservations are not externally removed. Each newly reserved
candidate consumes an inode and a directory entry, including failed creations.
Deleting reservation files or recreating the backing directory breaks the lifetime
guarantee. No automatic garbage collection is provided. Programs or official
proroot allocators that ignore these tokens are outside the guarantee.

Covered deterministic sequences:

- fixed 77: create, RMID, then 64 repeated 77 collisions return `ENOSPC`;
- 77 then 78: allocator chooses 78; another old RMID(77) leaves segment 78 intact;
- existing decimal segment 79: original contents survive collision, token 79 is
  retained, and 79 cannot be reused after removing the legacy segment;
- existing token 81: contents remain unchanged; next candidate 82 is used.

The probe cleans only its own known files inside its private `mkdtemp` fixture,
after validating reservation lifetime. No shared or unknown reservation is deleted.

Actual validation: `SHM_ID_ABA_PASS`; `-Wall -Wextra -Werror` allocator compilation
with claim/copyout gates enabled passes. Full-tree warn gate currently reports two
unrelated warnings in concurrently edited preload.c; allocator and sigsys are clean.
