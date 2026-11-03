/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * prio_filter - answer "not running" for selected application UIDs on
 * cross-UID priority syscalls.
 *
 * In-tree port of the fgetpriority LKM
 * (github.com/aerath-stuff/fgetpriority), extended beyond its
 * getpriority() hook to setpriority() and the ioprio family.  Opt-in
 * (CONFIG_PRIO_FILTER default n, bitmap empty) and identical to stock
 * for ordinary callers, so no userspace ABI break.
 */
#ifndef _LINUX_PRIO_FILTER_H
#define _LINUX_PRIO_FILTER_H

#include <linux/types.h>
#include <linux/compiler.h>

/*
 * Which syscall family is asking.  PRIO_* (PRIO_USER = 2) and
 * IOPRIO_WHO_* (IOPRIO_WHO_USER = 3) live in different `which` spaces, so
 * every call site passes its own discriminator.
 */
enum prio_filter_site {
	PF_SITE_PRIO = 1,	/* sys_getpriority() / sys_setpriority() */
	PF_SITE_IOPRIO = 2,	/* sys_ioprio_get() / sys_ioprio_set() */
};

/*
 * An unmappable uid substituted for a hidden target before the stock
 * syscall body runs.  (uid_t)-1 is the kernel's INVALID_UID: uid_valid()
 * is false, no user_struct/task can be attached to it, so the stock
 * absent-uid path answers -ESRCH with the same errno *and* latency as
 * querying an uid that is simply not running (no fast-path signature).
 *
 * Mechanism credit: fgetpriority@7e8360bf, which rewrites `who` in its
 * syscall-table hook prologue; here the rewrite happens inside the
 * syscall body.  Sentinel value credit: fgetpriority@9deff90, whose
 * (uid_t)-1 replaced the earlier 99999 choice (last isolated-uid slot)
 * since isolated uids can hold live tasks.
 *
 * Queries passing who == -1 are stock: prio_filter_blocks() rejects
 * negative `who` up front (pf_appid_of() would be 67295, outside the
 * appid window).
 */
#define PF_NO_TASKS_UID		((int)(uid_t)-1)

#ifdef CONFIG_PRIO_FILTER

bool prio_filter_blocks(enum prio_filter_site site, int which, int who);

#else /* !CONFIG_PRIO_FILTER */

static inline bool prio_filter_blocks(enum prio_filter_site site, int which, int who)
{
	return false;
}

#endif /* CONFIG_PRIO_FILTER */

#endif /* _LINUX_PRIO_FILTER_H */
