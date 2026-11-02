/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * prio_filter - answer "not running" for selected application UIDs on
 * cross-UID priority syscalls.
 *
 * Direct in-tree port of the fgetpriority LKM
 * (fgetpriority/kernel/routine.c, sys_call_table slot 141 hook), extended to
 * also shape setpriority(), ioprio_get() and ioprio_set().  Custom feature:
 * no upstream or Qualcomm/Samsung equivalent exists (checked torvalds/linux
 * and CAF priority syscall implementations); the behaviour is opt-in
 * (CONFIG_PRIO_FILTER=n by default, bitmap empty) and identical to stock for
 * ordinary callers, so no userspace ABI break.
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
 * syscall body runs: no user_struct, no running tasks -> the stock code's
 * own absent-uid path answers -ESRCH (identical errno *and* identical
 * timing to querying any uid that is simply not running, so no fast-path
 * signature is observable).
 *
 * (uid_t)-1 is the kernel's own INVALID_UID sentinel value, so uid_valid()
 * is false by construction and the pass-through intact: argument
 * validation still runs, no existing user_struct or task can be attached
 * to it, and setters cannot reach their permission checks against a real
 * process.  Mechanism credited to upstream fgetpriority (aerath-stuff/
 * fgetpriority@7e8360bf), which rewrites `who` in the syscall table hook
 * prologue; here the rewrite happens inside the syscall body instead.
 *
 * Sentinel value credit: upstream aerath-stuff/fgetpriority@9deff90
 * ("Use an invalid UID for filtered priority operations") superseded the
 * former 99999 choice, the last isolated-uid slot.  Isolated uids *can*
 * own live tasks (up to LAST_ISOLATED_UID), and a substituted uid that a
 * real process holds would be answered *for* rather than with -ESRCH;
 * (uid_t)-1 cannot ever be mapped to a kuid a task carries.
 *
 * Callers querying this sentinel itself are unaffected: the filter
 * verdict for it is false (pf_appid_of((uid_t)-1) = 67295, outside the
 * [10000, 19999) window), and a negative `who` bails at the same
 * guard the stock body runs first regardless - such a query is stock
 * all the way through.
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
