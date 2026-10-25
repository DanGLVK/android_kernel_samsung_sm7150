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

#ifdef CONFIG_PRIO_FILTER

bool prio_filter_blocks(enum prio_filter_site site, int which, int who);

#else /* !CONFIG_PRIO_FILTER */

static inline bool prio_filter_blocks(enum prio_filter_site site, int which, int who)
{
	return false;
}

#endif /* CONFIG_PRIO_FILTER */

#endif /* _LINUX_PRIO_FILTER_H */
