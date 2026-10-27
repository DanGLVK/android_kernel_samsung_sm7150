// SPDX-License-Identifier: GPL-2.0-only
/*
 * prio_filter - "not running" shaping for cross-UID priority syscalls.
 *
 * Direct in-tree port of the fgetpriority LKM (which patched syscall table
 * slot 141, getpriority, with an unused-slot control channel) to an in-tree,
 * built-in-only implementation, extended per upstream request to also cover
 *:
 *   sys_getpriority()   kernel/sys.c
 *   sys_setpriority()   kernel/sys.c
 *   sys_ioprio_get()    block/ioprio.c
 *   sys_ioprio_set()    block/ioprio.c
 *
 * Origin: fgetpriority (local project, fgetpriority/kernel/routine.c).
 * Custom feature: no upstream / Qualcomm / Samsung equivalent exists for
 * per-UID priority-hiding (checked torvalds/linux and CAF priority syscall
 * implementations).  CONFIG_PRIO_FILTER defaults to n and the bitmap is
 * empty at boot, so stock behaviour is preserved bit-for-bit until root
 * userspace makes a UID visible to it.  Root-only control lives at
 * /sys/module/prio_filter/{command,state}; hide that path with SUSFS or any
 * other hiding layer if desired.
 *
 * Semantics (mirrors fgetpriority's getpriority_should_swap() as closely as
 * the API differs):
 *  - caller must be a Zygote-seccomped application (TIF_SECCOMP, uid >= 10000)
 *  - which must select PRIO_USER (2) / IOPRIO_WHO_USER (3)
 *  - the target may not be the caller itself (recognise-yourself controls)
 *  - the target application id (uid % 100000) must fall in [10000, 20000)
 *    and have its bit set by root
 * and if all of that holds the friendly answer is -ESRCH, which is the
 * stock kernel's own answer for "UID without running tasks" — see
 * kernel/sys.c (error = -ESRCH before the switch) and block/ioprio.c
 * (ret = -ESRCH initial).  Invalid `which` / ioprio class values keep their
 * stock -EINVAL paths: call sites only call us after their own validation.
 *
 * Answering mechanism (see PF_NO_TASKS_UID in include/linux/prio_filter.h):
 * on a hit the call site substitutes a dead uid (99999) and lets the
 * unmodified syscall body run, so errno *and* latency equal a plain
 * absent-uid lookup — there is no fast path for filtered targets and no
 * timing signature to observe.  History: the original hook returned
 * -ESRCH directly (fast-path latency leak, documented 4727738838eb);
 * local f93a82c2df28 equalized timing inside the uid arms but was
 * reverted for now; the dead-uid substitution supersedes both.
 */

#define pr_fmt(fmt) "prio_filter: " fmt

#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/module.h>	/* module_kset */
#include <linux/printk.h>
#include <linux/resource.h>	/* PRIO_USER */
#include <linux/ioprio.h>	/* IOPRIO_WHO_USER */
#include <linux/sched.h>
#include <linux/cred.h>		/* current_uid() / current_euid() */
#include <linux/seccomp.h>
#include <linux/string.h>
#include <linux/thread_info.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>

#include <linux/prio_filter.h>

/*
 * Android allocates one application id per app, 10000..19999.  The bitmap
 * is indexed by application id (uid % 100000), so secondary-user UIDs are
 * covered by the same bit as their user-0 twin.
 */
#define PF_APPID_FIRST	10000
#define PF_APPID_COUNT	10000	/* ids 10000..19999 */
#define PF_USER_OFFSET	100000

static DECLARE_BITMAP(pf_bitmap, PF_APPID_COUNT);

static inline bool pf_appid_applicable(unsigned int appid)
{
	return appid >= PF_APPID_FIRST && appid < PF_APPID_FIRST + PF_APPID_COUNT;
}

static inline unsigned int pf_appid_of(int who)
{
	return ((unsigned int)who) % PF_USER_OFFSET;
}

static __always_inline bool pf_caller_is_app(void)
{
	return current_uid().val >= PF_APPID_FIRST;
}

static inline bool pf_caller_is_seccomped(void)
{
#ifdef TIF_SECCOMP
	return test_thread_flag(TIF_SECCOMP);
#elif defined(CONFIG_SECCOMP)
	return current->seccomp.mode != SECCOMP_MODE_DISABLED;
#else
	return false;
#endif
}

bool prio_filter_blocks(enum prio_filter_site site, int which, int who)
{
	if ((site == PF_SITE_PRIO && which != PRIO_USER) ||
	    (site == PF_SITE_IOPRIO && which != IOPRIO_WHO_USER))
		return false;

	if (!pf_caller_is_seccomped())
		return false;

	if (!pf_caller_is_app())
		return false;

	/* always answer caller-own queries normally */
	if (who == current_uid().val)
		return false;

	if (who < 0)
		return false;

	if (!pf_appid_applicable(pf_appid_of(who)))
		return false;

	return test_bit(pf_appid_of(who) - PF_APPID_FIRST, pf_bitmap);
}
EXPORT_SYMBOL_GPL(prio_filter_blocks);

/*
 * /sys/module/prio_filter/command, 0200 root:root:
 *
 *   enable <uid>    start answering -ESRCH for <uid>
 *   disable <uid>   stop answering -ESRCH for <uid>
 *   reset           clear everything
 *
 * Only euid 0 may change state (su context); everyone else gets -EPERM.
 * Bits are keyed on the application id, so enabling 10042 or 110042 both
 * set bit 42.
 */
static int pf_apply_uid(unsigned int appid, bool enable)
{
	unsigned int bit = appid - PF_APPID_FIRST;

	if (enable) {
		set_bit(bit, pf_bitmap);
		pr_info("%s: appid %u\n", "enable", appid);
	} else {
		clear_bit(bit, pf_bitmap);
		pr_info("%s: appid %u\n", "disable", appid);
	}

	return 0;
}

static int pf_parse_command(const char *buf, size_t count)
{
	char cmd[16];
	int uid;
	int consumed = 0;

	/* one command per write; tolerate a trailing newline */
	if (sscanf(buf, "%15s%n", cmd, &consumed) != 1)
		return -EINVAL;

	if (!strcmp(cmd, "reset")) {
		bitmap_zero(pf_bitmap, PF_APPID_COUNT);
		pr_info("reset\n");
		return 0;
	}

	if (sscanf(buf + consumed, "%d", &uid) != 1)
		return -EINVAL;

	if (uid < 0 || !pf_appid_applicable(pf_appid_of(uid)))
		return -EINVAL;

	if (!strcmp(cmd, "enable"))
		return pf_apply_uid(pf_appid_of(uid), true);
	if (!strcmp(cmd, "disable"))
		return pf_apply_uid(pf_appid_of(uid), false);

	return -EINVAL;
}

static ssize_t pf_command_store(struct kobject *kobj, struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	int ret;

	if (current_euid().val != 0)
		return -EPERM;

	ret = pf_parse_command(buf, count);
	if (ret)
		return ret;

	return count;
}

/*
 * /sys/module/prio_filter/state, 0400 root:root:
 * hex dump of the bitmap, byte 0 = application id 10000 bit 0.
 */
static ssize_t pf_state_show(struct kobject *kobj, struct kobj_attribute *attr,
			     char *buf)
{
	const unsigned char *map = (const unsigned char *)pf_bitmap;
	static const char hex[] = "0123456789abcdef";
	size_t bytes = PF_APPID_COUNT / BITS_PER_BYTE;
	ssize_t pos = 0;
	size_t i;

	for (i = 0; i < bytes && pos + 3 < PAGE_SIZE; i++) {
		buf[pos++] = hex[map[i] >> 4];
		buf[pos++] = hex[map[i] & 0x0f];
		if ((i & 31) == 31)
			buf[pos++] = '\n';
	}

	return pos;
}

static struct kobj_attribute pf_command_attr =
	__ATTR(command, 0200, NULL, pf_command_store);

static struct kobj_attribute pf_state_attr =
	__ATTR(state, 0400, pf_state_show, NULL);

static struct attribute *pf_attrs[] = {
	&pf_command_attr.attr,
	&pf_state_attr.attr,
	NULL,
};

static const struct attribute_group pf_attr_group = {
	.attrs = pf_attrs,
};

static struct kobject *pf_kobj;

static int __init prio_filter_init(void)
{
	int ret;

	pf_kobj = kobject_create_and_add("prio_filter", &module_kset->kobj);
	if (!pf_kobj)
		return -ENOMEM;

	ret = sysfs_create_group(pf_kobj, &pf_attr_group);
	if (ret) {
		kobject_put(pf_kobj);
		return ret;
	}

	pr_info("ready: /sys/module/prio_filter (empty set, filtering disabled)\n");
	return 0;
}
fs_initcall(prio_filter_init);

/* built-in only, never a module (CONFIG_PRIO_FILTER is bool) */
#ifdef CONFIG_PRIO_FILTER_MODULE
#error "prio_filter must be built-in, not a module"
#endif
