// SPDX-License-Identifier: GPL-2.0-only
/*
 * prio_filter - "not running" shaping for cross-UID priority syscalls.
 *
 * In-tree port of the fgetpriority LKM (github.com/aerath-stuff/fgetpriority),
 * covering getpriority()/setpriority() (kernel/sys.c) and
 * ioprio_get()/ioprio_set() (block/ioprio.c).
 *
 * A call is filtered only when all of the following hold:
 *   - caller is a Zygote-seccomped application (TIF_SECCOMP, uid >= 10000)
 *   - `which` selects PRIO_USER / IOPRIO_WHO_USER (target != caller)
 *   - the target appid (uid % 100000) is in [10000, 20000) and either has
 *     its bitmap bit set (hma mode) or blanket mode is on
 * and a hit answers -ESRCH by substituting the unmappable PF_NO_TASKS_UID
 * and letting the stock body run (see include/linux/prio_filter.h for the
 * mechanism, timing and upstream credits).
 *
 * Root control (CONFIG_PRIO_FILTER_CONTROL=y) lives at
 * /sys/module/prio_filter/{command,mode,state}, defaults to hma and is
 * reset each boot like the bitmap.  With the interface compiled out the
 * filter is blanket-locked (see the CONFIG help text).  Hide that sysfs
 * path with SUSFS or any other hiding layer if desired.
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

/* blanket mode: every cross-app uid reads as "not running" (bitmap ignored) */
#ifdef CONFIG_PRIO_FILTER_CONTROL
static bool pf_blanket;
#else
/*
 * No control surface: the filter is locked in blanket mode, which is what
 * upstream fgetpriority operates as by default (its whitelist ships empty,
 * so every cross-app appid reads as "not running" and nothing is
 * configurable).  Nothing writes pf_blanket in this configuration, so the
 * verdict branch below is compile-time constant true.
 */
static bool pf_blanket = true;
#endif

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

	/* blanket mode: anything that is not the caller's own uid reads
	 * as "not running" (upstream fgetpriority blanket semantics) */
	if (pf_blanket)
		return true;

	return test_bit(pf_appid_of(who) - PF_APPID_FIRST, pf_bitmap);
}
EXPORT_SYMBOL_GPL(prio_filter_blocks);

/*
 * The userspace control interface (CONFIG_PRIO_FILTER_CONTROL): everything
 * below exists only when the interface is compiled in.  Without it these
 * functions are absent and no /sys/module/prio_filter exists at all - a
 * built-in driver only gets that directory via kobject_create_and_add()
 * below or a registered module_param (there is none), and the blank
 * pf_blanket default from above makes every cross-app read answer -ESRCH.
 */
#ifdef CONFIG_PRIO_FILTER_CONTROL

/*
 * /sys/module/prio_filter/command, 0200 root:root:
 *
 *   enable <uid>    start answering -ESRCH for <uid>
 *   disable <uid>   stop answering -ESRCH for <uid>
 *   reset           clear everything
 *   mode hma        verdicts come from the bitmap (default)
 *   mode blanket    every cross-app uid answers -ESRCH (bitmap ignored)
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
	char arg[16];
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

	if (!strcmp(cmd, "mode")) {
		if (sscanf(buf + consumed, "%15s", arg) != 1)
			return -EINVAL;
		if (!strcmp(arg, "hma")) {
			pf_blanket = false;
			pr_info("mode: hma (bitmap seeding)\n");
			return 0;
		}
		if (!strcmp(arg, "blanket")) {
			pf_blanket = true;
			pr_info("mode: blanket (all cross-app reads absent)\n");
			return 0;
		}
		return -EINVAL;
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
 * /sys/module/prio_filter/mode, 0400 root:root:
 *   "hma"     - the bitmap decides (fgetp-seeded, the default)
 *   "blanket" - every app uid outside the caller's own reads as not running
 *               (bitmap still seedable but ignored by verdicts); zero-config,
 *               but aggregate "task UIDs found" counters collapse to ~0 for
 *               scanning apps, which is itself a fingerprint
 */
static ssize_t pf_mode_show(struct kobject *kobj, struct kobj_attribute *attr,
			    char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%s\n", pf_blanket ? "blanket" : "hma");
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

static struct kobj_attribute pf_mode_attr =
	__ATTR(mode, 0400, pf_mode_show, NULL);

static struct attribute *pf_attrs[] = {
	&pf_command_attr.attr,
	&pf_state_attr.attr,
	&pf_mode_attr.attr,
	NULL,
};

static const struct attribute_group pf_attr_group = {
	.attrs = pf_attrs,
};

static struct kobject *pf_kobj;
#endif /* CONFIG_PRIO_FILTER_CONTROL */

static int __init prio_filter_init(void)
{
#ifdef CONFIG_PRIO_FILTER_CONTROL
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
#else
	/*
	 * Interface-less build: no device-visible control path at all; the
	 * blanket default in pf_blanket cannot be changed at runtime.
	 */
	pr_info("ready: blanket mode, no control interface\n");
#endif
	return 0;
}
fs_initcall(prio_filter_init);

/* built-in only, never a module (CONFIG_PRIO_FILTER is bool) */
#ifdef CONFIG_PRIO_FILTER_MODULE
#error "prio_filter must be built-in, not a module"
#endif
