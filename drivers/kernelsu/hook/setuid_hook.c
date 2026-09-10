#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs_def.h>
#endif // #ifdef CONFIG_KSU_SUSFS

#ifdef CONFIG_KSU_SUSFS
static inline bool is_zygote_isolated_service_uid(uid_t uid)
{
	uid %= 100000;
	return (uid >= 99000 && uid < 100000);
}

static inline bool is_zygote_normal_app_uid(uid_t uid)
{
	uid %= 100000;
	return (uid >= 10000 && uid < 19999);
}

extern u32 susfs_zygote_sid;

// - susfs_extra_works is defined and initialized (via INIT_WORK) in fs/susfs.c.
//   Its work handler, susfs_run_extra_works(), takes care of re-flagging sus
//   paths (and any other deferred susfs works) with the proper ksu_cred context
//   applied internally, so we only need to queue it here.
extern struct work_struct susfs_extra_works;

#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
extern void susfs_try_umount(uid_t uid);
#endif // #ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
#endif // #ifdef CONFIG_KSU_SUSFS

static __always_inline void ksu_handle_setresuid_cred(struct cred *new, const struct cred *old)
{
	if (!new || !old)
		return;

	uid_t new_uid = ksu_get_uid_t(new->uid);
	uid_t old_uid = ksu_get_uid_t(old->uid);

	// old process is not root, ignore it.
	if (unlikely(!!old_uid))
		return;

	if (IS_ENABLED(CONFIG_KSU_DEBUG))
		pr_info("handle_setresuid from %d to %d\n", old_uid, new_uid);

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	// Check if spawned process is isolated service first, and force to do umount if so
	if (is_zygote_isolated_service_uid(new_uid)) {
		goto do_umount;
	}
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT

	// we dont have those new fancy things upstream has
	// lets just do the original thing where we disable seccomp
	if (unlikely(is_uid_manager(new_uid)))
		goto install_ksu_fd;

	if (ksu_is_allow_uid_for_current(new_uid))
		goto kill_seccomp;

	// Handle kernel umount
	goto do_umount;

install_ksu_fd:
	pr_info("install fd for manager: %d\n", new_uid);
	ksu_install_fd();

kill_seccomp:
	disable_seccomp();
	set_thread_flag(TIF_KSU_MANAGED); // sucompat fast-path
	return;
do_umount:
#ifndef CONFIG_KSU_SUSFS_TRY_UMOUNT
	ksu_handle_umount(new, old);
#else
	susfs_try_umount(new_uid);
#endif // #ifndef CONFIG_KSU_SUSFS_TRY_UMOUNT

#ifdef CONFIG_KSU_SUSFS
	// - defer extra susfs works to workqueue after do_umount so that we do not
	//   block here and reduce the risk of time side channel as much as possible.
	//   susfs_extra_works is initialized in susfs_init() and its handler runs
	//   susfs_run_sus_path_loop() (which now applies ksu_cred internally) on a
	//   background kernel worker thread.
	queue_work(system_wq, &susfs_extra_works);

	susfs_set_current_proc_umounted();

	return;
#endif // #ifdef CONFIG_KSU_SUSFS
}

