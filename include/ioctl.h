/**
 * ioctl.h - data structure definictions for bdevt ioctl interface.
 */
#ifndef BDEVT_IOCTL_H
#define BDEVT_IOCTL_H

#ifdef __KERNEL__
#include <linux/kernel.h>
#include <linux/ioctl.h>
#else /* __KERNEL__ */
#include <stdio.h>
#include <sys/ioctl.h>
#endif /* __KERNEL__ */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * If you want to assign device minor automatically, specify this.
 */
#define BDEVT_DYNAMIC_MINOR (-1U)

struct bdevt_ctl {
	/* Command id. */
	int command;

	/* Used for integer value transfer. */
	union {
		int val_int;
		u64 val_u64;
		u32 val_u32;
	};
} __attribute__((packed));

/**
 * Ioctl command id/cmd.
 */
#define BDEVT_IOCTL_ID 0xfe
#define BDEVT_IOCTL_CMD 3

#define BDEVT_IOCTL _IOWR(BDEVT_IOCTL_ID, BDEVT_IOCTL_CMD, struct bdevt_ctl)

/**
 * For bdevt_ctl.command.
 */
enum {
	BDEVT_IOCTL_DUMMY = 0,

	/****************************************
	 * The target is /dev/bdevt_ctl
	 ****************************************/

	/*
	 * Start a bdevt device.
	 *
	 * INPUT: ctl->val_u64 as device size [logical block].
	 * OUTPUT: ctl->val_u32 as minor id.
	 * RETURN: 0 in success, or -EFAULT.
	 */
	BDEVT_IOCTL_START_DEV,

	/*
	 * Get major id.
	 *
	 * INPUT: None.
	 * OUTPUT: ctl->val_u32 as major id.
	 * RETURN: 0 in success, or -EFAULT.
	 */
	BDEVT_IOCTL_GET_MAJOR,

	/*
	 * Get number of bdevt devices.
	 *
	 * INPUT: None.
	 * OUTPUT: ctl->val_int as number of bdevt devices.
	 * RETURN: 0 in success, or -EFAULT.
	 */
	BDEVT_IOCTL_NUM_OF_DEV,

	/****************************************
	 * The targets are bdevt devices.
	 ****************************************/

	/*
	 * Stop a bdevt device.
	 *
	 * INPUT: None.
	 * OUTPUT: None.
	 * RETURN: 0 in success, or -EFAULT.
	 */
	BDEVT_IOCTL_STOP_DEV,

	/*
	 * Make the device crash.
	 *
	 * INPUT: None.
	 * OUTPUT: None.
	 * RETURN: 0 in success, or -EFAULT.
	 */
	BDEVT_IOCTL_MAKE_CRASH,

	/*
	 * Recover the device from crash.
	 *
	 * INPUT: None.
	 * OUTPUT: None.
	 * RETURN: 0 in success, or -EFAULT.
	 */
	BDEVT_IOCTL_RECOVER_CRASH,

	/*
	 * Make the device the state that IOs will fail.
	 *
	 * INPUT: ctl->val_int
	 *   0: read will fail.
	 *   1: write will fail.
	 *   2: both will fail.
	 * OUTPUT: None.
	 * RETURN: 0 in success, or -EFAULT.
	 */
	BDEVT_IOCTL_MAKE_ERROR,

	/*
	 * Recover the device from error.
	 *
	 * INPUT: None.
	 * OUTPUT: None.
	 * RETURN: 0 in success, or -EFAULT.
	 */
	BDEVT_IOCTL_RECOVER_ERROR,
};

#ifdef __cplusplus
}
#endif

#endif /* BDEVT_IOCTL_H */
