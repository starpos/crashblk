/**
 * ioctl.h - data structure definictions for clashblk ioctl interface.
 */
#ifndef CRASHBLK_IOCTL_H
#define CRASHBLK_IOCTL_H

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
#define CRASHBLK_DYNAMIC_MINOR (-1U)

struct crashblk_ctl {
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
#define CRASHBLK_IOCTL_ID 0xfe
#define CRASHBLK_IOCTL_CMD 3

#define CRASHBLK_IOCTL _IOWR(CRASHBLK_IOCTL_ID, CRASHBLK_IOCTL_CMD, struct crashblk_ctl)

/**
 * For crashblk_ctl.command.
 */
enum {
	CRASHBLK_IOCTL_DUMMY = 0,

	/****************************************
	 * The target is /dev/crashblk_ctl
	 ****************************************/

	/*
	 * Start a crashblk device.
	 *
	 * INPUT: ctl->val_u64 as device size [logical block].
	 * OUTPUT: ctl->val_u32 as minor id.
	 * RETURN: 0 in success, or -EFAULT.
	 */
	CRASHBLK_IOCTL_START_DEV,

	/*
	 * Get major id.
	 *
	 * INPUT: None.
	 * OUTPUT: ctl->val_int as major id.
	 * RETURN: 0 in success, or -EFAULT.
	 */
	CRASHBLK_IOCTL_GET_MAJOR,

	/*
	 * Get number of crashblk devices.
	 *
	 * INPUT: None.
	 * OUTPUT: ctl->val_int as number of crashblk devices.
	 * RETURN: 0 in success, or -EFAULT.
	 */
	CRASHBLK_IOCTL_NUM_OF_DEV,

	/****************************************
	 * The targets are crashblk devices.
	 ****************************************/

	/*
	 * Stop a crashblk device.
	 *
	 * INPUT: None.
	 * OUTPUT: None.
	 * RETURN: 0 in success, or -EFAULT.
	 */
	CRASHBLK_IOCTL_STOP_DEV,

	/*
	 * Make the device crash.
	 *
	 * INPUT: None.
	 * OUTPUT: None.
	 * RETURN: 0 in success, or -EFAULT.
	 */
	CRASHBLK_IOCTL_CRASH,

	/*
	 * Make the device the state that IOs will fail.
	 *
	 * INPUT: ctl->val_int
	 *   CRASHBLK_STATE_READ_ERROR or
	 *   CRASHBLK_STATE_WRITE_ERROR or
	 *   CRASHBLK_STATE_RW_ERROR.
	 * OUTPUT: None.
	 * RETURN: 0 in success, or -EFAULT.
	 */
	CRASHBLK_IOCTL_IO_ERROR,

	/*
	 * Recover the device from crash or IO errors.
	 *
	 * INPUT: None.
	 * OUTPUT: None.
	 * RETURN: 0 in success, or -EFAULT.
	 */
	CRASHBLK_IOCTL_RECOVER,

	/*
	 * Get state
	 *
	 * INPUT: None.
	 * OUTPUT: ctl->val_int
	 *   CRASHBLK_STATE_XXX
	 */
	CRASHBLK_IOCTL_GET_STATE,
};

#define CRASHBLK_STATE_NORMAL            0
#define CRASHBLK_STATE_READ_ERROR        1
#define CRASHBLK_STATE_WRITE_ERROR       2
#define CRASHBLK_STATE_RW_ERROR          3
#define CRASHBLK_STATE_CRASHING          4
#define CRASHBLK_STATE_CRASHED           5

#ifdef __cplusplus
}
#endif

#endif /* CRASHBLK_IOCTL_H */
