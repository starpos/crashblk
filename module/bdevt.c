/**
 * bdevt.c - a memory block device driver for test.
 *
 * (C) 2014, Cybozu Labs, Inc.
 * @author HOSHINO Takashi <hoshino@labs.cybozu.co.jp>
 */
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/workqueue.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/compat.h>
#include <linux/miscdevice.h>

#include "common.h"
#include "block_size.h"
#include "logger.h"
#include "size_list.h"
#include "build_date.h"
#include "ioctl.h"

/*******************************************************************************
 * Struct definition.
 *******************************************************************************/

struct bdevt_dev
{
	struct list_head list;
	u32 index;
	struct request_queue *q;
	struct gendisk *disk;
};

/*******************************************************************************
 * Module variable definitions.
 *******************************************************************************/

static int major_;
static int pbs_ = 512;

static LIST_HEAD(dev_list_);
static struct mutex lock_;
static int dev_indexes_ = 0;

/*******************************************************************************
 * Module parameter definitions.
 *******************************************************************************/

module_param_named(pbs, pbs_, int, S_IRUGO);
MODULE_PARM_DESC(pbs, "Physical block size [byte]");

/*******************************************************************************
 * Macro definitions.
 *******************************************************************************/

#define BDEVT_NAME "bdevt"
#define BDEVT_CTL_NAME "bdevt_ctl"

/*******************************************************************************
 * Static functions definition.
 *******************************************************************************/

static inline void print_bvec_iter(struct bvec_iter *iter, const char *prefix)
{
	pr_info("%sbvec_iter: sector %" PRIu64 " size %u idx %u bvec_done %u\n"
		, prefix
		, (u64)iter->bi_sector
		, iter->bi_size
		, iter->bi_idx
		, iter->bi_bvec_done);
}

static inline void print_bio_vec(struct bio_vec *bv, const char *prefix)
{
	pr_info("%sbio_vec: page %p len %u offset %u\n"
		, prefix
		, bv->bv_page
		, bv->bv_len
		, bv->bv_offset);
}

static inline void print_bio(struct bio *bio)
{
	struct bio_vec bv;
	struct bvec_iter iter;

	if (!bio) {
		pr_info("bio null\n");
		return;
	}
	pr_info("bio %p\n"
		"  bi_next %p\n"
		"  bi_flags %lx\n"
		"  bi_rw %lx\n"
		"  bi_phys_segments %u\n"
		"  bi_seg_front_size %u\n"
		"  bi_seg_back_size %u\n"
		"  bi_remaining %d\n"
		"  bi_end_io %p\n"
		"  bi_private %p\n"
		"  bi_vcnt %u\n"
		"  bi_max_vecs %u\n"
		"  bi_cnt %d\n"
		, bio
		, bio->bi_next
		, bio->bi_flags
		, bio->bi_rw
		, bio->bi_phys_segments
		, bio->bi_seg_front_size
		, bio->bi_seg_back_size
		, atomic_read(&bio->bi_remaining)
		, bio->bi_end_io
		, bio->bi_private
		, bio->bi_vcnt
		, bio->bi_max_vecs
		, atomic_read(&bio->bi_cnt));
	print_bvec_iter(&bio->bi_iter, "  cur ");

	bio_for_each_segment(bv, bio, iter) {
		print_bvec_iter(&iter, "  ");
		print_bio_vec(&bv, "  ");
	}
}

static struct bio_list split_bio_sectors(struct bio *bio)
{
	struct bio_list bl;
	bio_list_init(&bl);
	if (!bio_has_data(bio)) {
		bio_list_add(&bl, bio);
		return bl;
	}
	while (bio_sectors(bio) > 1) {
		struct bio *split;
	retry:
		split = bio_split(bio, 1, GFP_NOIO, fs_bio_set);
		if (!split) {
			schedule();
			goto retry;
		}
		bio_list_add(&bl, split);
	}
	bio_list_add(&bl, bio);
	return bl;
}

static void bdevt_queue_bio(struct request_queue *q, struct bio *bio)
{
	struct bio *clone, *bio2;
	struct bio_list bl;

	/* struct bdevt_dev *mdev = q->queuedata; */
	print_bio(bio);

retry0:
	clone = bio_clone(bio, GFP_NOIO);
	if (!clone) {
		LOGw("bio_clone failed %p.\n", bio);
		goto retry0;
	}

	bl = split_bio_sectors(clone);
	pr_info("split begin %u\n", bio_list_size(&bl));
	while ((bio2 = bio_list_pop(&bl))) {
		print_bio(bio2);
		bio_put(bio2);
	}
	ASSERT(bio_list_empty());
	pr_info("split end\n");

	/* do nothing and complete the IO. */

	pr_info("advance\n");
	while (bio_sectors(bio) > 0) {
		bio_advance(bio, LBS);
		print_bio(bio);
	}
	bio_endio(bio, 0);
}

static int bdevt_open(struct block_device *bdev, fmode_t mode)
{
	return 0;
}

static void bdevt_release(struct gendisk *gd, fmode_t mode)
{
	/* do nothing */
}

static int bdevt_ioctl(struct block_device *bdev, fmode_t mode,
			unsigned int cmd, unsigned long arg)
{
	return -ENOTTY;
}

/*******************************************************************************
 * Static variables definition.
 *******************************************************************************/

static struct block_device_operations bdevt_devops_ = {
	.owner		 = THIS_MODULE,
	.open		 = bdevt_open,
	.release	 = bdevt_release,
	.ioctl		 = bdevt_ioctl
};

/*******************************************************************************
 * Static functions definition.
 *******************************************************************************/

static void del_dev(struct bdevt_dev *mdev)
{
	list_del_init(&mdev->list);

	del_gendisk(mdev->disk);
	blk_cleanup_queue(mdev->q);
	put_disk(mdev->disk);
	kfree(mdev);
}

static bool add_dev(u64 size_lb)
{
	struct bdevt_dev *mdev;
	struct gendisk *disk;
	struct request_queue *q;

	mdev = kzalloc(sizeof(*mdev), GFP_KERNEL);
	if (!mdev)
		return -ENOMEM;

	INIT_LIST_HEAD(&mdev->list);

	q = mdev->q = blk_alloc_queue(GFP_KERNEL);
	if (!q) {
		LOGe("mdev->q init failed.\n");
		goto error0;
	}
	q->queuedata = mdev;
	blk_queue_make_request(q, bdevt_queue_bio);
	disk = mdev->disk = alloc_disk(1);
	if (!disk) {
		LOGe("mdev->disk alloc failed.\n");
		goto error1;
	}

	mutex_lock(&lock_);
	list_add_tail(&mdev->list, &dev_list_);
	mdev->index = dev_indexes_++;
	mutex_unlock(&lock_);

	blk_queue_logical_block_size(q, LBS);
	blk_queue_physical_block_size(q, pbs_);
	blk_queue_io_min(q, pbs_);
	blk_queue_io_opt(q, pbs_);
	q->limits.discard_granularity = pbs_;
	q->limits.max_discard_sectors = -1;
	q->limits.discard_zeroes_data = 0;
	queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, q);

	set_capacity(disk, size_lb);

	disk->flags |= GENHD_FL_EXT_DEVT;
	disk->major = major_;
	disk->first_minor = mdev->index;
	disk->fops = &bdevt_devops_;
	disk->private_data = mdev;
	disk->queue = q;
	sprintf(disk->disk_name, "%s%u", BDEVT_NAME, mdev->index);
	add_disk(disk);
	return true;

error1:
	blk_cleanup_queue(mdev->q);
error0:
	kfree(mdev);
	return false;
}

static void exit_all_devices(void)
{
	mutex_lock(&lock_);
	while (!list_empty(&dev_list_)) {
		struct bdevt_dev *mdev =
			list_entry(dev_list_.next, struct bdevt_dev, list);
		del_dev(mdev);
	}
	mutex_unlock(&lock_);
}

static bool is_valid_params(void)
{
	if (pbs_ != 512 && pbs_ != 4096) {
		LOGe("pbs must be 512 or 4096.\n");
		return false;
	}

	return true;
}

static void init_globals(void)
{
	mutex_init(&lock_);
}

/*******************************************************************************
 * Ioctl functions.
 *******************************************************************************/

static int ioctl_start_dev(struct bdevt_ctl *ctl)
{
	/* QQQ */
	return -EFAULT;
}
static int ioctl_get_major(struct bdevt_ctl *ctl)
{
	/* QQQ */
	return -EFAULT;
}
static int ioctl_num_of_dev(struct bdevt_ctl *ctl)
{
	/* QQQ */
	return -EFAULT;
}

static int dispatch_ioctl(struct bdevt_ctl *ctl)
{
	size_t i;
	struct {
		int id;
		int (*handler)(struct bdevt_ctl *ctl);
	} tbl[] = {
		{BDEVT_IOCTL_START_DEV, ioctl_start_dev},
		{BDEVT_IOCTL_GET_MAJOR, ioctl_get_major},
		{BDEVT_IOCTL_NUM_OF_DEV, ioctl_num_of_dev},
	};

	for (i = 0; i < sizeof(tbl); i++) {
		if (ctl->command == tbl[i].id)
			return tbl[i].handler(ctl);
	}
	LOGe("dispatch_ioctl: command %d is not supported.\n",
		ctl->command);
	return -ENOTTY;
}

static struct bdevt_ctl *bdevt_get_ctl(void __user *userctl, gfp_t gfp_mask)
{
	struct bdevt_ctl *ctl;

	ctl = kzalloc(sizeof(*ctl), gfp_mask);
	if (!ctl) {
		LOGe("memory allocation for bdevt_ctl error.\n");
		goto error0;
	}

	if (copy_from_user(ctl, userctl, sizeof(*ctl))) {
		LOGe("copy_from_user failed.\n");
		goto error1;
	}

	return ctl;

error1:
	kfree(ctl);
error0:
	return NULL;
}

static bool bdevt_put_ctl(void __user *userctl, struct bdevt_ctl *ctl)
{
	bool ret = true;

	if (copy_to_user(userctl, ctl, sizeof(*ctl)))
		ret = false;

	kfree(ctl);
	return ret;
}

static long bdevt_ctl_ioctl(struct file *file, unsigned int command, unsigned long u)
{
	int ret;
	struct bdevt_ctl *ctl;
	struct bdevt_ctl __user *user = (struct bdevt_ctl __user *)u;

	if (command != BDEVT_IOCTL_CMD)
		return -EFAULT;

	ctl = bdevt_get_ctl(user, GFP_KERNEL);
	if (!ctl)
		return -EFAULT;

	ret = dispatch_ioctl(ctl);

	if (!bdevt_put_ctl(user, ctl))
		return -EFAULT;

	return ret;
}

#ifdef CONFIG_COMPAT
static long bdevt_ctl_compat_ioctl(struct file *file, unsigned int command, unsigned long u)
{
	return bdevt_ctl_ioctl(file, command, (unsigned long)compat_ptr(u));
}
#endif

static const struct file_operations ctl_fops_ = {
	.open = nonseekable_open,
	.unlocked_ioctl = bdevt_ctl_ioctl,
	.compat_ioctl = bdevt_ctl_compat_ioctl,
	.owner = THIS_MODULE,
};

static struct miscdevice bdevt_misc_ = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = BDEVT_NAME,
	.nodename = BDEVT_CTL_NAME,
	.fops = &ctl_fops_,
};

/*******************************************************************************
 * Init/exit functions definition.
 *******************************************************************************/

static int __init bdevt_init(void)
{
	LOGi("%s module init.\n", BDEVT_NAME);
	LOGi("build date: " BUILD_DATE "\n");

	if (!is_valid_params()) goto error0;
	init_globals();

	/* Register a block device module. */
	major_ = register_blkdev(0, BDEVT_NAME);
	if (major_ <= 0) {
		LOGe("unable to get major device number.\n");
		goto error0;
	}

	if (misc_register(&bdevt_misc_) < 0) {
		LOGe("unable to register control device.\n");
		goto error1;
	}

	return 0;
#if 0
error2:
	misc_deregister(&bdevt_misc_);
#endif
error1:
	unregister_blkdev(major_, BDEVT_NAME);
	return -ENOMEM;
error0:
	return -EBUSY;
}

static void __exit bdevt_exit(void)
{
	misc_deregister(&bdevt_misc_);
	exit_all_devices();
	unregister_blkdev(major_, BDEVT_NAME);
	LOGi("%s module exit.\n", BDEVT_NAME);
}

module_init(bdevt_init);
module_exit(bdevt_exit);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("a memory block device driver for test");
MODULE_ALIAS(BDEVT_NAME);
/* MODULE_ALIAS_BLOCKDEV_MAJOR(BDEVT_MAJOR); */
