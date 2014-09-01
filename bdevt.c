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

#include "common.h"
#include "block_size.h"
#include "logger.h"
#include "size_list.h"
#include "build_date.h"

/*******************************************************************************
 * Struct definition.
 *******************************************************************************/

struct smpl_dev
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
static int nr_dev_ = 1;
/* specify 1m,2m ot create two device with 1MiB, 2MiB sizes */
static char *dev_sizes_ = "1m";

static LIST_HEAD(dev_list_);
static struct mutex lock_;
static int dev_indexes_ = 0;
static int hw_queue_depth_ = 64;
static int nr_submit_queues_ = 1;

/*******************************************************************************
 * Module parameter definitions.
 *******************************************************************************/

module_param_named(pbs, pbs_, int, S_IRUGO);
MODULE_PARM_DESC(pbs, "Physical block size [byte]");
module_param_named(nr_dev, nr_dev_, int, S_IRUGO);
MODULE_PARM_DESC(nr_dev, "Number of devices");
module_param_named(hw_queue_depth, hw_queue_depth_, int, S_IRUGO);
MODULE_PARM_DESC(hw_queue_depth, "Hardware queue depth.");
module_param_named(nr_submit_queues, nr_submit_queues_, int, S_IRUGO);
MODULE_PARM_DESC(nr_submit_queues, "Number of submit queues.");
module_param_named(dev_sizes, dev_sizes_, charp, S_IRUGO);
MODULE_PARM_DESC(dev_sizes, "Device size lists separated by comma. ex. '1m,2m'");

/*******************************************************************************
 * Macro definitions.
 *******************************************************************************/

#define SMPL_NAME "bio_none"

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

static void smpl_queue_bio(struct request_queue *q, struct bio *bio)
{
	struct bio *clone, *bio2;
	struct bio_list bl;

	/* struct smpl_dev *sdev = q->queuedata; */
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

static int smpl_open(struct block_device *bdev, fmode_t mode)
{
	return 0;
}

static void smpl_release(struct gendisk *gd, fmode_t mode)
{
	/* do nothing */
}

static int smpl_ioctl(struct block_device *bdev, fmode_t mode,
			unsigned int cmd, unsigned long arg)
{
	return -ENOTTY;
}

/*******************************************************************************
 * Static variables definition.
 *******************************************************************************/

static struct block_device_operations smpl_devops_ = {
	.owner		 = THIS_MODULE,
	.open		 = smpl_open,
	.release	 = smpl_release,
	.ioctl		 = smpl_ioctl
};

/*******************************************************************************
 * Static functions definition.
 *******************************************************************************/

static void del_dev(struct smpl_dev *sdev)
{
	list_del_init(&sdev->list);

	del_gendisk(sdev->disk);
	blk_cleanup_queue(sdev->q);
	put_disk(sdev->disk);
	kfree(sdev);
}

static bool add_dev(u64 size_lb)
{
	struct smpl_dev *sdev;
	struct gendisk *disk;
	struct request_queue *q;

	sdev = kzalloc(sizeof(*sdev), GFP_KERNEL);
	if (!sdev)
		return -ENOMEM;

	INIT_LIST_HEAD(&sdev->list);

	q = sdev->q = blk_alloc_queue(GFP_KERNEL);
	if (!q) {
		LOGe("sdev->q init failed.\n");
		goto error0;
	}
	q->queuedata = sdev;
	blk_queue_make_request(q, smpl_queue_bio);
	disk = sdev->disk = alloc_disk(1);
	if (!disk) {
		LOGe("sdev->disk alloc failed.\n");
		goto error1;
	}

	mutex_lock(&lock_);
	list_add_tail(&sdev->list, &dev_list_);
	sdev->index = dev_indexes_++;
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
	disk->first_minor = sdev->index;
	disk->fops = &smpl_devops_;
	disk->private_data = sdev;
	disk->queue = q;
	sprintf(disk->disk_name, "%s%u", SMPL_NAME, sdev->index);
	add_disk(disk);
	return true;

error1:
	blk_cleanup_queue(sdev->q);
error0:
	kfree(sdev);
	return false;
}

static void exit_all_devices(void)
{
	mutex_lock(&lock_);
	while (!list_empty(&dev_list_)) {
		struct smpl_dev *sdev =
			list_entry(dev_list_.next, struct smpl_dev, list);
		del_dev(sdev);
	}
	mutex_unlock(&lock_);
}

static bool init_all_devices(void)
{
	const char *p = dev_sizes_;
	const char *q;
	u64 size = 0;
	unsigned int c = 0;
	while (parse_u64(p, &q, &size)) {
		if (!add_dev(size / LBS))
			goto error;
		p = q;
		c++;
	}
	if (c == 0) {
		LOGe("Size not specified.");
		goto error;
	}
	return true;
error:
	exit_all_devices();
	return false;
}

static bool is_valid_params(void)
{
	if (pbs_ != 512 && pbs_ != 4096) {
		LOGe("pbs must be 512 or 4096.\n");
		return false;
	}
	if (nr_dev_ < 1) {
		LOGe("nr_dev must be positive integer\n.");
		return false;
	}
	if (hw_queue_depth_ < 1 || hw_queue_depth_ > 64) {
		LOGe("hw_queue_depth must be in [1, 64].");
		return false;
	}

	return true;
}

static void init_globals(void)
{
	mutex_init(&lock_);
}

/*******************************************************************************
 * Init/exit functions definition.
 *******************************************************************************/

static int __init smpl_init(void)
{
	LOGi("%s module init.\n", SMPL_NAME);
	LOGi("build date: " BUILD_DATE "\n");

	if (!is_valid_params()) goto error0;
	init_globals();

	/* Register a block device module. */
	major_ = register_blkdev(0, SMPL_NAME);
	if (major_ <= 0) {
		LOGe("unable to get major device number.\n");
		goto error0;
	}

	if (!init_all_devices()) goto error1;
	return 0;

error1:
	exit_all_devices();
	unregister_blkdev(major_, SMPL_NAME);
	return -ENOMEM;
error0:
	return -EBUSY;
}

static void __exit smpl_exit(void)
{
	exit_all_devices();
	unregister_blkdev(major_, SMPL_NAME);
	LOGi("%s module exit.\n", SMPL_NAME);
}

module_init(smpl_init);
module_exit(smpl_exit);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("memory block device using bio");
MODULE_ALIAS(SMPL_NAME);
/* MODULE_ALIAS_BLOCKDEV_MAJOR(SMPL_MAJOR); */
