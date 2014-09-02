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
#include <linux/spinlock.h>

#include "common.h"
#include "block_size.h"
#include "logger.h"
#include "size_list.h"
#include "build_date.h"
#include "ioctl.h"
#include "treemap.h"

/*******************************************************************************
 * Struct definition.
 *******************************************************************************/

struct bdevt_dev
{
	struct list_head list;
	u32 index;
	struct request_queue *q;
	struct gendisk *disk;

	struct mutex map_lock;
	struct map *map0; /* cache layer */
	struct map *map1; /* persistent layer */
};

struct page_block
{
	atomic_t cnt;
	struct page *page;
};

/*******************************************************************************
 * Module variable definitions.
 *******************************************************************************/

static int major_;

static struct list_head dev_list_;
static struct mutex dev_lock_;
static int dev_indexes_ = 0;
struct treemap_memory_manager mmgr_;

/*******************************************************************************
 * Module parameter definitions.
 *******************************************************************************/

/*******************************************************************************
 * Macro definitions.
 *******************************************************************************/

#define BDEVT_NAME "bdevt"
#define BDEVT_CTL_NAME "bdevt_ctl"

/*******************************************************************************
 * Static functions definition.
 *******************************************************************************/

static inline u64 sector_to_block(u64 sectors)
{
	do_div(sectors, PAGE_SIZE >> 9);
	return sectors;
}

static inline u64 block_to_sector(u64 blks)
{
	return blks * (PAGE_SIZE >> 9);
}

static struct page_block *alloc_page_block(gfp_t gfp_mask)
{
	struct page_block *pblk;

	pblk = kmalloc(sizeof(*pblk), gfp_mask);
	if (!pblk)
		goto error0;

	pblk->page = alloc_page(gfp_mask | __GFP_ZERO);
	if (!pblk->page)
		goto error1;

	atomic_set(&pblk->cnt, 1);
	return pblk;
#if 0
error2:
	__free_page(pblk->page);
#endif
error1:
	kfree(pblk);
error0:
	return NULL;
}

static void get_page_block(struct page_block *pblk)
{
	atomic_inc(&pblk->cnt);
}

static void put_page_block(struct page_block *pblk)
{
	if (atomic_dec_and_test(&pblk->cnt)) {
		__free_page(pblk->page);
		kfree(pblk);
	}
}

static struct page_block *alloc_page_block_retry_forever(gfp_t gfp_mask)
{
	struct page_block *pblk;

	pblk = alloc_page_block(GFP_KERNEL);
	while (!pblk) {
		schedule();
		pblk = alloc_page_block(GFP_KERNEL);
	}
	return pblk;
}

static struct page_block *try_add_page_block_to_mdev(
	struct bdevt_dev *mdev, u64 blks, bool is_cache)
{
	struct map *map = is_cache ? mdev->map0 : mdev->map1;
	struct page_block *pblk = alloc_page_block_retry_forever(GFP_NOIO);
	int ret;

retry:
	ret = map_add(map, blks, (unsigned long)pblk, GFP_NOIO);
	if (ret == 0) {
		/* Do nothing */
	} else if (ret == -EEXIST) {
		put_page_block(pblk);
		pblk = (struct page_block *)map_lookup(map, blks);
	} else {
		goto retry;
	}
	return pblk;
}

static void copy_page_block(struct page_block *dst, struct page_block *src)
{
	u8 *buf_dst, *buf_src;

	buf_dst = kmap_atomic(dst->page);
	buf_src = kmap_atomic(src->page);
	memcpy(buf_dst, buf_src, PAGE_SIZE);
	kunmap_atomic(buf_src);
	kunmap_atomic(buf_dst);
}

static struct page_block *get_page_block_for_write(struct bdevt_dev *mdev, u64 blks)
{
	struct map_cursor curt0, curt1;
	struct page_block *pblk0 = NULL, *pblk1 = NULL;

	mutex_lock(&mdev->map_lock);

	map_cursor_init(mdev->map0, &curt0);
	map_cursor_init(mdev->map1, &curt1);
	if (map_cursor_search(&curt0, blks, MAP_SEARCH_EQ)) {
		pblk0 = (struct page_block *)map_cursor_val(&curt0);
	} else {
		if (map_cursor_search(&curt1, blks, MAP_SEARCH_EQ))
			pblk1 = (struct page_block *)map_cursor_val(&curt1);
	}

	if (pblk0) {
		/* Do nothing */
	} else if (pblk1) {
		pblk0 = try_add_page_block_to_mdev(mdev, blks, true);
		copy_page_block(pblk0, pblk1);
	} else {
		ASSERT(!pblk0);
		pblk1 = try_add_page_block_to_mdev(mdev, blks, false);
		pblk0 = try_add_page_block_to_mdev(mdev, blks, true);
	}
	get_page_block(pblk0);
	mutex_unlock(&mdev->map_lock);
	return pblk0;
}

static struct page_block *get_page_block_for_read(struct bdevt_dev *mdev, u64 blks)
{
	struct map_cursor curt0, curt1;
	struct page_block *pblk0 = NULL, *pblk1 = NULL;

	mutex_lock(&mdev->map_lock);

	map_cursor_init(mdev->map0, &curt0);
	map_cursor_init(mdev->map1, &curt1);
	if (map_cursor_search(&curt0, blks, MAP_SEARCH_EQ)) {
		pblk0 = (struct page_block *)map_cursor_val(&curt0);
	} else {
		if (map_cursor_search(&curt1, blks, MAP_SEARCH_EQ))
			pblk1 = (struct page_block *)map_cursor_val(&curt1);
	}

	if (pblk0) {
		get_page_block(pblk0);
		mutex_unlock(&mdev->map_lock);
		return pblk0;
	}
	if (pblk1) {
		get_page_block(pblk1);
		mutex_unlock(&mdev->map_lock);
		return pblk1;
	}
	pblk1 = try_add_page_block_to_mdev(mdev, blks, false);
	get_page_block(pblk1);
	mutex_unlock(&mdev->map_lock);
	return pblk1;
}

static void write_bio(struct bdevt_dev *mdev, struct bio *bio)
{
	struct page_block *pblk;
	u64 blks;
	u32 dst_off, src_off;
	u8 *src_buf, *dst_buf;

	while (bio_sectors(bio) > 0) {
		blks = bio->bi_iter.bi_sector;
		dst_off = do_div(blks, PAGE_SIZE >> 9) * LBS;
		src_off = bio_offset(bio);

		pblk = get_page_block_for_write(mdev, blks);

		dst_buf = kmap_atomic(pblk->page);
		src_buf = kmap_atomic(bio_page(bio));
		memcpy(dst_buf + dst_off, src_buf + src_off, LBS);
		kunmap_atomic(dst_buf);
		kunmap_atomic(src_buf);

		put_page_block(pblk);
		bio_advance(bio, LBS);
	}
}

static void read_bio(struct bdevt_dev *mdev, struct bio *bio)
{
	struct page_block *pblk;
	u64 blks;
	u32 src_off, dst_off;
	u8 *src_buf, *dst_buf;

	while (bio_sectors(bio) > 0) {
		blks = bio->bi_iter.bi_sector;
		src_off = do_div(blks, PAGE_SIZE >> 9) * LBS;
		dst_off = bio_offset(bio);

		pblk = get_page_block_for_read(mdev, blks);

		src_buf = kmap_atomic(pblk->page);
		dst_buf = kmap_atomic(bio_page(bio));
		memcpy(dst_buf + dst_off, src_buf + src_off, LBS);
		kunmap_atomic(dst_buf);
		kunmap_atomic(src_buf);

		put_page_block(pblk);
		bio_advance(bio, LBS);
	}
}

static bool flush_bdevt_dev_partial(struct bdevt_dev *mdev, u32 nr_blks)
{
	u32 i;
	bool ret = true;

	mutex_lock(&mdev->map_lock);
	for (i = 0; i < nr_blks; i++) {
		struct map_cursor curt0, curt1;
		u64 blks;
		struct page_block *pblk0, *pblk1;

		if (map_is_empty(mdev->map0)) {
			ret = false;
			break;
		}

		map_cursor_init(mdev->map0, &curt0);
		map_cursor_begin(&curt0);
		map_cursor_next(&curt0);
		ASSERT(map_cursor_is_valid(&curt0));

		blks = map_cursor_key(&curt0);
		pblk0 = (struct page_block *)map_cursor_val(&curt0);
		map_cursor_del(&curt0);

		map_cursor_init(mdev->map1, &curt1);
		map_cursor_search(&curt1, blks, MAP_SEARCH_EQ);
		ASSERT(map_cursor_is_valid(&curt1));
		pblk1 = (struct page_block *)map_cursor_val(&curt1);

		copy_page_block(pblk1, pblk0);
		put_page_block(pblk0);
	}
	mutex_unlock(&mdev->map_lock);
	return ret;
}

static void flush_bdevt_dev(struct bdevt_dev *mdev)
{
	while (flush_bdevt_dev_partial(mdev, 32));
}

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
	struct bdevt_dev *mdev = q->queuedata;

	if (bio->bi_rw & REQ_WRITE) {
		if (bio->bi_rw & REQ_FLUSH) {
			LOGd("%u: flush", mdev->index);
			flush_bdevt_dev(mdev);
			if (bio_sectors(bio) > 0)
				write_bio(mdev, bio);

			bio_endio(bio, 0);
		} else if (bio->bi_rw & REQ_DISCARD) {
			/* TODO: implement */
			bio_endio(bio, 0);
		} else {
			write_bio(mdev, bio);
			bio_endio(bio, 0);
		}
	} else {
		read_bio(mdev, bio);
		bio_endio(bio, 0);
	}
}

/*******************************************************************************
 * Ioctl for /dev/bdevtX
 *******************************************************************************/

static void del_dev(struct bdevt_dev *mdev);

static int ioctl_stop_dev(struct bdevt_dev *mdev, struct bdevt_ctl *ctl)
{
	mutex_lock(&dev_lock_);
	list_del_init(&mdev->list);
	mutex_unlock(&dev_lock_);

	del_dev(mdev);
	return 0;
}

static int ioctl_make_crash(struct bdevt_dev *mdev, struct bdevt_ctl *ctl)
{
	/* QQQ */
	return -EFAULT;
}

static int ioctl_recover_crash(struct bdevt_dev *mdev, struct bdevt_ctl *ctl)
{
	/* QQQ */
	return -EFAULT;
}

static int ioctl_make_error(struct bdevt_dev *mdev, struct bdevt_ctl *ctl)
{
	/* QQQ */
	return -EFAULT;
}

static int ioctl_recover_error(struct bdevt_dev *mdev, struct bdevt_ctl *ctl)
{
	/* QQQ */
	return -EFAULT;
}

static int dispatch_dev_ioctl(struct bdevt_dev *mdev, struct bdevt_ctl *ctl)
{
	size_t i;
	struct {
		int id;
		int (*handler)(struct bdevt_dev *mdev, struct bdevt_ctl *ctl);
	} tbl[] = {
		{BDEVT_IOCTL_STOP_DEV, ioctl_stop_dev},
		{BDEVT_IOCTL_MAKE_CRASH, ioctl_make_crash},
		{BDEVT_IOCTL_RECOVER_CRASH, ioctl_recover_crash},
		{BDEVT_IOCTL_MAKE_ERROR, ioctl_make_error},
		{BDEVT_IOCTL_RECOVER_ERROR, ioctl_recover_error},
	};

	for (i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++) {
		if (ctl->command == tbl[i].id)
			return tbl[i].handler(mdev, ctl);
	}
	LOGe("dispatch_dev_ioctl: command %d is not supported.\n",
		ctl->command);
	return -ENOTTY;
}

/*******************************************************************************
 * Ioctl utility functions.
 *******************************************************************************/

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

/*******************************************************************************
 * For /dev/bdevtX
 *******************************************************************************/

static int bdevt_dev_open(struct block_device *bdev, fmode_t mode)
{
	return 0;
}

static void bdevt_dev_release(struct gendisk *gd, fmode_t mode)
{
	/* do nothing */
}

static int bdevt_dev_ioctl(struct block_device *bdev, fmode_t mode,
			unsigned int cmd, unsigned long arg)
{
	int ret;
	struct bdevt_ctl *ctl;
	struct bdevt_ctl __user *user = (struct bdevt_ctl __user *)arg;
	struct bdevt_dev *mdev = bdev->bd_disk->private_data;

	if (cmd != BDEVT_IOCTL)
		return -EFAULT;

	ctl = bdevt_get_ctl(user, GFP_KERNEL);
	if (!ctl)
		return -EFAULT;

	ret = dispatch_dev_ioctl(mdev, ctl);

	if (!bdevt_put_ctl(user, ctl))
		return -EFAULT;

	return ret;
}

/*******************************************************************************
 * Static variables definition.
 *******************************************************************************/

static struct block_device_operations bdevt_devops_ = {
	.owner		 = THIS_MODULE,
	.open		 = bdevt_dev_open,
	.release	 = bdevt_dev_release,
	.ioctl		 = bdevt_dev_ioctl
};

/*******************************************************************************
 * Static functions definition.
 *******************************************************************************/

static bool init_bdevt_dev(struct bdevt_dev *mdev)
{
	mutex_init(&mdev->map_lock);

	mdev->map0 = map_create(GFP_KERNEL, &mmgr_);
	if (!mdev->map0) {
		LOGe("map0 allocation failed.\n");
		goto error0;
	}

	mdev->map1 = map_create(GFP_KERNEL, &mmgr_);
	if (!mdev->map1) {
		LOGe("map1 allocation failed.\n");
		goto error1;
	}

	return true;

#if 0
error2:
	map_destroy(mdev->map1);
	mdev->map1 = NULL;
#endif
error1:
	map_destroy(mdev->map0);
	mdev->map0 = NULL;
error0:
	return false;
}

static void exit_bdevt_dev(struct bdevt_dev *mdev)
{
	struct map_cursor curt;

	/* Deallocate all blocks */
	map_cursor_init(mdev->map0, &curt);
	map_cursor_begin(&curt);
	map_cursor_next(&curt);
	while (!map_cursor_is_end(&curt)) {
		put_page_block((struct page_block *)map_cursor_val(&curt));
		map_cursor_del(&curt);
	}

	map_destroy(mdev->map1);
	mdev->map1 = NULL;
	map_destroy(mdev->map0);
	mdev->map0 = NULL;
}

/**
 * mdev must have been removed from dev_list_ before calling this.
 */
static void del_dev(struct bdevt_dev *mdev)
{
	del_gendisk(mdev->disk);
	blk_cleanup_queue(mdev->q);
	put_disk(mdev->disk);
	exit_bdevt_dev(mdev);
	kfree(mdev);
}

static bool add_dev(u64 size_lb, u32 *minorp)
{
	struct bdevt_dev *mdev;
	struct gendisk *disk;
	struct request_queue *q;

	mdev = kzalloc(sizeof(*mdev), GFP_KERNEL);
	if (!mdev)
		return -ENOMEM;

	if (!init_bdevt_dev(mdev))
		goto error0;

	INIT_LIST_HEAD(&mdev->list);

	q = mdev->q = blk_alloc_queue(GFP_KERNEL);
	if (!q) {
		LOGe("mdev->q init failed.\n");
		goto error1;
	}
	q->queuedata = mdev;
	blk_queue_make_request(q, bdevt_queue_bio);
	disk = mdev->disk = alloc_disk(1);
	if (!disk) {
		LOGe("mdev->disk alloc failed.\n");
		goto error2;
	}

	mutex_lock(&dev_lock_);
	list_add_tail(&mdev->list, &dev_list_);
	mdev->index = dev_indexes_++;
	mutex_unlock(&dev_lock_);

	blk_queue_logical_block_size(q, LBS);
	blk_queue_physical_block_size(q, LBS);
	blk_queue_io_min(q, LBS);
	blk_queue_io_opt(q, LBS);
	q->limits.discard_granularity = PAGE_SIZE;
	q->limits.max_discard_sectors = -1;
	q->limits.discard_zeroes_data = 0;
	queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, q);
	blk_queue_flush(q, REQ_FLUSH);
	blk_queue_flush_queueable(q, true);

	set_capacity(disk, size_lb);

	disk->flags |= GENHD_FL_EXT_DEVT;
	disk->major = major_;
	disk->first_minor = mdev->index;
	disk->fops = &bdevt_devops_;
	disk->private_data = mdev;
	disk->queue = q;
	sprintf(disk->disk_name, "%s%u", BDEVT_NAME, mdev->index);
	add_disk(disk);

	if (minorp)
		*minorp = mdev->index;

	return true;

error2:
	blk_cleanup_queue(mdev->q);
error1:
	exit_bdevt_dev(mdev);
error0:
	kfree(mdev);
	return false;
}

static void exit_all_devices(void)
{
	struct bdevt_dev *mdev, *mdev_next;

	mutex_lock(&dev_lock_);
	list_for_each_entry_safe(mdev, mdev_next, &dev_list_, list) {
		list_del_init(&mdev->list);
		del_dev(mdev);
	}
	mutex_unlock(&dev_lock_);
}

static void init_globals(void)
{
	INIT_LIST_HEAD(&dev_list_);
	mutex_init(&dev_lock_);
}

/*******************************************************************************
 * For /dev/bdevt_ctl
 *******************************************************************************/

static int ioctl_start_dev(struct bdevt_ctl *ctl)
{
	const u64 size_lb = ctl->val_u64;
	u32 minor = 0;

	if (size_lb == 0) {
		LOGe("invalid size %" PRIu64 "\n", size_lb);
		return -EFAULT;
	}
	if (!add_dev(size_lb, &minor)) {
		LOGe("add_dev failed\n");
		return -EFAULT;
	}
	ctl->val_u32 = minor;
	return 0;
}

static int ioctl_get_major(struct bdevt_ctl *ctl)
{
	ctl->val_u32 = major_;
	return 0;
}

static int ioctl_num_of_dev(struct bdevt_ctl *ctl)
{
	int nr = 0;
	struct bdevt_dev *mdev;

	mutex_lock(&dev_lock_);
	list_for_each_entry(mdev, &dev_list_, list)
		nr++;

	mutex_unlock(&dev_lock_);

	ctl->val_int = nr;
	return 0;
}

static int dispatch_ctl_ioctl(struct bdevt_ctl *ctl)
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
	LOGe("dispatch_ctl_ioctl: command %d is not supported.\n",
		ctl->command);
	return -ENOTTY;
}

static long bdevt_ctl_ioctl(struct file *file, unsigned int command, unsigned long u)
{
	int ret;
	struct bdevt_ctl *ctl;
	struct bdevt_ctl __user *user = (struct bdevt_ctl __user *)u;

	if (command != BDEVT_IOCTL)
		return -EFAULT;

	ctl = bdevt_get_ctl(user, GFP_KERNEL);
	if (!ctl)
		return -EFAULT;

	ret = dispatch_ctl_ioctl(ctl);

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

	init_globals();

	if (!initialize_treemap_memory_manager_kmalloc(&mmgr_, 16)) {
		LOGe("unable to initialize treemap memory manager.\n");
		goto error0;
	}

	major_ = register_blkdev(0, BDEVT_NAME);
	if (major_ <= 0) {
		LOGe("unable to get major device number.\n");
		goto error1;
	}

	if (misc_register(&bdevt_misc_) < 0) {
		LOGe("unable to register control device.\n");
		goto error2;
	}

	return 0;
#if 0
error3:
	misc_deregister(&bdevt_misc_);
#endif
error2:
	unregister_blkdev(major_, BDEVT_NAME);
error1:
	finalize_treemap_memory_manager(&mmgr_);
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
