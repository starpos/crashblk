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
#include <linux/idr.h>

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

	/* Ordered queue for serialized (single-threaded) tasks. */
	struct workqueue_struct *wq;
	struct work_struct worker;

	/*
	 * Temporarily inserted bio list.
	 * This needs lock to access to.
	 */
	spinlock_t lock;
	struct bio_list bl;

	atomic_t nr_running; /* for debug */

	/*
	 * The following data are accessed by only one thread.
	 * using ordered workqueue.
	 *
	 * key: blks [page size]
	 * value: struct *page
	 */
	struct map *map0; /* cache layer */
	struct map *map1; /* persistent layer (really in memory) */
};

/*******************************************************************************
 * Module variable definitions.
 *******************************************************************************/

static int is_put_log_ = false;

static int major_;
struct treemap_memory_manager mmgr_;

static spinlock_t dev_lock_;
static struct idr dev_idr_;

/*******************************************************************************
 * Module parameter definitions.
 *******************************************************************************/

module_param_named(is_put_log, is_put_log_, int, S_IRUGO | S_IWUSR);

/*******************************************************************************
 * Macro definitions.
 *******************************************************************************/

#define BDEVT_NAME "bdevt"
#define BDEVT_CTL_NAME "bdevt_ctl"

/*******************************************************************************
 * Static functions definition.
 *******************************************************************************/

static bool add_dev_to_idr(struct bdevt_dev *mdev)
{
	int minor;

	idr_preload(GFP_KERNEL);
	spin_lock(&dev_lock_);
	minor = idr_alloc(&dev_idr_, mdev, 0, 1 << MINORBITS, GFP_NOWAIT);
	spin_unlock(&dev_lock_);
	idr_preload_end();
	if (minor < 0)
		return false;

	mdev->index = (u32)minor;
	return true;
}

static void del_dev_from_idr(struct bdevt_dev *mdev)
{
	ASSERT(mdev->index < (1 << MINORBITS));

	spin_lock(&dev_lock_);
	idr_remove(&dev_idr_, (int)mdev->index);
	spin_unlock(&dev_lock_);
}

static struct bdevt_dev *pop_dev_from_idr(void)
{
	struct bdevt_dev *mdev;
	int minor = 0;

	spin_lock(&dev_lock_);
	mdev = idr_get_next(&dev_idr_, &minor);
	if (mdev)
		idr_remove(&dev_idr_, minor);

	spin_unlock(&dev_lock_);

	if (mdev)
		ASSERT((u32)minor == mdev->index);

	return mdev;
}

static int get_nr_dev_in_idr(void)
{
	struct bdevt_dev *mdev;
	int minor, nr = 0;

	spin_lock(&dev_lock_);
	idr_for_each_entry(&dev_idr_, mdev, minor)
		nr++;

	spin_unlock(&dev_lock_);

	return nr;
}

static void invoke_worker(struct bdevt_dev *mdev)
{
	queue_work(mdev->wq, &mdev->worker);
}

static inline u64 sector_to_block(u64 sectors)
{
	do_div(sectors, PAGE_SIZE >> 9);
	return sectors;
}

static inline u64 block_to_sector(u64 blks)
{
	return blks * (PAGE_SIZE >> 9);
}

static struct page *alloc_page_retry_forever(void)
{
	struct page *page = NULL;

	while (!(page = alloc_page(GFP_NOIO | __GFP_ZERO)))
		schedule();

	return page;
}

/**
 * Thread-unsafe.
 */
static void map_add_retry_forever(struct map *map, u64 key, struct page *page)
{
	int ret;
retry:
	ret = map_add(map, key, (unsigned long)page, GFP_NOIO);
	ASSERT(ret != -EEXIST);
	if (ret != 0) {
		schedule();
		goto retry;
	}
}

/**
 * Thread-unsafe.
 */
static struct page *get_page_for_write(struct bdevt_dev *mdev, u64 blks)
{
	struct map_cursor curt;
	struct page *page0, *page1;

	map_cursor_init(mdev->map1, &curt);
	if (map_cursor_search(&curt, blks, MAP_SEARCH_EQ)) {
		page1 = (struct page *)map_cursor_val(&curt);
	} else {
		page1 = alloc_page_retry_forever();
		map_add_retry_forever(mdev->map1, blks, page1);
	}

	map_cursor_init(mdev->map0, &curt);
	if (map_cursor_search(&curt, blks, MAP_SEARCH_EQ)) {
		page0 = (struct page *)map_cursor_val(&curt);
	} else {
		page0 = alloc_page_retry_forever();
		copy_highpage(page0, page1);
		map_add_retry_forever(mdev->map0, blks, page0);
	}

	return page0;
}

/**
 * Thread-unsafe.
 */
static struct page *get_page_for_read(struct bdevt_dev *mdev, u64 blks)
{
	struct map_cursor curt;

	map_cursor_init(mdev->map0, &curt);
	if (map_cursor_search(&curt, blks, MAP_SEARCH_EQ)) {
		return (struct page *)map_cursor_val(&curt);
	}

	map_cursor_init(mdev->map1, &curt);
	if (map_cursor_search(&curt, blks, MAP_SEARCH_EQ)) {
		return (struct page *)map_cursor_val(&curt);
	}

	return ZERO_PAGE(0);
}

/**
 * Thread-unsafe.
 */
static void exec_bio(struct bdevt_dev *mdev, struct bio *bio)
{
	struct page *page;
	u64 blks;
	u32 bio_off, page_off;
	u8 *bio_buf, *page_buf;
	bool is_write = bio->bi_rw & REQ_WRITE;

	ASSERT(!(bio->bi_rw & REQ_DISCARD));

	while (bio_sectors(bio) > 0) {
		u32 bytes;
		blks = bio->bi_iter.bi_sector;
		page_off = do_div(blks, PAGE_SIZE >> 9) << 9;
		bio_off = bio_offset(bio);
		bytes = min(bio_iter_len(bio, bio->bi_iter), (u32)(PAGE_SIZE) - page_off);

		if (is_write)
			page = get_page_for_write(mdev, blks);
		else
			page = get_page_for_read(mdev, blks);

		page_buf = kmap_atomic(page);
		bio_buf = kmap_atomic(bio_page(bio));
		if (is_write)
			memcpy(page_buf + page_off, bio_buf + bio_off, bytes);
		else
			memcpy(bio_buf + bio_off, page_buf + page_off, bytes);

		kunmap_atomic(page_buf);
		kunmap_atomic(bio_buf);

		bio_advance(bio, bytes);
	}
}

/**
 * Thread-unsafe.
 */
static void discard_block(struct bdevt_dev *mdev, u64 blks)
{
	struct map_cursor curt;
	struct page *page;
	struct map *maps[2] = {mdev->map0, mdev->map1};
	size_t i;

	for (i = 0; i < 2; i++) {
		map_cursor_init(maps[i], &curt);
		if (map_cursor_search(&curt, blks, MAP_SEARCH_EQ)) {
			page = (struct page *)map_cursor_val(&curt);
			__free_page(page);
			map_cursor_del(&curt);
		}
	}
}

/**
 * Thread-unsafe.
 */
static void discard_bio(struct bdevt_dev *mdev, struct bio *bio)
{
	ASSERT(!(bio->bi_rw & REQ_FLUSH));
	ASSERT(bio->bi_rw & REQ_WRITE);
	ASSERT(bio->bi_rw & REQ_DISCARD);

	while (bio_sectors(bio) > 0) {
		struct page *page;
		u32 bytes, page_off;
		u32 blks = bio->bi_iter.bi_sector;
		page_off = do_div(blks, PAGE_SIZE >> 9) << 9;
		bytes = min(bio->bi_iter.bi_size, (u32)PAGE_SIZE - page_off);

		if (bytes == (u32)PAGE_SIZE) {
			ASSERT(page_off == 0);
			discard_block(mdev, blks);
		} else {
			char *page_buf;
			page = get_page_for_write(mdev, blks);
			page_buf = kmap_atomic(page);
			memset(page_buf + page_off, 0, bytes);
		}
		bio_advance(bio, bytes);
	}
}

/**
 * Thread-unsafe.
 */
static void flush_all_blocks(struct bdevt_dev *mdev)
{
	while (!map_is_empty(mdev->map0)) {
		struct map_cursor curt;
		struct page *page0, *page1;
		u64 blks;

		map_cursor_init(mdev->map0, &curt);
		map_cursor_begin(&curt);
		map_cursor_next(&curt);
		ASSERT(map_cursor_is_valid(&curt));
		blks = map_cursor_key(&curt);
		page0 = (struct page *)map_cursor_val(&curt);
		map_cursor_del(&curt);

		map_cursor_init(mdev->map1, &curt);
		if (!map_cursor_search(&curt, blks, MAP_SEARCH_EQ))
			BUG();

		page1 = (struct page *)map_cursor_val(&curt);

		copy_highpage(page1, page0);
	}
}

static void log_info_bio(u32 device_index, const char *type, const struct bio *bio)
{
	if (!is_put_log_)
		return;

	LOGi("%u: %s %" PRIu64 " %u\n", device_index, type
			, (u64)bio->bi_iter.bi_sector, bio_sectors(bio));
}

/**
 * Thread-unsafe.
 */
static void process_bio(struct bdevt_dev *mdev, struct bio *bio)
{
	ASSERT(!(bio->bi_rw & REQ_FUA)); /* must be turned off */
	if (bio->bi_rw & REQ_WRITE) {
		if (bio->bi_rw & REQ_FLUSH) {
			LOGi("%u: flush\n", mdev->index);
			flush_all_blocks(mdev);
			if (bio_sectors(bio) > 0) {
				log_info_bio(mdev->index, "write", bio);
				exec_bio(mdev, bio);
			}
		} else if (bio->bi_rw & REQ_DISCARD) {
			log_info_bio(mdev->index, "discard", bio);
			discard_bio(mdev, bio);
		} else {
			log_info_bio(mdev->index, "write", bio);
			exec_bio(mdev, bio);
		}
	} else {
		log_info_bio(mdev->index, "read", bio);
		exec_bio(mdev, bio);
	}
	bio_endio(bio, 0);
	atomic_dec(&mdev->nr_running);
}

static void do_work(struct work_struct *ws)
{
	struct bdevt_dev *mdev = container_of(ws, struct bdevt_dev, worker);
	struct bio_list bl;
	struct bio *bio;

	bio_list_init(&bl);

	spin_lock(&mdev->lock);
	bio_list_merge(&bl, &mdev->bl);
	bio_list_init(&mdev->bl);
	spin_unlock(&mdev->lock);

	while ((bio = bio_list_pop(&bl)))
		process_bio(mdev, bio);
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

	atomic_inc(&mdev->nr_running);

	spin_lock(&mdev->lock);
	bio_list_add(&mdev->bl, bio);
	spin_unlock(&mdev->lock);

	invoke_worker(mdev);
}

/*******************************************************************************
 * Ioctl for /dev/bdevtX
 *******************************************************************************/

static void del_dev(struct bdevt_dev *mdev);

static int ioctl_stop_dev(struct bdevt_dev *mdev, struct bdevt_ctl *ctl)
{
	del_dev_from_idr(mdev);
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

static struct bdevt_dev *create_bdevt_dev(void)
{
	struct bdevt_dev *mdev;

	mdev = kzalloc(sizeof(*mdev), GFP_KERNEL);
	if (!mdev) {
		LOGe("allocate mdev failed.");
		return NULL;
	}

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

	spin_lock_init(&mdev->lock);
	bio_list_init(&mdev->bl);
	atomic_set(&mdev->nr_running, 0);
	mdev->index = (u32)(-1);

	return mdev;

#if 0
error2:
	map_destroy(mdev->map1);
#endif
error1:
	map_destroy(mdev->map0);
error0:
	kfree(mdev);
	return NULL;
}

static void free_all_pages_in_map(struct map *map)
{
	struct map_cursor curt;

	map_cursor_init(map, &curt);
	map_cursor_begin(&curt);
	map_cursor_next(&curt);
	while (!map_cursor_is_end(&curt)) {
		__free_page((struct page *)map_cursor_val(&curt));
		map_cursor_del(&curt);
	}
	ASSERT(map_is_empty(map));
}

static void destroy_bdevt_dev(struct bdevt_dev *mdev)
{
	free_all_pages_in_map(mdev->map0);
	free_all_pages_in_map(mdev->map1);
	map_destroy(mdev->map0);
	map_destroy(mdev->map1);
	kfree(mdev);
}

/**
 * mdev must have been removed from dev_list_ before calling this.
 */
static void del_dev(struct bdevt_dev *mdev)
{
	const u32 minor = mdev->index;
	int nr_running;

	del_gendisk(mdev->disk);

	/* Complete all pending IOs. */
	invoke_worker(mdev);
	flush_workqueue(mdev->wq);

	ASSERT(bio_list_empty(&mdev->bl));
	nr_running = atomic_read(&mdev->nr_running);
	LOGi("nr_running: %d\n", nr_running);
	ASSERT(nr_running == 0);

	destroy_workqueue(mdev->wq);
	blk_cleanup_queue(mdev->q);
	put_disk(mdev->disk);
	destroy_bdevt_dev(mdev);

	LOGi("deleted bdevt%u\n", minor);
}

static bool add_dev(u64 size_lb, u32 *minorp)
{
	struct bdevt_dev *mdev;
	struct gendisk *disk;
	struct request_queue *q;

	mdev = create_bdevt_dev();
	if (!mdev)
		return false;

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

	mdev->wq = alloc_ordered_workqueue(BDEVT_NAME, WQ_MEM_RECLAIM);
	if (!mdev->wq) {
		LOGe("unable to allocate workqueue.\n");
		goto error2;
	}
	INIT_WORK(&mdev->worker, do_work);

	if (!add_dev_to_idr(mdev))
		goto error3;

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
	snprintf(disk->disk_name, DISK_NAME_LEN, "%s%u", BDEVT_NAME, mdev->index);
	add_disk(disk);

	if (minorp)
		*minorp = mdev->index;

	LOGi("added bdevt%u\n", mdev->index);
	return true;

#if 0
error4:
	del_dev_from_idr(mdev);
#endif
error3:
	destroy_workqueue(mdev->wq);
error2:
	put_disk(mdev->disk);
error1:
	blk_cleanup_queue(mdev->q);
error0:
	destroy_bdevt_dev(mdev);
	return false;
}

static void exit_all_devices(void)
{
	struct bdevt_dev *mdev;

	while ((mdev = pop_dev_from_idr()))
		del_dev(mdev);
}

static void init_globals(void)
{
	spin_lock_init(&dev_lock_);
	idr_init(&dev_idr_);
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
	int nr = get_nr_dev_in_idr();

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
	idr_destroy(&dev_idr_);
	LOGi("%s module exit.\n", BDEVT_NAME);
}

module_init(bdevt_init);
module_exit(bdevt_exit);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("a memory block device driver for test");
MODULE_ALIAS(BDEVT_NAME);
/* MODULE_ALIAS_BLOCKDEV_MAJOR(BDEVT_MAJOR); */
