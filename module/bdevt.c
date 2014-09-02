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

	struct workqueue_struct *wq;
	struct work_struct worker;

	spinlock_t lock;
	struct bio_list bl;

	/* The following data are accessed by only one thread.
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

/**
 * Thread-unsafe.
 */
static void process_bio(struct bdevt_dev *mdev, struct bio *bio)
{
	if (bio->bi_rw & REQ_WRITE) {
		if (bio->bi_rw & REQ_FLUSH) {
			LOGd("%u: flush", mdev->index);
			flush_all_blocks(mdev);
			if (bio_sectors(bio) > 0)
				exec_bio(mdev, bio);
		} else if (bio->bi_rw & REQ_DISCARD) {
			discard_bio(mdev, bio);
		} else {
			exec_bio(mdev, bio);
		}
	} else {
		exec_bio(mdev, bio);
	}
	bio_endio(bio, 0);
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
	spin_lock(&mdev->lock);
	bio_list_init(&mdev->bl);

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
		__free_page((struct page *)map_cursor_val(&curt));
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
	const u32 minor = mdev->index;

	del_gendisk(mdev->disk);

	/* Complete all pending IOs. */
	invoke_worker(mdev);
	flush_workqueue(mdev->wq);

	destroy_workqueue(mdev->wq);
	blk_cleanup_queue(mdev->q);
	put_disk(mdev->disk);
	exit_bdevt_dev(mdev);
	kfree(mdev);

	LOGi("deleted bdevt%u\n", minor);
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

	mdev->wq = alloc_ordered_workqueue(BDEVT_NAME, WQ_MEM_RECLAIM);
	if (!mdev->wq) {
		LOGe("unable to allocate workqueue.\n");
		goto error3;
	}
	INIT_WORK(&mdev->worker, do_work);

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
	snprintf(disk->disk_name, DISK_NAME_LEN, "%s%u", BDEVT_NAME, mdev->index);
	add_disk(disk);

	if (minorp)
		*minorp = mdev->index;

	LOGi("added bdevt%u\n", mdev->index);

	return true;

#if 0
error4:
	destroy_workqueue(mdev->wq);
#endif
error3:
	put_disk(mdev->disk);
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
