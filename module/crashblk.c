/**
 * crashblk.c - a memory block device driver for crash test.
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
#include <linux/random.h>

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

struct mem_dev
{
	struct list_head list;
	u32 index;
	struct request_queue *q;
	struct gendisk *disk;

	/* Ordered queue for serialized (single-threaded) tasks. */
	struct workqueue_struct *wq_ordered;
	struct work_struct bio_task;
	struct work_struct crash_task;
	struct work_struct recover_task;

	/*
	 * Temporarily inserted bio list for bio_task.
	 * This needs lock to access to.
	 */
	spinlock_t ready_lock;
	struct bio_list ready_bl;

	/* For waiting (delayed) tasks. */
	struct workqueue_struct *wq_wait;

	atomic_t nr_running; /* for debug */
	atomic_t state; /* for error/crash state. */

	/*
	 * The following data are accessed by only one thread.
	 * using ordered workqueue.
	 *
	 * key: blks [page size]
	 * value: struct *page
	 */
	struct map *map0; /* cache layer */
	struct map *map1; /* persistent layer (really in memory) */

	/*
	 * lost percentage in crash.
	 * [0, 100].
	 */
	atomic_t lost_pct_in_crash;

	/*
	 * 0 or 1.
	 * If 1, submitted IOs will be reordered.
	 */
	atomic_t does_reorder_io;

	/*
	 * min/max delay [ms].
	 * Of course min_delay_ms must be <= max_delay_ms.
	 */
	spinlock_t delay_lock;
	u32 min_delay_ms;
	u32 max_delay_ms;
};

struct pack_work
{
	struct delayed_work dwork;
	struct mem_dev *mdev;
	struct bio_list bl;
};

/*******************************************************************************
 * Module variable definitions.
 *******************************************************************************/

static int is_put_log_ = false;

static int major_;
struct treemap_memory_manager mmgr_;

static spinlock_t dev_lock_;
static struct idr dev_idr_;

atomic_t nr_pages_; /* number of allocated pages for debug. */

/*******************************************************************************
 * Module parameter definitions.
 *******************************************************************************/

module_param_named(is_put_log, is_put_log_, int, S_IRUGO | S_IWUSR);

/*******************************************************************************
 * Macro definitions.
 *******************************************************************************/

#define CRASHBLK_NAME "crashblk"
#define CRASHBLK_CTL_NAME "crashblk_ctl"

/*******************************************************************************
 * Static functions definition.
 *******************************************************************************/

/*
 * Utilities
 */

static inline struct pack_work* create_pack_work(struct mem_dev *mdev, struct bio_list *bl)
{
	struct pack_work *pwork;
retry:
	pwork = kmalloc(sizeof(struct pack_work), GFP_NOIO);
	if (!pwork) {
		schedule();
		goto retry;
	}
	pwork->mdev = mdev;
	bio_list_init(&pwork->bl);
	bio_list_merge(&pwork->bl, bl);
	bio_list_init(bl);
	return pwork;
}

static inline void destroy_pack_work(struct pack_work *pwork)
{
	ASSERT(pwork);
	ASSERT(bio_list_empty(&pwork->bl));
	kfree(pwork);
}

static inline void queue_pack_work_task(
	struct workqueue_struct *wq, struct pack_work *pwork,
	void (*task)(struct work_struct *), uint delay_ms)
{
	INIT_DELAYED_WORK(&pwork->dwork, task);
	queue_delayed_work(wq, &pwork->dwork, msecs_to_jiffies(delay_ms));
}

static inline struct pack_work* get_pack_work_from_work(struct work_struct *work)
{
	struct delayed_work *dwork = container_of(work, struct delayed_work, work);
	struct pack_work *pwork = container_of(dwork, struct pack_work, dwork);
	return pwork;
}

static void log_info_bio(u32 device_index, const char *type, const struct bio *bio)
{
	if (!is_put_log_)
		return;

	LOGi("%u: %s %" PRIu64 " %u\n", device_index, type
			, (u64)bio->bi_sector, bio_sectors(bio));
}

static struct page *alloc_page_retry_forever(void)
{
	struct page *page = NULL;

	while (!(page = alloc_page(GFP_NOIO | __GFP_ZERO)))
		schedule();

	atomic_inc(&nr_pages_);
	return page;
}

static void free_page_wrap(struct page *page)
{
	__free_page(page);
	atomic_dec(&nr_pages_);
}

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

static void free_all_pages_in_map(struct map *map)
{
	struct map_cursor curt;

	map_cursor_init(map, &curt);
	map_cursor_begin(&curt);
	map_cursor_next(&curt);
	while (!map_cursor_is_end(&curt)) {
		free_page_wrap((struct page *)map_cursor_val(&curt));
		map_cursor_del(&curt);
	}
	ASSERT(map_is_empty(map));
}

/**
 * @pct percentage [0, 100]
 *   100 means all the pages will be freed.
 *   0 means no page will not be freed.
 */
static void free_pages_in_map_randomly(struct map *map, int pct,
				size_t *nr_alive_p, size_t *nr_lost_p)
{
	struct map_cursor curt;
	size_t nr_alive = 0, nr_lost = 0;

	if (pct < 0)
		pct = 0;
	if (pct > 100)
		pct = 100;

	map_cursor_init(map, &curt);
	map_cursor_begin(&curt);
	map_cursor_next(&curt);
	while (!map_cursor_is_end(&curt)) {
		uint rand;
		int pctx;
		get_random_bytes(&rand, sizeof(rand));
		pctx = rand % 100;
		if (pctx < pct) {
			free_page_wrap((struct page *)map_cursor_val(&curt));
			map_cursor_del(&curt);
			nr_lost++;
		} else {
			map_cursor_next(&curt);
			nr_alive++;
		}
	}
	if (nr_alive_p)
		*nr_alive_p = nr_alive;
	if (nr_lost_p)
		*nr_lost_p = nr_lost;
}

/*
 * Utilities for bio debug.
 */

/*
 * State utilities
 */

static const int allowed_for_error[] = {
	CRASHBLK_STATE_NORMAL,
	CRASHBLK_STATE_READ_ERROR,
	CRASHBLK_STATE_WRITE_ERROR,
	CRASHBLK_STATE_RW_ERROR,
};

static const int allowed_in_error[] = {
	CRASHBLK_STATE_READ_ERROR,
	CRASHBLK_STATE_WRITE_ERROR,
	CRASHBLK_STATE_RW_ERROR,
};

static const int read_error_states[] = {
	CRASHBLK_STATE_READ_ERROR,
	CRASHBLK_STATE_RW_ERROR,
	CRASHBLK_STATE_CRASHING,
	CRASHBLK_STATE_CRASHED,
};

static const int write_error_states[] = {
	CRASHBLK_STATE_WRITE_ERROR,
	CRASHBLK_STATE_RW_ERROR,
	CRASHBLK_STATE_CRASHING,
	CRASHBLK_STATE_CRASHED,
};

static bool find_state(int state, const int *state_array, size_t size)
{
	size_t i;
	for (i = 0; i < size; i++) {
		if (state == state_array[i])
			return true;
	}
	return false;
}

#define is_allowed_for_error(state)					\
	find_state(state, allowed_for_error, sizeof(allowed_for_error)/sizeof(int))
#define is_allowed_in_error(state)					\
	find_state(state, allowed_in_error, sizeof(allowed_in_error)/sizeof(int))
#define is_read_error(state)						\
	find_state(state, read_error_states, sizeof(read_error_states)/sizeof(int))
#define is_write_error(state)						\
	find_state(state, write_error_states, sizeof(write_error_states)/sizeof(int))

static const char *get_state_str(int state)
{
	size_t i;
	struct {
		int state;
		const char *name;
	} tbl[] = {
		{CRASHBLK_STATE_NORMAL, "normal"},
		{CRASHBLK_STATE_READ_ERROR, "read_error"},
		{CRASHBLK_STATE_WRITE_ERROR, "write_error"},
		{CRASHBLK_STATE_RW_ERROR, "rw_error"},
		{CRASHBLK_STATE_CRASHING, "crashing"},
		{CRASHBLK_STATE_CRASHED, "crashed"},
	};

	for (i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++) {
		if (state == tbl[i].state)
			return tbl[i].name;
	}
	return "none";
}

/*
 * idr utilities
 */

static bool add_dev_to_idr(struct mem_dev *mdev)
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

static void del_dev_from_idr(struct mem_dev *mdev)
{
	ASSERT(mdev->index < (1 << MINORBITS));

	spin_lock(&dev_lock_);
	idr_remove(&dev_idr_, (int)mdev->index);
	spin_unlock(&dev_lock_);
}

static struct mem_dev *pop_dev_from_idr(void)
{
	struct mem_dev *mdev;
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
	struct mem_dev *mdev;
	int minor, nr = 0;

	spin_lock(&dev_lock_);
	idr_for_each_entry(&dev_idr_, mdev, minor)
		nr++;

	spin_unlock(&dev_lock_);

	return nr;
}

/*
 * For tasks
 */

static inline void invoke_bio_task(struct mem_dev *mdev)
{
	queue_work(mdev->wq_ordered, &mdev->bio_task);
}

static inline void invoke_crash_task(struct mem_dev *mdev)
{
	queue_work(mdev->wq_ordered, &mdev->crash_task);
}

static inline void invoke_recover_task(struct mem_dev *mdev)
{
	queue_work(mdev->wq_ordered, &mdev->recover_task);
}

/*
 * For IO processing
 */

/**
 * Thread-unsafe.
 */
static struct page *get_page_for_write(struct mem_dev *mdev, u64 blks)
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
static struct page *get_page_for_read(struct mem_dev *mdev, u64 blks)
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
 *
 * bio->bi_iter will be changed.
 */
static void exec_bio_detail(struct mem_dev *mdev, struct bio *bio, bool is_write)
{
	struct page *page;
	u64 blks;
	u32 bio_off, page_off;
	u8 *bio_buf, *page_buf;

	ASSERT(((bio->bi_rw & REQ_WRITE) != 0) == is_write);
	ASSERT(!(bio->bi_rw & REQ_DISCARD));

	while (bio_sectors(bio) > 0) {
		u32 bytes;
		blks = bio->bi_sector;
		page_off = do_div(blks, PAGE_SIZE >> 9) << 9;
		bio_off = bio_offset(bio);
		bytes = min(bio_iovec(bio)->bv_len, (u32)(PAGE_SIZE) - page_off);

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
static void discard_block(struct mem_dev *mdev, u64 blks)
{
	struct map_cursor curt;
	struct map *maps[2] = {mdev->map0, mdev->map1};
	size_t i;

	for (i = 0; i < 2; i++) {
		map_cursor_init(maps[i], &curt);
		if (map_cursor_search(&curt, blks, MAP_SEARCH_EQ)) {
			free_page_wrap((struct page *)map_cursor_val(&curt));
			map_cursor_del(&curt);
		}
	}
}

/**
 * Thread-unsafe.
 */
static void discard_bio(struct mem_dev *mdev, struct bio *bio)
{
	ASSERT(bio->bi_rw & REQ_WRITE);
	ASSERT(bio->bi_rw & REQ_DISCARD);

	while (bio_sectors(bio) > 0) {
		struct page *page;
		u32 bytes, page_off;
		u32 blks = bio->bi_sector;
		page_off = do_div(blks, PAGE_SIZE >> 9) << 9;
		bytes = min(bio->bi_size, (u32)PAGE_SIZE - page_off);

		if (bytes == (u32)PAGE_SIZE) {
			ASSERT(page_off == 0);
			discard_block(mdev, blks);
		} else {
			char *page_buf;
			page = get_page_for_write(mdev, blks);
			page_buf = kmap_atomic(page);
			memset(page_buf + page_off, 0, bytes);
			kunmap_atomic(page_buf);
		}
		bio_advance(bio, bytes);
	}
}

/**
 * @cur cursor of map0.
 *   The item will be deleted and the cur will indicates its next.
 */
static void flush_block_detail(struct map_cursor *cur, struct map *map1)
{
	struct page *page0, *page1;
	u64 blks;
	struct map_cursor curt;

	blks = map_cursor_key(cur);
	page0 = (struct page *)map_cursor_val(cur);
	LOG_("flush blks %" PRIu64 "\n", blks);

	map_cursor_init(map1, &curt);
	if (!map_cursor_search(&curt, blks, MAP_SEARCH_EQ))
		BUG();

	page1 = (struct page *)map_cursor_val(&curt);

	copy_highpage(page1, page0);
	free_page_wrap(page0);
	map_cursor_del(cur);
}

static void flush_all_blocks(struct mem_dev *mdev)
{
	struct map_cursor curt;

	LOG_("%u: flush all blocks\n", mdev->index);

	map_cursor_init(mdev->map0, &curt);
	map_cursor_begin(&curt);
	map_cursor_next(&curt);

	while (!map_cursor_is_end(&curt))
		flush_block_detail(&curt, mdev->map1);

	ASSERT(map_is_empty(mdev->map0));
}

/**
 * Range [blks0, blks1).
 */
static void flush_blocks_in_range(struct mem_dev *mdev, u64 blks0, u64 blks1)
{
	struct map_cursor curt;

	LOG_("%u: flush range [%" PRIu64 ", %" PRIu64 ")\n"
		, mdev->index, blks0, blks1);

	map_cursor_init(mdev->map0, &curt);
	if (!map_cursor_search(&curt, blks0, MAP_SEARCH_GE))
		return;

	while (!map_cursor_is_end(&curt) && map_cursor_key(&curt) < blks1)
		flush_block_detail(&curt, mdev->map1);
}

/**
 * Use pos,len instead of bio->bi_sector,bio_sectors(bio).
 */
static void flush_blocks_for_bio(struct mem_dev *mdev, struct bio *bio, sector_t pos, uint len)
{
	u64 blks0, blks1;
	u32 rem;

	ASSERT(len > 0);
	LOG_("%u: flush bio %" PRIu64 " %u\n", mdev->index, (u64)pos, len);

	blks0 = pos;
	do_div(blks0, PAGE_SIZE >> 9);

	blks1 = pos + len;
	rem = do_div(blks1, PAGE_SIZE >> 9);
	if (rem != 0)
		blks1++;

	ASSERT(blks0 < blks1);
	flush_blocks_in_range(mdev, blks0, blks1);
}

static void exec_read_bio(struct mem_dev *mdev, struct bio *bio)
{
	exec_bio_detail(mdev, bio, false);
}

static void exec_write_bio(struct mem_dev *mdev, struct bio *bio)
{
	exec_bio_detail(mdev, bio, true);
}

static void backup_bio_pos_and_len(struct bio *bio, sector_t *posp, uint *lenp)
{
	*posp = bio->bi_sector;
	*lenp = bio_sectors(bio);
}

/**
 * Thread-unsafe.
 */
static void process_bio(struct mem_dev *mdev, struct bio *bio)
{
	const int state = atomic_read(&mdev->state);
	int err = 0;

	if (bio->bi_rw & REQ_WRITE) {
		sector_t pos;
		uint len;
		if (is_write_error(state)) {
			err = -EIO;
			goto fin;
		}
		if (bio->bi_rw & REQ_FLUSH) {
			log_info_bio(mdev->index, "flush", bio);
			flush_all_blocks(mdev);
			if (bio_sectors(bio) == 0)
				goto fin;
		}
		backup_bio_pos_and_len(bio, &pos, &len);
		if (bio->bi_rw & REQ_DISCARD) {
			log_info_bio(mdev->index, "discard", bio);
			discard_bio(mdev, bio);
		} else {
			log_info_bio(mdev->index, "write", bio);
			exec_write_bio(mdev, bio);
		}
		if (bio->bi_rw & REQ_FUA)
			flush_blocks_for_bio(mdev, bio, pos, len);
	} else {
		if (is_read_error(state)) {
			err = -EIO;
			goto fin;
		}
		log_info_bio(mdev->index, "read", bio);
		exec_read_bio(mdev, bio);
	}
fin:
	/*
	 * If BIO_UPTODATE flag is set, err is 0.
	 * otherwise, err is -EIO.
	 */
	if (err)
		clear_bit(BIO_UPTODATE, &bio->bi_flags);
	else
		set_bit(BIO_UPTODATE, &bio->bi_flags);
}

static void bio_list_insert_randomly(struct bio_list *bl, struct bio *bio, size_t nr)
{
	size_t idx, i;
	struct bio *bio1;

	if (!bl->tail || nr == 0) {
		bio_list_add(bl, bio);
		return;
	}

	/* Decide position randomly. */
	get_random_bytes(&idx, sizeof(idx));
	idx %= nr;

	/* Get the insert position. */
	bio1 = bl->head;
	for (i = 0; i < idx; i++) {
		if (!bio1->bi_next)
			break;
		bio1 = bio1->bi_next;
	}

	/* If reached end */
	if (!bio1->bi_next) {
		bio_list_add(bl, bio);
		return;
	}

	/* Insert bio to the position */
	ASSERT(bio1 != bl->tail);
	bio->bi_next = NULL;
	bio->bi_next = bio1->bi_next;
	bio1->bi_next = bio;
}

/**
 * Reorder bio list randomly.
 * Any IOs can not get over flush requests.
 */
static void reorder_bio_list(struct bio_list *bl)
{
	struct bio_list bl0, bl1;
	struct bio *bio;
	size_t nr = 0;
#ifdef DEBUG
	const size_t size = bio_list_size(bl);
	size_t nr_flush = 0;
#endif
	bio_list_init(&bl0);
	bio_list_init(&bl1);

	while ((bio = bio_list_pop(bl))) {
		if (bio->bi_rw & REQ_FLUSH) {
			bio_list_merge(&bl1, &bl0);
			bio_list_init(&bl0);
			bio_list_add(&bl1, bio);
			nr = 0;
#ifdef DEBUG
			nr_flush++;
#endif
		} else {
			bio_list_insert_randomly(&bl0, bio, nr);
			nr++;
		}
	}
	bio_list_merge(&bl1, &bl0);
	bio_list_init(&bl0);
#ifdef DEBUG
	ASSERT(size == bio_list_size(&bl1));
	if (size > 1 || nr_flush > 0)
		LOG_("reorder size > 0: %zu %zu\n", size, nr_flush);
#endif

	bio_list_merge(bl, &bl1);
	bio_list_init(&bl1);
#ifdef DEBUG
	ASSERT(size == bio_list_size(bl));
#endif
}

/*
 * For tasks.
 */

static void run_delay2_task(struct work_struct *ws)
{
	struct pack_work *pwork = get_pack_work_from_work(ws);
	struct mem_dev *mdev = pwork->mdev;
	struct bio *bio;

	if (atomic_read(&mdev->does_reorder_io))
		reorder_bio_list(&pwork->bl);

	while ((bio = bio_list_pop(&pwork->bl))) {
		int err = test_bit(BIO_UPTODATE, &bio->bi_flags) ? 0 : -EIO;
		bio_endio(bio, err);
		atomic_dec(&mdev->nr_running);
	}
	destroy_pack_work(pwork);
}

static inline uint get_random_delay(struct mem_dev *mdev)
{
	uint32_t diff, min_delay;
	uint delay;

	spin_lock(&mdev->delay_lock);
	min_delay = mdev->min_delay_ms;
	diff = mdev->max_delay_ms - mdev->min_delay_ms;
	spin_unlock(&mdev->delay_lock);

	if (diff == 0)
		return (uint)min_delay;

	get_random_bytes(&delay, sizeof(delay));
	delay %= diff;
	delay += min_delay;
	return delay;
}

static inline void invoke_delay2_task(struct mem_dev *mdev, struct bio_list *bl)
{
	struct pack_work *pwork;
	uint delay_ms;

	ASSERT(!bio_list_empty(bl));
	pwork = create_pack_work(mdev, bl);
	ASSERT(pwork);

	delay_ms = get_random_delay(mdev) / 2; /* 2 is magic number... */
	queue_pack_work_task(mdev->wq_wait, pwork, run_delay2_task, delay_ms);
}

/**
 * run_bio_task() and run_crash_task() are serialized by each ordered workqueue.
 */
static void run_bio_task(struct work_struct *ws)
{
	struct mem_dev *mdev = container_of(ws, struct mem_dev, bio_task);
	struct bio_list bl0, bl1;
	struct bio *bio;

	bio_list_init(&bl0);

	spin_lock(&mdev->ready_lock);
	bio_list_merge(&bl0, &mdev->ready_bl);
	bio_list_init(&mdev->ready_bl);
	spin_unlock(&mdev->ready_lock);

	if (bio_list_empty(&bl0))
		return;

	if (atomic_read(&mdev->does_reorder_io))
		reorder_bio_list(&bl0);

	bio_list_init(&bl1);
	while ((bio = bio_list_pop(&bl0))) {
		process_bio(mdev, bio);
		bio_list_add(&bl1, bio);
	}

	invoke_delay2_task(mdev, &bl1);
}

/**
 * run_bio_task() and run_crash_task() are serialized by an ordered workqueue
 * on each device.
 */
static void run_crash_task(struct work_struct *ws)
{
	struct mem_dev *mdev = container_of(ws, struct mem_dev, crash_task);
	const int pct = atomic_read(&mdev->lost_pct_in_crash);
	size_t nr_alive, nr_lost;

	free_pages_in_map_randomly(mdev->map0, pct, &nr_alive, &nr_lost);
	LOGi("%u: carsh with lost pct: %d nr_alive: %zu nr_lost: %zu\n"
		, mdev->index, pct, nr_alive, nr_lost);
}

static void run_recover_task(struct work_struct *ws)
{
	struct mem_dev *mdev = container_of(ws, struct mem_dev, recover_task);

	flush_all_blocks(mdev);
}

static void run_delay1_task(struct work_struct *ws)
{
	struct pack_work *pwork = get_pack_work_from_work(ws);
	struct mem_dev *mdev = pwork->mdev;

	spin_lock(&mdev->ready_lock);
	bio_list_merge(&mdev->ready_bl, &pwork->bl);
	bio_list_init(&pwork->bl);
	spin_unlock(&mdev->ready_lock);

	invoke_bio_task(mdev);
	destroy_pack_work(pwork);
}

static inline void invoke_delay1_task(struct mem_dev *mdev, struct bio *bio)
{
	struct bio_list bl;
	struct pack_work *pwork;
	uint delay_ms;

	bio_list_init(&bl);
	bio_list_add(&bl, bio);

	pwork = create_pack_work(mdev, &bl);
	ASSERT(pwork);

	delay_ms = get_random_delay(mdev);
	queue_pack_work_task(mdev->wq_wait, pwork, run_delay1_task, delay_ms);
}

static void crashblk_make_request(struct request_queue *q, struct bio *bio)
{
	struct mem_dev *mdev = q->queuedata;
	atomic_inc(&mdev->nr_running);
	invoke_delay1_task(mdev, bio);
}

/*
 * Ioctl for /dev/crashblkX
 */

static void del_dev(struct mem_dev *mdev);

static int ioctl_stop_dev(struct mem_dev *mdev, struct crashblk_ctl *ctl)
{
	del_dev_from_idr(mdev);
	del_dev(mdev);
	return 0;
}

static int ioctl_crash(struct mem_dev *mdev, struct crashblk_ctl *ctl)
{
	int prev_st = atomic_read(&mdev->state);
	int new_st = CRASHBLK_STATE_CRASHING;
	int st;

	if (!is_allowed_for_error(prev_st)) {
		LOGe("%u: bad state prev: %d\n", mdev->index, prev_st);
		return -EFAULT;
	}
	st = atomic_cmpxchg(&mdev->state, prev_st, new_st);
	if (prev_st != st) {
		LOGe("%u: make_crash: state change to crashing failed: "
			"expected %d prev %d.\n"
			, mdev->index, prev_st, st);
		return -EFAULT;
	}
	LOGi("%u: state change: crashing\n", mdev->index);

	invoke_crash_task(mdev);
	flush_workqueue(mdev->wq_ordered);

	prev_st = CRASHBLK_STATE_CRASHING;
	new_st = CRASHBLK_STATE_CRASHED;
	st = atomic_cmpxchg(&mdev->state, prev_st, new_st);
	if (prev_st != st) {
		LOGe("%u: make_crash: state change to crashed failed: "
			"expected %d prev %d\n"
			, mdev->index, prev_st, st);
		atomic_set(&mdev->state, 0); /* reset */
		return -EFAULT;
	}
	LOGi("%u: state change: crashed\n", mdev->index);
	return 0;
}

static int ioctl_io_error(struct mem_dev *mdev, struct crashblk_ctl *ctl)
{
	const int prev_st = atomic_read(&mdev->state);
	const int new_st = ctl->val_int;
	int st;

	if (!is_allowed_for_error(prev_st) || !is_allowed_in_error(new_st)) {
		LOGe("%u: io_error: bad state prev %s new %s.\n"
			, mdev->index, get_state_str(prev_st)
			, get_state_str(new_st));
		return -EFAULT;
	}
	st = atomic_cmpxchg(&mdev->state, prev_st, new_st);
	if (st != prev_st) {
		LOGe("%u: io_error: state change failed: "
			"expected %s prev %s new %s\n"
			, mdev->index, get_state_str(prev_st)
			, get_state_str(st), get_state_str(new_st));
		return -EFAULT;
	}
	return 0;
}

static int ioctl_recover(struct mem_dev *mdev, struct crashblk_ctl *ctl)
{
	const int prev_st = atomic_read(&mdev->state);
	const int new_st = CRASHBLK_STATE_NORMAL;
	int st;

	if (!is_allowed_in_error(prev_st)
		&& prev_st != CRASHBLK_STATE_CRASHED) {
		LOGe("%u: recover: bad state prev %s.\n"
			, mdev->index, get_state_str(prev_st));
		return -EFAULT;
	}

	invoke_recover_task(mdev);
	flush_workqueue(mdev->wq_ordered);

	st = atomic_cmpxchg(&mdev->state, prev_st, new_st);
	if (st != prev_st) {
		LOGe("%u: recover: state change failed: "
			"expected %s prev %s\n"
			, mdev->index, get_state_str(prev_st)
			, get_state_str(st));
		return -EFAULT;
	}
	return 0;
}

static int ioctl_get_state(struct mem_dev *mdev, struct crashblk_ctl *ctl)
{
	ctl->val_int = atomic_read(&mdev->state);
	return 0;
}

static int ioctl_set_lost_pct(struct mem_dev *mdev, struct crashblk_ctl *ctl)
{
	const int pct = ctl->val_int;

	if (pct < 0 || pct > 100) {
		LOGe("%u: pct must be in the range [0, 100] but %d\n"
			, mdev->index, pct);
		return -EFAULT;
	}

	atomic_set(&mdev->lost_pct_in_crash, pct);
	LOGi("%u: set lost_pct_in_crash: %d\n", mdev->index, pct);
	return 0;
}

static int ioctl_set_reorder(struct mem_dev *mdev, struct crashblk_ctl *ctl)
{
	const int reorder = ctl->val_int != 0;

	atomic_set(&mdev->does_reorder_io, reorder);
	LOGi("%u: set reorder: %d\n", mdev->index, reorder);
	return 0;
}

static int ioctl_get_delay_ms(struct mem_dev *mdev, struct crashblk_ctl *ctl)
{
	u32 v[2];
	v[0] = mdev->min_delay_ms;
	v[1] = mdev->max_delay_ms;
	memcpy(&ctl->val_u64, &v[0], sizeof(u64));
	return 0;
}

static int ioctl_set_delay_ms(struct mem_dev *mdev, struct crashblk_ctl *ctl)
{
	u32 v[2];

	memcpy(&v[0], &ctl->val_u64, sizeof(u64));
	if (v[0] > v[1]) {
		LOGe("%u: min/max constraint error %u %u\n"
			, mdev->index, v[0], v[1]);
		return -EFAULT;
	}
	mdev->min_delay_ms = v[0];
	mdev->max_delay_ms = v[1];
	return 0;
}

static int dispatch_dev_ioctl(struct mem_dev *mdev, struct crashblk_ctl *ctl)
{
	size_t i;
	struct {
		int id;
		int (*handler)(struct mem_dev *mdev, struct crashblk_ctl *ctl);
	} tbl[] = {
		{CRASHBLK_IOCTL_STOP_DEV, ioctl_stop_dev},
		{CRASHBLK_IOCTL_CRASH, ioctl_crash},
		{CRASHBLK_IOCTL_IO_ERROR, ioctl_io_error},
		{CRASHBLK_IOCTL_RECOVER, ioctl_recover},
		{CRASHBLK_IOCTL_GET_STATE, ioctl_get_state},
		{CRASHBLK_IOCTL_SET_LOST_PCT, ioctl_set_lost_pct},
		{CRASHBLK_IOCTL_SET_REORDER, ioctl_set_reorder},
		{CRASHBLK_IOCTL_GET_DELAY_MS, ioctl_get_delay_ms},
		{CRASHBLK_IOCTL_SET_DELAY_MS, ioctl_set_delay_ms},
	};

	for (i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++) {
		if (ctl->command == tbl[i].id)
			return tbl[i].handler(mdev, ctl);
	}
	LOGe("dispatch_dev_ioctl: command %d is not supported.\n",
		ctl->command);
	return -ENOTTY;
}

/*
 * Ioctl utility functions.
 */

static struct crashblk_ctl *crashblk_get_ctl(void __user *userctl, gfp_t gfp_mask)
{
	struct crashblk_ctl *ctl;

	ctl = kzalloc(sizeof(*ctl), gfp_mask);
	if (!ctl) {
		LOGe("memory allocation for crashblk_ctl error.\n");
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

static bool crashblk_put_ctl(void __user *userctl, struct crashblk_ctl *ctl)
{
	bool ret = true;

	if (copy_to_user(userctl, ctl, sizeof(*ctl)))
		ret = false;

	kfree(ctl);
	return ret;
}

/*
 * For /dev/crashblkX operations.
 */

static int mem_dev_open(struct block_device *bdev, fmode_t mode)
{
	return 0;
}

static void mem_dev_release(struct gendisk *gd, fmode_t mode)
{
	/* do nothing */
}

static int mem_dev_ioctl(struct block_device *bdev, fmode_t mode,
			unsigned int cmd, unsigned long arg)
{
	int ret;
	struct crashblk_ctl *ctl;
	struct crashblk_ctl __user *user = (struct crashblk_ctl __user *)arg;
	struct mem_dev *mdev = bdev->bd_disk->private_data;

	if (cmd != CRASHBLK_IOCTL)
		return -EFAULT;

	ctl = crashblk_get_ctl(user, GFP_KERNEL);
	if (!ctl)
		return -EFAULT;

	ret = dispatch_dev_ioctl(mdev, ctl);

	if (!crashblk_put_ctl(user, ctl))
		return -EFAULT;

	return ret;
}

static struct block_device_operations mem_devops_ = {
	.owner		 = THIS_MODULE,
	.open		 = mem_dev_open,
	.release	 = mem_dev_release,
	.ioctl		 = mem_dev_ioctl
};

/*
 * For controlling devices
 */

static struct mem_dev *create_mem_dev(void)
{
	struct mem_dev *mdev;

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

	spin_lock_init(&mdev->ready_lock);
	bio_list_init(&mdev->ready_bl);
	atomic_set(&mdev->nr_running, 0);
	atomic_set(&mdev->state, 0);
	spin_lock_init(&mdev->delay_lock);
	spin_lock(&mdev->delay_lock);
	mdev->min_delay_ms = 0; /* default value */
	mdev->max_delay_ms = 3; /* default value */
	spin_unlock(&mdev->delay_lock);
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

static void destroy_mem_dev(struct mem_dev *mdev)
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
static void del_dev(struct mem_dev *mdev)
{
	const u32 minor = mdev->index;
	int nr_running;

	del_gendisk(mdev->disk);

	/* Complete all pending IOs. */
	flush_workqueue(mdev->wq_wait); /* waiting/reorder tasks.*/
	flush_workqueue(mdev->wq_ordered);
	flush_workqueue(mdev->wq_wait); /* completion tasks. */

	ASSERT(bio_list_empty(&mdev->bl));
	nr_running = atomic_read(&mdev->nr_running);
	LOGi("%u: nr_running: %d\n", mdev->index, nr_running);
	ASSERT(nr_running == 0);

	destroy_workqueue(mdev->wq_ordered);
	destroy_workqueue(mdev->wq_wait);
	blk_cleanup_queue(mdev->q);
	put_disk(mdev->disk);
	destroy_mem_dev(mdev);

	LOGi("deleted crashblk%u\n", minor);
}

static bool add_dev(u64 size_lb, u32 *minorp)
{
	struct mem_dev *mdev;
	struct gendisk *disk;
	struct request_queue *q;

	mdev = create_mem_dev();
	if (!mdev)
		return false;

	INIT_LIST_HEAD(&mdev->list);

	q = mdev->q = blk_alloc_queue(GFP_KERNEL);
	if (!q) {
		LOGe("mdev->q init failed.\n");
		goto error0;
	}
	q->queuedata = mdev;
	blk_queue_make_request(q, crashblk_make_request);
	disk = mdev->disk = alloc_disk(1);
	if (!disk) {
		LOGe("mdev->disk alloc failed.\n");
		goto error1;
	}

	if (!add_dev_to_idr(mdev))
		goto error2;

	mdev->wq_ordered = alloc_ordered_workqueue(CRASHBLK_NAME "%uo", WQ_MEM_RECLAIM, mdev->index);
	if (!mdev->wq_ordered) {
		LOGe("unable to allocate workqueue (ordered).\n");
		goto error3;
	}
	INIT_WORK(&mdev->bio_task, run_bio_task);
	INIT_WORK(&mdev->crash_task, run_crash_task);
	INIT_WORK(&mdev->recover_task, run_recover_task);

	mdev->wq_wait = alloc_workqueue(CRASHBLK_NAME "%uw", WQ_UNBOUND | WQ_MEM_RECLAIM,
					WQ_UNBOUND_MAX_ACTIVE, mdev->index);
	if (!mdev->wq_wait) {
		LOGe("unable to allocate workqueue (wait).");
		goto error4;
	}

	atomic_set(&mdev->lost_pct_in_crash, 100);
	atomic_set(&mdev->does_reorder_io, 0);

	blk_queue_logical_block_size(q, LBS);
	blk_queue_physical_block_size(q, LBS);
	blk_queue_io_min(q, LBS);
	blk_queue_io_opt(q, LBS);
	q->limits.discard_granularity = PAGE_SIZE;
	q->limits.max_discard_sectors = UINT_MAX;
	q->limits.discard_zeroes_data = 1;
	queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, q);
	blk_queue_flush(q, REQ_FLUSH | REQ_FUA);
	blk_queue_flush_queueable(q, true);

	set_capacity(disk, size_lb);

	disk->flags |= GENHD_FL_EXT_DEVT;
	disk->major = major_;
	disk->first_minor = mdev->index;
	disk->fops = &mem_devops_;
	disk->private_data = mdev;
	disk->queue = q;
	snprintf(disk->disk_name, DISK_NAME_LEN, "%s%u", CRASHBLK_NAME, mdev->index);
	add_disk(disk);

	if (minorp)
		*minorp = mdev->index;

	LOGi("added crashblk%u\n", mdev->index);
	return true;

#if 0
error5:
	destroy_workqueue(mdev->wq_wait)
#endif
error4:
	destroy_workqueue(mdev->wq_ordered);
error3:
	del_dev_from_idr(mdev);
error2:
	put_disk(mdev->disk);
error1:
	blk_cleanup_queue(mdev->q);
error0:
	destroy_mem_dev(mdev);
	return false;
}

static void exit_all_devices(void)
{
	struct mem_dev *mdev;

	while ((mdev = pop_dev_from_idr()))
		del_dev(mdev);
}

static void init_globals(void)
{
	spin_lock_init(&dev_lock_);
	atomic_set(&nr_pages_, 0);
	idr_init(&dev_idr_);
}

/*
 * For /dev/crashblk_ctl
 */

static int ioctl_start_dev(struct crashblk_ctl *ctl)
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

static int ioctl_get_major(struct crashblk_ctl *ctl)
{
	ctl->val_int = major_;
	return 0;
}

static int ioctl_num_of_dev(struct crashblk_ctl *ctl)
{
	ctl->val_int = get_nr_dev_in_idr();
	return 0;
}

static int dispatch_ctl_ioctl(struct crashblk_ctl *ctl)
{
	size_t i;
	struct {
		int id;
		int (*handler)(struct crashblk_ctl *ctl);
	} tbl[] = {
		{CRASHBLK_IOCTL_START_DEV, ioctl_start_dev},
		{CRASHBLK_IOCTL_GET_MAJOR, ioctl_get_major},
		{CRASHBLK_IOCTL_NUM_OF_DEV, ioctl_num_of_dev},
	};

	for (i = 0; i < sizeof(tbl); i++) {
		if (ctl->command == tbl[i].id)
			return tbl[i].handler(ctl);
	}
	LOGe("dispatch_ctl_ioctl: command %d is not supported.\n",
		ctl->command);
	return -ENOTTY;
}

static long crashblk_ctl_ioctl(struct file *file, unsigned int command, unsigned long u)
{
	int ret;
	struct crashblk_ctl *ctl;
	struct crashblk_ctl __user *user = (struct crashblk_ctl __user *)u;

	if (command != CRASHBLK_IOCTL)
		return -EFAULT;

	ctl = crashblk_get_ctl(user, GFP_KERNEL);
	if (!ctl)
		return -EFAULT;

	ret = dispatch_ctl_ioctl(ctl);

	if (!crashblk_put_ctl(user, ctl))
		return -EFAULT;

	return ret;
}

#ifdef CONFIG_COMPAT
static long crashblk_ctl_compat_ioctl(struct file *file, unsigned int command, unsigned long u)
{
	return crashblk_ctl_ioctl(file, command, (unsigned long)compat_ptr(u));
}
#endif

static const struct file_operations ctl_fops_ = {
	.open = nonseekable_open,
	.unlocked_ioctl = crashblk_ctl_ioctl,
	.compat_ioctl = crashblk_ctl_compat_ioctl,
	.owner = THIS_MODULE,
};

/*
 * Control device.
 */

static struct miscdevice crashblk_misc_ = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = CRASHBLK_NAME,
	.nodename = CRASHBLK_CTL_NAME,
	.fops = &ctl_fops_,
};

/*
 * Init/exit functions definition.
 */

static int __init crashblk_init(void)
{
	LOGi(CRASHBLK_NAME " module init.\n");
	LOGi("build date: " BUILD_DATE "\n");

	init_globals();

	if (!initialize_treemap_memory_manager_kmalloc(&mmgr_, 16)) {
		LOGe("unable to initialize treemap memory manager.\n");
		goto error0;
	}

	major_ = register_blkdev(0, CRASHBLK_NAME);
	if (major_ <= 0) {
		LOGe("unable to get major device number.\n");
		goto error1;
	}
	LOGi(CRASHBLK_NAME " major %u\n", major_);

	if (misc_register(&crashblk_misc_) < 0) {
		LOGe("unable to register control device.\n");
		goto error2;
	}

	return 0;
#if 0
error3:
	misc_deregister(&crashblk_misc_);
#endif
error2:
	unregister_blkdev(major_, CRASHBLK_NAME);
error1:
	finalize_treemap_memory_manager(&mmgr_);
	return -ENOMEM;
error0:
	return -EBUSY;
}

static void __exit crashblk_exit(void)
{
	misc_deregister(&crashblk_misc_);
	exit_all_devices();
	unregister_blkdev(major_, CRASHBLK_NAME);
	idr_destroy(&dev_idr_);
	finalize_treemap_memory_manager(&mmgr_);

	LOGi("nr_pages: %d\n", atomic_read(&nr_pages_));
	LOGi("%s module exit.\n", CRASHBLK_NAME);
}

module_init(crashblk_init);
module_exit(crashblk_exit);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("a memory block device driver for crash test");
MODULE_ALIAS(CRASHBLK_NAME);
/* MODULE_ALIAS_BLOCKDEV_MAJOR(CRASHBLK_MAJOR); */
