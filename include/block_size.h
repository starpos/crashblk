/**
 * block_size.h - Definitions for block size.
 *
 * Converters are available for logical-to-physical, physical to logical.
 */
#ifndef BLOCK_SIZE_H
#define BLOCK_SIZE_H

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
 * Macros.
 *******************************************************************************/

/**
 * Logical block size is fixed.
 */
#define LBS (1U << 9)

/**
 * Assertion of logical/physical block size.
 */
#define ASSERT_LBS_PBS(lbs, pbs) ASSERT(is_valid_lbs_pbs(lbs, pbs))
#define ASSERT_PBS(pbs) ASSERT(is_valid_pbs(pbs))

/*******************************************************************************
 * Prototype of static inline functions.
 *******************************************************************************/

static inline bool is_valid_lbs_pbs(u32 lbs, u32 pbs);
static inline bool is_valid_pbs(u32 pbs);

static inline u32 n_lb_in_pb(u32 pbs);

static inline u64 capacity_pb(u32 pbs, u64 capacity_lb);
static inline u64 addr_pb(u32 pbs, u64 addr_lb);
static inline u64 off_in_pb(u32 pbs, u64 addr_lb);
static inline u64 addr_lb(u32 pbs, u64 addr_pb);
static inline u64 capacity_lb(u32 pbs, u64 capacity_pb);

/*******************************************************************************
 * Definition of static inline functions.
 *******************************************************************************/

/**
 * Logical-physical block size validation.
 */
static inline bool is_valid_lbs_pbs(u32 lbs, u32 pbs)
{
	return (lbs > 0 && pbs >= lbs && pbs % lbs == 0);
}

/**
 * Physical block size validation.
 */
static inline bool is_valid_pbs(u32 pbs)
{
	return is_valid_lbs_pbs(LBS, pbs);
}

/**
 * Get number of logical blocks in a physical block.
 */
static inline u32 n_lb_in_pb(u32 pbs)
{
	u32 ret;
	ASSERT_PBS(pbs);
	ret = pbs / LBS;
	ASSERT(ret > 0);
	return ret;
}

/**
 * Capacity conversion (logical to physial).
 *
 * @pbs physical block size in bytes.
 * @capacity_lb number of logical blocks.
 *
 * @return number of physical blocks required to store
 *   capacity_lb logical blocks.
 */
static inline u64 capacity_pb(u32 pbs, u64 capacity_lb)
{
	u32 n_lb;
	ASSERT_PBS(pbs);
	n_lb = n_lb_in_pb(pbs);
	return ((capacity_lb + n_lb - 1) / n_lb);
}

/**
 * Address conversion (logical to physical).
 */
static inline u64 addr_pb(u32 pbs, u64 addr_lb)
{
	ASSERT_PBS(pbs);
	return (addr_lb / (u64)n_lb_in_pb(pbs));
}

/**
 * Get offset in the physical block.
 */
static inline u64 off_in_pb(u32 pbs, u64 addr_lb)
{
	ASSERT_PBS(pbs);
	return (addr_lb % (u64)n_lb_in_pb(pbs));
}

/**
 * Address conversion (physical to logical).
 */
static inline u64 addr_lb(u32 pbs, u64 addr_pb)
{
	ASSERT_PBS(pbs);
	return (addr_pb * (u64)n_lb_in_pb(pbs));
}

/**
 * Capacity conversion (physial to logical).
 *
 * @pbs physical block size in bytes.
 * @capacity_pb number of physical blocks.
 *
 * @return number of logical blocks.
 */
static inline u64 capacity_lb(u32 pbs, u64 capacity_pb)
{
	return addr_lb(pbs, capacity_pb);
}

#ifdef __cplusplus
}
#endif

#endif /* BLOCK_SIZE_H */
