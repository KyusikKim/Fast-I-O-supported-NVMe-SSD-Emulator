#ifndef _LINUX_HMB_H
#define _LINUX_HMB_H

#include <linux/hash.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/types.h> /* atomic_t */
#include <linux/time.h> /* for getnstimeofday() */
#include <linux/gfp.h> /* for *GFP* */
#include <linux/blk_types.h> /* for blk_qc_t */
#include <linux/completion.h> /* for struct completion */

#define HMB_HAS_NO_ENTRY (-1)
#define HMB_BIO_NUMBER_MAX (64)

#define HMB_BITMAP_PART_MAX_VALUE (0xFFFFFFFF)
#define HMB_BITMAP_BITS_PER_PART (8 * sizeof(HmbBitmap32))

#define HMB_DEBUG_TIME_ACC 0
#define HMB_DEBUG_TIME_TMP 1

#define HMB_FASTIO_PARAM__MAX_OCCUPIED_RATIO (70)
#define HMB_FASTIO_PARAM__MIN_TASK_NICE (-20)

extern atomic64_t *HMB_accNum;
extern atomic64_t *HMB_accNum_inserted;
extern atomic64_t *HMB_accNum_deleted;
extern atomic64_t *HMB_accNum_diff;
extern atomic64_t *HMB_accNum_diff_max;
extern atomic64_t *HMB_accNum_sqSize;

extern atomic64_t *HMB_FastIO_n_procssed;
extern atomic64_t *HMB_FastIO_n_missed;

extern atomic64_t HMB_FastIO_n_locked;
extern atomic64_t HMB_FastIO_n_waited;
extern atomic64_t HMB_FastIO_pid_locked;
extern atomic64_t HMB_FastIO_pid_waited;
extern atomic64_t HMB_FastIO_cpu_locked;
extern atomic64_t HMB_FastIO_cpu_waited;

extern uint64_t HMB_num_queues;

#define HMB_NUMBER_OF_SQ_ENTRIES(sq_size, head, tail) ((tail >= head) ? ((uint64_t)tail - head) : (((uint64_t)sq_size - head) + tail))

//#define HMB_DEBUG_CLOSELY

typedef uint32_t HmbBitmap32;
typedef int32_t HmbHeads;

struct bio;

enum {
	HMB_UL_DISABLED = 0,
	HMB_UL_URGENT   = 1,
	HMB_UL_HIGH     = 2,
	HMB_UL_MIDDLE   = 3,
	HMB_UL_LOW      = 4,
};

#define HMB_UL_NUMBER (4)

#pragma pack(push, 1)	 /* for avoiding automatic structure padding */
typedef struct HmbSplitTable
{
	int16_t  seg_id;
	uint32_t offset;
} HmbSplitTable;
#pragma pack(pop)

#pragma pack(push, 1)	 /* for avoiding automatic structure padding */
typedef struct HmbSharedEnt
{
	uint32_t segment;       /* 4bytes (acc: 4) */
	uint32_t offset;        /* 4bytes (acc: 8) */

	uint32_t e_own;         /* 4bytes (acc: 12) */
	uint32_t e_prev;        /* 4bytes (acc: 16) */
	uint32_t e_next;        /* 4bytes (acc: 20) */

	uint64_t lpn    : 55;   /* 8bytes (acc: 32) */
	uint64_t usable :  1;  
	uint64_t dirty  :  1;  
	uint64_t urgency:  3;
	uint64_t rsvd   :  4;  
} HmbSharedEnt;
#pragma pack(pop)

#pragma pack(push, 1)    /* for avoiding automatic structure padding */
/** [1] Shared data between host and this controller */
typedef struct HmbSharedBitmapEnt
{
	HmbBitmap32 filled;
} HmbSharedBitmapEnt;
/** [1] **/
#pragma pack(pop)

#pragma pack(push, 1)    /* for avoiding automatic structure padding */
typedef struct HmbSortedEnt
{
	uint32_t e_own;
	uint32_t e_next;
	uint32_t e_prev;

	/* [1] for Write Buffer */
	uint32_t w_e_prev;
	uint32_t w_e_next;
	/* [1] */

	uint32_t r_e_prev;
	uint32_t r_e_next;
} HmbSortedEnt;
#pragma pack(pop)

#pragma pack(push, 1)    /* for avoiding automatic structure padding */
typedef struct HmbDLL
{
	int32_t e_prev;
	int32_t e_next;
} HmbDLL;
#pragma pack(pop)

#pragma pack(push, 1)    /* for avoiding automatic structure padding */
typedef struct HmbMeta
{
	uint32_t HMB__SE_num_max;             /* 4bytes (acc: 4) */

	uint16_t HMB__SE_ST_num;      /* 2bytes (acc: 6) */
	uint32_t HMB__SE_ST_unit;     /* 4bytes (acc: 10) */

	int16_t  HMB__SE_ST_seg_id;   /* 2bytes (acc: 12) */
	uint32_t HMB__SE_ST_offset;   /* 4bytes (acc: 16) */

	int16_t  C__table_ST_seg_id;  /* 2bytes (acc: 18) */
	uint32_t C__table_ST_offset;  /* 4bytes (acc: 22) */

	uint16_t C__table_ST_num;     /* 2bytes (acc: 24) */
	uint32_t C__table_ST_unit;    /* 4bytes (acc: 28) */

	uint32_t C__n_max_entries;            /* 4bytes (acc: 32) */

	int16_t  C__heads_ST_seg_id;  /* 2bytes (acc: 34) */
	uint32_t C__heads_ST_offset;  /* 4bytes (acc: 38) */

	uint16_t C__heads_ST_num;     /* 2bytes (acc: 40) */
	uint32_t C__heads_ST_unit;    /* 4bytes (acc: 44) */

	uint8_t  C__heads_hash_bit;           /* 1byte  (acc: 45) */
	uint32_t C__heads_cnt_max;            /* 4bytes (acc: 49) */

	int16_t  C__sorted_ST_seg_id; /* 2bytes (acc: 51) */
	uint32_t C__sorted_ST_offset; /* 4bytes (acc: 55) */

	uint16_t C__sorted_ST_num;    /* 2bytes (acc: 57) */
	uint32_t C__sorted_ST_unit;   /* 4bytes (acc: 61) */

	int16_t  C__victimAll_seg_id;         /* 2bytes (acc: 63) */
	uint32_t C__victimAll_offset;         /* 4bytes (acc: 67) */

	int16_t  C__bm_seg_id;                /* 2bytes (acc: 69) */
	uint32_t C__bm_offset;                /* 4bytes (acc: 73) */

	int16_t  C__bm_empty_seg_id;          /* 2bytes (acc: 75) */
	uint32_t C__bm_empty_offset;          /* 4bytes (acc: 79) */

	int32_t  lock;                        /* 4bytes (acc: 83) */

	int16_t  C__urgency_seg_id;           /* 2bytes (acc: 85) */
	uint32_t C__urgency_offset;           /* 4bytes (acc: 89) */

	uint32_t C__bm_parts_cnt;             /* 4bytes (acc: 93) */

	uint32_t C__n_cached;                 /* 4bytes (acc: 97) */
	uint32_t C__n_dirty;                  /* 4bytes (acc: 101) */
	uint16_t C__pctg_explicitFlush;       /* 2bytes (acc: 103) */

	int16_t  C__victimRc_seg_id;          /* 2bytes (acc: 105) */
	uint32_t C__victimRc_offset;          /* 4bytes (acc: 109) */

	int16_t  C__bm_empty_table_seg_id;    /* 2bytes (acc: 111) */
	uint32_t C__bm_empty_table_offset;    /* 4bytes (acc: 115) */

	int16_t  C__table_bm_ST_seg_id;       /* 2bytes (acc: 117) */
	uint32_t C__table_bm_ST_offset;       /* 4bytes (acc: 121) */

	uint16_t C__cache_unit_bits;          /* 2bytes (acc: 123) */

	int16_t  FASTIO__data_ST_seg_id;
	uint32_t FASTIO__data_ST_offset;

	uint16_t FASTIO__data_ST_num;
	uint32_t FASTIO__data_ST_unit;

	int16_t  FASTIO__meta_seg_id;
	uint32_t FASTIO__meta_offset;

	uint64_t FASTIO__data_max_bytes;

	/* HMB: Reserved area for 8KB aligned structure size */
	//uint8_t  rsvd[5];                     /* 5bytes (acc: 128) */
} HmbMeta;
#pragma pack(pop)

typedef struct HmbFastIOMeta
{
	uint64_t lba;
	uint64_t nlb      : 63; 
	uint64_t is_write : 1;
} HmbFastIOMeta; 

typedef struct HmbCtrl
{
	//atomic_t lock_local;
	spinlock_t lock_local;
	struct completion lock_local_completion;
	unsigned long lock_local_flags;

	bool hmb_enabled;
	bool fwb_enabled;
	bool fastIO_enabled;

	/**
		Related with hmb
	**/
	uint64_t cache_unit;
	uint8_t  cache_unit_bits;

	void**          hmb_addr;
	uint32_t        hmb_cnt;
	uint64_t        hmb_size;
	struct HmbMeta* hmb_header;

	/**
		Realted with cache
	**/
	//struct HmbSharedEnt *table;
	struct HmbSplitTable* table_ST;
	uint16_t              table_split_num;
	uint32_t              table_split_unit;
	uint64_t              table_cnt_max;

	struct HmbSplitTable* table_bm_ST;

	/*
	spinlock_t    table_lock;
	unsigned long table_lock_flags;
	*/

	struct HmbSplitTable* heads_ST;
	uint16_t              heads_split_num;
	uint32_t              heads_split_unit;

	uint8_t  heads_hash_bit;
	uint32_t heads_cnt_max;

	//struct HmbSharedEnt *shared;
	//struct HmbSortedEnt *sorted;
	struct HmbSplitTable* sorted_ST;
	uint16_t              sorted_split_num;
	uint32_t              sorted_split_unit;

	int32_t* urgency;
	int32_t* victimAll;
	int32_t* victimRc;

	HmbBitmap32* bm;
	uint32_t     bm_parts_cnt;
	int32_t*     bm_empty;
	HmbDLL*      bm_empty_table;

	HmbFastIOMeta* fastIO_meta;
	HmbSplitTable* fastIO_data_ST;
	uint16_t       fastIO_data_ST_num;
	uint32_t       fastIO_data_ST_unit;
	uint64_t       fastIO_data_max_size;
	
	atomic_t n_hit_f;
	atomic_t n_hit_p;
	atomic_t n_miss;
	atomic_t n_error;

	atomic64_t n_sectors_requested_read;
	atomic64_t n_sectors_requested_write;
	atomic64_t n_sectors_hit;
	atomic64_t n_sectors_buffered;

	/* Add functions to use these variables  */
	atomic64_t t_overhead_buffering;
	atomic64_t t_overhead_caching;

	uint64_t t_WB_processing_hit[2];
	uint64_t t_WB_processing_miss[2];
	uint64_t t_WB_confirming_hitness[2];
	uint64_t t_WB_shared_get_by_lpn[2];
	uint64_t t_WB_shared_get_new_entry[2];
	uint64_t t_WB_entry_delete[2];
	uint64_t t_WB_entry_insert[2];
	uint64_t t_WB_LRU_reorder[2];
	uint64_t t_WB_get_page_addr[2];
	uint64_t t_WB_copy_loop[2];
	uint64_t t_WB_loops;
	uint64_t t_WB_bm_set[2];
	uint64_t t_WB_bm_is_empty[2];
} HmbCtrl;

extern struct HmbCtrl HMB_CTRL;

void hmb_printf(const char *file, int line, const char *func, const char *format, ...);
#define hmb_debug(fmt, ...) hmb_printf(__FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)

void hmb_elapsed_time_acc(bool is_start, uint64_t *t);
uint64_t hmb_get_current_time_ns(void);

#define HMB_HASH_MULTIPLIER_64 GOLDEN_RATIO_64
u32 hmb_hash (u64 value, u8 bits);

bool hmb_valid_hash_val  (uint32_t hashed);
bool hmb_valid_heads_idx (int32_t idx);
bool hmb_valid_table_idx (uint32_t idx);

void hmb_lock   (unsigned long *flags);
void hmb_unlock (unsigned long *flags);

void hmb_lock_local(void);
void hmb_unlock_local(void);
bool hmb_lock_try_local(void);

void hmb_meta_update(void);

void hmb_endio(struct bio **hit_bio, uint32_t hit_cnt, struct bio **miss_bio, uint32_t miss_cnt, \
		       struct bio *last, bool is_last_hit, bool is_for_RC);
bool hmb_generic_make_request(struct bio **bios, uint32_t cnt);
void hmb_chain_multiple(struct bio **bios, uint32_t cnt, struct bio *parent);

HmbSharedEnt*  hmb_table_get_by_idx  (uint32_t idx);
HmbSplitTable* hmb_table_ST_get_by_idx (uint32_t idx);

HmbSplitTable*      hmb_table_bm_ST_get_by_idx      (uint32_t idx); // *
HmbSharedBitmapEnt* hmb_table_bm_get_by_idx         (uint32_t idx); 
bool                hmb_table_bm_isCached_fully     (uint32_t idx);
bool                hmb_table_bm_isCached_partially (uint32_t idx, uint32_t idx_internal);
bool                hmb_table_bm_set                (bool enable, uint32_t idx, uint32_t idx_internal);
bool                hmb_table_bm_set_fully          (bool enable, uint32_t idx);

HmbSortedEnt*  hmb_sorted_get_by_idx (uint32_t idx);
HmbSplitTable* hmb_sorted_ST_get_by_idx (uint32_t idx);

HmbHeads*      hmb_heads_get_by_idx (uint32_t idx);
HmbSplitTable* hmb_heads_ST_get_by_idx (uint32_t idx);

int32_t* hmb_victimAll_get     (void);
int32_t* hmb_victimRc_get      (void);

int32_t hmb_RC_sorted_get_head_idx (void); 
bool    hmb_RC_sorted_set_head     (uint32_t idx);
bool    hmb_RC_sorted_insert_tail  (uint32_t idx);
bool    hmb_RC_sorted_delete       (uint32_t idx);

int32_t hmb_RCOnly_sorted_get_head_idx (void); 
bool    hmb_RCOnly_sorted_set_head     (uint32_t idx);
bool    hmb_RCOnly_sorted_insert_tail  (uint32_t idx);
bool    hmb_RCOnly_sorted_delete       (uint32_t idx);

bool hmb_RC_reorder (uint32_t idx); // *
bool hmb_RC_evict   (uint32_t n_evict);  // *

bool hmb_RC_copy_from_HMB (struct bio *b);
bool hmb_RC_is_cachable   (struct bio *b, u64 *sector_first, u64 *sector_last);

bool hmb_RC_valid_entry (HmbSharedEnt *e, uint64_t lpn, uint32_t idx_internal);


int32_t  hmb_WB_sorted_get_head     (int32_t urgency);
bool     hmb_WB_sorted_set_head     (int32_t urgency, uint32_t idx);
bool     hmb_WB_sorted_insert_tail  (int32_t urgency, uint32_t idx);
bool     hmb_WB_sorted_delete       (int32_t urgency, uint32_t idx);
bool     hmb_WB_sorted_delete_head  (int32_t urgency);

bool hmb_WB_completion        (struct bio **hit, uint32_t n_hit, struct bio **miss, uint32_t n_miss);
bool hmb_WB_processing_hits   (struct bio **hit, uint32_t n_hit);
bool hmb_WB_processing_misses (struct bio **miss, uint32_t n_miss);
bool hmb_WB_is_insertable     (uint32_t n_entries);

bool hmb_WB_is_bufferable (struct bio *b, u64 *sector_first, u64 *sector_last);

bool hmb_WB_valid_entry (HmbSharedEnt *e, uint64_t lpn);

void hmb_partition_remap(struct bio *bio);

bool hmb_bm_get_empty (uint32_t *val);
bool hmb_bm_set       (bool enable, uint32_t val); 

HmbDLL*  hmb_bm_empty_get_by_idx (uint32_t idx);
int32_t* hmb_bm_empty_get_head   (void);
bool     hmb_bm_empty_set_head   (uint32_t idx);
bool     hmb_bm_empty_insert     (uint32_t idx);
bool     hmb_bm_empty_delete     (uint32_t idx);


HmbSharedEnt* hmb_shared_get_head_by_lpn       (uint64_t lpn);
HmbSharedEnt* hmb_shared_get_by_lpn            (uint64_t lpn);
bool          hmb_shared_set_head              (uint32_t idx);
bool          hmb_shared_insert_tail           (uint32_t idx);
bool          hmb_shared_delete                (uint32_t idx);
void          hmb_shared_set_dirty             (bool to_dirty, uint32_t idx);
void          hmb_shared_set_enable            (bool enable, uint32_t idx);
int32_t       hmb_shared_get_new_entry_idx     (uint64_t lpn);
bool          hmb_shared_is_reusable_by_idx    (uint32_t idx);
#define       hmb_shared_get_by_idx         hmb_table_get_by_idx


void hmb_table_nCached_inc(bool is_inc);
void hmb_table_nDirty_inc(bool is_inc);

blk_qc_t hmb_caching(struct bio *bio);
blk_qc_t hmb_buffering(struct bio *bio);

uint64_t hmb_sector_to_lpn          (uint64_t sector_idx);
uint32_t hmb_sector_to_internal_idx (uint64_t sector_idx);

void hmb_fastIO_data_copy(struct bio *bio, bool for_write);
uint64_t hmb_fastIO_get_occupiedRatio (uint64_t qid);

HmbSplitTable* hmb_fastIO_data_ST_get_by_idx(uint32_t idx);
void *hmb_fastIO_get_data(uint64_t innerOffset);

#endif /* #ifndef _LINUX_HMB_H_ */

