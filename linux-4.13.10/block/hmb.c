#include <linux/hmb.h>

#include <linux/types.h>
#include <linux/preempt.h> /* preempt_enable(), preempt_disable() */
#include <linux/bio.h> /* struct bio */
#include <linux/blkdev.h> /* generic_make_request() */
#include <linux/log2.h> /* ilog2() */
#include <asm-generic/div64.h> /* do_div() */
#include <linux/printk.h> /* printk(), printk_safe_flush() */
#include <linux/spinlock.h> /* spin_lock_irqsave(), spin_lock_irqrestore() */
#include <linux/kernel.h> /* for might_sleep() */

HmbCtrl HMB_CTRL;
EXPORT_SYMBOL(HMB_CTRL);

atomic64_t *HMB_accNum_inserted = NULL;
atomic64_t *HMB_accNum_deleted = NULL;
atomic64_t *HMB_accNum_diff = NULL;
atomic64_t *HMB_accNum_diff_max = NULL;
atomic64_t *HMB_accNum = NULL;
atomic64_t *HMB_accNum_sqSize = NULL;

atomic64_t *HMB_FastIO_n_procssed = NULL;
atomic64_t *HMB_FastIO_n_missed = NULL;

atomic64_t HMB_FastIO_n_locked;
atomic64_t HMB_FastIO_n_waited;
atomic64_t HMB_FastIO_pid_locked;
atomic64_t HMB_FastIO_pid_waited;
atomic64_t HMB_FastIO_cpu_locked;
atomic64_t HMB_FastIO_cpu_waited;

EXPORT_SYMBOL(HMB_accNum_inserted);
EXPORT_SYMBOL(HMB_accNum_deleted);
EXPORT_SYMBOL(HMB_accNum_diff);
EXPORT_SYMBOL(HMB_accNum_diff_max);
EXPORT_SYMBOL(HMB_accNum);
EXPORT_SYMBOL(HMB_accNum_sqSize);

EXPORT_SYMBOL(HMB_FastIO_n_procssed);
EXPORT_SYMBOL(HMB_FastIO_n_missed);
EXPORT_SYMBOL(HMB_FastIO_n_locked);
EXPORT_SYMBOL(HMB_FastIO_n_waited);
EXPORT_SYMBOL(HMB_FastIO_pid_locked);
EXPORT_SYMBOL(HMB_FastIO_pid_waited);
EXPORT_SYMBOL(HMB_FastIO_cpu_locked);
EXPORT_SYMBOL(HMB_FastIO_cpu_waited);

uint64_t HMB_num_queues;
EXPORT_SYMBOL(HMB_num_queues);

void hmb_printf(const char *file, int line, const char *func, const char *format, ...)
{
	va_list for_printf;
	char str_buf[512];

	sprintf(str_buf, "HMB: [%s:%s():%d] ", file, func, line);
	va_start(for_printf, format);
	vsprintf(str_buf + strlen(str_buf), format, for_printf);
	va_end(for_printf);

#if 0
	if(str_buf[strlen(str_buf)-2] == '\n')
	{
		str_buf[strlen(str_buf)-2] = '\0';
	}
#endif

	//printk("%s\n", str_buf);
	printk(KERN_ALERT "%s\n", str_buf);
	printk_safe_flush();
}
EXPORT_SYMBOL(hmb_printf);

void hmb_elapsed_time_acc(bool is_start, uint64_t *t)
{
	struct timespec t_cur;

	if(is_start)
	{
		getnstimeofday(&t_cur);
		t[HMB_DEBUG_TIME_TMP] = t_cur.tv_sec * 1000000000 + t_cur.tv_nsec;
	}
	else
	{
		getnstimeofday(&t_cur);
		t[HMB_DEBUG_TIME_ACC] += ((t_cur.tv_sec * 1000000000 + t_cur.tv_nsec) - t[1]);
	}
}

uint64_t hmb_get_current_time_ns(void)
{
	struct timespec t_cur;

	getnstimeofday(&t_cur);
	return t_cur.tv_sec * 1000000000 + t_cur.tv_nsec;
}

void hmb_lock(unsigned long *flags)
{
	atomic_t *lock;
	unsigned long tmp_flags = 0; 

#ifdef HMB_DEBUG_CLOSELY
	if(unlikely(HMB_CTRL.hmb_enabled == false || flags == NULL))
	{    
		hmb_debug("Unexpected locking");
		return;
	}    
#endif

	local_irq_save(tmp_flags);
	preempt_disable();

	*flags = tmp_flags;
	lock = (atomic_t *)(&HMB_CTRL.hmb_header->lock);

	smp_mb__before_atomic();
	while(atomic_cmpxchg(lock, 0, 1) != 0)
	{
		smp_mb__before_atomic();
	}
	smp_mb__after_atomic();
}
EXPORT_SYMBOL(hmb_lock);

void hmb_unlock(unsigned long *flags)
{
	atomic_t *lock;
	unsigned long tmp_flags = *flags;

#ifdef HMB_DEBUG_CLOSELY
	if(unlikely(HMB_CTRL.hmb_enabled == false || flags == NULL))
	{    
		hmb_debug("Unexpected unlocking");
		return;
	}    
#endif

	lock = (atomic_t *)(&HMB_CTRL.hmb_header->lock);

	atomic_dec(lock);

	local_irq_restore(tmp_flags);
	preempt_enable();
}
EXPORT_SYMBOL(hmb_unlock);

void hmb_lock_local()
{
#if 0
	atomic_t *lock;

	lock = &HMB_CTRL.lock_local;

	local_irq_save(HMB_flags);
	preempt_disable();

	smp_mb__before_atomic();
	while(atomic_cmpxchg(lock, 0, 1) != 0)
	{
		smp_mb__before_atomic();
	}
	smp_mb__after_atomic();
#endif
#if 0
	spin_lock(&HMB_CTRL.lock_local);
#endif
	int ret;

	while(!(ret = spin_trylock(&HMB_CTRL.lock_local)))
	{
#if 0
		struct task_struct *t_locked = pid_task(find_get_pid(atomic64_read(&HMB_FastIO_pid_locked)), PIDTYPE_PID);
		uint64_t cur_cpu =  smp_processor_id();
#endif

		atomic64_inc(&HMB_FastIO_n_waited);
#if 0
		atomic64_set(&HMB_FastIO_pid_waited, current->pid);
		atomic64_set(&HMB_FastIO_cpu_waited, cur_cpu);
#endif

#if 0
		if(atomic64_read(&HMB_FastIO_pid_waited) != atomic64_read(&HMB_FastIO_pid_locked))
		{
			hmb_debug("<DIFF-PID> waited: CPU %lu: %s (%d)", cur_cpu, current->comm, current->pid);
			hmb_debug("<DIFF-PID> locked: CPU %ld: %s (%d)\n", atomic64_read(&HMB_FastIO_cpu_locked), t_locked->comm, t_locked->pid);
		}

		if(atomic64_read(&HMB_FastIO_cpu_waited) != atomic64_read(&HMB_FastIO_cpu_locked))
		{
			hmb_debug("<DIFF-CPU> waited: CPU %lu: %s (%d)", cur_cpu, current->comm, current->pid);
			hmb_debug("<DIFF-CPU> locked: CPU %ld: %s (%d)\n", atomic64_read(&HMB_FastIO_cpu_locked), t_locked->comm, t_locked->pid);
		}
#endif
		wait_for_completion(&HMB_CTRL.lock_local_completion);
	}
	atomic64_inc(&HMB_FastIO_n_locked);
#if 0
	atomic64_set(&HMB_FastIO_pid_locked, current->pid);
	atomic64_set(&HMB_FastIO_cpu_locked, smp_processor_id());
#endif
}
EXPORT_SYMBOL(hmb_lock_local);

void hmb_unlock_local()
{
#if 0
	atomic_t *lock;

	lock = &HMB_CTRL.lock_local;

	atomic_dec(lock);

	local_irq_restore(HMB_flags);
	preempt_enable();
#endif
	spin_unlock(&HMB_CTRL.lock_local);
	complete(&HMB_CTRL.lock_local_completion);
}
EXPORT_SYMBOL(hmb_unlock_local);

bool hmb_lock_try_local()
{
#if 0
	atomic_t *lock;

	lock = &HMB_CTRL.lock_local;

	smp_mb__before_atomic();
	if(atomic_cmpxchg(lock, 0, 1) != 0)
	{
		return false;
	}

	smp_mb__after_atomic();
	return true;
#endif
	return false;
}
EXPORT_SYMBOL(hmb_lock_try_local);

void hmb_meta_update(void)
{
	HmbMeta *meta = HMB_CTRL.hmb_header;
	uint64_t i;
	void *addr;

	if(unlikely(HMB_CTRL.hmb_enabled == false || meta == NULL))
	{
		hmb_debug("Kernel-side HMB module has some problems.");

		HMB_CTRL.hmb_enabled = false;
		HMB_CTRL.fastIO_enabled = false;
		HMB_CTRL.fwb_enabled = false;

		return;
	}

	if(meta->C__table_ST_seg_id < 0)
	{
		hmb_debug("Metadata for FWB was not initialized by the SSD. (%d)", \
				meta->C__table_ST_seg_id);

		HMB_CTRL.fwb_enabled = false;
	}
	else
	{
		hmb_debug("Metadata for FWB was normally initialized by the SSD.");

		HMB_CTRL.fwb_enabled = true;

		/* Update #maximum cache entries */
		HMB_CTRL.table_cnt_max = meta->C__n_max_entries;

		HMB_CTRL.heads_cnt_max = meta->C__heads_cnt_max;
		/* Update hash bit */
		HMB_CTRL.heads_hash_bit = meta->C__heads_hash_bit;

		HMB_CTRL.table_split_num  = meta->C__table_ST_num;
		HMB_CTRL.table_split_unit = meta->C__table_ST_unit;

		HMB_CTRL.heads_split_num  = meta->C__heads_ST_num;
		HMB_CTRL.heads_split_unit = meta->C__heads_ST_unit;

		HMB_CTRL.sorted_split_num  = meta->C__sorted_ST_num;
		HMB_CTRL.sorted_split_unit = meta->C__sorted_ST_unit;

		addr = HMB_CTRL.hmb_addr[meta->C__table_ST_seg_id] \
			   + meta->C__table_ST_offset;
		HMB_CTRL.table_ST = (HmbSplitTable *)addr;
		hmb_debug("#### table_ST in %d.%u ###", \
				meta->C__table_ST_seg_id, \
				meta->C__table_ST_offset);
		for(i=0; i<HMB_CTRL.table_split_num; i++)
		{
			hmb_debug("  - [%3lu] SID: %3d, OFFSET: %u", i, \
					HMB_CTRL.table_ST[i].seg_id, \
					HMB_CTRL.table_ST[i].offset);
		}

		addr = HMB_CTRL.hmb_addr[meta->C__table_bm_ST_seg_id] \
			   + meta->C__table_bm_ST_offset;
		HMB_CTRL.table_bm_ST = (HmbSplitTable *)addr;
		hmb_debug("#### table_bm_ST in %d.%u ###", \
				meta->C__table_bm_ST_seg_id, \
				meta->C__table_bm_ST_offset);
		for(i=0; i<HMB_CTRL.table_split_num; i++)
		{
			hmb_debug("  - [%3lu] SID: %3d, OFFSET: %u", i, \
					HMB_CTRL.table_bm_ST[i].seg_id, \
					HMB_CTRL.table_bm_ST[i].offset);
		}

		addr = HMB_CTRL.hmb_addr[meta->C__heads_ST_seg_id] \
			   + meta->C__heads_ST_offset;
		HMB_CTRL.heads_ST = (HmbSplitTable *)addr;
		hmb_debug("### heads_ST in %d.%u ###", \
				meta->C__heads_ST_seg_id, \
				meta->C__heads_ST_offset);
		for(i=0; i<HMB_CTRL.heads_split_num; i++)
		{
			hmb_debug("  - [%3lu] SID: %3d, OFFSET: %u", i, \
					HMB_CTRL.heads_ST[i].seg_id, \
					HMB_CTRL.heads_ST[i].offset);
		}

		addr = HMB_CTRL.hmb_addr[meta->C__sorted_ST_seg_id] \
			   + meta->C__sorted_ST_offset;
		HMB_CTRL.sorted_ST = (HmbSplitTable *)addr;
		hmb_debug("### sorted_ST in %d.%u ###", \
				meta->C__sorted_ST_seg_id, \
				meta->C__sorted_ST_offset);
		for(i=0; i<HMB_CTRL.sorted_split_num; i++)
		{
			hmb_debug("  - [%3lu] SID: %3d, OFFSET: %u", i, \
					HMB_CTRL.sorted_ST[i].seg_id, \
					HMB_CTRL.sorted_ST[i].offset);
		}

		addr = HMB_CTRL.hmb_addr[meta->C__urgency_seg_id] \
			   + meta->C__urgency_offset;
		HMB_CTRL.urgency = (int32_t *)addr;

		addr = HMB_CTRL.hmb_addr[meta->C__victimAll_seg_id] \
			   + meta->C__victimAll_offset;
		HMB_CTRL.victimAll = (int32_t *)addr;

		addr = HMB_CTRL.hmb_addr[meta->C__victimRc_seg_id] \
			   + meta->C__victimRc_offset;
		HMB_CTRL.victimRc = (int32_t *)addr;

		addr = HMB_CTRL.hmb_addr[meta->C__bm_seg_id] \
			   + meta->C__bm_offset;
		HMB_CTRL.bm = (int32_t *)addr;

		addr = HMB_CTRL.hmb_addr[meta->C__bm_empty_seg_id] \
			   + meta->C__bm_empty_offset;
		HMB_CTRL.bm_empty = (int32_t *)addr;

		HMB_CTRL.bm_parts_cnt = meta->C__bm_parts_cnt;

		addr = HMB_CTRL.hmb_addr[meta->C__bm_empty_table_seg_id] \
			   + meta->C__bm_empty_table_offset;
		HMB_CTRL.bm_empty_table = (HmbDLL *)addr;

		/* HMB: to support flexible HMB cache size */
		HMB_CTRL.cache_unit_bits = meta->C__cache_unit_bits; 
		HMB_CTRL.cache_unit = 1 << meta->C__cache_unit_bits; 

		hmb_debug("### HMB cache size: %lubytes (--> %u bits)", \
				HMB_CTRL.cache_unit, HMB_CTRL.cache_unit_bits);
	}

	if(meta->FASTIO__meta_seg_id < 0 || \
			meta->FASTIO__data_ST_seg_id < 0 || \
			meta->FASTIO__data_ST_unit == 0 || \
			meta->FASTIO__data_ST_num == 0)
	{
		hmb_debug("Metadata for Fast I/O was not initialized by the SSD. (%d, %d)", \
				meta->FASTIO__meta_seg_id, meta->FASTIO__data_ST_seg_id);

		HMB_CTRL.fastIO_enabled = false;
	}
	else
	{
		uint64_t i;

		hmb_debug("Metadata for Fast I/O was normally initialized by the SSD.");

		HMB_CTRL.fastIO_enabled = true;

		spin_lock_init(&HMB_CTRL.lock_local);
		init_completion(&HMB_CTRL.lock_local_completion);

		addr = HMB_CTRL.hmb_addr[meta->FASTIO__data_ST_seg_id] \
			   + meta->FASTIO__data_ST_offset;
		HMB_CTRL.fastIO_data_ST = addr;
		HMB_CTRL.fastIO_data_ST_unit = meta->FASTIO__data_ST_unit;
		HMB_CTRL.fastIO_data_ST_num = meta->FASTIO__data_ST_num;
		HMB_CTRL.fastIO_data_max_size = meta->FASTIO__data_max_bytes;

		addr = HMB_CTRL.hmb_addr[meta->FASTIO__meta_seg_id] \
			   + meta->FASTIO__meta_offset;
		HMB_CTRL.fastIO_meta = (HmbFastIOMeta *)addr;

		hmb_debug("#### Information realted to Fast I/O ####");
		hmb_debug("  - Unit of the split table for data region   : %u", HMB_CTRL.fastIO_data_ST_unit);
		hmb_debug("  - Number of the split table for data region : %u", HMB_CTRL.fastIO_data_ST_num);
		hmb_debug("  - Maximum size of the data region           : %lu", HMB_CTRL.fastIO_data_max_size);

		hmb_debug("  - Mapped information for the Fast I/O data:");
		for(i=0; i<HMB_CTRL.fastIO_data_ST_num; i++)
		{
			hmb_debug("    --> [%3lu] seg: %3d, offset: 0x%X", i, \
					HMB_CTRL.fastIO_data_ST[i].seg_id, \
					HMB_CTRL.fastIO_data_ST[i].offset);
		}
		return;
	}
#if 0
	hmb_debug("### Host's internal memory addresses ###");
	for(i=0; i<HMB_CTRL.hmb_cnt; i++)
	{
		hmb_debug("  - HMB #%2lu: 0x%llX", i+1, HMB_CTRL.hmb_addr[i]);
	}
#endif
}
EXPORT_SYMBOL(hmb_meta_update);

u32 hmb_hash(u64 value, u8 bits)
{
	return (u32)((value * HMB_HASH_MULTIPLIER_64) >> (64 - bits));
}
EXPORT_SYMBOL(hmb_hash);

bool hmb_valid_hash_val(uint32_t hashed)
{
	return (hashed < HMB_CTRL.heads_cnt_max);
}
EXPORT_SYMBOL(hmb_valid_hash_val);

bool hmb_valid_heads_idx(int32_t idx)
{
	return (idx >= 0 && idx < HMB_CTRL.table_cnt_max);
}
EXPORT_SYMBOL(hmb_valid_heads_idx);

bool hmb_valid_table_idx(uint32_t idx)
{
	return (idx < HMB_CTRL.table_cnt_max);
}
EXPORT_SYMBOL(hmb_valid_table_idx);

bool hmb_RC_valid_entry(HmbSharedEnt *e, uint64_t lpn, uint32_t idx_internal)
{
#if 0
	return (e->lpn == lpn && \
			e->usable == 1 && \
			hmb_table_bm_isCached_partially(e->e_own, idx_internal));
#endif
	return (e->lpn == lpn && \
			hmb_table_bm_isCached_partially(e->e_own, idx_internal));
}
EXPORT_SYMBOL(hmb_RC_valid_entry);

void hmb_endio(struct bio **hit_bio, uint32_t hit_cnt, struct bio **miss_bio, uint32_t miss_cnt, \
		       struct bio *last, bool is_last_hit, bool is_for_RC)
{
	uint32_t i;

	hmb_chain_multiple(miss_bio, miss_cnt, last);
	hmb_chain_multiple(hit_bio, hit_cnt, last);

	if(is_for_RC == false)
	{
		for(i=0; i<miss_cnt; i++)
		{
			if(!is_for_RC)
			{
				atomic64_add(bio_sectors(miss_bio[i]), &HMB_CTRL.n_sectors_buffered);
			}
			bio_endio(miss_bio[i]);
		}
	}

	for(i=0; i<hit_cnt; i++) 
	{    
		if(!is_for_RC)
		{
			atomic64_add(bio_sectors(hit_bio[i]), &HMB_CTRL.n_sectors_buffered);
		}
		else
		{
			atomic64_add(bio_sectors(hit_bio[i]), &HMB_CTRL.n_sectors_hit);
		}
		bio_endio(hit_bio[i]);
	}    

	if(is_last_hit)
	{    
		if(!is_for_RC)
		{
			atomic64_add(bio_sectors(last), &HMB_CTRL.n_sectors_buffered);
		}
		else
		{
			atomic64_add(bio_sectors(last), &HMB_CTRL.n_sectors_hit);
		}
		bio_endio(last);
	}    
}
EXPORT_SYMBOL(hmb_endio);

bool hmb_generic_make_request(struct bio **bios, uint32_t cnt)
{
	uint32_t i;

	for(i=0; i<cnt; i++) 
	{    
		generic_make_request(bios[i]);
	}    

	return true;
}
EXPORT_SYMBOL(hmb_generic_make_request);

void hmb_chain_multiple(struct bio **bios, uint32_t cnt, struct bio *parent)
{
	uint32_t i;

	for(i=0; i<cnt; i++)
	{
		bio_chain(bios[i], parent);
	}
}
EXPORT_SYMBOL(hmb_chain_multiple);

/**
  [1] Is one of the sectors in bio cached in HMB?
  - If "yes",
  -> Return relative first location and last location
  -> i.e. argument 'sector_first" and 'sector_last'
 **/
bool hmb_RC_is_cachable(struct bio *b, u64 *sector_first, u64 *sector_last)
{
	sector_t sector_idx;
	u64 sector_num;

	u64 i;
	bool is_first;
	HmbSharedEnt *cache;

	sector_num = bio_sectors(b);
	sector_idx = b->bi_iter.bi_sector;

	*sector_first = 0;
	*sector_last = 0;
	is_first = true;

	for(i=0; i<sector_num; i++)
	{
		sector_t sector_idx_cur = sector_idx + i;
		uint64_t lpn_new = hmb_sector_to_lpn(sector_idx_cur);
		uint32_t idx_internal = hmb_sector_to_internal_idx(sector_idx_cur);
		uint32_t hashed;
		HmbHeads idx_heads;

		HmbSharedEnt *loop, *head;

		/* [2] Step 1. Hashing to get head's index */
		hashed = hmb_hash(lpn_new, HMB_CTRL.heads_hash_bit);
		/* [2] */

		/* [2] Step 2. Get an index of the 'heads' */
		idx_heads = *hmb_heads_get_by_idx(hashed);
		if(idx_heads == HMB_HAS_NO_ENTRY)
		{
			if(is_first == false)
			{
				*sector_last = i-1;
				return true;
			}

			continue;
		}
		/* [2] */

		cache = NULL;

		/* [2] Step 3-1. Get head entry of the LRU list for the "lpn_new" */
		head = hmb_table_get_by_idx(idx_heads);
		if(hmb_RC_valid_entry(head, lpn_new, idx_internal) == true)
		{
			cache = head;
		}
		/* [2] */
		/* [2] Step 3-2. Check: Has LRU list for the "lpn_new" cached entry? */
		else
		{
			for(loop = hmb_table_get_by_idx(head->e_next); \
					loop != head; \
					loop = hmb_table_get_by_idx(loop->e_next))
			{
				if(hmb_RC_valid_entry(loop, lpn_new, idx_internal) == true)
				{
					cache = loop;
					break;
				}
			} /* for(loop = &HMB_CTRL.table[head->e_next]; ... */
		}  /* else of "hmb_RC_valid_entry(head, lpn_new)" */
		/* [2] */

		/* [2] If the LRU list has valid cache entry */
		if(cache != NULL)
		{
			if(is_first == true)
			{
				*sector_first = i;
				is_first = false;
			}
		}
		/* [2] */

		/* if(cache == NULL) */
		else
		{
			if(is_first == false)
			{
				*sector_last = i-1;
				return true;
			}
		}
	} /* for(i=0; i<sector_num; i++) */

	if(is_first == false)
	{
		*sector_last = i-1;
		return true;
	}

	return false;
}
EXPORT_SYMBOL(hmb_RC_is_cachable);

/** [1] **/

bool hmb_RC_copy_from_HMB(struct bio *b)
{
	sector_t sector_idx;
	u64 sector_num;

	u64 i;
	unsigned short bio_v_idx;
	u32 remainder_hmb, remainder_bio_v_cur;
	u32 written_hmb, written_bio_v_cur;
	void *bio_v_cur_mapped = NULL;
	struct bio_vec *bio_v, *bio_v_cur;

	sector_num = bio_sectors(b);
	sector_idx = b->bi_iter.bi_sector;

	bio_v = b->bi_io_vec;
	bio_v_idx = b->bi_iter.bi_idx;
	bio_v_cur = &bio_v[bio_v_idx];
	written_bio_v_cur = b->bi_iter.bi_bvec_done;
	remainder_bio_v_cur = bio_v_cur->bv_len - written_bio_v_cur;
	
	//if(unlikely((bio_v_cur_mapped = (u8 *)kmap(bio_v_cur->bv_page)) == NULL))
	if(unlikely((bio_v_cur_mapped = page_address(bio_v_cur->bv_page)) == NULL))
	{
		hmb_debug("Failed to get mapped virtual memory address of a page included in the bio.");
		return false;
	}

	for(i=0; i<sector_num; i++)
	{
		HmbSharedEnt *meta;
		HmbSharedEnt *loop, *head;
		uint32_t hashed;
		HmbHeads idx_heads;

		sector_t sector_idx_cur = sector_idx + i;
		uint64_t lpn_new = hmb_sector_to_lpn(sector_idx_cur);
		uint32_t idx_internal = hmb_sector_to_internal_idx(sector_idx_cur);

		/* [1] Hashing and verifying */
		hashed = hmb_hash(lpn_new, HMB_CTRL.heads_hash_bit);
		/* [1] */

#ifdef HMB_DEBUG_CLOSELY
		if(unlikely((idx_heads = (*hmb_heads_get_by_idx(hashed))) == HMB_HAS_NO_ENTRY))
		{
			hmb_debug("One of the 'heads' does not have entry.");
			return false;
		}
#endif
		idx_heads = *hmb_heads_get_by_idx(hashed);

		/*
		   If an entry for the 'lpn_new' exists,
		   - meta is filled by pointer for an entry of "HMB_CTRL.table"
		 */
		meta = NULL;

		/* [1] when head of the lru list is a target entry */
		head = hmb_table_get_by_idx(idx_heads);
		if(hmb_RC_valid_entry(head, lpn_new, idx_internal) == true)
		{
			meta = head;
		}
		/* [1] */

		else
		{
			for(loop = hmb_table_get_by_idx(head->e_next); \
					loop != head; \
					loop = hmb_table_get_by_idx(loop->e_next))
			{
				/* [1] when an entry of the lru list is a target entry */
				if(hmb_RC_valid_entry(loop, lpn_new, idx_internal) == true)
				{
					meta = loop;
					break;
				}
				/* [1] */
			}
		} /* else of "if(hmb_RC_valid_entry(loop, lpn_new))" */

#if 0
		hmb_debug("<DBG> SECTOR: 0x%08lX, LBA: 0x%08lX, BM: 0x%08X, ID_OWN: %6u, ID_INTER: %1u, <<9: %4u, CACHED: %1d, U: %lu, D: %lu", \
				sector_idx, lpn_new, hmb_table_bm_get_by_idx(meta->e_own)->filled, meta->e_own, \
				idx_internal, idx_internal << 9, \
				hmb_table_bm_isCached_partially(meta->e_own, idx_internal), \
				meta->usable, meta->dirty);
#endif

		/* Update LRU list */
		if(unlikely(hmb_RC_reorder(meta->e_own) == false))
		{
			hmb_debug("Failed to reorder");
			return false;
		}

		remainder_hmb = 512;
		written_hmb = 0;
		do
		{
			void *dst, *src;

			dst = bio_v_cur_mapped + bio_v_cur->bv_offset + written_bio_v_cur;
			src = HMB_CTRL.hmb_addr[meta->segment] + \
				  meta->offset + (idx_internal << 9) + \
				  written_hmb;

			if(remainder_hmb < remainder_bio_v_cur) /* When BIO VECTOR has spare space */
			{
				memcpy(dst, src, remainder_hmb);

				/* Update BIO VECTOR related parts */
				remainder_bio_v_cur -= remainder_hmb;
				written_bio_v_cur += remainder_hmb;

				/* Update HMB related parts */
				break;
			} /* if(remainder_hmb < remainder_bio_v_cur) */

			/* if (remainder_hmb >= remainder_bio_v_cur) */
			else
			{
				memcpy(dst, src, remainder_bio_v_cur);

				/* Update HMB related parts */
				remainder_hmb -= remainder_bio_v_cur;
				written_hmb += remainder_bio_v_cur;

				/* Update BIO VECTOR related parts */
				//kunmap(bio_v_cur->bv_page);

				if(i != sector_num - 1)
				{
					++bio_v_idx;
					bio_v_cur = &bio_v[bio_v_idx];
					remainder_bio_v_cur = bio_v_cur->bv_len;
					written_bio_v_cur = 0;

					//if(unlikely((bio_v_cur_mapped = (u8 *)kmap(bio_v_cur->bv_page)) == NULL))
					if(unlikely((bio_v_cur_mapped = page_address(bio_v_cur->bv_page)) == NULL))
					{
						hmb_debug("Failed to get mapped virtual memory address of a page included in the bio.");
						return false;
					}
				}
			} /* else of "if(remainder_hmb <= remainder_bio_v_cur)" */
		} while(remainder_hmb > 0);
	}

	return true;
}
EXPORT_SYMBOL(hmb_RC_copy_from_HMB);

HmbSharedEnt *hmb_table_get_by_idx(uint32_t idx)
{
#if 0
	HmbSplitTable *st;
	void *addr;

	uint64_t dividend;
	uint32_t divisor, remainder;

	dividend = idx;
	divisor = HMB_CTRL.table_split_unit;
	remainder = do_div(dividend, divisor);

	st = hmb_table_ST_get_by_idx((uint32_t)dividend);
	addr = HMB_CTRL.hmb_addr[st->seg_id] + st->offset;

	return &(((HmbSharedEnt *)addr)[remainder]);
#endif
	HmbSplitTable *st;
	void *addr;
	uint32_t seg, offset;

	seg = idx / HMB_CTRL.table_split_unit;
	offset = idx % HMB_CTRL.table_split_unit;

	st = hmb_table_ST_get_by_idx(seg);
	addr = HMB_CTRL.hmb_addr[st->seg_id] + st->offset;

	return &(((HmbSharedEnt *)addr)[offset]);
}
EXPORT_SYMBOL(hmb_table_get_by_idx);

HmbSplitTable* hmb_table_ST_get_by_idx(uint32_t idx)
{
	return &(HMB_CTRL.table_ST[idx]);
}
EXPORT_SYMBOL(hmb_table_ST_get_by_idx);

HmbSplitTable *hmb_table_bm_ST_get_by_idx(uint32_t idx) 
{
	return &(HMB_CTRL.table_bm_ST[idx]);
}
EXPORT_SYMBOL(hmb_table_bm_ST_get_by_idx);

HmbSharedBitmapEnt *hmb_table_bm_get_by_idx(uint32_t idx) 
{
#if 0
	HmbSplitTable *st;
	void *addr;

	uint64_t dividend;
	uint32_t divisor, remainder;

	dividend = idx;
	divisor = HMB_CTRL.table_split_unit;
	remainder = do_div(dividend, divisor);

	st = hmb_table_bm_ST_get_by_idx((uint32_t)dividend);
	addr = HMB_CTRL.hmb_addr[st->seg_id] + st->offset;

	return &(((HmbSharedBitmapEnt *)addr)[remainder]);
#endif
	HmbSplitTable *st;
	void *addr;

	uint32_t seg, offset;

	seg = idx / HMB_CTRL.table_split_unit;
	offset = idx % HMB_CTRL.table_split_unit;

	st = hmb_table_bm_ST_get_by_idx(seg);
	addr = HMB_CTRL.hmb_addr[st->seg_id] + st->offset;

	return &(((HmbSharedBitmapEnt *)addr)[offset]);

}
EXPORT_SYMBOL(hmb_table_bm_get_by_idx);

bool hmb_table_bm_isCached_fully(uint32_t idx) 
{
	HmbBitmap32 *bm = &(hmb_table_bm_get_by_idx(idx)->filled);

	return (*bm == HMB_BITMAP_PART_MAX_VALUE);
}
EXPORT_SYMBOL(hmb_table_bm_isCached_fully);

bool hmb_table_bm_isCached_partially(uint32_t idx, uint32_t idx_internal)
{
	HmbBitmap32 *bm = &(hmb_table_bm_get_by_idx(idx)->filled);

	return (*bm & (1 << idx_internal));
}
EXPORT_SYMBOL(hmb_table_bm_isCached_partially);

bool hmb_table_bm_set(bool enable, uint32_t idx, uint32_t idx_internal)
{
	HmbBitmap32 *bm = &(hmb_table_bm_get_by_idx(idx)->filled);

#ifdef HMB_DEBUG_CLOSELY
	if(unlikely(enable && (*bm & (1 << idx_internal))))
	{
		hmb_debug("Already filled! (idx: %u, idx_internal: %u)", idx, idx_internal);
		return false;
	}

	if(unlikely(!enable && !(*bm & (1 << idx_internal))))
	{
		hmb_debug("Already empty! (idx: %u, idx_internal: %u)", idx, idx_internal);
		return false;
	}
#endif

	if(enable)
	{
		*bm |= (1 << idx_internal);
	}

	else
	{
		*bm &= ~(1 << idx_internal);
	}

	return true;
}
EXPORT_SYMBOL(hmb_table_bm_set);

bool hmb_table_bm_set_fully(bool enable, uint32_t idx)
{
	HmbBitmap32 *bm = &(hmb_table_bm_get_by_idx(idx)->filled);

	if(enable)
	{
		*bm = HMB_BITMAP_PART_MAX_VALUE;
	}

	else
	{
		uint32_t i;

		*bm = 0;

		/* Fill unused parts */
		for(i=(1 << (HMB_CTRL.cache_unit_bits - 9)); \
				i<HMB_BITMAP_BITS_PER_PART; i++)
		{
			hmb_table_bm_set(true, idx, i);
		}
	}

	return true;
}
EXPORT_SYMBOL(hmb_table_bm_set_fully);

HmbSortedEnt *hmb_sorted_get_by_idx(uint32_t idx)
{
#if 0
	HmbSplitTable *st;
	void *addr;

	uint64_t dividend;
	uint32_t divisor, remainder;

	dividend = idx;
	divisor = HMB_CTRL.sorted_split_unit;
	remainder = do_div(dividend, divisor);

	st = hmb_sorted_ST_get_by_idx((uint32_t)dividend);
	addr = HMB_CTRL.hmb_addr[st->seg_id] + st->offset;

	return &(((HmbSortedEnt *)addr)[remainder]);
#endif
	HmbSplitTable *st;
	void *addr;
	uint32_t seg, offset;

	seg = idx / HMB_CTRL.sorted_split_unit;
	offset = idx % HMB_CTRL.sorted_split_unit;

	st = hmb_sorted_ST_get_by_idx(seg);
	addr = HMB_CTRL.hmb_addr[st->seg_id] + st->offset;

	return &(((HmbSortedEnt *)addr)[offset]);
}
EXPORT_SYMBOL(hmb_sorted_get_by_idx);

HmbSplitTable* hmb_sorted_ST_get_by_idx (uint32_t idx)
{
	return &(HMB_CTRL.sorted_ST[idx]);
}
EXPORT_SYMBOL(hmb_sorted_ST_get_by_idx);

HmbHeads *hmb_heads_get_by_idx(uint32_t idx)
{
#if 0
	HmbSplitTable *st;
	void *addr;

	uint64_t dividend;
	uint32_t divisor, remainder;

	dividend = idx;
	divisor = HMB_CTRL.heads_split_unit;
	remainder = do_div(dividend, divisor);

	st = hmb_heads_ST_get_by_idx((uint32_t)dividend);
	addr = HMB_CTRL.hmb_addr[st->seg_id] + st->offset;

	return &(((HmbHeads *)addr)[remainder]);
#endif
	HmbSplitTable *st;
	uint32_t seg, offset;
	void *addr;

	seg = idx / HMB_CTRL.heads_split_unit;
	offset = idx % HMB_CTRL.heads_split_unit;

	st = hmb_heads_ST_get_by_idx(seg);
	addr = HMB_CTRL.hmb_addr[st->seg_id] + st->offset;

	return &(((HmbHeads *)addr)[offset]);
}
EXPORT_SYMBOL(hmb_heads_get_by_idx);

HmbSplitTable* hmb_heads_ST_get_by_idx(uint32_t idx)
{
	return &(HMB_CTRL.heads_ST[idx]);
}
EXPORT_SYMBOL(hmb_heads_ST_get_by_idx);

int32_t hmb_WB_sorted_get_head(int32_t urgency)
{
	return HMB_CTRL.urgency[urgency-1];
}
EXPORT_SYMBOL(hmb_WB_sorted_get_head);

int32_t *hmb_victimAll_get(void)
{
	return HMB_CTRL.victimAll;
}
EXPORT_SYMBOL(hmb_victimAll_get);

int32_t *hmb_victimRc_get(void)
{
	return HMB_CTRL.victimRc;
}
EXPORT_SYMBOL(hmb_victimRc_get);

int32_t hmb_RC_sorted_get_head_idx(void)
{
	return *(HMB_CTRL.victimAll);
}
EXPORT_SYMBOL(hmb_RC_sorted_get_head_idx);

bool hmb_RC_sorted_set_head(uint32_t idx)
{
	int32_t ret; 

	ret = hmb_RC_sorted_get_head_idx();
	if(ret == HMB_HAS_NO_ENTRY)
	{    
		HmbSortedEnt *entry = hmb_sorted_get_by_idx(idx);

		entry->e_own  = idx; 
		entry->e_next = idx; 
		entry->e_prev = idx; 
	}    

	*(hmb_victimAll_get()) = idx; 

	return true;
}
EXPORT_SYMBOL(hmb_RC_sorted_set_head);

bool hmb_RC_sorted_insert_tail(uint32_t idx)
{
	HmbSortedEnt *entry, *head, *tail;
	int32_t idx_head, idx_tail;

	idx_head = hmb_RC_sorted_get_head_idx();
	if(idx_head == HMB_HAS_NO_ENTRY)
	{    
		return hmb_RC_sorted_set_head(idx);
	}    

	head = hmb_sorted_get_by_idx(idx_head);
	idx_tail = head->e_prev;
	tail = hmb_sorted_get_by_idx(idx_tail);
	entry = hmb_sorted_get_by_idx(idx);

	/* [1] Set the 'entry' to most recently used entry */
	tail->e_next = idx;
	head->e_prev = idx;

	entry->e_next = idx_head;
	entry->e_prev = idx_tail;

	return true;

}
EXPORT_SYMBOL(hmb_RC_sorted_insert_tail);

bool hmb_RC_sorted_delete(uint32_t idx)
{
	HmbSortedEnt *entry, *prev, *next;
	uint32_t idx_prev, idx_next;

	entry = hmb_sorted_get_by_idx(idx);
	idx_next = entry->e_next; /* get index of the next entry of the 'entry' */
	idx_prev = entry->e_prev; /* get index of the previous entry of the 'entry' */

	prev = hmb_sorted_get_by_idx(idx_prev);
	next = hmb_sorted_get_by_idx(idx_next);

	prev->e_next = idx_next;
	next->e_prev = idx_prev;

	if(idx_next == idx)
	{
		*hmb_victimAll_get() = HMB_HAS_NO_ENTRY;
	}

	else if(hmb_RC_sorted_get_head_idx() == idx)
	{
		return hmb_RC_sorted_set_head(idx_next);
	}

	return true;
}
EXPORT_SYMBOL(hmb_RC_sorted_delete);

int32_t hmb_RCOnly_sorted_get_head_idx(void)
{
	return *(HMB_CTRL.victimRc);
}
EXPORT_SYMBOL(hmb_RCOnly_sorted_get_head_idx);

bool hmb_RCOnly_sorted_set_head(uint32_t idx)
{
	int32_t ret; 

	ret = hmb_RCOnly_sorted_get_head_idx();
	if(ret == HMB_HAS_NO_ENTRY)
	{    
		HmbSortedEnt *entry = hmb_sorted_get_by_idx(idx);

		entry->e_own  = idx; 
		entry->r_e_next = idx; 
		entry->r_e_prev = idx; 
	}    

	*(hmb_victimRc_get()) = idx; 

	return true;
}
EXPORT_SYMBOL(hmb_RCOnly_sorted_set_head);

bool hmb_RCOnly_sorted_insert_tail(uint32_t idx)
{
	HmbSortedEnt *entry, *head, *tail;
	int32_t idx_head, idx_tail;

	idx_head = hmb_RCOnly_sorted_get_head_idx();
	if(idx_head == HMB_HAS_NO_ENTRY)
	{    
		return hmb_RCOnly_sorted_set_head(idx);
	}    

	head = hmb_sorted_get_by_idx(idx_head);
	idx_tail = head->r_e_prev;
	tail = hmb_sorted_get_by_idx(idx_tail);
	entry = hmb_sorted_get_by_idx(idx);

	/* [1] Set the 'entry' to most recently used entry */
	tail->r_e_next = idx;
	head->r_e_prev = idx;

	entry->r_e_next = idx_head;
	entry->r_e_prev = idx_tail;

	return true;

}
EXPORT_SYMBOL(hmb_RCOnly_sorted_insert_tail);

bool hmb_RCOnly_sorted_delete(uint32_t idx)
{
	HmbSortedEnt *entry, *prev, *next;
	uint32_t idx_prev, idx_next;

	entry = hmb_sorted_get_by_idx(idx);
	idx_next = entry->r_e_next; /* get index of the next entry of the 'entry' */
	idx_prev = entry->r_e_prev; /* get index of the previous entry of the 'entry' */

	prev = hmb_sorted_get_by_idx(idx_prev);
	next = hmb_sorted_get_by_idx(idx_next);

	prev->r_e_next = idx_next;
	next->r_e_prev = idx_prev;

	if(idx_next == idx)
	{
		*hmb_victimRc_get() = HMB_HAS_NO_ENTRY;
	}

	else if(hmb_RCOnly_sorted_get_head_idx() == idx)
	{
		return hmb_RCOnly_sorted_set_head(idx_next);
	}

	return true;
}
EXPORT_SYMBOL(hmb_RCOnly_sorted_delete);

bool hmb_RC_reorder(uint32_t idx)
{
	if(unlikely(hmb_RC_sorted_delete(idx) == false))
	{
		hmb_debug("Failed to delete entry.");
		return false;
	}

	if(unlikely(hmb_RC_sorted_insert_tail(idx) == false))
	{
		hmb_debug("Failed to re-insert for reordering.");
		return false;
	}

	if(hmb_shared_get_by_idx(idx)->dirty == 0)
	{
		if(unlikely(hmb_RCOnly_sorted_delete(idx) == false))
		{
			hmb_debug("Failed to delete RC entry.");
			return false;
		}

		if(unlikely(hmb_RCOnly_sorted_insert_tail(idx) == false))
		{
			hmb_debug("Failed to re-insert for reordering.");
			return false;
		}
	}

	return true;
}
EXPORT_SYMBOL(hmb_RC_reorder);

bool hmb_RC_evict(uint32_t n_evict)
{
	uint32_t i;

	for(i=0; i<n_evict; i++)
	{
		int32_t ret;
		uint32_t idx_sorted_head;

		ret = hmb_RCOnly_sorted_get_head_idx();
		if(ret == HMB_HAS_NO_ENTRY)
		{
			if(i == 0)
			{
				return false;
			}
			return true;
		}

		idx_sorted_head = (uint32_t)ret;
		hmb_shared_set_enable(false, idx_sorted_head);

		/* Step 3. Remove the entry from its heads */
		if(unlikely(hmb_RC_sorted_delete(idx_sorted_head) == false))
		{
			hmb_debug("Invalid relationship.");
			return false;
		}

		if(unlikely(hmb_RCOnly_sorted_delete(idx_sorted_head) == false))
		{
			hmb_debug("Invalid relationship.");
			return false;
		}

		if(unlikely(hmb_shared_delete(idx_sorted_head) == false))
		{
			hmb_debug("Failed to remove entry.");
			return false;
		}
	}
	return true;
}
EXPORT_SYMBOL(hmb_RC_evict);

bool hmb_WB_sorted_set_head(int32_t urgency, uint32_t idx)
{
	int32_t idx_head; 

#ifdef HMB_DEBUG_CLOSELY
	if(unlikely(!(urgency >= HMB_UL_URGENT && urgency <= HMB_UL_LOW)))
	{    
		hmb_debug("Out of range (urgency: %d)", urgency);
		return false;
	}    
#endif

	idx_head = hmb_WB_sorted_get_head(urgency);
	if(idx_head == HMB_HAS_NO_ENTRY)
	{    
		HmbSortedEnt *entry;

		entry = hmb_sorted_get_by_idx(idx);

		entry->w_e_next = idx; 
		entry->w_e_prev = idx; 
	}    

	HMB_CTRL.urgency[urgency-1] = idx;

	return true;
}
EXPORT_SYMBOL(hmb_WB_sorted_set_head);

bool hmb_WB_sorted_insert_tail(int32_t urgency, uint32_t idx)
{
	HmbSortedEnt *entry, *head, *tail;
	int32_t idx_tail, idx_head;

#ifdef HMB_DEBUG_CLOSELY
	if(unlikely(!(urgency >= HMB_UL_URGENT && urgency <= HMB_UL_LOW)))
	{
		hmb_debug("Out of range (urgency: %d)", urgency);
		return false;
	}
	if(hmb_shared_get_by_idx(idx)->dirty == 0)
	{
		hmb_debug("Invalid relationship: Why it is not dirty?");
		return false;
	}
#endif

	idx_head = hmb_WB_sorted_get_head(urgency);
	if(idx_head == HMB_HAS_NO_ENTRY)
	{
		return hmb_WB_sorted_set_head(urgency, idx);
	}

	head = hmb_sorted_get_by_idx(idx_head);
	idx_tail = head->w_e_prev;
	tail = hmb_sorted_get_by_idx(idx_tail);

	entry = hmb_sorted_get_by_idx(idx);

	/* [1] Set the 'entry' to most recently used entry */
	tail->w_e_next = idx;
	head->w_e_prev = idx;

	entry->w_e_next = idx_head;
	entry->w_e_prev = idx_tail;

	return true;
}
EXPORT_SYMBOL(hmb_WB_sorted_insert_tail);

bool hmb_WB_sorted_delete(int32_t urgency, uint32_t idx)
{
	HmbSortedEnt *entry, *prev, *next;
	int32_t idx_prev, idx_next;

#ifdef HMB_DEBUG_CLOSELY
	if(unlikely(!(urgency >= HMB_UL_URGENT && urgency <= HMB_UL_LOW)))
	{
		hmb_debug("Out of range (urgency: %d)", urgency);
		return false;
	}
#endif

	entry = hmb_sorted_get_by_idx(idx);
	idx_next = entry->w_e_next; /* get index of the next entry of the 'entry' */
	idx_prev = entry->w_e_prev; /* get index of the previous entry of the 'entry' */

	prev = hmb_sorted_get_by_idx(idx_prev);
	next = hmb_sorted_get_by_idx(idx_next);

	prev->w_e_next = idx_next;
	next->w_e_prev = idx_prev;

	if(idx_next == idx)
	{
		HMB_CTRL.urgency[urgency-1] = HMB_HAS_NO_ENTRY;
	}

	else if(hmb_WB_sorted_get_head(urgency) == idx)
	{
		return hmb_WB_sorted_set_head(urgency, idx_next);
	}

	return true;
}
EXPORT_SYMBOL(hmb_WB_sorted_delete);

bool hmb_WB_sorted_delete_head(int32_t urgency)
{
	return hmb_WB_sorted_delete(urgency, hmb_WB_sorted_get_head(urgency));
}
EXPORT_SYMBOL(hmb_WB_sorted_delete_head);

/* same as blk_partition_remap() in block/blk-core.c */
void hmb_partition_remap(struct bio *bio)
{
	struct block_device *bdev = bio->bi_bdev;

	/*   
	 * Zone reset does not include bi_size so bio_sectors() is always 0.
	 * Include a test for the reset op code and perform the remap if needed.
	 */
	if (bdev != bdev->bd_contains &&
			(bio_sectors(bio) || bio_op(bio) == REQ_OP_ZONE_RESET)) {
		struct hd_struct *p = bdev->bd_part;

		bio->bi_iter.bi_sector += p->start_sect;
		bio->bi_bdev = bdev->bd_contains;
	}    
}
EXPORT_SYMBOL(hmb_partition_remap);

bool hmb_bm_get_empty(uint32_t *val)
{
	HmbBitmap32 *bm;
	HmbBitmap32 idx_bits;

	int32_t ret;

	if((ret = *hmb_bm_empty_get_head()) == HMB_HAS_NO_ENTRY)
	{
		//hmb_debug("The bitmap is already full!");
		return false;
	}

	bm = HMB_CTRL.bm;
	idx_bits = ~(bm[ret]);
	idx_bits = (HmbBitmap32)ilog2(idx_bits);
	*val = (HMB_BITMAP_BITS_PER_PART * (ret)) + idx_bits;

	return true;
}
EXPORT_SYMBOL(hmb_bm_get_empty);

bool hmb_bm_set(bool enable, uint32_t val)
{
	HmbBitmap32 *bm;
	uint32_t n_shifts, n_parts;

	bm = HMB_CTRL.bm;

	n_shifts = val % HMB_BITMAP_BITS_PER_PART;
	n_parts = val / HMB_BITMAP_BITS_PER_PART;

#ifdef HMB_DEBUG_CLOSELY
	if(unlikely(enable && (bm[n_parts] & (1 << n_shifts))))
	{    
		hmb_debug("Already filled! (val: %u, n_shifts: %u, n_parts: %u)", val, n_shifts, n_parts);
		return false;
	}    

	if(unlikely(!enable && !(bm[n_parts] & (1 << n_shifts))))
	{    
		hmb_debug("Already empty! (val: %u, n_shifts: %u, n_parts: %u)", val, n_shifts, n_parts);
		return false;
	}    
#endif

	if(enable)
	{    
		bm[n_parts] |= (1 << n_shifts);

		if(bm[n_parts] == HMB_BITMAP_PART_MAX_VALUE)
		{    
			if(hmb_bm_empty_delete(n_parts) == false)
			{
				hmb_debug("Invalid relationship.");
				return false;
			}
		}    
	}    

	else 
	{    
		if(bm[n_parts] == HMB_BITMAP_PART_MAX_VALUE)
		{
			if(hmb_bm_empty_insert(n_parts) == false)
			{
				hmb_debug("Invalid relationship.");
				return false;
			}
		}
		bm[n_parts] &= ~(1 << n_shifts);
	}    

	return true;
}
EXPORT_SYMBOL(hmb_bm_set);

HmbDLL *hmb_bm_empty_get_by_idx(uint32_t idx)
{
	return &HMB_CTRL.bm_empty_table[idx];
}
EXPORT_SYMBOL(hmb_bm_empty_get_by_idx);

int32_t *hmb_bm_empty_get_head(void)
{
	return HMB_CTRL.bm_empty;
}
EXPORT_SYMBOL(hmb_bm_empty_get_head);

bool hmb_bm_empty_set_head(uint32_t idx)
{
	HmbDLL *entry;
	int32_t *head;

	entry = hmb_bm_empty_get_by_idx(idx);
	head = hmb_bm_empty_get_head();

	if(*head != HMB_HAS_NO_ENTRY)
	{    
		hmb_debug("head is already set!");
		return false;
	}    

	*head = idx; 
	entry->e_next = idx; 
	entry->e_prev = idx; 

	return true;
}
EXPORT_SYMBOL(hmb_bm_empty_set_head);

bool hmb_bm_empty_insert(uint32_t idx)
{
	HmbDLL *head, *tail, *entry;
	uint32_t idx_head, idx_tail;
	int32_t ret; 

	if((ret = *hmb_bm_empty_get_head()) == HMB_HAS_NO_ENTRY)
	{    
		return hmb_bm_empty_set_head(idx);
	}

	entry = hmb_bm_empty_get_by_idx(idx);

	idx_head = ret;
	head = hmb_bm_empty_get_by_idx(idx_head);

	idx_tail = head->e_prev;
	tail = hmb_bm_empty_get_by_idx(idx_tail);

	tail->e_next = idx;
	head->e_prev = idx;

	entry->e_next = idx_head;
	entry->e_prev = idx_tail;

	return true;
}

bool hmb_bm_empty_delete(uint32_t idx)
{
	HmbDLL *entry, *prev, *next, *head;
	uint32_t idx_prev, idx_next, idx_head;
	int32_t ret;

	entry = hmb_bm_empty_get_by_idx(idx);

	idx_next = entry->e_next; /* get index of the next entry of the 'entry' */
	idx_prev = entry->e_prev; /* get index of the previous entry of the 'entry' */

	prev = hmb_bm_empty_get_by_idx(idx_prev);
	next = hmb_bm_empty_get_by_idx(idx_next);

	prev->e_next = idx_next;
	next->e_prev = idx_prev;

	if((ret = *hmb_bm_empty_get_head()) == HMB_HAS_NO_ENTRY)
	{
		hmb_debug("Invalid relationship.");
		return false;
	}

	idx_head = ret;
	head = hmb_bm_empty_get_by_idx(idx_head);

	/* [1] If requested entry to delete is a head */
	if(head == entry)
	{
		int32_t *head_idx;

		head_idx = hmb_bm_empty_get_head();

		if(idx == idx_next)
		{
			*head_idx = HMB_HAS_NO_ENTRY;
		}

		else
		{
			*head_idx = idx_next;
		}
	}
	/* [1] */

	return true;
}
EXPORT_SYMBOL(hmb_bm_empty_delete);

HmbSharedEnt* hmb_shared_get_head_by_lpn(uint64_t lpn)
{
	uint32_t hashed;
	HmbHeads idx; 

	hashed = hmb_hash(lpn, HMB_CTRL.heads_hash_bit);

	idx = *(hmb_heads_get_by_idx(hashed));
	if(idx == HMB_HAS_NO_ENTRY)
	{    
		return NULL;
	}    

	return hmb_table_get_by_idx(idx);
}
EXPORT_SYMBOL(hmb_shared_get_head_by_lpn);

HmbSharedEnt* hmb_shared_get_by_lpn(uint64_t lpn)
{
	HmbSharedEnt *head, *loop;

	if((head = hmb_shared_get_head_by_lpn(lpn)) == NULL)
	{
		return NULL;
	}

	if(head->lpn == lpn)
	{
		return head;
	}

	for(loop = hmb_shared_get_by_idx(head->e_next); \
			loop != head;
			loop = hmb_shared_get_by_idx(loop->e_next))
	{
		if(loop->lpn == lpn)
		{
			return loop;
		}
	}

	return NULL;
}
EXPORT_SYMBOL(hmb_shared_get_by_lpn);

bool hmb_shared_set_head(uint32_t idx)
{
	HmbSharedEnt *entry;
	HmbHeads *head;
	uint32_t hashed;

	entry = hmb_table_get_by_idx(idx);

	hashed = hmb_hash(entry->lpn, HMB_CTRL.heads_hash_bit);

	head = hmb_heads_get_by_idx(hashed);
#ifdef HMB_DEBUG_CLOSELY
	if(unlikely(*head != HMB_HAS_NO_ENTRY))
	{
		hmb_debug("head is already set!");
		return false;
	}
#endif

	*head = idx;

	entry->e_own = idx;
	entry->e_next = idx;
	entry->e_prev = idx;

	hmb_table_nCached_inc(true);

	return true;
}
EXPORT_SYMBOL(hmb_shared_set_head);

bool hmb_shared_insert_tail(uint32_t idx)
{
	HmbSharedEnt *head, *tail, *entry;
	uint32_t idx_head, idx_tail;

	/* [1] If the LRU list for 'entry' has no entry */
	entry = hmb_table_get_by_idx(idx);
	if((head = hmb_shared_get_head_by_lpn(entry->lpn)) == NULL)
	{
		return hmb_shared_set_head(idx);
	}
	/* [1] */

	/* "tail": the most recently used entry */
	tail = hmb_table_get_by_idx(head->e_prev);

	idx_head = head->e_own;  /* entry index for head (i.e. least recently used) */
	idx_tail = tail->e_own;  /* entry index for tail (i.e. most recently used) */

	/* [1] Set the 'entry' to most recently used entry */
	tail->e_next = idx;
	head->e_prev = idx;

	entry->e_own = idx;
	entry->e_next = idx_head;
	entry->e_prev = idx_tail;
	/* [1] */

	hmb_table_nCached_inc(true);

	return true;
}
EXPORT_SYMBOL(hmb_shared_insert_tail);

bool hmb_shared_delete(uint32_t idx)
{
	HmbSharedEnt *entry, *prev, *next, *head;
	uint32_t idx_prev, idx_next;

	entry = hmb_table_get_by_idx(idx);

	idx_next = entry->e_next; /* get index of the next entry of the 'entry' */
	idx_prev = entry->e_prev; /* get index of the previous entry of the 'entry' */

	prev = hmb_table_get_by_idx(idx_prev);
	next = hmb_table_get_by_idx(idx_next);

	prev->e_next = idx_next;
	next->e_prev = idx_prev;

	head = hmb_shared_get_head_by_lpn(entry->lpn);
#ifdef HMB_DEBUG_CLOSELY
	if(unlikely(head  == NULL))
	{   
		hmb_debug("Invalid relationship!");
		return false;
	}
#endif

	/* [1] If requested entry to delete is a head */
	if(head == entry)
	{   
		HmbHeads *heads;
		uint32_t hashed;

		hashed = hmb_hash(entry->lpn, HMB_CTRL.heads_hash_bit);
		heads = hmb_heads_get_by_idx(hashed);

		if(idx == idx_next)
		{   
			*heads = HMB_HAS_NO_ENTRY;
		}

		else
		{   
			*heads = idx_next;
		}
	}

	if(unlikely(hmb_bm_set(false, idx) == false))
	{   
		hmb_debug("Failed to disable bitmap.");
		return false;
	}

#if 0
	if(unlikely(hmb_table_bm_set_fully(false, idx) == false))
	{   
		hmb_debug("Failed to disable bitmap.");
		return false;
	}
#endif

#ifdef HMB_DEBUG_CLOSELY
	if(entry->dirty != 0)
	{
#if 0
		hmb_table_nDirty_inc(false);
		hmb_table_get_by_idx(entry->e_own)->urgency = HMB_UL_DISABLED;
		hmb_shared_set_dirty(entry->e_own);
#endif
		hmb_debug("Invalid relationship: host cannot remove dirty entry!");

		return false;
	}
#endif
	hmb_table_nCached_inc(false);

	return true;
}
EXPORT_SYMBOL(hmb_shared_delete);

void hmb_shared_set_dirty(bool to_dirty, uint32_t idx)
{
	HmbSharedEnt *entry = hmb_table_get_by_idx(idx);

	if(to_dirty)
	{
		entry->dirty = 1;
	}
	else
	{
		entry->dirty = 0;
	}
}
EXPORT_SYMBOL(hmb_shared_set_dirty);

void hmb_shared_set_enable(bool enable, uint32_t idx)
{
	HmbSharedEnt *entry = hmb_table_get_by_idx(idx);

	if(enable)
	{
		entry->usable = 1;
	}
	else
	{
		entry->usable = 0;
	}
}
EXPORT_SYMBOL(hmb_shared_set_enable);

int32_t hmb_shared_get_new_entry_idx(uint64_t lpn)
{
	uint32_t new_idx;
	HmbSharedEnt *entry;
	HmbSortedEnt *entry_sorted;

#ifdef HMB_DEBUG_TIME_DETAIL
	hmb_elapsed_time_acc(true, HMB_CTRL.t_WB_bm_is_empty);
#endif
	
	if(hmb_bm_get_empty(&new_idx) == false)
	{
		return -1;
	}
#ifdef HMB_DEBUG_TIME_DETAIL
	hmb_elapsed_time_acc(false, HMB_CTRL.t_WB_bm_is_empty);
#endif

#ifdef HMB_DEBUG_TIME_DETAIL
	hmb_elapsed_time_acc(true, HMB_CTRL.t_WB_bm_set);
#endif
	if(unlikely(hmb_bm_set(true, new_idx) == false))
	{
		hmb_debug("Invalid relationship: failed to fill data into bitmap.");
		return -1;
	}

	if(unlikely(hmb_table_bm_set_fully(false, new_idx) == false))
	{
		hmb_debug("Invalid relationship: failed to fill data into table bitmap.");
		return -1;
	}
#ifdef HMB_DEBUG_TIME_DETAIL
	hmb_elapsed_time_acc(false, HMB_CTRL.t_WB_bm_set);
#endif

	entry = hmb_table_get_by_idx(new_idx);
	entry_sorted = hmb_sorted_get_by_idx(new_idx);

	entry->usable = 0;
	entry->e_own = new_idx;
	entry->lpn = lpn;
	entry->dirty = 0;
	entry->urgency = HMB_UL_DISABLED;

	entry_sorted->e_own = new_idx;

	return (int32_t)new_idx;
}
EXPORT_SYMBOL(hmb_shared_get_new_entry_idx);

bool hmb_shared_is_reusable_by_idx(uint32_t idx)
{
	HmbSharedEnt *entry;

	entry = hmb_table_get_by_idx(idx);

	if(entry->usable == 1)
	{
		return true;
	}

	return false;
}
EXPORT_SYMBOL(hmb_shared_is_reusable_by_idx);

bool hmb_WB_completion(struct bio **hit, uint32_t n_hit, struct bio **miss, uint32_t n_miss)
{
	bool result = true;
	uint32_t i, cnt_sectors = 0;

	for(i=0; i<n_miss; i++)
	{
		cnt_sectors += bio_sectors(miss[i]);
	}
	/* Guessing */
	cnt_sectors >>= (HMB_CTRL.cache_unit_bits - 9);

	if(hmb_WB_is_insertable(cnt_sectors) == false) 
	{
		return false;
	}

#ifdef HMB_DEBUG_TIME_DETAIL
	hmb_elapsed_time_acc(true, HMB_CTRL.t_WB_processing_hit);
#endif
	if(unlikely(hmb_WB_processing_hits(hit, n_hit) == false))
	{
		hmb_debug("Failed to process hit bios.");
		result = false;
	}
#ifdef HMB_DEBUG_TIME_DETAIL
	hmb_elapsed_time_acc(false, HMB_CTRL.t_WB_processing_hit);
#endif

#ifdef HMB_DEBUG_TIME_DETAIL
	hmb_elapsed_time_acc(true, HMB_CTRL.t_WB_processing_miss);
#endif
	if(result && hmb_WB_processing_misses(miss, n_miss) == false)
	{
		result = false;
	}
#ifdef HMB_DEBUG_TIME_DETAIL
	hmb_elapsed_time_acc(false, HMB_CTRL.t_WB_processing_miss);
#endif

	return result;
}
EXPORT_SYMBOL(hmb_WB_completion);

bool hmb_WB_processing_hits(struct bio **hit, uint32_t n_hit)
{
	uint32_t i, j;
	
	for(i=0; i<n_hit; i++)
	{
		struct bio *bio;
		sector_t sector_idx_first;
		uint32_t n_lb;
		HmbSharedEnt *shared;

		unsigned short bio_v_idx;
		u32 remainder_req, remainder_bio_v_cur;
		u32 written_req, written_bio_v_cur;
		void *bio_v_cur_mapped = NULL;
		struct bio_vec *bio_v, *bio_v_cur;

		bio = hit[i];

		sector_idx_first = bio->bi_iter.bi_sector;
		n_lb = bio_sectors(bio);

		bio_v = bio->bi_io_vec;

		bio_v_idx = bio->bi_iter.bi_idx;
		bio_v_cur = &bio_v[bio_v_idx];
		written_bio_v_cur = bio->bi_iter.bi_bvec_done;
		remainder_bio_v_cur = bio_v_cur->bv_len - written_bio_v_cur;

		for(j=0; j<n_lb; j++)
		{
			sector_t sector_idx = sector_idx_first + j;
			uint64_t lpn = hmb_sector_to_lpn(sector_idx);
			uint32_t idx_internal = hmb_sector_to_internal_idx(sector_idx);

#ifdef HMB_DEBUG_TIME_DETAIL
			hmb_elapsed_time_acc(true, HMB_CTRL.t_WB_shared_get_by_lpn);
#endif
			shared = hmb_shared_get_by_lpn(lpn);
#ifdef HMB_DEBUG_TIME_DETAIL
			hmb_elapsed_time_acc(false, HMB_CTRL.t_WB_shared_get_by_lpn);
#endif

#ifdef HMB_DEBUG_CLOSELY
			if(unlikely(shared == NULL))
			{
				hmb_debug("Invalid relationship");
				return false;
			}
#endif

#if 0
			hmb_debug("<DEBUG> ST: 0x%010lX, LBA: 0x%010lX, IDX-INT: %1u, C-ED?: %1d, SFT-IDX-INT: %u", \
					sector_idx, lpn, idx_internal, \
					hmb_table_bm_isCached_partially(shared->e_own, idx_internal), idx_internal << 9);
#endif

			/* Case 1. If the cached entry is clean */
			if(shared->urgency == HMB_UL_DISABLED)
			{
#ifdef HMB_DEBUG_CLOSELY
				if(shared->dirty != 0)
				{
					hmb_debug("Invalid relationship: it must be clean.");
					return false;
				}
#endif
				if(unlikely(hmb_RCOnly_sorted_delete(shared->e_own) == false))
				{
					hmb_debug("Failed to remove entry from the RC-only LRU list.");
					return false;
				}

				/* Apply bio's urgency level to shared entry in HMB */
				shared->urgency = bio->hmb_urgency;

				/* enable dirty bit */
				hmb_shared_set_dirty(true, shared->e_own);
				hmb_table_nDirty_inc(true);

				/* Insert shared entry in new list */
#ifdef HMB_DEBUG_TIME_DETAIL
				hmb_elapsed_time_acc(true, HMB_CTRL.t_WB_entry_insert);
#endif
				if(unlikely(hmb_WB_sorted_insert_tail(shared->urgency, shared->e_own) == false))
				{
					hmb_debug("Failed to insert entry into the sorted entry.");
					return false;
				}
#ifdef HMB_DEBUG_TIME_DETAIL
				hmb_elapsed_time_acc(false, HMB_CTRL.t_WB_entry_insert);
#endif

				/* Remove the entry from the RC-only LRU list */
#ifdef HMB_DEBUG_TIME_DETAIL
				hmb_elapsed_time_acc(true, HMB_CTRL.t_WB_entry_delete);
#endif
#ifdef HMB_DEBUG_TIME_DETAIL
				hmb_elapsed_time_acc(false, HMB_CTRL.t_WB_entry_delete);
#endif
			}

			/*
				Case 2. If the cached entry has lower urgency
				+ Case 3. If the cached entry has upper urgency
					- The target entry moves their location to tail in the UL.
			*/
			else 
			{
#ifdef HMB_DEBUG_CLOSELY
				if(shared->dirty == 0)
				{
					hmb_debug("Invalid relationship: it must be dirty.");
					return false;
				}
#endif
				/* Remove shared entry from existing list */
#ifdef HMB_DEBUG_TIME_DETAIL
				hmb_elapsed_time_acc(true, HMB_CTRL.t_WB_entry_delete);
#endif
				if(unlikely(hmb_WB_sorted_delete(shared->urgency, shared->e_own) == false))
				{
					hmb_debug("Failed to remove entry from the sorted entry.");
					return false;
				}
#ifdef HMB_DEBUG_TIME_DETAIL
				hmb_elapsed_time_acc(false, HMB_CTRL.t_WB_entry_delete);
#endif

				/* Case 3: apply bio's urgency level to shared entry in HMB */
				if(shared->urgency > bio->hmb_urgency)
				{
					shared->urgency = bio->hmb_urgency;
				}

				/* Insert shared entry in new list */
#ifdef HMB_DEBUG_TIME_DETAIL
				hmb_elapsed_time_acc(true, HMB_CTRL.t_WB_entry_insert);
#endif
				if(unlikely(hmb_WB_sorted_insert_tail(shared->urgency, shared->e_own) == false))
				{
					hmb_debug("Failed to insert entry into the sorted entry.");
					return false;
				}
#ifdef HMB_DEBUG_TIME_DETAIL
				hmb_elapsed_time_acc(false, HMB_CTRL.t_WB_entry_insert);
#endif
			}

			/* update LRU list */
#ifdef HMB_DEBUG_TIME_DETAIL
			hmb_elapsed_time_acc(true, HMB_CTRL.t_WB_LRU_reorder);
#endif
			if(unlikely(hmb_RC_reorder(shared->e_own) == false))
			{
				hmb_debug("Invalid relationship!");
				return false;
			}
#ifdef HMB_DEBUG_TIME_DETAIL
			hmb_elapsed_time_acc(false, HMB_CTRL.t_WB_LRU_reorder);
#endif

			/* Copy data from page(s) allocated for the bio into HMB */
#ifdef HMB_DEBUG_TIME_DETAIL
			hmb_elapsed_time_acc(true, HMB_CTRL.t_WB_get_page_addr);
#endif
			if(unlikely((bio_v_cur_mapped = page_address(bio_v_cur->bv_page)) == NULL))
			{
				hmb_debug("Failed to get mapped virtual memory address of a page included in the bio.");
				return false;
			}
#ifdef HMB_DEBUG_TIME_DETAIL
			hmb_elapsed_time_acc(false, HMB_CTRL.t_WB_get_page_addr);
#endif

			written_req = 0;
			remainder_req = 512;
		
#ifdef HMB_DEBUG_TIME_DETAIL
			hmb_elapsed_time_acc(true, HMB_CTRL.t_WB_copy_loop);
#endif
			do
			{
				void *dst, *src;

				src = bio_v_cur_mapped + bio_v_cur->bv_offset + written_bio_v_cur;
				dst = HMB_CTRL.hmb_addr[shared->segment] + \
					  shared->offset + (idx_internal << 9) + \
					  written_req;

				if(remainder_req < remainder_bio_v_cur) /* When BIO VECTOR has spare space */
				{
					memcpy(dst, src, remainder_req);

					/* Update BIO VECTOR related parts */
					remainder_bio_v_cur -= remainder_req;
					written_bio_v_cur += remainder_req;

					break;
				} /* if(remainder_req < remainder_bio_v_cur) */

				/* if (remainder_req >= remainder_bio_v_cur) */
				else
				{
					memcpy(dst, src, remainder_bio_v_cur);

					/* Update HMB related parts */
					remainder_req -= remainder_bio_v_cur;
					written_req += remainder_bio_v_cur;

					if(j != n_lb - 1)
					{
						++bio_v_idx;
						bio_v_cur = &bio_v[bio_v_idx];
						remainder_bio_v_cur = bio_v_cur->bv_len;
						written_bio_v_cur = 0;

						if(unlikely((bio_v_cur_mapped = page_address(bio_v_cur->bv_page)) == NULL))
						{
							hmb_debug("Failed to get mapped virtual memory address of a page included in the bio.");
							return false;
						}
					}
				} /* else of "if(remainder_req <= remainder_bio_v_cur)" */
			} while(remainder_req > 0);
#ifdef HMB_DEBUG_TIME_DETAIL
			hmb_elapsed_time_acc(false, HMB_CTRL.t_WB_copy_loop);
#endif

			if(!hmb_table_bm_isCached_partially(shared->e_own, idx_internal))
			{
				hmb_table_bm_set(true, shared->e_own, idx_internal);
			}

#if 0
			hmb_debug("<DBG> SECTOR: 0x%08lX, LBA: 0x%08lX, BM: 0x%08X, ID_OWN: %6u, ID_INTER: %1u, <<9: %4u, CACHED: %1d, U: %lu, D: %lu", \
					sector_idx, lpn, hmb_table_bm_get_by_idx(shared->e_own)->filled, shared->e_own, \
					idx_internal, idx_internal << 9, \
					hmb_table_bm_isCached_partially(shared->e_own, idx_internal), \
					shared->usable, shared->dirty);
#endif
		} /* for(j=0; j<bio_sectors(bio); j++) */

	} /*for(i=0; i<n_hit; i++) */

	return true;
}
EXPORT_SYMBOL(hmb_WB_processing_hits);

bool hmb_WB_processing_misses(struct bio **miss, uint32_t n_miss)
{
	uint32_t i, j;
	
	for(i=0; i<n_miss; i++)
	{
		struct bio *bio;
		sector_t sector_idx_first;
		uint32_t n_lb;
		HmbSharedEnt *shared;

		unsigned short bio_v_idx;
		u32 remainder_req, remainder_bio_v_cur;
		u32 written_req, written_bio_v_cur;
		void *bio_v_cur_mapped = NULL;
		struct bio_vec *bio_v, *bio_v_cur;

		bio = miss[i];

		sector_idx_first = bio->bi_iter.bi_sector;
		n_lb = bio_sectors(bio);
		HMB_CTRL.t_WB_loops += n_lb; /* FIXME: for debug */

		bio_v = bio->bi_io_vec;
#ifdef HMB_DEBUG_CLOSELY
		if(unlikely(bio_v == NULL))
		{
			hmb_debug("BIO VECTOR is not initialized.");
			return false;
		}
#endif

		bio_v_idx = bio->bi_iter.bi_idx;
		bio_v_cur = &bio_v[bio_v_idx];
		written_bio_v_cur = bio->bi_iter.bi_bvec_done;
		remainder_bio_v_cur = bio_v_cur->bv_len - written_bio_v_cur;

		for(j=0; j<n_lb; j++)
		{
			sector_t sector_idx = sector_idx_first + j;
			uint64_t lpn = hmb_sector_to_lpn(sector_idx);
			uint32_t idx_internal = hmb_sector_to_internal_idx(sector_idx);

			int32_t new_idx;

#ifdef HMB_DEBUG_CLOSELY
			if(unlikely(bio->hmb_urgency == HMB_UL_DISABLED))
			{
				hmb_debug("Invalid relationship");
				return false;
			}
#endif

			shared = hmb_shared_get_by_lpn(lpn);
			
			if(shared == NULL)
			{
#ifdef HMB_DEBUG_TIME_DETAIL
				hmb_elapsed_time_acc(true, HMB_CTRL.t_WB_shared_get_new_entry);
#endif
				new_idx = hmb_shared_get_new_entry_idx(lpn);
#ifdef HMB_DEBUG_TIME_DETAIL
				hmb_elapsed_time_acc(false, HMB_CTRL.t_WB_shared_get_new_entry);
#endif

				if(new_idx < 0)
				{
					if(hmb_RC_evict(n_lb - j) == false)
					{
						/* FIXME: Restoration when eviction is failed. */
#ifdef HMB_DEBUG_TIME_DETAIL
						hmb_debug("<DEBUG> Failed to evict %d/%d entries.", n_lb - j, n_lb);
#endif
						return false;
					}

#ifdef HMB_DEBUG_TIME_DETAIL
					hmb_elapsed_time_acc(true, HMB_CTRL.t_WB_shared_get_new_entry);
#endif
					new_idx = hmb_shared_get_new_entry_idx(lpn);
#ifdef HMB_DEBUG_TIME_DETAIL
					hmb_elapsed_time_acc(false, HMB_CTRL.t_WB_shared_get_new_entry);
#endif
#ifdef HMB_DEBUG_CLOSELY
					if(unlikely(new_idx < 0))
					{
						hmb_debug("Invalid relationship");
						return false;
					}
#endif
				}

#ifdef HMB_DEBUG_TIME_DETAIL
				hmb_elapsed_time_acc(true, HMB_CTRL.t_WB_entry_insert);
#endif
				if(unlikely(hmb_shared_insert_tail(new_idx) == false))
				{
					hmb_debug("Failed to insert new entry to adequate LRU list.");
					return false;
				}
#ifdef HMB_DEBUG_TIME_DETAIL
				hmb_elapsed_time_acc(false, HMB_CTRL.t_WB_entry_insert);
#endif

#ifdef HMB_DEBUG_TIME_DETAIL
				hmb_elapsed_time_acc(true, HMB_CTRL.t_WB_entry_insert);
#endif
				if(unlikely(hmb_RC_sorted_insert_tail(new_idx) == false))
				{
					hmb_debug("Failed to insert new entry.");
					return false;
				}
#ifdef HMB_DEBUG_TIME_DETAIL
				hmb_elapsed_time_acc(false, HMB_CTRL.t_WB_entry_insert);
#endif
				hmb_shared_set_enable(true, new_idx);

				/* Apply bio's urgency level to shared entry in HMB */
				shared = hmb_shared_get_by_idx(new_idx);
				shared->urgency = bio->hmb_urgency;

				/* Enable dirty bit */
				hmb_shared_set_dirty(true, new_idx);
				hmb_table_nDirty_inc(true);

				/* Insert shared entry in new list */
#ifdef HMB_DEBUG_TIME_DETAIL
				hmb_elapsed_time_acc(true, HMB_CTRL.t_WB_entry_insert);
#endif
				if(unlikely(hmb_WB_sorted_insert_tail(shared->urgency, new_idx) == false))
				{
					hmb_debug("Failed to insert entry into the sorted entry.");
					return false;
				}
#ifdef HMB_DEBUG_TIME_DETAIL
				hmb_elapsed_time_acc(false, HMB_CTRL.t_WB_entry_insert);
#endif

#ifdef HMB_DEBUG_TIME_DETAIL
				hmb_elapsed_time_acc(true, HMB_CTRL.t_WB_get_page_addr);
#endif
				if(unlikely((bio_v_cur_mapped = page_address(bio_v_cur->bv_page)) == NULL))
				{
					hmb_debug("Failed to get mapped virtual memory address of a page included in the bio.");
					return false;
				}
#ifdef HMB_DEBUG_TIME_DETAIL
				hmb_elapsed_time_acc(false, HMB_CTRL.t_WB_get_page_addr);
#endif
			}

			written_req = 0;
			remainder_req = 512;

#ifdef HMB_DEBUG_TIME_DETAIL
			hmb_elapsed_time_acc(true, HMB_CTRL.t_WB_copy_loop);
#endif
			do
			{
				void *dst, *src;

				src = bio_v_cur_mapped + bio_v_cur->bv_offset + written_bio_v_cur;
				dst = HMB_CTRL.hmb_addr[shared->segment] + \
					  shared->offset + (idx_internal << 9) + \
					  written_req;

				if(remainder_req < remainder_bio_v_cur) /* When BIO VECTOR has spare space */
				{
					memcpy(dst, src, remainder_req);

					/* Update BIO VECTOR related parts */
					remainder_bio_v_cur -= remainder_req;
					written_bio_v_cur += remainder_req;

					break;
				} /* if(remainder_req < remainder_bio_v_cur) */

				/* if (remainder_req >= remainder_bio_v_cur) */
				else
				{
					memcpy(dst, src, remainder_bio_v_cur);

					/* Update HMB related parts */
					remainder_req -= remainder_bio_v_cur;
					written_req += remainder_bio_v_cur;

					if(j != n_lb - 1)
					{
						++bio_v_idx;
						bio_v_cur = &bio_v[bio_v_idx];
						remainder_bio_v_cur = bio_v_cur->bv_len;
						written_bio_v_cur = 0;

						if(unlikely((bio_v_cur_mapped = page_address(bio_v_cur->bv_page)) == NULL))
						{
							hmb_debug("Failed to get mapped virtual memory address of a page included in the bio.");
							return false;
						}
					}
				} /* else of "if(remainder_req <= remainder_bio_v_cur)" */
			} while(remainder_req > 0);
#ifdef HMB_DEBUG_TIME_DETAIL
			hmb_elapsed_time_acc(false, HMB_CTRL.t_WB_copy_loop);
#endif

			hmb_table_bm_set(true, shared->e_own, idx_internal);

#if 0
			hmb_debug("<DBG> SECTOR: 0x%08lX, LBA: 0x%08lX, BM: 0x%08X, ID_OWN: %6u, ID_INTER: %1u, <<9: %4u, CACHED: %1d, U: %lu, D: %lu", \
					sector_idx, lpn, hmb_table_bm_get_by_idx(shared->e_own)->filled, shared->e_own, \
					idx_internal, idx_internal << 9, \
					hmb_table_bm_isCached_partially(shared->e_own, idx_internal), \
					shared->usable, shared->dirty);
#endif

		} /* for(j=0; j<bio_sectors(bio); j++) */

	} /*for(i=0; i<n_hit; i++) */

	return true;
}
EXPORT_SYMBOL(hmb_WB_processing_misses);

blk_qc_t hmb_caching(struct bio *bio)
{
	bool is_cnt_applied = false;
	bool is_initial_loop = true;

	uint32_t miss_cnt = 0, hit_cnt = 0;
	struct bio *miss_bio[HMB_BIO_NUMBER_MAX] = {NULL, };
	struct bio  *hit_bio[HMB_BIO_NUMBER_MAX] = {NULL, };
	unsigned long flags;

	u64 sector_idx_hit_first, sector_idx_hit_last;

	uint64_t t_start;

	t_start = hmb_get_current_time_ns();

	/**
	  [1] Update first sector information 
	  - Consider: Has this SSD multiple partitions?
	 **/
	hmb_partition_remap(bio);
	/** [1] **/

	hmb_lock(&flags);
	while(hmb_RC_is_cachable( \
				bio, \
				&sector_idx_hit_first, \
				&sector_idx_hit_last) == true)
	{
		u64 sector_num, sector_num_hits;
		struct bio *bio_splited = NULL;

		sector_num_hits = sector_idx_hit_last - sector_idx_hit_first + 1;
		sector_num = bio_sectors(bio);

		/**
		  [1] FULLY HIT
		  - If all sectors in the bio are cached
		 **/
		if(sector_num_hits == sector_num)
		{
			if(unlikely(hmb_RC_copy_from_HMB(bio) == false))
			{
				hmb_debug("ERROR: Data was changed on processing caching entries");

				atomic_inc(&(HMB_CTRL.n_error));

				hmb_endio(hit_bio, hit_cnt, miss_bio, miss_cnt, bio, false, true);

				hmb_unlock(&flags);

				if(!hmb_generic_make_request(miss_bio, miss_cnt))
				{
					hmb_debug("Critical problem!");
				}

				atomic64_add(hmb_get_current_time_ns() - t_start, &HMB_CTRL.t_overhead_caching);
				return generic_make_request(bio);

			}

			/** [2] The request represented by fio is completed in the host kernel **/
			if(is_cnt_applied == false)
			{
				if(is_initial_loop == true)
				{
					atomic_inc(&(HMB_CTRL.n_hit_f));
				}
				else
				{
					atomic_inc(&(HMB_CTRL.n_hit_p));
				}
				is_cnt_applied = true;
			}

			hmb_endio(hit_bio, hit_cnt, miss_bio, miss_cnt, bio, true, true);

			hmb_unlock(&flags);

			if(hmb_generic_make_request(miss_bio, miss_cnt) == false)
			{
				hmb_debug("Critical problem!");
			}

			atomic64_add(hmb_get_current_time_ns() - t_start, &HMB_CTRL.t_overhead_caching);
			return BLK_STS_OK;

			/** [2] **/
		}
		/** [1] **/

		/**
		  [1] PARTIALLY HIT
		  - Hit: Some sectors are cached.
		  - Missed: And the other are NOT cached.
		  - Hit part and missed part(s) are devided to different 'bio's.
		 **/
		/** [2] bio split point **/

		/** [3] Part 1: If some front sectors are missed */
		if(sector_idx_hit_first != 0)
		{
			bio_splited = bio_split(bio, (int)sector_idx_hit_first, GFP_ATOMIC, bio->bi_pool);

			if(unlikely(bio_splited == NULL))
			{
				hmb_debug("Unknown error");
				atomic_inc(&(HMB_CTRL.n_error));

				hmb_endio(hit_bio, hit_cnt, miss_bio, miss_cnt, bio, false, true);

				hmb_unlock(&flags);

				if(!hmb_generic_make_request(miss_bio, miss_cnt))
				{
					hmb_debug("Critical problem!");
				}

				atomic64_add(hmb_get_current_time_ns() - t_start, &HMB_CTRL.t_overhead_caching);
				return generic_make_request(bio);
			}

			miss_bio[miss_cnt++] = bio_splited;

		}
		/** [3] **/
		/** [3] Part 2: Processing hit sector(s) **/
		/* If all remained sectors are hit */
		sector_num = bio_sectors(bio);
		if(sector_num_hits == sector_num)
		{
			bio_splited = bio; /* bio_splited for hit sectors */
		}
		/* If parts of remained sectors are hit */
		else
		{
			/* Detach hit sectors */
			bio_splited = bio_split(bio, (int)sector_num_hits, GFP_ATOMIC, bio->bi_pool);

			if(unlikely(bio_splited == NULL))
			{
				hmb_debug("Unknown error");
				atomic_inc(&(HMB_CTRL.n_error));

				hmb_endio(hit_bio, hit_cnt, miss_bio, miss_cnt, bio, false, true);

				hmb_unlock(&flags);

				if(!hmb_generic_make_request(miss_bio, miss_cnt))
				{
					hmb_debug("Critical problem!");
				}

				atomic64_add(hmb_get_current_time_ns() - t_start, &HMB_CTRL.t_overhead_caching);
				return generic_make_request(bio);
			}
			/** [4] **/
		}

		if(unlikely(hmb_RC_copy_from_HMB(bio_splited) == false))
		{
			hmb_debug("ERROR: Data was changed on processing caching entries.");
			atomic_inc(&(HMB_CTRL.n_error));

			hmb_endio(hit_bio, hit_cnt, miss_bio, miss_cnt, bio, false, true);

			hmb_unlock(&flags);

			if(!hmb_generic_make_request(miss_bio, miss_cnt))
			{
				hmb_debug("Critical problem!");
			}

			if(bio != bio_splited)
			{
				generic_make_request(bio);
			}
			atomic64_add(hmb_get_current_time_ns() - t_start, &HMB_CTRL.t_overhead_caching);
			return generic_make_request(bio_splited);
		}

		if(is_cnt_applied == false)
		{
			atomic_inc(&(HMB_CTRL.n_hit_p));
			is_cnt_applied = true;
		}

		/** [3] **/
		if(sector_num_hits == sector_num)
		{
			hmb_endio(hit_bio, hit_cnt, miss_bio, miss_cnt, bio, true, true);

			hmb_unlock(&flags);

			if(!hmb_generic_make_request(miss_bio, miss_cnt))
			{
				hmb_debug("Critical problem!");
			}

			atomic64_add(hmb_get_current_time_ns() - t_start, &HMB_CTRL.t_overhead_caching);
			return BLK_STS_OK;
		}

		hit_bio[hit_cnt++] = bio_splited;

		is_initial_loop = false;

		if(unlikely(hit_cnt >= HMB_BIO_NUMBER_MAX || miss_cnt >= HMB_BIO_NUMBER_MAX))
		{
			hmb_debug("# separated entries reaches to maximum numbers.");

			hmb_endio(hit_bio, hit_cnt, miss_bio, miss_cnt, bio, false, true);

			hmb_unlock(&flags);

			if(!hmb_generic_make_request(miss_bio, miss_cnt))
			{
				hmb_debug("Critical problem!");
			}

			atomic64_add(hmb_get_current_time_ns() - t_start, &HMB_CTRL.t_overhead_caching);
			return generic_make_request(bio);
		}

		/** [2] **/
		/** [1] **/
	} /* while(hmb_RC_is_cachable(...) */

	if(is_cnt_applied == false)
	{
		atomic_inc(&(HMB_CTRL.n_miss));
	}

	hmb_endio(hit_bio, hit_cnt, miss_bio, miss_cnt, bio, false, true);

	hmb_unlock(&flags);

	if(!hmb_generic_make_request(miss_bio, miss_cnt))
	{
		hmb_debug("Critical problem!");
	}

	atomic64_add(hmb_get_current_time_ns() - t_start, &HMB_CTRL.t_overhead_caching);
	return generic_make_request(bio);
}
EXPORT_SYMBOL(hmb_caching);

blk_qc_t hmb_buffering(struct bio *bio)
{
	u64 sector_idx_hit_first, sector_idx_hit_last;
	bool is_initial_loop = true;

	uint32_t miss_cnt = 0, hit_cnt = 0;
	struct bio *miss_bio[HMB_BIO_NUMBER_MAX] = {NULL, };
	struct bio  *hit_bio[HMB_BIO_NUMBER_MAX] = {NULL, };
	unsigned long flags;

	uint64_t t_start;

	t_start = hmb_get_current_time_ns();

	hmb_lock(&flags);

	if(HMB_CTRL.hmb_header->C__n_max_entries == HMB_CTRL.hmb_header->C__n_dirty)
	{
		hmb_unlock(&flags);

		//hmb_debug("<DEBUG> HMB is already full!");

		atomic64_add(hmb_get_current_time_ns() - t_start, &HMB_CTRL.t_overhead_buffering);
		return generic_make_request(bio);
	}

	/**
	  [1] Update first sector information 
	  - Consider: Has this SSD multiple partitions?
	 **/
	hmb_partition_remap(bio);
	/** [1] **/

#ifdef HMB_DEBUG_TIME_DETAIL
	hmb_elapsed_time_acc(true, HMB_CTRL.t_WB_confirming_hitness);
#endif
	while(hmb_WB_is_bufferable( \
				bio, \
				&sector_idx_hit_first, \
				&sector_idx_hit_last) == true)
	{
		u64 sector_num, sector_num_hits;
		struct bio *bio_splited = NULL;

#ifdef HMB_DEBUG_TIME_DETAIL
		hmb_elapsed_time_acc(false, HMB_CTRL.t_WB_confirming_hitness);
#endif

		sector_num_hits = sector_idx_hit_last - sector_idx_hit_first + 1;
		sector_num = bio_sectors(bio);

		/**
		  [1] FULLY HIT
		  - If all sectors in the bio are cached
		 **/
		if(sector_num_hits == sector_num)
		{
			/** [2] The request represented by fio is completed in the host kernel **/
			hit_bio[hit_cnt++] = bio;

			if(unlikely(!hmb_WB_completion(hit_bio, hit_cnt, miss_bio, miss_cnt)))
			{
				//hmb_debug("<DEBUG> Failed to be buffering!");

				hmb_chain_multiple(hit_bio, hit_cnt-1, bio);
				hmb_chain_multiple(miss_bio, miss_cnt, bio);

				hmb_unlock(&flags);

				if(unlikely(!hmb_generic_make_request(hit_bio, hit_cnt-1)))
				{
					hmb_debug("Critical problem!");
				}
				if(unlikely(!hmb_generic_make_request(miss_bio, miss_cnt)))
				{
					hmb_debug("Critical problem!");
				}

				atomic64_add(hmb_get_current_time_ns() - t_start, &HMB_CTRL.t_overhead_buffering);
				return generic_make_request(bio);
			}

			hmb_endio(hit_bio, hit_cnt-1, miss_bio, miss_cnt, bio, true, false);

			hmb_unlock(&flags);

			atomic64_add(hmb_get_current_time_ns() - t_start, &HMB_CTRL.t_overhead_buffering);
			return BLK_STS_OK;

			/** [2] **/
		}
		/** [1] **/

		/**
		  [1] PARTIALLY HIT
		  - Hit: Some sectors are cached.
		  - Missed: And the other are NOT cached.
		  - Hit part and missed part(s) are devided to different 'bio's.
		 **/
		/** [2] bio split point **/

		/** [3] Part 1: If some front sectors are missed */
		if(sector_idx_hit_first != 0)
		{
			bio_splited = bio_split(bio, (int)sector_idx_hit_first, GFP_ATOMIC, bio->bi_pool);
			if(unlikely(bio_splited == NULL))
			{
				hmb_debug("Unknown error");

				hmb_chain_multiple(hit_bio, hit_cnt, bio);
				hmb_chain_multiple(miss_bio, miss_cnt, bio);

				hmb_unlock(&flags);

				if(unlikely(!hmb_generic_make_request(hit_bio, hit_cnt)))
				{
					hmb_debug("Critical problem!");
				}
				if(unlikely(!hmb_generic_make_request(miss_bio, miss_cnt)))
				{
					hmb_debug("Critical problem!");
				}

				atomic64_add(hmb_get_current_time_ns() - t_start, &HMB_CTRL.t_overhead_buffering);
				return generic_make_request(bio);
			}

			bio_splited->hmb_urgency = bio->hmb_urgency;

			miss_bio[miss_cnt++] = bio_splited;

		}
		/** [3] **/
		/** [3] Part 2: Processing hit sector(s) **/
		/* If all remained sectors are hit */
		sector_num = bio_sectors(bio);
		if(sector_num_hits == sector_num)
		{
			bio_splited = bio; /* bio_splited for hit sectors */
		}
		/* If parts of remained sectors are hit */
		else
		{
			/* Detach hit sectors */
			bio_splited = bio_split(bio, (int)sector_num_hits, GFP_ATOMIC, bio->bi_pool);
			if(unlikely(bio_splited == NULL))
			{
				hmb_debug("Unknown error");

				hmb_chain_multiple(hit_bio, hit_cnt, bio);
				hmb_chain_multiple(miss_bio, miss_cnt, bio);

				hmb_unlock(&flags);

				if(unlikely(!hmb_generic_make_request(hit_bio, hit_cnt)))
				{
					hmb_debug("Critical problem!");
				}
				if(unlikely(!hmb_generic_make_request(miss_bio, miss_cnt)))
				{
					hmb_debug("Critical problem!");
				}

				atomic64_add(hmb_get_current_time_ns() - t_start, &HMB_CTRL.t_overhead_buffering);
				return generic_make_request(bio);
			}

			bio_splited->hmb_urgency = bio->hmb_urgency;
			/** [4] **/
		}

		/** [3] **/
		hit_bio[hit_cnt++] = bio_splited;

		if(sector_num_hits == sector_num)
		{
			if(unlikely(!hmb_WB_completion(hit_bio, hit_cnt, miss_bio, miss_cnt)))
			{
				//hmb_debug("<DEBUG> Failed to be buffering!");

				hmb_chain_multiple(hit_bio, hit_cnt-1, bio);
				hmb_chain_multiple(miss_bio, miss_cnt, bio);

				hmb_unlock(&flags);

				if(unlikely(!hmb_generic_make_request(hit_bio, hit_cnt-1)))
				{
					hmb_debug("Critical problem!");
				}
				if(unlikely(!hmb_generic_make_request(miss_bio, miss_cnt)))
				{
					hmb_debug("Critical problem!");
				}

				atomic64_add(hmb_get_current_time_ns() - t_start, &HMB_CTRL.t_overhead_buffering);
				return generic_make_request(bio);
			}

			hmb_endio(hit_bio, hit_cnt-1, miss_bio, miss_cnt, bio, true, false);

			hmb_unlock(&flags);

			atomic64_add(hmb_get_current_time_ns() - t_start, &HMB_CTRL.t_overhead_buffering);
			return BLK_STS_OK;
		}

		is_initial_loop = false;

		if(unlikely(hit_cnt >= HMB_BIO_NUMBER_MAX || miss_cnt >= HMB_BIO_NUMBER_MAX))
		{
			hmb_debug("# separated entries reached to limitation.");

			hmb_chain_multiple(hit_bio, hit_cnt, bio);
			hmb_chain_multiple(miss_bio, miss_cnt, bio);

			hmb_unlock(&flags);

			if(unlikely(!hmb_generic_make_request(hit_bio, hit_cnt)))
			{
				hmb_debug("Critical problem!");
			}
			if(unlikely(!hmb_generic_make_request(miss_bio, miss_cnt)))
			{
				hmb_debug("Critical problem!");
			}

			atomic64_add(hmb_get_current_time_ns() - t_start, &HMB_CTRL.t_overhead_buffering);
			return generic_make_request(bio);
		}

		/** [2] **/
		/** [1] **/
#ifdef HMB_DEBUG_TIME_DETAIL
		hmb_elapsed_time_acc(true, HMB_CTRL.t_WB_confirming_hitness);
#endif
	} /* while(hmb_WB_is_bufferable(...) */
#ifdef HMB_DEBUG_TIME_DETAIL
	hmb_elapsed_time_acc(false, HMB_CTRL.t_WB_confirming_hitness);
#endif

	miss_bio[miss_cnt++] = bio;

	if(unlikely(!hmb_WB_completion(hit_bio, hit_cnt, miss_bio, miss_cnt)))
	{
		//hmb_debug("<DEBUG> Failed to be buffering!");

		hmb_chain_multiple(hit_bio, hit_cnt, bio);
		hmb_chain_multiple(miss_bio, miss_cnt-1, bio);

		hmb_unlock(&flags);

		if(unlikely(!hmb_generic_make_request(hit_bio, hit_cnt)))
		{
			hmb_debug("Critical problem!");
		}
		if(unlikely(!hmb_generic_make_request(miss_bio, miss_cnt-1)))
		{
			hmb_debug("Critical problem!");
		}

		atomic64_add(hmb_get_current_time_ns() - t_start, &HMB_CTRL.t_overhead_buffering);
		return generic_make_request(bio);
	}

	hmb_endio(hit_bio, hit_cnt, miss_bio, miss_cnt-1, bio, true, false);

	hmb_unlock(&flags);

	atomic64_add(hmb_get_current_time_ns() - t_start, &HMB_CTRL.t_overhead_buffering);
	return BLK_STS_OK;
}
EXPORT_SYMBOL(hmb_buffering);

void hmb_table_nCached_inc(bool is_inc)
{
	HmbMeta *meta = HMB_CTRL.hmb_header;

	if(is_inc)
	{
#ifdef HMB_DEBUG_CLOSELY
		if(unlikely(meta->C__n_max_entries == meta->C__n_cached))
		{
			hmb_debug("Already # cached entries reached # max. cachable entries!");
			return;
		}
#endif
		meta->C__n_cached++;
	}
	else
	{
#ifdef HMB_DEBUG_CLOSELY
		if(unlikely(meta->C__n_cached == 0))
		{
			hmb_debug("Already # cache entries reached zero!");
			return;
		}
#endif
		meta->C__n_cached--;
	}

}
EXPORT_SYMBOL(hmb_table_nCached_inc);

void hmb_table_nDirty_inc(bool is_inc)
{
	HmbMeta *meta = HMB_CTRL.hmb_header;

	if(is_inc)
	{
#ifdef HMB_DEBUG_CLOSELY
		if(unlikely(meta->C__n_dirty == meta->C__n_max_entries))
		{
			hmb_debug("Already # dirty entries reached # cached entries!");
			return;
		}
#endif
		meta->C__n_dirty++;
	}
	else
	{
#ifdef HMB_DEBUG_CLOSELY
		if(unlikely(meta->C__n_dirty == 0))
		{
			hmb_debug("Already # dirty entries reached zero!");
			return;
		}
#endif
		meta->C__n_dirty--;
	}
}
EXPORT_SYMBOL(hmb_table_nDirty_inc);

bool hmb_WB_is_insertable(uint32_t n_entries)
{
	HmbMeta *meta = HMB_CTRL.hmb_header;

	if(meta->C__n_max_entries - meta->C__n_dirty < n_entries)
	{
		return false;
	}

#if 0
	if(hmb_RCOnly_sorted_get_head_idx() == HMB_HAS_NO_ENTRY)
	{
		return false;
	}
#endif

#if 0
	uint64_t dividend;
	uint32_t divisor, remainder;

	dividend = (meta->C__n_dirty + n_entries) * 100;
	divisor  = meta->C__n_cached + n_entries;

	remainder = do_div(dividend, divisor);

	if(unlikely((dividend >= meta->C__pctg_explicitFlush)))
	{
#if 0
		hmb_debug("<dividend>  Before: %lu, after: %lu", (meta->C__n_dirty + n_entries), dividend);
		hmb_debug("<divisor>   Before: %u, after: %u", (meta->C__n_cached + n_entries), divisor);
		hmb_debug("<remainder> %u", remainder);
#endif
		return false;
	}	
#endif

	return true;
}
EXPORT_SYMBOL(hmb_WB_is_insertable);

bool hmb_WB_is_bufferable(struct bio *b, u64 *sector_first, u64 *sector_last)
{
	sector_t sector_idx;
	u64 sector_num;

	u64 i;
	bool is_first;
	HmbSharedEnt *cache;

	sector_num = bio_sectors(b);
	sector_idx = b->bi_iter.bi_sector;

	*sector_first = 0;
	*sector_last = 0;
	is_first = true;

	for(i=0; i<sector_num; i++)
	{
		sector_t sector_idx_cur = sector_idx + i;
		uint64_t lpn_new = hmb_sector_to_lpn(sector_idx_cur);
		uint32_t hashed;
		HmbHeads idx_heads;
		uint64_t n_loops = 0;

		HmbSharedEnt *loop, *head;

		/* [2] Step 1. Hashing to get head's index */
		hashed = hmb_hash(lpn_new, HMB_CTRL.heads_hash_bit);
		/* [2] */

		/* [2] Step 2. Get an index of the 'heads' */
		idx_heads = *hmb_heads_get_by_idx(hashed);
		if(idx_heads == HMB_HAS_NO_ENTRY)
		{
			if(is_first == false)
			{
				*sector_last = i-1;
				return true;
			}

			continue;
		}
		/* [2] */

		cache = NULL;

		/* [2] Step 3-1. Get head entry of the LRU list for the "lpn_new" */
		head = hmb_table_get_by_idx(idx_heads);
		if(hmb_WB_valid_entry(head, lpn_new) == true)
		{
			cache = head;
		}
		/* [2] */
		/* [2] Step 3-2. Check: Has LRU list for the "lpn_new" cached entry? */
		else
		{
			for(loop = hmb_table_get_by_idx(head->e_next); \
					loop != head; \
					loop = hmb_table_get_by_idx(loop->e_next))
			{
				if(++n_loops > 100)
				{
					hmb_debug("#loops is larger than 100!");
					hmb_debug(" - from e_head: %u --> %u --> %u --> %u --> %u", \
							hmb_table_get_by_idx(head->e_prev)->e_prev, head->e_prev, \
							head->e_own, head->e_next, hmb_table_get_by_idx(head->e_next)->e_next);
					hmb_debug(" - from e_loop: %u --> %u --> %u --> %u --> %u", \
							hmb_table_get_by_idx(loop->e_prev)->e_prev, loop->e_prev, \
							loop->e_own, loop->e_next, hmb_table_get_by_idx(loop->e_next)->e_next);
					return false;
				}
				if(hmb_WB_valid_entry(loop, lpn_new) == true)
				{
					cache = loop;
					break;
				}
			} /* for(loop = &HMB_CTRL.table[head->e_next]; ... */
		} /* else of "hmb_WB_valid_entry(head, lpn_new)" */
		/* [2] */

		/* [2] If the LRU list has valid cache entry */
		if(cache != NULL)
		{
			if(is_first == true)
			{
				*sector_first = i;
				is_first = false;
			}
		}
		/* [2] */

		/* if(cache == NULL) */
		else
		{
			if(is_first == false)
			{
				*sector_last = i-1;
				return true;
			}
		}
	} /* for(i=0; i<sector_num; i++) */

	if(is_first == false)
	{
		*sector_last = i-1;
		return true;
	}

	return false;
}
EXPORT_SYMBOL(hmb_WB_is_bufferable);

bool hmb_WB_valid_entry(HmbSharedEnt *e, uint64_t lpn)
{
	//return (e->lpn == lpn && e->usable == 1);
	return (e->lpn == lpn);
}
EXPORT_SYMBOL(hmb_WB_valid_entry);
/** [1] **/

uint64_t hmb_sector_to_lpn(uint64_t sector_idx)
{
	return sector_idx >> (HMB_CTRL.cache_unit_bits - 9);
}
EXPORT_SYMBOL(hmb_sector_to_lpn);

uint32_t hmb_sector_to_internal_idx(uint64_t sector_idx)
{
	uint64_t lpn = hmb_sector_to_lpn(sector_idx);
	uint64_t lpn_to_sec = lpn << (HMB_CTRL.cache_unit_bits - 9);

	return (uint32_t)(sector_idx - lpn_to_sec);
}
EXPORT_SYMBOL(hmb_sector_to_internal_idx);

void hmb_fastIO_data_copy(struct bio *bio, bool for_write)
{
	unsigned short bio_v_idx;
	uint64_t remainder_hmb, remainder_bio_v_cur, remainder_sector;
	uint64_t written_hmb, written_bio_v_cur;
	void *bio_v_cur_mapped = NULL;
	struct bio_vec *bio_v, *bio_v_cur;

	bio_v = bio->bi_io_vec;
	bio_v_idx = bio->bi_iter.bi_idx;
	bio_v_cur = &bio_v[bio_v_idx];
	written_bio_v_cur = bio->bi_iter.bi_bvec_done;
	remainder_bio_v_cur = bio_v_cur->bv_len - written_bio_v_cur;

	bio_v_cur_mapped = page_address(bio_v_cur->bv_page);

	written_hmb = 0;
	remainder_hmb = HMB_CTRL.fastIO_data_ST_unit;

	remainder_sector = ((uint64_t)bio_sectors(bio)) << 9;

	do   
	{
		if(remainder_hmb < remainder_bio_v_cur) /* if remainder_hmb has the smallest number */
		{
			if(for_write)
			{
				memcpy(hmb_fastIO_get_data(written_hmb), \
						bio_v_cur_mapped + bio_v_cur->bv_offset + written_bio_v_cur, \
						remainder_hmb);
			}
			else
			{
				memcpy(bio_v_cur_mapped + bio_v_cur->bv_offset + written_bio_v_cur, \
						hmb_fastIO_get_data(written_hmb), \
						remainder_hmb);
			}

			written_hmb += remainder_hmb;
			written_bio_v_cur += remainder_hmb;

			remainder_bio_v_cur -= remainder_hmb;
			remainder_sector -= remainder_hmb;
			remainder_hmb = HMB_CTRL.fastIO_data_ST_unit;
		} /* if(remainder_hmb < remainder_bio_v_cur) */

		else /* if (remainder_hmb >= remainder_bio_v_cur) --> if remainder_bio_v_cur has the smallest number */
		{
			if(for_write)
			{
				memcpy(hmb_fastIO_get_data(written_hmb), \
						bio_v_cur_mapped + bio_v_cur->bv_offset + written_bio_v_cur, \
						remainder_bio_v_cur);
			}
			else
			{
				memcpy(bio_v_cur_mapped + bio_v_cur->bv_offset + written_bio_v_cur, \
						hmb_fastIO_get_data(written_hmb), \
						remainder_bio_v_cur);
			}

			written_hmb += remainder_bio_v_cur;

			remainder_hmb -= remainder_bio_v_cur;
			remainder_sector -= remainder_bio_v_cur;

			if(remainder_hmb == 0)
			{
				remainder_hmb = HMB_CTRL.fastIO_data_ST_unit;
			}

			if(remainder_sector != 0)
			{
				++bio_v_idx;
				bio_v_cur = &bio_v[bio_v_idx];
				remainder_bio_v_cur = bio_v_cur->bv_len;
				written_bio_v_cur = 0;

				if(unlikely((bio_v_cur_mapped = page_address(bio_v_cur->bv_page)) == NULL))
				{
					hmb_debug("Failed to get mapped virtual memory address of a page included in the bio.");
				}
			}
		} /* else of "if(remainder_hmb < remainder_bio_v_cur)" */
	} while (remainder_sector > 0);
}
EXPORT_SYMBOL(hmb_fastIO_data_copy);

uint64_t hmb_fastIO_get_occupiedRatio(uint64_t qid)
{
	return 100 * atomic64_read(&HMB_accNum_diff[qid]) / atomic64_read(&HMB_accNum_sqSize[qid]);
}
EXPORT_SYMBOL(hmb_fastIO_get_occupiedRatio);

HmbSplitTable* hmb_fastIO_data_ST_get_by_idx(uint32_t idx)
{
	return &(HMB_CTRL.fastIO_data_ST[idx]);
}
EXPORT_SYMBOL(hmb_fastIO_data_ST_get_by_idx);

void *hmb_fastIO_get_data(uint64_t innerOffset)
{
	HmbSplitTable *st;
	uint64_t seg, offset;
	void *addr;

	seg = innerOffset / HMB_CTRL.fastIO_data_ST_unit;
	offset = innerOffset % HMB_CTRL.fastIO_data_ST_unit;

	st = hmb_fastIO_data_ST_get_by_idx(seg);
	addr = HMB_CTRL.hmb_addr[st->seg_id] + st->offset;

	return addr + offset;
}
EXPORT_SYMBOL(hmb_fastIO_get_data);
