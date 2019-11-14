/**
   #Group:  SSLab <sswlab.kw.ac.kr>
   #Author: Kyusik Kim <kks@kw.ac.kr> and Taeseok Kim <tskim@kw.ac.kr>

   #Project Name: HMB-supported DRAM-less SSD Simulator
   #Module Name: Read-ahead Cache
   #File Name: m_cache.h

   #Version: v0.1
   #Last Modified: April 9, 2018

   #Description:
     Functions, definitions and structures for read-ahead Cache

     (1) for caching contents 
       --> hmb_spaceMgmt_RC_caching()
     (2) for supporting hash table
	   --> hmb_spaceMgmt_*_hash*(), ...
 	 (3) for managing the cache
       --> hmb_spaceMgmt_*() excepts for contents mentioned in '(1)' and '(2)
**/

/**
    #Revision History
	  v0.1
	    - First draft
**/

#include "hmb_fastIO.h"
#include "hmb_types.h" /* HmbFastIOCtrl, HmbFastIOMeta, ... */
#include "hmb.h" /* hmb_calloc() */

#include "ssd.h" /* SSD_WRITE(), SSD_READ() */

#include "hw/block/block.h"
#include "sysemu/block-backend.h"

#include "qemu/timer.h" /* qemu_clock_get_ns() */
#include <time.h>

HmbFastIOCtrl HMB_FASTIO_CTRL;

HmbFastIOMeta *hmb_fastIO_get_meta(bool for_write)
{
	if(for_write)
	{
		return (HmbFastIOMeta *)(HMB_FASTIO_CTRL.meta->w);
	}
	return (HmbFastIOMeta *)(HMB_FASTIO_CTRL.meta->r);
}

void *hmb_fastIO_get_data(bool for_write, uint64_t internalOffset)
{
	uint64_t seg, offset;

	seg = internalOffset / HMB_FASTIO_CTRL.data_ST_unit;
	offset = internalOffset % HMB_FASTIO_CTRL.data_ST_unit;

	if(for_write)
	{
		return ((void *)HMB_FASTIO_CTRL.data_mapped[seg]->w) + offset;
	}
	return ((void *)HMB_FASTIO_CTRL.data_mapped[seg]->r) + offset;
}

bool hmb_fastIO_init(uint64_t max_data_bytes)
{
	uint64_t i;

	HmbMeta *meta_w;
	HmbMapInfo *m_data_ST, *m_meta;
	HmbSegEnt *e_data_ST, *e_meta;

	HMB_FASTIO_CTRL.enabled = true;

	/** Allocated metadata area for FAST I/O in HMB **/
	if((HMB_FASTIO_CTRL.meta = \
			   	hmb_calloc(sizeof(HmbFastIOMeta))) == NULL)
	{
		hmb_debug("Failed to allocate HMB space for Fast I/O metadata");
		HMB_FASTIO_CTRL.enabled = false;
		return false;
	}

	/** Determine unit of the split table and number of the table to describe data area for Fast I/O **/
	HMB_FASTIO_CTRL.data_ST_unit = 1048576; /* Split unit: 1MB */
	HMB_FASTIO_CTRL.max_data_size_bytes = max_data_bytes;
	HMB_FASTIO_CTRL.data_ST_num = max_data_bytes / HMB_FASTIO_CTRL.data_ST_unit;
	if(max_data_bytes % HMB_FASTIO_CTRL.data_ST_unit)
	{
		HMB_FASTIO_CTRL.data_ST_num++;
	}

	/** Allocate the split table for the data area for FAST I/O in HMB **/
	if((HMB_FASTIO_CTRL.data_ST = \
				hmb_calloc(sizeof(HmbSplitTable) * HMB_FASTIO_CTRL.data_ST_num)) == NULL)
	{
		hmb_debug("Failed to allocate HMB space for Fast I/O metadata");
		HMB_FASTIO_CTRL.enabled = false;
		return false;
	}

	if((HMB_FASTIO_CTRL.data_mapped = (HmbMappedAddr **)calloc( \
					HMB_FASTIO_CTRL.data_ST_num, \
					sizeof(HmbMappedAddr *))) == NULL)
	{
		hmb_debug("Failed to allocate heap space for Fast I/O metadata");
		HMB_FASTIO_CTRL.enabled = false;
		return false;
	}

	hmb_debug("********** Mapped information for the Fast I/O data: ");
	for(i=0; i<HMB_FASTIO_CTRL.data_ST_num; i++)
	{
		HmbMapInfo *m_data;
		HmbSegEnt *e_data;

		if((HMB_FASTIO_CTRL.data_mapped[i] = \
					hmb_calloc(HMB_FASTIO_CTRL.data_ST_unit)) == NULL)
		{
			hmb_debug("Failed to allocate HMB space for Fast I/O data");
			HMB_FASTIO_CTRL.enabled = false;
			return false;
		}

		if((m_data = hmb_mapInfo_search(HMB_FASTIO_CTRL.data_mapped[i])) == NULL)
		{    
			hmb_debug("Invalid relationship.");
			HMB_FASTIO_CTRL.enabled = false;
			return false;
		}    
		if((e_data = hmb_get_segEnt_by_id(false, m_data->entry_id)) == NULL)
		{    
			hmb_debug("Invalid relationship.");
			HMB_FASTIO_CTRL.enabled = false;
			return false;
		}    

		hmb_fastIO_ST_get_by_idx(true, i)->seg_id = e_data->segment_id;
		hmb_fastIO_ST_get_by_idx(true, i)->offset = e_data->offset;

		hmb_debug("  - [%3lu] seg: %3d, offset: 0x%X", i, \
				hmb_fastIO_ST_get_by_idx(false, i)->seg_id, \
				hmb_fastIO_ST_get_by_idx(false, i)->offset);
	}

	if((m_data_ST = hmb_mapInfo_search(HMB_FASTIO_CTRL.data_ST)) == NULL)
	{    
		hmb_debug("Invalid relationship.");
		return false;
	}    
	if((e_data_ST = hmb_get_segEnt_by_id(false, m_data_ST->entry_id)) == NULL)
	{    
		hmb_debug("Invalid relationship.");
		return false;
	}    

	if((m_meta = hmb_mapInfo_search(HMB_FASTIO_CTRL.meta)) == NULL)
	{    
		hmb_debug("Invalid relationship.");
		return false;
	}    

	if((e_meta = hmb_get_segEnt_by_id(false, m_meta->entry_id)) == NULL)
	{    
		hmb_debug("Invalid relationship.");
		return false;
	}    

	meta_w = hmb_meta_get(true);

	meta_w->FASTIO__meta_seg_id = e_meta->segment_id;
	meta_w->FASTIO__meta_offset = e_meta->offset;

	meta_w->FASTIO__data_ST_seg_id = e_data_ST->segment_id;
	meta_w->FASTIO__data_ST_offset = e_data_ST->offset;

	meta_w->FASTIO__data_ST_unit = HMB_FASTIO_CTRL.data_ST_unit;
	meta_w->FASTIO__data_ST_num = HMB_FASTIO_CTRL.data_ST_num;
	meta_w->FASTIO__data_max_bytes = max_data_bytes;

	return true;
}

HmbSplitTable *hmb_fastIO_ST_get_by_idx(bool for_write, uint32_t idx) 
{
	if(for_write)
	{    
		return &(((HmbSplitTable *)(HMB_FASTIO_CTRL.data_ST->w))[idx]);
	}    
	return &(((HmbSplitTable *)(HMB_FASTIO_CTRL.data_ST->r))[idx]);
}
