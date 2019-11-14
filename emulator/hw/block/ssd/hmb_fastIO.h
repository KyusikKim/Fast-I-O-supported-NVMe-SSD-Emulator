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

#ifndef __SSD__HMB_FASTIO_H
#define __SSD__HMB_FASTIO_H

#include "hmb_debug.h"
#include "hmb_types.h"

#include <stdint.h>
#include <stdbool.h>

HmbFastIOMeta *hmb_fastIO_get_meta(bool for_write);
void *hmb_fastIO_get_data(bool for_write, uint64_t internalOffset);

bool hmb_fastIO_init(uint64_t max_data_bytes);

HmbSplitTable *hmb_fastIO_ST_get_by_idx(bool for_write, uint32_t idx);

#endif /* #ifndef __SSD__HMB_FASTIO_H__ */

