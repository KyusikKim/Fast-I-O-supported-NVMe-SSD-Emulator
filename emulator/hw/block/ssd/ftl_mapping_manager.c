// File: ftl_mapping_manager.c
// Date: 2014. 12. 03.
// Author: Jinsoo Yoo (jedisty@hanyang.ac.kr)
// Copyright(c)2014
// Hanyang University, Seoul, Korea
// Embedded Software Systems Laboratory. All right reserved

#include "common.h"
#include "hmb_types.h"
#include "hmb_utils.h"
#include "hmb_config.h"
#include "hmb_debug.h"

//int64_t* mapping_table;
void* block_table_start;

void INIT_MAPPING_TABLE(struct ssdstate *ssd)
{
    struct ssdconf *sc = &(ssd->ssdparams);
	FILE* fp;

	/* Allocation Memory for Mapping Table */
	ssd->mapping_table = (int64_t*)calloc(sc->PAGE_MAPPING_ENTRY_NB, sizeof(int64_t));
	if(ssd->mapping_table == NULL){
		printf("ERROR[%s] Calloc mapping table fail\n", __FUNCTION__);
		return;
	}

	/* Initialization Mapping Table */
	
	/* If mapping_table.dat file exists */
	hmb_debug("Start to restore mapping table information...");

	fp = fopen("./data/mapping_table.dat","r");
	if(fp != NULL){
		if(fread(ssd->mapping_table, sizeof(int64_t), sc->PAGE_MAPPING_ENTRY_NB, fp) != sc->PAGE_MAPPING_ENTRY_NB)
		{
			int i;	

			for(i=0;i<sc->PAGE_MAPPING_ENTRY_NB;i++){
				ssd->mapping_table[i] = -1;
			}
			hmb_debug("  - Failed to read expected all mapping table entries.");
			hmb_debug("  - All entries were cleared.");
		}

		else
		{
			hmb_debug("  - All entries were restored.");
		}
		fclose(fp);
	}
	else {	
		int i;	

		for(i=0;i<sc->PAGE_MAPPING_ENTRY_NB;i++){
			ssd->mapping_table[i] = -1;
		}

		hmb_debug("  - Failed to open file for mapping table.");
		hmb_debug("  - All entries were cleared.");
	}
}

void TERM_MAPPING_TABLE(struct ssdstate *ssd)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int64_t PAGE_MAPPING_ENTRY_NB = sc->PAGE_MAPPING_ENTRY_NB;
	FILE* fp;
	int64_t ret;

	hmb_debug("Start to store mapping table information...");

	fp = fopen("./data/mapping_table.dat","w");
	if(fp == NULL){
		//printf("ERROR[%s] File open fail\n", __FUNCTION__);
		hmb_debug("  - Failed to open/make file for mapping table.");
		hmb_debug("  - Any entries were stored.");
		//return;
	}

	else
	{
		/* Write the mapping table to file */
		if((ret = fwrite(ssd->mapping_table, sizeof(int64_t),PAGE_MAPPING_ENTRY_NB,fp)) != PAGE_MAPPING_ENTRY_NB)
		{
			hmb_debug("  - Failed to write all mapping table entries. (%ld/%ld)", ret, PAGE_MAPPING_ENTRY_NB);
			hmb_debug("  - Any entries were stored.");
			fclose(fp);
			unlink("./data/mapping_table.dat");
		}

		else
		{
			hmb_debug("  - All entries were stored.");
			fclose(fp);
		}
	}

	/* Free memory for mapping table */
	free(ssd->mapping_table);
}

int64_t GET_MAPPING_INFO(struct ssdstate *ssd, int64_t lpn)
{
    int64_t *mapping_table = ssd->mapping_table;
	int64_t ppn = mapping_table[lpn];

	return ppn;
}

int GET_NEW_PAGE(struct ssdstate *ssd, int mode, int mapping_index, int64_t* ppn)
{
	struct ssdconf *sc = &(ssd->ssdparams);
	int BLOCK_NB = sc->BLOCK_NB;
	int PAGE_NB = sc->PAGE_NB;


	empty_block_entry* curr_empty_block;

#ifdef HMB_DEBUGGING_TIME
	hmb_timeDbg_record(&HMB_DEBUG_TIME_PER_REQUEST.of_femu__get_empty_block, true);
#endif
	curr_empty_block = GET_EMPTY_BLOCK(ssd, mode, mapping_index);
#ifdef HMB_DEBUGGING_TIME
	hmb_timeDbg_record(&HMB_DEBUG_TIME_PER_REQUEST.of_femu__get_empty_block, false);
#endif

	/* If the flash memory has no empty block,
	   Get empty block from the other flash memories */
	if(mode == VICTIM_INCHIP && curr_empty_block == NULL){
		/* Try again */
#ifdef HMB_DEBUGGING_TIME
		hmb_timeDbg_record(&HMB_DEBUG_TIME_PER_REQUEST.of_femu__get_empty_block, true);
#endif
		curr_empty_block = GET_EMPTY_BLOCK(ssd, VICTIM_OVERALL, mapping_index);
#ifdef HMB_DEBUGGING_TIME
		hmb_timeDbg_record(&HMB_DEBUG_TIME_PER_REQUEST.of_femu__get_empty_block, false);
#endif
	}

	if(curr_empty_block == NULL){
		printf("ERROR[%s] fail\n", __FUNCTION__);
		return FAIL;
	}

	*ppn = curr_empty_block->phy_flash_nb*BLOCK_NB*PAGE_NB \
		   + curr_empty_block->phy_block_nb*PAGE_NB \
		   + curr_empty_block->curr_phy_page_nb;

	curr_empty_block->curr_phy_page_nb += 1;

	return SUCCESS;
}

int UPDATE_OLD_PAGE_MAPPING(struct ssdstate *ssd, int64_t lpn)
{
	int64_t old_ppn;

#ifdef FTL_MAP_CACHE
	old_ppn = CACHE_GET_PPN(lpn);
#else
	old_ppn = GET_MAPPING_INFO(ssd, lpn);
#endif

	if(old_ppn == -1){
#ifdef FTL_DEBUG
		printf("[%s] New page \n", __FUNCTION__);
#endif
		return SUCCESS;
	}
	else{
		UPDATE_BLOCK_STATE_ENTRY(ssd, CALC_FLASH(ssd, old_ppn), CALC_BLOCK(ssd, old_ppn), CALC_PAGE(ssd, old_ppn), INVALID);
		UPDATE_INVERSE_MAPPING(ssd, old_ppn, -1);
	}

	return SUCCESS;
}

int UPDATE_NEW_PAGE_MAPPING(struct ssdstate *ssd, int64_t lpn, int64_t ppn)
{
    int64_t *mapping_table = ssd->mapping_table;

	/* Update Page Mapping Table */
#ifdef FTL_MAP_CACHE
	CACHE_UPDATE_PPN(lpn, ppn);
#else
	mapping_table[lpn] = ppn;
#endif

	/* Update Inverse Page Mapping Table */
	UPDATE_BLOCK_STATE_ENTRY(ssd, CALC_FLASH(ssd, ppn), CALC_BLOCK(ssd, ppn), CALC_PAGE(ssd, ppn), VALID);
	UPDATE_BLOCK_STATE(ssd, CALC_FLASH(ssd, ppn), CALC_BLOCK(ssd, ppn), DATA_BLOCK);
	UPDATE_INVERSE_MAPPING(ssd, ppn, lpn);

	return SUCCESS;
}

unsigned int CALC_FLASH(struct ssdstate *ssd, int64_t ppn)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int BLOCK_NB = sc->BLOCK_NB;
    int PAGE_NB = sc->PAGE_NB;
    int FLASH_NB = sc->FLASH_NB;

	unsigned int flash_nb = (ppn/PAGE_NB)/BLOCK_NB;

	if(flash_nb >= FLASH_NB){
		printf("ERROR[%s] flash_nb %u\n", __FUNCTION__,flash_nb);
	}
	return flash_nb;
}

unsigned int CALC_BLOCK(struct ssdstate *ssd, int64_t ppn)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int BLOCK_NB = sc->BLOCK_NB;
    int PAGE_NB = sc->PAGE_NB;

	unsigned int block_nb = (ppn/PAGE_NB)%BLOCK_NB;

	if(block_nb >= BLOCK_NB){
		printf("ERROR[%s] block_nb %u\n",__FUNCTION__, block_nb);
	}
	return block_nb;
}

unsigned int CALC_PAGE(struct ssdstate *ssd, int64_t ppn)
{
    struct ssdconf *sc = &(ssd->ssdparams);
    int PAGE_NB = sc->PAGE_NB;

	unsigned int page_nb = ppn%PAGE_NB;

	return page_nb;
}
