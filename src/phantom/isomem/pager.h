/**
 *
 * Phantom OS
 *
 * Copyright (C) 2005-2010 Dmitry Zavalishin, dz@dz.ru
 *
 * Pager (virtual memory/snapshot engine) IO interface.
 *
**/

#ifndef PAGER_H
#define PAGER_H

#include <phantom_disk.h>

#include "paging_device.h"
#include <pager_io_req.h>
#include "pagelist.h"
#include <spinlock.h>
#include <hal.h>


/* TODO: need queue sort to optimize head movement */


//void      pager_stop_io(); // called after io is complete
void        pager_free_io_resources(pager_io_request *req);

// Load superblock from disk (from default disk block, see DISK_STRUCT_SB_OFFSET_LIST)
// Panics if failed to load good superblock and failed to repair it
void        pager_get_superblock(void);
// Try to load root superblock from the specified disk block
// Return 0 if root superblock and its copies are fine, or if repair was successful
int         pager_try_get_superblock_from(disk_page_no_t root_block);
/* Write superblock and its copies to disk */
void        pager_update_superblock(void);

void        pager_fix_incomplete_format(void);
int         pager_fast_fsck(void);
int         pager_long_fsck(void);

/**
 * Adds the specified disk block to the active freelist (or increments active 
 * free_start, if applicable). If the current active list head is full, it is 
 * flushed to disk, and the given disk block is used as a new active freelist head.
 */
void        pager_put_to_free_list_locked( disk_page_no_t );
/**
 * Performs some sanity checks and loads freelist head specified in superblock to
 * memory. Allocates a new active freelist head.
 */
void        pager_init_free_list(void);
/**
 * Writes current active freelist head to disk and writes both active freelist head
 * and active_free_start to superblock. Allocates a new active freelist head.
 * 
 * When this function returns, the previous active freelist is fully commited to 
 * disk and will become valid after the superblock is saved to disk.
 */
void        pager_commit_active_free_list(void);
/**
 * Marks a disk block as a blocklist page to be freed. The block will actually be 
 * freed by a call to `pager_free_blocklist_pages()`. This is done to aboid blocks
 * containing blocklist nodes to be overwritten with new data too soon.
 * 
 * XXX : since the list of free blocklist blocks is stored in memory, these blocks
 * can be lost / leaked.
 */
void        pager_free_blocklist_page_locked(disk_page_no_t blk);
/**
 * Actually free all the blocklist blocks marked to be freed by 
 * `pager_free_blocklist_page_locked()`. Frees blocks using `pager_free_page()`
 */
void        pager_free_blocklist_pages(void);
/**
 * Calculates the number of free disk blocks (for last snapshot)
 * May take some time (and IO) to complete.
 * 
 * TODO: ensure this is thread safe? do we need thread safety at all?
 */
int64_t     pager_calculate_free_block_count(void);


// NB! On pager_init() call pagefile must be good and healthy,
// so if one needs some check and fix, it must be done
// before.

#if PAGING_PARTITION
#include <disk.h>
void partition_pager_init(phantom_disk_partition_t *p);
#else
void        pager_init(paging_device * device); // {  }
#endif

void        pager_finish(void);


int         pager_interrupt_alloc_page(disk_page_no_t *out);
int         pager_alloc_page_locked(disk_page_no_t *out);
void        pager_free_page( disk_page_no_t );

int         pager_can_grow(); // can I grow pagespace


void        pager_enqueue_for_pagein ( pager_io_request *p );
void        pager_enqueue_for_pagein_fast ( pager_io_request *p );
void        pager_enqueue_for_pageout( pager_io_request *p );
void        pager_enqueue_for_pageout_fast( pager_io_request *p );
void        pager_raise_request_priority(pager_io_request *p);
int         pager_dequeue_from_pageout(pager_io_request *p);

errno_t     pager_fence(void);

//void                pager_io_done(void);

long        pager_object_space_address(void);

phantom_disk_superblock *        pager_superblock_ptr();

void        pager_refill_free(void);

//! called to start new io
//! called under sema!
void        pager_start_io();



void        phantom_fsck(int do_rebuild );


void        phantom_free_snap(
        disk_page_no_t old_snap_start,
        disk_page_no_t curr_snap_start,
        disk_page_no_t new_snap_start,
        disk_page_no_t snap_reading_start
);


#endif // PAGER_H

