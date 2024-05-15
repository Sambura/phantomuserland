/**
 *
 * Phantom OS
 *
 * Copyright (C) 2005-2010 Dmitry Zavalishin, dz@dz.ru
 *
 * Paging: queue, FSCK
 *
 *
**/


#define DEBUG_MSG_PREFIX "pager"
#include "debug_ext.h"
#define debug_level_flow 0
#define debug_level_error 10
#define debug_level_info 10

#include <phantom_assert.h>
#include <errno.h>

#include <ph_string.h>
#include <ph_malloc.h>

#include <kernel/vm.h>
#include <kernel/stats.h>
#include <kernel/page.h>

#include <phantom_disk.h>

#include "pager.h"
#include "pagelist.h"

#if PAGING_PARTITION
#include <disk.h>
#endif

// TODO : killme ? probably, recheck and execute 
#define USE_SYNC_IO 0

#define free_reserve_size  32


static hal_mutex_t              pager_freelist_mutex;
static phantom_disk_superblock  superblock;


#if !PAGING_PARTITION
static int _DEBUG = 1;


static hal_mutex_t              pager_mutex;

static void                	pager_io_done(void);
static void 			page_device_io_final_callback(void);


static int                      pagein_is_in_process = 0;
static int                      pageout_is_in_process = 0;

static paging_device            *pdev;

static pager_io_request         *pager_current_request = 0;

static pager_io_request         *pagein_q_start = 0;    // points to first (will go now) page
static pager_io_request         *pagein_q_end = 0;      // points to last page
//static int                        pagein_q_len;

static pager_io_request         *pageout_q_start = 0;
static pager_io_request         *pageout_q_end = 0;
//static int                      pageout_q_len;


#endif

#if !USE_SYNC_IO
static disk_page_io             freelist_io;
static disk_page_io             superblock_io;
#else

static union
{
    struct phantom_disk_blocklist free_head;
    char __fill[PAGE_SIZE];
} u;

#endif

static int                      need_fsck;


static int                      freelist_inited = 0;
static disk_page_no_t           free_reserve[free_reserve_size]; // for interrupt time allocs
static int                      free_reserve_n;

static disk_page_no_t           active_freelist_head = 0;
static disk_page_no_t           active_freelist_root = 0;
static disk_page_no_t           active_free_start = 0;

// in-memory temporary blocklist
struct phantom_mem_blocklist {
    disk_page_no_t      list[128];
    int                 used;
    struct phantom_mem_blocklist *next;
};

static struct phantom_mem_blocklist *freed_list_blocks;


static disk_page_no_t           sb_default_page_numbers[] = DISK_STRUCT_SB_OFFSET_LIST;

// Note: some of these declarations were moved here from pager.h since they are not
// thread-safe, and require mutex to be taken. No reason to expose these calls

static int pager_alloc_page(disk_page_no_t *out_page_no);
static void pager_release_free_reserve(void);
/*
    Allocates disk blocks and adds them to reserve list until it is full. Allocated
    blocks come from either active freelist, or active `free_start` if the freelist 
    is emtpy.
    
    Reserve list of free disk blocks is a short array providing easy access
    to some available to use disk blocks.

    Should be called with `pager_freelist_mutex` taken
*/
static void pager_refill_free_reserve(void);
/**
 * Writes the contents of the current active freelist head to disk, and sets the 
 * given disk block as a new active head. Allows active freelist head to be 0, in
 * which case the disk write is skipped
 * 
 * Should be called with `pager_freelist_mutex` taken
 */
static void pager_extend_active_free_list( disk_page_no_t );

#if !PAGING_PARTITION


// called when io is done on page device
static void page_device_io_final_callback()
{
    pager_io_done();
};




//---------------------------------------------------------------------------

int
pager_can_grow() // can I grow pagespace
{
    //if(!pdev)
        return 0;
    //else            return pdev->can_grow();
}

#endif


phantom_disk_superblock *
pager_superblock_ptr()
{
    return &superblock;
}

// call under lock
static void pager_free_blocklist_page(disk_page_no_t blk) {
    if (blk == 0) return;

    if (freed_list_blocks->used >= __countof(freed_list_blocks->list)) {
        struct phantom_mem_blocklist *new_node = ph_calloc(1, sizeof(struct phantom_mem_blocklist));
        new_node->next = freed_list_blocks;
        freed_list_blocks = new_node;
    }
    
    freed_list_blocks->list[freed_list_blocks->used++] = blk;
}

void pager_free_blocklist_page_locked(disk_page_no_t blk) {
    hal_mutex_lock(&pager_freelist_mutex);
    pager_free_blocklist_page(blk);
    hal_mutex_unlock(&pager_freelist_mutex);
}

#if PAGING_PARTITION

// static
phantom_disk_partition_t *pp;

void partition_pager_init(phantom_disk_partition_t *p)
{
    pp = p;
    assert(pp);

    hal_mutex_init(&pager_freelist_mutex, "PagerFree");

#if !USE_SYNC_IO
    disk_page_io_init(&freelist_io);
    disk_page_io_init(&superblock_io);
    disk_page_io_allocate(&superblock_io);

    freed_list_blocks = ph_calloc(1, sizeof(struct phantom_mem_blocklist));
    if (freed_list_blocks == NULL) panic("Out of memory");
#endif

    {
        phantom_disk_format(&superblock, 0x50000, "Unnamed Phantom System");
        phantom_sync_write_block(pp, &superblock, 0, 1);
        ph_printf("SUPERBLOCK WRITTEN");
        hal_sleep_msec(60 * 1000);
    }

    SHOW_FLOW0( 1, "Pager get superblock" );
    pager_get_superblock();

    //phantom_dump_superblock(&superblock);    getchar();

    pager_fast_fsck();

    if( need_fsck )
    {
        panic("I don't have any fsck yet. I must die.\n");
        pager_long_fsck();
    }

    //superblock.fs_is_clean = 0; // mark as dirty
    pager_update_superblock();
}


void
pager_finish()
{
    // XXX : make sure everything is free?
    pager_commit_active_free_list();
    superblock.fs_is_clean = 1; // mark as clean
    pager_update_superblock();
    //disk_page_io_finish(&superblock_io);
}

// TODO implement for partitioning code
int pager_dequeue_from_pageout(pager_io_request *rq)
{
    return !disk_dequeue( pp, rq );
}

// TODO implement for partitioning code
void pager_raise_request_priority(pager_io_request *rq)
{
    disk_raise_priority( pp, rq );
}

void pager_enqueue_for_pagein ( pager_io_request *rq )
{
    assert(rq->phys_page);
    if( rq->flag_pagein ) panic("enqueue_for_pagein: page is already on pager queue (in)");
    if( rq->flag_pageout ) panic("enqueue_for_pagein: page is already on pager queue (out)");

    rq->flag_pagein = 1;
    rq->next_page = 0;

    STAT_INC_CNT( STAT_CNT_PAGEIN );

    disk_enqueue( pp, rq );

}

void pager_enqueue_for_pagein_fast ( pager_io_request *rq )
{
    rq->flag_urgent = 1;
    pager_enqueue_for_pagein ( rq );
}


void pager_enqueue_for_pageout( pager_io_request *rq )
{
    assert(rq->phys_page);
    if( rq->flag_pagein ) panic("enqueue_for_pageout: page is already on pager queue (in)");
    if( rq->flag_pageout ) panic("enqueue_for_pageout: page is already on pager queue (out)");

    rq->flag_pageout = 1;
    rq->next_page = 0;

    STAT_INC_CNT( STAT_CNT_PAGEOUT );

    disk_enqueue( pp, rq );
}


void pager_enqueue_for_pageout_fast( pager_io_request *rq )
{
    rq->flag_urgent = 1;
    pager_enqueue_for_pageout( rq );
}

errno_t pager_fence()
{
    return disk_fence( pp );
}



#else
void
pager_init(paging_device * device)
{
    pagein_q_start = pagein_q_end = 0;
    //pagein_q_len = 0;
    pageout_q_start = pageout_q_end = 0;
    //pageout_q_len = 0;
    pagein_is_in_process = pageout_is_in_process = 0;

    hal_mutex_init(&pager_mutex, "Pager Q");
    hal_mutex_init(&pager_freelist_mutex, "PagerFree");

    disk_page_io_init(&freelist_io);
    disk_page_io_init(&superblock_io);
    disk_page_io_allocate(&superblock_io);

    pdev = device;

    if(_DEBUG) hal_printf("Pager get superblock");
    pager_get_superblock();
    if(_DEBUG) hal_printf(" ...DONE\n");

    //phantom_dump_superblock(&superblock);    getchar();


    pager_fast_fsck();

    if( need_fsck )
        {
        panic("I don't have any fsck yet. I must die.\n");
        pager_long_fsck();
        }


    //superblock.fs_is_clean = 0; // mark as dirty
    pager_update_superblock();

}

void
pager_finish()
{
    // BUG! Kick all stuff out - especially disk_page_cachers
    pager#_flush_free_list();

    superblock.fs_is_clean = 1; // mark as clean
    pager_update_superblock();
    disk_page_io_finish(&superblock_io);
}





void pager_debug_print_q()
{
    if(!_DEBUG) return;

    pager_io_request *last = pagein_q_start;

    for( ; last; last = last->next_page)
    {
        hal_printf("\nreq = 0x%X, next = 0x%X, disk = %d\n", last, last->next_page, last->disk_page);
    }
}














// called under sema!
void pager_start_io() // called to start new io
{
    if( pagein_is_in_process || pageout_is_in_process ) return;
    if( pagein_is_in_process && pageout_is_in_process ) panic("double io in start_io");

    if(_DEBUG) hal_printf("pager start io\n");

    // pagein has absolute priority as system response time depends on it - right?
    if(pagein_q_start)
    {
        pager_current_request = pagein_q_start;
        pagein_q_start = pager_current_request->next_page;
        if(pagein_q_start == 0) pagein_q_end = 0;

        pagein_is_in_process = 1;
        paging_device_start_read_rq( pdev, pager_current_request, page_device_io_final_callback );
    }
    else if(pageout_q_start)
    {
        pager_current_request = pageout_q_start;
        pageout_q_start = pager_current_request->next_page;
        if(pageout_q_start == 0) pageout_q_end = 0;

        pageout_is_in_process = 1;
        paging_device_start_write_rq( pdev, pager_current_request, page_device_io_final_callback );
    }
}




static void pager_io_done() // called after io is complete
{
    //hal_printf("pager_stop_io... ");
    hal_mutex_lock(&pager_mutex);

    if( (!pagein_is_in_process) && (!pageout_is_in_process) ) panic("stop when no io in pager");
    if( pagein_is_in_process    &&   pageout_is_in_process  ) panic("double io in stop_io");

    pager_io_request *last = pager_current_request;
//set_dr7(0); // turn off all debug registers

    STAT_INC_CNT( last->flag_pageout ? STAT_CNT_PAGEOUT : STAT_CNT_PAGEIN );

    if(pagein_is_in_process)
    {
        pager_debug_print_q();

        last->flag_pagein = 0;
        if(last->pager_callback)
        {
            hal_mutex_unlock(&pager_mutex);
            last->pager_callback( last, 0 );
            hal_mutex_lock(&pager_mutex);
        }
        pagein_is_in_process = 0;
    }

    if(pageout_is_in_process)
    {
        last->flag_pageout = 0;
        if(last->pager_callback)
        {
            hal_mutex_unlock(&pager_mutex);
            last->pager_callback( last, 1 );
            hal_mutex_lock(&pager_mutex);
        }
        pageout_is_in_process = 0;
    }

    pager_start_io();
    hal_mutex_unlock(&pager_mutex);
}





void pager_enqueue_for_pagein ( pager_io_request *p )
{
    if(p->phys_page == 0)
        panic("pagein to zero address");

    /*
    hal_printf("ENQ 4 pagein req  0x%X  VA 0x%X PA 0x%X disk %d, Q START = 0x%X\n",
               p,
               p->virt_addr,
               p->phys_page,
               p->disk_page,
               pagein_q_start
              ); */

    if( p->flag_pagein || p->flag_pageout ) panic("enqueue_for_pagein: page is already on pager queue");

    hal_mutex_lock(&pager_mutex);

    p->flag_pagein = 1;
    p->next_page = 0;
    if( pagein_q_start == 0 ) { pagein_q_start = p; pagein_q_end = p; /*start_io();*/ }
    else { pagein_q_end->next_page = p; pagein_q_end = p; }

    //hal_printf("ENQ 4 pagein p->next_page 0x%X\n",               p->next_page              );

    pager_start_io();

    hal_mutex_unlock(&pager_mutex);
}

void pager_enqueue_for_pagein_fast ( pager_io_request *p )
{
#if 1
    pager_enqueue_for_pagein( p );
#else
    if( p->flag_pagein || p->flag_pageout ) panic("enqueue_for_pagein_fast: page is already on pager queue");

    hal_mutex_lock(&pager_mutex);

    p->flag_pagein = 1;
    if( pagein_q_start == 0 ) { pagein_q_start = p; pagein_q_end = p; p->next_page = 0; }
    else { p->next_page = pagein_q_start; pagein_q_start = p; }
    pager_start_io();

    hal_mutex_unlock(&pager_mutex);
#endif
}

void pager_enqueue_for_pageout( pager_io_request *p )
{
    if(p->phys_page == 0)
        panic("pageout from zero address");
    /*hal_printf("ENQ 4 pageout req  0x%X  VA 0x%X PA 0x%X disk %d, Q START = 0x%X\n",
      p,
      p->virt_addr,
      p->phys_page,
      p->disk_page,
      pagein_q_start
      ); */
    if( p->flag_pagein || p->flag_pageout ) panic("enqueue_for_pageout: page is already on pager queue");

    hal_mutex_lock(&pager_mutex);

    p->flag_pageout = 1;
    p->next_page = 0;
    if( pageout_q_start == 0 ) { pageout_q_start = p; pageout_q_end = p; }
    else { pageout_q_end->next_page = p;  pageout_q_end = p; }
    pager_start_io();

    hal_mutex_unlock(&pager_mutex);
}


void pager_enqueue_for_pageout_fast( pager_io_request *p )
{
#if 1
    pager_enqueue_for_pageout( p );
#else
    if( p->flag_pagein || p->flag_pageout ) panic("enqueue_for_pageout_fast: page is already on pager queue");

    hal_mutex_lock(&pager_mutex);

    p->flag_pageout = 1;
    if( pageout_q_start == 0 ) { pageout_q_start = p; pageout_q_end = p; p->next_page = 0; }
    else { p->next_page = pageout_q_start;  pageout_q_start = p; }
    pager_start_io();

    hal_mutex_unlock(&pager_mutex);
#endif
}


void pager_raise_request_priority(pager_io_request *p)
{
    hal_mutex_lock(&pager_mutex);

    if (pager_current_request != p && pageout_q_start != p)
    {
        pager_io_request *i;
        for (i = pageout_q_start; i; i = i->next_page)
        {
            if (i->next_page == p)
            {
                i->next_page = p->next_page;
                if (pageout_q_end == p)
                    pageout_q_end = i;
                p->next_page = pageout_q_start;
                pageout_q_start = p;
                break;
            }
        }
    }

    hal_mutex_unlock(&pager_mutex);
}

int pager_dequeue_from_pageout(pager_io_request *p)
{
    int dequeued = 0;
    hal_mutex_lock(&pager_mutex);

    if (pageout_q_start == p)
    {
        pageout_q_start = p->next_page;
        if (!pageout_q_start)
            pageout_q_end = 0;
        p->flag_pageout = 0;
        dequeued = 1;
    }
    else if (pager_current_request != p)
    {
        pager_io_request *i;
        for (i = pageout_q_start; i; i = i->next_page)
        {
            if (i->next_page == p)
            {
                i->next_page = p->next_page;
                if (pageout_q_end == p)
                    pageout_q_end = i;

                p->flag_pageout = 0;
                dequeued = 1;
                break;
            }
        }
    }

    hal_mutex_unlock(&pager_mutex);

    return dequeued;
}

errno_t pager_fence()
{
    SHOW_ERROR0( 0, "No fence!" );
    return ENODEV;
}


#endif

// ---------------------------------------------------------------------------
//
// Superblock works
//
// ---------------------------------------------------------------------------

#if USE_SYNC_IO

void write_blocklist_sure( struct phantom_disk_blocklist *list, disk_page_no_t addr  )
{
#if PAGING_PARTITION
    char buf[PAGE_SIZE];

    * ((struct phantom_disk_blocklist *)buf) = *list;
    assert(!phantom_sync_write_block( pp, buf, addr, 1 ));
#else
    (void) list;
    (void) addr;
    panic("no old code here");
#endif
}

void read_blocklist_sure( struct phantom_disk_blocklist *list, disk_page_no_t addr  )
{
#if PAGING_PARTITION
    char buf[PAGE_SIZE];

    assert(!phantom_sync_read_block( pp, buf, addr, 1 ));
    *list = * ((struct phantom_disk_blocklist *)buf);
#else
    (void) list;
    (void) addr;
    panic("no old code here");
#endif
}

void write_freehead_sure( disk_page_no_t addr )
{
    write_blocklist_sure( &u.free_head, addr );
}

void read_freehead_sure()
{
    read_blocklist_sure( &u.free_head, superblock.free_list );
}

errno_t write_superblock(phantom_disk_superblock *in, disk_page_no_t addr )
{
#if PAGING_PARTITION
    char buf[PAGE_SIZE];

    * ((phantom_disk_superblock *)buf) = *in;
    return phantom_sync_write_block( pp, buf, addr, 1 );
#else
    (void) in;
    (void) addr;
    panic("no old code here");
    return EIO;
#endif
}

#endif

errno_t read_uncheck_superblock(phantom_disk_superblock *out, disk_page_no_t addr )
{
#if USE_SYNC_IO
    char buf[PAGE_SIZE];

    errno_t rc = phantom_sync_read_block( pp, buf, addr, 1 );
    if( rc ) return rc;

    *out = * ((phantom_disk_superblock *)buf);
    return 0;
#else
    disk_page_io sb;

    disk_page_io_init( &sb );
    errno_t rc = disk_page_io_load_sync(&sb, addr);
    if( rc ) return rc;

    *out = * ((phantom_disk_superblock *)disk_page_io_data(&sb));

    disk_page_io_finish( &sb );
    return 0;
#endif
}


errno_t read_check_superblock(phantom_disk_superblock *out, disk_page_no_t addr )
{
#if USE_SYNC_IO
    char buf[PAGE_SIZE];

    errno_t rc = phantom_sync_read_block( pp, buf, addr, 1 );
    if( rc ) return rc;

    if( phantom_calc_sb_checksum( (phantom_disk_superblock *)buf ))
        {
        *out = * ((phantom_disk_superblock *)buf);
        return 0;
        }

    return ENOENT;
#else
    disk_page_io sb;

    disk_page_io_init( &sb );
    errno_t rc = disk_page_io_load_sync(&sb, addr);
    if( rc ) return rc;

    if( phantom_calc_sb_checksum( (phantom_disk_superblock *)disk_page_io_data(&sb) ))
        {
        *out = * ((phantom_disk_superblock *)disk_page_io_data(&sb));

        disk_page_io_finish( &sb );
        return 0;
        }

    disk_page_io_finish( &sb );
    return ENOENT;
#endif
}

int find_superblock(
    phantom_disk_superblock *out,
    disk_page_no_t *pages, int n_pages,
    disk_page_no_t exclude, disk_page_no_t *where )
{
    int i;
    for( i = 0; i < n_pages; i++ )
    {
        disk_page_no_t curr = pages[i];
        if( curr == 0 || curr == exclude )
            continue;

        hal_printf("Looking for superblock at %d... ", curr );

        if( !read_check_superblock( out, curr ) )
        {
            *where = curr;
            hal_printf("Found superblock at %d\n", curr );
            return 1;
        }
    }

    hal_printf("Superblock not found\n" );
    return 0;
}

// Does `sb_default_page_numbers` contain the given disk block?
static int is_default_sb_block(disk_page_no_t page) {
    for (int i = 0; i < __countof(sb_default_page_numbers); i++) {
        if (sb_default_page_numbers[i] == page) return 1;
    }

    return 0;
}

void
pager_fix_incomplete_format()
{
    disk_page_no_t     sb2a, sb3a, free, max;

    // TODO: Use some more sophisticated selection alg.
    sb2a = sb_default_page_numbers[1];
    sb3a = sb_default_page_numbers[2];

    superblock.sb2_addr = sb2a;
    superblock.sb3_addr = sb3a;

    // find a block for freelist
    free = superblock.disk_start_page;
    while(is_default_sb_block(free)) free++;

    max = sb_default_page_numbers[0];
    for (int j = 0; j < __countof(sb_default_page_numbers); j++)
        max = max > sb_default_page_numbers[j] ? max : sb_default_page_numbers[j];
    max = max > free ? max : free;
    max++; // cover upper block itself. now max is one page above

    // blocks, not covered by freelist start with this one
    superblock.free_start = active_free_start = max;
    superblock.free_list = 0;       // none yet - read by pager_extend_active_free_list

    pager_extend_active_free_list( free );

    disk_page_no_t i;
    for( i = superblock.disk_start_page; i < max; i++ )
    {
        if(i == free || is_default_sb_block(i)) continue;

        pager_put_to_free_list_locked(i);
    }

    freelist_inited = 1;
    pager_commit_active_free_list();

    if( 0 == superblock.object_space_address )
        superblock.object_space_address = PHANTOM_AMAP_START_VM_POOL;

    pager_update_superblock();
}


void
pager_get_superblock()
{
    if (pager_try_get_superblock_from(sb_default_page_numbers[0]) == 0) return;

    SHOW_INFO0(3, "Failed to load default root superblock, trying secondary");

    // if we're here - primary superblock is damaged, rewrite it ASAP
    if (pager_try_get_superblock_from(sb_default_page_numbers[3]) == 0) {
        *((phantom_disk_superblock *)disk_page_io_data(&superblock_io)) = superblock;

        if (disk_page_io_save_sync(&superblock_io, sb_default_page_numbers[0]))
            panic( "Superblock primary write error!" );
        return;
    }

    panic("Failed to load superblock");
}

#if !USE_SYNC_IO
int
pager_try_get_superblock_from(disk_page_no_t root_block)
{
    disk_page_no_t     sb_found_page_numbers[4];

    phantom_disk_superblock     root_sb;
    int                         root_sb_cs_ok;

    phantom_disk_superblock     sb1;
    int                         sb1_ok = 0;

    phantom_disk_superblock     sb2;
    int                         sb2_ok = 0;

    SHOW_FLOW( 4, "Trying to load superblock at %d...", root_block);

    errno_t rc = read_uncheck_superblock(&root_sb, root_block);
    if (rc) SHOW_ERROR( 0, "sb read err @%d", root_block);

    root_sb_cs_ok = phantom_calc_sb_checksum( &root_sb );

    SHOW_FLOW( 0, "root sb sys name = '%.*s', checksum %s\n",
               DISK_STRUCT_SB_SYSNAME_SIZE, root_sb.sys_name,
               root_sb_cs_ok ? "ok" : "wrong"
             );


    sb_found_page_numbers[0] = root_sb.sb2_addr;
    sb_found_page_numbers[1] = root_sb.sb3_addr;

    disk_page_no_t     found_sb1;
    disk_page_no_t     found_sb2;

    SHOW_FLOW0( 2, "Find sb1");
    sb1_ok = find_superblock( &sb1, sb_found_page_numbers, 2, 0, &found_sb1 );

    if( sb1_ok )
    {
        SHOW_FLOW0( 2, "Find sb2");
        sb2_ok = find_superblock( &sb2, sb_found_page_numbers, 2, found_sb1, &found_sb2  );
    }

    SHOW_FLOW( 7, "sb1 status %d, sb2 - %d, sb3 - %d\n", root_sb_cs_ok, sb1_ok, sb2_ok );
    SHOW_FLOW( 7, "root sb sb2 addr %d, sb3 addr %d, free start %d, free list %d, fs clean %d\n",
               root_sb.sb2_addr, root_sb.sb3_addr,
               root_sb.free_start, root_sb.free_list,
               root_sb.fs_is_clean
             );

    if(
       root_sb_cs_ok && (!sb1_ok) && !(sb2_ok) &&
       root_sb.sb2_addr == 0 && root_sb.sb3_addr == 0 &&
       root_sb.free_start != 0 && root_sb.free_list == 0 &&
       root_sb.fs_is_clean
      )
    {
        SHOW_FLOW0( 0, "incomplete filesystem found, fixing...");
        superblock = root_sb;
        pager_fix_incomplete_format();
        SHOW_FLOW0( 0, "incomplete format fixed");

        phantom_fsck( 0 );

        return 0;
    }

    if(
       root_sb_cs_ok && sb1_ok && sb2_ok &&
       superblocks_are_equal(&root_sb, &sb1) &&
       superblocks_are_equal(&root_sb, &sb2)
      )
    {
        if( (root_sb.version >> 16) != DISK_STRUCT_VERSION_MAJOR )
        {
            hal_printf("Disk FS major version number is incorrect: 0x%X\n", root_sb.version >> 16 );
            return -1;
        }

        if( (root_sb.version & 0xFFFF) > DISK_STRUCT_VERSION_MINOR )
        {
            hal_printf("Disk FS minor version number is too big: 0x%X\n", root_sb.version & 0xFFFF );
            return -1;
        }

        if( (root_sb.version & 0xFFFF) < DISK_STRUCT_VERSION_MINOR )
            hal_printf(" Warning: Disk FS minor version number is low: 0x%X, mine is 0x%X...", root_sb.version & 0xFFFF, DISK_STRUCT_VERSION_MINOR );

        hal_printf(" all 3 superblocks are found and good, ok.\n");
        superblock = root_sb;

        if( !superblock.fs_is_clean )
        {
            need_fsck = 1;
            hal_printf("FS marked as dirty, need to check.\n");
        }
        else
        {
            phantom_fsck( 0 );
            return 0;
        }
    }

    // Note: might as well return -1 here, but decided to leave the segment below
    //      in case it could be actually used for something

    // something is wrong
    need_fsck = 1;
    SHOW_ERROR0( 0, " (need fsck)...");
    SHOW_ERROR0( 0, " default superblock copies are wrong, looking for more...");

    // XXX : what exactly is this for? it either fails or fails... sad

    size_t n_sb_default_page_numbers = sizeof(sb_default_page_numbers)/sizeof(disk_page_no_t); 
    if( !sb1_ok )
        sb1_ok = find_superblock( &sb1, sb_default_page_numbers,
                                  n_sb_default_page_numbers, 0, &found_sb1 );

    if( sb1_ok )
    {
        sb_found_page_numbers[2] = sb1.sb2_addr;
        sb_found_page_numbers[3] = sb1.sb3_addr;

        sb2_ok = find_superblock( &sb2, sb_found_page_numbers, 4, found_sb1, &found_sb2  );
        if( !sb2_ok )
            sb2_ok = find_superblock( &sb2, sb_default_page_numbers,
                                      n_sb_default_page_numbers, found_sb1, &found_sb2  );
    }

    (void) sb2_ok;

    return -1;
}
#endif

static void get_copy_dests(disk_page_no_t sb1, disk_page_no_t sb2, 
    disk_page_no_t *sb1_out, disk_page_no_t *sb2_out)
{
    disk_page_no_t free_slots[2];
    size_t n_sb_default_page_numbers = sizeof(sb_default_page_numbers)/sizeof(disk_page_no_t); 
    int free_cnt = 0;

    for (int i = 0; i < n_sb_default_page_numbers; i++) {
        if (i == 0 || i == 3) continue; // root and secondary

        if (sb_default_page_numbers[i] != sb1 && sb_default_page_numbers[i] != sb2)
            free_slots[free_cnt++] = sb_default_page_numbers[i];

        if (free_cnt >= 2) break;
    }

    assert(free_cnt == 2);

    SHOW_INFO(11, "New selected sb copy dests: %d and %d", free_slots[0], free_slots[1]);

    *sb1_out = free_slots[0];
    *sb2_out = free_slots[1];
}

void
pager_update_superblock()
{
    errno_t rc;

    SHOW_FLOW0( 0, " updating superblock...");

#if !USE_SYNC_IO
    assert(!(superblock_io.req.flag_pagein || superblock_io.req.flag_pageout));
#endif

    // change destinations for copy superblocks
    get_copy_dests(superblock.sb2_addr, superblock.sb3_addr, &superblock.sb2_addr, &superblock.sb3_addr);
    phantom_calc_sb_checksum( &superblock );

#if USE_SYNC_IO
    rc = write_superblock( &superblock, sb_default_page_numbers[0] );
    if( rc ) SHOW_ERROR0( 0, "Superblock 0 (main) write error!" ); // TODO rc


    if( need_fsck )
    {
        SHOW_ERROR0( 0, " disk is insane, will update root copy only (who called me here, btw?)...");
    }
    else
    {
        rc = write_superblock( &superblock, superblock.sb2_addr );
        if( rc ) SHOW_ERROR0( 0, "Superblock 1 write error!" ); // TODO rc

        rc = write_superblock( &superblock, superblock.sb3_addr );
        if( rc ) SHOW_ERROR0( 0, "Superblock 1 write error!" ); // TODO rc

        SHOW_FLOW0( 0, "saved all 3");
    }
#else
    *((phantom_disk_superblock *)disk_page_io_data(&superblock_io)) = superblock;
    
    if (!need_fsck) { // XXX : why is this?
        rc = disk_page_io_save_sync(&superblock_io, superblock.sb2_addr);
        if( rc ) panic( "Superblock 1 write error!" );
        rc = disk_page_io_save_sync(&superblock_io, superblock.sb3_addr);
        if( rc ) panic( "Superblock 2 write error!" );
    }

    // if secondary write is interrupted, root superblock is still good
    rc = disk_page_io_save_sync(&superblock_io, sb_default_page_numbers[3]); // save secondary copy
    if( rc ) panic( "Superblock secondary write error!" );

    // if root write is interrupted, we already have secondary + 2 copies
    rc = disk_page_io_save_sync(&superblock_io, sb_default_page_numbers[0]); // save secondary copy
    if( rc ) panic( "Superblock root write error!" );
    SHOW_FLOW0( 0, " saved all 3");

    if( need_fsck ) // XXX : what is this?
    {
        SHOW_ERROR0( 0, " disk is insane, will update root copy only (who called me here, btw?)...\n");
    }

#endif
}

// ---------------------------------------------------------------------------
//
// Free list works
//
// ---------------------------------------------------------------------------

//const int            pager_free_reserve_size = 30;


// Call under lock
void
pager_extend_active_free_list( disk_page_no_t fp )
{
    struct phantom_disk_blocklist freelist;

    ph_memset( &freelist, 0, sizeof(freelist) );

    freelist.head.magic = DISK_STRUCT_MAGIC_FREEHEAD;
    freelist.head.used = 0;
    freelist.head.next = active_freelist_head;
    freelist.head._reserved = 0;

    struct phantom_disk_blocklist *list = (struct phantom_disk_blocklist*)disk_page_io_data(&freelist_io);

#if USE_SYNC_IO
    u.free_head = freelist;
    //errno_t rc = phantom_sync_write_block( pp, &freelist, fp, 1 );
    //if( rc ) SHOW_ERROR0( 0, "empty freelist block write error!" ); // TODO rc
    //write_blocklist_sure( &freelist, fp );
    write_freehead_sure( fp );
#else
    if (active_freelist_head) {
        errno_t rc = disk_page_io_save_sync(&freelist_io, active_freelist_head);
        if (rc) panic("pager_extend_active_free_list");
    }

    *list = freelist;
    active_freelist_head = fp;
#endif
}

void pager_free_blocklist_pages(void) {
    hal_mutex_lock(&pager_freelist_mutex);
    struct phantom_mem_blocklist blocklist = *freed_list_blocks;
    ph_memset(freed_list_blocks, 0, sizeof(struct phantom_mem_blocklist));
    hal_mutex_unlock(&pager_freelist_mutex);

    struct phantom_mem_blocklist *current = &blocklist;
    while (current) {
        for (int i = 0; i < current->used; i++) {
            pager_free_page(current->list[i]);
        }

        struct phantom_mem_blocklist *prev = current;
        current = current->next;
        // do not free stack memory :)
        if (prev != &blocklist) ph_free(prev);
    }
}

void pager_commit_active_free_list(void)
{
    hal_mutex_lock(&pager_freelist_mutex);
    if (active_freelist_head == 0) panic("No active head");

    // to not leak reserved blocks
    pager_release_free_reserve();

#if USE_SYNC_IO
    //errno_t rc = phantom_sync_write_block( pp, &u.free_head, superblock.free_list, 1 );
    //if( rc ) SHOW_ERROR0( 0, "empty freelist block write error!" ); // TODO rc
    write_freehead_sure( superblock.free_list );
#else
    errno_t rc = disk_page_io_save_sync(&freelist_io, active_freelist_head);
    if( rc ) SHOW_ERROR0( 0, "freelist block write error!" ); // TODO rc
    
    pager_free_blocklist_page(superblock.free_list);
    superblock.free_list = active_freelist_head;
    superblock.free_start = active_free_start;

    active_freelist_root = ((struct phantom_disk_blocklist *)disk_page_io_data(&freelist_io))->head.next;

#endif
    pager_refill_free_reserve();
    if (pager_alloc_page(&active_freelist_head) == 0) panic("Out of disk");

    hal_mutex_unlock(&pager_freelist_mutex);
}

// call with lock
static void
pager_put_to_free_list( disk_page_no_t free_page )
{
    SHOW_FLOW( 8, "Put to free %d", free_page);

    if( need_fsck )
    {
        SHOW_ERROR0( 1, " disk is insane, put_to_free_list skipped...");
        return;
    }

    if (active_free_start + 1 == free_page) {
        active_free_start++;
        return;
    }

#if USE_SYNC_IO
    struct phantom_disk_blocklist *list = &u.free_head;
#else
    struct phantom_disk_blocklist *list = (struct phantom_disk_blocklist *) disk_page_io_data(&freelist_io);
#endif

    if( list->head.used >= N_REF_PER_BLOCK ) {
#if USE_SYNC_IO
            //errno_t rc = phantom_sync_write_block( pp, &u.free_head, superblock.free_list, 1 );
            //if( rc ) panic( "empty freelist block write error!" );
            write_freehead_sure( superblock.free_list );

            pager_format_empty_free_list_block( free_page );
            superblock.free_list = free_page;
#else
            pager_extend_active_free_list(free_page);
#endif
    } else { list->list[list->head.used++] = free_page; }
}

void pager_put_to_free_list_locked(disk_page_no_t free_page) {
    hal_mutex_lock(&pager_freelist_mutex);
    pager_put_to_free_list(free_page);
    hal_mutex_unlock(&pager_freelist_mutex);
}

// call in lock
static void pager_release_free_reserve(void) {
    SHOW_INFO(10, "Releasing free reserve: %d blocks", free_reserve_n);

    while(free_reserve_n) {
        disk_page_no_t page_no = free_reserve[--free_reserve_n];

        assert(((unsigned long)page_no) >= ((unsigned long)superblock.disk_start_page));
        assert(!is_default_sb_block(page_no));

        pager_put_to_free_list(page_no);
    }
}

void
pager_init_free_list()
{
    hal_mutex_lock(&pager_freelist_mutex);

    if (freelist_inited)
    {
        SHOW_FLOW0( 1, "already done - skipped");

        hal_mutex_unlock(&pager_freelist_mutex);
        return;
    }

    SHOW_FLOW0( 2, "start");

    if( need_fsck )
        panic("disk is insane, can't init freelist...");

    if(superblock.free_list == 0 )
        panic("superblock.free_list == 0, can't init freelist...");

#if USE_SYNC_IO
    //errno_t rc = phantom_sync_read_block( pp, &u.free_head, superblock.free_list, 1 );
    //if( rc ) panic( "empty freelist block read error!" );
    read_freehead_sure();
#else
    errno_t rc = disk_page_io_load_sync(&freelist_io, superblock.free_list);
    if( rc ) panic("Freelist IO error");
#endif

    struct phantom_disk_blocklist *list = (struct phantom_disk_blocklist *) disk_page_io_data(&freelist_io);

    freelist_inited = 1;
    active_free_start = superblock.free_start;
    active_freelist_root = list->head.next;
    if(pager_alloc_page(&active_freelist_head) == 0) panic("Out of disk");

    hal_mutex_unlock(&pager_freelist_mutex);
    SHOW_FLOW0( 2, " ...DONE");
}


int
pager_interrupt_alloc_page(disk_page_no_t *out)
{
    SHOW_FLOW0( 11, "Interrupt Alloc page... ");
    assert(freelist_inited);

    hal_mutex_lock(&pager_freelist_mutex);

    if( free_reserve_n )
        {
        *out = free_reserve[--free_reserve_n];
        // TODO: Schedule a DPC to refill ASAP!
        hal_mutex_unlock(&pager_freelist_mutex);
        return 1;
        }

    hal_mutex_unlock(&pager_freelist_mutex);
    return 0;
}

void
pager_refill_free_reserve()
{
    SHOW_FLOW0( 10, "Refill free reserve... ");
#if USE_SYNC_IO
    struct phantom_disk_blocklist *list = &u.free_head;
#else
    struct phantom_disk_blocklist *list = (struct phantom_disk_blocklist *) disk_page_io_data(&freelist_io);
#endif

    while( free_reserve_n < free_reserve_size )
        {
        if( list->head.used > 0 )
            free_reserve[free_reserve_n++] = list->list[--list->head.used];
        else {
            if (list->head.next == 0) {
                SHOW_FLOW0( 10, "Using the last blocklist... ");
                break; // that was last one, we will not kill freelist head
            }

            int move_active_root = 0;
            if (list->head.next != active_freelist_root) {
                free_reserve[free_reserve_n++] = active_freelist_head;
                active_freelist_head = list->head.next;
            } else {
                pager_free_blocklist_page(list->head.next);
                move_active_root = 1;
            }

#if USE_SYNC_IO
            //errno_t rc = phantom_sync_read_block( pp, &u.free_head, superblock.free_list, 1 );
            //if( rc ) panic( "empty freelist block read error!" );
            read_freehead_sure();

#else
            errno_t rc = disk_page_io_load_sync(&freelist_io, list->head.next);
            if( rc ) panic("Freelist IO error");
#endif

            if( list->head.magic != DISK_STRUCT_MAGIC_FREEHEAD ||
                list->head.used > N_REF_PER_BLOCK ||
                list->head._reserved != 0
                )
                {
                ph_printf("Free list head values are insane, need fsck\n");
                list->head.used = 0;
                list->head.next = active_freelist_root = 0;
                list->head.magic = 0;
                // BUG! Need some way out of here. Reboot is ok, btw.
                // We are possibly still able to do a snap because
                // superblock.free_start allocations are possibly available
                // (btw we better try to reclaim superblock.free_start space
                // in ph_free()), and we can find out if we can make one
                // more snap...
                break;
                }
            
            if (move_active_root) active_freelist_root = list->head.next;
            }
        }

    while( free_reserve_n < free_reserve_size && active_free_start < superblock.disk_page_count )
        free_reserve[free_reserve_n++] = active_free_start++;
    
    if (active_free_start >= superblock.disk_page_count - 100){
        SHOW_ERROR(0, "Running out of free space! %x %x", active_free_start, superblock.disk_page_count);
    }
}

int64_t pager_calculate_free_block_count(void) {
    int64_t start_free = superblock.disk_page_count - superblock.free_start;
    int64_t list_free = 0, list_nodes = 0;

    struct disk_page_io disk_io;
    disk_page_io_init(&disk_io);
    struct phantom_disk_blocklist *list = disk_page_io_data(&disk_io);
    if (disk_page_io_load_sync(&disk_io, superblock.free_list)) {
        SHOW_ERROR0(0, "Disk load error"); return -1;
    }

    do {
        if( list->head.magic != DISK_STRUCT_MAGIC_FREEHEAD ||
            list->head.used > N_REF_PER_BLOCK ||
            list->head._reserved != 0
        ) {
            SHOW_ERROR0(0, "Freelist values are insane");
            disk_page_io_finish(&disk_io);
            return -1;
        }

        list_nodes++;
        list_free += list->head.used;

        if (list->head.next == 0) break;
        errno_t rc = disk_page_io_load_sync(&disk_io, list->head.next);
        if (rc) {
            SHOW_ERROR0(0, "Disk load error");
            disk_page_io_finish(&disk_io);
            return -1;
        }
    } while (list_free + start_free < superblock.disk_page_count);

    assert(list->head.next == 0);
    disk_page_io_finish(&disk_io);
    
    int64_t true_free = list_free + start_free;
    int64_t total_free = true_free + list_nodes;
    int percentage = 1000 * total_free / superblock.disk_page_count;

    SHOW_INFO(9, "Disk usage stats: %d blocks free (%d.%d%% : %d true [%d startfree, %d in freelist], %d nodes)", 
        total_free, percentage / 10, percentage % 10, true_free, start_free, list_free, list_nodes);

    return total_free;
}

void
pager_refill_free()
{
    SHOW_FLOW0( 3, "pager_refill_free... ");
    assert(freelist_inited);

    hal_mutex_lock(&pager_freelist_mutex);
    pager_refill_free_reserve();
    hal_mutex_unlock(&pager_freelist_mutex);
}

// call under lock
static int
pager_alloc_page(disk_page_no_t *out_page_no)
{
    SHOW_FLOW0( 11, "Alloc page... ");

    pager_refill_free_reserve();

    if( free_reserve_n )
    {
        *out_page_no = free_reserve[--free_reserve_n];

        SHOW_FLOW( 11, " ...alloc DONE: %d", *out_page_no);
        STAT_INC_CNT(STAT_PAGER_DISK_ALLOC);
        return 1;
    }

    SHOW_FLOW0( 11, " ...alloc FAILED");
    return 0;
}

int
pager_alloc_page_locked(disk_page_no_t *out_page_no)
{
    hal_mutex_lock(&pager_freelist_mutex);
    assert(freelist_inited);
    int ret = pager_alloc_page(out_page_no);
    hal_mutex_unlock(&pager_freelist_mutex);

    return ret;
}

void
pager_free_page( disk_page_no_t page_no )
{
    SHOW_FLOW0( 11, "Free page... ");
    STAT_INC_CNT(STAT_PAGER_DISK_FREE);

    if( ((unsigned long)page_no) < ((unsigned long)superblock.disk_start_page))
        panic("Free: freeing block below disk start: %ld < %ld", (unsigned long)page_no, (unsigned long)superblock.disk_start_page );

    if (is_default_sb_block(page_no))
    {
        SHOW_ERROR( 0, "tried to free possible superblock @%d", page_no );
        panic("tried to free superblock");
    }

    pager_put_to_free_list_locked( page_no );
}


// ---------------------------------------------------------------------------
//
// FS check
//
// ---------------------------------------------------------------------------


// general FS sanity check
int
pager_fast_fsck()
{
    pager_init_free_list();

    hal_mutex_lock(&pager_freelist_mutex);
#if USE_SYNC_IO
    struct phantom_disk_blocklist *flist = &u.free_head;
#else
    struct phantom_disk_blocklist *flist = (struct phantom_disk_blocklist *) disk_page_io_data(&freelist_io);
#endif
    if( flist->head.magic != DISK_STRUCT_MAGIC_FREEHEAD )
        {
        need_fsck = 1;
        SHOW_ERROR0( 0, "Free list magic is wrong, need fsck");
        hal_mutex_unlock(&pager_freelist_mutex);
        return 0;
        }

    if(
       flist->head.used > N_REF_PER_BLOCK ||
       flist->head._reserved != 0
       )
        {
        need_fsck = 1;
        SHOW_ERROR0( 0, "Free list head values are insane, need fsck\n");
        hal_mutex_unlock(&pager_freelist_mutex);
        return 0;
        }

    hal_mutex_unlock(&pager_freelist_mutex);
    // check (and invalidate?) pagelist heads here, etc.

    return 1;
}


int
pager_long_fsck()
{
    return 0;
}




