/**
 *
 * Phantom OS
 *
 * Copyright (C) 2005-2009 Dmitry Zavalishin, dz@dz.ru
 *
 * Fast and dirty garbage collection
 *
**/

#define DEBUG_MSG_PREFIX "vm.gc"
#include <debug_ext.h>
#define debug_level_flow 10
#define debug_level_error 10
#define debug_level_info 10

#include <vm/alloc.h>
#include <vm/internal.h>
#include <vm/object_flags.h>
#include <vm/object.h>

#include "../isomem/vm_map.h"
#include "../isomem/pager.h"
#include "../isomem/pagelist.h"

#include <kernel/stats.h>
#include <kernel/atomic.h>
#include <kernel/config.h>

#include <arch/arch-page.h>

#include <ph_malloc.h>

static pvm_object_t shift_ptr(pvm_object_t o, long long shift)
{
    return (pvm_object_t)((char*)o + shift);
}

static unsigned char  gc_flags_last_generation = 0;

static char* load_snap() {
    unsigned long page_count = N_OBJMEM_PAGES + 1;
    SHOW_FLOW0(1, "Started");

    disk_page_no_t snap_start = 0;

    if (pager_superblock_ptr()->last_snap != 0) {
        hal_printf("-- Use last snap\n");
        snap_start = pager_superblock_ptr()->last_snap;
    }
    else if (pager_superblock_ptr()->prev_snap != 0) {
        hal_printf("-- Missing last snap, use previous snap\n");
        snap_start = pager_superblock_ptr()->prev_snap;
    }

    char* snapshot = 0;

    if (snap_start == 0) {
        hal_printf("\n!!! No pagelist to load !!!\n");
    }
    else {
        hal_printf("Loading pagelist from %d...\n", snap_start);

        pagelist loader;
        pagelist_init(&loader, snap_start, 0, DISK_STRUCT_MAGIC_SNAP_LIST);
        pagelist_seek(&loader);


        disk_page_no_t curr_block;
        snapshot = ph_calloc(page_count, PAGE_SIZE);
        unsigned int np;

        for (np = 0; np < page_count; np++) {
            if (!pagelist_read_seq(&loader, &curr_block)) {
                ph_printf("\n!!! Incomplete pagelist !!!\n");
                //panic("Incomplete pagelist\n");
                break;
            }

            if (curr_block == 0) {
                continue;
            }

            disk_page_io sb;
            disk_page_io_init(&sb);
            errno_t rc = disk_page_io_load_sync(&sb, curr_block);

            if (rc) {
                panic("failed to load snapshot in gc\n");
            }

            ph_memcpy(snapshot, disk_page_io_data(&sb), PAGE_SIZE);
            snapshot += PAGE_SIZE;
        }

        pagelist_finish(&loader);
    }

    return snapshot;
}

static void mark_tree(pvm_object_storage_t *p, long long shift);

static pvm_object_storage_t **collect_unmarked(char *start, long long shift);

static int free_unmarked(pvm_object_storage_t **to_free);

static void gc_process_children(gc_iterator_call_t f, pvm_object_storage_t *p, void *arg);

static void mark_tree_o(pvm_object_t o, void *arg);

void run_gc_on_snap() {
    // synchonization?

    gc_flags_last_generation++; // bump generation
    if (gc_flags_last_generation == 0)  gc_flags_last_generation++;  // != 0 'cause allocation reset gc_flags to zero

    //phantom_virtual_machine_threads_stopped++; // pretend we are stopped
    //TODO: refine synchronization

    // First pass - tree walk, mark visited.
    // Root is always used. All other objects, including pvm_root and pvm_root.threads_list, should be reached from root...
    // char* snapshot = load_snap(pager_superblock_ptr()->disk_page_count);
    char* snapshot = load_snap();
    if (snapshot == 0) {
        ph_printf("\n!!! No snapshot loaded !!!\n");
        return;
    }

    long long shift = snapshot - (char*)get_pvm_object_space_start();

    mark_tree((pvm_object_storage_t*)snapshot, shift);
    pvm_object_storage_t** to_free = collect_unmarked(snapshot, shift);

    // Second pass - linear walk to free unused objects.
    int freed = free_unmarked(to_free);

    if (freed > 0)
        ph_printf("\ngc: %i objects freed\n", freed);
}

static void mark_tree(pvm_object_storage_t* p, long long shift)
{
    ph_printf("\nGC: process another object\n");
    p->_ah.gc_flags = gc_flags_last_generation;  // set

    assert(p->_ah.object_start_marker == PVM_OBJECT_START_MARKER);
    assert(p->_ah.alloc_flags & PVM_OBJECT_AH_ALLOCATOR_FLAG_ALLOCATED);

    // Fast skip if no children -
    if (!(p->_flags & PHANTOM_OBJECT_STORAGE_FLAG_IS_CHILDFREE)) {
        gc_process_children(mark_tree_o, p, &shift);
    }
}

static void mark_tree_o(pvm_object_t o, void* arg) {
    long long shift = *((long long*)arg);

    if (o == 0) // Don't try to process null objects
        return;

    if (o->_ah.gc_flags != gc_flags_last_generation)
        mark_tree(o, shift);

    //if (o.interface->_ah.gc_flags != gc_flags_last_generation)  mark_tree( o.interface );
}

static void gc_process_children(gc_iterator_call_t f, pvm_object_storage_t* p, void* arg) {
    f(p->_class, arg);

    long long shift = *((long long*)arg);

    // Fast skip if no children - done!
    //if( p->_flags & PHANTOM_OBJECT_STORAGE_FLAG_IS_CHILDFREE )
    //    return;

    // plain non internal objects -
    if (!(p->_flags & PHANTOM_OBJECT_STORAGE_FLAG_IS_INTERNAL))
    {
        unsigned i;

        for (i = 0; i < da_po_limit(p); i++)
        {
            f(shift_ptr(da_po_ptr(p->da)[i], shift), arg);
        }
        return;
    }

    // We're here if object is internal.

    // Now find and call class-specific function: pvm_gc_iter_*

    gc_iterator_func_t  iter = pvm_internal_classes[pvm_object_da(p->_class, class)->sys_table_id].iter;

    iter(f, p, arg);
}

static pvm_object_storage_t** collect_unmarked(char* start, long long shift) {
    char* end = (char*)start + N_OBJMEM_PAGES * 4096L;
    char* curr;

    int freed = 0;
    for (curr = start; curr < end; curr += ((pvm_object_storage_t*)curr)->_ah.exact_size) {
        pvm_object_storage_t* p = (pvm_object_storage_t*)curr;
        assert(p->_ah.object_start_marker == PVM_OBJECT_START_MARKER);

        if ((p->_ah.gc_flags != gc_flags_last_generation) && (p->_ah.alloc_flags != PVM_OBJECT_AH_ALLOCATOR_FLAG_FREE))  //touch not accessed but allocated objects
        {
            ++freed;
        }
    }

    pvm_object_storage_t** to_free = ph_calloc((freed + 1), sizeof(pvm_object_storage_t*));

    int i = 0;
    for (curr = start; curr < end; curr += ((pvm_object_storage_t*)curr)->_ah.exact_size) {
        pvm_object_storage_t* p = (pvm_object_storage_t*)curr;
        assert(p->_ah.object_start_marker == PVM_OBJECT_START_MARKER);

        if ((p->_ah.gc_flags != gc_flags_last_generation) && (p->_ah.alloc_flags != PVM_OBJECT_AH_ALLOCATOR_FLAG_FREE))  //touch not accessed but allocated objects
        {
            to_free[i++] = shift_ptr(p, -shift);
        }
    }

    to_free[i] = 0;
    return to_free;
}

static int free_unmarked(pvm_object_storage_t** to_free) {
    int i = 0;
    while (to_free[i] != 0) {
        pvm_object_storage_t* p = to_free[i];

        if (p->_flags & PHANTOM_OBJECT_STORAGE_FLAG_IS_FINALIZER)
        {
            // based on the assumption that finalizer is only valid for some internal childfree objects - is it correct?
            gc_finalizer_func_t  func = pvm_internal_classes[pvm_object_da(p->_class, class)->sys_table_id].finalizer;

            if (func != 0)
                func(p);

            // should run ref_dec for children?
        }

        p->_ah.refCount = 0;  // free now
        p->_ah.alloc_flags = PVM_OBJECT_AH_ALLOCATOR_FLAG_FREE; // free now
    }
}
