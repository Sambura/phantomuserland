/**
 *
 * Phantom OS
 *
 * Copyright (C) 2005-2009 Dmitry Zavalishin, dz@dz.ru
 *
 * Fast and dirty garbage collection
 *
**/

#define DEBUG_MSG_PREFIX "vm.gc_on_snap"
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
#include <kernel/snap_sync.h>

#include <arch/arch-page.h>

#include <ph_malloc.h>

static long long shift;
hal_mutex_t *vm_read_snap_mutex;
static hal_mutex_t _vm_read_snap_mutex;

void init_gc() {
    if (hal_mutex_init(&_vm_read_snap_mutex, "ReadSnap"))
        panic("Can't init read snap mutex");

    vm_read_snap_mutex = &_vm_read_snap_mutex;
}


static pvm_object_t shift_ptr(pvm_object_t o, long long shift) {
    return (pvm_object_t) ((char *) o + shift);
}

static unsigned char gc_flags_last_generation = 0;

static void mark_tree(pvm_object_storage_t *p);

static char *load_snap() {
    unsigned long page_count = N_OBJMEM_PAGES + 1;
    SHOW_FLOW0(1, "Started");

    hal_mutex_lock(vm_read_snap_mutex);

    if (pager_superblock_ptr()->snap_already_read != 0) {
        ph_printf("\n!!! Previously loaded snapshot not cleaned yet !!!\n");
        return 0;
    }

    disk_page_no_t snap_start = 0;

    if (pager_superblock_ptr()->last_snap != 0) {
        hal_printf("-- Use last snap\n");
        snap_start = pager_superblock_ptr()->last_snap;
    } else if (pager_superblock_ptr()->prev_snap != 0) {
        hal_printf("-- Missing last snap, use previous snap\n");
        snap_start = pager_superblock_ptr()->prev_snap;
    }

    pager_superblock_ptr()->snap_reading = snap_start;
    hal_mutex_unlock(vm_read_snap_mutex);

    if (snap_start == 0) {
        hal_printf("\n!!! No pagelist to load !!!\n");
        return 0;
    }

    hal_printf("Loading pagelist from %d...\n", snap_start);
    pagelist loader;
    pagelist_init(&loader, snap_start, 0, DISK_STRUCT_MAGIC_SNAP_LIST);
    pagelist_seek(&loader);

    disk_page_no_t curr_block;
    char *snapshot = ph_calloc(page_count, PAGE_SIZE);
    char *snapshot_seeker = snapshot;
    unsigned int np;
    for (np = 0; np < page_count; np++) {
        if (np % 500 == 0)
            ph_printf("np: %d/%d\n", np, page_count);

        if (!pagelist_read_seq(&loader, &curr_block)) {
            ph_printf("\n!!! Incomplete pagelist !!!\n");
            snapshot = 0;
            break;
        }

        if (curr_block == 0) {
            snapshot_seeker += PAGE_SIZE;
            continue; // change
        }

        disk_page_io sb;
        disk_page_io_init(&sb);
        errno_t rc = disk_page_io_load_sync(&sb, curr_block);

        if (rc) {
            panic("failed to load snapshot in gc\n");
        }

        ph_memcpy(snapshot_seeker, disk_page_io_data(&sb), PAGE_SIZE);
        snapshot_seeker += PAGE_SIZE;
    }

    pagelist_finish(&loader);

    hal_mutex_lock(vm_read_snap_mutex);
    pager_superblock_ptr()->snap_reading = 0;
    pager_superblock_ptr()->snap_already_read = snap_start;
    hal_mutex_unlock(vm_read_snap_mutex);

    return snapshot;
}

static pvm_object_storage_t **collect_unmarked(char *start);

static int free_unmarked(pvm_object_storage_t **to_free);

static void gc_process_children(gc_iterator_call_t f, pvm_object_storage_t *p, void *arg);

static void mark_tree_o(pvm_object_t o, void *arg);

void run_gc_on_snap() {
    // synchonization?

    gc_flags_last_generation++; // bump generation
    if (gc_flags_last_generation == 0) gc_flags_last_generation++; // != 0 'cause allocation reset gc_flags to zero

    //phantom_virtual_machine_threads_stopped++; // pretend we are stopped
    //TODO: refine synchronization

    // First pass - tree walk, mark visited.
    // Root is always used. All other objects, including pvm_root and pvm_root.threads_list, should be reached from root...
    // char* snapshot = load_snap(pager_superblock_ptr()->disk_page_count);
    char *snapshot = load_snap();
    if (snapshot == 0) {
        ph_printf("\n!!! No snapshot loaded !!!\n");
        return;
    }

    shift = snapshot - (char *) get_pvm_object_space_start();
    ph_printf("real space start: %p\n", get_pvm_object_space_start());
    ph_printf("real space end: %p\n", get_pvm_object_space_end());
    ph_printf("snapshot is loaded\n");
    ph_printf("shift: %d\n", shift);
    ph_printf("snapshot addr: %p\n", snapshot);
    ph_printf("reference start marker: %d\n", PVM_OBJECT_START_MARKER);

    mark_tree((pvm_object_storage_t *) snapshot);
    pvm_object_storage_t **to_free = collect_unmarked(snapshot);
    ph_printf("Collect unmarked finished\n");

    // Second pass - linear walk to free unused objects.
    int freed = free_unmarked(to_free);

    // if (freed > 0)
    //     ph_printf("\ngc: %i objects freed\n", freed);
}

struct disk_page_io gc_io;

typedef struct gc_map {
    uint64_t *keys;
    uint64_t *values;
    
    uint64_t capacity;
    uint64_t count;
} gc_map_t;

void gc_map_init(gc_map_t *map) {
    map->count = 0;
    map->capacity = 16;
    map->keys = ph_malloc(sizeof(uint64_t) * map->capacity);
    map->values = ph_malloc(sizeof(uint64_t) * map->capacity);
}

void gc_map_release(gc_map_t *map) {
    ph_free(map->keys);
    ph_free(map->values);
}

uint64_t *__gc_map_try_get(gc_map_t *map, uint64_t key) {
    for (uint64_t i = 0; i < map->count; i++) {
        if (map->keys[i] == key) {
            return &map->values[i];
        }
    }

    return NULL;
}

// 0 if found, -1 if not
int gc_map_try_get(gc_map_t *map, uint64_t key, uint64_t *out) {
    assert(out);

    uint64_t *local_out = __gc_map_try_get(map, key);
    if (local_out) {
        *out = *local_out;
        return 0;
    }
    
    return -1;
}

void __increase_capacity(void **container, uint64_t prev_capacity, uint64_t new_capacity, size_t elem_size) {
    void *new_container = ph_malloc(elem_size * new_capacity);
    ph_memcpy(new_container, *container, prev_capacity * elem_size);
    ph_free(*container);
    *container = new_container;
}

void gc_map_insert_nocheck(gc_map_t *map, uint64_t key, uint64_t value) {
    if (map->count == map->capacity) {
        map->capacity *= 2;
        __increase_capacity((void**) &map->keys, map->count, map->capacity, sizeof(key));
        __increase_capacity((void**) &map->values, map->count, map->capacity, sizeof(value));
    }

    map->keys[map->count] = key;
    map->values[map->count] = value;
    map->count++;
}

// returns previous value (or 0 if none)
uint64_t gc_map_increment(gc_map_t *map, uint64_t key) {
    uint64_t *value_ptr = __gc_map_try_get(map, key);
    if (value_ptr) {
        (*value_ptr)++;
        return *value_ptr - 1;
    }

    gc_map_insert_nocheck(map, key, 1);
    return 0;
}

// set value if key is present in map. 0 on success, 1 on skip
static int gc_map_set_or_skip(gc_map_t *map, uint64_t key, uint64_t value, uint64_t *old_value) {
    uint64_t *value_ptr = __gc_map_try_get(map, key);
    if (!value_ptr) return 1;

    *old_value = *value_ptr;
    (*value_ptr) = value;
    return 0;
}

extern vm_page *get_vm_page(unsigned long index);

static unsigned char *load_page(gc_map_t *map, uint64_t page_index) {
    unsigned char *page = NULL;
    
    if (gc_map_try_get(map, page_index, &page) == 0) {
        return page;
    }

    // page not loaded, load now:
    vm_page *page_struct = get_vm_page(page_index);
    if (page_struct->make_page) { // non empty page
        if (disk_page_io_load_sync(&gc_io, page_struct->make_page)) panic("Could not load from disk");
        page = ph_malloc(PAGE_SIZE);
        ph_memcpy(page, disk_page_io_data(&gc_io), PAGE_SIZE);
    }

    gc_map_insert_nocheck(map, page_index, page);
    return page;
}

static const unsigned char *extract_header_part(unsigned char **pages, int start, int size) {
    static char buffer[8];
    assert(size <= sizeof(buffer));

    for (int i = 0; i < size; i++) {
        long current_offset = start + i;
        unsigned char curr_byte;

        if (current_offset < PAGE_SIZE) {
            curr_byte = *(unsigned char*)(pages[0] + current_offset);
        } else {
            curr_byte = *(unsigned char*)(pages[1] + current_offset - PAGE_SIZE);
        }

        buffer[i] = curr_byte;
    }

    return buffer;
}

static void write_header_part(unsigned char **pages, int start, int size, const unsigned char *data)
{
    assert(data && size > 0);

    for (int i = 0; i < size; i++) {
        long current_offset = start + i;

        if (current_offset < PAGE_SIZE) {
            *(pages[0] + current_offset) = data[i];
        } else {
            *(pages[1] + current_offset - PAGE_SIZE) = data[i];
        }
    }
}

#define OBJ_FLAGS_OFFSET        __offsetof(pvm_object_storage_t, _flags)
#define OBJ_FLAGS_SIZE          sizeof(uint32_t)
#define OBJ_REFCNT_OFFSET       __offsetof(pvm_object_storage_t, _ah.refCount)
#define OBJ_REFCNT_SIZE         sizeof(int32_t)
#define OBJ_MARKER_OFFSET       __offsetof(pvm_object_storage_t, _ah.object_start_marker)
#define OBJ_MARKER_SIZE         sizeof(unsigned int)
#define OBJ_AFLAGS_OFFSET       __offsetof(pvm_object_storage_t, _ah.alloc_flags)
#define OBJ_AFLAGS_SIZE         sizeof(unsigned char)
#define OBJ_ESIZE_OFFSET        __offsetof(pvm_object_storage_t, _ah.exact_size)
#define OBJ_ESIZE_SIZE          sizeof(unsigned int)

// if the object is childfree return NULL (since why waste time on them?)
static pvm_object_t gc_get_parent_object_image(gc_map_t *map, pvm_object_t real_object, bool *to_free)
{
    long page_index = addr_to_page_index((uintptr_t)real_object);
    assert(page_index >= 0);
    int object_offset = addr_to_page_offset((uintptr_t)real_object);
    int flags_field_offset = object_offset + OBJ_FLAGS_OFFSET;
    bool flags_on_first_page = flags_field_offset + OBJ_FLAGS_SIZE <= PAGE_SIZE;
    *to_free = false;

    // Assuming object header (including `_flags` and `da_size`) fits on a single page
    //      (seems like a reasonable assumption tho)
    unsigned char *base_pages[] = { 
        load_page(map, page_index),
        !flags_on_first_page ? load_page(map, page_index + 1) : NULL
    };

    assert(base_pages[0]); // empty page cannot contain object header (can it?)
    assert(base_pages[1] || flags_on_first_page);

    // check start marker
    int start_marker_offset = object_offset + OBJ_MARKER_OFFSET;
    unsigned int start_marker = *(unsigned int*)extract_header_part(
            base_pages, start_marker_offset, OBJ_MARKER_SIZE);
    assert(start_marker == PVM_OBJECT_START_MARKER);

    // check object image is allocated
    int alloc_flags_offset = object_offset + OBJ_AFLAGS_OFFSET;
    unsigned char alloc_flags = *(unsigned char*)extract_header_part(base_pages, 
            alloc_flags_offset, OBJ_AFLAGS_SIZE);
    assert(alloc_flags & PVM_OBJECT_AH_ALLOCATOR_FLAG_ALLOCATED);

    // childfree check
    uint32_t flags = *(uint32_t*)extract_header_part(base_pages, flags_field_offset, 
            OBJ_FLAGS_SIZE);
    if (flags & PHANTOM_OBJECT_STORAGE_FLAG_IS_CHILDFREE) return NULL;

    int size_field_offset = object_offset + OBJ_ESIZE_OFFSET;
    unsigned int exact_object_size = *(unsigned int*)extract_header_part(
            base_pages, size_field_offset, OBJ_ESIZE_SIZE);

    long object_end_offset = object_offset + exact_object_size;

    if (object_end_offset <= PAGE_SIZE) { // whole object is in the first page
        return base_pages[0] + object_offset;
    }

    int pages_required = (object_end_offset + PAGE_SIZE - 1) / PAGE_SIZE;
    unsigned char *obj_image = ph_malloc(exact_object_size);
    unsigned char *cur = obj_image;

    ph_memcpy(cur, base_pages[0] + object_offset, PAGE_SIZE - object_offset);
    cur += PAGE_SIZE - object_offset;
    
    for (int curr_page = 1; cur != obj_image + exact_object_size; curr_page++) {
        long remaining_size = exact_object_size - (cur - obj_image);
        assert(remaining_size > 0);
        unsigned char *cur_page = load_page(map, page_index + curr_page);
        int to_copy = remaining_size <= PAGE_SIZE ? remaining_size : PAGE_SIZE;

        if (cur_page)
            ph_memcpy(cur, cur_page, to_copy);
        else 
            ph_memset(cur, 0, to_copy);
        cur += to_copy;
    }

    *to_free = true;
    return obj_image;
}

static int32_t extract_real_refcount(gc_map_t *map, pvm_object_t real_object) {
    long page_index = addr_to_page_index((uintptr_t)real_object);
    assert(page_index >= 0);
    int object_offset = addr_to_page_offset((uintptr_t)real_object);
    int refcnt_offset = object_offset + OBJ_REFCNT_OFFSET;
    bool refcnt_on_first_page = refcnt_offset + OBJ_REFCNT_SIZE <= PAGE_SIZE;

    unsigned char *base_pages[] = { 
        load_page(map, page_index),
        !refcnt_on_first_page ? load_page(map, page_index + 1) : NULL
    };

    assert(base_pages[0]);
    assert(base_pages[1] || refcnt_on_first_page);
    int32_t refcount = *(int32_t*)extract_header_part(
            base_pages, refcnt_offset, sizeof(int32_t));
    
    return refcount;
}

static void load_header_pages(gc_map_t *map, pvm_object_t real_object) {
    long page_index = addr_to_page_index((uintptr_t)real_object);
    assert(page_index >= 0);
    int object_offset = addr_to_page_offset((uintptr_t)real_object);
    int flags_field_offset = object_offset + OBJ_FLAGS_OFFSET;
    bool flags_on_first_page = flags_field_offset + OBJ_FLAGS_SIZE <= PAGE_SIZE;

    load_page(map, page_index);
    if (!flags_on_first_page) load_page(map, page_index + 1);
}

gc_map_t *new_refcnt_map, *loaded_pages_map;

static void mark_tree_incremental(pvm_object_t real_object, void *data) {
    if (real_object == NULL) return;
    int mark_mode = data ? 1 : 0;

    assert(data == NULL || (intptr_t)data == 1);
    if (mark_mode == 1) { // reverse pass
        uint64_t old_refcnt; // mark object as non-garbage
        assert(gc_map_set_or_skip(new_refcnt_map, real_object, 0, &old_refcnt) == 0);
        if (old_refcnt == 0) return; // was already marked, return
    } else {
        // local reference inc
        // if refcount was non-zero, the object is already marked - return
        if (gc_map_increment(new_refcnt_map, real_object) > 0) return;
    }

    bool to_free = false;
    // copy of the object
    pvm_object_t object_image = gc_get_parent_object_image(loaded_pages_map, real_object, &to_free);
    if (object_image == NULL) return; // object is childfree, return
    // all the needed asserts and checks are performed in gc_get_parent_object_image

    gc_process_children(mark_tree_incremental, object_image, data);

    if (to_free) ph_free(object_image);
}

static void gc_free_object_image(gc_map_t *map, pvm_object_t real_object, bool *is_modified)
{
    long page_index = addr_to_page_index((uintptr_t)real_object);
    assert(page_index >= 0);
    int object_offset = addr_to_page_offset((uintptr_t)real_object);
    // assuming flags are further in the object than refcount
    int alloc_flags_offset = object_offset + OBJ_AFLAGS_OFFSET;
    int refcount_offset = object_offset + OBJ_REFCNT_OFFSET;
    bool flags_on_first_page = alloc_flags_offset + OBJ_AFLAGS_SIZE <= PAGE_SIZE;

    uint64_t *in_map_addresses[] = { 
        __gc_map_try_get(map, page_index),
        !flags_on_first_page ? __gc_map_try_get(map, page_index + 1) : NULL
    };

    unsigned char *pages[] = {
        *in_map_addresses[0], flags_on_first_page ? NULL : *in_map_addresses[1]
    };

    // free image object
    unsigned char new_aflags = PVM_OBJECT_AH_ALLOCATOR_FLAG_FREE;
    int32_t new_refcnt = 0;
    write_header_part(pages, alloc_flags_offset, OBJ_AFLAGS_SIZE, &new_aflags);
    write_header_part(pages, refcount_offset, OBJ_REFCNT_SIZE, &new_refcnt);

    // mark page images dirty
    is_modified[in_map_addresses[0] - map->values] = true;
    if (!flags_on_first_page) {
        is_modified[in_map_addresses[1] - map->values] = true;
    }
}

int freed_size = 0;

extern void cycle_root_buffer_rm_candidate(pvm_object_storage_t *p);

static void free_incremetnal(gc_map_t *map, pvm_object_t real_object, bool *is_modified) {
    pvm_object_is_allocated_assert(real_object);

    if (real_object->_flags & PHANTOM_OBJECT_STORAGE_FLAG_IS_FINALIZER) {
        int syscall_id = pvm_object_da(real_object->_class, class)->sys_table_id;
        gc_finalizer_func_t func = pvm_internal_classes[syscall_id].finalizer;

        if (func != 0)
            func(real_object);

        // should run ref_dec for children?
        // yes, probably
    }

    // free real object
    real_object->_ah.refCount = 0;
    real_object->_ah.alloc_flags = PVM_OBJECT_AH_ALLOCATOR_FLAG_FREE;
    freed_size += real_object->_ah.exact_size;

    if ( !(real_object->_flags & PHANTOM_OBJECT_STORAGE_FLAG_IS_CHILDFREE) )
        cycle_root_buffer_rm_candidate(real_object);

    gc_free_object_image(map, real_object, is_modified);
}

#define get_array_slot_nocheck(arr, i) ((pvm_object_t*)(pvm_data_area(arr, array)->page->da))[i]

// we will run on the unfinished snapshot - no need for protection from deletion
void run_gc_incremental(pvm_object_t cycle_candidates) {
    SHOW_INFO0(1, "GC LIGHT: START");
    uint64_t start_time = hal_system_time();
    // gc buffer only contains objects with non-zero refcount (== no invalid/freed objects)
    assert(cycle_candidates);
    gc_map_t new_refcnt, loaded_pages;
    gc_map_init(&new_refcnt); gc_map_init(&loaded_pages);
    new_refcnt_map = &new_refcnt;
    loaded_pages_map = &loaded_pages;

    disk_page_io_init(&gc_io);
    
    SHOW_INFO(1, "GC LIGHT: Initialized. Objects to process: %d", pvm_get_array_size(cycle_candidates));
    // recount references (forward pass)
    for (int i = 0; i < pvm_get_array_size(cycle_candidates); i++) {
        mark_tree_incremental(get_array_slot_nocheck(cycle_candidates, i), 0);
    }

    SHOW_INFO(1, "GC LIGHT: Forward pass done. Pages loaded: %d", loaded_pages.count);
    // find objects with external references (reverse pass)
    for (int i = 0; i < new_refcnt.count; i++) {
        pvm_object_t object = (pvm_object_t) new_refcnt.keys[i];
        int64_t counted_refs = new_refcnt.values[i];
        if (counted_refs == 0) continue; // marked as non-garbage in earlier iterations
        // all candidates have 1 extra reference counted
        for (int i = 0; i < pvm_get_array_size(cycle_candidates); i++) {
            if (get_array_slot_nocheck(cycle_candidates, i) == object) {
                counted_refs--;
                break;
            }
        }
        int32_t actual_refs = extract_real_refcount(loaded_pages_map, object);
        if (counted_refs == actual_refs) continue; // potential garbage
        if (counted_refs > actual_refs) {
            SHOW_ERROR(1, "Too many references counted: %d/%d @%p", 
                    counted_refs, actual_refs, object);
            dumpo(object);
            continue; // replace with panic later?
        }

        // counted less than actual - there is an external reference
        mark_tree_incremental(object, 1); // reverse pass
    }

    SHOW_INFO0(1, "GC LIGHT: Reverse pass done");
    int freed_count = 0;
    freed_size = 0;
    // free garbage, mark dirty pages to page out
    // +4 for pages that *may* be required for `cycle_candidates`
    bool *is_modified = ph_calloc(loaded_pages.count + 4, sizeof(bool));
    for (int i = 0; i < new_refcnt.count; i++) {
        pvm_object_t object = (pvm_object_t) new_refcnt.keys[i];

        if (new_refcnt.values[i] == 0) continue; // not garbage
        // ph_printf("Freeing: ");
        // pvm_object_print(pvm_data_area(object->_class, class)->class_name);
        // ph_printf("\n");
        free_incremetnal(loaded_pages_map, object, is_modified);
        freed_count++;
    }

    // remove cycle candidates array from snapshot too
    pvm_object_t array_page = pvm_data_area(cycle_candidates, array)->page;
    if (array_page) {
        load_header_pages(loaded_pages_map, array_page);
        free_incremetnal(loaded_pages_map, array_page, is_modified);
    }
    load_header_pages(loaded_pages_map, cycle_candidates);
    free_incremetnal(loaded_pages_map, cycle_candidates, is_modified);

    SHOW_INFO0(1, "GC LIGHT: Pageout...");
    // sync pageout of dirty pages
    int pages_written = 0;
    //void *gc_io_mem = gc_io.mem;
    for (int i = 0; i < loaded_pages.count; i++) {
        if (!loaded_pages.values[i]) continue;

        if (is_modified[i]) {
            vm_page *page_struct = get_vm_page(loaded_pages.keys[i]);
            // should figure out if it is possible to directly write from loaded_pages.values[i]
            //gc_io.mem = loaded_pages.values[i];
            ph_memcpy(disk_page_io_data(&gc_io), loaded_pages.values[i], PAGE_SIZE);

            if (disk_page_io_save_sync(&gc_io, page_struct->make_page)) panic("Could not save to disk");
            pages_written++;
            
            assert(page_struct->make_page);
        }

        ph_free((void*) loaded_pages.values[i]);
    }
    //gc_io.mem = gc_io_mem;

    SHOW_INFO(1, "GC LIGHT: Pageout done. Pages written: %d", pages_written);
    disk_page_io_finish(&gc_io);
    gc_map_release(&new_refcnt);
    gc_map_release(&loaded_pages);

    SHOW_INFO0(1, "GC LIGHT: FINISH");
    uint64_t end_time = hal_system_time();
    SHOW_INFO(1, "GC stats: pages loaded: %d, objects freed: %d, objects iterated: %d. Elapsed: %d ms", 
        loaded_pages.count, freed_count, new_refcnt.count, (end_time - start_time) / 1000);
    SHOW_INFO(1, "GC stats: freed %d KB (%d bytes)", freed_size / 1024, freed_size);
}

// silently delete object
void release_gc_buffer(pvm_object_t gc_buffer) {
    if (gc_buffer == NULL) return;

    pvm_object_t p = pvm_data_area(gc_buffer, array)->page;
    if (p) {
        p->_ah.refCount = 0;
        p->_ah.alloc_flags = PVM_OBJECT_AH_ALLOCATOR_FLAG_FREE;
    }

    gc_buffer->_ah.refCount = 0;
    gc_buffer->_ah.alloc_flags = PVM_OBJECT_AH_ALLOCATOR_FLAG_FREE;
}

static void mark_tree(pvm_object_storage_t *obj_in_snap) {
    // ph_printf("\nGC: process another object\n");
    // ph_printf("Flags: '");
    // print_object_flags(obj_in_snap);
    // ph_printf("'\n");
    // ph_printf("object class:\n");
    // dumpo(obj_in_snap->_class);

    // ph_printf("p: %p, p->ah: %p, p->da: %p\n", obj_in_snap, &obj_in_snap->_ah, obj_in_snap->da);
    // ph_printf("start marker: %d\n", obj_in_snap->_ah.object_start_marker);

    obj_in_snap->_ah.gc_flags = gc_flags_last_generation; // set

    // ph_printf("assert start marker and allocated\n");
    assert(obj_in_snap->_ah.object_start_marker == PVM_OBJECT_START_MARKER);
    assert(obj_in_snap->_ah.alloc_flags & PVM_OBJECT_AH_ALLOCATOR_FLAG_ALLOCATED);

    // ph_printf("check if childfree\n");
    // Fast skip if no children -
    if (!(obj_in_snap->_flags & PHANTOM_OBJECT_STORAGE_FLAG_IS_CHILDFREE)) {
        // ph_printf("not childfree, call gc_process_children\n");
        // ph_printf("p addr: %p\n", &obj_in_snap);
        gc_process_children(mark_tree_o, obj_in_snap, 0);
    }
}

static void mark_tree_o(pvm_object_t obj_in_pvm, void *arg) {
    if (obj_in_pvm == 0) // Don't try to process null objects
        return;

    pvm_object_t obj_in_snap = shift_ptr(obj_in_pvm, shift);

    if (obj_in_snap->_ah.gc_flags != gc_flags_last_generation)
        mark_tree(obj_in_snap);

    //if (o.interface->_ah.gc_flags != gc_flags_last_generation)  mark_tree( o.interface );
}

static void gc_process_children(gc_iterator_call_t f, pvm_object_storage_t *obj_in_snap, void *arg) {
    // ph_printf("GC: process children\n");
    f(obj_in_snap->_class, arg);

    // Fast skip if no children - done!
    //if( p->_flags & PHANTOM_OBJECT_STORAGE_FLAG_IS_CHILDFREE )
    //    return;

    // plain non internal objects -
    if (!(obj_in_snap->_flags & PHANTOM_OBJECT_STORAGE_FLAG_IS_INTERNAL)) {
        // ph_printf("External object, normal iter\n");
        unsigned i;

        for (i = 0; i < da_po_limit(obj_in_snap); i++) {
            f(da_po_ptr(obj_in_snap->da)[i], arg);
        }
        return;
    }

    // We're here if object is internal.

    // Now find and call class-specific function: pvm_gc_iter_*
    // ph_printf("Internal object, get iter method\n");
    gc_iterator_func_t iter = pvm_internal_classes[pvm_object_da(obj_in_snap->_class, class)->
        sys_table_id].iter;

    iter(f, obj_in_snap, arg);
}

static pvm_object_storage_t **collect_unmarked(char *start) {
    char *end = (char *) start + N_OBJMEM_PAGES * 4096L;
    char *curr;

    int freed = 0;
    for (curr = start; curr < end; curr += ((pvm_object_storage_t *) curr)->_ah.exact_size) {
        pvm_object_storage_t *p = (pvm_object_storage_t *) curr;
        assert(p->_ah.object_start_marker == PVM_OBJECT_START_MARKER);

        if ((p->_ah.gc_flags != gc_flags_last_generation) && (p->_ah.alloc_flags != PVM_OBJECT_AH_ALLOCATOR_FLAG_FREE))
        //touch not accessed but allocated objects
        {
            ++freed;
        }
    }

    LOG_INFO_(5, "Found %d objects to free", freed);

    pvm_object_storage_t **to_free = ph_calloc((freed + 1), sizeof(pvm_object_storage_t *));

    int i = 0;
    for (curr = start; curr < end; curr += ((pvm_object_storage_t *) curr)->_ah.exact_size) {
        pvm_object_storage_t *p = (pvm_object_storage_t *) curr;
        assert(p->_ah.object_start_marker == PVM_OBJECT_START_MARKER);

        if ((p->_ah.gc_flags != gc_flags_last_generation) && (p->_ah.alloc_flags != PVM_OBJECT_AH_ALLOCATOR_FLAG_FREE))
        //touch not accessed but allocated objects
        {
            to_free[i++] = shift_ptr(p, -shift);
        }
    }

    to_free[i] = 0;
    return to_free;
}

static int free_unmarked(pvm_object_storage_t **to_free) {
    int i = 0;
    long long freed_size = 0;

    vm_lock_persistent_memory();
    while (to_free[i] != 0) {
        pvm_object_storage_t *p = to_free[i];
        pvm_object_is_allocated_assert(p);
        freed_size += p->_ah.exact_size;

        if (p->_flags & PHANTOM_OBJECT_STORAGE_FLAG_IS_FINALIZER) {
            // based on the assumption that finalizer is only valid for some internal childfree objects - is it correct?
            gc_finalizer_func_t func = pvm_internal_classes[pvm_object_da(p->_class, class)->sys_table_id].finalizer;

            if (func != 0)
                func(p);

            // should run ref_dec for children?
        }

        p->_ah.refCount = 0; // free now
        p->_ah.alloc_flags = PVM_OBJECT_AH_ALLOCATOR_FLAG_FREE; // free now
        i++;
    }
    vm_unlock_persistent_memory();

    LOG_INFO_(5, "GC finished: freed %d KB", freed_size / 1024);

    return i;
}
