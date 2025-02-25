/*
 * XXX : It is an exact copy of base/attached_ram_dataspace.h except:
 *         - it has virtual destructor to be compatible with registries
 */

/*
 * \brief  Utility to allocate and locally attach a RAM dataspace
 * \author Norman Feske
 * \date   2008-03-22
 */

/*
 * Copyright (C) 2008-2017 Genode Labs GmbH
 *
 * This file is part of the Genode OS framework, which is distributed
 * under the terms of the GNU Affero General Public License version 3.
 */

#ifndef PHANTOM_ENV_LOCAL_ATTACHED_RAM_DATASPACE
#define PHANTOM_ENV_LOCAL_ATTACHED_RAM_DATASPACE

#include <util/touch.h>
#include <base/ram_allocator.h>
#include <base/env.h>

namespace Phantom
{
    class Local_attached_ram_dataspace;
}

using namespace Genode;

/*
 * Utility for allocating and attaching a RAM dataspace
 *
 * The combination of RAM allocation and a local RM attachment is a frequent
 * use case. Each function may fail, which makes error handling inevitable.
 * This utility class encapsulates this functionality to handle both operations
 * as a transaction. When embedded as a member, this class also takes care
 * about freeing and detaching the dataspace at destruction time.
 */
class Phantom::Local_attached_ram_dataspace
{
private:
    size_t _size = 0;
    Ram_allocator *_ram = nullptr;
    Region_map *_rm = nullptr;
    Ram_dataspace_capability _ds{};
    void *_local_addr = nullptr;
    Cache const _cache = CACHED;

    template <typename T>
    static void _swap(T &v1, T &v2)
    {
        T tmp = v1;
        v1 = v2;
        v2 = tmp;
    }

    void _detach_and_free_dataspace()
    {
        if (_local_addr)
            _rm->detach(_local_addr);

        if (_ds.valid())
            _ram->free(_ds);
    }

    void _alloc_and_attach()
    {
        if (!_size)
            return;

        try
        {
            _ds = _ram->alloc(_size, _cache);
            _local_addr = _rm->attach(_ds);
        }
        /* revert allocation if attaching the dataspace failed */
        catch (Region_map::Region_conflict)
        {
            _ram->free(_ds);
            throw;
        }
        catch (Region_map::Invalid_dataspace)
        {
            _ram->free(_ds);
            throw;
        }

        /*
         * Eagerly map dataspace if used for DMA
         *
         * On some platforms, namely Fiasco.OC on ARMv7, the handling
         * of page faults interferes with the caching attributes used
         * for uncached DMA memory. See issue #452 for more details
         * (https://github.com/genodelabs/genode/issues/452). As a
         * work-around for this issues, we eagerly map the whole
         * dataspace before writing actual content to it.
         */
        if (_cache != CACHED)
        {
            enum
            {
                PAGE_SIZE = 4096
            };
            unsigned char volatile *base = (unsigned char volatile *)_local_addr;
            for (size_t i = 0; i < _size; i += PAGE_SIZE)
                touch_read_write(base + i);
        }
    }

    /*
     * Noncopyable
     */
    Local_attached_ram_dataspace(Local_attached_ram_dataspace const &);
    Local_attached_ram_dataspace &operator=(Local_attached_ram_dataspace const &);

public:
    /**
     * Constructor
     *
     * \throw Out_of_ram
     * \throw Out_of_caps
     * \throw Region_map::Region_conflict
     * \throw Region_map::Invalid_dataspace
     */
    Local_attached_ram_dataspace(Ram_allocator &ram, Region_map &rm,
                                 size_t size, Cache cache = CACHED)
        : _size(size), _ram(&ram), _rm(&rm), _cache(cache)
    {
        _alloc_and_attach();
    }

    /**
     * Destructor
     */
    virtual ~Local_attached_ram_dataspace() { _detach_and_free_dataspace(); }

    /**
     * Return capability of the used RAM dataspace
     */
    Ram_dataspace_capability cap() const { return _ds; }

    /**
     * Request local address
     *
     * This is a template to avoid inconvenient casts at
     * the caller. A newly allocated RAM dataspace is
     * untyped memory anyway.
     */
    template <typename T>
    T *local_addr() const { return static_cast<T *>(_local_addr); }

    /**
     * Return size
     */
    size_t size() const { return _size; }

    void swap(Local_attached_ram_dataspace &other)
    {
        _swap(_size, other._size);
        _swap(_ram, other._ram);
        _swap(_ds, other._ds);
        _swap(_local_addr, other._local_addr);
    }

    /**
     * Re-allocate dataspace with a new size
     *
     * The content of the original dataspace is not retained.
     */
    void realloc(Ram_allocator *ram_allocator, size_t new_size)
    {
        if (new_size < _size)
            return;

        _detach_and_free_dataspace();

        _size = new_size;
        _ram = ram_allocator;

        _alloc_and_attach();
    }
};

#endif /* _INCLUDE__BASE__ATTACHED_RAM_DATASPACE_H_ */
