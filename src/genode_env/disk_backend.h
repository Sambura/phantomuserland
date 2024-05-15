#ifndef PHANTOM_ENV_DISK_BACKEND_H
#define PHANTOM_ENV_DISK_BACKEND_H

#include "phantom_env.h"

#include <base/stdint.h>
#include <base/component.h>
#include <base/heap.h>
#include <block_session/connection.h>
#include <base/allocator.h>
#include <base/allocator_avl.h>
#include <base/log.h>
#include <base/signal.h>

extern "C"
{
#include <hal.h>
#include <pager_io_req.h>
#include <ph_string.h>
}

namespace Phantom
{
    class Disk_backend;
};

/**
 * Block session connection
 *
 * Imported from repos/dde_rump/src/lib/rump/io.cc
 *
 */

class Phantom::Disk_backend
{
protected:
    bool _debug = false;
    int _jobs_pending = 0;

    Genode::Env &_env;
    Genode::Heap &_heap;
    Genode::Entrypoint _ep{_env, 30*1024*sizeof(long) , "disk_ep", Genode::Affinity::Location()};
    Genode::Allocator_avl _block_alloc{&_heap};

    struct DJob : Block::Connection<DJob>::Job
    {
        pager_io_request *_req;

        DJob(Block::Connection<DJob> &connection, Block::Operation operation, pager_io_request *req)
            : Block::Connection<DJob>::Job(connection, operation), _req(req)
        {
        }
    };

    Block::Connection<DJob> _block{_env, &_block_alloc, 8 * 1024 * 1024};
    Block::Session::Info _info{_block.info()};
    Genode::Mutex _session_mutex{};

    void _handle_block_io()
    {
        if (_debug)
            Genode::log("Handling block io");
        // _triggered++;
        _block.update_jobs(*this);
    }

    Genode::Signal_handler<Disk_backend> _block_io_sigh{
        _ep, *this, &Disk_backend::_handle_block_io};

public:
    enum class Operation
    {
        READ,
        WRITE,
        SYNC
    };

    // Transfer data from or to pseudo phys memory
    void transferData(physaddr_t phys_addr, void *virt_addr, size_t length, bool to_phys)
    {
        // XXX : Replace with something defined in header
        // const size_t PAGE_SIZE = 4096;
        // TODO : Rework to be more efficient
        // TODO : IT SHOULD NOT HAPPEN IN OBJECT SPACE! Use another allocator
        // TODO : Also, might result in some memory leaks
        // Need to write to pseudo phys page. It means that we need to map it first
        // void *temp_mapping = nullptr;

        // size_t length_in_pages = length / PAGE_SIZE + ((length % PAGE_SIZE > 0) ? 1 : 0);

        // hal_alloc_vaddress(&temp_mapping, length_in_pages);
        // hal_pages_control(phys_addr, temp_mapping, length_in_pages, page_map, to_phys ? page_rw : page_ro);

        // Transfer data
        if (to_phys)
        {
            // ph_memcpy(temp_mapping, virt_addr, length);
            memcpy_v2p(phys_addr, virt_addr, length);
        }
        else
        {
            // ph_memcpy(virt_addr, temp_mapping, length);
            memcpy_p2v(virt_addr, phys_addr, length);
        }

        // Now we can remove temporary mapping and dealloc address
        // hal_pages_control(0, temp_mapping, length_in_pages, page_unmap, page_rw);
        // hal_free_vaddress(temp_mapping, length_in_pages);
    }

    /**
     * Block::Connection::Update_jobs_policy
     */
    void produce_write_content(DJob &job, Block::seek_off_t offset, char *dst, size_t length)
    {
        if (_debug)
            Genode::log("Produce content req=", job._req);
        // Producing content to write on the disk
        transferData(job._req->phys_page, (void *)dst, length, false);
    }

    /**
     * Block::Connection::Update_jobs_policy
     */
    void consume_read_result(DJob &job, Block::seek_off_t offset,
                             char const *src, size_t length)
    {
        if (_debug)
            Genode::log("Consuming result req=", job._req);
        // Consuming content read from the disk
        transferData(job._req->phys_page, (void *)src, length, true);
    }

    /**
     * Block_connection::Update_jobs_policy
     */
    void completed(DJob &job, bool success)
    {
        _jobs_pending--;

        if (_debug)
            Genode::log("Completed req=", job._req);

        if (!(job._req->flag_pageout ^ job._req->flag_pagein)){
            Genode::error("Completed pager request, but strange flags received. pagein=", job._req->flag_pagein, " pageout=", job._req->flag_pageout);
        }

        // XXX : Maybe should be done after zeroing flags
        // Calling pager callback
        if (job._req->pager_callback != 0){
            job._req->pager_callback(job._req, job._req->flag_pageout);
        }

        // XXX : pager_io_request requires some finishing operations
        //       But not sure what is required. One of the ideas is to use
        //       pager_io_request_done( rq );
        //       But it is almost not used anywhere
        // XXX : It is done by Phantom code, but it is very controversial thing though.
        //       What will happen if we would like to check what operation it was?
        job._req->flag_pageout = 0;
        job._req->flag_pagein = 0;

        // TODO : error handling

        hal_spin_unlock(&job._req->lock);

        destroy(_heap, &job);
    }

    Disk_backend(Genode::Env &env, Genode::Heap &heap) : _env(env), _heap(heap)
    {
        _block.sigh(_block_io_sigh);

        Genode::log("block device with block size ", _info.block_size, " block count ",
                    _info.block_count, " writeable=", _info.writeable);
        Genode::log("");
    }

    Genode::uint64_t block_count() const { return _info.block_count; }
    Genode::size_t block_size() const { return _info.block_size; }
    bool writable() const { return _info.writeable; }

    Block::Session::Info getInfo()
    {
        return _info;
    }

    void startAsyncJob(Block::Operation op, pager_io_request *req)
    {
        if (_debug){
            Genode::log("Starting async job req=", req);
            Genode::log(op);
        }
        _jobs_pending++;
        // Allocating DJob in the heap. Should be destroyed on completed() callback
        new (_heap) DJob(_block, op, req);

        _block.update_jobs(*this);
    }

    // XXX : No clue if this is functional, timeout added just in case
    //      but yeah idk if this will actually do the job :/
    int waitForPendingJobs() {
        int elapsedMs = 0;
        
        while (_jobs_pending > 0)
        {
            elapsedMs += 25;
            hal_sleep_msec(25);

            if (elapsedMs > 1500) {
                Genode::error("Disk fence: timeout");
                return -1;
            }
        }

        return 0;
    }

    /*
     * A synchronous operation
     * Offset and length should be block aligned. Otherwise they may be cropped.
     *
     * XXX : 0 offset and 0 length may lead to qemu AHCI error
     * `qemu-system-x86_64: ahci: PRDT length for NCQ command (0x1) is smaller than the requested size (0x2000000)`
     */
    // bool submit(Operation op, bool sync_req, Genode::int64_t offset, Genode::size_t length, void *data)
    // {
    //     using namespace Block;

    //     Genode::Mutex::Guard guard(_session_mutex);

    //     Block::Packet_descriptor::Opcode opcode;

    //     switch (op)
    //     {
    //     case Operation::READ:
    //         opcode = Block::Packet_descriptor::READ;
    //         break;
    //     case Operation::WRITE:
    //         opcode = Block::Packet_descriptor::WRITE;
    //         break;
    //     default:
    //         return false;
    //         break;
    //     }

    //     /* allocate packet */
    //     try
    //     {
    //         Block::Packet_descriptor packet(_session.alloc_packet(length),
    //                                         opcode, offset / _info.block_size,
    //                                         length / _info.block_size);

    //         // Genode::log("Block: cnt=", packet.block_count());
    //         // Genode::log("       num=", packet.block_number());
    //         // Genode::log("       off=", packet.offset());
    //         // It is ok for the offset not to be equal to the defined one

    //         /* out packet -> copy data */
    //         if (opcode == Block::Packet_descriptor::WRITE)
    //         {
    //             Genode::log("Block: writing");
    //             Genode::memcpy(_session.tx()->packet_content(packet), data, length);
    //         }

    //         // XXX : Busy waiting!!!
    //         // _session.tx()->submit_packet(packet);
    //         while (!_session.tx()->try_submit_packet(packet))
    //             ;
    //     }
    //     catch (Block::Session::Tx::Source::Packet_alloc_failed)
    //     {
    //         Genode::error("I/O back end: Packet allocation failed!");
    //         return false;
    //     }

    //     // Block::Packet_descriptor packet = _session.tx()->get_acked_packet();

    //     Genode::log("Block: getting ack");

    //     // XXX:  Spinning until got the packet
    //     while (!_session.tx()->ack_avail())
    //     {
    //         _ep.wait_and_dispatch_one_io_signal();
    //     }
    //     Genode::log("Block: ack available");

    //     Block::Packet_descriptor packet = _session.tx()->try_get_acked_packet();
    //     Genode::log("Block: received ack");

    //     /* in packet */
    //     if (opcode == Block::Packet_descriptor::READ)
    //         Genode::memcpy(data, _session.tx()->packet_content(packet), length);

    //     bool succeeded = packet.succeeded();

    //     Genode::log("Block: cnt=", packet.block_count());
    //     Genode::log("       num=", packet.block_number());
    //     Genode::log("       off=", packet.offset());
    //     Genode::log("       siz=", packet.size());
    //     Genode::log("        ok=", packet.succeeded());

    //     _session.tx()->release_packet(packet);

    //     Genode::log("Block: performing sync");

    //     /* sync request */
    //     if (sync_req)
    //     {
    //         // _sync();
    //     }

    //     return succeeded;
    // }
};

#endif
