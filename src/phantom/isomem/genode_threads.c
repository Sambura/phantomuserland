#ifdef PHANTOM_THREADS_STUB

#define DEBUG_MSG_PREFIX "vm.unixhal"
#include <debug_ext.h>
#define debug_level_flow 10
#define debug_level_error 10
#define debug_level_info 10

#include <stdarg.h>
#include <threads.h>
#include <pthread.h>
#include "genode_misc.h"

/*
*
* Thread creation/destruction
*
*/

int hal_start_kernel_thread_arg(void (*thread)(void *arg), void *arg)
{
    _stub_print();
    return 0;
}

void hal_start_kernel_thread(void (*thread)(void))
{
    _stub_print();
}

void hal_exit_kernel_thread()
{
    panic("hal_exit_kernel_thread");
}

tid_t hal_start_thread(void (*thread)(void *arg), void *arg, int flags)
{
    _stub_print();
    return 0;
}

errno_t t_kill_thread(tid_t tid)
{
    _stub_print();
    return 0;
}

errno_t t_current_set_death_handler(void (*handler)(phantom_thread_t *tp))
{
    _stub_print();
    return 0;
}

/*
*
* Thread info
*
*/

phantom_thread_t *get_current_thread()
{
    _stub_print();
    return 0;
}

tid_t get_current_tid(void)
{
    ph_printf("get_current_tid\n");
    _stub_print();
    return (int)pthread_self();
}

void *get_thread_owner(phantom_thread_t *t)
{
    return 0;
}

errno_t t_get_owner(int tid, void **owner) { return ENOENT; }

errno_t t_current_get_priority(int *prio)
{
    _stub_print();
    *prio = 0;
    return 0;
}

errno_t t_get_ctty(tid_t tid, struct wtty **ct) { return ENOENT; }

/*
*
* Thread configuration
*
*/

void hal_set_current_thread_name(const char *name)
{
    (void)name;
}

errno_t hal_set_current_thread_priority(int p)
{
    (void)p;
    return EINVAL;
}

errno_t t_current_set_name(const char *name)
{
    (void)name;
    return EINVAL;
}
errno_t t_current_set_priority(int p)
{
    (void)p;
    return EINVAL;
}
errno_t t_set_owner(tid_t tid, void *owner)
{
    return EINVAL;
}

/*
*
* Multithreading
*
*/

void t_smp_enable(int yn)
{
    _stub_print();
}

//< Enable or disable access to paged memory - calls arch pagemap func.
void t_set_paged_mem(bool enable)
{
    _stub_print();
}

void wake_sleeping_thread(void *arg)
{
    // arg is tid
    _stub_print();
}

/**
 *
 * Adds flag to sleep flags of thread, removes thread from
 * runnable set, unlocks the lock given, switches off to some other thread.
 */
void thread_block(int sleep_flag, hal_spinlock_t *lock_to_be_unlocked)
{
    _stub_print();
}

/*
*
* Snapshot machinery
*
*/

void t_migrate_to_boot_CPU(void)
{
    _stub_print();
}

// mark myself as snapper thread
errno_t t_set_snapper_flag(void)
{
    _stub_print();
    return 0;
}

// TODO : Remove if not needed

// void phantom_thread_wait_4_snap()
// {
//     // Just return
// }

// void phantom_snapper_wait_4_threads()
// {
//     // Do nothing in non-kernel version
//     // Must be implemented if no-kernel multithread will be done
// }

// void phantom_snapper_reenable_threads()
// {
//     //
// }

// void phantom_activate_thread()
// {
//     // Threads do not work in this mode
// }

#endif
