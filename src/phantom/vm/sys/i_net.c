/**
 *
 * Phantom OS
 *
 * Copyright (C) 2005-2019 Dmitry Zavalishin, dz@dz.ru
 *
 * .internal.net class implementation
 * 
 * See <https://github.com/dzavalishin/phantomuserland/wiki/InternalClasses>
 * See <https://github.com/dzavalishin/phantomuserland/wiki/InternalMethodWritingGuide>
 *
**/


#define DEBUG_MSG_PREFIX "vm.sysc.udp"
#include <debug_ext.h>
#define debug_level_flow 0
#define debug_level_error 1
#define debug_level_info 0


#include <phantom_libc.h>
#include <vm/syscall_net.h>
#include <vm/alloc.h>
#include <kernel/snap_sync.h>
#include <kernel/net.h>
#include <kernel/json.h>

#include <errno.h>


static int debug_print = 0;





static int si_net_tostring_5( pvm_object_t me, pvm_object_t *ret, struct data_area_4_thread *tc, int n_args, pvm_object_t *args )
{
    (void) me;
    DEBUG_INFO;
    SYSCALL_RETURN( pvm_create_string_object( "net" ));
}








static int si_net_resolve_16( pvm_object_t me, pvm_object_t *ret, struct data_area_4_thread *tc, int n_args, pvm_object_t *args )
{
    (void) me;
    //struct data_area_4_udp      *da = pvm_data_area( me, udp );

    DEBUG_INFO;

    CHECK_PARAM_COUNT(1);
    //int addr = AS_INT(args[0]);
    //(void) addr;

    //SYSCALL_PUT_THIS_THREAD_ASLEEP()

    SYSCALL_THROW_STRING( "not implemented" );
}












syscall_func_t  syscall_table_4_net[18] =
{
    &si_void_0_construct,               &si_void_1_destruct,
    &si_void_2_class,                   &si_void_3_clone,
    &si_void_4_equals,                  &si_net_tostring_5,
    &si_void_6_toXML,                   &si_void_7_fromXML,
    // 8
    &invalid_syscall,                   &invalid_syscall,
    &invalid_syscall,                   &invalid_syscall,
    &invalid_syscall,                   &invalid_syscall,
    &invalid_syscall,                   &si_void_15_hashcode,
    // 16
    &si_net_resolve_16,                 &invalid_syscall,
    //&invalid_syscall,                   &si_net_send_19,
    //&invalid_syscall,                   &si_net_recv_21,
    // 24
    //&invalid_syscall,                   &si_net_recvfrom_23,
    //&invalid_syscall,                   &si_net_sendto_25,

};
DECLARE_SIZE(net);

















void pvm_internal_init_net(pvm_object_t os)
{
    struct data_area_4_net      *da = (struct data_area_4_net *)os->da;

    (void) da;

    //da->connected = 0;

}

pvm_object_t     pvm_create_net_object(void)
{
    return pvm_create_object( pvm_get_net_class() );
}

void pvm_gc_iter_net(gc_iterator_call_t func, pvm_object_t  os, void *arg)
{
    struct data_area_4_net      *da = (struct data_area_4_net *)os->da;

    (void) da;

    //gc_fcall( func, arg, ot );
    //gc_fcall( func, arg, da->p_kernel_state_object );
    //gc_fcall( func, arg, da->callback );
}


void pvm_gc_finalizer_net( pvm_object_t  os )
{
    // is it called?
    struct data_area_4_net *da = (struct data_area_4_net *)os->da;
    (void) da;
}


void pvm_restart_net( pvm_object_t o )
{
    // struct data_area_4_net *da = pvm_object_da( o, net );

    //da->connected = 0;
    //if( da->connected )
    {
        ph_printf("restarting NET - unimpl!");
    }

}

