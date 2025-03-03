/**
 *
 * Phantom OS
 *
 * Copyright (C) 2005-2011 Dmitry Zavalishin, dz@dz.ru
 *
 * Trap/interrupt context structure. See arch/...
 *
 *
**/


#ifndef GENERAL_TRAP_H
#define GENERAL_TRAP_H


#ifdef ARCH_mips
#include <mips/trap.h>
#else

#ifdef ARCH_arm
#include <arm/trap.h>
#else

#ifdef ARCH_ia32
#include <ia32/trap.h>

#elif defined(ARCH_amd64)
#include <amd64/trap.h>

#elif defined(ARCH_e2k)
#include <e2k/trap.h>

#else

#ifdef PHANTOM_GENODE

// TODO : Create a separate header!

#define ARCH_N_TRAPS 32



// Copied from amd64
struct trap_state {
    int state;
};

#else

#error No arch?

#endif

#endif
#endif
#endif


#ifndef ASSEMBLER

#ifndef PHANTOM_GENODE
int (*phantom_trap_handlers[ARCH_N_TRAPS])(struct trap_state *ts);
#endif

//! This is what called from low-level asm trap code
void phantom_kernel_trap( struct trap_state *ts );


void            dump_ss(struct trap_state *st);
const char *    trap_name(unsigned int trapnum);
int             trap_panic(struct trap_state *ts);

// Check if current thread is usermode and convert trap to thread kill
// returns nonzero if handled
int             phantom_check_user_trap( struct trap_state *ts );

//! Return signal number for this kind of trap - machdep
int             trap2signo( struct trap_state *ts );


//! Unix syscall dispatcher
void            syscall_sw(struct trap_state *st);

//! Pagefault trap handler
int vm_map_page_fault_trap_handler(struct trap_state *st);

#endif // ASSEMBLER


#endif // GENERAL_TRAP_H


