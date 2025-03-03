/**
 *
 * Phantom OS
 *
 * Copyright (C) 2005-2011 Dmitry Zavalishin, dz@dz.ru
 *
 * Unix subsystem signal processing. Not impl yet.
 *
 *
**/

#ifndef UUSIGNAL_H
#define UUSIGNAL_H

#include <signal.h>
//#include <unix/uuprocess.h>

#ifdef PHANTOM_GENODE

typedef struct signal_handling
{
    u_int32_t           signal_pending;
    u_int32_t           signal_mask; // 0 for ignored

    // unimpl
    u_int32_t           signal_stop; // 1 = stop process
    u_int32_t           signal_cont; // 1 = resume process
    //u_int32_t           signal_kill; // 1 = kill process

    void *              signal_handler[NSIG]; // 0 = kill

} signal_handling_t;

#endif

/**
 * \ingroup Unix
 * @{
**/

struct uuprocess;

//! Machdep func to deliver signal to user thread
errno_t sig_deliver(struct uuprocess *u, struct trap_state *st, int nsig, void *handler);

//! Init signal_handling_t struct
void sig_init(signal_handling_t *sh);

//! Send a signal (turn bit on)
void sig_send(signal_handling_t *sh, int signal);

//! Translate signals to user - internal, remove from here?
void sig_exec(struct uuprocess *u, signal_handling_t *sh, struct trap_state *st);

//! Translate signals to user
void execute_signals(struct uuprocess *u, struct trap_state *st);

//! Send signal to current thread
void sig_send_to_current(int signal);

#endif // UUSIGNAL_H
