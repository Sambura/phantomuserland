set (PHANTOM_PVM_DIR ${CMAKE_CURRENT_LIST_DIR})

set (PHANTOM_PVM_SOURCE 
    exec.c 
    syscall_io.c 
    backtrace.c 
    syscall_sync.c 
    refdec.c 
    gen_machindep.c 
    syscall.c 
    json_parse.c 
    gdb.c 
    vm_sleep.c 
    e4c.c 
    stacks.c 
    wpool.c 
    code.c 
    root.c 
    syscall_net_kernel.c 
    vtest.c 
    syscall_win.c 
    create.c 
    load_class.c 
    ftype.c 
    video_test.c 
    syscall_tty.c 
    object.c 
    alloc.c 
    syscall_net_windows.c 
    find_class_file.c 
    vm_threads.c 
    jit.c 
    internal.c 
    bulk.c 
    gc.c 
    gc_on_snap.c
    wpaint.c 
    syscall_net.c 
    directory.c 
    sys/i_stat.c 
    sys/i_udp.c 
    sys/i_time.c 
    sys/i_ui_control.c 
    sys/i_io.c 
    sys/i_ui_font.c 
    sys/i_port.c 
    sys/i_http.c 
    sys/i_net.c 
    sys/i_wasm.c
)

if (PHANTOM_BUILD_NO_DISPLAY)
  set(PHANTOM_PVM_SOURCE ${PHANTOM_PVM_SOURCE} headless_screen.c)
endif ()

set (${WAMR_SOURCES} "")
include (${PHANTOM_PVM_DIR}/wamr.cmake)

# convert filenames to absolute paths
list(TRANSFORM PHANTOM_PVM_SOURCE PREPEND ${PHANTOM_PVM_DIR}/)

set (PHANTOM_PVM_SOURCE ${PHANTOM_PVM_SOURCE} ${WAMR_SOURCES})
