#ifndef _I_WASM
#define _I_WASM

#include <wasm_export.h>

struct data_area_4_wasm
{
    bool is_master;

    // .internal.array, stores objects containing description of wasm native symbols 
    pvm_object_t wasm_native_symbols;
    // .internal.array, stores objects allocated by wasm runtime using malloc
    pvm_object_t wasm_runtime_objects;

    wasm_module_t module;
    wasm_module_inst_t module_instance;
    wasm_exec_env_t exec_env;
    wasm_function_inst_t function_instance;
    void* natives_list_ptr;

    pvm_object_t wasm_code_str;
    
    // array of strings (environment variables)
    pvm_object_t env_vars_array;

    // arrays of hal mutexes / conds created by WAMR
    pvm_object_t wasm_mutex_array;
    pvm_object_t wasm_cond_array;

    // Directory containing IDs and corresponding phantom objects accessible by wasm program.
    pvm_object_t wasm_sandboxed_objects;
    // The next value of sandboxed object id
    uint64_t next_object_id;

    // wasm function was called by this thread
    pvm_object_t owner_thread;
    // object thrown by wasm program
    pvm_object_t inner_exception;
};

#endif // _I_WASM
